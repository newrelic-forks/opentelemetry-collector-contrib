# SQL Server: lock, thread pool, and tempdb metrics

**Date:** 2026-06-23
**Branch:** `lock-threadpool-tempdb-metrics` (cut from `sqlserver-core-metrics`)
**Receivers touched:** `receiver/sqlserverreceiver` and `receiver/nrsqlserverreceiver`. Identical changes applied to both.
**Prior work:** [2026-06-22-sqlserver-instance-database-metrics-design.md](2026-06-22-sqlserver-instance-database-metrics-design.md) — same conventions reused.

## Background

Confluence audit page 5734137875 catalogs metrics missing from the OTel `sqlserverreceiver` vs the existing New Relic SQL Server integration. PR #222 closed 19 entries across the instance, database, and wait-stats categories. This branch closes 30 more entries across `enable_lock_metrics` (20), `enable_thread_pool_metrics` (7), and `enable_tempdb_metrics` (3).

## Goals

- Cover all 30 missing entries across the 3 categories.
- For TempDB, go beyond a basic 5-field snapshot — add the deeper signals a DBA needs to diagnose contention (object-type breakdown, per-file size, allocation-page wait split).
- All new metrics disabled by default, `stability: development`, direct-DB connection only.
- Names follow OTel semconv (lowercase dot-separated).
- Same set mirrored to upstream `sqlserverreceiver` and the NR `nrsqlserverreceiver` fork.

## Non-goals

- Azure SQL Database edition-specific fallbacks. Queries that fail on Engine Edition 5 will fail-fast with a clear error.
- PDH/perf-counter collection mode.
- Backfilling entries the audit already classified as "Matching" (e.g. `latch.*`).

## Metric catalog — 11 new metrics

### Lock (2 metrics, covers 20 audit entries)

| Metric | Type / unit | Attributes |
|---|---|---|
| `sqlserver.lock.by_mode.count` | gauge / `{locks}` | `db.namespace`, `lock.mode ∈ {shared, exclusive, update, intent, schema, bulk_update, shared_intent_exclusive}` |
| `sqlserver.lock.by_resource.count` | gauge / `{locks}` | `db.namespace`, `lock.resource ∈ {key, page, row, table, extent, file, hobt, metadata, application, allocation_unit, database_level}` |

The audit's `total` entries become NRQL aggregations (`SUM(...)`) over the attribute, so no separate `total` metric is needed.

### Thread pool (4 metrics, covers 7 audit entries)

| Metric | Type / unit | Attributes |
|---|---|---|
| `sqlserver.thread_pool.workers.count` | gauge / `{workers}` | `worker.state ∈ {running, suspended_or_sleeping}` |
| `sqlserver.thread_pool.workers.max` | gauge / `{workers}` | — |
| `sqlserver.thread_pool.workers.utilization` | gauge / `1` | — |
| `sqlserver.thread_pool.tasks.count` | gauge / `{tasks}` | `task.state ∈ {current, queued, waiting_for_threadpool}` |

`runnable_tasks` from the audit is already covered by `sqlserver.os.scheduler.runnable_tasks.count` (added in PR #222).

### TempDB (5 metrics, covers 3 audit entries + 7 enrichment dims)

| Metric | Type / unit | Attributes |
|---|---|---|
| `sqlserver.tempdb.allocation.wait_time.total` | sum (cumulative, monotonic) / `s` | `allocation.page_type ∈ {gam, sgam, pfs, other}` |
| `sqlserver.tempdb.contention.waiters.count` | gauge / `{waiters}` | — |
| `sqlserver.tempdb.data_files.count` | gauge / `{files}` | — |
| `sqlserver.tempdb.file.size` | gauge / `By` | `file_type ∈ {data, log}`, `tempdb.file.id` |
| `sqlserver.tempdb.space.usage` | gauge / `By` | `tempdb.space_kind ∈ {user_objects, internal_objects, version_store, free}` |

`allocation.page_type` splits the allocation-waits bucket into the three pages that actually cause contention (GAM, SGAM, PFS) plus an `other` catch-all — different fixes apply to different ones. `tempdb.space_kind` from `sys.dm_db_file_space_usage` tells the operator whether tempdb is full of user temp tables, internal spills, version-store rows, or genuinely free — different fixes apply to each.

### New enum attributes added to metadata.yaml

```yaml
allocation.page_type:
  description: TempDB allocation-page wait type.
  type: string
  enum: [gam, sgam, pfs, other]
lock.mode:
  description: SQL Server lock request mode.
  type: string
  enum: [shared, exclusive, update, intent, schema, bulk_update, shared_intent_exclusive]
lock.resource:
  description: SQL Server lock resource type.
  type: string
  enum: [key, page, row, table, extent, file, hobt, metadata, application, allocation_unit, database_level]
task.state:
  description: SQL Server task state for thread-pool diagnostics.
  type: string
  enum: [current, queued, waiting_for_threadpool]
tempdb.file.id:
  description: Numeric file_id within tempdb (master_files.file_id).
  type: int
tempdb.space_kind:
  description: TempDB space usage category.
  type: string
  enum: [user_objects, internal_objects, version_store, free]
worker.state:
  description: SQL Server worker state.
  type: string
  enum: [running, suspended_or_sleeping]
```

## Query strategy

### Reuse: none

None of the existing queries return the data we need at the granularity we need.

### New (3 queries)

#### `sqlServerLockQuery` (per-DB, both by_mode and by_resource in one rowset)

```sql
SELECT
    DB_NAME(tl.resource_database_id) AS db_name,
    -- by mode
    SUM(CASE WHEN tl.request_mode IN ('S', 'IS')              THEN 1 ELSE 0 END) AS [shared],
    SUM(CASE WHEN tl.request_mode IN ('X', 'IX')              THEN 1 ELSE 0 END) AS [exclusive],
    SUM(CASE WHEN tl.request_mode IN ('U', 'IU', 'SIU', 'UIX') THEN 1 ELSE 0 END) AS [update_mode],
    SUM(CASE WHEN tl.request_mode IN ('IS','IX','IU','SIU','SIX','UIX') THEN 1 ELSE 0 END) AS [intent],
    SUM(CASE WHEN tl.request_mode IN ('Sch-S', 'Sch-M')        THEN 1 ELSE 0 END) AS [schema_mode],
    SUM(CASE WHEN tl.request_mode = 'BU'                       THEN 1 ELSE 0 END) AS [bulk_update],
    SUM(CASE WHEN tl.request_mode = 'SIX'                      THEN 1 ELSE 0 END) AS [shared_intent_exclusive],
    -- by resource
    SUM(CASE WHEN tl.resource_type = 'KEY'              THEN 1 ELSE 0 END) AS [res_key],
    SUM(CASE WHEN tl.resource_type = 'PAGE'             THEN 1 ELSE 0 END) AS [res_page],
    SUM(CASE WHEN tl.resource_type = 'RID'              THEN 1 ELSE 0 END) AS [res_row],
    SUM(CASE WHEN tl.resource_type = 'OBJECT'           THEN 1 ELSE 0 END) AS [res_table],
    SUM(CASE WHEN tl.resource_type = 'EXTENT'           THEN 1 ELSE 0 END) AS [res_extent],
    SUM(CASE WHEN tl.resource_type = 'FILE'             THEN 1 ELSE 0 END) AS [res_file],
    SUM(CASE WHEN tl.resource_type = 'HOBT'             THEN 1 ELSE 0 END) AS [res_hobt],
    SUM(CASE WHEN tl.resource_type = 'METADATA'         THEN 1 ELSE 0 END) AS [res_metadata],
    SUM(CASE WHEN tl.resource_type = 'APPLICATION'      THEN 1 ELSE 0 END) AS [res_application],
    SUM(CASE WHEN tl.resource_type = 'ALLOCATION_UNIT'  THEN 1 ELSE 0 END) AS [res_allocation_unit],
    SUM(CASE WHEN tl.resource_type = 'DATABASE'         THEN 1 ELSE 0 END) AS [res_database_level]
FROM sys.dm_tran_locks tl WITH (NOLOCK)
WHERE tl.resource_database_id > 0
GROUP BY tl.resource_database_id
HAVING COUNT(*) > 0;
```

One row per DB with active locks. Scraper emits both metrics from each row.

#### `sqlServerThreadPoolQuery` (single row, all worker/task/scheduler stats)

```sql
WITH waits AS (
    SELECT COUNT(*) AS waiting_for_threadpool
    FROM sys.dm_os_waiting_tasks WITH (NOLOCK)
    WHERE wait_type = 'THREADPOOL'
),
sched AS (
    SELECT SUM(work_queue_count) AS work_queue, SUM(current_tasks_count) AS current_tasks
    FROM sys.dm_os_schedulers WITH (NOLOCK)
    WHERE scheduler_id < 255 AND status = 'VISIBLE ONLINE'
),
workers AS (
    SELECT
        SUM(CASE WHEN state = 'RUNNING' THEN 1 ELSE 0 END) AS running,
        SUM(CASE WHEN state NOT IN ('RUNNING','RUNNABLE') THEN 1 ELSE 0 END) AS suspended_or_sleeping
    FROM sys.dm_os_workers WITH (NOLOCK)
),
cfg AS (
    SELECT max_workers_count AS max_workers FROM sys.dm_os_sys_info
)
SELECT
    workers.running,
    workers.suspended_or_sleeping,
    cfg.max_workers,
    CAST(workers.running AS float) / NULLIF(CAST(cfg.max_workers AS float), 0) AS utilization,
    sched.current_tasks,
    sched.work_queue,
    waits.waiting_for_threadpool
FROM waits, sched, workers, cfg;
```

#### `sqlServerTempDBQuery` (single rowset, multiple sections via CROSS JOIN)

```sql
WITH
file_space AS (
    SELECT
        SUM(user_object_reserved_page_count)     * 8 * 1024 AS bytes_user_objects,
        SUM(internal_object_reserved_page_count) * 8 * 1024 AS bytes_internal_objects,
        SUM(version_store_reserved_page_count)   * 8 * 1024 AS bytes_version_store,
        SUM(unallocated_extent_page_count)       * 8 * 1024 AS bytes_free
    FROM tempdb.sys.dm_db_file_space_usage WITH (NOLOCK)
),
data_files AS (
    SELECT COUNT(*) AS data_file_count
    FROM sys.master_files WITH (NOLOCK)
    WHERE database_id = 2 AND type = 0
),
waits AS (
    SELECT
        (SELECT COUNT(*) FROM sys.dm_os_wait_stats
         WHERE wait_type IN ('PAGELATCH_IO','PAGELATCH_SH','PAGELATCH_EX','PAGELATCH_UP')
           AND waiting_tasks_count > 0) AS pagelatch_waiters,
        ISNULL((SELECT SUM(wait_time_ms) FROM sys.dm_os_wait_stats WHERE wait_type LIKE '%GAM%'  AND wait_type NOT LIKE '%SGAM%'), 0) AS gam_ms,
        ISNULL((SELECT SUM(wait_time_ms) FROM sys.dm_os_wait_stats WHERE wait_type LIKE '%SGAM%'), 0) AS sgam_ms,
        ISNULL((SELECT SUM(wait_time_ms) FROM sys.dm_os_wait_stats WHERE wait_type LIKE '%PFS%'),  0) AS pfs_ms,
        ISNULL((SELECT SUM(wait_time_ms) FROM sys.dm_os_wait_stats
                WHERE wait_type LIKE '%ALLOCATION%' AND wait_type NOT LIKE '%GAM%' AND wait_type NOT LIKE '%SGAM%' AND wait_type NOT LIKE '%PFS%'), 0) AS other_ms
)
SELECT
    file_space.bytes_user_objects,
    file_space.bytes_internal_objects,
    file_space.bytes_version_store,
    file_space.bytes_free,
    data_files.data_file_count,
    waits.pagelatch_waiters,
    waits.gam_ms, waits.sgam_ms, waits.pfs_ms, waits.other_ms
FROM file_space, data_files, waits;
```

A separate query (`sqlServerTempDBFileQuery`) returns per-file sizes:

```sql
SELECT
    file_id,
    CASE type WHEN 0 THEN 'data' WHEN 1 THEN 'log' ELSE 'other' END AS file_type,
    CAST(size AS BIGINT) * 8 * 1024 AS size_bytes
FROM sys.master_files WITH (NOLOCK)
WHERE database_id = 2 AND type IN (0, 1);
```

### Engine support

All queries use DMVs available on Standard/Enterprise/Express (EngineEdition 2,3,4) and Managed Instance (8). Azure SQL Database (5) is excluded — `tempdb.sys.dm_db_file_space_usage` and `sys.master_files` can't be reached the same way from a user database on Azure SQL DB.

## Scraper changes

5 new scraper functions, one per query plus one per metric-emission family:

| Function | Query | Metrics emitted |
|---|---|---|
| `recordLockMetrics` | `sqlServerLockQuery` | `sqlserver.lock.by_mode.count` (×7 / DB), `sqlserver.lock.by_resource.count` (×11 / DB) |
| `recordThreadPoolMetrics` | `sqlServerThreadPoolQuery` | 4 thread-pool metrics |
| `recordTempDBMetrics` | `sqlServerTempDBQuery` | `sqlserver.tempdb.allocation.wait_time.total` (×4), `sqlserver.tempdb.contention.waiters.count`, `sqlserver.tempdb.data_files.count`, `sqlserver.tempdb.space.usage` (×4) |
| `recordTempDBFileMetrics` | `sqlServerTempDBFileQuery` | `sqlserver.tempdb.file.size` (one per file) |

Each function follows the receiver's existing `recordXxxMetrics(ctx) error` pattern. Wired into `ScrapeMetrics` switch and `setupQueries`.

### Enabled-gating

Each scraper exits early when none of its target metrics are enabled, matching the pattern used in `recordOSMemoryMetrics`.

## File touch list (per receiver)

Applied identically to `receiver/sqlserverreceiver/` and `receiver/nrsqlserverreceiver/`:

| File | Change |
|---|---|
| `metadata.yaml` | +7 attribute defs, +11 metric defs |
| `queries.go` | +4 query consts (lock, threadpool, tempdb, tempdb-file) |
| `scraper.go` | +4 record functions, +4 calls in `ScrapeMetrics` switch |
| `factory.go` | +4 entries in `setupQueries` |
| `factory_test.go` | bump expected metric count (77 → 88) |
| `internal/metadata/generated_*.go` | regenerated by `mdatagen` |
| `documentation.md` | regenerated by `mdatagen` |

Plus `.chloggen/sqlserver-lock-threadpool-tempdb-metrics.yaml`.

## Testing

Same approach as PR #222: rely on the auto-generated `generated_metrics_test.go` for unit-level coverage of each new metric. No new fixture files unless `mdatagen` complains. Integration tests in `integration_test.go` are not modified — defaults are `enabled: false`, so existing baselines stay stable.

### Pre-commit gate

```bash
cd receiver/sqlserverreceiver   && go generate ./... && make fmt && make gci && make lint && go test ./...
cd receiver/nrsqlserverreceiver && go generate ./... && make fmt && make gci && make lint && go test ./...
```

All must pass.

## Rollout

1. Implement on `lock-threadpool-tempdb-metrics`.
2. Local validation passes.
3. PR to `sqlserver-core-metrics` (same target as PR #222).
4. After merge, remaining categories from the audit:
   - failover_cluster (10)
   - database_principals (8)
   - database_role_membership (11)

That leaves 29 to go after this branch — done in a future PR.
