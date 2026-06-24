# SQL Server: missing instance + database metrics

**Date:** 2026-06-22
**Branch (planned):** `sqlserver-instance-database-metrics` (cut from `sqlserver-core-metrics`)
**Receivers touched:** `receiver/sqlserverreceiver` (upstream copy in `newrelic-forks/opentelemetry-collector-contrib`) and `receiver/nrsqlserverreceiver` (NR fork). Identical changes applied to both.

## Background

The Confluence audit "PP / NRDOT vs OTel sqlserverreceiver — Core Metrics Comparison & Validation" (page 5734137875) catalogs 78 PP/NRDOT metrics that are currently "Not Available" in the OTel `sqlserverreceiver`. This spec scopes the first slice of that work: the `enable_instance_metrics` and `enable_database_metrics` categories — 18 PP entries total. The remaining categories (failover_cluster, database_principals, database_role_membership, security, lock, thread_pool, tempdb, database_buffer) are explicitly out of scope and will be handled by follow-up branches.

NRDOT reference implementation lives at:

- `/Users/spathlavath/nrdot-collector-components` on branch `feature/otel-mssql-qpm-receiver`
- Key files: `receiver/newrelicsqlserverreceiver/queries/instance_metrics.go`, `database_metrics.go`

## Goals

- Add 10 new OTel metrics that fully cover the 18 PP "Not Available" entries in the instance + database categories (process status and memory variants collapse into attributes per OTel conventions).
- Default all new metrics to `enabled: false`, `stability: development`. Users opt in.
- Follow OTel semantic naming conventions (https://opentelemetry.io/docs/specs/semconv/general/naming/).
- Direct-connection collection mode only. PDH/perf-counter mode untouched.
- Same set of changes mirrored to upstream `sqlserverreceiver` and `nrsqlserverreceiver`.

## Non-goals

- Azure SQL Database / Azure Managed Instance edition-specific query variants. Scrape fails gracefully (debug log, no metrics emitted) on editions where required DMVs are unavailable.
- PDH/perf-counter collection mode.
- Other PP categories from the Confluence doc (failover_cluster, principals, role_membership, security, lock, thread_pool, tempdb, database_buffer).
- Manual end-to-end verification against a real SQL Server (will happen after merge, not part of this branch).

## Metric catalog

10 new metrics covering all 18 PP entries.

### Instance (8 metrics → 15 PP entries)

| # | OTel metric | Type / unit | Attributes | PP entries covered |
|---|---|---|---|---|
| 1 | `sqlserver.batch.compilation.utilization` | gauge / `1` | — | `compilations_per_batch` |
| 2 | `sqlserver.batch.page_split.utilization` | gauge / `1` | — | `page_splits_per_batch` |
| 3 | `sqlserver.os.memory.usage` | gauge / `By` | `memory.state ∈ {available, total}` | `memory_available`, `memory_total` |
| 4 | `sqlserver.os.memory.utilization` | gauge / `1` | — | `memory_utilization_percent` |
| 5 | `sqlserver.os.disk.size` | gauge / `By` | — | `disk_in_bytes` |
| 6 | `sqlserver.os.scheduler.runnable_tasks.count` | gauge / `{tasks}` | — | `runnable_tasks` |
| 7 | `sqlserver.process.count` | gauge / `{processes}` | `process.status ∈ {background, dormant, preconnect, runnable, running, sleeping, suspended}` | `background_processes_count`, `dormant_processes_count`, `preconnect_processes_count`, `runnable_processes_count`, `running_processes_count`, `sleeping_processes_count`, `suspended_processes_count` |
| 8 | `sqlserver.kill_connection.error.rate` | sum (cumulative, monotonic) / `{errors}` | — | `stats.kill_connection_errors_per_sec` |

### Database (2 metrics → 3 PP entries)

Per-DB scoping uses the existing `db.namespace` metric attribute, matching how other per-DB metrics in this receiver (e.g. `sqlserver.database.file.size`) are scoped.

| # | OTel metric | Type / unit | Attributes | PP entries covered |
|---|---|---|---|---|
| 9 | `sqlserver.database.page_file.size` | gauge / `By` | `db.namespace`, `page_file.state ∈ {used, free, total}` | `page_file_available_bytes`, `page_file_total_bytes` |
| 10 | `sqlserver.database.transactions.active` | gauge / `{transactions}` | `db.namespace` | `transactions.active` |

### New enum attributes (added to `metadata.yaml` under `attributes:`)

```yaml
memory.state:
  description: The memory state.
  type: string
  enum: [available, total]
page_file.state:
  description: The state of the database page file space.
  type: string
  enum: [used, free, total]
process.status:
  description: The status of the SQL Server process/session.
  type: string
  enum: [background, dormant, preconnect, runnable, running, sleeping, suspended]
```

The 7 process statuses come from `sys.dm_exec_sessions.status`. NRDOT's "blocked" status is omitted because the existing `sqlserver.processes.blocked` metric already covers blocked-session counts.

## Query strategy

### Reuse: `sqlServerPerformanceCountersQuery`

The existing perf-counter query already harvests the rows we need for the 4 counter-derived metrics. **No SQL change required.** Wiring:

| New metric | How | Where |
|---|---|---|
| `sqlserver.batch.compilation.utilization` | Computed in Go: `sql_compilations_rate / batch_request_rate` | Post-processing in `recordDatabasePerfCounterMetrics` |
| `sqlserver.batch.page_split.utilization` | Computed in Go: `page_splits_rate / batch_request_rate` | Same |
| `sqlserver.kill_connection.error.rate` | New row handler for `SQL Errors / Kill Connection Errors` | New entry in `perfCounterRecorders` |
| `sqlserver.database.transactions.active` | New row handler for `Databases / Active Transactions` | Merged into the existing `Databases` block in `perfCounterRecorders` (instance `*` → one datapoint per database, scoped by `db.namespace`) |

### New (5 small DMV queries added to `queries.go`)

Each becomes a new `const` plus a corresponding scraper method.

```go
// 1. OS memory: available + total bytes, plus utilization percent.
const sqlServerOSMemoryQuery = `SELECT
    MAX(sys_mem.total_physical_memory_kb * 1024.0)     AS total_physical_memory_bytes,
    MAX(sys_mem.available_physical_memory_kb * 1024.0) AS available_physical_memory_bytes,
    (MAX(proc_mem.physical_memory_in_use_kb) /
     (MAX(sys_mem.total_physical_memory_kb) * 1.0)) * 100 AS memory_utilization_percent
  FROM sys.dm_os_process_memory proc_mem,
       sys.dm_os_sys_memory     sys_mem`

// 2. Total disk size across volumes hosting database files.
const sqlServerOSDiskQuery = `SELECT SUM(total_bytes) AS total_disk_space_bytes FROM (
    SELECT DISTINCT dovs.volume_mount_point, dovs.total_bytes
    FROM sys.master_files mf WITH (NOLOCK)
    CROSS APPLY sys.dm_os_volume_stats(mf.database_id, mf.file_id) dovs
  ) drives`

// 3. Runnable tasks summed across OS schedulers.
const sqlServerOSSchedulerRunnableTasksQuery = `SELECT
    SUM(runnable_tasks_count) AS runnable_tasks_count
  FROM sys.dm_os_schedulers
  WHERE scheduler_id < 255 AND status = 'VISIBLE ONLINE'`

// 4. Process counts pivoted by status. One row, 7 columns.
const sqlServerProcessCountQuery = `SELECT
    MAX(CASE WHEN status='background' THEN counts ELSE 0 END) AS background,
    MAX(CASE WHEN status='dormant'    THEN counts ELSE 0 END) AS dormant,
    MAX(CASE WHEN status='preconnect' THEN counts ELSE 0 END) AS preconnect,
    MAX(CASE WHEN status='runnable'   THEN counts ELSE 0 END) AS runnable,
    MAX(CASE WHEN status='running'    THEN counts ELSE 0 END) AS running,
    MAX(CASE WHEN status='sleeping'   THEN counts ELSE 0 END) AS sleeping,
    MAX(CASE WHEN status='suspended'  THEN counts ELSE 0 END) AS suspended
  FROM (
    SELECT status, COUNT(*) counts FROM (
      SELECT COALESCE(req.status, sess.status) AS status
      FROM sys.dm_exec_sessions sess
      LEFT JOIN sys.dm_exec_requests req ON sess.session_id = req.session_id
      WHERE sess.session_id > 50
    ) statuses
    GROUP BY status) sessions`

// 5. Per-database page file: total + used bytes (free is derived as total - used).
const sqlServerDatabasePageFileQuery = `SELECT
    DB_NAME() AS db_name,
    SUM(a.total_pages) * 8.0 * 1024 AS reserved_space_bytes,
    (SUM(a.total_pages) - SUM(a.used_pages)) * 8.0 * 1024 AS reserved_space_not_used_bytes
  FROM sys.partitions p WITH (NOLOCK)
  INNER JOIN sys.allocation_units a WITH (NOLOCK) ON p.partition_id = a.container_id
  LEFT JOIN sys.internal_tables it WITH (NOLOCK) ON p.object_id = it.object_id`
```

The page_file query runs once per user database (existing receiver pattern: iterate `sys.databases` list and execute the query in each DB's context). The exact iteration mechanism (USE statement vs. database-scoped exec) is determined during implementation to match the receiver's existing per-DB patterns.

### Edition handling

DMVs used: `sys.dm_os_process_memory`, `sys.dm_os_sys_memory`, `sys.master_files`, `sys.dm_os_volume_stats`, `sys.dm_os_schedulers`, `sys.dm_exec_sessions`, `sys.dm_exec_requests`, `sys.partitions`, `sys.allocation_units`. These work on standard SQL Server and Azure Managed Instance. On Azure SQL Database, queries error → existing scraper error handling logs a debug message and emits no metrics. No Azure-specific fallback queries in this branch.

## Scraper changes

### Extend `perfCounterRecorders` (`recorders.go`)

- New top-level block for `SQL Errors / Kill Connection Errors` → calls `RecordSqlserverKillConnectionErrorRateDataPoint`.
- One additional entry merged into the existing `Databases` block: `Active Transactions` → `RecordSqlserverDatabaseTransactionsActiveDataPoint`. Because the existing block uses `instance: "*"`, this becomes per-DB automatically.

### Ratio post-processing (`scraper.go`)

Inside `recordDatabasePerfCounterMetrics`, while iterating perf-counter rows, capture three values into locals:

- `batch_request_rate` (object `SQL Statistics`, counter `Batch Requests/sec`)
- `sql_compilation_rate` (`SQL Statistics`, `SQL Compilations/sec`)
- `page_split_rate` (`Access Methods`, `Page Splits/sec`, instance `_Total`)

After the row loop, if `batch_request_rate > 0`, emit:

- `sqlserver.batch.compilation.utilization = sql_compilation_rate / batch_request_rate`
- `sqlserver.batch.page_split.utilization = page_split_rate / batch_request_rate`

When `batch_request_rate == 0` or any of the three counters are missing from the result set, skip emission (no datapoint, no error).

### Five new scraper functions

Each follows existing receiver convention (`recordDatabaseSizeMetrics`, `recordMemoryTargetMetrics`): take `ctx`, run a query via `s.client`, iterate rows, call recorders, return error aggregated via `scrapererror.ScrapeErrors`.

| Function | Query | Metrics emitted |
|---|---|---|
| `recordOSMemoryMetrics` | `sqlServerOSMemoryQuery` | `sqlserver.os.memory.usage` (2 datapoints: `available`, `total`), `sqlserver.os.memory.utilization` |
| `recordOSDiskMetrics` | `sqlServerOSDiskQuery` | `sqlserver.os.disk.size` |
| `recordOSSchedulerMetrics` | `sqlServerOSSchedulerRunnableTasksQuery` | `sqlserver.os.scheduler.runnable_tasks.count` |
| `recordProcessCountMetrics` | `sqlServerProcessCountQuery` | `sqlserver.process.count` (7 datapoints by `process.status`) |
| `recordDatabasePageFileMetrics` | `sqlServerDatabasePageFileQuery` (per DB) | `sqlserver.database.page_file.size` (3 datapoints per DB: `used`, `free`, `total`) |

Each is invoked from `ScrapeMetrics` after the existing block of `s.recordXxx(ctx)` calls, in the same error-aggregation pattern.

### Enabled-gating short-circuit

Defaults are `enabled: false`. `RecordXxxDataPoint` calls are no-ops when disabled, but a query roundtrip is still wasted unless guarded. Each new scraper function exits early when none of its target metrics are enabled — matching the existing `recordDatabaseSizeMetrics` pattern:

```go
mc := s.config.Metrics
if !mc.SqlserverOsMemoryUsage.Enabled && !mc.SqlserverOsMemoryUtilization.Enabled {
    return nil
}
```

## File touch list (per receiver)

Applied identically to both `receiver/sqlserverreceiver/` and `receiver/nrsqlserverreceiver/`:

| File | Change |
|---|---|
| `metadata.yaml` | +3 attribute defs, +10 metric defs |
| `queries.go` | +5 query consts (~80 lines) |
| `recorders.go` | +1 block for `SQL Errors`, +1 line for `Active Transactions` inside the existing `Databases` block |
| `scraper.go` | +5 record functions (~150 lines), +ratio post-processing (~20 lines), +5 calls in `ScrapeMetrics` |
| `recorders_test.go` | +2 cases (kill_connection, active_transactions) |
| `scraper_test.go` | +5 cases (one per new record func) plus ratio post-processing case |
| `testdata/*.yaml` | regenerated expectations, plus new fixtures for new queries |
| `internal/metadata/generated_*.go` | regenerated by `mdatagen` |
| `documentation.md` | regenerated by `mdatagen` |

Plus one shared changelog entry: `.chloggen/sqlserver-instance-database-metrics.yaml` (`change_type: enhancement`, components `receiver/sqlserver` and `receiver/nrsqlserver`).

## Testing strategy

### Unit tests

`recorders_test.go` — extend the existing table-driven test:
- Add row for `SQL Errors / Kill Connection Errors / Errors/sec` → assert kill_connection.error.rate recorded.
- Add row for `Databases / Active Transactions` → assert database.transactions.active recorded with the right `db.namespace` metric attribute.

`scraper_test.go` — one case per new record function, mocking `sqlquery.DBProviderFunc` with fixture rows:
- `recordOSMemoryMetrics`: total=`16777216000`, available=`4194304000`, util=`75.0` → 3 datapoints.
- `recordOSDiskMetrics`: total=`500000000000` → 1 datapoint.
- `recordOSSchedulerMetrics`: tasks=`5` → 1 datapoint.
- `recordProcessCountMetrics`: row with all 7 status columns → 7 datapoints with correct attribute values.
- `recordDatabasePageFileMetrics`: 2 DBs × (total, used) → 6 datapoints (2 DBs × 3 states).
- Ratio post-processing: counters → `compilation.utilization=0.1`, `page_split.utilization=0.05`. Zero-denominator case asserts no datapoint emitted.

Fixtures placed in `testdata/` follow existing naming. Each new scraper function gets a paired result-set fixture and an `expected<Name>.yaml` (and `RemoveServerResourceAttributes.yaml` variant where the existing receiver maintains both — e.g. matching the `expectedDatabaseSize.yaml` + `expectedDatabaseSizeRemoveServerResourceAttributes.yaml` pattern).

### Integration test

Existing `integration_test.go` is not modified (defaults `enabled: false` → no expectation diff). Add one new `TestIntegration_NewInstanceDatabaseMetrics` that explicitly enables all 10 new metrics and asserts they appear, reusing the existing Docker-based fixture pattern with appropriate build tags.

### Generated code verification

After `mdatagen`:
- `internal/metadata/generated_metrics.go` has 10 new `RecordSqlserver*DataPoint` methods.
- `internal/metadata/generated_metrics_test.go` has 10 new test cases.
- `internal/metadata/generated_config.go` has 10 new metric configs with `Enabled: false` defaults.
- `documentation.md` lists 10 new entries.

### Pre-commit gate

```bash
cd receiver/sqlserverreceiver  && go generate ./... && make fmt && make gci && make lint && go test ./...
cd receiver/nrsqlserverreceiver && go generate ./... && make fmt && make gci && make lint && go test ./...
```

All must pass.

## Rollout

1. New branch `sqlserver-instance-database-metrics` cut from `sqlserver-core-metrics`.
2. Implement, verify locally, push.
3. Open PR against `newrelic-fork`'s default branch (matching prior NR-fork PRs).
4. After merge, follow-up branches address the remaining 60 metrics across the other PP categories.

## Implementation notes

These are details to confirm while writing the code, not blockers on the design:

- Exact per-DB iteration shape for `recordDatabasePageFileMetrics` — pick the pattern that minimizes deviation from `recordDatabaseSizeMetrics` / similar existing per-DB scrapers.
- Whether `Page Splits/sec` is reachable from the existing perf-counter result set under instance `_Total` or `*`; verify during implementation against the existing query's WHERE filter (line ~244 in `queries.go` already gates `Page Splits/sec` to instance `_Total`, so it should be available).
