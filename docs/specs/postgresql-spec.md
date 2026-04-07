# PostgreSQL Receiver Spec

## Status: Draft
Last updated: 2026-04-06 via foundation branch
Approved by: —

---

## Receiver Identity

| Field | Value |
|-------|-------|
| Component | receiver/postgresqlreceiver |
| Stability | Metrics: beta / Logs: development |
| Database versions supported | PostgreSQL 9.6+ (pg_stat_statements required for top queries; v17+ uses split bgwriter/checkpointer views) |
| Driver | `github.com/lib/pq v1.10.9` |
| Priority | MEDIUM |

---

## Metrics & Log Events

Defined in `metadata.yaml` — the single source of truth for metric names, types, units,
enabled/disabled defaults, attributes, and log event schemas. Currently: **36 metrics**
(22 enabled, 14 disabled), **2 log events** (both disabled by default).

Do NOT duplicate the metrics catalog here. Any new metric or attribute change starts
in `metadata.yaml`, then gets wired through the implementation patterns below.

### Adding

| OTel Name | Type | Unit | Enabled | Source Query | Priority | Jira | Status |
|-----------|------|------|---------|-------------|----------|------|--------|
| — | — | — | — | — | — | — | — |

---

## Query Source Map

Each metric group is sourced from a specific SQL query. The query functions are in `client.go`.

| Query Function / Constant | Source View / Table | Metrics Group | Notes |
|--------------------------|---------------------|---------------|-------|
| `getDatabaseStats` | `pg_stat_database` | commits, rollbacks, deadlocks, temp_files, temp.io, tup_*, blks_hit, blks_read | Filtered by database list |
| `getDatabaseLocks` | `pg_locks JOIN pg_class` | database.locks | Grouped by relation, mode, locktype |
| `getBGWriterStats` | `pg_stat_bgwriter` (< v17) or `pg_stat_bgwriter + pg_stat_checkpointer` (v17+) | bgwriter.* (buffers.allocated, buffers.writes, checkpoint.count, duration, maxwritten) | Version-detected via `SHOW server_version` |
| `getBackends` | `pg_stat_activity` | backends | COUNT grouped by datname |
| `getDatabaseSize` | `pg_database_size()` via `pg_catalog.pg_database` | db_size | Excludes template databases |
| `getDatabaseTableMetrics` | `pg_stat_user_tables` | rows, operations, table.size, table.vacuum.count, sequential_scans | Per-table via `pg_relation_size(relid)` |
| `getBlocksReadByTable` | `pg_statio_user_tables` | blocks_read (8 source attributes) | COALESCE to handle NULLs |
| `getReplicationStats` | `pg_stat_replication` | replication.data_delay, wal.lag or wal.delay | Feature-gated: precise lag uses `::decimal`, deprecated uses `::integer` |
| `getLatestWalAgeSeconds` | `pg_stat_archiver` | wal.age | Returns `errNoLastArchive` if no previous archive |
| `getMaxConnections` | `SHOW max_connections` | connection.max | Single scalar |
| `getIndexStats` | `pg_stat_user_indexes` | index.scans, index.size | Per-index via `pg_relation_size(indexrelid)` |
| `getFunctionStats` | `pg_stat_user_functions JOIN pg_proc` | function.calls | Handles overloaded functions via CTE |
| `listDatabases` | `pg_database` | database.count | Excludes templates |
| `getQuerySamples` | `pg_stat_activity` (Go template: `querySampleTemplate.tmpl`) | log: db.server.query_sample | Filters by newest query timestamp; trace context extraction |
| `getTopQuery` | `pg_stat_statements` (Go template: `topQueryTemplate.tmpl`) | log: db.server.top_query | Joined with `pg_roles` and `pg_database`; ordered by calls DESC |

---

## Configuration

### Schema

```yaml
receivers:
  postgresql:
    # Connection
    endpoint: "localhost:5432"
    transport: tcp                     # tcp or unix
    username: ""
    password: ""

    # Database filtering
    databases: []                      # Empty = auto-discover all
    exclude_databases: []

    # TLS
    tls:
      insecure: false
      insecure_skip_verify: true
      ca_file: ""
      cert_file: ""
      key_file: ""

    # Connection pooling (behind feature gate: receiver.postgresql.connectionPool)
    connection_pool:
      max_idle_time: null
      max_lifetime: null
      max_idle: null
      max_open: null

    # Collection
    collection_interval: 10s
    initial_delay: 1s

    # Top query collection
    top_query_collection:
      collection_interval: 1m
      top_n_query: 200
      max_rows_per_query: 1000
      max_explain_each_interval: 1000
      query_plan_cache_size: 1000
      query_plan_cache_ttl: 1h

    # Query sample collection
    query_sample_collection:
      max_rows_per_query: 1000
```

### Validation Rules (from `config.go:Validate()`)

| Rule | Error |
|------|-------|
| `username` is empty | `invalid config: missing username` |
| `password` is empty | `invalid config: missing password` |
| `transport` not `tcp` or `unix` | `invalid config: 'transport' must be 'tcp' or 'unix'` |
| `endpoint` not `host:port` | `invalid config: 'endpoint' must be in the form <host>:<port>` |
| TLS `ServerName` set | `invalid config: field 'ServerName' not supported` |
| TLS `MaxVersion` set | `invalid config: field 'MaxVersion' not supported` |
| TLS `MinVersion` set | `invalid config: field 'MinVersion' not supported` |

### Connection String Construction (from `client.go`)

Built in `postgreSQLConfig.ConnectionString()`:
1. Defaults database to `"postgres"` if empty
2. Splits endpoint into host + port via `net.SplitHostPort`
3. For unix transport, prepends `"/"` to host (lib/pq expects `/path/.s.PGSQL.port`)
4. Format: `port={port} host={host} user={user} password={pass} dbname={db} {sslmode}`
5. SSL mode derived from TLS config:
   - `insecure: true` → `sslmode='disable'`
   - `insecure_skip_verify: true` → `sslmode='require'`
   - Otherwise → `sslmode='verify-full'` with optional `sslrootcert`, `sslkey`, `sslcert`

---

## Implementation Patterns

### How Scrapers Are Created

`factory.go:NewFactory()` registers two receiver factories:

1. **Metrics receiver** (`createMetricsReceiver`):
   - Checks `receiver.postgresql.connectionPool` feature gate to select `poolClientFactory` or `defaultClientFactory`
   - Creates `postgreSQLScraper` with a 1-entry LRU cache and 1-entry TTL cache (placeholders; top-query scraper uses larger caches)
   - Wraps in `scraper.NewMetrics` with `scraper.WithShutdown`
   - Returns via `scraperhelper.NewMetricsController`

2. **Logs receiver** (`createLogsReceiver`):
   - Conditionally adds log scrapers based on `cfg.Events.DbServerQuerySample.Enabled` and `cfg.Events.DbServerTopQuery.Enabled`
   - **Query sample scraper**: same cache as metrics (placeholder), calls `scrapeQuerySamples`
   - **Top query scraper**: sized LRU cache (`topNQuery * 10 * 2`), expirable TTL cache (`queryPlanCacheSize`, `queryPlanCacheTTL`), calls `scrapeTopQuery`
   - Each log scraper added via `scraperhelper.AddFactoryWithConfig`
   - Returns via `scraperhelper.NewLogsController`

### Traced Example: Adding a Metric from pg_stat_database

To add `postgresql.new_metric` sourced from `pg_stat_database`:

**Step 1: metadata.yaml** — Add the metric definition under `metrics:`.
**Step 2: Run `make generate`** in `receiver/postgresqlreceiver/`.
**Step 3: client.go** — Add the column to the `getDatabaseStats` SELECT and scan it into `databaseStats` struct.
**Step 4: scraper.go** — In `recordDatabase()`, call `p.mb.RecordPostgresqlNewMetricDataPoint(now, stats.newMetric)`.
**Step 5: Tests** — Update mock client expectations, add golden file entries.

```go
// Step 3 example: extend databaseStats struct
type databaseStats struct {
    // ... existing fields ...
    newMetric int64
}
// Extend the SELECT in getDatabaseStats and the Scan call

// Step 4 example: record in scraper.go
if stats, ok := r.dbStats[dbName]; ok {
    // ... existing records ...
    p.mb.RecordPostgresqlNewMetricDataPoint(now, stats.newMetric)
}
```

### Traced Example: Adding a Metric from pg_stat_user_tables

To add a per-table metric from `pg_stat_user_tables`:

**Step 1: metadata.yaml** — Add metric definition.
**Step 2: Run `make generate`**.
**Step 3: client.go** — Add column to `getDatabaseTableMetrics` query and `tableStats` struct.
**Step 4: scraper.go** — In `collectTables()`, call the record method inside the per-table loop.
**Step 5: Tests** — Update mock, golden files.

### How Cache and Delta Computation Works

Used only for **top query** log events to compute deltas:

- **Cache type**: `hashicorp/golang-lru/v2` — non-expirable LRU
- **Key format**: `{queryid}{columnName}` (e.g., `"12345total_exec_time"`)
- **Cache size**: `topNQuery * 10 * 2` (10 delta columns, 2x headroom)
- **Delta logic**: `delta = currentValue - cachedValue`. If delta ≤ 0, emit 0 and skip cache update. If delta > 0, update cache and emit delta.
- **Delta columns**: `total_exec_time`, `total_plan_time`, `rows`, `calls`, `shared_blks_dirtied`, `shared_blks_hit`, `shared_blks_read`, `shared_blks_written`, `temp_blks_read`, `temp_blks_written`

**Query plan cache** (separate):
- **Type**: `hashicorp/golang-lru/v2/expirable` — TTL-based LRU
- **Key format**: `{queryid}-plan`
- **Size**: configurable via `query_plan_cache_size` (default: 1000)
- **TTL**: configurable via `query_plan_cache_ttl` (default: 1h)
- **Purpose**: avoid re-running EXPLAIN for the same query within TTL

### How Query Obfuscation Works

- **Library**: `github.com/DataDog/datadog-agent/pkg/obfuscate`
- **DBMS mode**: `postgresql`
- **Settings**: `KeepSQLAlias: true`, `KeepBoolean: true`, `KeepNull: true`
- **What gets obfuscated**:
  - SQL text: `obfuscateSQL()` — replaces literal values with `?`
  - EXPLAIN plans: `obfuscateSQLExecPlan()` — obfuscates SQL values in JSON plan keys (Filter, Index Cond, etc.) while keeping structural keys (Node Type, Plan Rows, etc.)
- **Failure behavior**: on obfuscation error, logs WARN and sets query text to empty string `""`
- **Lazy initialization**: singleton `obfuscate.Obfuscator` initialized on first use via `sync.Once`

### How Resource Attributes Are Set

Resource attributes are populated by `setupResourceBuilder()` in `scraper.go`:

| Attribute | Source | When Set |
|-----------|--------|----------|
| `service.instance.id` | `host:port` from config endpoint (resolved: localhost → hostname) | Always |
| `postgresql.database.name` | Database name from iteration | Per-database metrics |
| `postgresql.schema.name` | Schema from query results | When `separateSchemaAttr` feature gate enabled |
| `postgresql.table.name` | Table name from query results | Per-table metrics |
| `postgresql.index.name` | Index name from query results | Per-index metrics |

Without `separateSchemaAttr`, table names are emitted as `schema.table` in the table attribute.

### Feature Gates

| Gate ID | Stage | Effect |
|---------|-------|--------|
| `postgresqlreceiver.preciselagmetrics` | beta (v0.89.0+) | Replaces `postgresql.wal.lag` (int seconds) with `postgresql.wal.delay` (float64 seconds) |
| `receiver.postgresql.connectionPool` | beta (v0.96.0+) | Uses persistent connection pool (`poolClientFactory`) instead of fresh connection per scrape (`defaultClientFactory`) |
| `receiver.postgresql.separateSchemaAttr` | alpha (v0.122.0+) | Reports schema as dedicated `postgresql.schema.name` resource attribute instead of prefixed to table name |

### Receiver-Specific Patterns

**Multi-database iteration**: The scraper connects to the default `postgres` database first to list/filter databases, then iterates each database with a dedicated client connection for per-database metrics (tables, indexes, functions). Global metrics (bgwriter, WAL, replication, max_connections, locks) are collected from the default connection.

**Concurrent retrieval**: `retrieveDBMetrics()` launches 3 goroutines in parallel (`sync.WaitGroup`) to fetch backends, database size, and database stats concurrently.

**Top query ranking**: Uses a priority queue (`internal/common/priorityqueue`) to rank queries by `total_exec_time` delta descending, then emits the top N.

**EXPLAIN safety**: Only explains queries starting with known DML keywords (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `WITH`, `MERGE`, `TABLE`, `VALUES`). Uses `PREPARE`/`EXECUTE` with NULL parameters and `force_generic_plan`. Queries prefixed with `/* otel-collector-ignore */` are excluded from collection.

**PostgreSQL v17 compatibility**: `getBGWriterStats` detects the major version via `SHOW server_version` and uses the split `pg_stat_bgwriter` + `pg_stat_checkpointer` views for v17+. In v17+, `buffers_backend` and `buffers_backend_fsync` are not available and set to -1.

---

## Test Patterns

### Unit Tests

Pattern: Mock client interface via `mockClientFactory` and `mockClient` implementing the `client` interface. Table-driven tests with golden file comparison.

```go
// Example: creating a test scraper with mock factory
factory := new(mockClientFactory)
factory.initMocks([]string{"otel"})

cfg := createDefaultConfig().(*Config)
cfg.Databases = []string{"otel"}

scraper := newPostgreSQLScraper(
    receivertest.NewNopSettings(metadata.Type),
    cfg, factory, newCache(1),
    newTTLCache[string](1, time.Second),
)
actualMetrics, err := scraper.scrape(t.Context())
```

**To add test data for a new query:**
1. Add mock expectations in `scraper_test.go` for the new client method
2. Update golden YAML files under `testdata/scraper/otel/` (both `expected.yaml` and `expected_schemaattr.yaml`)
3. Run `make test` and update golden files if needed

### Integration Tests

Pattern: `testcontainers-go` with PostgreSQL Docker images.

- **Container images**: `postgres:13.18` (pre-v17) and `postgres:17.2` (post-v17)
- **Init scripts**: `testdata/integration/01-init.sql` (schema + data), `02-create-extension.sh`
- **Build tag**: `//go:build integration`
- **Test matrix**: single_db, multi_db, all_db × {default, schemaattr, connpool} × {pre17, post17}
- **Comparison**: `pmetrictest.CompareMetrics` with golden YAML files under `testdata/integration/`

### Safety Tests

- `TestUnsuccessfulScrape`: verifies scraper returns error and empty metrics on bad endpoint
- `TestCreateDefaultConfig`: validates all default config values are set correctly
- `TestValidConfig` / `TestValidate`: exhaustive validation rule testing (missing user/pass, bad endpoint, unsupported TLS fields)

---

## Error Handling

| Scenario | Behavior | Code Location |
|----------|----------|---------------|
| Connection refused | Scrape fails with error, returns empty metrics | `scraper.go:scrape()` — `clientFactory.getClient()` |
| Auth failure | Scrape fails with error, returns empty metrics | `client_factory.go:getDB()` — `pq.NewConnector()` |
| Database list query fails | Scrape fails with error, returns empty metrics | `scraper.go:scrape()` — `listClient.listDatabases()` |
| Single database connection fails | Partial scrape error, other databases still collected | `scraper.go:scrape()` — per-database loop |
| Query timeout | Partial scrape error via context cancellation | All `client.go` query methods |
| Permission denied on pg_stat_activity | Query sample text shows `<insufficient privilege>`, skipped with WARN | `client.go:getQuerySamples()` |
| pg_stat_statements not installed | Top query collection fails, logged as ERROR | `client.go:getTopQuery()` |
| EXPLAIN fails for a query | Plan set to empty string, cached to avoid repeat errors, query still emitted | `client.go:explainQuery()` |
| Non-explainable query (DDL, etc.) | EXPLAIN silently skipped, returns empty plan | `client.go:isExplainableQuery()` |
| No WAL archive found | Silently returns (no error) — `errNoLastArchive` | `scraper.go:collectWalAge()` |
| Obfuscation failure | Query text set to empty string, logged as WARN | `client.go:getQuerySamples()`, `client.go:getTopQuery()` |
| Connection pool exhausted | Client creation fails, logged as ERROR | `client_factory.go:poolClientFactory.getClient()` |

---

## Permissions

### Minimum (metrics only)

```sql
-- Read-only access to statistics views
CREATE ROLE monitoring_user LOGIN PASSWORD 'password';
GRANT pg_monitor TO monitoring_user;
-- Or more granularly:
GRANT SELECT ON pg_stat_database TO monitoring_user;
GRANT SELECT ON pg_stat_bgwriter TO monitoring_user;
GRANT SELECT ON pg_stat_user_tables TO monitoring_user;
GRANT SELECT ON pg_statio_user_tables TO monitoring_user;
GRANT SELECT ON pg_stat_user_indexes TO monitoring_user;
GRANT SELECT ON pg_stat_replication TO monitoring_user;
GRANT SELECT ON pg_locks TO monitoring_user;
GRANT SELECT ON pg_stat_archiver TO monitoring_user;
GRANT SELECT ON pg_stat_user_functions TO monitoring_user;
```

### Query samples (additional)

```sql
-- pg_stat_activity access (shows query text for all backends)
GRANT SELECT ON pg_stat_activity TO monitoring_user;
```

### Top queries (additional)

```sql
-- pg_stat_statements extension must be installed
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
GRANT SELECT ON pg_stat_statements TO monitoring_user;
-- EXPLAIN requires access to the tables referenced in queries
-- The monitoring user needs at minimum SELECT on referenced tables
```

---

## Dependencies on Shared Code

| Package | Used For |
|---------|----------|
| `github.com/lib/pq` | PostgreSQL database driver (`database/sql` connector) |
| `github.com/hashicorp/golang-lru/v2` | LRU cache for top query delta computation |
| `github.com/hashicorp/golang-lru/v2/expirable` | TTL-based LRU cache for query plan caching |
| `github.com/DataDog/datadog-agent/pkg/obfuscate` | SQL and EXPLAIN plan obfuscation (postgresql DBMS mode) |
| `internal/sqlquery` | `DbClient` wrapper for template-based SQL queries (query samples, top queries) |
| `internal/common/priorityqueue` | Priority queue for ranking top queries by total_exec_time |
| `internal/common/testutil` | Feature gate test helpers (`SetFeatureGateForTest`) |
| `internal/coreinternal/scraperinttest` | Integration test framework with testcontainers |
| `pkg/golden` | Golden file reading for metric comparison tests |
| `pkg/pdatatest/pmetrictest` | Metric comparison assertions |
| `pkg/pdatatest/plogtest` | Log comparison assertions |

---

## Rollout Phases

### Phase 1: Foundation (P0)
- Metrics: existing enabled set (22 metrics)
- Config: no new fields
- Jira epic: TBD

### Phase 2: Advanced (P1)
- Metrics: TBD
- Jira epic: TBD

### Phase 3: Polish (P2)
- Metrics: TBD
- Jira epic: TBD

---

## Open Questions

| # | Question | Owner | Status |
|---|----------|-------|--------|
| 1 | Should connection pool feature gate be promoted to stable? | arch | Open |
| 2 | What new PostgreSQL-specific metrics do customers need? | PM | Open |
| 3 | Should `postgresql.wal.lag` (deprecated) be removed once `preciselagmetrics` gate reaches stable? | arch | Open |

---

## Change Log

| Date | PR | Section | What Changed | Why |
|------|-----|---------|-------------|-----|
| 2026-04-06 | foundation | All | Initial spec from codebase analysis | Foundation branch setup |
| 2026-04-06 | foundation | All | Updated to full template: added Query Source Map, Implementation Patterns, Test Patterns, Dependencies, detailed Error Handling, Validation Rules, Connection String Construction | Align with receiver-spec-template.md |
