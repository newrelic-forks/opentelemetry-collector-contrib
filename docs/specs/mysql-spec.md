# MySQL Receiver Spec

## Status: Draft
Last updated: 2026-04-06 via foundation branch
Approved by: —

---

## Receiver Identity

| Field | Value |
|-------|-------|
| Component | receiver/mysqlreceiver |
| Stability | Metrics: beta / Logs: development |
| Database versions supported | MySQL 8.0+, MariaDB 10.11+, MariaDB 11.x |
| Driver | `github.com/go-sql-driver/mysql` v1.9.3 |
| Priority | MEDIUM |

---

## Metrics & Log Events

Defined in `metadata.yaml` — the single source of truth for metric names, types, units,
enabled/disabled defaults, attributes, and log event schemas. Currently: **48 metrics**
(25 enabled, 23 disabled), **2 log events** (both disabled by default).

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
| `getGlobalStats` | `SHOW GLOBAL STATUS` | buffer_pool.*, double_writes, handlers, locks, log_operations, operations, page_operations, row_locks, row_operations, sorts, threads, tmp_resources, uptime, client.network.io, commands, connection.count, connection.errors, joins, max_used_connections, mysqlx_connections, mysqlx_worker_threads, opened_resources, prepared_statements, query.*, table_open_cache | ~66 status variables mapped via switch statement in `scrapeGlobalStats()` |
| `getInnodbStats` | `information_schema.innodb_metrics` | buffer_pool.limit | Single metric: `buffer_pool_bytes_data` |
| `getTableStats` | `information_schema.TABLES` | table.rows, table.average_row_length, table.size | Grouped by table_schema, table_name; size split by data_length and index_length |
| `getTableIoWaitsStats` | `performance_schema.table_io_waits_summary_by_table` | table.io.wait.count, table.io.wait.time | By operation (delete, fetch, insert, update), schema, table |
| `getIndexIoWaitsStats` | `performance_schema.table_io_waits_summary_by_index_usage` | index.io.wait.count, index.io.wait.time | By operation, schema, table, index |
| `getStatementEventsStats` | `performance_schema.events_statements_summary_by_digest` | statement_event.count, statement_event.wait.time | By schema, digest, digest_text; filtered by `digest_text_limit`, `limit`, `time_limit` |
| `getTableLockWaitEventStats` | `performance_schema.table_lock_waits_summary_by_table` | table.lock_wait.read.count/time, table.lock_wait.write.count/time | By operation, schema, table |
| `getReplicaStatusStats` | `SHOW REPLICA STATUS` or `SHOW SLAVE STATUS` | replica.sql_delay, replica.time_behind_source | Version-aware: MySQL 8.0.22+ uses `SHOW REPLICA STATUS`; older MySQL and MariaDB use `SHOW SLAVE STATUS` |
| `getVersion` | `SELECT VERSION()` | (internal) | Used to determine replica status command; parsed via `hashicorp/go-version` |
| `getQuerySamples` | `performance_schema.threads` JOIN `events_statements_current` JOIN `events_waits_current` JOIN `user_variables_by_thread` (template: `querySample.tmpl`) | log: db.server.query_sample | Extracts session_id, sql_text, digest, wait_event, traceparent |
| `getTopQueries` | `performance_schema.events_statements_summary_by_digest` (template: `topQuery.tmpl`) | log: db.server.top_query | Parameterized by lookbackTime and topNValue; excludes EXPLAIN and otel-collector-ignore queries |
| `explainQuery` | `EXPLAIN FORMAT=json` | (enrichment for top queries) | Checks truncation ("..." suffix), explainability (SELECT/DELETE/INSERT/REPLACE/UPDATE), switches schema via `USE` |

---

## Configuration

### Schema

```yaml
receivers:
  mysql:
    # Connection
    endpoint: "localhost:3306"
    transport: tcp
    username: "root"
    password: ""
    database: ""
    allow_native_passwords: true

    # TLS (defaults to insecure when not set)
    tls:
      insecure: true
      ca_file: ""
      cert_file: ""
      key_file: ""

    # Collection
    collection_interval: 10s
    initial_delay: 1s

    # Statement events (for statement_event metrics)
    statement_events:
      digest_text_limit: 120
      limit: 250
      time_limit: 24h

    # Top query collection
    top_query_collection:
      collection_interval: 60s
      lookback_time: 60
      max_query_sample_count: 1000
      top_query_count: 200
      query_plan_cache_size: 1000
      query_plan_cache_ttl: 1h

    # Query sample collection
    query_sample_collection:
      max_rows_per_query: 100
```

### Validation Rules (from `config.go`)

| Rule | Error |
|------|-------|
| No explicit `Validate()` method | Uses struct defaults only |
| TLS section not specified | Defaults to `insecure: true` via custom `Unmarshal` |
| `allow_native_passwords` not set | Defaults to `true` |

### Connection String Construction (from `client.go`)

Built in `mySQLClient.Connect()` via `mysql.Config.FormatDSN()`:
1. Creates `mysql.Config` with `User`, `Passwd`, `Net` (transport), `Addr` (endpoint), `DBName`
2. Sets `AllowNativePasswords` from config
3. If TLS is configured (not insecure), registers a custom TLS config via `mysql.RegisterTLSConfig("custom")` and sets `TLSConfig: "custom"`
4. Calls `cfg.FormatDSN()` to produce DSN string: `user:password@tcp(host:port)/dbname?allowNativePasswords=true&tls=custom`
5. Opens connection via `sql.Open("mysql", dsn)`

---

## Implementation Patterns

### How Scrapers Are Created

`factory.go:NewFactory()` registers two receiver factories:

1. **Metrics receiver** (`createMetricsReceiver`):
   - Creates `mySQLScraper` with a placeholder 1-entry LRU cache and 1-entry TTL cache
   - Wraps in `scraper.NewMetrics` with `scraper.WithStart` and `scraper.WithShutdown`
   - Returns via `scraperhelper.NewMetricsController`

2. **Logs receiver** (`createLogsReceiver`):
   - Conditionally adds log scrapers based on `cfg.Events.DbServerTopQuery.Enabled` and `cfg.Events.DbServerQuerySample.Enabled`
   - **Top query scraper**: sized LRU cache (`maxQuerySampleCount * 2 * 2`), expirable TTL cache (`queryPlanCacheSize`, `queryPlanCacheTTL`), calls `scrapeTopQueryFunc`
   - **Query sample scraper**: placeholder cache (size 1), calls `scrapeQuerySampleFunc`
   - Each log scraper added via `scraperhelper.AddFactoryWithConfig`
   - Returns via `scraperhelper.NewLogsController`

### Traced Example: Adding a Metric from SHOW GLOBAL STATUS

To add `mysql.new_metric` sourced from `SHOW GLOBAL STATUS`:

**Step 1: metadata.yaml** — Add the metric definition under `metrics:`.
**Step 2: Run `make generate`** in `receiver/mysqlreceiver/`.
**Step 3: scraper.go** — Add a case in the `scrapeGlobalStats()` switch statement to extract the value from the status key.
**Step 4: scraper.go** — Call `s.mb.RecordMysqlNewMetricDataPoint(now, value)`.
**Step 5: Tests** — Update mock expectations and golden file entries.

```go
// Step 3 example: add case in scrapeGlobalStats() switch
case "New_status_key":
    newMetric, err := parseInt(v)
    if err != nil {
        s.logInvalid("int", k, v)
        errs = append(errs, err)
    } else {
        s.mb.RecordMysqlNewMetricDataPoint(now, newMetric)
    }
```

### Traced Example: Adding a Metric from performance_schema

To add a metric from a new `performance_schema` view:

**Step 1: metadata.yaml** — Add metric definition.
**Step 2: Run `make generate`**.
**Step 3: client.go** — Add a new interface method and implementation query.
**Step 4: scraper.go** — Add a `scrape*` function called from `scrape()`, record data points.
**Step 5: factory.go** — Wire metric enablement check if needed.
**Step 6: Tests** — Update mock client, golden files.

### How Cache and Delta Computation Works

Used only for **top query** log events to compute deltas:

- **Cache type**: `hashicorp/golang-lru/v2` — non-expirable LRU
- **Key format**: `{schemaName}-{digest}-{column}` (e.g., `"mydb-abc123-sum_timer_wait"`)
- **Cache size**: `maxQuerySampleCount * 2 * 2` (headroom for multiple schemas × columns)
- **Delta logic** (`cacheAndDiff`): If key not cached, store current value and return `(false, 0)`. If cached, compute `diff = current - cached`. If diff > 0, update cache and return `(true, diff)`. If diff ≤ 0, update cache and return `(true, 0)`.
- **Delta columns**: `sum_timer_wait` (primary ranking column for top queries)

**Query plan cache** (separate):
- **Type**: `hashicorp/golang-lru/v2/expirable` — TTL-based LRU
- **Key format**: query digest string
- **Size**: configurable via `query_plan_cache_size` (default: 1000)
- **TTL**: configurable via `query_plan_cache_ttl` (default: 1h)
- **Purpose**: avoid re-running EXPLAIN for the same query within TTL

**Top query ranking**:
- Uses a priority queue (`internal/common/priorityqueue`) via `sortTopQueries()` to rank queries by `sum_timer_wait` delta descending, then emits the top N (`topQueryCount`)

### How Query Obfuscation Works

- **Library**: `github.com/DataDog/datadog-agent/pkg/obfuscate`
- **DBMS mode**: `mysql`
- **What gets obfuscated**:
  - SQL text: `obfuscateSQLString()` — replaces literal values with `?`
  - EXPLAIN plans: `obfuscatePlan()` — obfuscates SQL values in JSON plan keys while keeping structural keys
- **EXPLAIN plan keys**:
  - Obfuscated (`ObfuscateSQLValues`): `query`, `condition`, `operation`, `attached_condition`
  - Preserved (`KeepValues`): structural fields like `cost_info`, `access_type`, `table_name`, `key`, `key_length`, `possible_keys`, `ref`, `select_type`, `filtered`, `using_temporary_table`, `using_filesort`, `message`
- **Supports both MySQL EXPLAIN v1 and v2 formats** (v1: `query_block`, v2: `query_plan`)
- **Failure behavior**: on obfuscation error, logs WARN and returns empty string `""`
- **Lazy initialization**: `mySQLScraper.obfuscator` initialized in `mySQLScraper.start()` via `obfuscate.NewObfuscator()`

### How Resource Attributes Are Set

Resource attributes are set via `mb.EmitForResource()` and `lb.EmitForResource()` in `scraper.go`:

| Attribute | Source | When Set |
|-----------|--------|----------|
| `mysql.instance.endpoint` | Config endpoint (`host:port`) | Always (metrics and logs) |

### Receiver-Specific Patterns

**Version-aware replica status**: `getReplicaStatusStats()` checks the MySQL version via `hashicorp/go-version`. For MySQL ≥ 8.0.22, uses `SHOW REPLICA STATUS`. For older MySQL and MariaDB, falls back to `SHOW SLAVE STATUS`. Columns are dynamically scanned from the result set to handle varying column counts across versions.

**MariaDB compatibility**: Integration tests cover MariaDB 10.11.11 and 11.6.2 alongside MySQL 8.0.33. The version detection logic explicitly handles MariaDB version strings (which contain "MariaDB" suffix).

**Top query throttling**: `scrapeTopQueryFunc()` uses `lastExecutionTimestamp` to enforce `CollectionInterval` spacing between top query collections, preventing excessive queries to `performance_schema`.

**W3C TraceContext propagation**: `scrapeQuerySamples()` extracts the `@traceparent` MySQL user variable (set via `SET @traceparent = '...'` by instrumented applications) and parses it using `contextWithTraceparent()` to inject W3C-compliant trace context into emitted log records.

**Rename commands mapping**: The scraper maintains a `renameCommands` map to translate MySQL GLOBAL STATUS variable names to more descriptive metric attribute values (e.g., `Com_stmt_execute` → `execute`, `Com_stmt_prepare` → `prepare`).

**Template-based queries**: Both top query and query sample SQL are defined as Go `text/template` files (`templates/topQuery.tmpl`, `templates/querySample.tmpl`) rather than inline strings. Templates are parsed at compile time and executed with runtime parameters.

---

## Test Patterns

### Unit Tests

Pattern: Mock client interface via `fakeClient` implementing the `client` interface. Table-driven tests with golden file comparison.

```go
// Example: creating a test scraper with fake client
sc := newMySQLScraper(
    receivertest.NewNopSettings(metadata.Type),
    createDefaultConfig().(*Config),
    newCache[int64](100),
    newTTLCache[string](100, time.Hour),
)
sc.sqlclient = &fakeClient{/* configure return values */}
actualMetrics, err := sc.scrape(t.Context())
```

**To add test data for a new query:**
1. Add return values in the `fakeClient` implementation in `scraper_test.go`
2. Update golden YAML files under `testdata/scraper/` (expected metrics/logs)
3. Run `make test` and update golden files if needed

### Integration Tests

Pattern: `testcontainers-go` with MySQL and MariaDB Docker images via `scraperinttest` framework.

- **Container images**: `mysql:8.0.33` (with and without TLS), `mariadb:11.6.2`, `mariadb:10.11.11`
- **Build tag**: `//go:build integration`
- **Test matrix**: MySQL 8.0 (default, TLS), MariaDB 11.6, MariaDB 10.11
- **Comparison**: `pmetrictest.CompareMetrics` with golden YAML files under `testdata/integration/`

### Safety Tests

- `TestCreateDefaultConfig`: validates all default config values match expected defaults
- `TestValidConfig`: validates config loading from YAML test data

---

## Error Handling

| Scenario | Behavior | Code Location |
|----------|----------|---------------|
| Connection refused | `Connect()` fails, scraper start returns error | `client.go:Connect()` |
| Auth failure | `sql.Open` succeeds but first query fails, logged as ERROR | `client.go:Connect()` — `db.Ping()` |
| performance_schema disabled | IO wait, statement event, and lock wait metrics unavailable, logged as ERROR | `scraper.go:scrape()` — individual scrape* calls |
| Query timeout | Partial scrape error via context cancellation | All `client.go` query methods |
| Permission denied on performance_schema | Query fails, metrics for that group skipped, logged as ERROR | `scraper.go:scrape()` — errors appended to scrapedErrs |
| EXPLAIN fails for a query | Plan not captured, empty string cached to avoid repeat errors, query still emitted | `client.go:explainQuery()` |
| Query truncated (ends with "...") | EXPLAIN skipped — truncated queries are not explainable | `client.go:explainQuery()` |
| Non-explainable query (DDL, etc.) | EXPLAIN silently skipped, returns empty plan | `client.go:explainQuery()` — keyword check |
| No top queries in lookback window | No log records emitted for that interval | `scraper.go:scrapeTopQueries()` |
| SHOW REPLICA STATUS fails | Replica metrics skipped, logged as ERROR | `scraper.go:scrape()` — `scrapeReplicaStatusStats()` |
| Obfuscation failure | Query text set to empty string, logged as WARN | `obfuscate.go:obfuscateSQLString()` |
| EXPLAIN plan obfuscation failure | Plan set to empty string, logged as WARN | `obfuscate.go:obfuscatePlan()` |
| `innodb_metrics` query fails | `buffer_pool.limit` unavailable, logged as ERROR | `scraper.go:scrape()` — `scrapeInnodbStats()` |
| MariaDB version detection fails | Falls back to `SHOW SLAVE STATUS` | `client.go:getReplicaStatusStats()` |

---

## Permissions

### Minimum (metrics only)

```sql
-- Global status and variables
GRANT PROCESS ON *.* TO 'monitoring_user'@'%';  -- For SHOW GLOBAL STATUS

-- performance_schema access (for IO wait, statement events, lock wait metrics)
GRANT SELECT ON performance_schema.table_io_waits_summary_by_table TO 'monitoring_user'@'%';
GRANT SELECT ON performance_schema.table_io_waits_summary_by_index_usage TO 'monitoring_user'@'%';
GRANT SELECT ON performance_schema.events_statements_summary_by_digest TO 'monitoring_user'@'%';
GRANT SELECT ON performance_schema.table_lock_waits_summary_by_table TO 'monitoring_user'@'%';

-- information_schema access
GRANT SELECT ON information_schema.TABLES TO 'monitoring_user'@'%';
GRANT SELECT ON information_schema.innodb_metrics TO 'monitoring_user'@'%';
```

### Query samples (additional)

```sql
GRANT SELECT ON performance_schema.threads TO 'monitoring_user'@'%';
GRANT SELECT ON performance_schema.events_statements_current TO 'monitoring_user'@'%';
GRANT SELECT ON performance_schema.events_waits_current TO 'monitoring_user'@'%';
GRANT SELECT ON performance_schema.user_variables_by_thread TO 'monitoring_user'@'%';
```

### Top queries (additional)

```sql
GRANT SELECT ON performance_schema.events_statements_summary_by_digest TO 'monitoring_user'@'%';
-- EXPLAIN requires SELECT on queried tables
```

### Replica status

```sql
GRANT REPLICATION CLIENT ON *.* TO 'monitoring_user'@'%';  -- For SHOW REPLICA STATUS
```

---

## Dependencies on Shared Code

| Package | Used For |
|---------|----------|
| `github.com/go-sql-driver/mysql` | MySQL database driver (`database/sql`) |
| `github.com/hashicorp/golang-lru/v2` | LRU cache for top query delta computation |
| `github.com/hashicorp/golang-lru/v2/expirable` | TTL-based LRU cache for query plan caching |
| `github.com/hashicorp/go-version` | MySQL/MariaDB version parsing for replica status command selection |
| `github.com/DataDog/datadog-agent/pkg/obfuscate` | SQL and EXPLAIN plan obfuscation (mysql DBMS mode) |
| `internal/common/priorityqueue` | Priority queue for ranking top queries by sum_timer_wait |
| `internal/coreinternal/scraperinttest` | Integration test framework with testcontainers |
| `pkg/golden` | Golden file reading for metric comparison tests |
| `pkg/pdatatest/pmetrictest` | Metric comparison assertions |
| `pkg/pdatatest/plogtest` | Log comparison assertions |

---

## Rollout Phases

### Phase 1: Foundation (P0)
- Metrics: existing enabled set (25 metrics)
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
| 1 | Should we support connection pooling (like PostgreSQL receiver)? | arch | Open |
| 2 | What new MySQL-specific metrics do customers need? | PM | Open |
| 3 | Should `page_size` metric source be changed from GLOBAL VARIABLES to GLOBAL STATUS? | arch | Open |

---

## Change Log

| Date | PR | Section | What Changed | Why |
|------|-----|---------|-------------|-----|
| 2026-04-06 | foundation | All | Initial spec from codebase analysis | Foundation branch setup |
| 2026-04-06 | foundation | All | Updated to full template: added Query Source Map, Implementation Patterns, Test Patterns, Dependencies, detailed Error Handling with code locations, Connection String Construction, Receiver-Specific Patterns | Align with receiver-spec-template.md |
