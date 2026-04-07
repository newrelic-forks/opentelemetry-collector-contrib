# SQL Server Receiver Spec

## Status: Draft
Last updated: 2026-04-06 via foundation branch
Approved by: —

---

## Receiver Identity

| Field | Value |
|-------|-------|
| Component | receiver/sqlserverreceiver |
| Stability | Metrics: beta / Logs: development |
| Database versions | SQL Server 2012+ (Standard, Enterprise, Express, Developer), Azure SQL Database, Azure SQL Managed Instance |
| Driver | `github.com/microsoft/go-mssqldb` (with Kerberos: `integratedauth/krb5`) |
| Priority | HIGH |

---

## Metrics & Log Events

Defined in `metadata.yaml` — the single source of truth for metric names, types, units,
enabled/disabled defaults, attributes, and log event schemas. Currently: **50 metrics**
(24 enabled, 26 disabled), **2 log events** (both disabled by default).

Do NOT duplicate the metrics catalog here. Any new metric or attribute change starts
in `metadata.yaml`, then gets wired through the implementation patterns below.

---

## Query Source Map

Each metric group is sourced from a specific SQL query. The query functions are in `queries.go`.

| Query Function | Source DMV/View | Metrics Group | File:Line Reference |
|---------------|-----------------|---------------|---------------------|
| `getSQLServerDatabaseIOQuery(instanceName)` | `sys.dm_io_virtual_file_stats` JOIN `sys.master_files` | `sqlserver.database.latency`, `sqlserver.database.operations`, `sqlserver.database.io` | `queries.go` — returns inline SQL string, filters by instanceName when set |
| `getSQLServerPerformanceCounterQuery(instanceName)` | `sys.dm_os_performance_counters` | `sqlserver.batch.*`, `sqlserver.lock.*`, `sqlserver.page.buffer_cache.hit_ratio`, `sqlserver.page.life_expectancy`, `sqlserver.page.lookup.rate`, `sqlserver.user.connection.count`, `sqlserver.processes.blocked`, and 17 more perf counter metrics | `queries.go` — large CASE/WHEN pivot query |
| `getSQLServerPropertiesQuery(instanceName)` | `sys.dm_os_sys_info`, `sys.databases` | `sqlserver.computer.uptime`, `sqlserver.cpu.count`, `sqlserver.database.count` | `queries.go` — server properties |
| `getSQLServerWaitStatsQuery(instanceName)` | `sys.dm_os_wait_stats` | `sqlserver.os.wait.duration` | `queries.go` — by wait_category and wait_type |
| `getSQLServerQueryTextAndPlanQuery()` | `sys.dm_exec_query_stats` JOIN `sys.dm_exec_sql_text` JOIN `sys.dm_exec_query_plan` | `db.server.top_query` log event | `queries.go` — uses `go:embed templates/dbQueryAndTextQuery.tmpl` |
| `getSQLServerQuerySamplesQuery()` | `sys.dm_exec_requests` JOIN `sys.dm_exec_sessions` JOIN `sys.dm_exec_sql_text` | `db.server.query_sample` log event | `queries.go` — uses `go:embed templates/sqlServerQuerySample.tmpl` |

### Windows Performance Counters (Windows only, no DB connection)

Defined in `recorders.go` via `perfCounterRecorders` slice. Each entry maps a Windows
Performance Counter object + counter path to a metric recorder function. Counter paths
use the format `\SQLServer:{Object}\{Counter}` (or `\MSSQL${InstanceName}:{Object}\{Counter}`
for named instances).

| PC Object | Counters | Metrics |
|-----------|----------|---------|
| General Statistics | User Connections | `sqlserver.user.connection.count` |
| SQL Statistics | Batch Requests/sec, SQL Compilations/sec, SQL Re-Compilations/sec | `sqlserver.batch.*` |
| Locks(_Total) | Lock Waits/sec, Average Wait Time (ms) | `sqlserver.lock.*` |
| Buffer Manager | Buffer cache hit ratio, Page life expectancy, Lazy writes/sec, Checkpoint pages/sec, Page reads/sec, Page writes/sec | `sqlserver.page.*` |
| Access Methods(_Total) | Page Splits/sec | `sqlserver.page.split.rate` |
| Databases(*) | Transactions/sec, Write Transactions/sec, Log Flushes/sec, Log Flush Waits/sec, Log Bytes Flushed/sec, Log Growths, Log Shrinks, Percent Log Used | `sqlserver.transaction.*`, `sqlserver.transaction_log.*` |

---

## Configuration

### Schema

```yaml
receivers:
  sqlserver:
    # Connection — choose ONE of datasource or server/username/password/port
    datasource: ""                    # Full DSN (server=X;user id=X;password=X;port=X) or URL format
    server: ""                        # Server hostname
    username: ""                      # SQL Server username
    password: ""                      # SQL Server password (configopaque.String)
    port: 0                           # TCP port (default 1433 when connecting)

    # Instance identity (Windows only — rejected on other platforms)
    instance_name: ""                 # Named instance
    computer_name: ""                 # Required if instance_name is set (Windows only)

    # Collection
    collection_interval: 10s
    initial_delay: 1s

    # Top query collection
    top_query_collection:
      collection_interval: 1m         # Independent from main collection_interval
      lookback_time: 0s               # 0 = 2x collection_interval (EffectiveLookbackTime())
      max_query_sample_count: 1000    # Valid: 0–10000
      top_query_count: 250            # Must be <= max_query_sample_count

    # Query sample collection
    query_sample_collection:
      max_rows_per_query: 100
```

### Validation Rules (from `config.go:Validate()`)

| Rule | Error |
|------|-------|
| `datasource` and `server/username/password/port` are mutually exclusive | "datasource cannot be used with server/username/password/port" |
| If any of `server`, `username`, `password`, `port` is set, ALL must be set | "all of server, username, password, port must be specified" |
| `instance_name` requires `computer_name` on Windows | "instance_name and computer_name must be set together" |
| `instance_name`/`computer_name` silently ignored on non-Windows | `config_others.go:validateInstanceAndComputerName()` is no-op |
| `lookback_time` must be >= 0 | "lookback_time must be >= 0" |
| `max_query_sample_count` must be 0–10000 | "max_query_sample_count must be between 0 and 10000" |
| `top_query_count` must be <= `max_query_sample_count` | "top_query_count must be <= max_query_sample_count" |

### Connection String Construction (from `factory.go:getDBConnectionString()`)

When `datasource` is empty, connection string is built as:
```
server={Server};user id={Username};password={Password};port={Port}
```

---

## Implementation Patterns

### How Scrapers Are Created

The factory (`factory.go`) creates scrapers through this flow:

1. `createMetricsReceiver()` → `setupScrapers()` → `setupSQLServerScrapers()`
2. `createLogsReceiver()` → `setupLogsScrapers()` → `setupSQLServerLogsScrapers()`

`setupSQLServerScrapers()` is the key function. It checks which metrics are enabled
in the config and creates a `sqlServerScraperHelper` for each SQL query that has
at least one enabled metric. Each scraper gets:
- The SQL query string
- A `DbProviderFunc` (creates `*sql.DB`)
- A `ClientProviderFunc` (wraps `*sql.DB` into `sqlquery.DbClient`)
- The receiver `Config`
- An LRU cache (for delta computation in logs scrapers)

On Windows, a separate `sqlServerPCScraper` is additionally created for Performance
Counter collection. Both PC and direct DB scrapers run within the same `MetricsController`.

### Traced Example: Adding a Metric from dm_os_performance_counters

To add `sqlserver.foo.bar` sourced from `dm_os_performance_counters`:

**Step 1: metadata.yaml** — Add the metric definition:
```yaml
metrics:
  sqlserver.foo.bar:
    enabled: false
    description: Description here
    stability: development
    unit: "{unit}"
    gauge:
      value_type: double
```

**Step 2: Run `make generate`** in receiver directory to regenerate `internal/metadata/`.

**Step 3: queries.go** — Add the counter to `getSQLServerPerformanceCounterQuery()`.
The function builds a large SQL query with CASE/WHEN blocks. Add a new WHEN clause
for the performance counter name, mapping it to the metric field name:
```sql
WHEN counter_name = 'Foo Bar' AND object_name LIKE '%:General Statistics%'
  THEN 'sqlserver.foo.bar'
```

**Step 4: scraper.go** — Add a `record*` case in `ScrapeMetrics()`. The method matches
on `scraper.sqlQuery` to route to the correct recording function. Inside the recording
function (e.g., `recordDatabasePerformanceCounters`), add:
```go
case "sqlserver.foo.bar":
    val, err := strconv.ParseFloat(row[valueKey], 64)
    if err != nil { ... }
    s.mb.RecordSqlserverFooBarDataPoint(now, val)
```

**Step 5: factory.go** — In `setupSQLServerScrapers()`, ensure the perf counter query
is created when `cfg.Metrics.SqlserverFooBar.Enabled` is true. Add it to the
`enabledPerformanceCounterMetrics` check.

**Step 6: Tests** — Update `testdata/perfCounterQueryData.txt` to include the new
counter data, and update the expected golden file. The test framework uses
`golden.ReadMetrics()` / `pmetrictest.CompareMetrics()`.

**Step 7 (Windows only): recorders.go** — Add an entry to `perfCounterRecorders`:
```go
{
    object: "General Statistics",
    recorders: map[string]recordFunc{
        "Foo Bar": func(mb *metadata.MetricsBuilder, now pcommon.Timestamp, val float64, _ string) {
            mb.RecordSqlserverFooBarDataPoint(now, val)
        },
    },
},
```

### Traced Example: Adding a Metric from a New DMV Query

To add `sqlserver.new_thing` sourced from a NEW DMV (e.g., `sys.dm_db_resource_stats`):

**Step 1–2:** Same as above (metadata.yaml + make generate).

**Step 3: queries.go** — Add a new query function:
```go
func getSQLServerResourceStatsQuery(instanceName string) string {
    // Return the SQL query string, optionally filtering by instanceName
}
```

**Step 4: scraper.go** — Add a new `record*` method and add a new case in
`ScrapeMetrics()` routing based on the query string.

**Step 5: factory.go** — In `setupSQLServerScrapers()`, add a new scraper creation
block that checks if the relevant metric(s) are enabled, creates the scraper with the
new query, and appends it to the scrapers slice. Follow the existing pattern:
```go
if cfg.Metrics.SqlserverNewThing.Enabled {
    scrapers = append(scrapers, newSQLServerScraper(..., getSQLServerResourceStatsQuery(cfg.InstanceName), ...))
}
```

**Step 6:** Add test data files and golden files.

### How Cache and Delta Computation Works (Logs/Top Query)

`cacheAndDiff(queryHash, queryPlanHash, procedureID, column, currentValue)`:
- Cache key: `{queryHash}-{queryPlanHash}-{procedureID}-{column}`
- First call for a key: stores value, returns `(false, currentValue)` — not cached yet
- Subsequent calls: computes `currentValue - cachedValue`, updates cache, returns `(true, delta)`
- Negative `currentValue` (-1): means column was NULL/unparseable, cache entry removed
- Cache is LRU with size `maxQuerySampleCount * 8 * 2` entries

Top queries are ranked by `total_elapsed_time` delta (descending), using `sortRows()`.

### How Query Obfuscation Works

`obfuscate.go` provides two methods:
- `obfuscateSQLString(sql)` — uses DataDog `obfuscate.NewObfuscator` with MSSQL DBMS type
- `obfuscateXMLPlan(xmlPlan)` — walks XML tokens, obfuscates `StatementText`, `ConstValue`, `ScalarString`, `ParameterCompiledValue` attributes via the SQL obfuscator. If any attribute obfuscation fails, returns empty string (not error).

### How Resource Attributes Are Set

`setupResourceBuilder()` in `scraper.go` sets resource attributes from two sources:
1. **Config:** `host.name` from `Server` or parsed from `DataSource`, `server.address`, `server.port`, `service.instance.id` (via `computeServiceInstanceID`)
2. **Query row data:** `sqlserver.computer.name`, `sqlserver.instance.name`, `sqlserver.database.name` from the `computer_name`, `instance_name`, `database_name` columns in query results

`computeServiceInstanceID()` in `service_instance_id.go`: Returns `host:port`. Resolves `localhost`/`127.0.0.1` to actual hostname. Parses DSN via `msdsn.Parse()`. Default port is 1433.

### Feature Gate

| Gate ID | Stage | Effect |
|---------|-------|--------|
| `receiver.sqlserver.RemoveServerResourceAttribute` | alpha (v0.129.0+) | When enabled, removes `server.address` and `server.port` from metrics resource attributes |

---

## Test Patterns

### Unit Tests (scraper_test.go)

Pattern: **mock client with JSON test data files**.

```go
// 1. Create config with direct DB connection
cfg := createDefaultConfig().(*Config)
cfg.Username = "sa"; cfg.Password = "password"; cfg.Server = "0.0.0.0"; cfg.Port = 1433

// 2. Enable desired metrics/events
cfg.Metrics.SqlserverDatabaseLatency.Enabled = true

// 3. Create scrapers via setupSQLServerScrapers()
scrapers := setupSQLServerScrapers(receivertest.NewNopSettings(metadata.Type), cfg)

// 4. Replace real client with mockClient (routes SQL query → test data file)
scraper.client = mockClient{instanceName: scraper.config.InstanceName, SQL: scraper.sqlQuery}

// 5. Scrape and compare with golden file
actualMetrics, err := scraper.ScrapeMetrics(t.Context())
expectedMetrics, _ := golden.ReadMetrics(filepath.Join("testdata", "expectedDatabaseIO.yaml"))
pmetrictest.CompareMetrics(expectedMetrics, actualMetrics, pmetrictest.IgnoreMetricDataPointsOrder(), ...)
```

**mockClient** (`scraper_test.go:311-368`): Implements `sqlquery.DbClient`. Routes
`QueryRows()` to the correct test data file based on SQL query string matching (same
pattern as the real scraper). Test data files are in `testdata/` as JSON arrays of
`sqlquery.StringMap` objects.

**To add test data for a new query:**
1. Create `testdata/myNewQueryData.txt` with JSON array of `StringMap`
2. Add a case to `mockClient.QueryRows()` matching the new query
3. Create expected golden file `testdata/expectedMyNewQuery.yaml`
4. Use `golden.WriteMetrics(t, expectedFile, actualMetrics)` to generate initial golden file

### Unit Tests (scraper_windows_test.go)

Pattern: **mock PerfCounterWatcher**.

Uses `mockPerfCounterWatcher` (testify mock) returning canned `CounterValue` slices.
Tests validate against golden YAML files (`testdata/golden_scrape.yaml`).

### Integration Tests (integration_test.go)

Pattern: **testcontainers-go** with `mcr.microsoft.com/mssql/server:2022-latest`.

Setup: Container with `Developer` edition, init script at `testdata/integration/01-init.sh`
creates a test database, user, and table. Tests simulate real client queries and validate
that scraped log records contain expected data. Build tag: `//go:build integration`.

### Safety Test (factory_test.go:TestSetupQueries)

Reads `metadata.yaml` at test time and asserts exactly 50 metrics exist. If metrics
are added or removed, this test forces you to also update `setupQueries` — prevents
metrics from being added to `metadata.yaml` without being wired into the factory.

---

## Error Handling

| Scenario | Behavior | Code Location |
|----------|----------|---------------|
| Connection refused | `scraper.Start()` fails, logged as ERROR | `scraper.go:Start()` |
| Auth failure | `scraper.Start()` fails, logged as ERROR | `scraper.go:Start()` |
| Query timeout | Scrape returns error, controller handles retry | `scraper.go:ScrapeMetrics()` |
| Permission denied on DMV | Query returns error, logged as WARN | `scraper.go` record methods |
| NULL values in result rows | `sqlquery.ErrNullValueWarning`, row processed with zero value | Throughout scraper.go |
| String parse failure for numeric field | Logged as WARN, field skipped | Throughout scraper.go record methods |
| Invalid SQL query (no match in router) | Returns error, empty metrics | `scraper.go:ScrapeMetrics()` default case |
| SQL obfuscation failure | Row skipped, logged as WARN | `scraper.go` via `obfuscator.obfuscateSQLString()` |
| XML plan obfuscation failure | Returns empty string (not error), plan omitted | `obfuscate.go:obfuscateXMLPlan()` |
| No direct DB connection configured | INFO log, direct DB scrapers not created (Windows PC still works) | `factory.go:setupScrapers()` |
| No metrics enabled for a query | Scraper not created for that query | `factory.go:setupSQLServerScrapers()` |
| Windows PC counter not found | Logged as WARN per counter, scraping continues for found counters | `scraper_windows.go:start()` |
| Top query collection interval not elapsed | ScrapeLogs returns empty, no error | `scraper.go:ScrapeLogs()` |
| Negative cache delta (counter reset) | For top queries: value still emitted. Cache stores new value. | `scraper.go:cacheAndDiff()` |
| Multi-statement proc duplicate rows | Deduplicated by matching on `query_hash + query_plan_hash` (not just plan_handle) | `templates/dbQueryAndTextQuery.tmpl` JOIN condition |

---

## Permissions

### Minimum (metrics only — direct DB connection)

```sql
GRANT VIEW SERVER STATE TO [monitoring_user];
-- Azure SQL Database: GRANT VIEW DATABASE STATE TO [monitoring_user];
```

### Query samples + Top queries (same permission)

```sql
-- Uses dm_exec_requests, dm_exec_sessions, dm_exec_sql_text,
-- dm_exec_query_stats, dm_exec_query_plan — all covered by:
GRANT VIEW SERVER STATE TO [monitoring_user];
```

### Windows Performance Counters

No SQL permissions required. Collector process needs access to Windows Performance
Counters (any authenticated user).

---

## Dependencies on Shared Code

| Package | Used For |
|---------|----------|
| `internal/sqlquery` | `DbClient` interface, `DbProviderFunc`, `ClientProviderFunc`, `StringMap`, `TelemetryConfig`, `NullStringMap` |
| `internal/common/priorityqueue` | Not used (SQL Server uses custom `sortRows()`) |
| `pkg/winperfcounters` | `PerfCounterWatcher` interface (Windows only) |
| `pkg/golden` | Golden file test utilities |
| `pkg/pdatatest/pmetrictest` | Metric comparison in tests |
| `DataDog/datadog-agent/pkg/obfuscate` | SQL string and XML plan obfuscation |
| `hashicorp/golang-lru/v2` | LRU cache for top query delta computation |

---

## Rollout Phases

### Phase 1: Foundation (P0)
- Metrics: existing enabled set (24 metrics)
- Config: no new fields
- Jira epic: TBD

### Phase 2: Advanced (P1)
- Metrics: TBD (customer-driven)
- Jira epic: TBD

### Phase 3: Polish (P2)
- Metrics: TBD
- Jira epic: TBD

---

## Open Questions

| # | Question | Owner | Status |
|---|----------|-------|--------|
| 1 | Should we add connection pooling for direct DB connections? | arch | Open |
| 2 | Can we unify Windows PC + direct DB metric overlap? | arch | Open |
| 3 | What are the specific new metrics customers need? | PM | Open |

---

## Change Log

| Date | PR | Section | What Changed | Why |
|------|-----|---------|-------------|-----|
| 2026-04-06 | foundation | All | Initial spec from full codebase analysis | Foundation branch setup |
