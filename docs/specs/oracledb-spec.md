# Oracle DB Receiver Spec

## Status: Draft
Last updated: 2026-04-06 via foundation branch
Approved by: —

---

## Receiver Identity

| Field | Value |
|-------|-------|
| Component | receiver/oracledbreceiver |
| Stability | Metrics: alpha / Logs: development |
| Database versions | Oracle 19c+ (uses V$SQL, V$SESSION, V$SQL_PLAN, DBA_TABLESPACE_USAGE_METRICS) |
| Driver | `github.com/sijms/go-ora/v2` |
| Priority | HIGH |

---

## Metrics & Log Events

Defined in `metadata.yaml` — the single source of truth for metric names, types, units,
enabled/disabled defaults, attributes, and log event schemas. Currently: **42 metrics**
(25 enabled, 17 disabled), **2 log events** (both disabled by default).

Do NOT duplicate the metrics catalog here. Any new metric or attribute change starts
in `metadata.yaml`, then gets wired through the implementation patterns below.

---

## Query Source Map

All SQL queries are defined as constants in `scraper.go`. Templates are embedded via `go:embed`.

| Query Constant / Template | Source View | Metrics Group | Notes |
|--------------------------|-------------|---------------|-------|
| `statsSQL` | `V$SYSSTAT` | 27 metrics: enqueue/exchange deadlocks, executions, parse calls, hard parses, logons, user commits/rollbacks, physical reads/writes (direct, IO requests), parallel operations (7 variants), logical reads, CPU time, PGA memory, db block gets, consistent gets | Single `SELECT * FROM V$SYSSTAT`, rows matched by `NAME` column |
| `sessionCountSQL` | `V$SESSION` | `oracledb.sessions.usage` | `GROUP BY status, type` — returns count by session type and status |
| `systemResourceLimitsSQL` | `V$RESOURCE_LIMIT` | `oracledb.processes.{usage,limit}`, `oracledb.sessions.limit`, `oracledb.enqueue_locks.{usage,limit}`, `oracledb.dml_locks.{usage,limit}`, `oracledb.enqueue_resources.{usage,limit}`, `oracledb.transactions.{usage,limit}` | Rows matched by `RESOURCE_NAME` column. UNLIMITED values converted to `-1` |
| `tablespaceUsageSQL` | `DBA_TABLESPACE_USAGE_METRICS` JOIN `DBA_TABLESPACES` | `oracledb.tablespace_size.{usage,limit}` | Block counts multiplied by `BLOCK_SIZE` to get bytes. Empty `TABLESPACE_SIZE` → `-1` for backward compat |
| `oracleQueryMetricsAndTextSql.tmpl` | `V$SQL` LEFT JOIN `DBA_PROCEDURES` LEFT JOIN `V$SQL` (self-join for proc executions) | `db.server.top_query` log event | Embedded via `go:embed`. Bind params: `:1` = lookback seconds, `:2` = max rows. Filters by `LAST_ACTIVE_TIME >= SYSDATE - NUMTODSINTERVAL(:1, 'SECOND')` |
| `oracleQueryPlanSql.tmpl` | `V$SQL_PLAN` | Execution plans for top queries | Embedded via `go:embed`. `WHERE CHILD_ADDRESS IN (HEXTORAW(:1), ...)` — placeholders built dynamically per batch |
| `oracleQuerySampleSql.tmpl` | `V$SESSION` JOIN `V$SQL` LEFT JOIN `DBA_PROCEDURES` | `db.server.query_sample` log event | Embedded via `go:embed`. Bind param: `:1` = max rows. Filters `WHERE S.SQL_ID IS NOT NULL AND S.STATUS = 'ACTIVE'` |

---

## Configuration

### Schema

```yaml
receivers:
  oracledb:
    # Connection — choose ONE of datasource or endpoint/username/password/service
    datasource: ""                     # Full Oracle URL (oracle://user:pass@host:port/service)
    endpoint: ""                       # host:port
    username: ""
    password: ""
    service: ""                        # Oracle service name

    # Collection
    collection_interval: 10s
    initial_delay: 1s

    # Top query collection
    top_query_collection:
      collection_interval: 1m          # Independent from main collection_interval
      max_query_sample_count: 1000     # Valid: 1–10000
      top_query_count: 200             # Valid: 1–200, must be <= max_query_sample_count

    # Query sample collection
    query_sample_collection:
      max_rows_per_query: 100
```

### Validation Rules (from `config.go:Validate()`)

| Rule | Error |
|------|-------|
| If `datasource` is empty, `endpoint` must be set | `errEmptyEndpoint` |
| `endpoint` must be `host:port` format with valid host | `errBadEndpoint` |
| Port must be 0–65535 | `errBadPort` |
| If `datasource` is empty, `username` required | `errEmptyUsername` |
| If `datasource` is empty, `password` required | `errEmptyPassword` |
| If `datasource` is empty, `service` required | `errEmptyService` |
| If `datasource` is set, it must be a valid URL | `errBadDataSource` |
| `datasource` takes precedence — other connection fields ignored when set | — |
| `max_query_sample_count` must be 1–10000 | `errMaxQuerySampleCount` |
| `top_query_count` must be 1–200 and <= `max_query_sample_count` | `errTopQueryCount` |

### Connection String Construction (from `factory.go:getDataSource()`)

When `datasource` is empty, connection URL is built via:
```go
go_ora.BuildUrl(host, port, service, username, password, nil)
// Produces: oracle://username:password@host:port/service
```

When `datasource` is set, it is used directly.

`getInstanceName()` parses the datasource URL and returns `host:port/service`.
`getHostName()` parses the datasource URL and returns `host:port`.

---

## Implementation Patterns

### How Scrapers Are Created

The factory (`factory.go`) creates two independent receivers:

1. `createReceiverFunc()` → creates a single `oracleScraper` via `newScraper()` for metrics
2. `createLogsReceiverFunc()` → creates a single `oracleScraper` via `newLogsScraper()` for logs

Both use the same `oracleScraper` struct but separate instances. The logs scraper gets
additional fields: `metricCache` (LRU), `topQueryCollectCfg`, `querySampleCfg`, `obfuscator`.

On `start()`, the scraper opens a DB connection and creates 4 `dbClient` instances
for metrics collection (stats, sessionCount, systemResourceLimits, tablespaceUsage)
and 1 for query samples. The top query and plan clients are created dynamically during
each scrape because the plan query has dynamic placeholders.

### Traced Example: Adding a Metric from V$SYSSTAT

To add `oracledb.new_stat` sourced from `V$SYSSTAT`:

**Step 1: metadata.yaml** — Add the metric definition:
```yaml
metrics:
  oracledb.new_stat:
    enabled: false
    description: Description here
    stability: development
    sum:
      aggregation_temporality: cumulative
      monotonic: true
      value_type: int
      input_type: string
    unit: "{unit}"
```

**Step 2: Run `make generate`** in receiver directory to regenerate `internal/metadata/`.

**Step 3: scraper.go** — Add a constant for the V$SYSSTAT `NAME` value:
```go
const newStat = "new stat name from V$SYSSTAT"
```

**Step 4: scraper.go** — Add the metric to the `runStats` enablement check (the large `||` block):
```go
runStats := s.metricsBuilderConfig.Metrics.OracledbEnqueueDeadlocks.Enabled ||
    // ... existing checks ...
    s.metricsBuilderConfig.Metrics.OracledbNewStat.Enabled
```

**Step 5: scraper.go** — Add a `case` in the `switch row["NAME"]` block inside `scrape()`:
```go
case newStat:
    err := s.mb.RecordOracledbNewStatDataPoint(now, row["VALUE"])
    if err != nil {
        scrapeErrors = append(scrapeErrors, err)
    }
```

**Step 6: Tests** — Update the `queryResponses` map in `scraper_test.go` to include
the new stat name and value. Update the expected metric count assertion
(`assert.Equal(t, 18, m.ResourceMetrics()...Metrics().Len())`) to the new count.

### Traced Example: Adding a Metric from a New View

To add `oracledb.new_thing` from a new view (e.g., `V$SYSMETRIC`):

**Step 1–2:** Same as above (metadata.yaml + make generate).

**Step 3: scraper.go** — Add a new SQL constant:
```go
const newThingSQL = "SELECT metric_name, value FROM V$SYSMETRIC WHERE ..."
```

**Step 4: scraper.go** — Add a new `dbClient` field to `oracleScraper`:
```go
type oracleScraper struct {
    // ... existing fields ...
    newThingClient dbClient
}
```

**Step 5: scraper.go** — Initialize the client in `start()`:
```go
s.newThingClient = s.clientProviderFunc(s.db, newThingSQL, s.logger)
```

**Step 6: scraper.go** — Add collection logic in `scrape()` with enablement check:
```go
if s.metricsBuilderConfig.Metrics.OracledbNewThing.Enabled {
    rows, err := s.newThingClient.metricRows(ctx)
    if err != nil {
        scrapeErrors = append(scrapeErrors, fmt.Errorf("error executing %s: %w", newThingSQL, err))
    }
    for _, row := range rows {
        // record metric from row
    }
}
```

**Step 7: Tests** — Add `newThingSQL` to `queryResponses` map, add a fakeDbClient
routing case, update assertions.

### How Cache and Delta Computation Works (Top Queries)

`collectTopNMetricData()` uses an LRU cache sized at `MaxQuerySampleCount * 2`:

- **Cache key:** `{sqlID}:{childNumber}` (e.g., `fxk8aq3nds8aw:0`)
- **Cache value:** `map[string]int64` — all 17 metric column values for that query
- **First scrape for a key:** stores values, no log record emitted (need two scrapes for delta)
- **Subsequent scrapes:** compute `delta = newValue - oldValue` for each metric
- **Negative delta on any metric:** possible cursor purge from shared pool → row discarded
- **Zero execution count delta:** no new executions since last scrape → row discarded
- **Ranking:** `sort.Slice` by `ELAPSED_TIME` delta descending, truncated to `TopQueryCount`

The 17 delta metrics are: `EXECUTIONS`, `ELAPSED_TIME`, `CPU_TIME`, `APPLICATION_WAIT_TIME`,
`CONCURRENCY_WAIT_TIME`, `USER_IO_WAIT_TIME`, `CLUSTER_WAIT_TIME`, `ROWS_PROCESSED`,
`BUFFER_GETS`, `PHYSICAL_READ_REQUESTS`, `PHYSICAL_WRITE_REQUESTS`, `PHYSICAL_READ_BYTES`,
`PHYSICAL_WRITE_BYTES`, `DIRECT_READS`, `DIRECT_WRITES`, `DISK_READS`, `PROCEDURE_EXECUTIONS`.

Time metrics (ELAPSED_TIME, CPU_TIME, wait times) are stored in microseconds in V$SQL
and converted to seconds via `asFloatInSeconds()` (divide by 1,000,000) when emitting.

### V$SQL Lookback Time Calculation

`calculateLookbackSeconds()`:
- First collection: uses `CollectionInterval` (default: 60s)
- Subsequent: `now + 10s buffer - lastExecutionTimestamp` (ceiling to int)
- The 10s buffer accounts for V$SQL refresh lag (documented up to 5s) plus 5s for collection delays

### How Query Plan Retrieval Works

After selecting top N queries, plans are fetched in a single batch:
1. Build `HEXTORAW(:N)` placeholders for each hit's `CHILD_ADDRESS`
2. Format `oracleQueryPlanDataSQL` template with placeholders
3. Execute with all child addresses as bind params
4. Group returned rows by `CHILD_ADDRESS` into a `map[string][]metricRow`
5. Marshal each plan to JSON string for the log record

### How Query Obfuscation Works

`obfuscate.go` provides `obfuscateSQLString(sql)`:
- Uses DataDog `obfuscate.NewObfuscator` with `DBMS: "oracle"`
- Returns obfuscated query text with literals replaced by `?`
- On failure: returns error (caller decides whether to skip or continue)

For top queries: obfuscation failure → row skipped with Warn log, scrape continues.
For query samples: obfuscation failure → row skipped with Error log, scrape continues.

### How Resource Attributes Are Set

`setupResourceBuilder()` in `scraper.go`:
- `oracledb.instance.name` ← `instanceName` (parsed from datasource: `host:port/service`)
- `host.name` ← `hostName` (parsed from datasource: `host:port`)
- `service.instance.id` ← `getInstanceID()`: returns `host:port/service`. Resolves `localhost`/`127.0.0.1`/`[::1]` to actual hostname. Defaults to `unknown:1521` on error.

### Receiver-Specific Patterns

#### Trace Context from ACTION Column
Query samples extract W3C TraceContext from Oracle's `ACTION` column:
```go
queryContext := propagator.Extract(context.Background(), propagation.MapCarrier{
    "traceparent": row["ACTION"],
})
```
Applications set this via `DBMS_APPLICATION_INFO.SET_ACTION('00-{traceId}-{spanId}-01')`.

#### Stored Procedure Attribution
Both top queries and query samples join to `DBA_PROCEDURES` to capture:
- `PROGRAM_ID` / `PROCEDURE_ID` → object ID
- `PROCEDURE_NAME` → `owner.object_name` (NULL when no procedure)
- `PROCEDURE_TYPE` → object type from DBA_PROCEDURES
- `PROCEDURE_EXECUTIONS` → minimum executions across statements in the procedure (best-effort)

#### V$SYSSTAT CPU Time Units
CPU time from V$SYSSTAT is in tens of milliseconds. The scraper divides by 100 to convert
to seconds before recording.

#### Dynamic Column Discovery
`dbSQLClient.metricRows()` in `db_client.go` uses `sqlRows.ColumnTypes()` to dynamically
discover column names at runtime. All column names are uppercased via `strings.ToUpper()`.
Values are formatted via `fmt.Sprintf` — byte slices use `%s`, everything else uses `%v`.

---

## Test Patterns

### Unit Tests (scraper_test.go)

Pattern: **fakeDbClient with canned response arrays**.

```go
// 1. Create scraper directly with fake DB provider
scrpr := oracleScraper{
    logger: zap.NewNop(),
    mb:     metadata.NewMetricsBuilder(cfg, receivertest.NewNopSettings(metadata.Type)),
    dbProviderFunc: func() (*sql.DB, error) { return nil, nil },
    clientProviderFunc: func(_ *sql.DB, s string, _ *zap.Logger) dbClient {
        return &fakeDbClient{Responses: [][]metricRow{queryResponses[s]}}
    },
    metricsBuilderConfig: metadata.DefaultMetricsBuilderConfig(),
}

// 2. Start, scrape, assert
err := scrpr.start(t.Context(), componenttest.NewNopHost())
m, err := scrpr.scrape(t.Context())
assert.Equal(t, 18, m.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().Len())
```

**fakeDbClient** (`fake_db_client.go`): Implements `dbClient`. Sequential response array
with `RequestCounter` — each call to `metricRows()` returns the next response. Can also
return a configured `Err`.

**Routing by SQL string:** Tests route fake responses by matching the `s` parameter
(the SQL string) in `clientProviderFunc`. For logs tests, `strings.Contains(s, "V$SQL_PLAN")`
distinguishes plan queries from metrics queries.

**To add test data for a new query:**
1. Add test responses to `queryResponses` map in `scraper_test.go`
2. Add routing in `clientProviderFunc` to return the right fakeDbClient for the new SQL
3. For logs: create JSON test data file in `testdata/` (e.g., `myNewData.txt`)
4. Generate golden file with `golden.WriteLogs()`, then switch to `golden.ReadLogs()` + `plogtest.CompareLogs()`

### Integration Tests

**None.** Oracle has no free Docker image for testcontainers. All testing uses fakeDbClient.

---

## Error Handling

| Scenario | Behavior | Code Location |
|----------|----------|---------------|
| Connection refused | `start()` fails with wrapped error | `scraper.go:start()` |
| Auth failure | `start()` fails (DB open error) | `scraper.go:start()` |
| V$SYSSTAT query failure | Error appended to scrapeErrors, partial scrape returned | `scraper.go:scrape()` |
| V$SESSION query failure | Error appended, sessions.usage metric missing | `scraper.go:scrape()` |
| V$RESOURCE_LIMIT query failure | Error appended, resource limit metrics missing | `scraper.go:scrape()` |
| DBA_TABLESPACE query failure | Error appended, tablespace metrics missing | `scraper.go:scrape()` |
| Numeric parse failure in V$SYSSTAT | Error appended, specific metric skipped | `scraper.go:scrape()` switch cases |
| CPU time from V$SYSSTAT in 10ms units | Divided by 100 to get seconds | `scraper.go:scrape()` cpuTime case |
| Tablespace with empty TABLESPACE_SIZE | Recorded as `-1` (backward compat) | `scraper.go:scrape()` tablespace block |
| Top query: no data returned | Returns error "no data returned from oracleQueryMetricsClient" | `scraper.go:collectTopNMetricData()` |
| Top query: negative delta | Possible cursor purge → row discarded silently | `scraper.go:collectTopNMetricData()` |
| Top query: zero execution delta | No new executions → row discarded | `scraper.go:collectTopNMetricData()` |
| Top query: obfuscation failure | Row skipped, Warn logged with sql_id | `scraper.go:obfuscateCacheHits()` |
| Query sample: empty SQL_FULLTEXT | Row skipped silently | `scraper.go:collectQuerySamples()` |
| Query sample: obfuscation failure | Row skipped, Error logged | `scraper.go:collectQuerySamples()` |
| Query sample: unparseable DURATION_SEC | Error appended | `scraper.go:collectQuerySamples()` |
| Plan fetch failure | Plan data empty, queries still emitted without plans | `scraper.go:getChildAddressToPlanMap()` |
| Collection interval not elapsed | Top query scrape skipped, Debug logged | `scraper.go:scrapeLogs()` |

---

## Permissions

### Minimum (metrics only)

```sql
-- V$SYSSTAT, V$SESSION, V$RESOURCE_LIMIT
GRANT SELECT_CATALOG_ROLE TO monitoring_user;
-- Or more granularly:
GRANT SELECT ON V_$SYSSTAT TO monitoring_user;
GRANT SELECT ON V_$SESSION TO monitoring_user;
GRANT SELECT ON V_$RESOURCE_LIMIT TO monitoring_user;
GRANT SELECT ON DBA_TABLESPACE_USAGE_METRICS TO monitoring_user;
GRANT SELECT ON DBA_TABLESPACES TO monitoring_user;
```

### Query samples (additional)

```sql
GRANT SELECT ON V_$SQL TO monitoring_user;
GRANT SELECT ON DBA_PROCEDURES TO monitoring_user;
```

### Top queries (additional)

```sql
-- Same as query samples, plus:
GRANT SELECT ON V_$SQL_PLAN TO monitoring_user;
```

---

## Dependencies on Shared Code

| Package | Used For |
|---------|----------|
| `hashicorp/golang-lru/v2` | LRU cache for top query delta computation |
| `DataDog/datadog-agent/pkg/obfuscate` | SQL obfuscation (oracle DBMS mode) |
| `sijms/go-ora/v2` | Oracle database driver + `BuildUrl()` for connection string |
| `pkg/golden` | Golden file test utilities |
| `pkg/pdatatest/plogtest` | Log comparison in tests |

Note: Oracle receiver does NOT use `internal/sqlquery` (has its own `dbClient` interface)
or `internal/common/priorityqueue` (uses `sort.Slice` instead).

---

## Rollout Phases

### Phase 1: Foundation (P0)
- Metrics: existing enabled set (25 metrics)
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
| 1 | Can we add integration tests via Oracle XE container? | arch | Open |
| 2 | Should we migrate to use `internal/sqlquery` for consistency with SQL Server? | arch | Open |
| 3 | What new Oracle-specific metrics do customers need? | PM | Open |

---

## Change Log

| Date | PR | Section | What Changed | Why |
|------|-----|---------|-------------|-----|
| 2026-04-06 | foundation | All | Initial spec from full codebase analysis | Foundation branch setup |
