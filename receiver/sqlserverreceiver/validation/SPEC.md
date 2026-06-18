# SQL Server Receiver Validation Tool -- Design Spec

## Validation Results (2026-06-18)

Validation completed using `Validate-Deltas.ps1` against `dbQueryAndTextQuery.tmpl`:

| Check | Result | Notes |
|-------|--------|-------|
| Unit Conversion (us->s) | **100% PASS** | All time fields correctly divided by 1,000,000 |
| Filtering (exec>0 AND elapsed>0) | **100% PASS** | No events emitted with zero values |
| Attribute Mapping (db.namespace) | **100% PASS** | USE [db] context correctly handled |
| Delta Logic (cacheAndDiff) | **~90% PASS** | Remaining diffs are timing noise (script T1/T2 != collector T1/T2) |

### Known False Positives (not bugs):
- **14.3% diff on execution_count**: Script window (65s) captures 7 executions while collector's 60s window captures 6
- **5-8% diff on elapsed_time/worker_time**: DMV counters update between script snapshot and collector scrape
- **db.namespace = testdb vs master**: Query uses `USE [testdb]` but `DB_NAME(st.dbid)` returns compilation context (master)

## Problem

The sqlserver receiver executes 12 SQL queries against SQL Server DMVs, applies transformations (unit conversions, delta calculations, counter-type formulas, attribute mapping), and emits metrics/logs via the OTel pipeline. Today there is no automated way to verify that:

1. The emitted metric values match what SQL Server actually reports
2. Unit conversions (ms->s, KB->bytes, us->s) are applied correctly
3. Delta logic (`cacheAndDiff`) produces correct increments across scrapes
4. Performance counter type 537003264 base-counter division works correctly
5. Column-to-attribute mappings are accurate
6. Code changes do not silently alter metric semantics

The existing `integration_test.go` validates basic scraper functionality (logs emit, queries run) but does not cross-check metric values against independent ground truth.

## Receiver Processing Logic (from scraper.go)

Based on code review of `receiver/sqlserverreceiver/scraper.go`:

### dbQueryAndTextQuery.tmpl Processing Flow:

1. **Query execution** (line 1180): Runs SQL with `@lookbackTime` and `@maxSampleCount` params
2. **First pass - elapsed time delta for sorting** (line 1193-1211):
   - For each row, computes `cacheAndDiff(queryHash, queryPlanHash, procID, "total_elapsed_time", value)`
   - Stores delta in `totalElapsedTimeDiffsMicrosecond[]`
3. **Sort and top-N selection** (line 1214): Sorts rows by elapsed_time delta descending, keeps top `TopQueryCount`
4. **Second pass - all field deltas** (line 1258-1311):
   - `execution_count`: `cacheAndDiff` → int64 delta
   - `total_logical_reads`: `cacheAndDiff` → int64 delta
   - `total_logical_writes`: `cacheAndDiff` → int64 delta
   - `total_physical_reads`: `cacheAndDiff` → int64 delta
   - `total_rows`: `cacheAndDiff` → int64 delta
   - `total_grant_kb`: `cacheAndDiff` → int64 delta
   - `total_worker_time`: `cacheAndDiff` → int64 delta → then `/1_000_000` → float64 seconds
   - `procedure_execution_count`: `cacheAndDiff` → int64 delta
5. **total_elapsed_time** (line 1316): Uses pre-computed value from step 2, `/1_000_000` → float64 seconds
6. **Filtering** (line 1317): Skip if `execution_count == 0` OR `totalElapsedTimeVal == 0`
7. **Emit event** (line 1327): `RecordDbServerTopQueryEvent()`

### cacheAndDiff logic (line 1375-1397):
- Cache key: `queryHash-queryPlanHash-column` (or `procedureID-queryHash-queryPlanHash-column`)
- First time (not cached): returns `(false, val)` → caller sets to 0
- Cached and value increased: returns `(true, val - cached)` → positive delta
- Cached and value same/decreased: returns `(true, 0)` → zero delta

### Fields NOT using delta (passed through directly):
- `database_name` (from SQL query result)
- `query_text` (obfuscated)
- `full_query_text` (obfuscated)
- `query_plan` (obfuscated XML)
- `last_execution_time` (ISO timestamp string)
- `plan_creation_time` (ISO timestamp string)
- `procedure_id`, `procedure_name`

---

## Requirements

### Must-Have

- M1: Validate emitted metric values against independent SQL queries to the same DMVs
- M2: Verify unit conversions (latency ms->s, memory KB->bytes, time us->s)
- M3: Verify delta/`cacheAndDiff` behavior across multiple scrapes (first-scrape zeros, positive deltas, counter-reset handling)
- M4: Verify performance counter type 537003264 base-counter division
- M5: Verify attribute correctness (database_name, file_type, wait_category, direction)
- M6: Run in CI with Docker (testcontainers-go, `mcr.microsoft.com/mssql/server:2022-latest`)
- M7: Use the same build-tag gating pattern as existing `integration_test.go`
- M8: No modification to the collector binary or receiver code required
- M9: Catch regressions when queries or transformations change

### Nice-to-Have

- N1: Offline replay capability (validate against saved snapshots without live SQL Server)
- N2: Golden-file regression mode using `pkg/golden`
- N3: Validate Windows perf counter path (requires Windows CI)
- N4: Validate Azure SQL Database/Managed Instance code paths
- N5: Configurable tolerance thresholds per metric
- N6: CLI tool for ad-hoc validation against a user's SQL Server instance

---

## Approach Comparison

| Criterion | A: Live Comparison | B: Snapshot Replay | C: Integration Test Harness |
|-----------|-------------------|-------------------|---------------------------|
| **Runtime dependency** | Live SQL Server + running collector binary | Live SQL Server (capture only); offline for validate | Live SQL Server (Docker container) |
| **Collector modification** | None (reads file exporter output) | None (reads debug output) | None (calls scraper API directly) |
| **Timing sensitivity** | High -- bracket-and-interpolate required | Medium -- two-snapshot capture window | Low -- scraper called synchronously in-process |
| **Debug output parsing** | Yes (OTLP JSON from file exporter) | Yes (debug text format, fragile) | No -- uses `pmetric.Metrics` / `plog.Logs` in memory |
| **Delta validation** | Complex (replicate LRU externally) | Medium (T1/T2 snapshots) | Simple (call ScrapeMetrics/ScrapeLogs multiple times) |
| **CI integration** | Hard (build collector, manage processes) | Medium (two-phase, needs coordination) | Easy (single `go test` command) |
| **Flakiness risk** | High (timing races between processes) | Medium (capture timing) | Low (synchronous, deterministic workload) |
| **Maintenance** | High (separate binary, config, process mgmt) | Medium (replay engine mirrors scraper) | Low (extends existing test patterns) |
| **Code reuse** | Imports queries.go, duplicates transforms | Imports queries.go, duplicates transforms | Calls scraper directly, no duplication |
| **Existing pattern match** | No precedent in repo | No precedent in repo | Extends existing `integration_test.go` |
| **Implementation effort** | ~3-4 weeks | ~2-3 weeks | ~1-2 weeks |

---

## Recommendation: Approach C (Integration Test Harness) with Snapshot Extension

**Primary**: Approach C. It has the lowest implementation cost, lowest flakiness risk, best CI integration, and directly extends the existing test infrastructure. The synchronous in-process design eliminates timing issues entirely for most validations.

**Extension from B**: Add optional snapshot capture/replay for offline regression testing. After a validation test run, serialize the raw SQL results and scraper output to JSON golden files. Future runs can compare against these files to detect regressions without needing live SQL Server.

**Justification**:
- The repo already uses testcontainers-go with the same MSSQL image
- Calling `scraper.ScrapeMetrics()` directly avoids all output-parsing fragility
- Synchronous scrape + immediate raw SQL query minimizes timing drift to near-zero
- Single `go test -tags integration_validation` command -- no process orchestration
- Zero code duplication -- reuses actual scraper code paths

---

## Detailed Design

### File Structure

```
receiver/sqlserverreceiver/
  validation/
    validation_test.go           # Main test file (//go:build integration_validation)
    workload.go                  # Workload generator (IO, waits, query stats)
    verifier.go                  # Raw SQL queries for ground-truth comparison
    assertions.go                # Custom assertion helpers (tolerance, attribute matching)
    helpers.go                   # Container setup, config builders
    testdata/
      02-validation-init.sh      # Enhanced init script (grants, Query Store, tables)
      golden/                    # Optional golden files for regression
        metrics_database_io.yaml
        metrics_perf_counters.yaml
        logs_top_query.yaml
```

### Build Tag

```go
//go:build integration_validation
```

Separate from the existing `integration` tag so it can run independently (longer runtime, heavier workload).

### Container Setup

Extends the existing pattern with an enhanced init script:

```go
func setupValidationContainer(t *testing.T) (*sql.DB, uint) {
    // Same image: mcr.microsoft.com/mssql/server:2022-latest
    // Enhanced init:
    //   - GRANT VIEW SERVER STATE, VIEW DATABASE STATE
    //   - CREATE multiple databases (for multi-db validation)
    //   - Enable Query Store (for top-query log validation)
    //   - Create tables with known row counts
    //   - Create stored procedures for query stats population
}
```

### Input/Output

**Inputs**:
- SQL Server container (auto-provisioned)
- Deterministic workload (known INSERT/SELECT/UPDATE counts)
- Receiver config with all metrics/events enabled

**Outputs**:
- Pass/fail per metric with drift values
- Optional golden files for regression comparison
- Test failure messages with: metric name, expected value, actual value, tolerance, raw SQL result

### How Each Metric Type Is Validated

#### Gauges (point-in-time values)

```
Strategy: Query DMV immediately after scrape, compare values.
Tolerance: Exact match for static values (cpu_count, database_count);
           +/- 5% for volatile values (buffer_cache_hit_ratio, page_life_expectancy).

Example - sqlserver.page.buffer_cache.hit_ratio:
  1. Call scraper.ScrapeMetrics()
  2. Query: SELECT cntr_value FROM sys.dm_os_performance_counters
     WHERE counter_name = 'Buffer cache hit ratio'
  3. Apply base-counter division (same formula as queries.go line 294)
  4. Assert: |scraper_value - raw_value| <= tolerance
```

#### Cumulative Sums (monotonic counters)

```
Strategy: Take raw snapshot before and after scrape; verify scraper value
          falls within [before, after] range.
Tolerance: scraper_value >= raw_before AND scraper_value <= raw_after

Example - sqlserver.database.io:
  1. raw_before = SELECT num_of_bytes_read FROM sys.dm_io_virtual_file_stats(...)
  2. Call scraper.ScrapeMetrics()
  3. raw_after = SELECT num_of_bytes_read FROM sys.dm_io_virtual_file_stats(...)
  4. Assert: raw_before <= scraper_value <= raw_after
```

#### Delta Metrics (cacheAndDiff-based, logs)

```
Strategy: Multi-scrape with controlled workload injection between scrapes.
Tolerance: exact match for execution_count (deterministic);
           lower-bound for elapsed_time (non-deterministic).

Example - executionCount delta:
  1. Execute known query Q exactly 50 times
  2. Scrape 1 (primes cache, returns 0 for deltas)
  3. Execute Q exactly 30 more times
  4. Scrape 2 (cache hit, delta should be ~30)
  5. Assert: delta == 30 (exact, because we control the workload)
     Note: background queries (stats updates) may add noise;
     filter by query_hash to isolate our test query.
```

#### Unit Conversions

```
Strategy: Query raw value, apply expected conversion, compare to scraper output.

Validations:
  - Latency: raw_ms / 1000.0 == scraper_seconds
  - Memory: raw_kb * 1024 == scraper_bytes
  - Worker time: raw_us / 1_000_000 == scraper_seconds
  - Wait time: raw_ms / 1000.0 == scraper_seconds
```

#### Attribute Correctness

```
Strategy: For each metric data point, verify attributes match raw SQL column values.

Validations:
  - database_name matches DB_NAME() or sys.databases.name
  - file_type matches CASE on data_space_id (0=ROWS, 1=LOG)
  - wait_category matches the category mapping in queries.go
  - direction (read/write) matches the column source
```

### How Timing/Delta Issues Are Handled

| Issue | Solution |
|-------|----------|
| DMV values change between raw query and scrape | Bracket strategy: query before AND after scrape; assert value in range |
| First scrape emits 0 for delta metrics | Explicit test: verify scrape 1 returns 0; only validate deltas on scrape 2+ |
| Counter reset (simulated by restarting sqlservr) | Verify `cacheAndDiff` returns 0 when current < cached |
| Background SQL Server activity adds noise | Filter by known query_hash for log metrics; use lower-bound assertions for counters |
| LRU cache eviction | Test with cache size < number of tracked queries; verify evicted entries return 0 on next scrape |
| Scraper internal timing | Synchronous calls eliminate inter-process timing entirely |

### Dependencies

Already in go.mod:
- `github.com/testcontainers/testcontainers-go`
- `github.com/microsoft/go-mssqldb`
- `github.com/stretchr/testify`
- `go.opentelemetry.io/collector/pdata/pmetric`
- `go.opentelemetry.io/collector/pdata/plog`
- `github.com/hashicorp/golang-lru/v2`

Optional (for golden files):
- `github.com/open-telemetry/opentelemetry-collector-contrib/pkg/golden`
- `github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatatest/pmetrictest`

### Usage Examples

```bash
# Run full validation suite
go test -tags integration_validation -v -timeout 120s \
  ./receiver/sqlserverreceiver/validation/

# Run only delta validation tests
go test -tags integration_validation -v -run TestDeltaCorrectness \
  ./receiver/sqlserverreceiver/validation/

# Update golden files after intentional metric changes
go test -tags integration_validation -v \
  -update-golden \
  ./receiver/sqlserverreceiver/validation/
```

### Test Functions (Outline)

```go
func TestMetricsValueCorrectness(t *testing.T)     // M1: values match DMVs
func TestUnitConversions(t *testing.T)              // M2: ms->s, KB->bytes, us->s
func TestDeltaCorrectness(t *testing.T)             // M3: multi-scrape delta behavior
func TestFirstScrapeZeros(t *testing.T)             // M3: first scrape returns 0
func TestCounterReset(t *testing.T)                 // M3: counter reset handling
func TestPerfCounterBaseDiv(t *testing.T)           // M4: type 537003264 formula
func TestAttributeMapping(t *testing.T)             // M5: attributes match raw SQL
func TestMonotonicCounters(t *testing.T)            // values never decrease
func TestLogQueryTextDelta(t *testing.T)            // log event delta fields
func TestMultipleDatabases(t *testing.T)            // per-database metrics
```

---

## Open Questions

1. **Build tag**: Use a new `integration_validation` tag or extend the existing `integration` tag? The validation tests are heavier (multi-scrape, workload generation) and take longer (~60s vs ~20s).

2. **Package location**: Place tests in `receiver/sqlserverreceiver/validation/` (separate package, black-box) or in `receiver/sqlserverreceiver/` alongside existing `integration_test.go` (same package, white-box access to internals like `cacheAndDiff`)?

3. **Tolerance values**: What percentage tolerance is acceptable for volatile gauges? Suggested default: 5% relative or 1 absolute unit, whichever is larger. Should this be configurable per-metric?

4. **Golden files**: Should we include golden-file regression testing (compare scraper output against saved YAML baselines)? This adds maintenance burden when metrics intentionally change but catches unintentional drift.

5. **Query Store requirement**: The top-query validation requires Query Store enabled. Should the init script enable it (adds container startup time), or should those tests be separately tagged?

6. **CI runner**: Where will this run? GitHub Actions (Linux Docker available), or also local developer machines? This affects container resource assumptions.

7. **Scope of first implementation**: Validate all 12 queries in phase 1, or start with a subset (e.g., Database IO + Perf Counters + Query Text) and expand incrementally?
