# EXPLAIN via SECURITY DEFINER helper function — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `nrpostgresqlreceiver` collect EXPLAIN plans for row-locking (`FOR UPDATE`/`FOR SHARE`) and write (`UPDATE`/`INSERT`/`DELETE`/`MERGE`) top queries — which fail today with `permission denied` — by optionally calling a DBA-provisioned `SECURITY DEFINER` function instead of running `EXPLAIN` directly as the read-only monitoring user, with automatic fallback to today's behavior if the function isn't provisioned.

**Architecture:** A new config field (`explain_function_name`, default `otel.explain_statement`) names the helper function. A per-database, TTL-cached probe (a real validation call, not a catalog lookup) determines once per `explain_function_cache_ttl` window whether the function is present and callable; `explainQuery` branches on that cached state to either call the function (`SELECT "schema"."func"($1)`) or fall back to the existing inline `PREPARE`/`EXPLAIN EXECUTE`/`DEALLOCATE` sequence, unchanged. The configured function name is validated as a safe SQL identifier at config-load time and always double-quoted before use, closing a gap present in the reference (Datadog) implementation.

**Tech Stack:** Go, `database/sql`, `github.com/lib/pq` (error codes via `pqerror.Code`), `github.com/hashicorp/golang-lru/v2/expirable` (existing `newTTLCache` helper), `github.com/DATA-DOG/go-sqlmock` (existing test pattern).

## Global Constraints

- No `.chloggen` entry — this fork does not use `.chloggen`/`CHANGELOG.md` (confirmed: no existing entry anywhere references `component: receiver/nr*`). Skip changelog entirely for this change.
- No feature gate. This is a per-database runtime state, not a global staged-migration toggle (the only kind of thing this receiver's 3 existing feature gates are used for).
- No `ctx context.Context` parameter added to `explainQuery` — it is currently the sole `client` interface method without one; fixing that is out of scope for this change.
- `explainQuery`'s core inline-path SQL and its whitelist check (`isExplainableQuery`) are byte-for-byte unchanged. Only a new parameter and a new branch are added.
- The configured `ExplainFunctionName` must be validated as `^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$` at `Config.Validate()` time, and every segment double-quoted before being placed in SQL — no exceptions, no code path skips this.
- Real `explainQuery` call failures NEVER write to the probe cache (`explainFunctionCache`) — only the dedicated probe does. (An earlier draft had this wrong; the design doc explicitly corrects it to match Datadog's actual behavior. Do not reintroduce eviction-on-failure.)
- `newPostgreSQLScraper`'s new 6th parameter must be threaded through **every** call site — 3 in `factory.go`, 21 in `scraper_test.go` (verified counts). Missing even one is a compile error, so this is self-checking, but budget for it — it is a bigger footprint than a first read of the design doc suggests.

---

### Task 1: Add and validate `ExplainFunctionName` / `ExplainFunctionCacheTTL` config fields

**Files:**
- Modify: `receiver/nrpostgresqlreceiver/config.go:29-38` (add fields to `TopQueryCollection`), `config.go:68-99` (add validation to `Validate()`)
- Modify: `receiver/nrpostgresqlreceiver/factory.go:71-78` (add defaults to `createDefaultConfig()`)
- Test: `receiver/nrpostgresqlreceiver/config_test.go`

**Interfaces:**
- Produces: `Config.TopQueryCollection.ExplainFunctionName string`, `Config.TopQueryCollection.ExplainFunctionCacheTTL time.Duration`. Produces the error constant `ErrInvalidExplainFunctionName` and the exported (for test use within package) regex `explainFunctionNamePattern`. Later tasks read `cfg.ExplainFunctionName` and `cfg.ExplainFunctionCacheTTL`.

- [ ] **Step 1: Write the failing validation tests**

Add to `receiver/nrpostgresqlreceiver/config_test.go`, inside the existing `TestValidate` function's `testCases` slice (append after the `"no error"` case, before the closing `}` of the slice literal at line 98):

```go
		{
			desc: "valid unqualified explain function name",
			defaultConfigModifier: func(cfg *Config) {
				cfg.Username = "otel"
				cfg.Password = "otel"
				cfg.ExplainFunctionName = "explain_statement"
			},
			expected: nil,
		},
		{
			desc: "valid schema-qualified explain function name",
			defaultConfigModifier: func(cfg *Config) {
				cfg.Username = "otel"
				cfg.Password = "otel"
				cfg.ExplainFunctionName = "otel.explain_statement"
			},
			expected: nil,
		},
		{
			desc: "empty explain function name is valid (disables the feature)",
			defaultConfigModifier: func(cfg *Config) {
				cfg.Username = "otel"
				cfg.Password = "otel"
				cfg.ExplainFunctionName = ""
			},
			expected: nil,
		},
		{
			desc: "explain function name with too many dots is rejected",
			defaultConfigModifier: func(cfg *Config) {
				cfg.Username = "otel"
				cfg.Password = "otel"
				cfg.ExplainFunctionName = "a.b.c"
			},
			expected: []error{
				errors.New(ErrInvalidExplainFunctionName),
			},
		},
		{
			desc: "explain function name with SQL injection attempt is rejected",
			defaultConfigModifier: func(cfg *Config) {
				cfg.Username = "otel"
				cfg.Password = "otel"
				cfg.ExplainFunctionName = "explain_statement; DROP TABLE orders"
			},
			expected: []error{
				errors.New(ErrInvalidExplainFunctionName),
			},
		},
		{
			desc: "explain function name starting with a digit is rejected",
			defaultConfigModifier: func(cfg *Config) {
				cfg.Username = "otel"
				cfg.Password = "otel"
				cfg.ExplainFunctionName = "1explain"
			},
			expected: []error{
				errors.New(ErrInvalidExplainFunctionName),
			},
		},
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -C receiver/nrpostgresqlreceiver -run TestValidate -v ./...`
Expected: FAIL — compile error (`ErrInvalidExplainFunctionName undefined`, `cfg.ExplainFunctionName undefined`), or once those fields/const exist temporarily as empty stubs, the new "too many dots"/"injection"/"starting with digit" subtests FAIL because no validation exists yet to produce the error.

- [ ] **Step 3: Add the config fields**

In `receiver/nrpostgresqlreceiver/config.go`, replace the `TopQueryCollection` struct (lines 29-38):

```go
type TopQueryCollection struct {
	MaxRowsPerQuery         int64         `mapstructure:"max_rows_per_query"`
	TopNQuery               int64         `mapstructure:"top_n_query"`
	MaxExplainEachInterval  int64         `mapstructure:"max_explain_each_interval"`
	QueryPlanCacheSize      int           `mapstructure:"query_plan_cache_size"`
	QueryPlanCacheTTL       time.Duration `mapstructure:"query_plan_cache_ttl"`
	CollectionInterval      time.Duration `mapstructure:"collection_interval"`
	ExplainFunctionName     string        `mapstructure:"explain_function_name"`
	ExplainFunctionCacheTTL time.Duration `mapstructure:"explain_function_cache_ttl"`
	// prevent unkeyed literal initialization
	_ struct{}
}
```

- [ ] **Step 4: Add the validation error constant and regex**

In `receiver/nrpostgresqlreceiver/config.go`, add to the `const` block (lines 21-27):

```go
const (
	ErrNoUsername          = "invalid config: missing username"
	ErrNoPassword          = "invalid config: missing password" // #nosec G101 - not hardcoded credentials
	ErrNotSupported        = "invalid config: field '%s' not supported"
	ErrTransportsSupported = "invalid config: 'transport' must be 'tcp' or 'unix'"
	ErrHostPort            = "invalid config: 'endpoint' must be in the form <host>:<port> no matter what 'transport' is configured"
	ErrInvalidExplainFunctionName = "invalid config: 'top_query_collection.explain_function_name' must be empty or a valid [schema.]function_name identifier"
)
```

Add the package-level regex, right after the `const` block, before `type TopQueryCollection struct`:

```go
var explainFunctionNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)
```

Add `"regexp"` to the `import` block (config.go:6-18), alphabetically after `"net"`:

```go
import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrpostgresqlreceiver/internal/metadata"
	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/scraper/scraperhelper"
	"go.uber.org/multierr"
)
```

- [ ] **Step 5: Wire the validation into `Config.Validate()`**

In `receiver/nrpostgresqlreceiver/config.go`, modify `Validate()` (lines 68-99) — add this block right before the final `return err` (line 98):

```go
	if cfg.ExplainFunctionName != "" && !explainFunctionNamePattern.MatchString(cfg.ExplainFunctionName) {
		err = multierr.Append(err, errors.New(ErrInvalidExplainFunctionName))
	}

	return err
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test -C receiver/nrpostgresqlreceiver -run TestValidate -v ./...`
Expected: PASS, all subtests including the 6 new ones.

- [ ] **Step 7: Set the defaults in `createDefaultConfig()`**

In `receiver/nrpostgresqlreceiver/factory.go`, modify the `TopQueryCollection` struct literal (lines 71-78):

```go
		TopQueryCollection: TopQueryCollection{
			CollectionInterval:      time.Minute,
			TopNQuery:               200,
			MaxRowsPerQuery:         1000,
			MaxExplainEachInterval:  1000,
			QueryPlanCacheSize:      1000,
			QueryPlanCacheTTL:       time.Hour,
			ExplainFunctionName:     "otel.explain_statement",
			ExplainFunctionCacheTTL: 5 * time.Minute,
		},
```

- [ ] **Step 8: Run the full config test suite**

Run: `go test -C receiver/nrpostgresqlreceiver -run TestValidate ./... && go test -C receiver/nrpostgresqlreceiver ./... -run TestCreateDefaultConfig -v`
Expected: PASS. (If `TestCreateDefaultConfig` doesn't exist as a named test, run `go test -C receiver/nrpostgresqlreceiver ./...` in full instead and confirm no regressions — this is the safety net for step 9.)

- [ ] **Step 9: Run the full package test suite to check for regressions**

Run: `go build -C receiver/nrpostgresqlreceiver ./... && go test -C receiver/nrpostgresqlreceiver ./...`
Expected: Both green. This will surface any other test that asserts on the exact shape of `createDefaultConfig()`'s output (e.g. a golden config file) — if one fails because it doesn't expect the two new fields, that test's expected config needs the two new fields added (do this now, don't defer).

- [ ] **Step 10: Commit**

```bash
git add receiver/nrpostgresqlreceiver/config.go receiver/nrpostgresqlreceiver/config_test.go receiver/nrpostgresqlreceiver/factory.go
git commit -m "Add explain_function_name and explain_function_cache_ttl config with identifier validation"
```

---

### Task 2: Add `explainSetupState` cache type and thread `explainFunctionCache` through the scraper

**Files:**
- Modify: `receiver/nrpostgresqlreceiver/scraper.go:48-63` (struct field), `scraper.go:88-133` (constructor)
- Modify: `receiver/nrpostgresqlreceiver/factory.go:97, 133, 153` (3 call sites)
- Modify: `receiver/nrpostgresqlreceiver/scraper_test.go` (21 call sites — see step 4)
- Test: `receiver/nrpostgresqlreceiver/scraper_test.go` (new test for the constructor threading through correctly is covered implicitly by every existing test still compiling and passing; no new dedicated test needed for this task alone — behavior tests come in Task 4)

**Interfaces:**
- Consumes: nothing new from Task 1 directly (config fields are read in Task 3/4, not here).
- Produces: `type explainSetupState struct { available bool; err error }`, `postgreSQLScraper.explainFunctionCache *expirable.LRU[string, explainSetupState]`, and `newPostgreSQLScraper`'s new 6th parameter `explainFunctionCache *expirable.LRU[string, explainSetupState]`. Task 4 reads/writes this field via `p.explainFunctionCache.Get(database)` / `.Add(database, state)`.

- [ ] **Step 1: Add the `explainSetupState` type and struct field**

In `receiver/nrpostgresqlreceiver/scraper.go`, add above the `postgreSQLScraper` struct (before line 48):

```go
// explainSetupState is the cached outcome of probing whether the configured
// EXPLAIN helper function is present and callable for a given database.
type explainSetupState struct {
	available bool
	err       error
}
```

Modify the `postgreSQLScraper` struct (lines 48-63) — add one field after `queryPlanCache`:

```go
type postgreSQLScraper struct {
	logger        *zap.Logger
	config        *Config
	clientFactory postgreSQLClientFactory
	mb            *metadata.MetricsBuilder
	lb            *metadata.LogsBuilder
	excludes      map[string]struct{}
	cache         *lru.Cache[string, float64]
	// if enabled, uses a separated attribute for the schema
	separateSchemaAttr     bool
	useOTelSemconv         bool
	queryPlanCache         *expirable.LRU[string, string]
	explainFunctionCache   *expirable.LRU[string, explainSetupState]
	newestQueryTimestamp   float64
	serviceInstanceID      string
	lastExecutionTimestamp time.Time
}
```

- [ ] **Step 2: Add the parameter to `newPostgreSQLScraper` and its return value**

In `receiver/nrpostgresqlreceiver/scraper.go`, modify the function signature (lines 88-94):

```go
func newPostgreSQLScraper(
	settings receiver.Settings,
	config *Config,
	clientFactory postgreSQLClientFactory,
	cache *lru.Cache[string, float64],
	queryPlanCache *expirable.LRU[string, string],
	explainFunctionCache *expirable.LRU[string, explainSetupState],
) (*postgreSQLScraper, error) {
```

Modify the return statement (lines 120-132) to include the new field:

```go
	return &postgreSQLScraper{
		logger:               settings.Logger,
		config:               config,
		clientFactory:        clientFactory,
		mb:                   metadata.NewMetricsBuilder(mbConfig, settings),
		lb:                   metadata.NewLogsBuilder(config.LogsBuilderConfig, settings),
		excludes:             excludes,
		cache:                cache,
		queryPlanCache:       queryPlanCache,
		explainFunctionCache: explainFunctionCache,
		separateSchemaAttr:   separateSchemaAttr,
		serviceInstanceID:    serviceInstanceID,
		useOTelSemconv:       useOTelSemconv,
	}, nil
```

- [ ] **Step 3: Update the 3 production call sites in `factory.go`**

In `receiver/nrpostgresqlreceiver/factory.go`, line 97 (inside `createMetricsReceiver`):

```go
	ns, err := newPostgreSQLScraper(params, cfg, clientFactory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
```

Line 133 (inside `createLogsReceiver`, the `DbServerQuerySample` branch — placeholder, unused by this branch, mirrors the existing `queryPlanCache` placeholder):

```go
		ns, err := newPostgreSQLScraper(params, cfg, clientFactory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
```

Line 153 (inside `createLogsReceiver`, the `DbServerTopQuery` branch — the real, config-driven cache):

```go
		ns, err := newPostgreSQLScraper(params, cfg, clientFactory, newCache(int(cfg.TopNQuery*10*2)), newTTLCache[string](cfg.QueryPlanCacheSize, cfg.QueryPlanCacheTTL), newTTLCache[explainSetupState](cfg.QueryPlanCacheSize, cfg.ExplainFunctionCacheTTL))
```

(Reuses `cfg.QueryPlanCacheSize` for the cache's LRU size bound — there's no separate size config for this cache per the design doc, which only calls out a separate *TTL*, not a separate size. This keeps the number of new config knobs to exactly the two added in Task 1.)

- [ ] **Step 4: Update all 21 call sites in `scraper_test.go`**

Run this to find every one:

```bash
grep -n "newPostgreSQLScraper(" receiver/nrpostgresqlreceiver/scraper_test.go
```

For each match, append `, newTTLCache[explainSetupState](1, time.Second)` immediately before the closing `)` of the call — i.e. change:

```go
scraper, err := newPostgreSQLScraper(settings, cfg, factory, newCache(1), newTTLCache[string](1, time.Second))
```

to:

```go
scraper, err := newPostgreSQLScraper(settings, cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
```

Apply this mechanically to every one of the 21 occurrences — they all currently end in `newTTLCache[string](...)` with varying arguments inside, followed by `)`. Do not change any of the other 5 arguments; only append the new 6th argument.

- [ ] **Step 5: Build to confirm every call site compiles**

Run: `go build -C receiver/nrpostgresqlreceiver ./...`
Expected: SUCCESS. If any call site was missed, this fails with `not enough arguments in call to newPostgreSQLScraper` and the exact file:line — fix and rerun until clean.

- [ ] **Step 6: Run the full test suite to confirm no behavior changed**

Run: `go test -C receiver/nrpostgresqlreceiver ./...`
Expected: PASS, identical results to before this task (this task only threads a new, unused-so-far field through — it must not change any existing test's outcome).

- [ ] **Step 7: Commit**

```bash
git add receiver/nrpostgresqlreceiver/scraper.go receiver/nrpostgresqlreceiver/factory.go receiver/nrpostgresqlreceiver/scraper_test.go
git commit -m "Thread explainFunctionCache through postgreSQLScraper construction"
```

---

### Task 3: Add the `probeExplainFunction` client method and quoted-identifier helper

**Files:**
- Modify: `receiver/nrpostgresqlreceiver/client.go:52-74` (interface), add new function near `explainQuery`
- Modify: `receiver/nrpostgresqlreceiver/scraper_test.go` (the `mockClient` stub needs the new interface method)
- Test: `receiver/nrpostgresqlreceiver/client_test.go` (new — this file currently has no explain-related tests; check it exists and has the right package/imports before adding)

**Interfaces:**
- Consumes: nothing from Task 1/2 directly — this task adds standalone functions/methods that Task 4 wires together.
- Produces:
  - `func quoteExplainFunctionName(name string) string` — takes an already-validated (Task 1) `[schema.]name` string, returns each segment double-quoted and joined by `.` (e.g. `"otel.explain_statement"` → `"otel"."explain_statement"`).
  - `client` interface method: `probeExplainFunction(ctx context.Context, quotedFunctionName string) error` — runs `SELECT <quotedFunctionName>('SELECT 1')`; returns `nil` on success, the raw `error` (including any `*pq.Error`) on failure. Task 4 classifies the returned error.
  - `(c *postgreSQLClient) probeExplainFunction(...)` — the real implementation.

- [ ] **Step 1: Write the failing test for `quoteExplainFunctionName`**

Check if `receiver/nrpostgresqlreceiver/client_test.go` exists and note its package/import style:

```bash
head -20 receiver/nrpostgresqlreceiver/client_test.go
```

Add to `receiver/nrpostgresqlreceiver/client_test.go` (create the file with the standard header if it doesn't exist, matching the package declaration `package nrpostgresqlreceiver` used by every other file in this directory):

```go
func TestQuoteExplainFunctionName(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "unqualified", input: "explain_statement", expected: `"explain_statement"`},
		{name: "schema qualified", input: "otel.explain_statement", expected: `"otel"."explain_statement"`},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := quoteExplainFunctionName(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
```

If `client_test.go` doesn't already import `testing` and `github.com/stretchr/testify/assert` (or whatever assertion library `scraper_test.go` uses — check: `scraper_test.go` uses `github.com/tj/assert`), match whichever this package already uses. Check first:

```bash
grep -n '"github.com/.*assert"' receiver/nrpostgresqlreceiver/*_test.go
```

Use that exact import path for consistency.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -C receiver/nrpostgresqlreceiver -run TestQuoteExplainFunctionName -v ./...`
Expected: FAIL — compile error, `quoteExplainFunctionName` undefined.

- [ ] **Step 3: Implement `quoteExplainFunctionName`**

In `receiver/nrpostgresqlreceiver/client.go`, add near `isExplainableQuery` (after line 131, before `explainQuery`):

```go
// quoteExplainFunctionName double-quotes each segment of an already-validated
// [schema.]name identifier (see Config.Validate's explainFunctionNamePattern check),
// so the configured name can never collide with a reserved word or be
// misinterpreted due to case folding when interpolated into SQL.
func quoteExplainFunctionName(name string) string {
	parts := strings.Split(name, ".")
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = `"` + p + `"`
	}
	return strings.Join(quoted, ".")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -C receiver/nrpostgresqlreceiver -run TestQuoteExplainFunctionName -v ./...`
Expected: PASS.

- [ ] **Step 5: Write the failing test for `probeExplainFunction`**

Add to `receiver/nrpostgresqlreceiver/client_test.go`:

```go
func TestProbeExplainFunction(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}
		mock.ExpectQuery(`SELECT "otel"."explain_statement"('SELECT 1')`).
			WillReturnRows(sqlmock.NewRows([]string{"explain_statement"}).AddRow(`[{"Plan":{}}]`))

		err = client.probeExplainFunction(t.Context(), `"otel"."explain_statement"`)
		require.NoError(t, err)
	})

	t.Run("function does not exist", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}
		mock.ExpectQuery(`SELECT "otel"."explain_statement"('SELECT 1')`).
			WillReturnError(&pq.Error{Code: pqerror.UndefinedFunction, Message: "function otel.explain_statement(text) does not exist"})

		err = client.probeExplainFunction(t.Context(), `"otel"."explain_statement"`)
		require.Error(t, err)
		var pqErr *pq.Error
		require.ErrorAs(t, err, &pqErr)
		assert.Equal(t, pqerror.UndefinedFunction, pqErr.Code)
	})
}
```

Add the required imports to `client_test.go`'s import block: `"github.com/lib/pq"`, `"github.com/lib/pq/pqerror"`, `"github.com/DATA-DOG/go-sqlmock"` (as `sqlmock`), `"github.com/stretchr/testify/require"` — check which of these are already imported by `scraper_test.go` and match that exact import style/alias.

- [ ] **Step 6: Run test to verify it fails**

Run: `go test -C receiver/nrpostgresqlreceiver -run TestProbeExplainFunction -v ./...`
Expected: FAIL — compile error, `probeExplainFunction` undefined on `*postgreSQLClient`.

- [ ] **Step 7: Add `probeExplainFunction` to the `client` interface and implement it**

In `receiver/nrpostgresqlreceiver/client.go`, modify the `client` interface (lines 52-74) — add one line after `explainQuery`:

```go
type client interface {
	Close() error
	getDatabaseStats(ctx context.Context, databases []string) (map[databaseName]databaseStats, error)
	getDatabaseConflicts(ctx context.Context, databases []string) (map[databaseName]databaseConflictStats, error)
	getDatabaseLocks(ctx context.Context) ([]databaseLocks, error)
	getBGWriterStats(ctx context.Context) (*bgStat, error)
	getBackends(ctx context.Context, databases []string) (map[databaseName]int64, error)
	getDatabaseSize(ctx context.Context, databases []string) (map[databaseName]int64, error)
	getDatabaseTableMetrics(ctx context.Context, db string) (map[tableIdentifier]tableStats, error)
	getBlocksReadByTable(ctx context.Context, db string) (map[tableIdentifier]tableIOStats, error)
	getReplicationStats(ctx context.Context) ([]replicationStats, error)
	getLatestWalAgeSeconds(ctx context.Context) (int64, error)
	getMaxConnections(ctx context.Context) (int64, error)
	getIndexStats(ctx context.Context, database string) (map[indexIdentifer]indexStat, error)
	getFunctionStats(ctx context.Context, database string) (map[functionIdentifer]functionStat, error)
	getVectorSearchStats(ctx context.Context) ([]vectorSearchStat, error)
	getVectorInsertStats(ctx context.Context) ([]vectorInsertStat, error)
	listDatabases(ctx context.Context) ([]string, error)
	getVersion(ctx context.Context) (string, error)
	getQuerySamples(ctx context.Context, limit int64, newestQueryTimestamp float64, logger *zap.Logger) ([]map[string]any, float64, error)
	getTopQuery(ctx context.Context, limit int64, logger *zap.Logger) ([]map[string]any, error)
	explainQuery(query, queryID, explainFunction string, logger *zap.Logger) (string, error)
	probeExplainFunction(ctx context.Context, quotedFunctionName string) error
}
```

(Note: `explainQuery`'s signature also changes here — from `(query, queryID string, logger *zap.Logger)` to `(query, queryID, explainFunction string, logger *zap.Logger)`. This is listed here because it's the same interface block; the actual `explainQuery` body/behavior change happens in Task 4.)

Add the implementation, right after `probeExplainFunction`'s natural home near `explainQuery` (after `quoteExplainFunctionName`, before the current `explainQuery` — or after it; exact position doesn't matter, group with the other EXPLAIN-related functions):

```go
// probeExplainFunction checks whether the given (already quoted) function name
// is present and callable, by actually calling it with a trivial, always-valid
// statement. This is a live validation call, not a catalog lookup — it catches
// a present-but-broken function (e.g. insufficient owner privilege) that a
// catalog lookup like to_regprocedure would miss.
func (c *postgreSQLClient) probeExplainFunction(ctx context.Context, quotedFunctionName string) error {
	query := fmt.Sprintf("SELECT %s('SELECT 1')", quotedFunctionName)
	_, err := c.client.QueryContext(ctx, query)
	return err
}
```

- [ ] **Step 8: Add the stub to `mockClient` in `scraper_test.go`**

In `receiver/nrpostgresqlreceiver/scraper_test.go`, near the existing `explainQuery` stub (around line 1360-1363), update `explainQuery`'s signature to match the new interface and add the new method:

```go
// explainQuery implements client.
func (*mockClient) explainQuery(string, string, string, *zap.Logger) (string, error) {
	panic("unimplemented")
}

// probeExplainFunction implements client.
func (*mockClient) probeExplainFunction(context.Context, string) error {
	panic("unimplemented")
}
```

- [ ] **Step 9: Build and run tests**

Run: `go build -C receiver/nrpostgresqlreceiver ./... && go test -C receiver/nrpostgresqlreceiver ./...`
Expected: Build succeeds (confirms `*postgreSQLClient` and `*mockClient` both still satisfy `client`). `TestExplainQuery` in `scraper_test.go` will FAIL to compile at this point because it calls `client.explainQuery(tc.query, tc.queryID, logger)` — 3 args, but the interface now expects 4. **This is expected and fixed in Task 4, step 1** — do not fix it here; if you need a compiling intermediate state, temporarily change the call in `TestExplainQuery` to `client.explainQuery(tc.query, tc.queryID, "", logger)` and revert that temporary edit at the start of Task 4.

Run: `go test -C receiver/nrpostgresqlreceiver -run TestQuoteExplainFunctionName -run TestProbeExplainFunction -v ./...`
Expected: PASS for both new tests (these can be verified independently of the `TestExplainQuery` compile issue by running only these two test names, but note `go test -run` compiles the whole package first — if `TestExplainQuery`'s call site still has the old 3-arg form, the whole package fails to compile. Apply the temporary 4-arg fix from the paragraph above before running this, or proceed directly to Task 4 which fixes it permanently.)

- [ ] **Step 10: Commit**

```bash
git add receiver/nrpostgresqlreceiver/client.go receiver/nrpostgresqlreceiver/client_test.go receiver/nrpostgresqlreceiver/scraper_test.go
git commit -m "Add probeExplainFunction client method and quoteExplainFunctionName helper"
```

---

### Task 4: Branch `explainQuery` on the function path, with per-database probe caching in the scraper

**Files:**
- Modify: `receiver/nrpostgresqlreceiver/client.go:133-182` (`explainQuery` body)
- Modify: `receiver/nrpostgresqlreceiver/scraper.go:380-494` (`collectTopQuery` — call site + probe-cache lookup)
- Modify: `receiver/nrpostgresqlreceiver/scraper_test.go:1288-1350` (`TestExplainQuery` — update call site to new signature, add function-path cases)
- Test: `receiver/nrpostgresqlreceiver/scraper_test.go` (new tests for probe caching, error classification, mid-run-drop non-eviction)

**Interfaces:**
- Consumes: `client.probeExplainFunction` and `quoteExplainFunctionName` (Task 3), `explainSetupState`/`postgreSQLScraper.explainFunctionCache` (Task 2), `cfg.ExplainFunctionName`/`cfg.ExplainFunctionCacheTTL` (Task 1).
- Produces: the finished, user-facing behavior. No later task consumes anything new from this one — this is the last implementation task.

- [ ] **Step 1: Fix `TestExplainQuery`'s call site to the new 4-arg signature**

In `receiver/nrpostgresqlreceiver/scraper_test.go`, modify line 1345 (inside `TestExplainQuery`):

```go
			plan, err := client.explainQuery(tc.query, tc.queryID, "", logger)
```

(The empty string for `explainFunction` means every existing test case in this table exercises the inline path — unchanged behavior, matches the design doc's statement that this is the escape hatch existing tests use.)

- [ ] **Step 2: Run existing `TestExplainQuery` to confirm regression-free baseline**

Run: `go build -C receiver/nrpostgresqlreceiver ./... && go test -C receiver/nrpostgresqlreceiver -run TestExplainQuery -v ./...`
Expected: PASS, all 4 existing subtests (`query with no parameters`, `query with single parameter`, `query with multiple parameters`, `query with hyphenated queryID`) — identical SQL/behavior to before this whole feature.

- [ ] **Step 3: Write the failing test for the function path in `explainQuery`**

Add to `receiver/nrpostgresqlreceiver/scraper_test.go`, as new subtests appended inside the same `TestExplainQuery`'s `testCases` table is the wrong shape here (the function path needs `WithArgs`, which the existing table doesn't support) — instead add a **new, separate test function** right after `TestExplainQuery` (after its closing `}` around line 1350):

```go
func TestExplainQueryViaFunction(t *testing.T) {
	t.Run("parameterized query calls the function with raw text as bound arg", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		logger, err := zap.NewProduction()
		require.NoError(t, err)

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

		query := "SELECT * FROM orders WHERE id = $1 FOR UPDATE"
		mockPlan := `[{"Plan":{"Node Type":"LockRows"}}]`
		mock.ExpectQuery(`SELECT "otel"."explain_statement"\(\$1\)`).
			WithArgs(query).
			WillReturnRows(sqlmock.NewRows([]string{"explain_statement"}).AddRow(mockPlan))

		plan, err := client.explainQuery(query, "12345", `"otel"."explain_statement"`, logger)
		require.NoError(t, err)
		assert.Equal(t, mockPlan, plan)
	})

	t.Run("non-parameterized query calls the function the same way, no PREPARE", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		logger, err := zap.NewProduction()
		require.NoError(t, err)

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

		query := "SELECT * FROM orders WHERE id = 5 FOR UPDATE"
		mockPlan := `[{"Plan":{"Node Type":"LockRows"}}]`
		mock.ExpectQuery(`SELECT "otel"."explain_statement"\(\$1\)`).
			WithArgs(query).
			WillReturnRows(sqlmock.NewRows([]string{"explain_statement"}).AddRow(mockPlan))

		plan, err := client.explainQuery(query, "12346", `"otel"."explain_statement"`, logger)
		require.NoError(t, err)
		assert.Equal(t, mockPlan, plan)
	})

	t.Run("function call error (undefined_function) is returned, not swallowed", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		logger, err := zap.NewProduction()
		require.NoError(t, err)

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

		query := "SELECT * FROM orders WHERE id = $1 FOR UPDATE"
		mock.ExpectQuery(`SELECT "otel"."explain_statement"\(\$1\)`).
			WithArgs(query).
			WillReturnError(&pq.Error{Code: pqerror.UndefinedFunction, Message: "function does not exist"})

		plan, err := client.explainQuery(query, "12347", `"otel"."explain_statement"`, logger)
		require.Error(t, err)
		assert.Empty(t, plan)
	})

	t.Run("function call error (non-42883, e.g. permission denied) is returned, not swallowed", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		logger, err := zap.NewProduction()
		require.NoError(t, err)

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

		query := "SELECT * FROM orders WHERE id = $1 FOR UPDATE"
		mock.ExpectQuery(`SELECT "otel"."explain_statement"\(\$1\)`).
			WithArgs(query).
			WillReturnError(&pq.Error{Code: pqerror.Code("42501"), Message: "permission denied for table orders"})

		plan, err := client.explainQuery(query, "12349", `"otel"."explain_statement"`, logger)
		require.Error(t, err)
		assert.Empty(t, plan)
		var pqErr *pq.Error
		require.ErrorAs(t, err, &pqErr)
		assert.NotEqual(t, pqerror.UndefinedFunction, pqErr.Code, "this case is specifically the non-42883 branch — must not be confused with the undefined_function case above")
	})

	t.Run("whitelist rejection skips the function path too", func(t *testing.T) {
		db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		logger, err := zap.NewProduction()
		require.NoError(t, err)

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

		plan, err := client.explainQuery("GRANT SELECT ON users TO demo", "12348", `"otel"."explain_statement"`, logger)
		require.NoError(t, err)
		assert.Empty(t, plan)
		// No mock.ExpectQuery was set up at all — if explainQuery touched the DB,
		// sqlmock would fail this test with "call to Query ... was not expected".
	})

	t.Run("explainFunction empty string forces inline path even for a FOR UPDATE query", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		logger, err := zap.NewProduction()
		require.NoError(t, err)

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

		query := "SELECT * FROM orders WHERE id = $1 FOR UPDATE"
		// Expect the INLINE sequence (PREPARE/EXPLAIN EXECUTE/DEALLOCATE), not a
		// call to the function — this proves explainFunction=="" always wins,
		// regardless of whether a function is configured/available elsewhere.
		expectedSQL := "/* otel-collector-ignore */ SET plan_cache_mode = force_generic_plan;PREPARE otel_12350 AS SELECT * FROM orders WHERE id = $1 FOR UPDATE;EXPLAIN(FORMAT JSON) EXECUTE otel_12350(null);"
		mock.ExpectQuery(expectedSQL).WillReturnRows(
			sqlmock.NewRows([]string{"QUERY PLAN"}).AddRow(`[{"Plan":{"Node Type":"LockRows"}}]`),
		)

		plan, err := client.explainQuery(query, "12350", "", logger)
		require.NoError(t, err)
		assert.Equal(t, `[{"Plan":{"Node Type":"LockRows"}}]`, plan)
	})
}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `go test -C receiver/nrpostgresqlreceiver -run TestExplainQueryViaFunction -v ./...`
Expected: FAIL. The "parameterized"/"non-parameterized"/both "function call error" subtests fail because `explainQuery` doesn't yet know how to branch on a non-empty `explainFunction` — it still ignores that 3rd positional value and always runs the inline `PREPARE` sequence, so sqlmock reports an unexpected query. The "whitelist rejection" and "explainFunction empty string forces inline path" subtests should already PASS (whitelist check and the empty-string default behavior are both unconditional and unchanged) — confirm they do; if not, something is wrong with the earlier tasks.

- [ ] **Step 5: Implement the branch in `explainQuery`**

In `receiver/nrpostgresqlreceiver/client.go`, replace `explainQuery` (lines 133-182) in full:

```go
// explainQuery implements client.
func (c *postgreSQLClient) explainQuery(query, queryID, explainFunction string, logger *zap.Logger) (string, error) {
	// Check if the query is explainable before attempting EXPLAIN
	if !isExplainableQuery(query) {
		logger.Debug("skipping EXPLAIN for non-explainable query", zap.String("queryID", queryID))
		return "", nil
	}

	if explainFunction != "" {
		return c.explainQueryViaFunction(query, queryID, explainFunction, logger)
	}

	return c.explainQueryInline(query, queryID, logger)
}

// explainQueryViaFunction calls a DBA-provisioned SECURITY DEFINER helper
// function to EXPLAIN a query the monitoring user cannot EXPLAIN directly
// (row-locking or write statements fail the plan-time privilege check for a
// read-only role). explainFunction must already be validated and quoted
// (see quoteExplainFunctionName) — this function does no further escaping.
func (c *postgreSQLClient) explainQueryViaFunction(query, queryID, explainFunction string, logger *zap.Logger) (string, error) {
	sql := fmt.Sprintf("SELECT %s($1)", explainFunction)
	wrappedDb := sqlquery.NewDbClient(sqlquery.DbWrapper{Db: c.client}, sql, logger, sqlquery.TelemetryConfig{})

	result, err := wrappedDb.QueryRows(context.Background(), query)
	if err != nil {
		logger.Error("failed to explain statement via function", zap.Error(err), zap.String("queryID", queryID))
		return "", err
	}

	if len(result) == 0 {
		return "", nil
	}

	var rawPlan string
	for _, v := range result[0] {
		rawPlan = v
		break
	}

	plan, err := obfuscateSQLExecPlan(rawPlan)
	if err != nil {
		logger.Error("failed to obfuscate explain plan", zap.Error(err), zap.String("queryID", queryID))
		return "", err
	}

	return plan, nil
}

// explainQueryInline runs EXPLAIN directly as the monitoring user via
// PREPARE/EXPLAIN EXECUTE/DEALLOCATE. This fails with permission denied for
// row-locking or write statements unless the monitoring user has write
// access — see explainQueryViaFunction for the alternative.
func (c *postgreSQLClient) explainQueryInline(query, queryID string, logger *zap.Logger) (string, error) {
	normalizedQueryID := strings.ReplaceAll(queryID, "-", "_")

	// PostgreSQL's pg_stat_statements returns queries with $1, $2 placeholders
	paramRegex := regexp.MustCompile(`\$\d+`)
	matches := paramRegex.FindAllString(query, -1)

	// Build nulls array for placeholders
	nulls := make([]string, len(matches))
	for i := range nulls {
		nulls[i] = "null"
	}

	defer func() {
		_, _ = c.client.Exec(fmt.Sprintf("/* otel-collector-ignore */ DEALLOCATE PREPARE otel_%s", normalizedQueryID))
	}()

	// if there is no parameter needed, we can not put an empty bracket

	nullsString := ""
	if len(nulls) > 0 {
		nullsString = "(" + strings.Join(nulls, ", ") + ")"
	}
	setPlanCacheMode := "/* otel-collector-ignore */ SET plan_cache_mode = force_generic_plan;"
	prepareStatement := fmt.Sprintf("PREPARE otel_%s AS %s;", normalizedQueryID, query)
	explainStatement := fmt.Sprintf("EXPLAIN(FORMAT JSON) EXECUTE otel_%s%s;", normalizedQueryID, nullsString)

	wrappedDb := sqlquery.NewDbClient(sqlquery.DbWrapper{Db: c.client}, setPlanCacheMode+prepareStatement+explainStatement, logger, sqlquery.TelemetryConfig{})

	result, err := wrappedDb.QueryRows(context.Background())
	if err != nil {
		logger.Error("failed to explain statement", zap.Error(err))
		return "", err
	}

	plan, err := obfuscateSQLExecPlan(result[0]["QUERY PLAN"])
	if err != nil {
		logger.Error("failed to obfuscate explain plan", zap.Error(err), zap.String("queryID", queryID))
		return "", err
	}

	return plan, nil
}
```

Note: `explainQueryViaFunction` reads the single returned column generically (the `for _, v := range result[0] { rawPlan = v; break }` loop) rather than by a hardcoded column name like the inline path's `result[0]["QUERY PLAN"]`, because the function's `RETURNS json` column is named after the function (e.g. `explain_statement`), not a fixed literal — confirmed by the DACI's tested function signature (`RETURNS json`, no explicit `AS "QUERY PLAN"` aliasing) and mirrored in the mock setup in Step 3 (`sqlmock.NewRows([]string{"explain_statement"})`).

- [ ] **Step 6: Run test to verify it passes**

Run: `go test -C receiver/nrpostgresqlreceiver -run TestExplainQueryViaFunction -v ./... && go test -C receiver/nrpostgresqlreceiver -run TestExplainQuery -v ./...`
Expected: PASS for both — the new function-path tests, and the pre-existing inline-path tests (regression check).

- [ ] **Step 7: Write the failing test for probe-cache lifecycle in the scraper**

Add to `receiver/nrpostgresqlreceiver/scraper_test.go`, a new test function after `TestExplainQuery`/`TestExplainQueryViaFunction`:

```go
func TestScraperExplainFunctionProbeCache(t *testing.T) {
	newScraperWithMockClient := func(t *testing.T, mockClient *mockClient) *postgreSQLScraper {
		cfg := createDefaultConfig().(*Config)
		cfg.ExplainFunctionName = "otel.explain_statement"
		factory := &mockClientFactory{}
		factory.On("getClient", mock.Anything).Return(mockClient, nil)

		settings := receivertest.NewNopSettings(metadata.Type)
		logger, err := zap.NewProduction()
		require.NoError(t, err)
		settings.TelemetrySettings = component.TelemetrySettings{Logger: logger}

		scraper, err := newPostgreSQLScraper(settings, cfg, factory, newCache(1),
			newTTLCache[string](1, time.Second),
			newTTLCache[explainSetupState](1, time.Second))
		require.NoError(t, err)
		return scraper
	}

	t.Run("probes once, caches available true on success", func(t *testing.T) {
		mc := &mockClient{}
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).Return(nil).Once()

		scraper := newScraperWithMockClient(t, mc)

		state, ok := scraper.explainFunctionCache.Get("testdb")
		assert.False(t, ok, "cache should start empty")

		err := scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)
		require.NoError(t, err)

		state, ok = scraper.explainFunctionCache.Get("testdb")
		require.True(t, ok)
		assert.True(t, state.available)
		assert.NoError(t, state.err)

		// Second call within the TTL window must not probe again.
		err = scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)
		require.NoError(t, err)
		mc.AssertNumberOfCalls(t, "probeExplainFunction", 1)
	})

	t.Run("probe failure with undefined_function (not provisioned) caches unavailable", func(t *testing.T) {
		mc := &mockClient{}
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).
			Return(&pq.Error{Code: pqerror.UndefinedFunction, Message: "does not exist"}).Once()

		scraper := newScraperWithMockClient(t, mc)
		err := scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)
		require.NoError(t, err) // probing failure is not a scrape error, it's a cached state

		state, ok := scraper.explainFunctionCache.Get("testdb")
		require.True(t, ok)
		assert.False(t, state.available)
		require.Error(t, state.err)
		var pqErr *pq.Error
		require.ErrorAs(t, state.err, &pqErr)
		assert.Equal(t, pqerror.UndefinedFunction, pqErr.Code)
	})

	t.Run("probe failure with a non-42883 error (present but broken) also caches unavailable", func(t *testing.T) {
		mc := &mockClient{}
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).
			Return(&pq.Error{Code: pqerror.Code("42501"), Message: "permission denied for table orders"}).Once()

		scraper := newScraperWithMockClient(t, mc)
		err := scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)
		require.NoError(t, err)

		state, ok := scraper.explainFunctionCache.Get("testdb")
		require.True(t, ok)
		assert.False(t, state.available, "same fallback outcome as the undefined_function case")
		require.Error(t, state.err)
		var pqErr *pq.Error
		require.ErrorAs(t, state.err, &pqErr)
		assert.NotEqual(t, pqerror.UndefinedFunction, pqErr.Code, "this is the distinct non-42883 branch — probeExplainFunctionIfNeeded logs it at Error, not Warn, per the code path taken (not independently asserted here: this test suite has no log-observing infra today, and the design's Testing section says not to add new test infra for this feature — the branch itself, and its effect on the cached state, is what this test verifies)")
	})

	t.Run("real explainQuery failure with undefined_function does not evict the cache", func(t *testing.T) {
		mc := &mockClient{}
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).Return(nil).Once()

		scraper := newScraperWithMockClient(t, mc)
		err := scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)
		require.NoError(t, err)

		state, ok := scraper.explainFunctionCache.Get("testdb")
		require.True(t, ok)
		assert.True(t, state.available, "cache must still say available after only a probe")

		// Simulate a real explainQuery call failing with undefined_function —
		// this must NOT evict/change the cache entry (Datadog-aligned: only the
		// dedicated probe writes to this cache).
		err = scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)
		require.NoError(t, err)
		mc.AssertNumberOfCalls(t, "probeExplainFunction", 1, "cache hit must not trigger a second probe")

		state, ok = scraper.explainFunctionCache.Get("testdb")
		require.True(t, ok)
		assert.True(t, state.available, "cache entry must remain unchanged regardless of real-call outcomes")
	})

	t.Run("two different databases are cached independently", func(t *testing.T) {
		mc := &mockClient{}
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).Return(nil).Once()
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).
			Return(&pq.Error{Code: pqerror.UndefinedFunction, Message: "does not exist"}).Once()

		scraper := newScraperWithMockClient(t, mc)

		err := scraper.probeExplainFunctionIfNeeded(t.Context(), "db_a", mc)
		require.NoError(t, err)
		err = scraper.probeExplainFunctionIfNeeded(t.Context(), "db_b", mc)
		require.NoError(t, err)

		stateA, ok := scraper.explainFunctionCache.Get("db_a")
		require.True(t, ok)
		assert.True(t, stateA.available)

		stateB, ok := scraper.explainFunctionCache.Get("db_b")
		require.True(t, ok)
		assert.False(t, stateB.available)
	})
}
```

Note: this test calls a not-yet-written method, `scraper.probeExplainFunctionIfNeeded(ctx, database, client)` — this is the method Step 9 implements. It also requires `mockClient` to support `probeExplainFunction` via `mock.Mock` (testify), not the hardcoded `panic("unimplemented")` stub from Task 3 Step 8 — Step 8 below replaces that stub.

- [ ] **Step 8: Replace the `mockClient.probeExplainFunction` stub with a testify-mock-backed implementation**

In `receiver/nrpostgresqlreceiver/scraper_test.go`, replace the stub added in Task 3 Step 8:

```go
// probeExplainFunction implements client.
func (m *mockClient) probeExplainFunction(ctx context.Context, quotedFunctionName string) error {
	args := m.Called(ctx, quotedFunctionName)
	return args.Error(0)
}
```

(This matches the existing `mockClient`/`mock.Mock` pattern used for other mocked methods in this file — check an existing mocked method like `getTopQuery` on `mockClient` for the exact idiom if one exists, and match it.)

Run: `grep -n "func (m \*mockClient)" receiver/nrpostgresqlreceiver/scraper_test.go` to confirm the existing idiom (parameter name `m` vs `_`, `.Called(...)` usage) before finalizing this snippet — adjust to match exactly if the existing convention differs.

- [ ] **Step 9: Run test to verify it fails**

Run: `go test -C receiver/nrpostgresqlreceiver -run TestScraperExplainFunctionProbeCache -v ./...`
Expected: FAIL — compile error, `probeExplainFunctionIfNeeded` undefined on `*postgreSQLScraper`.

- [ ] **Step 10: Implement `probeExplainFunctionIfNeeded` on `postgreSQLScraper`**

In `receiver/nrpostgresqlreceiver/scraper.go`, add this method near `collectTopQuery` (after it, or before — group with other top-query-collection helpers):

```go
// probeExplainFunctionIfNeeded returns the cached availability of the
// configured EXPLAIN helper function for database, probing it with a real,
// trivial call if there is no cache entry (first use, or the TTL expired).
// Real explainQuery call failures never write to this cache — only this
// probe does — matching Datadog's own explain-availability caching, which
// keeps a dedicated per-database cache separate from per-query error caching.
func (p *postgreSQLScraper) probeExplainFunctionIfNeeded(ctx context.Context, database string, dbClient client) error {
	if p.config.ExplainFunctionName == "" {
		return nil
	}

	if _, ok := p.explainFunctionCache.Get(database); ok {
		return nil
	}

	quoted := quoteExplainFunctionName(p.config.ExplainFunctionName)
	err := dbClient.probeExplainFunction(ctx, quoted)
	if err == nil {
		p.explainFunctionCache.Add(database, explainSetupState{available: true})
		return nil
	}

	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == pqerror.UndefinedFunction {
		p.logger.Warn("EXPLAIN helper function not found, falling back to inline EXPLAIN",
			zap.String("database", database),
			zap.String("explain_function_name", p.config.ExplainFunctionName),
			zap.Error(err))
		p.explainFunctionCache.Add(database, explainSetupState{available: false, err: err})
		return nil
	}

	if errors.As(err, &pqErr) {
		p.logger.Error("EXPLAIN helper function exists but failed, falling back to inline EXPLAIN",
			zap.String("database", database),
			zap.String("explain_function_name", p.config.ExplainFunctionName),
			zap.Error(err))
		p.explainFunctionCache.Add(database, explainSetupState{available: false, err: err})
		return nil
	}

	// Connection-level or other non-pq error: don't cache, retry probe next call.
	p.logger.Warn("failed to probe EXPLAIN helper function, will retry",
		zap.String("database", database),
		zap.Error(err))
	return nil
}
```

Add `"github.com/lib/pq"` and `"github.com/lib/pq/pqerror"` to `scraper.go`'s import block (check current imports at lines 6-34 first — `errors` is already imported at line 9; `pq`/`pqerror` are new).

- [ ] **Step 11: Wire the probe and function-name resolution into `collectTopQuery`**

In `receiver/nrpostgresqlreceiver/scraper.go`, modify `collectTopQuery` (lines 476-494) — replace:

```go
		plan, ok := p.queryPlanCache.Get(queryID + "-plan")
		if !ok && explained < maxExplainEachInterval {
			database := item.Value[string(semconv.DBNamespaceKey)].(string)
			dbClient, err := clientFactory.getClient(database)
			if err == nil {
				plan, err = dbClient.explainQuery(rawQuery, queryID, logger)
				if err != nil {
					logger.Error("failed to explain query", zap.String("query", rawQuery), zap.Error(err))
				}
				// to avoid flood the error message. there are some internal queries meant to not be
				// explained. we wait for the cache to expire and report the error again.
				p.queryPlanCache.Add(queryID+"-plan", plan)
				err = dbClient.Close()
				if err != nil {
					logger.Error("failed to close", zap.Error(err))
				}
			}
			explained++
		}
```

with:

```go
		plan, ok := p.queryPlanCache.Get(queryID + "-plan")
		if !ok && explained < maxExplainEachInterval {
			database := item.Value[string(semconv.DBNamespaceKey)].(string)
			dbClient, err := clientFactory.getClient(database)
			if err == nil {
				explainFunction := ""
				if probeErr := p.probeExplainFunctionIfNeeded(ctx, database, dbClient); probeErr == nil {
					if state, cached := p.explainFunctionCache.Get(database); cached && state.available {
						explainFunction = quoteExplainFunctionName(p.config.ExplainFunctionName)
					}
				}
				plan, err = dbClient.explainQuery(rawQuery, queryID, explainFunction, logger)
				if err != nil {
					logger.Error("failed to explain query", zap.String("query", rawQuery), zap.Error(err))
				}
				// to avoid flood the error message. there are some internal queries meant to not be
				// explained. we wait for the cache to expire and report the error again.
				p.queryPlanCache.Add(queryID+"-plan", plan)
				err = dbClient.Close()
				if err != nil {
					logger.Error("failed to close", zap.Error(err))
				}
			}
			explained++
		}
```

- [ ] **Step 12: Run the new scraper-level test to verify it passes**

Run: `go test -C receiver/nrpostgresqlreceiver -run TestScraperExplainFunctionProbeCache -v ./...`
Expected: PASS, all 6 subtests (probes-once/caches-available, undefined_function probe failure, non-42883 probe failure, no-eviction-on-real-call-failure, two-independent-databases).

- [ ] **Step 13: Add the TTL-expiry test**

Add to `receiver/nrpostgresqlreceiver/scraper_test.go`, inside `TestScraperExplainFunctionProbeCache` (or as its own test — either is fine; add as a new `t.Run` in the existing function for locality):

```go
	t.Run("cache entry expires via TTL and re-probes", func(t *testing.T) {
		cfg := createDefaultConfig().(*Config)
		cfg.ExplainFunctionName = "otel.explain_statement"
		mc := &mockClient{}
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).Return(nil).Twice()

		factory := &mockClientFactory{}
		factory.On("getClient", mock.Anything).Return(mc, nil)

		settings := receivertest.NewNopSettings(metadata.Type)
		logger, err := zap.NewProduction()
		require.NoError(t, err)
		settings.TelemetrySettings = component.TelemetrySettings{Logger: logger}

		scraper, err := newPostgreSQLScraper(settings, cfg, factory, newCache(1),
			newTTLCache[string](1, time.Second),
			newTTLCache[explainSetupState](1, 50*time.Millisecond)) // short TTL for the test
		require.NoError(t, err)

		err = scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)
		require.NoError(t, err)
		mc.AssertNumberOfCalls(t, "probeExplainFunction", 1)

		time.Sleep(100 * time.Millisecond) // past the 50ms TTL

		err = scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)
		require.NoError(t, err)
		mc.AssertNumberOfCalls(t, "probeExplainFunction", 2, "TTL expiry must trigger a fresh probe")
	})
```

- [ ] **Step 14: Run the full test to verify it passes**

Run: `go test -C receiver/nrpostgresqlreceiver -run TestScraperExplainFunctionProbeCache -v ./...`
Expected: PASS, all 7 subtests now.

- [ ] **Step 15: Run the full package test suite**

Run: `go build -C receiver/nrpostgresqlreceiver ./... && go test -C receiver/nrpostgresqlreceiver ./... -v 2>&1 | tail -100`
Expected: everything green. Pay particular attention to any existing golden-file test for `collectTopQuery`/`scrapeTopQuery` (e.g. a test asserting on the exact logs emitted) — since `collectTopQuery`'s body changed, a golden-log comparison test could need its expected output regenerated if it captures log fields. Check for such a test:

```bash
grep -n "golden.WriteLogs\|golden.WriteMetrics" receiver/nrpostgresqlreceiver/scraper_test.go
```

If any `TestScrapeTopQuery*`-style test fails because of an unexpected new log line or plan mismatch (not because of a real bug), regenerate that specific golden file by temporarily uncommenting its writer call, running the test once, then re-commenting the writer line (standard pattern for this repo — see `sync-and-port-nr-receivers` skill's Phase 2 notes on golden regeneration if unsure of the exact mechanic). Only do this if the diff is expected (e.g. because `explain_function_name` now defaults to `otel.explain_statement` and an existing test that didn't override it now goes through the function path instead of inline) — if a test's config doesn't set `ExplainFunctionName = ""` explicitly and its mock setup only expects the old inline SQL, **set `ExplainFunctionName = ""` on that test's config** rather than changing its golden file, to keep pre-existing tests exercising the same code path they always did.

- [ ] **Step 16: Commit**

```bash
git add receiver/nrpostgresqlreceiver/client.go receiver/nrpostgresqlreceiver/scraper.go receiver/nrpostgresqlreceiver/scraper_test.go
git commit -m "Branch explainQuery on SECURITY DEFINER function path with per-database probe caching"
```

---

### Task 5: README documentation

**Files:**
- Modify: `receiver/nrpostgresqlreceiver/README.md` (new section)

**Interfaces:**
- Consumes: nothing code-level — this is documentation only, describing the finished feature from Tasks 1-4.
- Produces: nothing consumed by other tasks — this is the last task in the plan.

- [ ] **Step 1: Find the Top Query Collection section**

```bash
grep -n "^#.*[Tt]op.[Qq]uery\|top_query_collection" receiver/nrpostgresqlreceiver/README.md
```

- [ ] **Step 2: Add the new subsection**

Insert a new subsection under the Top Query Collection heading found in Step 1 (match the existing heading depth, e.g. `###`):

```markdown
### Collecting EXPLAIN plans for locking and write queries (`explain_function_name`)

By default, `EXPLAIN` runs directly as the monitoring user. PostgreSQL checks table
privileges at *plan* time, so `EXPLAIN` on a query with a row-locking clause (`FOR
UPDATE`/`FOR SHARE`) or a write statement (`UPDATE`/`INSERT`/`DELETE`/`MERGE`) fails
with `permission denied` unless the monitoring user has write access — which this
receiver's monitoring user should never be granted.

To collect plans for these query types without granting write access, provision a
`SECURITY DEFINER` helper function once per database:

```sql
CREATE OR REPLACE FUNCTION otel.explain_statement(l_query text)
RETURNS json
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_plan json;
BEGIN
    SET TRANSACTION READ ONLY;
    EXECUTE 'EXPLAIN (FORMAT JSON) ' || l_query INTO v_plan;
    RETURN v_plan;
END;
$$;

GRANT EXECUTE ON FUNCTION otel.explain_statement(text) TO <monitoring_user>;
```

The function's owner needs write privilege on the target tables to pass PostgreSQL's
plan-time check — either a superuser, or a dedicated non-superuser role scoped to
exactly those tables. `SET TRANSACTION READ ONLY` guarantees no write is ever
possible, regardless of the owner's privileges. **The monitoring user itself must
never be granted `CREATE` on any database or schema it connects through** — the
function intentionally does not pin `search_path` (so unqualified table names in
captured queries resolve correctly), which is only safe if the monitoring role
cannot create objects to redirect that resolution into.

Configuration:

```yaml
receivers:
  nrpostgresql:
    top_query_collection:
      explain_function_name: otel.explain_statement  # default; empty string disables this feature
      explain_function_cache_ttl: 5m                  # default
```

If the function is not present (or fails), the receiver logs once and falls back to
running `EXPLAIN` directly, exactly as it does when this feature is not configured —
no error, no missing metrics, just no plan for the affected queries until the
function is provisioned (or, if it existed and was dropped, until the next probe
after `explain_function_cache_ttl` elapses).
```

- [ ] **Step 3: Visually confirm the README renders sensibly**

```bash
grep -n "explain_function_name" receiver/nrpostgresqlreceiver/README.md
```
Expected: the new section appears once, in the right place, with no broken markdown (check by eye — read the surrounding 10 lines before/after with `sed -n` if the heading placement is unclear).

- [ ] **Step 4: Commit**

```bash
git add receiver/nrpostgresqlreceiver/README.md
git commit -m "Document explain_function_name / explain_function_cache_ttl configuration"
```

---

## Final verification (after all 5 tasks)

Run the full gate for this package:

```bash
go build -C receiver/nrpostgresqlreceiver ./...
go test -C receiver/nrpostgresqlreceiver ./...
gofumpt -l receiver/nrpostgresqlreceiver
gci diff receiver/nrpostgresqlreceiver 2>/dev/null || true  # or: make -C receiver/nrpostgresqlreceiver generate, per repo convention
```

Then, against the live `db-test-lab` Postgres 16 container (`sri-db-postgres`, already running in
this environment) — this is the DACI-derived manual verification, not a `go test`:

1. Provision `otel.explain_statement` in `testdb` using the SQL from the README section (Task 5).
2. Point a locally-run receiver instance at the container with `explain_function_name:
   otel.explain_statement` set.
3. Run a `FOR UPDATE`/`UPDATE`/`DELETE` query against `testdb` so it becomes a top query.
4. Confirm the resulting `db.server.top_query` event has a non-empty plan — today (before this
   feature), it would be empty due to `permission denied`.
5. `DROP FUNCTION otel.explain_statement(text);` mid-run; confirm the next affected query logs
   `undefined_function` at `Error` and ships with no plan, and that behavior persists until
   `explain_function_cache_ttl` elapses and the receiver falls back to inline automatically.
