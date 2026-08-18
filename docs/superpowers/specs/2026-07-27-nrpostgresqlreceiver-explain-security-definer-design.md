# Design: EXPLAIN via SECURITY DEFINER helper function in `nrpostgresqlreceiver`

## Context

`nrpostgresqlreceiver` collects `db.server.top_query` events including each query's execution
plan, obtained by running `EXPLAIN (FORMAT JSON)` on the captured query text. PostgreSQL checks
table privileges at plan time, not only at execution time, so `EXPLAIN` on a statement with a
row-locking clause (`FOR UPDATE`/`FOR SHARE`/etc.) or a write statement (`UPDATE`/`INSERT`/
`DELETE`/`MERGE`) fails with `permission denied for table <table> (SQLSTATE 42501)` when the
connecting role has no write privilege — even though `EXPLAIN` without `ANALYZE` never reads,
writes, or locks a row. Today the only workaround is `GRANT UPDATE ON ALL TABLES ... TO dbmon`,
which gives the monitoring user real write access to every table — a security anti-pattern, and
the subject of an internal DACI ("PostgreSQL top_query - Collecting EXPLAIN Plans Without Granting
Write Access to the Monitoring User").

This adds an optional second path: if a DBA has provisioned a `SECURITY DEFINER` helper function
in their database (default name `otel.explain_statement(text) RETURNS json`), the receiver calls
that function instead of running `EXPLAIN` inline. The function runs the `EXPLAIN` with borrowed,
scoped privilege and `SET TRANSACTION READ ONLY`, so no real write is ever possible even though the
function's owner holds write grants. The monitoring user itself never needs write access — it only
needs `EXECUTE` on the function.

The receiver detects whether the function exists per database and falls back to today's inline
behavior if not — no hard failure, no breaking change for anyone who hasn't provisioned it.

This is intended as a long-term, upstream-contributable feature (`opentelemetry-collector-contrib`
is the ultimate target repo), not an NR-only stopgap — naming, config shape, and fallback behavior
are chosen to read as generic and defensible to an upstream reviewer, not tied to any one vendor's
convention.

## Non-goals

- The receiver does not create, own, or manage the helper function's lifecycle. Provisioning is a
  one-time, per-database DBA action, documented separately (DACI + README), not automated by the
  receiver.
- No receiver-side query rewriting or table-name qualification. The function's `search_path` is
  intentionally left unpinned (DACI finding) so unqualified table names in captured queries resolve
  the same way they would for the querying application — this requires the monitoring role to have
  no `CREATE` privilege anywhere it connects; that is a provisioning requirement, not something the
  receiver enforces or can verify.
- No change to `getTopQuery`, caching of the *rendered plan itself* (`queryPlanCache`), obfuscation,
  or the `top_query` event schema. All of that stays exactly as it is today.
- No feature gate (`go.opentelemetry.io/collector/featuregate`). Checked against upstream
  convention: feature gates are used for global, staged-migration toggles between two whole code
  paths (e.g. `receiver.postgresql.connectionPool`, which swaps `newPoolClientFactory` for
  `newDefaultClientFactory` for every database, forever, until the gate graduates and one path is
  deleted). This feature is a per-database runtime capability check — closer to the existing,
  gate-free `pg_stat_statements`-availability handling already in the base receiver, which silently
  degrades per-query with no gate at all. A single global gate cannot even model "available in some
  databases, not others" on one receiver instance.

## Architecture / approach

### Config

Add to `TopQueryCollection` (`config.go`):

```go
ExplainFunctionName     string        `mapstructure:"explain_function_name"`
ExplainFunctionCacheTTL time.Duration `mapstructure:"explain_function_cache_ttl"`
```

`ExplainFunctionName` defaults to `"otel.explain_statement"`, set in `factory.go`'s
`createDefaultConfig()`. Empty string disables the function path entirely and forces inline-only
EXPLAIN — the exact behavior the receiver has today, byte for byte. This is the escape hatch for
anyone who wants zero behavior change, and it's what most existing unit tests will set to avoid
needing a mock function-probe path.

`ExplainFunctionCacheTTL` defaults to `5 * time.Minute` (see Per-database probe cache below for why
this is a separate knob from `QueryPlanCacheTTL`).

The field name and default deliberately avoid any vendor name (own an earlier project decision:
"otel." prefix, not "nr." or any commercial-tool name) so the config and the SQL DDL a DBA runs
read the same way whether this lands in the fork or upstream.

### Validating `ExplainFunctionName` before it ever reaches a query

**This is the single detail most likely to draw a maintainer's attention, and it's worth getting
right rather than leaving implicit.** `ExplainFunctionName` becomes part of the literal SQL text the
receiver sends (`SELECT <name>('SELECT 1')` for the probe, `SELECT <name>($1)` for the real call) —
Postgres has no way to bind an *identifier* (a function or table name) as a query parameter the way
`database/sql` binds *values*; `$1`/`$2` placeholders only ever stand in for values. So this one piece
of the query is unavoidably built with string formatting, not parameterization, no matter which
receiver or agent does it.

Checked how Datadog handles the identical problem (`self._explain_function`, interpolated the same
way): their runtime hot path (`statement_samples.py:746`,
`"SELECT {}(%s)".format(self._explain_function)`) does **no validation at all** on the configured
name before interpolating it. They do have a validation helper, `_safe_identifier`
(`diagnose.py:986-1005`) — it rejects anything with more than one `.`, rejects any character outside
`[A-Za-z0-9_]` per segment, and double-quotes each segment before use — but it is only wired into
their separate, optional `diagnose` CLI tool (`diagnose.py:683`), never into the actual per-query
collection path that runs continuously in production. That's a real, checkable inconsistency in a
public, widely-used reference implementation, not a deliberate design choice on their part.

**This design validates on every path, not just a diagnostics tool**, closing that gap rather than
reproducing it — this is the strongest, most concrete answer to "why should a maintainer trust
string-built SQL here": validate the identifier once, at config-load time (`Config.Validate()`,
`config.go:68`, alongside the existing username/password/TLS checks — same place, same pattern,
no new validation entry point), reusing the exact rule Datadog's own `_safe_identifier` encodes:

```go
var explainFunctionNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)
```

- At most one `.` (optional schema qualifier) — matches `_safe_identifier`'s `len(parts) > 2` check.
- Each segment must be a valid unquoted Postgres identifier (letter/underscore start, alnum/underscore
  after) — matches `_safe_identifier`'s per-character check.
- `Config.Validate()` rejects the config outright (fails collector startup, same as an invalid
  `Endpoint` today) if `ExplainFunctionName` is non-empty and doesn't match. This is stricter than
  Datadog's runtime-only check: an operator finds out at startup, from a clear config error, not from
  a confusing SQL error the first time a top query is collected.
- Once validated, the receiver **always double-quotes each segment** before building the call (e.g.
  `otel.explain_statement` → `"otel"."explain_statement"`) — same as `_safe_identifier`'s quoting step
  — so even a validated, alphanumeric-only name can't collide with a Postgres reserved word or
  case-folding surprise.
- This validation runs exactly once, at config load, not per-query — no runtime cost added to the hot
  path this feature is trying to make faster/safer, not slower.

Net effect: the empty-string escape hatch (disables the feature) and a valid `[schema.]name` are the
only two states that pass validation; anything else — an attempt to inject additional SQL via the
config field — is rejected before the collector even starts, on every code path that uses this field,
not just an optional side tool.

### Per-database probe cache

**Validated against Datadog's own implementation** (`datadog_checks/postgres/statement_samples.py`,
`_get_db_explain_setup_state`/`_get_db_explain_setup_state_cached`) and matched to the same shape,
not just "similarly designed" — the mechanism below is Datadog's, with generic naming.

Add to `postgreSQLScraper` (`scraper.go`), alongside the existing `queryPlanCache`:

```go
explainFunctionCache *expirable.LRU[string, explainSetupState]

type explainSetupState struct {
    available bool
    err       error // nil when available; the classified failure otherwise, for logging/metrics
}
```

Constructed the same way as `queryPlanCache` (`newTTLCache[explainSetupState](size, ttl)` — reusing
the existing generic helper in `factory.go`), keyed by database name, **with a real TTL, not a
permanent map**. This matters for two concrete reasons:

1. **Provisioning is decoupled from receiver restarts.** A DBA can run the provisioning script
   *after* the receiver is already running. A permanent "not found" cache entry would mean the
   receiver never notices until it's restarted — wrong for something meant to be a long-term,
   low-friction feature. TTL expiry re-probes automatically. Datadog uses `ttl=300` (5 minutes);
   we default to the same order of magnitude via a dedicated `ExplainFunctionCacheTTL` config field
   (default `5 * time.Minute`) rather than reusing `QueryPlanCacheTTL` — the two caches answer
   different questions (query plans go stale on their own schedule; "does this function work" is a
   provisioning-state question that changes far less often) and Datadog's own split into two
   separately-tuned caches (`_collection_strategy_cache` vs. its plan-related caches) confirms they
   shouldn't share one knob.
2. **Symmetry with `queryPlanCache`.** Same cache *shape* (per-key TTL, `expirable.LRU`), different
   TTL value for the reason above.

`dbClient` itself is short-lived — created and `Close()`'d within a single scrape loop
(`scraper.go`, `collectTopQuery`) — so the cache **must** live on the long-lived `postgreSQLScraper`,
not on the client. A cache on the client would re-probe every single scrape interval and defeat the
purpose entirely; this was the first design mistake caught and corrected before writing this doc.

**Probe mechanism — a live validation call, not a catalog lookup.** An earlier draft of this design
probed with `SELECT to_regprocedure($1) IS NOT NULL` — a pure catalog lookup that only confirms a
function with the right name/signature *exists*. Checked against Datadog's actual implementation and
found theirs does more: `_get_db_explain_setup_state` **calls the function for real**, with a
trivial, always-valid statement (Datadog uses `EXPLAIN_VALIDATION_QUERY = "SELECT * FROM
pg_stat_activity"`; ours uses `SELECT 1`, since it needs no table access at all and so can never
fail for a reason unrelated to the function itself), and classifies the *outcome* of that real call.
This catches failure modes a catalog lookup cannot see — most importantly the DACI's own tested
finding that a function can exist but still fail with `permission denied` if its owner lacks
sufficient privilege (a SELECT-only owner fails EXPLAIN of locking/DML statements even though the
function is present and callable). A catalog-lookup probe would wrongly report "available" in
exactly that case; the receiver would only discover the problem later, reactively, on the first real
top query that needs it. The live-call probe catches it once, upfront, per database.

Probe query: `SELECT <explainFunctionName>('SELECT 1')`, run once per database per TTL window.
Classify the result:
- **Success** → cache `{available: true, err: nil}`.
- **`undefined_function` (SQLSTATE `42883`)** → function not provisioned. Cache `{available: false,
  err: <the error>}`. This is the expected, common state for anyone who hasn't run the provisioning
  script — logged at `Warn`, not `Error`.
- **Any other error** (e.g. `permission denied` from an under-privileged owner, a malformed function
  body, wrong return type) → function is present but broken. Cache `{available: false, err: <the
  error>}`, logged at `Error` — this is a provisioning misconfiguration worth surfacing distinctly
  from "not provisioned at all," mirroring Datadog's own distinction between
  `DBExplainError.failed_function` and a clean "no function" state.
- **Connection-level error** (the probe couldn't even reach the database) → do not cache; retry the
  probe on the next call. Matches Datadog's `connection_error`/`database_error` handling (lines
  666-677 of their `_get_db_explain_setup_state`) — a transient connectivity problem should not be
  conflated with "function doesn't work," and caching it would wrongly disable the feature for the
  full TTL over what may be a one-off blip.

**Mid-run function drop (DACI's own flagged risk — "Stateful: ... a dropped function silently
disables plan collection") — corrected to match Datadog exactly, after checking their code directly.**
An earlier draft of this design had the receiver evict the per-database cache entry immediately on
a real-call `undefined_function` failure, reasoning that "every real explain attempt updates the
cache." **That is not what Datadog's code does, and this design now doesn't either.** Checked
directly (`statement_samples.py`): Datadog keeps two separate caches with no interaction between
them —
- `_collection_strategy_cache` (ours: `explainFunctionCache`) — keyed by `dbname`, written **only**
  by the dedicated validation probe (`_get_db_explain_setup_state`), pure TTL (`ttl=300`), **never**
  written to by a real explain call's outcome.
- `_explain_errors_cache` — keyed by `query_signature` (per query, not per database), written by
  real explain-call failures, used to skip re-attempting a query that's known to fail deterministically
  (e.g. a type mismatch). This is a *different* cache for a *different* question ("did this specific
  query fail before," not "does the function work for this database") and it never reads or writes
  `_collection_strategy_cache`.

The real call path (`_run_explain_safe`, line 805 of their file) only ever *reads*
`_get_db_explain_setup_state_cached` — it has no write path back into that cache on failure.

**So the correct, Datadog-aligned behavior is: no early eviction, ever, for either direction.**
- **Drop:** if the function is dropped mid-run, the per-database cache still says `available: true`
  until the TTL naturally expires (up to `ExplainFunctionCacheTTL`, default 5 minutes). Every real
  call in that window hits `undefined_function`, gets logged at `Error`, returns no plan for that one
  query (same degraded-not-crashed outcome as any other explain failure) — and the cache is left
  alone. Only the next scheduled probe, after TTL expiry, re-evaluates and flips the cache to
  `available: false`.
- **Recreate-after-drop:** symmetric — once cached `available: false`, real calls stop hitting the
  function at all (inline path is used instead), so there's no real call left to notice a recreate.
  Detection is bounded by the same TTL window.

This means detection latency is **symmetric, not asymmetric** — both directions are bounded by
`ExplainFunctionCacheTTL`, never faster, never slower. The DACI's "stateful, silently disables plan
collection" risk is not eliminated by this design (nor by Datadog's) — it's *bounded*: plan
collection for locking/write queries on an affected database can be down for up to one TTL window
after a drop, and takes up to one TTL window to resume after a fix, with every affected query logged
at `Error` in the meantime so the gap is visible in logs even though it isn't instantly self-healing.

### `explainQuery` branch

`client.go`'s `explainQuery` gains **exactly one** new parameter — the resolved function name
(empty string = disabled) — keeping the `client` interface mockable without baking config access
into it:

```go
explainQuery(query, queryID, explainFunction string, logger *zap.Logger) (string, error)
```

Note this does **not** add a `ctx context.Context` parameter, even though every other method on the
`client` interface takes one and `explainQuery` is currently the sole outlier (it uses
`context.Background()` internally today, `client.go:169`). Fixing that inconsistency is out of scope
for this change — it's an unrelated, unforced cleanup that would touch the single call site
(`scraper.go:481`) for no functional benefit to this feature. Keep the change surface to what this
feature strictly needs.

- `isExplainableQuery` whitelist check runs first, unchanged, in both branches — returns `("", nil)`
  before touching the DB at all for anything not on the whitelist.
- `explainFunction == ""` → today's inline `PREPARE otel_<id>` → `EXPLAIN(FORMAT JSON) EXECUTE
  otel_<id>(nulls)` → `DEALLOCATE` sequence, completely unchanged. Still branches on `$N`
  placeholders via the existing `paramRegex` to build the `nulls` array.
- `explainFunction` set and the per-database probe says available → `SELECT
  <quoted-explainFunction>($1)` (per-segment double-quoted, per the validation/quoting rule above —
  e.g. `"otel"."explain_statement"($1)`) with the **raw query text as-is** (placeholders included) as
  the sole bound parameter. No `PREPARE`/`DEALLOCATE`, no `nulls` array — the split between parameterized and
  non-parameterized queries that the inline path needs does **not** apply here, because the
  function's own body (`EXECUTE 'EXPLAIN (FORMAT JSON) ' || l_query INTO v_plan;`, provisioned
  DBA-side, verified against a live PG 16.14 container in the DACI work) treats `$1`/`$2` inside
  the query text as literal characters of the string being explained — they are never bound as
  parameters of the outer `SELECT <function>(...)` call. Both cases produce the *same* single SQL
  call from the receiver; the function path is simpler than the inline path specifically because of
  this.
- Result passed through `obfuscateSQLExecPlan`, unchanged, in both branches.

### Footprint — kept deliberately small

- `client.go`: `client` interface line 73 (signature), `explainQuery` function body (add the
  branch), `isExplainableQuery`/`explainableStatements` untouched.
- `scraper.go`: one call site (line 481) gains one argument; `postgreSQLScraper` struct gains one
  field (`explainFunctionCache`); `newPostgreSQLScraper` gains one parameter for that cache,
  mirroring how `queryPlanCache` was added.
- `config.go`: two new fields on the existing `TopQueryCollection` struct — no new top-level config
  section, no new nested struct. `Config.Validate()` (line 68) gains one more check, in the same
  style as the existing `Username`/`Password`/TLS checks — validates `ExplainFunctionName` against
  the identifier pattern (see Validating `ExplainFunctionName` above), appended via the same
  `multierr.Append` pattern already used for every other field.
- `factory.go`: `createDefaultConfig()` gains two default values (existing struct literal, two more
  lines); **all three** `newPostgreSQLScraper(...)` call sites (`createMetricsReceiver`, and both
  branches inside `createLogsReceiver`) need the extra cache argument threaded through, even the two
  that have nothing to do with top-query/EXPLAIN — this mirrors exactly how `queryPlanCache` itself
  is already threaded through today (all three sites pass *some* value for it, even
  `createMetricsReceiver` and the query-sample branch, which pass a throwaway
  `newTTLCache[string](1, time.Second)` placeholder since they don't use it). The new
  `explainFunctionCache` argument follows the identical existing pattern — a real cache only where
  it's used (the top-query branch), a same-shaped placeholder elsewhere — not a new pattern.
- No changes to `getTopQuery`, `getQuerySamples`, connection pooling, or any of the ~15 other
  `client` interface methods.
- **No feature gate added**, even though this file already has three
  (`ReceiverNrpostgresqlConnectionPoolFeatureGate`, `...SeparateSchemaAttrFeatureGate`,
  `...UseOTelSemconvFeatureGate`, all wired in `factory.go`) — reconfirms the Non-goals reasoning:
  those three gate global, staged code-path swaps; this is a per-database runtime state, which a
  gate can't express and doesn't need to.

## Error handling

| Situation | Behavior |
|---|---|
| Probe: function not provisioned (`undefined_function`, 42883) | Cache `{available: false, err}` with TTL. Log once per database at `Warn` (expected/normal state, not an error). Fall through to inline path for this and all calls until TTL expiry. |
| Probe: function present but broken (any other error — bad owner privilege, malformed body, wrong signature) | Cache `{available: false, err}` with TTL. Log once per database at `Error` — distinct from "not provisioned," since this means a DBA ran the provisioning script but got something wrong, which is worth surfacing differently. Fall through to inline for this database until TTL expiry or a corrected re-probe. |
| Probe: connection-level failure (couldn't reach the database at all) | Do not cache. Treat as unknown; fall back to inline for this call only; retry the probe on the next call. Caching off a transient connectivity failure would wrongly disable the feature for the full TTL over what may be a one-off blip. Matches Datadog's `connection_error`/`database_error` handling. |
| Real `explainQuery` call fails with `undefined_function` (42883) mid-run | Function existed at last probe, has since been dropped. **Cache entry is left as-is (Datadog-aligned — see Architecture): no early eviction.** Log at `Error` with query text, matching existing inline-path error logging (`client.go:171`). Return the error up to `scraper.go`'s existing handling (logged, cached as empty string, scrape continues) — same reliability bar as an inline EXPLAIN failure today. Every call in this database's remaining TTL window repeats this same outcome; the cache only updates on the next scheduled probe after TTL expiry. |
| Real `explainQuery` call fails with any other error (e.g. transient) | Log at `Error`, return the error, same downstream handling as above. Do **not** fall back to inline mid-call — that would double query cost per top query and could mask a real problem (e.g. wrong owner grants that only manifest on certain statement types) behind an always-succeeding inline path that silently loses locking/write-query coverage. A visible, logged failure is preferable to a silently degraded one here. Cache entry is left as-is, same as the row above — real-call outcomes never write to `explainFunctionCache`, only the dedicated probe does. |
| `isExplainableQuery` rejects the query | Unchanged: `("", nil)`, no DB call in either path. |

No scrape-level hard failures are introduced by this feature in any case above — every failure mode
degrades to "this one query's plan is missing, logged," matching the reliability bar of the
existing inline path.

## Testing

Extends the existing `sqlmock` pattern in `config_test.go`, `client_test.go`, and
`scraper_test.go` — no new test infra, no mocking library changes.

**`config_test.go` (`Config.Validate()` — `ExplainFunctionName` identifier check):**
1. Valid unqualified name (`explain_statement`) — passes validation.
2. Valid schema-qualified name (`otel.explain_statement`, the default) — passes validation.
3. Empty string — passes validation (the documented disable path, not an error).
4. Rejected: more than one `.` (e.g. `a.b.c`) — `Validate()` returns an error, mirroring
   `_safe_identifier`'s `len(parts) > 2` check.
5. Rejected: SQL metacharacters / injection attempt (e.g. `explain_statement; DROP TABLE orders`,
   or `explain_statement" --`) — `Validate()` returns an error. This is the test that directly
   demonstrates the fix over Datadog's runtime-only `_safe_identifier` gap: an attempt to smuggle
   extra SQL through this config field is rejected at startup, not discovered from a confusing SQL
   error the first time a query is explained.
6. Rejected: leading digit or other invalid identifier start (e.g. `1explain`) — matches Postgres's
   own unquoted-identifier rule, not just an arbitrary regex choice.

**`client_test.go` (`explainQuery` unit tests):**
7. Inline path, parameterized query — existing test, must remain unchanged/passing (regression
   guard).
8. Inline path, non-parameterized query — existing test, unchanged.
9. Function path, parameterized query — mock expects `SELECT "otel"."explain_statement"($1)` (note:
   quoted, per-segment, once validated — not the bare `otel.explain_statement` — see Validating
   `ExplainFunctionName` above) with the raw, placeholder-containing text as the bound parameter;
   asserts no `PREPARE`/`DEALLOCATE` statements are issued.
10. Function path, non-parameterized query — same mock shape, confirms the identical code path
    executes regardless of whether the query has placeholders (no receiver-side branching).
11. Function path, function call returns `undefined_function` (42883) — confirms the error is
    returned (not swallowed, not silently retried inline). Does **not** assert any cache
    interaction — `explainQuery`/`client.go` has no access to the scraper's cache in the first
    place; cache behavior is scraper-level and covered separately in test 18.
12. Function path, function call returns some other (non-42883) SQL error — confirms error is
    logged/returned, no fallback to inline mid-call.
13. `explainFunction == ""` — confirms inline path is taken unconditionally, even if a probe cache
    entry says the function is available (config-off wins).
14. Whitelist rejection — existing test, confirms neither path touches the mock DB.

**`scraper_test.go` (probe cache lifecycle across scrape cycles):**
15. First scrape for a database, function present and callable — mock expects exactly one
    `SELECT "otel"."explain_statement"('SELECT 1')` validation call; cache populated
    `{available: true, err: nil}`; `explainQuery` uses the function path.
16. Second scrape, same database, same scraper instance — mock expects **zero** additional
    validation calls (cache hit). This is the test that actually proves the "don't re-probe every
    scrape" requirement from the design, not just an assumption.
17. Probe fails with `undefined_function` — confirms subsequent `explainQuery` calls for that
    database use the inline path, the cache holds `{available: false, err}`, and the `Warn` log
    fires exactly once, not once per scrape.
18. Probe fails with a non-42883 error (e.g. `permission denied`, simulating a misconfigured owner)
    — confirms the cache holds `{available: false, err}` the same as case 17, but the log fires at
    `Error`, not `Warn` — asserting the two failure modes are distinguishable in logs even though
    both fall back to inline.
19. Real `explainQuery` call fails with `undefined_function` mid-run (simulating a dropped
    function, cache previously said `available: true`) — confirms the cache entry is **left
    unchanged** (Datadog-aligned: real-call outcomes never write to the probe cache) and the
    *next* scrape still uses the function path (cache hit, no re-probe) rather than falling back
    to inline. This is the test that guards against silently reintroducing the "evict on 42883"
    behavior from an earlier draft — it must fail loudly if that behavior comes back.
20. Probe cache entry expires via TTL — existing tests already construct scrapers with a
    `newTTLCache[string](1, time.Second)` 1-second TTL (`scraper_test.go`, e.g. line 46); this test
    reuses that same short-TTL construction (with the `ExplainFunctionCacheTTL` config field, not
    the shared `queryPlanCache` TTL — see Architecture), sleeps past it, and confirms a fresh
    validation call fires on the next call rather than an immediate re-probe or a permanent skip.
21. Two different databases in the same scraper — confirms the cache is keyed per-database, not
    global: one database having the function provisioned and working must not make the receiver
    assume every database does.

## Documentation and changelog (required for any config/behavior change per `CONTRIBUTING.md`)

- `README.md`: new section under Top Query Collection documenting (a) the `explain_function_name`
  config field and its default/empty-string behavior, (b) the exact SQL DDL a DBA runs to provision
  `otel.explain_statement` (pointing at the DACI's tested Appendix script — both the superuser-owner
  and scoped-role-owner variants), (c) that the monitoring role must never be granted `CREATE`
  anywhere it connects, for the reason documented in the DACI.
- **No `.chloggen` entry while this lives in the fork** — confirmed against the repo's own convention
  (`sync-and-port-nr-receivers` skill, and an empty-result grep for any existing
  `component: receiver/nr*` `.chloggen` entry): the `nr`-prefixed forks don't use `.chloggen` and have
  no `CHANGELOG.md`, so adding one here would be inconsistent with every prior fork change. **A
  `.chloggen/<slug>.yaml` entry is only added if/when this lands upstream** in
  `receiver/postgresqlreceiver` — `change_type: enhancement`, one-line note, issue link, at that time.

## Verification (how to confirm this works end to end, beyond unit tests)

1. Bring up the existing `db-test-lab` Postgres 16 container (already running as `sri-db-postgres`
   in this environment).
2. Provision `otel.explain_statement` using the DACI's tested Appendix script (either owner path).
3. Set `explain_function_name: otel.explain_statement` in the receiver's test config; point it at
   the test container; run a workload that produces `FOR UPDATE`/`UPDATE`/`DELETE` top queries.
4. Confirm `db.server.top_query` events now include non-empty plans for those query types — today
   they'd be silently missing (see DACI's own "Verified on PostgreSQL 16.14" item 3).
5. Drop the function mid-run; confirm each affected top query logs `undefined_function` at `Error`
   and ships with no plan (no crash, no missing metrics otherwise) for the remainder of the current
   `ExplainFunctionCacheTTL` window — then confirm the receiver falls back to inline automatically
   once the TTL expires and the next scheduled probe re-evaluates. This is deliberately not instant
   (see Architecture — matches Datadog's own TTL-only model); the test should confirm the bound is
   respected, not that recovery is immediate.
