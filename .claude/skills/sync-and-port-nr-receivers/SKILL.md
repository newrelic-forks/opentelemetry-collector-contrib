---
name: sync-and-port-nr-receivers
description: "Use when syncing the newrelic-forks contrib repo with upstream and porting new upstream receiver changes into the nr-prefixed forks (nroracledbreceiver, nrsqlserverreceiver). Covers the full recurring release workflow: merge origin/main, align collector deps, compute the base→fork parity delta, port additively (handling attribute collisions and shared-metric drift), regenerate, and run all gates."
---

# Sync & Port NR-Prefixed Receivers

Keeps the `nr`-prefixed forks (`receiver/nroracledbreceiver`, `receiver/nrsqlserverreceiver`) in
sync with their upstream base receivers (`receiver/oracledbreceiver`, `receiver/sqlserverreceiver`)
after each upstream release. Runs on the `pre-release` branch of
`github.com/newrelic-forks/opentelemetry-collector-contrib`.

The parity target is the **computed diff between each fork and its base**, never a specific PR
number. A PR is just the concrete instance of "what's currently missing." Always recompute.

## Environment quirks (this repo/host)

- `go` is often NOT on PATH in the tool shell. Use `/usr/local/go/bin/go`.
- Do NOT `cd` inside compound commands — it can break PATH. Use `go <cmd> -C <dir>` and absolute paths.
- `origin/main` mirrors `upstream/main` (the fork's `main` tracks open-telemetry). Either works as the
  sync source; confirm they're equal first.
- Never `git commit` the PORT. Provide commit messages; the user commits. NOTE: `git merge` (Phase 1)
  necessarily creates a merge commit — that is expected and fine; it's the port/skill edits that stay
  uncommitted in the working tree. Do not `reset` the merge unless the user asks.
- **Match the base's code/comment style exactly.** Copy metric blocks, query consts, and templates
  VERBATIM. Do NOT add explanatory comments (PR numbers, "ported from…", section headers) that the base
  receiver doesn't have — the forks are meant to read identically to base for the ported parts.
- **IDE false errors**: after adding a function in `queries.go` and referencing it in `factory.go`, the
  editor's Go language server may show `undefined: getXxx` until it re-indexes. `go build` is the source
  of truth — if it compiles, the IDE error is stale (reload the workspace to clear).

## Phase 1 — Sync `pre-release` with `origin/main`

1. `git fetch origin` (and `git fetch upstream`). Confirm `origin/main` == `upstream/main`.
2. Check divergence: `git rev-list --count pre-release..origin/main` (behind) and the reverse (ahead).
3. **Pre-flight the merge** — must be conflict-free:
   `git merge-tree --write-tree origin/main pre-release` → exit 0 and no `CONFLICT` lines.
   Also list files changed in both since the merge-base; if that set is non-empty, expect conflicts
   and STOP to resolve deliberately.
4. `git merge --no-edit origin/main`. Confirm 0 unmerged files.
5. **Align collector deps** (REQUIRED — else `go test` fails with `go: updates to go.mod needed` and
   CI's `check-collector-module-version` fails, as in PR #205). The merge bumps the BASE receivers'
   `go.opentelemetry.io/collector/*` deps to a new pseudo-version; the 4 nr/internal modules must
   follow: `internal/nrcommon`, `internal/nrsqlquery`, `receiver/nroracledbreceiver`,
   `receiver/nrsqlserverreceiver`.
   - Find the new pseudo-version from a base receiver: `grep 'collector/pdata ' receiver/sqlserverreceiver/go.mod`.
   - For each nr module, `go mod edit -C <mod> -require=<path>@<newver>` for every `collector/*` require
     still on the old pseudo-version (`v1.62.1-<new>` for v1.* modules, `v0.156.1-<new>` for v0.* — match
     the base's major line), then `go mod tidy -C <mod>`. Tidy internal modules FIRST, then the receivers
     (receivers depend on them via `replace`).
   - Verify: `grep -c '<OLD-pseudo-date>' <mod>/go.mod` == 0 for all 4.
6. **Gate:** `go build -C <mod> ./...` and `go test -C <mod> ./...` green for both shipping receivers.
   Do not start porting until sync is green.

## Phase 2 — Compute the parity delta (per fork↔base pair)

Do this AFTER sync (fork vs POST-MERGE base). Measuring against the pre-merge base misses exactly the
new metrics you're trying to port.

**Metric-name delta** (use anchored, whole-key extraction — naive `grep -c "name"` gives false
negatives because `.` is a regex wildcard and metric/attribute keys collide):
```
comm -13 \
  <(git show pre-release:receiver/<fork>/metadata.yaml   | grep -oE "^  <prefix>\.[a-z0-9_.]+:" | sort -u) \
  <(git show origin/main:receiver/<base>/metadata.yaml   | grep -oE "^  <prefix>\.[a-z0-9_.]+:" | sort -u)
```
(`<prefix>` = `sqlserver` or `oracledb`; forks use the SAME metric prefix as base, not `nr...`.)
Run the reverse (`comm -23`) too — those are fork-specific metrics you must NEVER touch.

**Attributes and metrics live in different YAML sections.** Detect the section before classifying —
an "attribute" can look like a missing metric (e.g. `sqlserver.lock.timeout.type` is an attribute).
```
awk '/^attributes:/{s="attr"} /^metrics:/{s="metric"} /^  <key>:/{print s": "$0}' metadata.yaml
```

**Query / SQL-template delta (do NOT skip — metric parity does not imply query parity).** A base
receiver can change HOW it collects — the SQL query or embedded template — without changing the metric
list. These changes MUST be ported too, or the fork silently collects less/different data. Examples: the
oracledb change from `V$SQL_PLAN` → `V$SQL_PLAN_STATISTICS_ALL` (same emitted fields + 7 new runtime-stat
columns, backward-compatible), or new/edited perf-counter names in a sqlserver query. Compare the query
sources directly:
```
# Embedded SQL template files (oracledb uses templates/*.tmpl):
for f in $(cd receiver/<base>/templates && ls); do
  diff receiver/<fork>/templates/$f receiver/<base>/templates/$f && echo "  $f: in sync" || echo "  $f: DRIFT ^"
done
# Inline query constants in queries.go / scraper.go — diff the query bodies base vs fork
# (grep the SQL const names and compare SELECT column lists, FROM views, WHERE counter lists).
```
Because both receivers emit the plan as whole-row JSON (every selected column flows into the event
automatically), porting a template's new columns usually needs only: (1) replace the fork template with
the base's, (2) mirror the base's mock query-data testdata (add the new columns), (3) regenerate the
affected golden. No per-column Go mapping is required unless the base added explicit column handling.
- **Copy the template byte-for-byte** (`cp receiver/<base>/templates/<f> receiver/<fork>/templates/<f>`).
  The base often reorders SELECT columns (e.g. alphabetized) and may omit a trailing newline — a
  hand-edit that leaves a trailing-newline or order difference will show as perpetual "drift."
- The fork's tests may match the query via a loose `strings.Contains(sql, "V$SQL_PLAN")` — a substring
  that still matches `V$SQL_PLAN_STATISTICS_ALL`, so tests can PASS while the new columns go unexercised.
  Update the mock data + golden regardless, or the coverage is silently incomplete.

## Phase 2 — Classify each delta item

1. **Additive new metric** — copy the metric block VERBATIM from base metadata.yaml into the fork at the
   correct ALPHABETICAL position; add any genuinely-new attributes it references.
2. **Attribute-name collision** — the fork already defines the attribute name with a DIFFERENT enum (for
   its own metrics). Do NOT replace. **Union the enums** (widen to include both sets), keep the fork's
   description. Each metric's scraper still emits only its own subset; the widened enum just permits both.
3. **Shared-metric definition drift** — a metric present in BOTH but differing (e.g. the fork's copy
   dropped an attribute base has). Align the fork to base: add the attribute + wire the scraper to emit
   the extra series. Check the fork's query already returns the needed columns/counters before assuming
   query work is needed.
4. **Deliberate fork divergence** — a difference the team chose to keep. Record it in the divergence
   report; do NOT silently port or erase it.

## Phase 2 — Port additively (fork files only)

For each new metric, mirror the base's wiring into the fork's equivalent structures — the forks keep the
base's dispatch shape, so copy logic VERBATIM (including value scaling and `metadata.Attribute...` args):

- **metadata.yaml** — metric defs (alpha order) + attributes (new / unioned).
- **queries.go** — new query `const` + `getXxxQuery()` getter; add new counter/column names into the
  existing query's SELECT/WHERE list.
- **factory.go** — new `isXxxQueryEnabled()` wired into `setupQueries()`; add new metrics' `.Enabled`
  checks to the relevant `isXxxQueryEnabled()` (e.g. perf-counter metrics → `isPerfCounterQueryEnabled`).
- **scraper.go** — new record method + its `ScrapeMetrics` switch case; new `case` blocks (and their
  counter-name `const`s) in the shared record function. Copy scaling verbatim (e.g. µs→s `/1_000_000.0`,
  KB→bytes `*1024`).
- Reuse existing fork helpers (`retrieveInt`/`retrieveFloat`/`setupResourceBuilder`) — don't reinvent.
- NEVER modify fork-specific metrics/queries/events. Additive only.
- **Concurrent scraper**: `nrsqlserver` has a `concurrent_scraper.go` that fans out queries, but it
  consumes the output of `setupQueries(cfg)` automatically. A query added to `setupQueries` + a `case`
  in the `ScrapeMetrics` switch runs concurrently with no changes to `concurrent_scraper.go` itself.

## Phase 2 — Regenerate + tests

- Regenerate: `make -C receiver/<fork> generate` (runs mdatagen + fmt + gci). Updates
  `internal/metadata/generated_*.go`, `documentation.md`, `internal/metadata/testdata/config.yaml`.
- **Test fixtures often need manual updates** (they don't regenerate from mdatagen):
  - Expected-query text files (e.g. `testdata/perfCounterQueryWith[out]InstanceName.txt`) must match the
    new query — add the new counter/column lines in the same position.
  - Mock DB data files (e.g. `testdata/perfCounterQueryData.txt`) need rows for the new counters — copy
    them VERBATIM from the base's merged testdata.
  - Golden files (`testdata/expected*.yaml`) — regenerate by temporarily uncommenting the writer line
    in the relevant test, running it once, then RE-COMMENTING it (the writer aborts the test with a
    "must be removed" note, so a run that "fails" only on that note is fine). Verify the diff matches
    what you expect (e.g. +1 series from a new attribute, or exactly the N new plan columns).
    There are TWO writer types — pick the right one:
    - **Metric goldens** → `golden.WriteMetrics(t, expectedFile, actualMetrics)` (e.g. sqlserver
      `TestSuccessfulScrape` → `expectedPerfCounters.yaml` and its `RemoveServerResourceAttributes` variant).
    - **Log/event goldens** → `golden.WriteLogs(t, expectedFile, logs)` (e.g. oracledb
      `TestScraper_ScrapeTopNLogs` → `expectedQueryTextAndPlanQuery.yaml`; query-sample / top-query /
      session-wait events are logs, not metrics). The query-plan change lands here, NOT in a metric golden.
    - nrsqlserver has ~23 `expected*.yaml`, nroracledb ~6. Only the goldens for tests whose input/config
      changed will shift; regenerate just those and confirm the rest are untouched.
- Note: metrics added as `enabled: false` won't appear in default-config goldens unless the test enables
  them. A golden shift on a DEFAULT run usually means a shared-metric change (new attribute), not the new
  opt-in metrics — confirm the real cause before regenerating.
- **No changelog for the forks.** The base receivers require a `.chloggen/*.yaml` entry per change, but
  the `nr`-prefixed forks do NOT use `.chloggen` and have no `CHANGELOG.md` (prior ports like #49068 added
  none, and CI does not changelog-check the fork modules). Do not add a fork changelog entry; the base
  `.chloggen` entry that arrived with the merge already documents the upstream change.

## Phase 3 — Gates (all must pass, per fork module dir)

- `make -C receiver/<fork> generate` — no unexpected drift.
- `gofumpt -l` clean, `gci` diff empty (both run by `make generate`/`make fmt`).
- `make -C receiver/<fork> lint` — zero findings.
- `go build -C receiver/<fork> ./...` and `go test -C receiver/<fork> ./...` — green.
- **Reverse-diff guardrail**: confirm no fork-specific metric/attribute/query/event was removed
  (`git diff` should be purely additive except intended alignment).

## Phase 3 — Post-port parity verification (MANDATORY)

After porting, prove that EVERY metric and attribute present in the base receiver on `origin/main` now
exists in the fork. This is the final acceptance gate — run it for BOTH pairs
(`nroracledb`↔`oracledb`, `nrsqlserver`↔`sqlserver`), against the WORKING TREE (your uncommitted port),
not committed refs. Both commands below must print nothing.

```
# 1. Every base metric is in the fork (metrics: section only). Empty output = complete.
diff \
  <(awk '/^metrics:$/{m=1;next} m&&/^[a-z]/{m=0} m&&/^  <prefix>\./{print}' receiver/<base>/metadata.yaml \
      | grep -oE "^  <prefix>\.[a-z0-9_.]+:" | sort -u) \
  <(awk '/^metrics:$/{m=1;next} m&&/^[a-z]/{m=0} m&&/^  <prefix>\./{print}' receiver/<fork>/metadata.yaml \
      | grep -oE "^  <prefix>\.[a-z0-9_.]+:" | sort -u) \
  | grep '^<'    # lines only in base = STILL MISSING from fork → port them

# 2. Every base attribute is in the fork (attributes: section only). Empty output = complete.
diff \
  <(awk '/^attributes:$/{a=1;next} a&&/^[a-z]/{a=0} a&&/^  [a-z]/{print}' receiver/<base>/metadata.yaml \
      | grep -oE "^  [a-z][a-z0-9_.]*:" | sort -u) \
  <(awk '/^attributes:$/{a=1;next} a&&/^[a-z]/{a=0} a&&/^  [a-z]/{print}' receiver/<fork>/metadata.yaml \
      | grep -oE "^  [a-z][a-z0-9_.]*:" | sort -u) \
  | grep '^<'    # lines only in base = missing attribute → add it

# 3. Query-parity: classify SQL template drift by DIRECTION (base-only = port; fork-only = leave).
for f in $(cd receiver/<base>/templates 2>/dev/null && ls); do
  baseonly=$(diff receiver/<fork>/templates/$f receiver/<base>/templates/$f 2>/dev/null | grep -cE "^>")
  [ "$baseonly" -gt 0 ] && echo "PORT NEEDED ($baseonly base-only lines): $f"
done
# base-only (`>`) lines = upstream added something the fork lacks → PORT (e.g. V$SQL_PLAN_STATISTICS_ALL
#   columns). fork-only (`<`) lines = NR customization the base lacks → LEAVE (e.g. the fork's
#   full_query_text / statement_*_offset columns in the sqlserver query-sample templates).
# Also diff inline SQL query constants in queries.go/scraper.go (FROM views, SELECT columns,
# WHERE counter lists) base vs fork — a metric can be present while its query is stale.
```

- Also re-check **shared-metric attribute drift**: for metrics in both, compare each metric's
  `attributes:` list base vs fork. A base metric that carries an attribute the fork's copy lacks is
  drift to reconcile (see the `sqlserver.lock.timeout.rate` example). Lines where the FORK has an extra
  attribute the base lacks are fork-ahead (e.g. `oracle.db.pdb` per-PDB additions) — leave them.
- **Events too, not just metrics.** Both base receivers have an `events:` section in metadata.yaml
  (query-sample / top-query / session-wait). Diff the base `events:` block vs the fork's for new events
  or new event-level attributes the base added. The forks are usually fork-ahead here (NR added the
  event machinery), but a base-only addition must be ported like a metric.
- **Metric-count guard**: `nrsqlserver` `factory_test.go` `TestSetupQueries` asserts the exact metric
  count (`require.Len(t, metricsMetadata, N, ...)`) — bump `N` by the number of metrics added.
  `nroracledb` has NO such guard (don't go looking for one). When metrics were added to nrsqlserver and
  this literal isn't updated, the failure message literally tells you to update it.
- If either diff prints a `<` line, the port is INCOMPLETE — go back and port the listed item. Do not
  declare done until both diffs are empty for both receiver pairs.

## Output

Report: sync result (behind/ahead, conflict-free, dep-alignment), the parity delta per receiver
(to-port list + known-divergence list), files changed, gate results, and a per-phase commit message.
Flag that published fork tags now predate the port (a follow-up patch tag may be warranted) — do not
auto-tag.

## Worked example (2026-07 sync)

Sync brought 33 upstream commits. Work done:
- **All 4 nr modules** needed collector-dep pseudo-version alignment after the merge (Phase 1 step 5).
- **nrsqlserver** (upstream #49144): ported 10 new metrics (clr / cursor×4 /
  stored_procedure.invocation.rate / task×2 / worker×2) via metadata + queries.go (worker-threads query
  + 11 perf-counter names) + factory.go (`isWorkerThreadsQueryEnabled` + 8 perf-counter `.Enabled`
  checks) + scraper.go (`recordWorkerThreadMetrics` + 9 perf-counter cases). Two attribute-name
  collisions (`task.state`, `worker.state`) resolved by UNIONing enums. One shared-metric drift:
  `sqlserver.lock.timeout.rate` had dropped the `sqlserver.lock.timeout.type` attribute — the fork query
  already selected both counters, so only metadata + a `nonzero`/`all` scraper split were needed. Fixed
  the `TestSetupQueries` count guard (129→139); updated query-text fixtures + mock perf-counter data;
  regenerated `expectedPerfCounters.yaml` (+RemoveServerResourceAttributes) via `golden.WriteMetrics`.
- **nroracledb**: metric/attribute delta was 0, BUT there was a **query-only** change (#49329):
  the plan template moved `V$SQL_PLAN` → `V$SQL_PLAN_STATISTICS_ALL` (+7 runtime-stat columns). Ported by
  copying the template byte-for-byte, mirroring the base's mock plan data, and regenerating the LOGS
  golden `expectedQueryTextAndPlanQuery.yaml` via `golden.WriteLogs` (`TestScraper_ScrapeTopNLogs`). This
  is the case that proves "metric parity ≠ done" — a receiver at full metric parity still had a stale query.
- sqlserver query-sample templates showed diffs but were all **fork-ahead** (NR's `full_query_text` /
  offset columns) — left as-is.
