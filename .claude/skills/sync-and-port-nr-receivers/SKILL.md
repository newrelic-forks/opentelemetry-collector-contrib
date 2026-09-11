---
name: sync-and-port-nr-receivers
description: "Use when syncing the newrelic-forks contrib repo with upstream and porting new upstream receiver changes into the nr-prefixed forks (nroracledbreceiver, nrsqlserverreceiver, nrpostgresqlreceiver, nrmysqlreceiver). Covers branching from pre-release, merging origin/main, aligning collector deps, computing the base→fork parity delta, porting additively (handling attribute collisions and shared-metric drift), regenerating, and running all gates. Does NOT cut a release — see [[release-nr-receivers]] for tagging/publishing on the bi-weekly cadence, which runs every cycle regardless of whether this skill found anything to port."
---

# Sync & Port NR-Prefixed Receivers

**Relationship to [[release-nr-receivers]]:** this skill answers "did we pull in upstream's new
metrics/queries." That skill answers "is there a tagged release NRDOT can consume, and does its
changelog say what changed." Run this skill when there's new upstream content to absorb; run
release-nr-receivers every cycle regardless, even when this skill was a no-op — NRDOT bumps on a
fixed 2-week schedule and needs a new fork tag every time, changes or not.

Keeps the `nr`-prefixed forks (`receiver/nroracledbreceiver`, `receiver/nrsqlserverreceiver`,
`receiver/nrpostgresqlreceiver`, `receiver/nrmysqlreceiver`) in sync with their upstream base
receivers (`receiver/oracledbreceiver`, `receiver/sqlserverreceiver`, `receiver/postgresqlreceiver`,
`receiver/mysqlreceiver`) after each upstream release. Work happens on a branch cut FROM
`pre-release` on `github.com/newrelic-forks/opentelemetry-collector-contrib` — never directly on
`pre-release` itself (see "Mandatory branching + PR process" below).

Fork↔base pairs (add new pairs here as new `nr`-prefixed forks are created — do not hardcode the
pair count elsewhere in this skill):

| Fork | Base | Metric/attribute prefix | Notes |
|---|---|---|---|
| `receiver/nroracledbreceiver` | `receiver/oracledbreceiver` | `oracledb` | has `templates/*.tmpl` SQL templates |
| `receiver/nrsqlserverreceiver` | `receiver/sqlserverreceiver` | `sqlserver` | has `templates/*.tmpl`; `concurrent_scraper.go`; `TestSetupQueries` metric-count guard |
| `receiver/nrpostgresqlreceiver` | `receiver/postgresqlreceiver` | `postgresql` | has `templates/*.tmpl`; some queries also inline in `client.go`/`scraper.go` |
| `receiver/nrmysqlreceiver` | `receiver/mysqlreceiver` | `mysql` | has `templates/*.tmpl`; some queries also inline in `client.go`/`scraper.go`; has `explain_mode` fork-specific field |

**ALL FOUR forks have a `templates/` directory.** An earlier version of this table claimed nrpostgresql
and nrmysql had none, so the query-parity step got skipped for them; two of nrpostgresql's four
templates needed porting in the 2026-09 sync. Never assume — `ls receiver/<fork>/templates/` each cycle.

The parity target is the **computed diff between each fork and its base**, never a specific PR
number. A PR is just the concrete instance of "what's currently missing." Always recompute.

## Mandatory branching + PR process (per NR-Prefixed Receiver Sync & Release Process doc)

- **Never work directly on `pre-release`.** Always create a new branch FROM `pre-release` before
  doing anything — including Phase 1's `git merge`. Naming convention: `sync-release/v<TARGET_VERSION>`
  (e.g. `sync-release/v0.158.0`). `<TARGET_VERSION>` is the `contrib-base` version in the repo root's
  `versions.yaml` (matches the pseudo-version base's `go.opentelemetry.io/collector/*` deps just moved
  to during Phase 1 step 5 — read it off any base receiver's go.mod, e.g.
  `grep 'collector/pdata ' receiver/sqlserverreceiver/go.mod`, and cross-check against `versions.yaml`).
- Complete Phase 1 (Sync & Port) and draft the changelog (that's [[release-nr-receivers]]'s Part 2) on
  this branch, then open a PR against `pre-release`. Post the PR link in `#data-integrations-team` for
  team review — required before merging or pushing tags.
- If you're resuming work already sitting on a misnamed branch (e.g. you started before confirming the
  target version), `git branch -m <old> sync-release/v<TARGET_VERSION>` renames in place — safe as long
  as nothing has been pushed/PR'd yet, since it's a pure local relabel that doesn't touch the working
  tree or history.

## Environment quirks (this repo/host)

- Run `which go` before assuming a path. On this host it is `/opt/homebrew/bin/go` and IS on PATH;
  `/usr/local/go/bin/go` does not exist. If PATH is unreliable in the tool shell, prepend it
  (`export PATH=/opt/homebrew/bin:$PATH`) rather than hardcoding a guessed absolute path.
- Do NOT `cd` inside compound commands — it can break PATH. Use `go <cmd> -C <dir>` and absolute paths.
- **`origin` has BOTH a `main` and a `MAIN` branch**, which collide on macOS's case-insensitive
  filesystem: after `git fetch origin`, `git rev-parse origin/main` fails with "unknown revision"
  because only one ref file can exist. Use `upstream/main` as the sync source instead. Confirm they
  match by comparing SHAs: `git ls-remote --heads origin refs/heads/main` vs `git rev-parse upstream/main`.
- **Lint locally with the PINNED linter, not whatever `golangci-lint` is on PATH.** CI pins v2.13.1 via
  `internal/tools/go.mod`; a stale local v1.x lacks the `modernize` linter entirely and will report
  "clean" on code CI rejects. Resolve it the way the Makefile does:
  `GOOS= GOARCH= go tool -modfile=internal/tools/go.mod -n github.com/golangci/golangci-lint/v2/cmd/golangci-lint`
  — or just use `make -C <mod> lint`, which does this for you.
- `gopls` may flag valid Go 1.26 syntax (e.g. `new(expr)`) as an error if the editor's gopls predates
  1.26. `go build`/`go vet`/`make lint` are the source of truth; upgrade gopls rather than "fixing" code.
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

**What "Phase 1 is done" means — do not use "behind upstream/main" as the test.** `main` keeps
receiving commits after a release is tagged, so a completed sync is ALWAYS "behind main" within
hours. Being 84 commits behind with 10 touching the base receivers is normal and is NOT an
incomplete sync. The decisive checks are:

```
git merge-base --is-ancestor v<TARGET> HEAD && echo "target release fully merged"
git rev-list --count HEAD..v<TARGET>          # must be 0
git show upstream/main:versions.yaml | grep -A1 contrib-base   # confirms no newer release exists yet
```

To decide whether a specific upstream commit was in scope, test it against the release tag, not
against `main`: `git merge-base --is-ancestor <sha> v<TARGET>`. If it is not an ancestor of the tag,
it is post-release work for the NEXT cycle.

One consequence worth being explicit about: merging `origin/main` pulls in post-release commits too,
so **the base receivers in your tree are "v<TARGET> + some unreleased commits."** The parity target is
the POST-MERGE base in your working tree (as Phase 2 says), which means those unreleased changes are
legitimately in scope for this port — e.g. in the 2026-09 cycle `#50008` and `#50669` were both
post-v0.160.0 yet correctly ported. Don't reject a delta just because it postdates the tag.

1. `git fetch origin` (and `git fetch upstream`). Confirm `origin/main` == `upstream/main`.
2. Check divergence: `git rev-list --count pre-release..origin/main` (behind) and the reverse (ahead).
3. **Pre-flight the merge** — must be conflict-free:
   `git merge-tree --write-tree origin/main pre-release` → exit 0 and no `CONFLICT` lines.
   Also list files changed in both since the merge-base; if that set is non-empty, expect conflicts
   and STOP to resolve deliberately.
4. `git merge --no-edit origin/main`. Confirm 0 unmerged files.
5. **Align collector deps** (REQUIRED — else `go test` fails with `go: updates to go.mod needed` and
   CI's `check-collector-module-version` fails, as in PR #205). The merge bumps the BASE receivers'
   `go.opentelemetry.io/collector/*` deps to a new pseudo-version; every nr/internal module must
   follow: `internal/nrcommon`, `internal/nrsqlquery`, `receiver/nroracledbreceiver`,
   `receiver/nrsqlserverreceiver`, `receiver/nrpostgresqlreceiver`, `receiver/nrmysqlreceiver` (6
   modules as of the fork↔base table above — this count is NOT fixed; re-derive it by listing the
   actual `nr`-prefixed receiver dirs plus the shared `internal/nr*` modules each time, since new
   forks get added).
   - Find the new pseudo-version from a base receiver: `grep 'collector/pdata ' receiver/sqlserverreceiver/go.mod`.
   - For each nr module, `go mod edit -C <mod> -require=<path>@<newver>` for every `collector/*` require
     still on the old pseudo-version (`v1.62.1-<new>` for v1.* modules, `v0.156.1-<new>` for v0.* — match
     the base's major line), then `go mod tidy -C <mod>`. Tidy internal modules FIRST, then the receivers
     (receivers depend on them via `replace`).
   - Verify: `grep -c '<OLD-pseudo-date>' <mod>/go.mod` == 0 for every nr/internal module.
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
- **`config.schema.yaml` IS generated — but by a separate root-level target that per-module
  `make generate` does NOT run, and mdatagen happily accepts a stale one without erroring** (a stale
  schema caused a real, silent gap in the 2026-08 sync). Regenerate it explicitly after ANY Config
  struct change, scoped to the nr dirs:
  ```
  SG=go.opentelemetry.io/collector/cmd/schemagen@v0.22.1-0.20260615181954-d04d642d0a3e   # see Makefile.Common SCHEMAGEN_PKG
  for d in internal/nrsqlquery receiver/nr*receiver; do go run "$SG" "$PWD/$d" -o "$PWD/$d"; done
  git status --short -- '*config.schema.yaml'    # empty = your hand-edit matched the generator
  ```
  Do NOT just run the bare root `make generate-schemas`: it computes `SCHEMA_DIRS` across the whole
  repo and will regenerate every base component's schema too, pulling unrelated upstream drift into
  your diff. Whenever a Config struct field's embedding style changes (e.g. the
  upstream #49973-style "un-embed locally defined config structs" refactor: anonymous embed →
  named field), the corresponding `config.schema.yaml` must move in lockstep:
  - A field that's still anonymously embedded is referenced from the top-level `allOf:` list
    (`- $ref: top_query_collection`).
  - A field that's a named struct (`TopQueryCollection TopQueryCollection`) must instead appear as a
    `properties:` entry (`top_query_collection: { $ref: top_query_collection }`), and the corresponding
    `allOf:` line must be deleted — leaving both is wrong (mdatagen won't complain, but the schema no
    longer matches the actual Go struct shape).
  - Diff `config.schema.yaml` against base the same way you diff `metadata.yaml` — after ANY Config
    struct change (un-embed refactor, new field addition), run
    `diff receiver/<fork>/config.schema.yaml receiver/<base>/config.schema.yaml` and classify each
    block the same way as metadata (base-only → port, fork-only → leave, e.g. `db_auth`/`explain_mode`
    are legitimately fork- or base-only depending on direction).
  - This is easy to miss because `config.go`'s change compiles and passes tests fine either way — the
    schema is a separate, silent source of truth for documentation/validation tooling, not enforced by
    the Go build.
- **No changelog for the forks.** The base receivers require a `.chloggen/*.yaml` entry per change, but
  the `nr`-prefixed forks do NOT use `.chloggen` and have no `CHANGELOG.md` (prior ports like #49068 added
  none, and CI does not changelog-check the fork modules). Do not add a fork changelog entry; the base
  `.chloggen` entry that arrived with the merge already documents the upstream change.

## Phase 2 — README parity (do NOT skip — this has been missed before)

`README.md` is real user-facing documentation and drifts exactly like metadata/queries do, but nothing
above catches it: it's not metadata.yaml, not a query, not a golden. Diff it explicitly, every sync:

```
diff receiver/<fork>/README.md receiver/<base>/README.md
```

Classify each diff block the same way as Phase 2 metric classification:
- **Base-only content** (base documents a feature/config/prerequisite the fork's README doesn't
  mention) → port it. This is usually either (a) generic upstream prose that applies to the fork
  unchanged (copy verbatim, e.g. a new `application_name`/traceparent correlation note, a new opt-in
  metrics section), or (b) an autogenerated block (badges, code owners, status table) — for
  autogenerated sections, keep the fork's own values (module name, code owners, issue-label queries use
  `nr<base>` not `<base>`), don't copy base's literal badge URLs/owner list over the fork's.
- **Fork-only content** (SECURITY DEFINER function docs, cache-TTL explanations, PG-version-gate notes,
  anything explaining an nr-specific fix or design decision) → leave alone. Never let a sync silently
  drop these — they're the whole point of the fork's README diverging from base.
- If the base added a section for a feature the fork doesn't implement yet (rare — should already be
  caught by the metric/query parity check in the same sync), note it as a to-port item there instead of
  duplicating tracking here.

**Commit README changes in the same sync commit as the code they document.** A README-only diff with no
corresponding code change is a red flag — re-check whether Phase 2's metric/query porting was actually
complete, since base READMEs are usually updated alongside the feature, not independently.

**Uncommitted README edits are exactly as fragile as any other uncommitted change** — if a README
customization exists only in the working tree (not committed) when Phase 1's `git merge` or any
branch-switching happens, it can be silently lost with no conflict/warning (git has nothing to compare
against, since there's no commit recording the divergence). Commit fork-specific README additions
promptly, same as code, rather than letting them sit as long-lived uncommitted state.

## Phase 3 — Gates (all must pass, per fork module dir)

- `make -C receiver/<fork> generate` — no unexpected drift.
- `gofumpt -l` clean, `gci` diff empty (both run by `make generate`/`make fmt`).
- `make -C receiver/<fork> lint` — zero findings.
- `go build -C receiver/<fork> ./...` and `go test -C receiver/<fork> ./...` — green.
- **Reverse-diff guardrail**: confirm no fork-specific metric/attribute/query/event was removed
  (`git diff` should be purely additive except intended alignment).

## Phase 3 — Post-port parity verification (MANDATORY)

After porting, prove that EVERY metric and attribute present in the base receiver on `origin/main` now
exists in the fork. This is the final acceptance gate — run it for EVERY pair in the fork↔base table
above that exists in the repo today (`nroracledb`↔`oracledb`, `nrsqlserver`↔`sqlserver`,
`nrpostgresql`↔`postgresql`, `nrmysql`↔`mysql`), against the WORKING TREE (your uncommitted port),
not committed refs. Both commands below must print nothing, per pair.

### FIRST: the structural audit (name-only greps are NOT sufficient)

**The grep gates below compare KEY NAMES ONLY. They cannot see a changed description, unit, enum
value, metric type, or a whole missing section.** In the 2026-09 sync they reported "parity complete"
while 27 real differences existed, including a `postgresql.database.locks` description change, a
`relation` description that contradicted the ported SQL (code emitted names, docs still said "OID …
or null"), 4 `mysql.commands` enum values the fork never emitted (real data loss — the golden went
6→10 datapoints once fixed), and `service.name`/`service.namespace` missing from `nroracledb` alone.

Run this FIRST, per pair, and classify every row before trusting anything below:

```
python3 - <<'PY'
import yaml
PAIRS=[("nroracledbreceiver","oracledbreceiver"),("nrsqlserverreceiver","sqlserverreceiver"),
       ("nrpostgresqlreceiver","postgresqlreceiver"),("nrmysqlreceiver","mysqlreceiver")]
SEC=["attributes","metrics","events","resource_attributes"]   # resource_attributes is easy to forget
def load(p):
    with open(p) as f: return yaml.safe_load(f) or {}
def walk(fv,bv,path,out):
    if isinstance(fv,dict) and isinstance(bv,dict):
        for k in sorted(set(fv)|set(bv)):
            if k not in fv: out.append(("BASE-ONLY",f"{path}.{k}"))
            elif k not in bv: out.append(("fork-only",f"{path}.{k}"))
            elif fv[k]!=bv[k]: walk(fv[k],bv[k],f"{path}.{k}",out)
    elif isinstance(fv,list) and isinstance(bv,list):
        if [x for x in bv if x not in fv]: out.append(("BASE-ONLY-ITEMS",path))
        if [x for x in fv if x not in bv]: out.append(("fork-only-items",path))
    else: out.append(("VALUE-DIFF",path))
for fork,base in PAIRS:
    f=load(f"receiver/{fork}/metadata.yaml"); b=load(f"receiver/{base}/metadata.yaml")
    rows=[]
    for sec in SEC:
        fs,bs=f.get(sec) or {},b.get(sec) or {}
        if not isinstance(fs,dict) or not isinstance(bs,dict): continue
        for k in sorted(set(bs)-set(fs)): rows.append((sec,k,"MISSING FROM FORK"))
        for k in sorted(set(bs)&set(fs)):
            if bs[k]==fs[k]: continue
            out=[]; walk(fs[k],bs[k],"",out)
            bad=[f"{t}{p}" for t,p in out if not t.startswith("fork-only")]
            if bad: rows.append((sec,k,", ".join(bad)))
    print(f"{fork}: {len(rows)}")
    for sec,k,d in rows: print(f"    [{sec}] {k} -> {d}")
PY
```

Every row is either drift to align to base, or deliberate divergence to record — decide explicitly,
never leave one unclassified. Classification aid, since "fork wording is different" is NOT
automatically deliberate:

- `git log -S'<metric.name>' -- receiver/<fork>/metadata.yaml` and
  `git log -L '/^  <metric.name>:/,+10:receiver/<fork>/metadata.yaml'` find the commit that made the
  fork differ. A dedicated commit with a reason (e.g. `12a58e59b15` "fix pga memory bug (#225)",
  which changed `oracledb.pga_memory` from a monotonic sum to a gauge) is DELIBERATE — aligning to
  base would reintroduce the bug. A change swept in by a bulk porting commit with no stated rationale
  is probably incidental drift.
- Compare the value at fork-creation too: if base and fork agreed then and differ now, someone
  changed one of them on purpose — find out which.
- **A description that contradicts the fork's own code is always a bug, never divergence.**

### Structural checks the metadata audit does NOT cover

Run these too, per pair — each caught something the metadata audit could not:

```
# 1. Base .go files with no fork counterpart (base added a whole file, e.g. mysql's client_factory.go)
comm -23 <(ls receiver/<base>/*.go | xargs -n1 basename | sort) \
         <(ls receiver/<fork>/*.go | xargs -n1 basename | sort)

# 2. Base-only PRODUCTION functions (exclude _test.go — fork test suites legitimately diverge, and
#    including them buries the signal under dozens of irrelevant test-name differences)
comm -23 \
  <(ls receiver/<base>/*.go | grep -v _test.go | xargs grep -hoE '^func (\([^)]*\) )?[A-Za-z_][A-Za-z0-9_]*' | sed -E 's/^func (\([^)]*\) )?//' | sort -u) \
  <(ls receiver/<fork>/*.go | grep -v _test.go | xargs grep -hoE '^func (\([^)]*\) )?[A-Za-z_][A-Za-z0-9_]*' | sed -E 's/^func (\([^)]*\) )?//' | sort -u)
```

For (2), a base-only name can mean three different things — check which before acting: the fork
genuinely lacks the feature (port it); the fork has the same feature under a different name (leave,
but record it — e.g. base's `repairNormalizedQuery`/`protectedSpans` cluster vs the fork's
`rewriteIntervalParams`/`dollarQuoteTag`, two implementations of the same #50669 fix); or you
half-renamed something during this port (fix it — renaming `getSharedRelationLocks` →
`getServerScopedLocks` in `client.go` while leaving `collectSharedRelationLocks` in `scraper.go`
happened in the 2026-09 sync and only this check found it).

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
  declare done until both diffs are empty for every fork↔base pair.
- **README parity** (see Phase 2's README section above): re-run `diff receiver/<fork>/README.md
  receiver/<base>/README.md` and confirm every base-only block has been either ported or explicitly
  logged as a to-port item. This is part of the mandatory acceptance gate, not optional polish.
- **`config.schema.yaml` parity** (see Phase 2's note above — easy to miss since `make generate` doesn't
  catch it): re-run `diff receiver/<fork>/config.schema.yaml receiver/<base>/config.schema.yaml` per pair.
  Base-only `properties:`/`allOf:` entries mean the fork's schema hasn't caught up with a Config struct
  change (most commonly the embed→named-field un-embed refactor) — port them. Fork-only entries
  (`db_auth` absent on a fork that hasn't adopted it yet, `explain_mode`, etc.) are expected divergence.

## Output

Report: sync result (behind/ahead, conflict-free, dep-alignment), the parity delta per receiver pair
(to-port list + known-divergence list), files changed, gate results, and a per-phase commit message.
Cover every pair from the fork↔base table (skip any whose fork doesn't exist yet — check by listing
`receiver/nr*receiver` dirs, since new forks get added over time). Flag that published fork tags now
predate the port (a follow-up patch tag may be warranted) — do not auto-tag. Remind the user of the
mandatory PR step: open the PR against `pre-release` from the `sync-release/v<TARGET_VERSION>` branch
and post the link in `#data-integrations-team` before merging or tagging.

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
- **README parity was not checked in this sync** (the phase didn't exist yet) — a later pass found and
  ported real base-only content missed here: nrpostgresql's `application_name`/traceparent note + Vector
  Metrics section, nroracledb's stale `V$SQL_PLAN` reference in its Events collection grants (the query
  itself had already moved to `V$SQL_PLAN_STATISTICS_ALL` above, but the README didn't), and nrsqlserver's
  missing `CONNECT ANY DATABASE`/`VIEW ANY DEFINITION` permission note. This is the reason the Phase 2
  README parity step above exists — run it every sync from now on.
