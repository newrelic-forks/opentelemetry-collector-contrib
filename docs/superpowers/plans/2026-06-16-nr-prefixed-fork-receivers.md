# NR-prefixed Oracle/SQL Server fork receivers — Implementation Record

> **Status:** Implemented (changes staged, not committed). This document records the steps that were actually executed end-to-end. The original plan was revised mid-execution after Go's `internal/` rule was discovered to block the simpler approach. See spec: `docs/superpowers/specs/2026-06-16-nr-prefixed-fork-receivers-design.md`.

**Goal achieved:** Both upstream contrib `oracledbreceiver` / `sqlserverreceiver` AND New Relic fork variants `nroracledbreceiver` / `nrsqlserverreceiver` build and ship side-by-side in `nrdot-collector`. Users can configure either flavor under distinct OpenTelemetry component types in a single collector config.

**Tech Stack:** Go 1.25, OpenTelemetry Collector Builder (`ocb`), `mdatagen` codegen tool.

**Repos:**
- `CONTRIB_DIR=/Users/spathlavath/otel/logs/opentelemetry-collector-contrib` (branch `nr-prefixed-receivers` off `pre-release`)
- `NRDOT_DIR=/Users/spathlavath/otel/logs/nrdot-collector-releases` (branch `nr-prefixed-receivers` off `main`)

**Hard constraint observed throughout:** no `git commit`, no `git push`. Everything is staged for the user to inspect and commit.

---

## Phase 0 — Branching

Created `nr-prefixed-receivers` in both repos. NRDOT_DIR's pre-existing uncommitted changes to `manifest.yaml` (the two upstream contrib oracle/sqlserver gomod lines) were carried onto the new branch via `git checkout -b` (default behavior — uncommitted edits follow into the new branch).

---

## Phase 1 — First attempt: rename in place

Initial direction (later abandoned):

1. `git mv receiver/oracledbreceiver receiver/nroracledbreceiver` — directory rename.
2. Edit `receiver/nroracledbreceiver/go.mod` line 1 to module `github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nroracledbreceiver`.
3. Edit `receiver/nroracledbreceiver/metadata.yaml` `type:` to `nroracledb`.
4. `sed -i ''` over all `.go` files to rewrite the receiver's self-import path from upstream to newrelic-forks.

This produced a buildable rename for the receiver in isolation, BUT:

```
scraper.go:34:2: use of internal package github.com/open-telemetry/opentelemetry-collector-contrib/internal/common/sqlcomments not allowed
```

Go's `internal/` rule rejects imports of `X/internal/Y` from packages whose module path does not begin with `X/`. With the receiver moved to `github.com/newrelic-forks/...`, it cannot reach `github.com/open-telemetry/.../internal/common/sqlcomments` even via a `replace` directive (the rule is enforced on the import-path string, not the fetch source).

Verified that `internal/common` and `internal/sqlquery` have 147 other consumers across the contrib-fork repo, so renaming those modules in place was not a viable shortcut.

---

## Phase 2 — Vendor internal packages under newrelic-forks prefix

### Task A — Create `internal/nrcommon` and `internal/nrsqlquery`

Created two new top-level Go modules:

- `internal/nrcommon/` with `go.mod` declaring `module github.com/newrelic-forks/opentelemetry-collector-contrib/internal/nrcommon` and subpackages copied from `internal/common/`: `sqlcomments`, `sqlnormalizer`, `priorityqueue`, `testutil`. Other `internal/common` subpackages (docker, maps, sanitize, ttlmap) deliberately not vendored — none of the renamed receivers need them.
- `internal/nrsqlquery/` with `go.mod` declaring `module github.com/newrelic-forks/opentelemetry-collector-contrib/internal/nrsqlquery`, copied from `internal/sqlquery/`.

Steps for each:

1. `cp -R` source-of-truth subpackages into the new directory.
2. `find ... -type f -name '*.go' -exec sed -i ''` to rewrite package import comments and any internal cross-imports from `github.com/open-telemetry/.../internal/<sub>` to `github.com/newrelic-forks/.../internal/nr<name>/<sub>`.
3. Authored `go.mod` for each new module by template from the upstream sibling, removing `require` entries that pointed at unused contrib internals. Copied `go.sum` and ran `go mod tidy` to clean.
4. `go build ./...` and `go test ./... -count=1 -short` from each new module — both pass.

### Task B — Rewire `nroracledbreceiver` to consume vendored modules

In `receiver/nroracledbreceiver/`:

1. `sed` over `.go` files: rewrote upstream `internal/common/{sqlcomments,sqlnormalizer,priorityqueue,testutil}` import paths to `internal/nrcommon/<sub>`.
2. `go.mod` edits:
   - Replaced require `github.com/open-telemetry/.../internal/common v0.154.0` with `github.com/newrelic-forks/.../internal/nrcommon v0.0.0-00010101000000-000000000000`.
   - Replaced replace `github.com/open-telemetry/.../internal/common => ../../internal/common` with `github.com/newrelic-forks/.../internal/nrcommon => ../../internal/nrcommon`.
3. `go mod tidy` — clean.
4. `go build ./...` — pass. `go test ./...` — pass.

### Task C — Regenerate `nroracledbreceiver/internal/metadata`

`metadata.yaml` was already edited in Phase 1 to set `type: nroracledb` but `internal/metadata/generated_status.go` still showed `Type = component.MustNewType("oracledb")`. Ran `make mdatagen` from inside the receiver directory. Generator updated the generated files.

The implementer also discovered all `*.go` files still declared `package oracledbreceiver` (the rename only changed the directory and module path, not the Go package name). Rewrote every `package oracledbreceiver` to `package nrsqlserverreceiver`/`nroracledbreceiver` so the source matches the directory + module + import comments.

A stray malformed import comment in `config_test.go` (`github.com/open-telemetry/open-telemetry-collector-contrib/...` — extra `open-`) caused by an earlier sed glitch was fixed by hand.

Final state for oracle:
- `Type = component.MustNewType("nroracledb")`
- `ScopeName = "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nroracledbreceiver"`
- `go build ./...` and `go test ./...` pass.

### Task D — Same treatment for sqlserver

Tasks A's outputs were reused (sqlserver consumes both `internal/nrcommon` and `internal/nrsqlquery`). For `receiver/nrsqlserverreceiver/`:

1. Created the directory by `git mv receiver/sqlserverreceiver receiver/nrsqlserverreceiver` (Phase 1 carryover).
2. Edited `go.mod` line 1 → newrelic-forks module path.
3. Edited `metadata.yaml` → `type: nrsqlserver`.
4. `sed` over `.go` files: rewrote receiver self-import; rewrote `internal/common/*` → `internal/nrcommon/*`; rewrote `internal/sqlquery` → `internal/nrsqlquery`.
5. `go.mod` edits: replaced require + replace blocks for both `internal/common` (→ `internal/nrcommon`) and `internal/sqlquery` (→ `internal/nrsqlquery`), pointing at the local `../../internal/...` paths.
6. Rewrote all `package sqlserverreceiver` → `package nrsqlserverreceiver`.
7. `go mod tidy` — clean.
8. `make mdatagen` — regenerated metadata.
9. `go build ./...` and `go test ./...` — pass. `Type = nrsqlserver`, `ScopeName` correct.

---

## Phase 3 — Strategic correction: keep upstream-mirror directories

User pointed out a concern with the rename-via-`git mv` approach: future merges from upstream contrib (which still has `receiver/oracledbreceiver/` and `receiver/sqlserverreceiver/`) would produce modify/delete conflicts on every file upstream changes, because those directories no longer exist on this branch.

**Correction applied:** restore the upstream-mirror directories on this branch.

```bash
git checkout pre-release -- receiver/oracledbreceiver receiver/sqlserverreceiver
```

This recreates both directories on disk and in the index, byte-identical to `pre-release` HEAD. Verified via `git diff pre-release -- receiver/oracledbreceiver receiver/sqlserverreceiver` returning empty.

Side effect: git's rename-detection no longer sees the move as a rename (because the original dirs exist again). The staged diff for `nroracledbreceiver/` and `nrsqlserverreceiver/` now shows pure-add (`A`) entries instead of `R` (rename). This is the intended state — the change becomes purely additive (188 files added, 0 deletions), and future upstream syncs land cleanly in the upstream-mirror directories.

All four receivers verified to build alongside each other in the same checkout:
- `receiver/oracledbreceiver/` — `go build ./...` ✅ (Type `oracledb`)
- `receiver/nroracledbreceiver/` — `go build ./...` ✅ (Type `nroracledb`)
- `receiver/sqlserverreceiver/` — `go build ./...` ✅ (Type `sqlserver`)
- `receiver/nrsqlserverreceiver/` — `go build ./...` ✅ (Type `nrsqlserver`)

---

## Phase 4 — Registry files

### `versions.yaml`

Added four entries (kept the original upstream-path entries for `oracledbreceiver` and `sqlserverreceiver`):

```yaml
      - github.com/newrelic-forks/opentelemetry-collector-contrib/internal/nrcommon
      - github.com/newrelic-forks/opentelemetry-collector-contrib/internal/nrsqlquery
      - github.com/open-telemetry/opentelemetry-collector-contrib/receiver/oracledbreceiver
      - github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nroracledbreceiver
      - github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver
      - github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrsqlserverreceiver
```

### `.github/CODEOWNERS`

Added two new entries directly below the upstream entries (kept upstream entries intact):

```
receiver/oracledbreceiver/                                       @open-telemetry/collector-contrib-approvers @dmitryax @crobert-1 @atoulme
receiver/nroracledbreceiver/                                     @open-telemetry/collector-contrib-approvers @dmitryax @crobert-1 @atoulme @newrelic/dbi
...
receiver/sqlserverreceiver/                                      @open-telemetry/collector-contrib-approvers @sincejune @crobert-1
receiver/nrsqlserverreceiver/                                    @open-telemetry/collector-contrib-approvers @sincejune @crobert-1 @newrelic/dbi
```

CODEOWNERS entries for `internal/nrcommon/` and `internal/nrsqlquery/` deferred — can be added in a follow-up if needed.

---

## Phase 5 — `nrdot-collector-releases` manifest

In `distributions/nrdot-collector/manifest.yaml`, added two new gomod entries alongside the existing upstream entries:

```yaml
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/oracledbreceiver v0.154.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver v0.154.0
  - gomod: github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nroracledbreceiver v0.154.0
  - gomod: github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrsqlserverreceiver v0.154.0
```

The existing `replaces:` block (only the prometheus CVE replace) was left unchanged. No new replace directives are needed because the four module paths are unambiguous; ocb resolves each via Go-proxy semantics once the four monorepo tags exist.

---

## Final verification

```text
=== all 4 receivers build ===
oracledbreceiver OK
nroracledbreceiver OK
sqlserverreceiver OK
nrsqlserverreceiver OK

=== type identifiers distinct ===
Type      = component.MustNewType("oracledb")
Type      = component.MustNewType("nroracledb")
Type      = component.MustNewType("sqlserver")
Type      = component.MustNewType("nrsqlserver")

=== upstream untouched ===
git diff --staged -- internal/common internal/sqlquery   →  (empty)
git diff pre-release -- receiver/oracledbreceiver receiver/sqlserverreceiver  →  (empty)

=== final staged stat ===
CONTRIB_DIR: 188 files changed, 72,617 insertions(+), 0 deletions(-)
NRDOT_DIR:     1 file changed,         4 insertions(+), 0 deletions(-)
```

End-to-end binary verification (`make generate-sources` + `make build` in NRDOT_DIR) is deferred until the four monorepo tags exist on `newrelic-forks/opentelemetry-collector-contrib`.

---

## Required follow-up after this change merges

After commits land on this branch and ship:

1. Push the contrib branch and tag four monorepo tags:
   ```
   receiver/nroracledbreceiver/v0.154.0
   receiver/nrsqlserverreceiver/v0.154.0
   internal/nrcommon/v0.154.0
   internal/nrsqlquery/v0.154.0
   ```
2. From `nrdot-collector-releases`, run `make generate-sources` followed by `make build`. Confirm `_build/components.go` registers all four receiver factories.
3. Smoke-test a collector config that uses `oracledb:`, `nroracledb:`, `sqlserver:`, and `nrsqlserver:` simultaneously (config validation only — actual DB connections not required).

---

## Lessons / patterns worth remembering

- **Don't rely on `replace` to bypass Go's `internal/` rule.** The rule operates on the import-path string; replace only affects fetch location.
- **`git mv` away from upstream paths invites merge-conflict pain.** When the goal is to coexist with future upstream changes, prefer pure-additive changes over directory renames so upstream-mirror paths stay clean.
- **Vendored modules can satisfy the internal/ rule** by living under a module-path prefix that matches the consumer's prefix.
- **Package import comments and package declarations are independent from module path.** Both must be updated together when renaming a Go package across module boundaries.
- **`mdatagen` reads `metadata.yaml` and rewrites generated files.** Always edit `metadata.yaml` first; never hand-edit `generated_*.go`.
