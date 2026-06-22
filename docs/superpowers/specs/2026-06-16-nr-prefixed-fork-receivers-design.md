# Design: NR-prefixed Oracle/SQL Server fork receivers in nrdot-collector

**Date:** 2026-06-16
**Status:** Implemented (pending push + tag)
**Author:** spathlavath (assisted by Claude)

## Goal

Ship both upstream contrib `oracledbreceiver` / `sqlserverreceiver` AND the New Relic fork variants in the same `nrdot-collector` binary, so users can opt into either one in their collector config.

## Background

The `pre-release` branch of `newrelic-forks/opentelemetry-collector-contrib` carries modified versions of the upstream Oracle and SQL Server receivers (extra metrics, query.comments handling, top-query updates, etc.). Before this change, those modified receivers:

- Lived at the **same Go module path** as upstream (`github.com/open-telemetry/opentelemetry-collector-contrib/receiver/oracledbreceiver`, `.../sqlserverreceiver`)
- Registered the **same OpenTelemetry component type** (`oracledb`, `sqlserver`)

The previous nrdot-collector build relied on Go `replace` directives to redirect those upstream module paths to the fork. As a result, only the fork shipped in the binary even though the manifest referenced upstream paths. Two receivers cannot coexist while they share the same module path (Go module identity) or the same component type (otelcol factory registration).

## Approach (final, as shipped)

Three coordinated decisions:

1. **Add nr-prefixed sibling receivers**, do NOT rename upstream-mirroring directories. Keep `receiver/oracledbreceiver/` and `receiver/sqlserverreceiver/` untouched on this branch — byte-identical to `pre-release` HEAD — so future upstream contrib syncs land here without merge conflicts. Add `receiver/nroracledbreceiver/` and `receiver/nrsqlserverreceiver/` as new directories carrying the NR-modified code at distinct Go module paths and component types.

2. **Vendor required `internal/` packages under the newrelic-forks module prefix.** Go's `internal/` rule rejects imports of `github.com/open-telemetry/.../internal/...` from packages under `github.com/newrelic-forks/...`. Plain Go `replace` directives don't bypass the rule (it's enforced on the import-path string, not the fetch source). The fork-side receivers therefore consume vendored copies at `github.com/newrelic-forks/.../internal/nrcommon/{sqlcomments,sqlnormalizer,priorityqueue,testutil}` and `.../internal/nrsqlquery`. The upstream `internal/common/` and `internal/sqlquery/` modules are unchanged and continue to serve the rest of the contrib-fork repo (147+ consumers).

3. **List both flavors in `nrdot-collector` `manifest.yaml`.** No `replace` directives needed — each module path is unambiguous on its own.

| Aspect | Upstream (kept) | NR fork (added) |
| --- | --- | --- |
| Directory | `receiver/oracledbreceiver` | `receiver/nroracledbreceiver` |
| Go module path | `github.com/open-telemetry/opentelemetry-collector-contrib/receiver/oracledbreceiver` | `github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nroracledbreceiver` |
| Component type | `oracledb` | `nroracledb` |
| Directory | `receiver/sqlserverreceiver` | `receiver/nrsqlserverreceiver` |
| Go module path | `github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver` | `github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrsqlserverreceiver` |
| Component type | `sqlserver` | `nrsqlserver` |

After this change, a user's collector config can reference `oracledb` (upstream) or `nroracledb` (NR fork) as distinct receivers; same for sqlserver / nrsqlserver.

## Changes

### 1. `newrelic-forks/opentelemetry-collector-contrib` (this repo, branch `nr-prefixed-receivers`)

#### 1.1 Vendored internal modules (new)

Two new top-level Go modules added:

- `internal/nrcommon/` — module `github.com/newrelic-forks/opentelemetry-collector-contrib/internal/nrcommon`
  Subpackages copied from `internal/common/`: `sqlcomments`, `sqlnormalizer`, `priorityqueue`, `testutil`. Other `internal/common` subpackages (docker, maps, sanitize, ttlmap) are not vendored — none of the renamed receivers need them.
- `internal/nrsqlquery/` — module `github.com/newrelic-forks/opentelemetry-collector-contrib/internal/nrsqlquery`
  Source-of-truth copy from `internal/sqlquery`.

Each new module has its own `go.mod` and `go.sum`, declares the new module path on line 1, and includes a require/replace block trimmed to actually-used dependencies (`go mod tidy` clean).

The package import comments (`package foo // import "..."`) and import statements within these vendored sources have been rewritten to point at the new newrelic-forks paths.

#### 1.2 NR-prefixed receivers (new)

- `receiver/nroracledbreceiver/` — copy of the pre-release branch's modified `oracledbreceiver`, with:
  - `go.mod` line 1: `module github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nroracledbreceiver`.
  - `go.mod` require/replace blocks updated to consume `github.com/newrelic-forks/.../internal/nrcommon` via local path `../../internal/nrcommon`. Other dependencies (`pkg/golden`, `pkg/pdatatest`, `pkg/pdatautil`) keep pointing at upstream contrib paths because those packages are NOT under an `internal/` segment, so the rule does not apply.
  - `metadata.yaml` `type:` field set to `nroracledb`.
  - All `*.go` files: package declarations changed to `package nroracledbreceiver`; import-comment URLs and `internal/metadata` import statements rewritten to the new module path; imports of `internal/common/{sqlcomments,sqlnormalizer}` rewritten to `internal/nrcommon/{sqlcomments,sqlnormalizer}`.
  - `internal/metadata/` regenerated via `make mdatagen` so `Type = component.MustNewType("nroracledb")` and `ScopeName = "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nroracledbreceiver"`.
  - testdata YAML scope-name strings rewritten to the new module path.

- `receiver/nrsqlserverreceiver/` — same treatment, mirroring sqlserver:
  - Module path `github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrsqlserverreceiver`.
  - Component type `nrsqlserver`.
  - Consumes both `internal/nrcommon` (via `../../internal/nrcommon`) and `internal/nrsqlquery` (via `../../internal/nrsqlquery`).
  - All package declarations changed to `package nrsqlserverreceiver`.
  - `internal/metadata` regenerated; testdata updated.

#### 1.3 Upstream-mirror directories (untouched)

`receiver/oracledbreceiver/` and `receiver/sqlserverreceiver/` are byte-identical to `pre-release` HEAD on this branch. Verified via `git diff pre-release -- receiver/oracledbreceiver receiver/sqlserverreceiver` returning empty. Future contrib syncs (merging upstream into `pre-release`, then merging `pre-release` into this branch) land cleanly in these directories without rename/delete conflicts. Engineering can use `diff -ruN receiver/oracledbreceiver receiver/nroracledbreceiver` (after stripping module-path noise) to see the NR-specific delta and decide what to port forward when upstream changes.

#### 1.4 Repo-level registry

- `versions.yaml`: adds entries for the two new vendored internal modules and the two new nr-prefixed receivers, alongside (not replacing) the existing upstream-path entries.
- `.github/CODEOWNERS`: adds two new entries for `receiver/nroracledbreceiver/` and `receiver/nrsqlserverreceiver/` mirroring the upstream owners and adding `@newrelic/dbi`. The existing upstream-receiver CODEOWNERS lines are preserved unchanged.

### 2. `nrdot-collector-releases/distributions/nrdot-collector/manifest.yaml`

Adds two new gomod entries alongside the existing upstream ones:

```yaml
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/oracledbreceiver v0.154.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver v0.154.0
  - gomod: github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nroracledbreceiver v0.154.0
  - gomod: github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrsqlserverreceiver v0.154.0
```

The existing `replaces:` block (only the prometheus CVE replace) is unchanged. No `replace` directive is required for the newrelic-forks paths because each module path is unambiguous; resolution is by upstream Go-proxy semantics once the four monorepo tags exist.

### 3. Versioning

After this change merges, four monorepo tags need to exist on `newrelic-forks/opentelemetry-collector-contrib` so `ocb` can resolve the new gomod entries:

- `receiver/nroracledbreceiver/v0.154.0`
- `receiver/nrsqlserverreceiver/v0.154.0`
- `internal/nrcommon/v0.154.0`
- `internal/nrsqlquery/v0.154.0`

`v0.154.0` matches the existing upstream entries in the manifest, keeping all four receivers at parallel versions.

## Verification

Confirmed locally on the implementation branch (`nr-prefixed-receivers`):

1. **Module sanity** — from each of the four module directories: `go build ./...` and `go test ./... -count=1 -short` exit 0.
2. **All four receivers coexist on disk** — both upstream-path and newrelic-forks-path receivers build successfully in the same checkout.
3. **Type identifiers distinct** — `grep MustNewType internal/metadata/generated_status.go` yields `oracledb`, `nroracledb`, `sqlserver`, `nrsqlserver`.
4. **Upstream untouched** — `git diff --staged -- internal/common/ internal/sqlquery/ receiver/oracledbreceiver/ receiver/sqlserverreceiver/` returns empty.
5. **Pure-additive change** — staged diff: 188 files, ~72,617 insertions, 0 deletions.

End-to-end binary verification (via `make generate-sources` + `make build` in `nrdot-collector-releases`) is deferred until the four monorepo tags are pushed.

## Out of scope

- Changes to the `nrdot-collector-experimental` distribution (does not currently reference oracle/sqlserver).
- Functional changes to either receiver — this is rename-and-vendor only.
- Documentation rewrites of receiver READMEs — the regenerated metadata picks up the new type name; further authoring is deferred.
- Automation to keep the renamed modules in sync with upstream contrib changes. With both upstream-mirror and nr-prefixed directories present, the workflow is: (a) merge upstream contrib into `pre-release` (changes land in `receiver/oracledbreceiver/`); (b) compare `oracledbreceiver` vs `nroracledbreceiver` to find new upstream behavior worth porting; (c) hand-apply ports. Automation is a future enhancement.

## Notes on alternatives considered

- **Rename in place via `git mv`, no vendoring.** Initial direction. Failed because Go's `internal/` rule blocks the renamed receiver from importing upstream's `internal/sqlquery` and `internal/common/*`. Vendoring under the newrelic-forks prefix solves this without affecting any of the 147+ other consumers of the upstream internal modules.
- **Replace upstream contrib with the fork via `replace` directive.** Simpler but only ships one variant per receiver type — does not satisfy the goal of side-by-side coexistence.
- **Vendor inside each receiver (`receiver/<name>/internal/...`).** Self-contained but duplicates `testutil` between the two receivers. Shared at repo level (under `internal/nrcommon`, `internal/nrsqlquery`) avoids that duplication and was chosen.
