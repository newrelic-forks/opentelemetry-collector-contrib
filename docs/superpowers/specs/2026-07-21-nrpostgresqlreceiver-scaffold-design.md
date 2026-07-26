# Design: Set up `nrpostgresqlreceiver` base directory (fork of `postgresqlreceiver`)

## Context

New Relic maintains fork receivers under `github.com/newrelic-forks/opentelemetry-collector-contrib`
that mirror upstream contrib receivers but re-home to the fork module path and depend only on the
fork's own internal modules (`internal/nrcommon`, `internal/nrsqlquery`). Two already exist:
`receiver/nroracledbreceiver` and `receiver/nrsqlserverreceiver`.

This work stands up a third, `receiver/nrpostgresqlreceiver`, as a faithful **scaffold** of the base
`receiver/postgresqlreceiver` — same metrics, same scraper/queries — re-homed to the fork and wired
into the build, exactly the way the oracle and sqlserver forks were first created. No new metrics or
NR-specific features are added in this scaffold; those come later.

Scope decision: **scaffold only** (structural parity with base, 0 metric delta).

## Non-goals

- No new metrics, query-sample/top-query features, or obfuscation beyond what base postgres already has.
- No new internal module. In particular **`nrcoreinternal` is NOT created** (see Internal Dependencies).

## Architecture / approach

Copy `receiver/postgresqlreceiver` verbatim, then apply the minimal mechanical "re-homing" changes that
turn it into an nr-fork module — the same shape as `nrsqlserverreceiver`.

### Module identity
- `go.mod` module → `github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrpostgresqlreceiver`
- Go package → `nrpostgresqlreceiver`; `doc.go` import comment updated; `//go:generate make mdatagen` kept.
- `metadata.yaml` → `type: nrpostgresql`; codeowners include `@newrelic/dbi`.
- Regenerate `internal/metadata/**` so `metadata.Type == component.MustNewType("nrpostgresql")` and all
  generated code carries the new type. Factory keeps `receiver.NewFactory(metadata.Type, …)`.

### Internal dependencies (the key detail)
Base postgres depends on three `open-telemetry/…/internal/*` modules. The fork convention is **zero**
base-internal modules — every usage maps to an existing NR module or is rewritten:

| Base dependency | Where used | Fork resolution |
|---|---|---|
| `internal/common/priorityqueue` | `scraper.go` (production) | → `internal/nrcommon/priorityqueue` (exists) |
| `internal/common/testutil` | `scraper_test.go` | → `internal/nrcommon/testutil` (exists) |
| `internal/sqlquery` | `client.go` (production) | → `internal/nrsqlquery` (exists; same symbols: `NewDbClient`, `DbWrapper`, `TelemetryConfig`, `ErrNullValueWarning`) |
| `internal/coreinternal/scraperinttest` | `integration_test.go` | rewrite integration test testcontainers-style (mirror `nrsqlserverreceiver/integration_test.go`); no coreinternal dep |

Result: `nrpostgresqlreceiver/go.mod` requires only `nrcommon` + `nrsqlquery` (with `replace →
../../internal/…`) plus the base collector deps at the fork pseudo-version — matching `nrsqlserverreceiver`.
**No `nrcoreinternal` module is needed.**

### External registration (wiring)
Mirror the entries the existing forks have:
- `cmd/otelcontribcol/components.go` — import + `nrpostgresqlreceiver.NewFactory()` + version-map entry.
- `cmd/otelcontribcol/builder-config-*.yaml` — `replace … => ../../receiver/nrpostgresqlreceiver` (and
  receivers list where the config enables it).
- `versions.yaml` — add the module to the `newrelic-forks` module-set.
- `.github/CODEOWNERS` — `receiver/nrpostgresqlreceiver/ … @newrelic/dbi`.

## Files

**Create** (`receiver/nrpostgresqlreceiver/`): copied+re-homed hand-written Go (`config.go`, `factory.go`,
`scraper.go`, `client.go`, `obfuscate.go`, `config_*.go`, `doc.go`, test files, rewritten
`integration_test.go`), `go.mod`/`go.sum`, `metadata.yaml`, `Makefile`, `README.md`, `documentation.md`,
`config.schema.yaml`, regenerated `internal/metadata/**`, copied `testdata/**`.

**Edit** (4 external files): `cmd/otelcontribcol/components.go`, `cmd/otelcontribcol/builder-config-*.yaml`,
`versions.yaml`, `.github/CODEOWNERS`.

## Verification

- `go mod tidy` clean (only `nrcommon`+`nrsqlquery` fork-internal deps; no `open-telemetry/…/internal/*`).
- `go build ./...` and `go test ./...` green in `receiver/nrpostgresqlreceiver`.
- `make generate` → no drift; `gci`, `gofumpt -l`, `make lint` clean.
- `otelcontribcol components` lists `nrpostgresql`; factory type resolves.
- Metric-parity: fork metric set == base postgres metric set (0 delta).
- Reverse-diff vs base: only re-homing changes (module path, import swaps, `type`) differ — no logic changes.

## Jira breakdown

Story under Feature **NR-589918** ("Postgres Otel Support"), broken into 4 sub-tasks (Problem/Solution/
Changes/Verification style, matching NR-589919's sub-tasks):
1. Scaffold module (copy + re-home identity + regenerate metadata).
2. Swap internal deps to nr modules + rewrite integration test testcontainers-style + `go mod tidy`.
3. Register/wire (components.go, builder-config, versions.yaml, CODEOWNERS).
4. Verify (build/test/generate/lint + metric-parity/reverse-diff).

## Notes
- No auto-commit; user commits.
- `nrcoreinternal` explicitly out of scope / not required.
