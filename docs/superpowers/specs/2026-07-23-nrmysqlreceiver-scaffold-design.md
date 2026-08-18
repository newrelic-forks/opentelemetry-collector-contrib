# Design: Set up `nrmysqlreceiver` base directory (fork of `mysqlreceiver`)

## Context

New Relic maintains fork receivers under `github.com/newrelic-forks/opentelemetry-collector-contrib`
that mirror upstream contrib receivers but re-home to the fork module path and depend only on the
fork's own internal modules (`internal/nrcommon`, `internal/nrsqlquery`). Three already exist:
`receiver/nroracledbreceiver`, `receiver/nrsqlserverreceiver`, and `receiver/nrpostgresqlreceiver`.

This work stands up a fourth, `receiver/nrmysqlreceiver`, as a faithful **scaffold** of the base
`receiver/mysqlreceiver` — same metrics, same scraper/queries/driver — re-homed to the fork and
wired into the build, exactly the way the oracle, sqlserver, and postgres forks were first created.
No new metrics or NR-specific features are added in this scaffold; those come later.

Scope decision: **scaffold only** (structural parity with base, 0 metric delta).

## Non-goals

- No new metrics, query-sample/top-query features, or obfuscation beyond what base mysql already has.
- No new internal module. In particular **`nrcoreinternal` is NOT created** (see Internal Dependencies).
- No driver change: the base `mysqlreceiver` already uses `github.com/go-sql-driver/mysql`; the fork keeps it.

## Architecture / approach

Copy `receiver/mysqlreceiver` verbatim, then apply the minimal mechanical "re-homing" changes that
turn it into an nr-fork module — the same shape as `nrpostgresqlreceiver`.

### Database translation (base already MySQL — recorded for completeness)
Because we fork the **MySQL** base receiver, the Postgres-specific choices in the reference spec map
to their MySQL equivalents automatically (they are already correct in the base and are **not** changed):

| Concern | PostgreSQL (`nrpostgresqlreceiver`) | MySQL (`nrmysqlreceiver`) |
|---|---|---|
| Default port | 5432 | **3306** (via `confignet.AddrConfig`) |
| Go driver | `github.com/lib/pq` (`pgx`/`libpq` family) | **`github.com/go-sql-driver/mysql`** |
| Connection string | libpq keyword DSN / URL | **go-sql-driver DSN** (`user:pass@tcp(host:port)/db?...`), assembled in `client.go`; `allow_native_passwords` + TLS knobs |
| Multi-DB config | `Databases []string` | single `Database string` (+ per-object `schema`/`table` attributes) |
| TLS field | embedded transport `Insecure` | named `TLS configtls.ClientConfig` (`cfg.TLS.Insecure`) |
| Replica/lag source | `pg_stat_replication` | `SHOW REPLICA/SLAVE STATUS` (version-gated) |

### Module identity
- `go.mod` module → `github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrmysqlreceiver`
- Go package → `nrmysqlreceiver`; `doc.go` import comment updated; `//go:generate make mdatagen` kept.
- `metadata.yaml` → `type: nrmysql`; codeowners include `@newrelic/dbi`.
- Regenerate `internal/metadata/**` so `metadata.Type == component.MustNewType("nrmysql")` and
  `ScopeName == ".../receiver/nrmysqlreceiver"`. Factory keeps `receiver.NewFactory(metadata.Type, …)`.
- **Metric names are unchanged** (`mysql.*`) — only the component *type* and module/package paths change.

### Internal dependencies (the key detail)
Base mysql depends on two `open-telemetry/…/internal/*` modules. The fork convention is **zero**
base-internal modules — every usage maps to an existing NR module or is rewritten:

| Base dependency | Where used | Fork resolution |
|---|---|---|
| `internal/common/priorityqueue` | `scraper.go` (production) | → `internal/nrcommon/priorityqueue` (exists) |
| `internal/coreinternal/scraperinttest` | `integration_test.go` | rewrite integration test testcontainers-style (mirror `nrpostgresqlreceiver`/`nrsqlserverreceiver`); no coreinternal dep |

Note vs. postgres: mysql does **not** use `internal/sqlquery`, so — unlike `nrpostgresqlreceiver` —
`nrmysqlreceiver/go.mod` requires only **`nrcommon`** (with `replace → ../../internal/nrcommon`) plus
the base collector deps at the fork pseudo-version. **No `nrsqlquery` and no `nrcoreinternal` needed.**

### External registration (wiring)
Mirror the entries the existing forks have (the fork receivers are currently wired via `versions.yaml`
+ `CODEOWNERS` only; they are not registered in `cmd/otelcontribcol` in this repo state):
- `versions.yaml` — add the module to the `newrelic-forks` module-set (right after `receiver/mysqlreceiver`).
- `.github/CODEOWNERS` — `receiver/nrmysqlreceiver/ … @newrelic/dbi`.
- (If/when a fork distro is built) `cmd/otelcontribcol/components.go` + `builder-config-*.yaml` — add
  `nrmysqlreceiver.NewFactory()` + `replace … => ../../receiver/nrmysqlreceiver`, mirroring the other forks.

## Files

**Create** (`receiver/nrmysqlreceiver/`): copied+re-homed hand-written Go (`config.go`, `factory.go`,
`scraper.go`, `client.go`, `config_*.go`, `doc.go`, `consts`/helpers, test files, rewritten
`integration_test.go`), `go.mod`/`go.sum`, `metadata.yaml`, `Makefile`, `README.md`, `documentation.md`,
regenerated `internal/metadata/**`, copied `templates/**` and `testdata/**`.

**Edit** (2 external files): `versions.yaml`, `.github/CODEOWNERS`.

## Verification

- `go mod tidy` clean (only `nrcommon` fork-internal dep; no `open-telemetry/…/internal/*`).
- `go build ./...` and `go test ./...` green in `receiver/nrmysqlreceiver`.
- `make generate` → no drift; `gci`, `gofumpt -l`, `make lint` clean.
- Metric-parity: fork metric set == base mysql metric set (0 delta) — verify `documentation.md` diff is
  empty except paths/type.
- Reverse-diff vs base: only re-homing changes (module path, `internal/common/priorityqueue`→`nrcommon`,
  `type`, rewritten integration test) differ — no logic changes.
- `-tags integration` build compiles the testcontainers integration test.

## Jira breakdown

Story under the MySQL OTel Support feature, broken into 4 sub-tasks (Problem/Solution/Changes/
Verification style, matching the postgres NR-589918 sub-tasks):
1. Scaffold module (copy + re-home identity + regenerate metadata).
2. Swap internal dep to `nrcommon` + rewrite integration test testcontainers-style + `go mod tidy`.
3. Register/wire (`versions.yaml`, `CODEOWNERS`; builder wiring when the fork distro needs it).
4. Verify (build/test/generate/lint + metric-parity/reverse-diff).

## Notes
- No auto-commit; user commits.
- `nrsqlquery`/`nrcoreinternal` explicitly out of scope / not required for MySQL.
- Follow-ups after scaffold lands (require tooling/network): `go mod tidy` to rebuild `go.sum`
  (base `go.sum` was copied and still references `internal/common`/`coreinternal`), and
  `make generate` (mdatagen) to confirm zero drift in `internal/metadata/**`.
