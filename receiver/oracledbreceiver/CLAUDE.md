# CLAUDE.md — Oracle DB Receiver

> For implementation details, patterns, and extension guides, see [`docs/specs/oracledb-spec.md`](../../docs/specs/oracledb-spec.md)

## Current State

- **Stability:** Metrics: alpha | Logs: development
- **Code owners:** @crobert-1, @atoulme
- **Priority:** HIGH — customer-driven, second receiver to enhance
- **Size:** ~2,565 LOC across 13 Go source files

## File Map

| File | Purpose |
|------|---------|
| `factory.go` | Receiver factory, creates metrics + logs receivers, builds oracle:// DSN, creates LRU cache |
| `scraper.go` | Core scraping logic — `oracleScraper` struct, all SQL query constants inline, metrics + logs collection |
| `db_client.go` | `dbClient` interface with `metricRows()`, wraps `database/sql`, dynamic column discovery via `ColumnTypes()` |
| `fake_db_client.go` | Test fake implementing `dbClient` — returns canned metric rows |
| `config.go` | Config: datasource (full DSN) OR endpoint/username/password/service, top query + query sample settings |
| `obfuscate.go` | SQL obfuscation via DataDog library (oracle DBMS mode) |
| `templates/` | `oracleQueryMetricsAndTextSql.tmpl`, `oracleQueryPlanSql.tmpl`, `oracleQuerySampleSql.tmpl` |
| `metadata.yaml` | 42 metrics, 2 log events — source of truth for metric definitions |
| `internal/metadata/` | Auto-generated from metadata.yaml — do NOT edit manually |

## Known Issues

| Issue | Notes |
|-------|-------|
| No integration tests | No free Oracle Docker image for testcontainers |
| V$SYSSTAT query fetches all rows even if few metrics enabled | Acceptable — single query, small result set |
| CPU time from V$SYSSTAT is in 10ms units | Divided by 100 in scraper |

## Change Log

| Date | PR | Who | What Changed |
|------|-----|-----|-------------|
| 2026-04-06 | foundation | — | Initial CLAUDE.md |
