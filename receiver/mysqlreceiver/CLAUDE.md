# CLAUDE.md — MySQL Receiver

> For implementation details, patterns, and extension guides, see [`docs/specs/mysql-spec.md`](../../docs/specs/mysql-spec.md)

## Current State

- **Stability:** Metrics: beta | Logs: development
- **Code owners:** @antonblock, @ishleenk17
- **Priority:** MEDIUM — start after SQL Server/Oracle patterns are proven
- **Size:** ~3,343 LOC across 14 Go source files

## File Map

| File | Purpose |
|------|---------|
| `factory.go` | Receiver factory, creates metrics + logs receivers, wires LRU caches and TTL caches |
| `scraper.go` | Core scraping logic — `mySQLScraper`, `scrape()`, `scrapeTopQueryFunc()`, `scrapeQuerySampleFunc()`, `contextWithTraceparent()` |
| `client.go` | `client` interface and `mySQLClient` implementation, wraps `database/sql` with MySQL-specific queries using `text/template` |
| `config.go` | Config: endpoint, transport, username/password, TLS, statement events, top query + query sample settings |
| `obfuscate.go` | SQL + query plan obfuscation via DataDog library (mysql mode), EXPLAIN FORMAT=JSON v1 and v2 |
| `templates/` | `querySample.tmpl` (performance_schema joins), `topQuery.tmpl` (events_statements_summary_by_digest) |
| `metadata.yaml` | 48 metrics, 2 log events — source of truth for metric definitions |
| `internal/metadata/` | Auto-generated from metadata.yaml — do NOT edit manually |

## Known Issues

| Issue | Notes |
|-------|-------|
| (none documented yet) | |

## Change Log

| Date | PR | Who | What Changed |
|------|-----|-----|-------------|
| 2026-04-06 | foundation | — | Initial CLAUDE.md |
