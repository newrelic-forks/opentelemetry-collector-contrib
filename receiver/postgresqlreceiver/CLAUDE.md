# CLAUDE.md — PostgreSQL Receiver

> For implementation details, patterns, and extension guides, see [`docs/specs/postgresql-spec.md`](../../docs/specs/postgresql-spec.md)

## Current State

- **Stability:** Metrics: beta | Logs: development
- **Code owners:** @djaglowski, @StefanKurek
- **Priority:** MEDIUM — after SQL Server and Oracle
- **Size:** ~4,482 LOC across 15 Go source files

## File Map

| File | Purpose |
|------|---------|
| `factory.go` | Receiver factory, creates metrics + logs scrapers, LRU cache, TTL-based plan cache, connection pool via feature gate |
| `scraper.go` | Core scraping — `postgreSQLScraper`, multi-database iteration, concurrent per-DB metric collection |
| `client.go` | `client` interface (17+ methods), all SQL queries inline, wraps `lib/pq` driver |
| `client_factory.go` | `defaultClientFactory` (fresh connection per scrape) and `poolClientFactory` (persistent pool, feature-gated) |
| `config.go` | Config: endpoint, transport (TCP/Unix), databases/exclude_databases, connection_pool, top query + query sample settings |
| `consts.go` | SQL query templates as string constants |
| `obfuscate.go` | SQL obfuscation via DataDog library (postgresql DBMS mode) |
| `metadata.yaml` | ~35 metrics, 2 log events — source of truth for metric definitions |
| `internal/metadata/` | Auto-generated from metadata.yaml — do NOT edit manually |

## Known Issues

| Issue | Notes |
|-------|-------|
| `pg_stat_statements` must be installed for top queries | Document as prerequisite |
| Connection pool feature gate not yet stable | `receiver.postgresql.connectionPool` — off by default |
| Separate schema attribute feature gate | `receiver.postgresql.separateSchemaAttr` — warn logged if not enabled |

## Change Log

| Date | PR | Who | What Changed |
|------|-----|-----|-------------|
| 2026-04-06 | foundation | — | Initial CLAUDE.md |
