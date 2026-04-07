# CLAUDE.md — SQL Server Receiver

> For implementation details, patterns, and extension guides, see [`docs/specs/sqlserver-spec.md`](../../docs/specs/sqlserver-spec.md)

## Current State

- **Stability:** Metrics: beta | Logs: development
- **Code owners:** @sincejune, @crobert-1 (seeking new)
- **Priority:** HIGH — customer-driven, first receiver to enhance
- **Size:** ~6,102 LOC across 27 Go source files

## File Map

| File | Purpose |
|------|---------|
| `factory.go` | Receiver factory, creates metrics + logs scrapers, wires LRU caches |
| `factory_windows.go` | Adds Windows Performance Counter scraper alongside DB scrapers |
| `factory_others.go` | Non-Windows: DB scrapers only |
| `scraper.go` | Core scraping logic — `sqlServerScraperHelper`, ScrapeMetrics/ScrapeLogs routing, record methods, cacheAndDiff |
| `scraper_windows.go` | Windows PC scraper using `winperfcounters.PerfCounterWatcher` |
| `recorders.go` | Maps Windows PC objects/counters → metric recorder functions |
| `config.go` | Config struct: datasource OR server/username/password/port, top query + query sample settings |
| `config_windows.go` / `config_others.go` | Platform-specific validation for instance_name/computer_name |
| `queries.go` | All SQL queries: Database IO, Perf Counters, Properties, Wait Stats. `go:embed` for templates |
| `templates/` | `dbQueryAndTextQuery.tmpl` (top queries), `sqlServerQuerySample.tmpl` (active sessions) |
| `obfuscate.go` | SQL string + XML query plan obfuscation via DataDog library |
| `service_instance_id.go` | Computes `service.instance.id` as `host:port` |
| `metadata.yaml` | 50 metrics, 2 log events — source of truth for metric definitions |
| `internal/metadata/` | Auto-generated from metadata.yaml — do NOT edit manually |

## Known Issues

| Issue | Notes |
|-------|-------|
| Query string matching in ScrapeMetrics is fragile | Any query text change breaks routing |
| `config_others.go` rejects instance_name/computer_name on non-Windows | By design — Windows PC concepts |

## Change Log

| Date | PR | Who | What Changed |
|------|-----|-----|-------------|
| 2026-04-06 | foundation | — | Initial CLAUDE.md |
