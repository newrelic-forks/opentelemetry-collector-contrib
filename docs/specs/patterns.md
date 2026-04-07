# Shared Patterns Across Database Receivers

These patterns are common to all 4 database receivers. Follow them consistently.
When proposing a new cross-cutting pattern, write an ADR in `docs/specs/decisions/`.

---

## Query Obfuscation

**Package:** `github.com/DataDog/datadog-agent/pkg/obfuscate`
**Used by:** All 4 receivers
**Purpose:** Strip sensitive data (parameter values, literals) from SQL queries before emitting as logs/events.
**Pattern:** Each receiver has an `obfuscate.go` file wrapping the DataDog obfuscator.

## LRU Caching

**Package:** `github.com/hashicorp/golang-lru/v2`
**Used by:** All 4 receivers
**Purpose:** Cache query plans, query hashes, and other computed values to avoid redundant work across collection intervals.
**Note:** PostgreSQL uses an expirable LRU variant with TTL. Other receivers use standard LRU.

## Metric Definitions via metadata.yaml

**Tool:** mdatagen (OpenTelemetry metadata generator)
**Used by:** All 4 receivers
**Purpose:** Metrics are defined in `metadata.yaml`, and `make generate` produces Go code in `internal/metadata/`.
**Rule:** NEVER edit files in `internal/metadata/` manually. Edit `metadata.yaml` and regenerate.

## Error Handling

**Convention:** Wrap errors with context, never swallow them.
- Use `fmt.Errorf("context: %w", err)` to wrap
- Log at appropriate level: ERROR for unrecoverable, WARN for recoverable/skippable
- Never `_ = someFunction()` on errors that indicate real failures
- On partial collection failure, log the error and continue collecting remaining metrics

## Logging

**Package:** `go.uber.org/zap`
**Source:** `zap.Logger` from receiver settings (`settings.Logger`)
**Convention:**
- Use structured fields: `logger.Warn("message", zap.Error(err), zap.String("key", value))`
- Don't log every collection interval for known issues — log once, then suppress

## Testing

**Framework:** `github.com/stretchr/testify`
**Patterns:**
- Table-driven tests for config validation and metric scenarios
- `testcontainers-go` for integration tests (SQL Server, PostgreSQL, MySQL — NOT Oracle)
- `go-sqlmock` for database query mocking (PostgreSQL)
- Fake client pattern for simpler mocking (Oracle)
- Golden files in `testdata/` for expected metric output

---

## Change Log

| Date | PR | What Changed |
|------|-----|-------------|
| 2026-04-06 | foundation | Initial patterns documented from codebase analysis |
