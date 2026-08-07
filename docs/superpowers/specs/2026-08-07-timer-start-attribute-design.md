# Design: nrmysqlreceiver — add `TIMER_START` to `db.server.query_sample`

**Date:** 2026-08-07
**Target:** `receiver/nrmysqlreceiver/templates/querySample.tmpl`, `client.go`, `scraper.go`, `metadata.yaml`.
**Goal:** give `db.server.query_sample` a stable per-execution marker for the currently-running
statement, closing a MySQL/MSSQL dashboard parity gap: MSSQL's `query_start` lets the "Wait time
by type" chart and similar widgets dedup on `(wait_type, query_start, session_id)`; MySQL had no
equivalent, so the same widget dedups on `(wait_type, thread_id, event_id)` instead — a weaker key
that doesn't change when a new statement begins on an otherwise idle-looking thread between scrapes.

## Problem recap

Earlier this session, auditing the Query details / Wait analysis pages against the MSSQL/Oracle
reference standard surfaced that MySQL's `db.server.query_sample` has no per-execution wall-clock
or monotonic anchor comparable to MSSQL's `query_start`. `mysql.event_id` alone increments per
wait event within a statement, not per statement — it doesn't reset or advance in a way a
dashboard query can key on to say "this is a new execution of the same statement on this thread."

## Hypothesis

`performance_schema.events_statements_current.TIMER_START` — a monotonically increasing
picosecond counter, internal to Performance Schema (not wall-clock time), reset only when a new
statement begins on a given thread — is present unconditionally on MySQL 5.6+ and MariaDB (no
version gate, confirmed against official docs earlier this session) and can serve as that stable
per-execution key.

## Empirical validation (done before writing any code)

Verified directly against the running lab (MySQL 8.0.46, `atiwari-nrmysql-db-mysql`):

```
mysql> SELECT THREAD_ID, TIMER_START, TIMER_WAIT, SQL_TEXT
       FROM performance_schema.events_statements_current WHERE TIMER_WAIT > 0 LIMIT 5;
THREAD_ID  TIMER_START          TIMER_WAIT   SQL_TEXT
70611      652332302642692000   41291000     SHOW REPLICA STATUS
70612      652302292955886000   9439833000   SELECT ... events_statements_summary_by_digest ...
70613      652332292824192000   665333000    /* otel-collector-ignore */ SELECT ...
93717      651786596568765000  637416000     SELECT @@session.transaction_read_only
93509      652336646947902000   67750000     /*nr_service_guid=...*/SELECT * FROM users WHERE id = 40861
```

Confirmed: nonzero, distinct, large picosecond values (~652,332 seconds ≈ 7.5 days of uptime-scale
magnitude) — consistent with a monotonic counter since Performance Schema init, not a Unix
timestamp. **Hypothesis confirmed** — safe to proceed.

## Design

- `templates/querySample.tmpl`: add `COALESCE(statement.TIMER_START, 0) AS statement_timer_start`
  to the SELECT list. The `statement` alias (`events_statements_current`) is already joined for
  `statement_timer_wait_seconds` etc. — no new join.
- `client.go`: add `statementTimerStart int64` to the `querySample` struct (next to
  `statementTimerWait`); add `case "statement_timer_start": dest = append(dest,
  &s.statementTimerStart)` to `getQuerySamples`'s column-name switch.
- `metadata.yaml`: new attribute `mysql.events_statements_current.timer_start` (`type: int`),
  added to `db.server.query_sample`'s `attributes:` list. Description states explicitly this is
  an internal monotonic picosecond counter (not wall-clock), useful as a stable per-execution key.
- `make mdatagen` regenerates `internal/metadata/generated_*.go` and `documentation.md`.
- `scraper.go`, `scrapeQuerySamples`: thread `sample.statementTimerStart` as a new trailing
  argument to `RecordDbServerQuerySampleEvent`.

No version gate needed — column is present unconditionally back to MySQL 5.6 and current MariaDB.

## Test plan

1. **Unit tests** (`scraper_test.go`):
   - Extend `testdata/scraper/*.txt` query-sample fixtures with an optional 18th tab-delimited
     column (mirrors the existing optional `traceparent`/`blockingThreadID` trailing columns in
     `mockClient.getQuerySamples`).
   - New test asserting a fixture row with a nonzero `statement_timer_start` value produces that
     exact value on the emitted `mysql.events_statements_current.timer_start` attribute.
   - Confirm an existing fixture lacking the new column still defaults to `0` (no regression).
2. `go test ./receiver/nrmysqlreceiver/...`.
3. **Local end-to-end**: rebuild `cmd/otelcolmin` (host cross-compile, see local rebuild memory),
   restart `atiwari-nrmysql-collector`, confirm `mysql.events_statements_current.timer_start`
   appears on live `db.server.query_sample` events in NRDB with plausible nonzero values.
