# Design: nrmysqlreceiver — add diffed rows examined/sent to `db.server.top_query`

**Date:** 2026-08-07
**Target:** `receiver/nrmysqlreceiver/templates/topQuery.tmpl`, `topQueryNoSampleTextTemplate`,
`client.go`, `scraper.go`, `metadata.yaml`.
**Goal:** give `db.server.top_query` a "rows examined" signal comparable to MSSQL, but correctly
*diffed* per scrape cycle — the upstream `mysqlreceiver`'s `mysql.statement_event.count` metric
reads the same columns undiffed, which can't be paired with `nrmysqlreceiver`'s own diffed
`count_star` for a meaningful per-execution average.

## Problem recap

The MSSQL/Oracle reference dashboard shows "Rows examined" per top query. MySQL's
`events_statements_summary_by_digest.SUM_ROWS_EXAMINED`/`SUM_ROWS_SENT` are the equivalent data,
but they're raw cumulative counters — same shape as `COUNT_STAR`/`SUM_TIMER_WAIT`, which
`nrmysqlreceiver` already diffs per scrape cycle via `cacheAndDiff` before emitting on
`db.server.top_query`. Reading rows-examined/sent through a different, undiffed path (as upstream
`mysqlreceiver` does for its own metrics) would produce numbers that aren't comparable to this
receiver's own `count_star`/`sum_timer_wait` on the same event.

## Hypothesis

`SUM_ROWS_EXAMINED`/`SUM_ROWS_SENT` are plain columns on the same
`events_statements_summary_by_digest` table `nrmysqlreceiver` already reads for
`count_star`/`sum_timer_wait`/`query_sample_text` — no new table, no new grant, no version gate —
and can be diffed with the exact same `cacheAndDiff(schema, digest, column, val)` primitive.

## Empirical validation (done before writing any code)

Confirmed against the running lab (MySQL 8.0.46), using the receiver's own monitoring user
(`newrelic`) to prove the existing grant already covers these columns:

```
mysql> SELECT DIGEST, COUNT_STAR, SUM_ROWS_EXAMINED, SUM_ROWS_SENT
       FROM performance_schema.events_statements_summary_by_digest
       ORDER BY LAST_SEEN DESC LIMIT 5;
DIGEST                   COUNT_STAR  SUM_ROWS_EXAMINED  SUM_ROWS_SENT
44e35cee...              32          32                 32
94256f25...              3623177     867003             125063
840a880e...              3620868     144784             144785
036c322c...              2898029     2078621            230144
5a982e98...              724577      14491580000         724579
```

Confirmed: both columns are populated, readable by the existing monitoring grant, and — as
expected for a raw cumulative counter table — magnitudes scale with `COUNT_STAR` (the last row's
`SUM_ROWS_EXAMINED` far exceeding `COUNT_STAR` is expected for a query that does a large scan per
execution, e.g. a correlated subquery). **Hypothesis confirmed.**

## Design

- `templates/topQuery.tmpl` and `templates/topQueryNoSampleTextTemplate`: append `,
  SUM_ROWS_EXAMINED, SUM_ROWS_SENT` to the end of each variant's SELECT list.
  `getTopQueries`'s `scanRow` (`client.go`) scans **positionally**, not by column name (unlike
  `getQuerySamples`), so column order must exactly match the `Scan()` argument order added below —
  appending at the end of each branch, after each variant's current last column
  (`query_sample_text` / `sum_timer_wait`), keeps existing columns' positions unchanged.
- `client.go`: add `sumRowsExamined int64`, `sumRowsSent int64` to `topQuery`; update both
  branches of `scanRow` to scan the two new columns at the end of each branch's argument list.
- `scraper.go`, `scrapeTopQueries`: diff both new columns exactly like `count_star` is diffed
  today:
  ```go
  cachedExamined, rowsExaminedVal := m.cacheAndDiff(q.schemaName, q.digest, "sum_rows_examined", q.sumRowsExamined)
  if !cachedExamined {
      rowsExaminedVal = 0
  }
  cachedSent, rowsSentVal := m.cacheAndDiff(q.schemaName, q.digest, "sum_rows_sent", q.sumRowsSent)
  if !cachedSent {
      rowsSentVal = 0
  }
  ```
- `metadata.yaml`: two new attributes,
  `mysql.events_statements_summary_by_digest.sum_rows_examined` and `.sum_rows_sent` (`type: int`),
  description phrasing matches the existing `count_star` entry ("...report in delta value.").
  Appended to the end of `db.server.top_query`'s `attributes:` list. `make mdatagen` + `make fmt gci`.
- `scraper.go`: thread `rowsExaminedVal`, `rowsSentVal` as two new trailing arguments to
  `RecordDbServerTopQueryEvent`.

No version gate needed — same table/grant already relied on for `count_star`/`sum_timer_wait`.

## Test plan

1. **Unit tests** (`scraper_test.go`):
   - Extend `testdata/scraper/top_queries.txt` and `top_queries_no_sample_text.txt` with two new
     optional trailing columns in `mockClient.getTopQueries`, mirroring the existing
     `if len(text) > 5 { q.querySampleText = ... }` pattern.
   - New test mirroring the existing count_star diff-testing pattern (pre-seed the cache with
     `rowsExamined-1`/`rowsSent-1` via `cacheAndDiff`, run one scrape, assert the emitted
     attributes equal exactly `1` — the diff, not the raw cumulative fixture value).
   - Cover both the with-sample-text and no-sample-text (MariaDB/MySQL<8) template paths, to
     confirm both `scanRow` branches parse the new trailing columns correctly.
2. `go test ./receiver/nrmysqlreceiver/...`.
3. **Local end-to-end**: rebuild `cmd/otelcolmin` (host cross-compile), restart
   `atiwari-nrmysql-collector`, confirm `mysql.events_statements_summary_by_digest.sum_rows_examined`
   /`.sum_rows_sent` in NRDB reflect per-cycle deltas (not the cumulative total) on real top-query
   events.
