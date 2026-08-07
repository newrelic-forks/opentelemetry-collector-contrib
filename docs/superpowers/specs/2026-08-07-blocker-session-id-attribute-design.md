# Design: nrmysqlreceiver — resolve the blocker's session id (PROCESSLIST_ID)

**Date:** 2026-08-07
**Target:** `receiver/nrmysqlreceiver/templates/querySample.tmpl`, `client.go`, `scraper.go`, `metadata.yaml`.
**Goal:** let a DBA cross-reference "who is blocking me" against the rest of the dashboard, which
identifies sessions by `mysql.session.id` (`PROCESSLIST_ID`) everywhere else — not by
`THREAD_ID`, the ID space `mysql.blocking.blocker.thread_id` (added earlier this session) uses.

## Problem recap

`mysql.blocking.blocker.thread_id` exposes `performance_schema.data_lock_waits.BLOCKING_THREAD_ID`
directly. That's the right ID for a follow-up query against Performance Schema, but it's the wrong
ID for a dashboard: every other session-identifying attribute here (`mysql.session.id`, the
`session_id` column) is `PROCESSLIST_ID`, and `THREAD_ID`/`PROCESSLIST_ID` are allocated from
independent ID spaces that only coincide by chance. A DBA looking at "blocked by thread 93833"
has no way to find that session elsewhere on the dashboard, which only ever shows
`mysql.session.id` (`PROCESSLIST_ID`) values.

## Hypothesis

`performance_schema.threads.PROCESSLIST_ID` gives the PROCESSLIST_ID for any `THREAD_ID`,
including a blocker's. Joining `data_lock_waits.BLOCKING_THREAD_ID` through `threads.THREAD_ID`
resolves the blocker's `PROCESSLIST_ID` with a second cheap PK-lookup subquery, same cost profile
as the existing `blocking_thread_id` subquery.

## Empirical validation (done before writing any code)

Reproduced a live blocking scenario against the lab MySQL 8.0.46 (`atiwari-nrmysql-db-mysql`):
session A opened a transaction and ran `SELECT * FROM orders WHERE id=1 FOR UPDATE`, holding the
row lock; session B then ran the same statement and blocked on it.

```
mysql> SELECT lw.REQUESTING_THREAD_ID, lw.BLOCKING_THREAD_ID,
              req.PROCESSLIST_ID AS requester_session_id, blk.PROCESSLIST_ID AS blocker_session_id
       FROM performance_schema.data_lock_waits lw
       JOIN performance_schema.threads req ON req.THREAD_ID = lw.REQUESTING_THREAD_ID
       JOIN performance_schema.threads blk ON blk.THREAD_ID = lw.BLOCKING_THREAD_ID;

REQUESTING_THREAD_ID  BLOCKING_THREAD_ID  requester_session_id  blocker_session_id
93843                 93833               93781                 93771
```

Confirmed: `BLOCKING_THREAD_ID` (93833) and the blocker's real `PROCESSLIST_ID` (93771) are
distinct values — proving the new attribute carries information the existing
`blocking_thread_id` doesn't, and that the `threads.THREAD_ID` join correctly resolves one to the
other. **Hypothesis confirmed.**

## Design

- `templates/querySample.tmpl`: add a second scalar subquery next to the existing
  `blocking_thread_id` one:
  ```sql
  COALESCE(
      (
          SELECT bt.PROCESSLIST_ID
          FROM performance_schema.data_lock_waits AS lw
          JOIN performance_schema.threads AS bt ON bt.THREAD_ID = lw.BLOCKING_THREAD_ID
          WHERE lw.REQUESTING_THREAD_ID = thread.thread_id
          LIMIT 1
      ), 0
  ) AS blocking_session_id
  ```
  Same cost profile as the existing subquery — the extra join only runs for the rare blocked row.
- `client.go`: add `blockingSessionID int64` to `querySample`; add `case
  "blocking_session_id": dest = append(dest, &s.blockingSessionID)`.
- `metadata.yaml`: new attribute `mysql.blocking.blocker.session_id` (`type: int`), description
  parallels the existing `mysql.blocking.blocker.thread_id` entry, explicit that this is the
  PROCESSLIST_ID for cross-referencing `mysql.session.id` elsewhere on the dashboard. Appended to
  the end of `db.server.query_sample`'s `attributes:` list (so it lands as a new trailing
  parameter, not reordering the existing generated function signature). `make mdatagen` +
  `make fmt gci`.
- `scraper.go`: thread `sample.blockingSessionID` as a new trailing argument to
  `RecordDbServerQuerySampleEvent`.

No version gate needed — `data_lock_waits` and `threads.PROCESSLIST_ID` are already relied on by
the existing `blocking_thread_id` feature on the same MySQL/MariaDB versions.

## Test plan

1. **Unit tests** (`scraper_test.go`):
   - Extend query-sample fixtures with an optional 19th tab-delimited column.
   - New fixture/test where the blocker's `THREAD_ID` and `PROCESSLIST_ID` are deliberately
     different values, asserting the emitted attribute equals the PROCESSLIST_ID, not a copy of
     `blocking_thread_id` — this is the case that actually exercises the join, not just proves the
     column parses.
   - Unblocked case reports `0`.
2. `go test ./receiver/nrmysqlreceiver/...`.
3. **Local end-to-end**: rebuild `cmd/otelcolmin` (host cross-compile), restart
   `atiwari-nrmysql-collector`, reproduce the live blocking scenario used for empirical
   validation, confirm `mysql.blocking.blocker.session_id` in NRDB matches the blocker's real
   `PROCESSLIST_ID`.
