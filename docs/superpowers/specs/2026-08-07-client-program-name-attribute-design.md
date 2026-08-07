# Design: nrmysqlreceiver — add client program name to `db.server.query_sample`

**Date:** 2026-08-07
**Target:** `receiver/nrmysqlreceiver/templates/querySample.tmpl`, `client.go`, `scraper.go`, `metadata.yaml`.
**Goal:** give `db.server.query_sample` a real client/driver identity, closing a MySQL/MSSQL
parity gap — MSSQL's `program_name` lets a DBA see what application/tool opened a session; MySQL
only had `session_user`/`client_address`, neither of which identifies the client software itself.

## Problem recap

Auditing the Query samples page against the MSSQL/Oracle reference standard found no MySQL
equivalent of `program_name`. `session_user`/`client_address` identify *who* and *from where*, not
*what* — two connections from the same app-tier host under the same DB user are indistinguishable
today.

## Hypothesis

`performance_schema.session_connect_attrs` stores per-connection attributes reported by the
client driver at connect time, keyed by `PROCESSLIST_ID` — including `_client_name`, the driver's
self-reported identity (e.g. `MySQL Connector/J`, `Go-MySQL-Driver`, `libmysql`). Joining it to
`threads.PROCESSLIST_ID` and filtering to `ATTR_NAME = '_client_name'` gives a real client
identity with no fan-out risk (at most one row per `(PROCESSLIST_ID, ATTR_NAME)` pair).

## Empirical validation (done before writing any code)

Verified directly against the running lab (MySQL 8.0.46):

```
mysql> SELECT PROCESSLIST_ID, ATTR_NAME, ATTR_VALUE FROM performance_schema.session_connect_attrs
       ORDER BY PROCESSLIST_ID LIMIT 20;
PROCESSLIST_ID  ATTR_NAME       ATTR_VALUE
70549           _client_name    Go-MySQL-Driver          -- the collector's own monitoring connections
93447           _client_name    MySQL Connector/J        -- the app tier's JDBC connections
93447           _client_version 8.1.0
...

mysql> SELECT THREAD_ID, PROCESSLIST_ID, PROCESSLIST_USER FROM performance_schema.threads
       WHERE PROCESSLIST_ID IS NOT NULL ORDER BY PROCESSLIST_ID LIMIT 20;
THREAD_ID  PROCESSLIST_ID  PROCESSLIST_USER
70611      70549           newrelic
93509      93447           atiwari-app-mysql
```

Confirmed: (a) the join key is `PROCESSLIST_ID`, not `THREAD_ID` — the two differ for every real
connection observed; (b) `_client_name` holds real, distinct driver identities per connection;
(c) `program_name` (a Postgres/MSSQL-style convention) is not an attribute MySQL connectors set —
`_client_name` is the correct key. **Hypothesis confirmed.**

## Design

- `templates/querySample.tmpl`: add
  ```sql
  LEFT JOIN performance_schema.session_connect_attrs AS attrs
      ON attrs.PROCESSLIST_ID = thread.PROCESSLIST_ID AND attrs.ATTR_NAME = '_client_name'
  ```
  Filtering to one `ATTR_NAME` in the join condition keeps it 1:1 — same pattern the existing
  `user_variables_by_thread` join already uses for `@traceparent`, no row fan-out. Add
  `COALESCE(attrs.ATTR_VALUE, '') AS client_program_name` to the SELECT list.
- `client.go`: add `clientProgramName string` to `querySample`; add `case
  "client_program_name": dest = append(dest, &s.clientProgramName)`.
- `metadata.yaml`: new attribute `mysql.session.client_name` (`type: string`) — empty when the
  client didn't report connect attributes (older client libraries) or the connect-attrs feature is
  disabled server-side. Appended to the end of `db.server.query_sample`'s `attributes:` list.
  `make mdatagen` + `make fmt gci`.
- `scraper.go`: thread `sample.clientProgramName` as a new trailing argument to
  `RecordDbServerQuerySampleEvent`.

No version gate needed — `session_connect_attrs` is available on any client reporting connect
attributes (the default for modern MySQL/MariaDB client libraries); a client that doesn't report
attributes just yields an empty string via the `LEFT JOIN` + `COALESCE`, not an error.

## Test plan

1. **Unit tests** (`scraper_test.go`):
   - Extend query-sample fixtures with an optional 21st tab-delimited column.
   - New test: a fixture row with a client name set asserts the attribute equals that value.
   - New test (or sub-case): a fixture row without it asserts an empty string, not an error — the
     "client didn't report connect attrs" case, which must not break existing rows.
2. `go test ./receiver/nrmysqlreceiver/...`.
3. **Local end-to-end**: rebuild `cmd/otelcolmin` (host cross-compile), restart
   `atiwari-nrmysql-collector`, confirm `mysql.session.client_name` in NRDB shows the correct,
   distinct driver identity for real connections (the app tier's JDBC connections vs. the
   receiver's own Go driver connections).
