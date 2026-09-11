# Changelog — nr-prefixed receivers

User-facing changes for the `nr`-prefixed receivers (`nrsqlserverreceiver`, `nroracledbreceiver`, ...),
including confirmation of which breaking changes from [CHANGELOG.md](./CHANGELOG.md) apply to them.

<!-- next version -->

## Unreleased

## v0.160.0

Synced with upstream contrib v0.160.0.

### 🛑 Breaking changes 🛑

- `receiver/nroracledb`: `oracledb.plan_hash_value` is now the raw Oracle numeric value instead of a
  hex-encoded string — e.g. `3123456789` where it previously emitted `33313233343536373839`. Anything
  decoding the hex form must be updated. Adopted from upstream `receiver/oracledb` (#50307).

- `receiver/nrpostgresql`: the `relation` attribute on `postgresql.database.locks` is now the relation
  NAME (e.g. `orders`) rather than the relation OID, and is an empty string rather than null when the
  lock target is not a relation. The metric also now reports locks that belong to no single database —
  transaction-ID locks and other non-relation targets — which were previously dropped entirely, so
  counts can rise and new series carrying an empty `relation` can appear. Adopted from upstream
  `receiver/postgresql` (#50008).

- `receiver/nrpostgresql`: `exclude_databases` now also filters the `db.server.query_sample` and
  `db.server.top_query` collectors. Those two previously ignored it, so excluded databases still
  produced samples and top queries; they no longer do. Adopted from upstream `receiver/postgresql`
  (#50056).

- `receiver/nrsqlserver`: `service.instance.id` now uses `host\instance` when the connection is
  configured through `datasource` with a named instance, instead of collapsing every instance on a
  host to `host:port`. Deployments monitoring named instances will see the resource identity change.
  Adopted from upstream `receiver/sqlserver` (#50535).

- `receiver/nrsqlserver`: `sqlserver.lock.timeout.rate`'s unit changed from `{timeouts}/s` to
  `{timeout}/s`, and its description from "Total number of lock timeouts." to "Number of lock timeouts
  per second." The emitted value was already per-second — only the unit string and description were
  wrong. Now matches `sqlserverreceiver`.

- `all`: minimum Go version raised to 1.26 (upstream #50394). **Already matched — no fork change was
  needed**; every `nr`-prefixed module declares `go 1.26.0`.

No other breaking change in upstream v0.159.0 or v0.160.0 applies to these receivers: neither release
carried a breaking entry scoped to `receiver/sqlserver`, `receiver/oracledb`, `receiver/postgresql`
or `receiver/mysql`.

### 🚩 New components 🚩

- `receiver/nroracledb`: 5 opt-in ASM metrics — `oracledb.asm.disk.errors` and
  `oracledb.asm.disk_group.{capacity,free,offline_disks,usable_free}` — with the
  `oracledb.asm.disk.name` / `oracledb.asm.disk_group.name` attributes. Both underlying queries
  return zero rows rather than erroring on instances that do not use ASM. Requires
  `GRANT SELECT ON V_$ASM_DISKGROUP_STAT` and `V_$ASM_DISK_STAT`. From upstream (#50489).

- `receiver/nrmysql`: 3 opt-in InnoDB row-lock wait metrics —
  `mysql.innodb.row_lock.wait.count` and `mysql.innodb.row_lock.wait.duration.{avg,max}` (#50172).

- `receiver/nrmysql`: 4 opt-in MyISAM key-cache metrics —
  `mysql.myisam.key_cache.{block.unused,block.used.max,disk.operation,request}` — with the
  `mysql.myisam.key_cache.operation.type` (read/write) attribute (#50247).

- `receiver/nrmysql`: 3 opt-in InnoDB transaction metrics — `mysql.innodb.history_list.length`,
  `mysql.innodb.transaction.active.count` and `mysql.innodb.transaction.active.duration.max`. The
  query that feeds them is skipped entirely when all three are disabled (#50380).

- `receiver/nrmysql`: `db_auth` configuration for AWS IAM authentication against RDS/Aurora MySQL,
  via a `dbauth` provider extension. Mutually exclusive with `password` and requires TLS
  (`tls.insecure: false`). Brings `nrmysql` in line with `nrpostgresql`, which already had it (#50411).

### 🧰 Bug fixes 🧰

- `receiver/nrmysql`: `mysql.commands` now also reports the `alter_table`, `create_index`,
  `create_table` and `optimize` command types. Only 6 of upstream's 10 `Com_*` counters were being
  emitted, so those four command counts were silently missing.

- `receiver/nrsqlserver`: `db.server.query_sample` no longer drops sessions whose SQL text is
  unavailable — including sessions blocked on schema locks. The query now falls back to
  `sys.dm_exec_input_buffer` instead of inner-joining `sys.dm_exec_sql_text`. Adopted from upstream
  (#49984).

- `receiver/nrpostgresql`: top-query collection no longer panics on a type assertion when
  `pg_stat_statements` still holds rows for a dropped database. Adopted from upstream (#49820).

- `receiver/nrmysql`: Disabling every metric fed by the table stats, statement events, table
  lock-wait, replica status, InnoDB, table io_waits, or index io_waits query groups now also
  skips the underlying query, instead of still running it and discarding the result.

- `receiver/nrpostgresql`: Disabling a per-table or per-index metric now also skips the query
  that fed it, instead of still running the query and discarding the result.

### 💡 Enhancements 💡

- `receiver/nrpostgresql`: `postgresql.table.count` alone now uses a cheap `COUNT(*)` instead of
  the full per-table query.

- `receiver/nroracledb`: added the `service.name` and `service.namespace` resource attributes, both
  disabled by default, matching the other `nr`-prefixed receivers and `oracledbreceiver`. When
  enabled, `service.name` defaults to `unknown_service:oracle`.

## v0.158.3

### 🧰 Bug fixes 🧰

- `receiver/nrsqlserver`: Skip emitting `db.server.query_sample`/`db.server.top_query` rows whose
  query text is empty, instead of emitting an empty-text record.

- `receiver/nrpostgresql`: `postgresql.backend_start` was emitted in the session's local timezone
  instead of UTC, making it non-comparable to `postgresql.blocking.start_time` (which is UTC). Both
  are now UTC.

- `receiver/nrmysql`: `mysql.events_waits_current.timer_wait` could report implausible values
  (millions of seconds) for the `redo_log_flush` wait event on Aurora MySQL. Readings above a sanity
  ceiling are now discarded instead of emitted as-is.

### 💡 Enhancements 💡

- `receiver/nrsqlserver`: `server.address` and `server.port` are now emitted by default.

## v0.158.0

### 🛑 Breaking changes 🛑

- `receiver/nroracledb` (upstream [#48643](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/48643)):
  `oracle.db.pdb` moved from a resource attribute to an opt-in data-point attribute. Already defined
  as a data-point attribute in the fork's `metadata.yaml` — no fork change was required.

- `receiver/nrpostgresql` (upstream [#49206](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/49206)):
  `postgresql.database.locks` is now collected per configured database via a dedicated
  `getSharedRelationLocks` query for shared catalogs plus a database-scoped `getDatabaseLocks`
  query, and the lock count switched from `COUNT(pid)` to `COUNT(*)` so locks held by prepared
  transactions (NULL `pid`) are counted. Also adds an opt-in `db.namespace` attribute. Ported.

### 🚩 New components 🚩

- `receiver/nrpostgresql`: First tagged release. Forked from upstream `receiver/postgresql`; adds
  `db_auth` credential provider support (e.g. AWS IAM), EXPLAIN-via-`SECURITY DEFINER`-function
  support with per-database probe caching, pgvector similarity-search metrics, NR correlation
  attribute extraction from SQL comments, and the `postgresql.query.execution.time` metric.

- `receiver/nrmysql`: First tagged release. Forked from upstream `receiver/mysql`; adds NR
  correlation attribute extraction and redaction on `db.query.text`, blocking-session detection and
  client program name on `db.server.query_sample`, `explain_mode` for EXPLAIN-via-definer-procedure,
  and rows examined/sent on `db.server.top_query`.

## v0.157.1

### 🛑 Breaking changes 🛑

- `receiver/nrsqlserver`: Removed `sqlserver.memory.target` and `sqlserver.kill_connection.error.rate`,
  duplicates of `sqlserver.memory.area{memory.pool="target"}` and
  `sqlserver.error.rate{sqlserver.error.category="kill_connection"}` respectively. Users with either
  metric `enabled: true` should switch to the equivalent above; the data was already being collected
  under the other name.

- `receiver/nrsqlserver` (upstream [#49453](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/49453)):
  Metric units were fixed to comply with the UCUM specification. Already matched upstream's corrected
  values — no fork change was required.

- `receiver/nrsqlserver` (upstream [#48927](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/48927)):
  `sqlserver.lock.timeout.rate` now requires a `sqlserver.lock.timeout.type` attribute (`all`,
  `nonzero`) and emits one data point per type instead of one aggregate value. Already emitted both
  data points — no fork change was required.

- `receiver/nroracledb` (upstream [#49329](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/49329)):
  SQL query plan details are now retrieved from `V$SQL_PLAN_STATISTICS_ALL` instead of `V$SQL_PLAN`.
  Requires the collector's database user to have access to `V$SQL_PLAN_STATISTICS_ALL`; deployments
  that only grant access to `V$SQL_PLAN` may see query plan collection failures until the appropriate
  privilege is granted. Already used `V$SQL_PLAN_STATISTICS_ALL` — no fork change was required.

### 🚩 New components 🚩

- `receiver/nrsqlserver`: Added opt-in host-level metrics for CPU, memory, and disk I/O as observed by SQL Server
  (`sqlserver.cpu.utilization`, `sqlserver.host.memory.limit`, `sqlserver.host.memory.usage`, `sqlserver.disk.io`,
  `sqlserver.disk.operations`), ported from upstream `receiver/sqlserver` ([#49862](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/49862)).

- `receiver/nroracledb`: Query-sample collection now uses a two-pass approach — session data is collected first,
  then SQL text/plan/child-address are fetched in a single batched lookup keyed by the SQL IDs seen in that pass
  (batched in groups of 1000 to stay under Oracle's `IN`-list limit) — avoiding a full V$SQL cursor-cache scan.
  Ported from upstream `receiver/oracledb` ([#49875](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/49875)).
