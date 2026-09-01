# Changelog — nr-prefixed receivers

User-facing changes for the `nr`-prefixed receivers (`nrsqlserverreceiver`, `nroracledbreceiver`, ...),
including confirmation of which breaking changes from [CHANGELOG.md](./CHANGELOG.md) apply to them.

<!-- next version -->

## Unreleased

### 🧰 Bug fixes 🧰

- `receiver/nrmysql`: Disabling every metric fed by the table stats, statement events, table
  lock-wait, replica status, InnoDB, table io_waits, or index io_waits query groups now also
  skips the underlying query, instead of still running it and discarding the result.

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
