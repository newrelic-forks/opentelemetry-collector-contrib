# Changelog — nr-prefixed receivers

User-facing changes for the `nr`-prefixed receivers (`nrsqlserverreceiver`, `nroracledbreceiver`, ...),
including confirmation of which breaking changes from [CHANGELOG.md](./CHANGELOG.md) apply to them.

<!-- next version -->

## v0.162.1

Patch release for `receiver/nroracledb` only — no new upstream contrib version this cycle.

### 🛑 Breaking changes 🛑

- `receiver/nroracledb` (upstream [#50230](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/50230)):
  `db.query.text` is now produced using the obfuscator's `ObfuscateAndNormalize` mode directly,
  instead of `obfuscate_only` plus a separate pass that manually anonymized collected comments.
  Comments and formatting (whitespace, line breaks) are now stripped from the text in addition to
  literals, so the same Oracle `sql_id` no longer yields different `query_text`/
  `db.query.text.normalized.hash` values purely from formatting differences — but the text format
  itself changes for every query. `KeepIdentifierQuotation` is also enabled, so a quoted identifier
  such as `"a b"` is no longer collapsed into the unquoted `a b`. Ported.

- `receiver/nroracledb`: `oracledb.sga.usage` changed from a non-monotonic cumulative sum to a gauge.
  Values are unchanged; only the metric type/aggregation temporality changes.

- `receiver/nroracledb`: upgraded `github.com/DataDog/datadog-agent/pkg/obfuscate` to v0.83.2.

### 🧰 Bug fixes 🧰

- `receiver/nroracledb`: the `V$SYSSTAT` and `V$SYSMETRIC` queries now also run when only a metric
  added in a previous cycle (e.g. the JVM/OS/session/lock/recovery `v$sysstat` metrics, or the
  `*.rate` `v$sysmetric` metrics) is enabled on its own. Previously the shared "is anything enabled"
  check for each query had not been updated when those metrics were ported, so enabling only one of
  them silently collected nothing.

- `receiver/nroracledb`: `oracle.db.pdb` now falls back to the connected PDB name when a row's
  `PDB_NAME` column is empty but the connection is to a specific PDB (e.g. direct-PDB connections such
  as on AWS RDS Oracle), instead of leaving the attribute blank.

- `receiver/nroracledb`: errors fetching execution-plan data for `db.server.top_query` are now
  surfaced as scrape errors instead of being silently discarded.

## v0.162.0

Synced with upstream contrib v0.162.0.

### 🛑 Breaking changes 🛑

- `receiver/nrsqlserver`: `collect_full_query_text` and `allowed_comment_keys` moved from the top
  level of the config into `top_query_collection` and `query_sample_collection`, so the two events
  are configured independently. A config that still sets either key at the top level now fails at
  startup with an unknown-key error instead of silently dropping the attributes.

- `receiver/nrsqlserver`: removed the `sqlserver.database.page_file.size` metric (disabled by
  default) and its `page_file.state` attribute.

- `receiver/nrsqlserver`: `sqlserver.session.duration` on `db.server.query_sample` now measures
  seconds since the session logged in, instead of the elapsed time of the session's active request,
  matching `nroracledb`. Values for idle or long-lived sessions will be much larger.

- `receiver/nrmysql`: three event attributes are renamed to match upstream `receiver/mysql`:
  `mysql.session.client_name` → `mysql.client.name` on `db.server.query_sample`, and
  `mysql.events_statements_summary_by_digest.sum_rows_examined` / `.sum_rows_sent` → `.examined_rows`
  / `.returned_rows` on `db.server.top_query`. Values are unchanged.

- `receiver/nrpostgresql`: `receiver.nrpostgresql.useOTelSemconv` is now Beta and **enabled by
  default** (was Alpha, disabled). Resource attributes emitted by default switch from the legacy
  per-entity model (`postgresql.database.name`, `.table.name`, `.index.name`, `.schema.name`, one
  resource per database/table/index) to a single per-server resource with `server.address`,
  `server.port`, and a UUID v5 `service.instance.id`, aligning with OpenTelemetry semantic
  conventions. To keep the legacy shape, disable the gate explicitly:
  `--feature-gates=-receiver.nrpostgresql.useOTelSemconv`.

- `receiver/nrpostgresql`: the `db.server.query_sample` log event's `postgresql.backend_start` and
  `postgresql.session_duration` attributes are renamed to `postgresql.backend.connection.start` and
  `postgresql.session.duration`, matching this receiver's existing dotted-namespace attribute
  convention (e.g. `postgresql.blocking.start_time`).

- `receiver/nrsqlserver`, `receiver/nroracledb`, `receiver/nrpostgresql`, `receiver/nrmysql`: the SQL
  normalizer now matches New Relic APM's, so `db.query.text.normalized.hash` can change for the same
  statement. `TRUE`/`FALSE`/`NULL` keyword literals, hex literals and PostgreSQL `EXTRACT` field
  names are now replaced with `?`; MySQL `@@` system variables are no longer treated as bind
  parameters; and invisible Unicode format characters are stripped. Anything keyed on the hash
  (dashboards, joins with APM data) sees new values for affected statements.

- `receiver/nroracledb` (upstream [#45270](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/45270)):
  units on 39 metrics moved to singular form, e.g. `{gets}` → `{get}`, `{sessions}` → `{session}`,
  `{parses}/s` → `{parse}/s`. Values are unchanged. Ported.

- `receiver/nroracledb` (upstream [#50882](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/50882), [#50951](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/50951)):
  `oracledb.plan.first_load` and `oracledb.plan.last_load` on `db.server.top_query` are now ISO 8601
  UTC timestamps (`2026-09-29T10:15:00Z`) instead of Oracle's native `YYYY-MM-DD/HH:MM:SS` in the
  server's local timezone, on both CDB-root and non-CDB connections. Ported.

- `receiver/nroracledb` (upstream [#50724](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/50724)):
  when the configured target has no parseable port, `service.instance.id` now resolves to
  `host:1521/service` instead of `unknown:1521/service`, which changes the resource identity for
  those configs. Targets with no parseable host at all (e.g. TNS descriptors) are unchanged. Ported.

- `receiver/nrsqlserver` (upstream [#50384](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/50384)):
  `server.address` and `server.port` removed from `db.server.top_query` log record attributes, kept
  as resource attributes enabled by default, and the `receiver.sqlserver.RemoveServerResourceAttribute`
  feature gate removed. **Already matched — no fork change was needed**; the fork never carried
  those log attributes or the gate. Its stale README section for the gate was removed.

No other breaking change in upstream v0.161.0 or v0.162.0 applies to these receivers. The two `all`
entries — removal of the deprecated mezmo exporter (#49953) and of the wavefront receiver (#51397) —
concern components these receivers do not use.

### 🚩 New components 🚩

- `receiver/nrsqlserver`, `receiver/nroracledb`, `receiver/nrpostgresql`, `receiver/nrmysql`: new
  `db.server.query_plan` event that reports the execution plan on a record of its own, so it can be
  filtered, routed or dropped independently of the query statistics. Disabled by default; while it is
  disabled nothing changes. Enabling it moves the plan off `db.server.top_query` (and, for `nrmysql`,
  `db.server.query_sample`, which keeps `mysql.query_plan.hash` as the join key; `nrmysql` also adds
  the `mysql.query_plan.source` attribute). It needs `db.server.top_query` enabled (`nrmysql`: top
  query or query sample): `nroracledb`, `nrpostgresql` and `nrmysql` reject a config that enables it
  alone, and `nrsqlserver` accepts it but collects nothing. From upstream (#50629, #51065, #51301,
  #51281).

- `receiver/nrsqlserver`, `receiver/nroracledb`: new `db.server.top_procedure` event reporting
  per-interval deltas of stored-procedure statistics, ranked by elapsed time. Disabled by default;
  configured through the new `top_procedure_collection` block (`max_procedure_sample_count`,
  `top_procedure_count`, `collection_interval`). From upstream (#50799, #50796).

- `receiver/nrmysql`: 3 opt-in InnoDB redo-log metrics — `mysql.innodb.redo_log.lsn.current`,
  `mysql.innodb.redo_log.lsn.checkpoint` and `mysql.innodb.redo_log.checkpoint.age` (#50650).

- `receiver/nrmysql`: 3 opt-in KPI metrics — `mysql.server.healthy`, `mysql.session.active.count` and
  `mysql.query.execution.time` (#50726).

- `receiver/nroracledb`: system and resource-limit metrics are now also collected when connected
  directly to a PDB, such as on AWS RDS Oracle (#50147).

### 🧰 Bug fixes 🧰

- `receiver/nroracledb`: `db.server.top_query` and `db.server.top_procedure` no longer run before
  their configured collection interval has elapsed (#50888).

- `receiver/nroracledb`: on CDB-root connections, dictionary joins are qualified by `CON_ID`, so
  procedure names and blocked-object owner/name are attributed to the correct PDB and procedure
  execution counts are no longer merged across PDBs. Uses `CDB_PROCEDURES`/`CDB_OBJECTS` when those
  grants are present and falls back otherwise (#50797).

- `receiver/nrmysql`: a connection lost part-way through a scrape is now reported as an error,
  instead of returning partial results that looked like a successful collection (#51125).

- `receiver/nrpostgresql`: fixed wrong top-query counter deltas and top-N ranking caused by an
  undersized counter cache (#51066), and by cache entries shared across databases and roles that ran
  the same query ID (#51067). Cache entries are keyed on the role OID (`userid`) rather than its name,
  so a dropped and re-created role no longer collides.

- `receiver/nrpostgresql`: query plans are now collected for top queries that use `EXTRACT(field
  FROM ...)` or a typed literal such as `interval '1 day'`, instead of failing EXPLAIN (#50670).

- `receiver/nrpostgresql`: `postgresql.table.size` now reports a table's total disk usage, including
  its indexes and TOAST storage, instead of only the main data heap. Adopted from upstream
  `receiver/postgresql` (#50918).

### 💡 Enhancements 💡

- `receiver/nroracledb`, `receiver/nrmysql`: `server.address` and `server.port` resource attributes,
  **enabled by default** (#50724, #50967).

- `receiver/nrsqlserver`, `receiver/nroracledb`, `receiver/nrpostgresql`, `receiver/nrmysql`: when
  the receiver connects over loopback (e.g. `localhost`, `127.0.0.1`), `server.address` reports the
  host name of the machine running the collector instead of `localhost`, matching how
  `service.instance.id` already resolves (#49885, #50724, #50889, #50967).

- `receiver/nrpostgresql`: `server.address` and `server.port` are emitted in both resource models,
  regardless of `receiver.nrpostgresql.useOTelSemconv` (#50889).

- `receiver/nrsqlserver`, `receiver/nrpostgresql`: `db.system.version` resource attribute, disabled
  by default (#51194, #51288).

- `receiver/nrsqlserver`: `sqlserver.db.edition` resource attribute, disabled by default.

- `receiver/nroracledb`: `oracle.db.edition` resource attribute, disabled by default (#51292).

- `receiver/nroracledb`: `db.system.name` attribute on `db.server.session.wait_sample` (#51065).

- `receiver/nrpostgresql`: `postgresql.userid` attribute (role OID) on `db.server.top_query` and
  `db.server.query_plan`; stays set even after the role is dropped (#51331).

- `receiver/nrpostgresql`: added a `connect_database` config option controlling which database the
  receiver connects to for cluster-wide queries (discovery, `pg_stat_statements`, bgwriter/WAL/
  replication stats, query samples, top query). Defaults to `postgres`, so existing configs are
  unaffected. Independent of `databases` — useful when `pg_stat_statements` is installed in a
  database other than `postgres`, or when connecting through a dedicated monitoring-only database.
  Adopted from upstream `receiver/postgresql` (#50921).

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
