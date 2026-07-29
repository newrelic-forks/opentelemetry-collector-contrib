# Changelog — nr-prefixed receivers

User-facing changes for the `nr`-prefixed receivers (`nrsqlserverreceiver`, `nroracledbreceiver`, ...),
including confirmation of which breaking changes from [CHANGELOG.md](./CHANGELOG.md) apply to them.

<!-- next version -->

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
