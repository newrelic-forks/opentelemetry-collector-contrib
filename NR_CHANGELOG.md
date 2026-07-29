# Changelog — nr-prefixed receivers

This file tracks user-facing changes for the `newrelic-forks` receiver variants
(`receiver/nrsqlserverreceiver`, `receiver/nroracledbreceiver`, `receiver/nrpostgresqlreceiver`,
and future `nr`-prefixed forks) that are not already covered by the base
[CHANGELOG.md](./CHANGELOG.md). Each entry either:

- documents a fork-specific change (something only the `nr`-prefixed component does), or
- confirms that a breaking change from the corresponding upstream base receiver
  (tracked in [CHANGELOG.md](./CHANGELOG.md)) has been adopted into the fork, and how.

Tags are cut per-component (`receiver/nrsqlserverreceiver/vX.Y.Z`,
`receiver/nroracledbreceiver/vX.Y.Z`, ...) alongside each entry below.

<!-- next version -->

## v0.157.1

Tracks upstream contrib [v0.156.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/releases/tag/v0.156.0)
and [v0.157.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/releases/tag/v0.157.0).

### 🛑 Breaking changes 🛑

- `receiver/nrsqlserver`: Removed `sqlserver.memory.target` and `sqlserver.kill_connection.error.rate`.
  Both were exact duplicates already covered by other metrics and existed only in the fork:
  - `sqlserver.memory.target` duplicated `sqlserver.memory.area{memory.pool="target"}` (same counter, same query, same scaling).
  - `sqlserver.kill_connection.error.rate` duplicated `sqlserver.error.rate{sqlserver.error.category="kill_connection"}`
    (same counter row, same value; kept only for backward compatibility until now).

  Users who had either metric `enabled: true` should switch to the metric/attribute combination above; no query or
  scraper changes are needed since the data was already collected under the other name.

- `receiver/sqlserver` (adopted from upstream, [#49453](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/49453)):
  Metric units were fixed to comply with the UCUM specification. `nrsqlserverreceiver`'s units already matched
  upstream's corrected values — no fork change was required.

- `receiver/sqlserver` (adopted from upstream, [#48927](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/48927)):
  `sqlserver.lock.timeout.rate` now requires a `sqlserver.lock.timeout.type` attribute (`all`, `nonzero`) and emits
  one data point per type instead of one aggregate value. `nrsqlserverreceiver` already emitted both `all` and
  `nonzero` data points for this metric — no fork change was required.

- `receiver/oracledb` (adopted from upstream, [#49329](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/49329)):
  SQL query plan details are now retrieved from `V$SQL_PLAN_STATISTICS_ALL` instead of `V$SQL_PLAN`. This requires
  the collector's database user to have access to `V$SQL_PLAN_STATISTICS_ALL`; deployments that only grant access
  to `V$SQL_PLAN` may see query plan collection failures until the appropriate privilege is granted.
  `nroracledbreceiver` already queries `V$SQL_PLAN_STATISTICS_ALL` — no fork change was required.

### 🚩 New components 🚩

- `receiver/nrsqlserver`: Added opt-in host-level metrics for CPU, memory, and disk I/O as observed by SQL Server
  (`sqlserver.cpu.utilization`, `sqlserver.host.memory.limit`, `sqlserver.host.memory.usage`, `sqlserver.disk.io`,
  `sqlserver.disk.operations`), ported from upstream `receiver/sqlserver` ([#49862](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/49862)).

- `receiver/nroracledb`: Query-sample collection now uses a two-pass approach — session data is collected first,
  then SQL text/plan/child-address are fetched in a single batched lookup keyed by the SQL IDs seen in that pass
  (batched in groups of 1000 to stay under Oracle's `IN`-list limit) — avoiding a full V$SQL cursor-cache scan.
  Ported from upstream `receiver/oracledb` ([#49874](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/49874) /
  [#49875](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/49875)). No config or emitted-field
  changes; sessions whose cursor has aged out of the shared pool are dropped, preserving prior behavior.
