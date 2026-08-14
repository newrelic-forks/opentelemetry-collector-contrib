# MySQL Receiver — End-to-End Reference

Personal reference for `receiver/mysqlreceiver` on the `pre-release` branch of this repo.

## What's inside

New Relic's fork, `receiver/nrmysqlreceiver`, adds 13 custom attributes across `db.server.top_query`
/ `db.server.query_sample` beyond what's documented here for upstream `receiver/mysqlreceiver` — see
[mysql-metrics-by-category.md](./mysql-metrics-by-category.md) §2/§3 for the full marked list.

| File | Focus |
|---|---|
| [mysql-metrics-by-category.md](./mysql-metrics-by-category.md) | Every metric, event, and attribute the receiver emits, grouped by operational question (query throughput, wait analysis, sessions, execution plans, InnoDB, locking, etc.) |
| [queries-executed.md](./queries-executed.md) | How many SQL queries the receiver runs to collect everything (13 statement types; 8 fixed per metrics scrape), when each runs, how to tune query load, and (§7) what you get with vs without `performance_schema`. |
| [core-metrics-cardinality.md](./core-metrics-cardinality.md) | Per-metric attribute count and time-series cardinality; §6 is the full 48-metric catalog ordered by cardinality for dashboard planning. |
| [01-architecture.md](./01-architecture.md) | Supplemental: factory → client → scraper → emitter lifecycle inside the receiver code. Useful when reading the source. |
| [server-address-port-entity-synthesis.md](./server-address-port-entity-synthesis.md) | Why the receiver doesn't emit `server.address`/`server.port` natively, why entity-definitions PR #3104 needs both, and the pipeline-config fix (no receiver code change required). |
| [dashboard-terminology-glossary.md](./dashboard-terminology-glossary.md) | Glossary of every term on the dashboard's Sessions, Clients, and Wait Analysis pages — what a "session" is, connected/running/blocked sessions, execution-count/P95 sampling caveats, and where each widget's number actually comes from (including which widgets source from a metric instead of `db.server.query_sample`, and why the new Wait Analysis (All Waits) page only shows whole-window totals, not trend lines). |
| [dashboard-clean-room-gap-analysis-2026-08-14.md](./dashboard-clean-room-gap-analysis-2026-08-14.md) | Discrepancies found between the Confluence spec / local docs and `receiver/nrmysqlreceiver` source while independently re-deriving a 6-page, 86-widget dashboard's NRQL straight from code. |

## Receiver config that emits everything

`db-test-lab/collectors/configs/receivers/mysql.yaml` — already at maximum for the upstream `mysqlreceiver`:

- 48/48 metrics enabled (25 default-on + 23 default-off)
- Both `db.server.*` events enabled (`query_sample`, `top_query` — both default-off)
- `mysql.instance.endpoint` resource attribute declared explicitly
- Statement-events / top-query / query-sample knobs pushed above upstream defaults (digest_text_limit 4096, statement limit 500, plan cache 1000 entries / 1 h TTL, sample rows 100)

## Quick-jump

| I want to know… | Go to |
|---|---|
| Which specific queries are slowest | `mysql-metrics-by-category.md` § 2 (Query details and top queries) |
| What sessions are executing right now and where each is stuck | § 3 (Live query samples) |
| Why a query is slow — see the EXPLAIN plan | § 4 (Execution plans) |
| Are we blocked on locks or IO | § 5 (Wait-time analysis) + § 7 (Locking) |
| How many connections and threads are open | § 6 (Sessions, threads, connections) |
| Is the buffer pool big enough for the working set | § 8 (InnoDB buffer pool and IO) |
| How many rows are being read vs updated | § 9 (Row and page operations) |
| How big is each table | § 10 (Table and schema volume) |
| Is the replica falling behind | § 11 (Replication) |
| What isn't available from this receiver | `mysql-metrics-by-category.md` — final section (What NOT to expect) |
| How many SQL queries the receiver runs (and how to tune load) | `queries-executed.md` |
| What works with vs without `performance_schema` enabled | `queries-executed.md` § 7 |
| How the receiver code itself is wired | `01-architecture.md` |
