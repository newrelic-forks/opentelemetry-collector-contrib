# MySQL clean-room dashboard — design spec

**Date:** 2026-08-14
**Status:** Approved by user, pending implementation plan

## Goal

Build a brand-new, third New Relic dashboard for `nrmysqlreceiver` query-performance
monitoring in the staging Database Team account (754495), derived independently from the
receiver's own source code — not by copying or extending either of the two dashboards that
already exist in that account.

## Explicit constraints

- **Do not touch either existing dashboard.** Read-only reference only, and only where
  explicitly needed for NRQL *syntax* conventions (not attribute content):
  - `NzU0NDk1fFZJWnxEQVNIQk9BUkR8ZGE6MTE3OTczMw` (primary, `staging.onenr.io/02wdvl2PojE`)
  - `NzU0NDk1fFZJWnxEQVNIQk9BUkR8ZGE6MTE4MDI2OA` (older snapshot, `staging.onenr.io/08jqW7epvwl`)
- **Code is the source of truth**, always, over the Confluence spec
  (`https://newrelic.atlassian.net/wiki/x/UoIuWQE`) and over the local reference docs in
  `docs/mysql-receiver/*.md`. Every widget's NRQL must be independently re-derived from
  `receiver/nrmysqlreceiver/metadata.yaml`, `client.go`, `scraper.go`, `templates/*.tmpl` — not
  copied from either doc source or from the existing dashboards' queries.
- No trace pipeline exists (`factory.go` registers only `WithMetrics`/`WithLogs`) — scope is
  metrics + logs only, confirmed by code read.
- Target account/credentials: `db-test-lab-nrmysql/.env` (`NEW_RELIC_ACCOUNT_ID=754495`,
  `NEW_RELIC_REGION=staging`, `NEW_RELIC_API_KEY` — a User API key).

## Confirmed telemetry inventory (clean-room, from `metadata.yaml` + code)

- **48 metrics** (`FROM Metric`), all `sum` type, all `aggregation_temporality: cumulative`.
  Category mapping cross-checked against the Confluence spec's §6.1–6.11 taxonomy and confirmed
  accurate (no drift found on the metrics side).
- **2 log events** (`FROM Log`, `event.name` in `db.server.query_sample` /
  `db.server.top_query`), both disabled by default. `db.server.query_sample` carries 27
  attributes including session identity, wait/blocking state, and APM-correlation fields.
  `db.server.top_query` carries 13 attributes including digest identity and per-digest
  execution/row deltas.
- Resource attributes: only `mysql.instance.endpoint` is actually set by the receiver itself
  (`service.instance.id`/`service.name`/`db.system.name`/`db.system.version` exist in
  `metadata.yaml` but are `enabled: false` by default and not receiver-populated).

## Confirmed spec-vs-code discrepancies (preliminary — finalized as Deliverable 1)

1. Confluence §7.1 documents `mysql.blocking.blocker.thread_id` / `.session_id` as live NR-fork
   attributes. Both are **retired in code** (commit `44776db2ea`) and no longer emitted. Code now
   emits `mysql.blocking.blockers` (JSON array of `{thread_id, session_id}` tuples) and
   `mysql.blocking.blocker.count` (int) instead — neither is mentioned anywhere in the spec.
2. `mysql.wait_event` / `mysql.wait_event_type` are emitted by code on `db.server.query_sample`
   (confirmed absent from upstream `receiver/mysqlreceiver/metadata.yaml`, so they're NR-fork
   additions) but are **not documented anywhere** in the spec — not as baseline, not as
   fork-only.
3. The spec's "13 fork-only attributes" count (§7, NR fork note) is stale: 2 of the 13 are
   retired, and at least 2 fork-only attributes emitted by current code are missing from the
   count entirely.

This list will be finalized (and cross-checked against `docs/mysql-receiver/*.md` for
Deliverable 2) while building each dashboard page, since widget construction requires reading
the same code paths anyway.

## Page architecture — operational-concern grouping

Chosen over telemetry-type grouping (mirrors spec's §6.1–11 almost 1:1, fragments correlated
widgets across pages) and persona grouping (too few pages, each a grab-bag) — see conversation
for full tradeoff discussion. Six pages, each with markdown-header sections:

1. **Overview & Instance Health** — At a Glance (billboards: uptime, connections, threads, QPS,
   slow queries, buffer pool usage %) · Connections & Threads · Command Mix & Throughput ·
   Replication Health
2. **Query Performance (Top Queries)** — Top Queries by Load (`db.server.top_query`) · Query
   Efficiency (rows examined vs. sent) · Digest Metrics Correlation
   (`mysql.statement_event.*`, flagged disabled-by-default)
3. **Live Sessions & Query Samples** — Currently Running Queries (`db.server.query_sample`) ·
   Session Status Breakdown · Client & Driver Identity
4. **Wait & Blocking Analysis** — Wait Event Breakdown (`mysql.wait_event`/`wait_event_type`) ·
   Blocking Chains (`mysql.blocking.blockers`/`.count`) · InnoDB & Table-Level Locking
5. **Execution Plans** — Plan Viewer (raw `mysql.query_plan` EXPLAIN JSON, filtered by
   `{{queryHash}}`) · Plan Availability & Coverage (% rows with non-empty plan) · markdown
   callout on the `query_plan.hash == digest` limitation (§7.5)
6. **Storage Engine & Capacity** — InnoDB Buffer Pool · Data/Page Operations & I/O Waits ·
   Caches & Temp Resources · Table & Schema Volume

## NRQL conventions

- Metrics: `` FROM Metric WHERE `metricName` = 'mysql.x' `` with cumulative counters computed as
  a `latest() - earliest()` delta subquery (per `aggregation_temporality: cumulative` in
  `metadata.yaml`). Dimension attributes referenced by their `name_override` value (e.g. `kind`,
  `schema`, `table`, `index`), not the raw attribute key.
- Logs: `` FROM Log WHERE `event.name` = 'db.server.top_query' AND `db.system.name` = 'mysql' ``,
  dotted attribute names backtick-quoted.
- Two dashboard-wide template variables:
  - `{{endpoint}}` → `mysql.instance.endpoint`, applied globally (account has multiple test
    MySQL entities sharing metric names).
  - `{{queryHash}}` → `db.query.text.normalized.hash`, applied on Page 5 for drill-down from a
    top query into its execution plan.
- Validate each widget's NRQL against live data before finalizing — in particular, confirm
  `mysql.instance.endpoint` (a resource attribute) actually resolves on `Log` records the same
  way it does on `Metric` records; adjust filtering if it doesn't.

## Deployment mechanics

- `dashboardCreate` NerdGraph mutation via direct `curl` to
  `https://staging-api.newrelic.com/graphql`, authenticated with `NEW_RELIC_API_KEY` from
  `db-test-lab-nrmysql/.env` — same proven path used for the two existing dashboards after the
  MCP tool's OAuth path hit `FORBIDDEN_OPERATION` on this account (see
  `project_mysql_dashboard_write_api_blocked` memory).
- Dashboard title: "MySQL Query Performance Monitoring — nrmysqlreceiver (clean-room)".
- After creation, confirm live by reading each page back (same verification discipline as the
  prior dashboard work) before reporting the URL as done.

## Deliverables

1. **This design spec** (self-reviewed, committed).
2. **`docs/mysql-receiver/dashboard-clean-room-gap-analysis-2026-08-14.md`** — one file, two
   sections:
   - §1: finalized Confluence-spec-vs-code discrepancy list (builds on the preliminary list
     above).
   - §2: local `docs/mysql-receiver/*.md` docs vs. code — gaps found incidentally while building
     widgets from raw source, without consulting those docs for attribute content.
4. **The live dashboard** in staging account 754495, plus its GUID and
   `https://staging.onenr.io/...` URL.
5. An implementation plan (via `writing-plans`) covering: per-page NRQL authoring, the NerdGraph
   payload assembly, the curl-based create + verify sequence, and the two gap docs.

## Out of scope

- No changes to either existing dashboard.
- No changes to receiver code, `metadata.yaml`, or the Confluence page itself — this task is
  read/analyze/build-new only.
