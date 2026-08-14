# MySQL Clean-Room Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and deploy a new, independently-derived New Relic dashboard for `nrmysqlreceiver` in staging account 754495 (6 pages, ~80 widgets), plus a gap-analysis doc covering Confluence-spec-vs-code and local-docs-vs-code drift discovered along the way.

**Architecture:** Author each dashboard page as a JSON widget array in its own file (clean-room NRQL, derived from `metadata.yaml`/`client.go`/`scraper.go` only), validate every widget's NRQL live via `curl` against the staging NerdGraph API, then assemble all six pages into one `dashboardCreate` mutation and deploy. No changes to receiver code or either pre-existing dashboard.

**Tech Stack:** NerdGraph (New Relic GraphQL API) via `curl` + `jq`, NRQL, bash.

**Spec:** `docs/superpowers/specs/2026-08-14-mysql-clean-room-dashboard-design.md`

## Global Constraints

- Account: **754495** (staging). Region: staging (`staging-api.newrelic.com` for NerdGraph, not the production API host).
- Credentials: source `/Users/atiwari/Desktop/Projects/db-test-lab-nrmysql/.env` for `NEW_RELIC_API_KEY` and `NEW_RELIC_ACCOUNT_ID` — never hardcode the key value into any committed file.
- **Never modify** the two existing dashboards (`NzU0NDk1fFZJWnxEQVNIQk9BUkR8ZGE6MTE3OTczMw`, `NzU0NDk1fFZJWnxEQVNIQk9BUkR8ZGE6MTE4MDI2OA`). Read-only reference only, for NRQL syntax mechanics, never for attribute content.
- Every widget's NRQL is derived from `receiver/nrmysqlreceiver/metadata.yaml` / `client.go` / `scraper.go` / `templates/*.tmpl` directly — not copied from the Confluence spec, not copied from `docs/mysql-receiver/*.md`, not copied from the two existing dashboards.
- Dashboard title: `MySQL Query Performance Monitoring — nrmysqlreceiver (clean-room)`.
- ~~Two dashboard-wide variables: `{{endpoint}}` → `mysql.instance.endpoint` (global), `{{queryHash}}` → `db.query.text.normalized.hash` (Page 5 only, per NerdGraph's per-widget variable scoping — see Task 8).~~ **Superseded by Part 2 below**, per user feedback after reviewing the live dashboard: both variables are removed; every widget that filtered by one now uses FACET-based breakdown instead. See Part 2's Global Constraints.
- Confirmed live (via `db-test-lab-nrmysql/collectors/configs/receivers/mysql.yaml`): two MySQL instances monitored (`nrmysql`, `nrmysql/db2`), all 48 metrics enabled, both log events enabled, `resource/mysql` processor adds `server.address`/`server.port` to **both** the `metrics/mysql` and `logs/mysql` pipelines — so `mysql.instance.endpoint` (receiver-native) is expected to resolve on `Log` records the same as on `Metric` records. Neither instance is configured as a replica and X-Plugin (`mysqlx_*`) is not in use — replication and mysqlx widgets are expected to return empty by design, not a bug.

## Widget JSON shape (used by every page task)

Metric widget:
```json
{
  "title": "<Title>",
  "layout": {"column": <c>, "row": <r>, "width": <w>, "height": <h>},
  "visualization": {"id": "<viz.billboard|viz.line|viz.bar|viz.pie|viz.table>"},
  "rawConfiguration": {
    "nrqlQueries": [
      {"accountId": 754495, "query": "<NRQL>"}
    ]
  }
}
```

Markdown section header/divider:
```json
{
  "title": "",
  "layout": {"column": 1, "row": <r>, "width": 12, "height": 1},
  "visualization": {"id": "viz.markdown"},
  "rawConfiguration": {"text": "<markdown text>"}
}
```

## Layout algorithm (used by every page task)

12-column grid. Process each page's widget table top-to-bottom, maintaining a `row` cursor starting at 1:

1. A markdown widget always starts a fresh row at full width (`column:1, width:12, height:1`); after placing it, `row += 1`.
2. Billboards: width 3, height 3, up to 4 per row (columns 1, 4, 7, 10). After the 4th billboard (or when the section's billboard run ends), `row += 3`.
3. Line/Bar/Pie charts: width 4, height 3, up to 3 per row (columns 1, 5, 9). After the 3rd chart (or when the run ends), `row += 3`.
4. Tables: width 12, height 4 (full width) unless the plan explicitly pairs two tables side by side (width 6 each). After the row, `row += 4`.

Reset nothing between sections — the row cursor is cumulative down the whole page.

---

### Task 1: Environment smoke test

**Files:**
- Create: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/lib.sh`

**Interfaces:**
- Produces: `lib.sh`, sourced by every later task's validation/deploy scripts. Defines `nrgraphql <json-body-file>` — a bash function that sources `.env`, POSTs the given JSON body file to the staging NerdGraph endpoint with the API key header, and prints the raw response.

- [ ] **Step 1: Write `lib.sh`**

```bash
#!/usr/bin/env bash
# Shared NerdGraph helper for the clean-room MySQL dashboard build.
set -euo pipefail

ENV_FILE="/Users/atiwari/Desktop/Projects/db-test-lab-nrmysql/.env"
NERDGRAPH_URL="https://staging-api.newrelic.com/graphql"

nrgraphql() {
  local body_file="$1"
  set -a; source "$ENV_FILE"; set +a
  curl -s "$NERDGRAPH_URL" \
    -H "Content-Type: application/json" \
    -H "API-Key: ${NEW_RELIC_API_KEY}" \
    -d @"$body_file"
}
```

- [ ] **Step 2: Verify the API key authenticates**

```bash
chmod +x docs/mysql-receiver/scripts/mysql-clean-room-dashboard/lib.sh
source docs/mysql-receiver/scripts/mysql-clean-room-dashboard/lib.sh
echo '{"query": "{ actor { user { email } } } "}' > /tmp/whoami.json
nrgraphql /tmp/whoami.json
```
Expected: JSON body containing `data.actor.user.email` with no `errors` array. If you get an auth error, re-check `NEW_RELIC_API_KEY` in the `.env` file — do not proceed until this passes.

- [ ] **Step 3: Verify account 754495 is reachable and matches the target**

```bash
echo '{"query": "{ actor { account(id: 754495) { name } } }"}' > /tmp/account.json
nrgraphql /tmp/account.json
```
Expected: `data.actor.account.name` present, no errors.

- [ ] **Step 4: Verify live telemetry exists for both monitored instances**

```bash
cat > /tmp/endpoints.json <<'EOF'
{"query": "{ actor { account(id: 754495) { nrql(query: \"FROM Metric SELECT uniques(`mysql.instance.endpoint`) SINCE 1 hour ago\") { results } } } } "}
EOF
nrgraphql /tmp/endpoints.json
```
Expected: `data.actor.account.nrql.results` contains a list with (at least) two distinct `host:port` strings, matching the two `nrmysql` / `nrmysql/db2` instances in `db-test-lab-nrmysql/collectors/configs/receivers/mysql.yaml`. Write down these two exact endpoint strings — Task 8 needs one as the `{{endpoint}}` variable's default value.

- [ ] **Step 5: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/lib.sh
git commit -m "$(cat <<'EOF'
chore: [docs/mysql-receiver] add NerdGraph helper for clean-room dashboard build

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 2: Page 1 — Overview & Instance Health

**Files:**
- Create: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-1-overview.json`

**Interfaces:**
- Consumes: `nrgraphql()` from Task 1's `lib.sh`.
- Produces: `page-1-overview.json` — a JSON array of widget objects (shape defined in Global Constraints above), consumed by Task 8's assembly step.

- [ ] **Step 1: Write the widget table, then translate it into `page-1-overview.json` using the layout algorithm**

| # | Title | Viz | NRQL |
|---|---|---|---|
| 1 | (markdown) | markdown | `## Overview & Instance Health\nAt-a-glance status of the MySQL instance selected via the endpoint variable above.` |
| 2 | Uptime (s) | billboard | `` FROM Metric SELECT latest(`mysql.uptime`) WHERE `metricName` = 'mysql.uptime' AND `mysql.instance.endpoint` = {{endpoint}} `` |
| 3 | Active connections | billboard | `` FROM Metric SELECT latest(`mysql.threads`) WHERE `metricName` = 'mysql.threads' AND kind = 'connected' AND `mysql.instance.endpoint` = {{endpoint}} `` |
| 4 | Threads running | billboard | `` FROM Metric SELECT latest(`mysql.threads`) WHERE `metricName` = 'mysql.threads' AND kind = 'running' AND `mysql.instance.endpoint` = {{endpoint}} `` |
| 5 | Queries/min | billboard | `` FROM Metric SELECT derivative(sum(`mysql.query.count`), 1 minute) WHERE `metricName` = 'mysql.query.count' AND `mysql.instance.endpoint` = {{endpoint}} `` |
| 6 | Slow queries (cumulative) | billboard | `` FROM Metric SELECT latest(`mysql.query.slow.count`) WHERE `metricName` = 'mysql.query.slow.count' AND `mysql.instance.endpoint` = {{endpoint}} `` |
| 7 | Buffer pool usage (bytes) | billboard | `` FROM Metric SELECT sum(`mysql.buffer_pool.usage`) WHERE `metricName` = 'mysql.buffer_pool.usage' AND `mysql.instance.endpoint` = {{endpoint}} `` |
| 8 | (markdown) | markdown | `### Connections & Threads` |
| 9 | Threads by kind | line | `` FROM Metric SELECT latest(`mysql.threads`) WHERE `metricName` = 'mysql.threads' AND `mysql.instance.endpoint` = {{endpoint}} FACET kind TIMESERIES `` |
| 10 | Connection errors by type | line | `` FROM Metric SELECT latest(`mysql.connection.errors`) WHERE `metricName` = 'mysql.connection.errors' AND `mysql.instance.endpoint` = {{endpoint}} FACET error TIMESERIES `` |
| 11 | Max used connections | billboard | `` FROM Metric SELECT latest(`mysql.max_used_connections`) WHERE `metricName` = 'mysql.max_used_connections' AND `mysql.instance.endpoint` = {{endpoint}} `` |
| 12 | X-Protocol connections (expected empty — X-Plugin not in use) | table | `` FROM Metric SELECT latest(`mysql.mysqlx_connections`) AS 'Connections' WHERE `metricName` = 'mysql.mysqlx_connections' AND `mysql.instance.endpoint` = {{endpoint}} FACET status `` |
| 13 | (markdown) | markdown | `### Command Mix & Throughput` |
| 14 | Command mix | bar | `` FROM Metric SELECT latest(`mysql.commands`) WHERE `metricName` = 'mysql.commands' AND `mysql.instance.endpoint` = {{endpoint}} FACET command `` |
| 15 | Query count vs. client-issued query count | line | `` FROM Metric SELECT derivative(sum(`mysql.query.count`), 1 minute) AS 'Total queries/min', derivative(sum(`mysql.query.client.count`), 1 minute) AS 'Client queries/min' WHERE (`metricName` = 'mysql.query.count' OR `metricName` = 'mysql.query.client.count') AND `mysql.instance.endpoint` = {{endpoint}} TIMESERIES `` |
| 16 | Handlers by type | bar | `` FROM Metric SELECT latest(`mysql.handlers`) WHERE `metricName` = 'mysql.handlers' AND `mysql.instance.endpoint` = {{endpoint}} FACET kind `` |
| 17 | Joins requiring full scans | bar | `` FROM Metric SELECT latest(`mysql.joins`) WHERE `metricName` = 'mysql.joins' AND `mysql.instance.endpoint` = {{endpoint}} FACET kind `` |
| 18 | Sorts by type | bar | `` FROM Metric SELECT latest(`mysql.sorts`) WHERE `metricName` = 'mysql.sorts' AND `mysql.instance.endpoint` = {{endpoint}} FACET kind `` |
| 19 | Prepared statement commands | bar | `` FROM Metric SELECT latest(`mysql.prepared_statements`) WHERE `metricName` = 'mysql.prepared_statements' AND `mysql.instance.endpoint` = {{endpoint}} FACET command `` |
| 20 | (markdown) | markdown | `### Replication Health\nOnly populated if this instance is configured as a replica — expected empty in this test lab (both instances are standalone).` |
| 21 | Seconds behind source | billboard | `` FROM Metric SELECT latest(`mysql.replica.time_behind_source`) WHERE `metricName` = 'mysql.replica.time_behind_source' AND `mysql.instance.endpoint` = {{endpoint}} `` |
| 22 | SQL delay (s) | billboard | `` FROM Metric SELECT latest(`mysql.replica.sql_delay`) WHERE `metricName` = 'mysql.replica.sql_delay' AND `mysql.instance.endpoint` = {{endpoint}} `` |

For validation purposes (Step 2), every `{{endpoint}}` placeholder in the query text must be temporarily substituted with the literal endpoint string you recorded in Task 1 Step 4 (e.g. `'atiwari-mysql:3306'`) — the `{{endpoint}}` token only resolves inside a real dashboard variable context, not in a raw NRQL-over-NerdGraph call.

- [ ] **Step 2: Validate every non-markdown widget's query live**

```bash
source docs/mysql-receiver/scripts/mysql-clean-room-dashboard/lib.sh
# Repeat for each widget query above with {{endpoint}} substituted:
cat > /tmp/q.json <<EOF
{"query": "{ actor { account(id: 754495) { nrql(query: \"<NRQL with endpoint substituted, backslash-escaped>\") { results } } } } "}
EOF
nrgraphql /tmp/q.json
```
For each: confirm `errors` is absent/null. Confirm `results` is non-empty for every widget EXCEPT #12 (mysqlx), #21, #22 (replication) — those are expected empty per Global Constraints. If widget #15's combined two-metricName query errors or returns nonsensical values, split it into two separate `derivative()` billboards instead (one per metric) and note the change.

- [ ] **Step 3: Write `page-1-overview.json`**

Translate the validated widget table into the JSON shape from Global Constraints, applying the layout algorithm. Save as `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-1-overview.json`, with the page wrapped as:
```json
{"name": "Overview & Instance Health", "description": "", "widgets": [ /* the 22 widgets */ ]}
```

- [ ] **Step 4: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-1-overview.json
git commit -m "$(cat <<'EOF'
docs: [mysql-receiver] author + validate clean-room dashboard page 1 (Overview)

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 3: Page 2 — Query Performance (Top Queries)

**Files:**
- Create: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-2-top-queries.json`

**Interfaces:**
- Consumes: `nrgraphql()` from Task 1.
- Produces: `page-2-top-queries.json`, consumed by Task 8.

- [ ] **Step 1: Write the widget table, then translate into JSON**

| # | Title | Viz | NRQL |
|---|---|---|---|
| 1 | (markdown) | markdown | `## Query Performance (Top Queries)\nAggregated view from db.server.top_query — disabled by default upstream; enabled in this test lab's receiver config.` |
| 2 | Top queries by total wait time | table | `` FROM Log SELECT latest(`db.query.text`) AS 'Query', filter(sum(`mysql.events_statements_summary_by_digest.count_star`), WHERE `mysql.events_statements_summary_by_digest.count_star` >= 0) AS 'Executions (delta)', filter(sum(`mysql.events_statements_summary_by_digest.sum_timer_wait`), WHERE `mysql.events_statements_summary_by_digest.sum_timer_wait` >= 0) AS 'Total wait (s, delta)' WHERE `event.name` = 'db.server.top_query' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} FACET `mysql.events_statements_summary_by_digest.digest` AS 'Digest' LIMIT 25 `` |
| 3 | Top 10 queries by total wait time | bar | `` FROM Log SELECT sum(`mysql.events_statements_summary_by_digest.sum_timer_wait`) WHERE `event.name` = 'db.server.top_query' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} FACET `mysql.events_statements_summary_by_digest.digest` LIMIT 10 `` |
| 4 | (markdown) | markdown | `### Query Efficiency — Rows Examined vs. Sent` |
| 5 | Rows examined vs. sent by query | table | `` FROM Log SELECT latest(`db.query.text`) AS 'Query', sum(`mysql.events_statements_summary_by_digest.sum_rows_examined`) AS 'Rows examined', sum(`mysql.events_statements_summary_by_digest.sum_rows_sent`) AS 'Rows sent' WHERE `event.name` = 'db.server.top_query' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} FACET `mysql.events_statements_summary_by_digest.digest` AS 'Digest' ORDER BY `Rows examined` DESC LIMIT 25 `` |
| 6 | Worst selectivity (rows examined per row sent) | bar | `` FROM Log SELECT sum(`mysql.events_statements_summary_by_digest.sum_rows_examined`)/filter(sum(`mysql.events_statements_summary_by_digest.sum_rows_sent`), WHERE `mysql.events_statements_summary_by_digest.sum_rows_sent` > 0) AS 'Rows examined per row sent' WHERE `event.name` = 'db.server.top_query' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} FACET `mysql.events_statements_summary_by_digest.digest` LIMIT 10 `` |
| 7 | (markdown) | markdown | `### Digest Metrics Correlation\nmysql.statement_event.* metrics are disabled by default upstream; enabled in this test lab.` |
| 8 | Statement event counts by digest (metric) | table | `` FROM Metric SELECT latest(`mysql.statement_event.count`) WHERE `metricName` = 'mysql.statement_event.count' AND `mysql.instance.endpoint` = {{endpoint}} FACET digest_text AS 'Query text', event_state LIMIT 25 `` |
| 9 | Statement event wait time by digest (metric) | line | `` FROM Metric SELECT latest(`mysql.statement_event.wait.time`) WHERE `metricName` = 'mysql.statement_event.wait.time' AND `mysql.instance.endpoint` = {{endpoint}} FACET digest_text TIMESERIES LIMIT 10 `` |

- [ ] **Step 2: Validate every non-markdown widget's query live** (same substitution procedure as Task 2 Step 2). If widgets 2/5/8/9 return zero results, check first whether `db.server.top_query` has any rows at all in the window: `FROM Log SELECT count(*) WHERE event.name = 'db.server.top_query' AND mysql.instance.endpoint = '<literal>'` — widen the time window (`SINCE 1 hour ago`) before concluding a query is wrong.

- [ ] **Step 3: Write `page-2-top-queries.json`** wrapped as `{"name": "Query Performance (Top Queries)", "description": "", "widgets": [...]}`.

- [ ] **Step 4: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-2-top-queries.json
git commit -m "$(cat <<'EOF'
docs: [mysql-receiver] author + validate clean-room dashboard page 2 (Top Queries)

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 4: Page 3 — Live Sessions & Query Samples

**Files:**
- Create: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-3-live-sessions.json`

**Interfaces:**
- Consumes: `nrgraphql()` from Task 1.
- Produces: `page-3-live-sessions.json`, consumed by Task 8.

- [ ] **Step 1: Write the widget table, then translate into JSON**

| # | Title | Viz | NRQL |
|---|---|---|---|
| 1 | (markdown) | markdown | `## Live Sessions & Query Samples\nReal-time snapshot from db.server.query_sample, refreshed on the metrics collection_interval.` |
| 2 | Currently running queries | table | `` FROM Log SELECT latest(`mysql.threads.thread_id`) AS 'Thread', latest(`mysql.session.id`) AS 'Session', latest(`user.name`) AS 'DB user', latest(`db.namespace`) AS 'Database', latest(`db.query.text`) AS 'Query', latest(`mysql.threads.processlist_state`) AS 'State', latest(`mysql.events_statements_current.timer_wait`) AS 'Elapsed (s)' WHERE `event.name` = 'db.server.query_sample' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} FACET `mysql.event_id` LIMIT 100 `` |
| 3 | (markdown) | markdown | `### Session Status Breakdown` |
| 4 | Sessions by status | pie | `` FROM Log SELECT uniqueCount(tuple(`mysql.threads.thread_id`, `mysql.session.id`)) WHERE `event.name` = 'db.server.query_sample' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} FACET `mysql.session.status` `` |
| 5 | Session status trend | line | `` FROM Log SELECT uniqueCount(tuple(`mysql.threads.thread_id`, `mysql.session.id`)) WHERE `event.name` = 'db.server.query_sample' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} FACET `mysql.session.status` TIMESERIES `` |
| 6 | (markdown) | markdown | `### Client & Driver Identity` |
| 7 | Connections by client driver | table | `` FROM Log SELECT uniqueCount(tuple(`mysql.threads.thread_id`, `mysql.session.id`)) AS 'Sessions' WHERE `event.name` = 'db.server.query_sample' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} FACET `mysql.session.client_name`, `client.address` LIMIT 50 `` |
| 8 | APM-correlated sessions | table | `` FROM Log SELECT latest(`db.query.text`) AS 'Query', latest(`db.query.comment_tags.nr_service_guid`) AS 'APM service GUID' WHERE `event.name` = 'db.server.query_sample' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} AND `db.query.comment_tags.nr_service_guid` IS NOT NULL AND `db.query.comment_tags.nr_service_guid` != '' FACET `mysql.event_id` LIMIT 50 `` |

- [ ] **Step 2: Validate every non-markdown widget's query live.** Widget 8 is expected empty unless a test workload is currently issuing APM-tagged queries with `nr_service_guid` in a leading SQL comment — do not treat an empty result as a bug without first confirming no such workload is running.

- [ ] **Step 3: Write `page-3-live-sessions.json`** wrapped as `{"name": "Live Sessions & Query Samples", "description": "", "widgets": [...]}`.

- [ ] **Step 4: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-3-live-sessions.json
git commit -m "$(cat <<'EOF'
docs: [mysql-receiver] author + validate clean-room dashboard page 3 (Live Sessions)

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 5: Page 4 — Wait & Blocking Analysis

**Files:**
- Create: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-4-wait-blocking.json`

**Interfaces:**
- Consumes: `nrgraphql()` from Task 1.
- Produces: `page-4-wait-blocking.json`, consumed by Task 8.

- [ ] **Step 1: Write the widget table, then translate into JSON**

| # | Title | Viz | NRQL |
|---|---|---|---|
| 1 | (markdown) | markdown | `## Wait & Blocking Analysis` |
| 2 | Wait events by top-level classification | bar | `` FROM Log SELECT count(*) WHERE `event.name` = 'db.server.query_sample' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} AND `mysql.session.status` = 'waiting' FACET `mysql.wait_event_type` `` |
| 3 | Wait event detail | table | `` FROM Log SELECT count(*) AS 'Occurrences', average(`mysql.events_waits_current.timer_wait`) AS 'Avg wait (s)' WHERE `event.name` = 'db.server.query_sample' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} AND `mysql.session.status` = 'waiting' FACET `mysql.wait_event_type`, `mysql.wait_event` LIMIT 50 `` |
| 4 | (markdown) | markdown | `### Blocking Chains` |
| 5 | Sessions currently blocked | billboard | `` FROM Log SELECT uniqueCount(tuple(`mysql.threads.thread_id`, `mysql.session.id`)) WHERE `event.name` = 'db.server.query_sample' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} AND `mysql.blocking.blocker.count` > 0 `` |
| 6 | Blocked session detail | table | `` FROM Log SELECT latest(`mysql.blocking.blockers`) AS 'Blocked by (sessions)', latest(`user.name`) AS 'DB user', latest(`db.namespace`) AS 'Database', latest(`db.query.text`) AS 'Waiting query', latest(`mysql.events_statements_current.timer_wait`) AS 'Elapsed (s)' WHERE `event.name` = 'db.server.query_sample' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} AND `mysql.blocking.blocker.count` > 0 FACET `mysql.threads.thread_id` AS 'Thread', `mysql.session.id` AS 'Session' LIMIT 100 `` |
| 7 | Blocked session count trend | line | `` FROM Log SELECT uniqueCount(tuple(`mysql.threads.thread_id`, `mysql.session.id`)) WHERE `event.name` = 'db.server.query_sample' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} AND `mysql.blocking.blocker.count` > 0 TIMESERIES `` |
| 8 | (markdown) | markdown | `### InnoDB & Table-Level Locking (metrics)` |
| 9 | Table locks — immediate vs. waited | line | `` FROM Metric SELECT latest(`mysql.locks`) WHERE `metricName` = 'mysql.locks' AND `mysql.instance.endpoint` = {{endpoint}} FACET kind TIMESERIES `` |
| 10 | Row locks — waits vs. time | line | `` FROM Metric SELECT latest(`mysql.row_locks`) WHERE `metricName` = 'mysql.row_locks' AND `mysql.instance.endpoint` = {{endpoint}} FACET kind TIMESERIES `` |
| 11 | Top tables by read lock wait time | table | `` FROM Metric SELECT latest(`mysql.table.lock_wait.read.time`) WHERE `metricName` = 'mysql.table.lock_wait.read.time' AND `mysql.instance.endpoint` = {{endpoint}} FACET schema, table LIMIT 25 `` |
| 12 | Top tables by write lock wait time | table | `` FROM Metric SELECT latest(`mysql.table.lock_wait.write.time`) WHERE `metricName` = 'mysql.table.lock_wait.write.time' AND `mysql.instance.endpoint` = {{endpoint}} FACET schema, table LIMIT 25 `` |
| 13 | Top tables by read lock wait count | table | `` FROM Metric SELECT latest(`mysql.table.lock_wait.read.count`) WHERE `metricName` = 'mysql.table.lock_wait.read.count' AND `mysql.instance.endpoint` = {{endpoint}} FACET schema, table LIMIT 25 `` |
| 14 | Top tables by write lock wait count | table | `` FROM Metric SELECT latest(`mysql.table.lock_wait.write.count`) WHERE `metricName` = 'mysql.table.lock_wait.write.count' AND `mysql.instance.endpoint` = {{endpoint}} FACET schema, table LIMIT 25 `` |

This page has 14 widget-table rows (3 markdown + 11 real widgets) — covers all 6 metrics in the
spec's §6.6 Locking category (`locks`, `row_locks`, both `table.lock_wait.read.*`, both
`table.lock_wait.write.*`), plus the log-based wait/blocking widgets.

- [ ] **Step 2: Validate every non-markdown widget's query live.** Widgets 2/3/5/6/7 will legitimately return empty unless a test workload is actively holding/waiting on a lock at query time — before treating an empty result as a bug, either check for a currently-blocked session with `FROM Log SELECT count(*) WHERE event.name = 'db.server.query_sample' AND mysql.blocking.blocker.count > 0 SINCE 1 hour ago`, or drive a manual lock-contention scenario against the test-lab MySQL instance to produce real data, then re-check.

- [ ] **Step 3: Write `page-4-wait-blocking.json`** wrapped as `{"name": "Wait & Blocking Analysis", "description": "", "widgets": [...]}`.

- [ ] **Step 4: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-4-wait-blocking.json
git commit -m "$(cat <<'EOF'
docs: [mysql-receiver] author + validate clean-room dashboard page 4 (Wait & Blocking)

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 6: Page 5 — Execution Plans

**Files:**
- Create: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-5-execution-plans.json`

**Interfaces:**
- Consumes: `nrgraphql()` from Task 1.
- Produces: `page-5-execution-plans.json`, consumed by Task 8.

- [ ] **Step 1: Write the widget table, then translate into JSON**

| # | Title | Viz | NRQL |
|---|---|---|---|
| 1 | (markdown) | markdown | `## Execution Plans\nFilter by a specific query using the queryHash variable above (bound to db.query.text.normalized.hash).` |
| 2 | Query text + plan (query samples) | table | `` FROM Log SELECT latest(`db.query.text`) AS 'Query', latest(`mysql.query_plan`) AS 'Execution plan (raw EXPLAIN JSON)' WHERE `event.name` = 'db.server.query_sample' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} AND `db.query.text.normalized.hash` = {{queryHash}} LIMIT 1 `` |
| 3 | Query text + plan (top queries) | table | `` FROM Log SELECT latest(`db.query.text`) AS 'Query', latest(`mysql.query_plan`) AS 'Execution plan (raw EXPLAIN JSON)' WHERE `event.name` = 'db.server.top_query' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} AND `db.query.text.normalized.hash` = {{queryHash}} LIMIT 1 `` |
| 4 | (markdown) | markdown | `**Note:** mysql.query_plan.hash is set to the same value as the query digest by design — it is not an independently computed structural plan fingerprint. Two executions of the same digest with a different actual execution plan (e.g. after an index change) still report the same mysql.query_plan.hash.` |
| 5 | (markdown) | markdown | `### Plan Availability & Coverage` |
| 6 | Query samples with a plan (%) | billboard | `` FROM Log SELECT filter(count(*), WHERE `mysql.query_plan` IS NOT NULL AND `mysql.query_plan` != '') / count(*) * 100 WHERE `event.name` = 'db.server.query_sample' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} `` |
| 7 | Top queries with a plan (%) | billboard | `` FROM Log SELECT filter(count(*), WHERE `mysql.query_plan` IS NOT NULL AND `mysql.query_plan` != '') / count(*) * 100 WHERE `event.name` = 'db.server.top_query' AND `db.system.name` = 'mysql' AND `mysql.instance.endpoint` = {{endpoint}} `` |

- [ ] **Step 2: Validate.** Widgets 2/3 need a real `db.query.text.normalized.hash` value substituted in place of `{{queryHash}}` for validation — get one via `FROM Log SELECT latest(db.query.text.normalized.hash) WHERE event.name = 'db.server.query_sample' AND mysql.instance.endpoint = '<literal>' SINCE 1 hour ago`, then substitute it into widgets 2/3 (with `{{endpoint}}` also substituted) before running. Widgets 6/7 need only the `{{endpoint}}` substitution.

- [ ] **Step 3: Write `page-5-execution-plans.json`** wrapped as `{"name": "Execution Plans", "description": "", "widgets": [...]}`.

- [ ] **Step 4: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-5-execution-plans.json
git commit -m "$(cat <<'EOF'
docs: [mysql-receiver] author + validate clean-room dashboard page 5 (Execution Plans)

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 7: Page 6 — Storage Engine & Capacity

**Files:**
- Create: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-6-storage-capacity.json`

**Interfaces:**
- Consumes: `nrgraphql()` from Task 1.
- Produces: `page-6-storage-capacity.json`, consumed by Task 8.

- [ ] **Step 1: Write the widget table, then translate into JSON**

| # | Title | Viz | NRQL |
|---|---|---|---|
| 1 | (markdown) | markdown | `## Storage Engine & Capacity` |
| 2 | Buffer pool usage (bytes) by status | line | `` FROM Metric SELECT latest(`mysql.buffer_pool.usage`) WHERE `metricName` = 'mysql.buffer_pool.usage' AND `mysql.instance.endpoint` = {{endpoint}} FACET status TIMESERIES `` |
| 3 | Buffer pool limit (bytes) | billboard | `` FROM Metric SELECT latest(`mysql.buffer_pool.limit`) WHERE `metricName` = 'mysql.buffer_pool.limit' AND `mysql.instance.endpoint` = {{endpoint}} `` |
| 4 | Buffer pool operations | bar | `` FROM Metric SELECT latest(`mysql.buffer_pool.operations`) WHERE `metricName` = 'mysql.buffer_pool.operations' AND `mysql.instance.endpoint` = {{endpoint}} FACET operation `` |
| 5 | Buffer pool pages by kind | line | `` FROM Metric SELECT latest(`mysql.buffer_pool.pages`) WHERE `metricName` = 'mysql.buffer_pool.pages' AND `mysql.instance.endpoint` = {{endpoint}} FACET kind TIMESERIES `` |
| 6 | Buffer pool page flushes (cumulative) | billboard | `` FROM Metric SELECT latest(`mysql.buffer_pool.page_flushes`) WHERE `metricName` = 'mysql.buffer_pool.page_flushes' AND `mysql.instance.endpoint` = {{endpoint}} `` |
| 7 | Buffer pool data pages | billboard | `` FROM Metric SELECT latest(`mysql.buffer_pool.data_pages`) WHERE `metricName` = 'mysql.buffer_pool.data_pages' AND `mysql.instance.endpoint` = {{endpoint}} FACET status `` |
| 8 | InnoDB page size (bytes) | billboard | `` FROM Metric SELECT latest(`mysql.page_size`) WHERE `metricName` = 'mysql.page_size' AND `mysql.instance.endpoint` = {{endpoint}} `` |
| 9 | (markdown) | markdown | `### Data/Page Operations & I/O Waits` |
| 10 | InnoDB operations | bar | `` FROM Metric SELECT latest(`mysql.operations`) WHERE `metricName` = 'mysql.operations' AND `mysql.instance.endpoint` = {{endpoint}} FACET operation `` |
| 11 | InnoDB page operations | bar | `` FROM Metric SELECT latest(`mysql.page_operations`) WHERE `metricName` = 'mysql.page_operations' AND `mysql.instance.endpoint` = {{endpoint}} FACET operation `` |
| 12 | InnoDB row operations | bar | `` FROM Metric SELECT latest(`mysql.row_operations`) WHERE `metricName` = 'mysql.row_operations' AND `mysql.instance.endpoint` = {{endpoint}} FACET operation `` |
| 13 | Double-write buffer activity | bar | `` FROM Metric SELECT latest(`mysql.double_writes`) WHERE `metricName` = 'mysql.double_writes' AND `mysql.instance.endpoint` = {{endpoint}} FACET kind `` |
| 14 | InnoDB log operations | bar | `` FROM Metric SELECT latest(`mysql.log_operations`) WHERE `metricName` = 'mysql.log_operations' AND `mysql.instance.endpoint` = {{endpoint}} FACET operation `` |
| 15 | Top tables by I/O wait time | table | `` FROM Metric SELECT latest(`mysql.table.io.wait.time`) WHERE `metricName` = 'mysql.table.io.wait.time' AND `mysql.instance.endpoint` = {{endpoint}} FACET schema, table, operation LIMIT 25 `` |
| 16 | Top indexes by I/O wait time | table | `` FROM Metric SELECT latest(`mysql.index.io.wait.time`) WHERE `metricName` = 'mysql.index.io.wait.time' AND `mysql.instance.endpoint` = {{endpoint}} FACET schema, table, index, operation LIMIT 25 `` |
| 17 | Top tables by I/O wait count | table | `` FROM Metric SELECT latest(`mysql.table.io.wait.count`) WHERE `metricName` = 'mysql.table.io.wait.count' AND `mysql.instance.endpoint` = {{endpoint}} FACET schema, table, operation LIMIT 25 `` |
| 18 | Top indexes by I/O wait count | table | `` FROM Metric SELECT latest(`mysql.index.io.wait.count`) WHERE `metricName` = 'mysql.index.io.wait.count' AND `mysql.instance.endpoint` = {{endpoint}} FACET schema, table, index, operation LIMIT 25 `` |
| 19 | (markdown) | markdown | `### Caches & Temp Resources` |
| 20 | Table open cache hit/miss/overflow | line | `` FROM Metric SELECT latest(`mysql.table_open_cache`) WHERE `metricName` = 'mysql.table_open_cache' AND `mysql.instance.endpoint` = {{endpoint}} FACET status TIMESERIES `` |
| 21 | Temp resources created | bar | `` FROM Metric SELECT latest(`mysql.tmp_resources`) WHERE `metricName` = 'mysql.tmp_resources' AND `mysql.instance.endpoint` = {{endpoint}} FACET resource `` |
| 22 | Opened resources (cumulative) | billboard | `` FROM Metric SELECT latest(`mysql.opened_resources`) WHERE `metricName` = 'mysql.opened_resources' AND `mysql.instance.endpoint` = {{endpoint}} FACET kind `` |
| 23 | (markdown) | markdown | `### Table & Schema Volume` |
| 24 | Largest tables by size | table | `` FROM Metric SELECT latest(`mysql.table.size`) WHERE `metricName` = 'mysql.table.size' AND `mysql.instance.endpoint` = {{endpoint}} FACET schema, table, kind LIMIT 25 `` |
| 25 | Row counts by table | table | `` FROM Metric SELECT latest(`mysql.table.rows`) WHERE `metricName` = 'mysql.table.rows' AND `mysql.instance.endpoint` = {{endpoint}} FACET schema, table LIMIT 25 `` |
| 26 | Average row length by table | table | `` FROM Metric SELECT latest(`mysql.table.average_row_length`) WHERE `metricName` = 'mysql.table.average_row_length' AND `mysql.instance.endpoint` = {{endpoint}} FACET schema, table LIMIT 25 `` |

This page has 26 widget-table rows (4 markdown + 22 real widgets) — covers all 6 §6.1 InnoDB
Buffer Pool metrics (including `data_pages` and `page_size`, both easy to drop since they don't
share the `buffer_pool.` name prefix with `usage`/`limit`/`operations`/`pages`/`page_flushes`),
all 4 §6.7 Table & Index I/O Wait metrics (both `.count` and `.time` for table and index), all
§6.5 Data/Page Operations, all §6.10 Caches/Temp/Uptime (uptime itself is on Page 1), and all
§6.8 Table Metadata.

- [ ] **Step 2: Validate every non-markdown widget's query live** (same substitution procedure). For widgets 20/21, if you want them explicitly sorted descending, add `` ORDER BY latest(`mysql.table.size`) `` / `` ORDER BY latest(`mysql.table.rows`) `` respectively during validation — confirm the syntax is accepted by the live NRQL parser before locking it into the JSON (NRQL's `ORDER BY` on a `FACET`+aggregate query is valid, but confirm live rather than assuming).

- [ ] **Step 3: Write `page-6-storage-capacity.json`** wrapped as `{"name": "Storage Engine & Capacity", "description": "", "widgets": [...]}`.

- [ ] **Step 4: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-6-storage-capacity.json
git commit -m "$(cat <<'EOF'
docs: [mysql-receiver] author + validate clean-room dashboard page 6 (Storage & Capacity)

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 8: Assemble and deploy the dashboard

**Files:**
- Create: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/assemble-and-create.sh`
- Create: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/dashboard-guid.txt` (gitignored — see Step 4)

**Interfaces:**
- Consumes: `lib.sh` (Task 1), all six `page-*.json` files (Tasks 2–7).
- Produces: a live dashboard in account 754495; writes its GUID to `dashboard-guid.txt` for Task 9 to consume.

- [ ] **Step 1: Write `assemble-and-create.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source ./lib.sh

# Two dashboard-wide variables: {{endpoint}} applied to every page (empty
# isMultiSelection list = global), {{queryHash}} applies only where the
# widget itself references it (NerdGraph scopes variables by usage, not by
# an explicit page list).
DASHBOARD_NAME="MySQL Query Performance Monitoring — nrmysqlreceiver (clean-room)"

python3 - "$DASHBOARD_NAME" <<'PYEOF' > /tmp/dashboard-create.json
import json, sys

name = sys.argv[1]
pages = []
for f in [
    "page-1-overview.json",
    "page-2-top-queries.json",
    "page-3-live-sessions.json",
    "page-4-wait-blocking.json",
    "page-5-execution-plans.json",
    "page-6-storage-capacity.json",
]:
    with open(f) as fh:
        pages.append(json.load(fh))

dashboard = {
    "name": name,
    "permissions": "PUBLIC_READ_WRITE",
    "pages": pages,
    "variables": [
        {
            "name": "endpoint",
            "title": "MySQL Instance Endpoint",
            "type": "STRING",
            "isMultiSelection": False,
            "replacementStrategy": "DEFAULT",
            "nrqlQuery": {
                "accountIds": [754495],
                "query": "FROM Metric SELECT uniques(`mysql.instance.endpoint`) SINCE 1 day ago",
            },
        },
        {
            "name": "queryHash",
            "title": "Query Hash (db.query.text.normalized.hash)",
            "type": "STRING",
            "isMultiSelection": False,
            "replacementStrategy": "DEFAULT",
            "nrqlQuery": {
                "accountIds": [754495],
                "query": "FROM Log SELECT uniques(`db.query.text.normalized.hash`) WHERE `event.name` = 'db.server.query_sample' SINCE 1 day ago",
            },
        },
    ],
}

mutation = {
    "query": (
        "mutation($accountId: Int!, $dashboard: DashboardInput!) { "
        "dashboardCreate(accountId: $accountId, dashboard: $dashboard) { "
        "entityResult { guid name } errors { description type } } }"
    ),
    "variables": {"accountId": 754495, "dashboard": dashboard},
}
json.dump(mutation, sys.stdout)
PYEOF

nrgraphql /tmp/dashboard-create.json | tee /tmp/dashboard-create-response.json
```

- [ ] **Step 2: Run it**

```bash
chmod +x docs/mysql-receiver/scripts/mysql-clean-room-dashboard/assemble-and-create.sh
docs/mysql-receiver/scripts/mysql-clean-room-dashboard/assemble-and-create.sh
```
Expected: response JSON with `data.dashboardCreate.entityResult.guid` and `.name` populated, `errors` null/absent. If `errors` is non-empty, read the `description` — a schema error here means a widget's `rawConfiguration` or `layout` doesn't match NerdGraph's expected shape; fix the offending page JSON file and re-run (this script is idempotent to re-run — it always creates a fresh dashboard, so if a partial/bad one gets created, note its GUID and plan to delete it once the correct one exists).

- [ ] **Step 3: Extract and save the GUID**

```bash
jq -r '.data.dashboardCreate.entityResult.guid' /tmp/dashboard-create-response.json \
  > docs/mysql-receiver/scripts/mysql-clean-room-dashboard/dashboard-guid.txt
cat docs/mysql-receiver/scripts/mysql-clean-room-dashboard/dashboard-guid.txt
```

- [ ] **Step 4: Add a `.gitignore` entry for the GUID file (account-specific runtime output, not source)**

```bash
echo "docs/mysql-receiver/scripts/mysql-clean-room-dashboard/dashboard-guid.txt" >> .gitignore
```

- [ ] **Step 5: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/assemble-and-create.sh .gitignore
git commit -m "$(cat <<'EOF'
feat: [docs/mysql-receiver] add dashboardCreate assembly script for clean-room dashboard

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 9: Verify the live dashboard

**Files:**
- Create: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/verify.sh`

**Interfaces:**
- Consumes: `lib.sh` (Task 1), `dashboard-guid.txt` (Task 8).
- Produces: a pass/fail confirmation, and the final `https://staging.onenr.io/...` URL to report to the user.

- [ ] **Step 1: Write `verify.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source ./lib.sh

GUID="$(cat dashboard-guid.txt)"

cat > /tmp/verify-query.json <<EOF
{"query": "{ actor { entity(guid: \"${GUID}\") { guid name ... on DashboardEntity { pages { name widgets { title } } } } } } "}
EOF

nrgraphql /tmp/verify-query.json | tee /tmp/verify-response.json
echo
echo "Page/widget counts:"
jq '.data.actor.entity.pages[] | {name, widgetCount: (.widgets | length)}' /tmp/verify-response.json
```

- [ ] **Step 2: Run it**

```bash
chmod +x docs/mysql-receiver/scripts/mysql-clean-room-dashboard/verify.sh
docs/mysql-receiver/scripts/mysql-clean-room-dashboard/verify.sh
```
Expected: 6 pages returned, named exactly `Overview & Instance Health`, `Query Performance (Top Queries)`, `Live Sessions & Query Samples`, `Wait & Blocking Analysis`, `Execution Plans`, `Storage Engine & Capacity`, with widget counts 22, 9, 8, 14, 7, 26 respectively (matching the widget-table row counts in Tasks 2–7 — Page 4 and Page 6 grew from the self-review fix that added the `.count`-variant lock/IO-wait metrics and the two easy-to-drop buffer-pool metrics). If any page is missing widgets, re-check that page's JSON file for a malformed entry that NerdGraph silently dropped, fix it, and re-run Task 8's `assemble-and-create.sh` (creates a new dashboard — note the old GUID for cleanup) followed by this verify step again.

- [ ] **Step 3: Derive the human-facing URL**

The `guid` from Step 1 maps to a `staging.onenr.io/<short-id>` URL the same way the two existing dashboards do. Confirm the exact URL by opening `https://staging.onenr.io/redirect/entity/${GUID}` (or checking the NerdGraph entity's `permalink`/URL field if present in the Step 1 response) rather than guessing the short-id format.

- [ ] **Step 4: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/verify.sh
git commit -m "$(cat <<'EOF'
test: [docs/mysql-receiver] add live verification script for clean-room dashboard

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 10: Write the gap-analysis doc

**Files:**
- Create: `docs/mysql-receiver/dashboard-clean-room-gap-analysis-2026-08-14.md`

**Interfaces:**
- Consumes: the discrepancies already confirmed during brainstorming (spec section) plus any additional ones noticed while building Tasks 2–7 (e.g. the `explain_mode: procedure` config knob found in `db-test-lab-nrmysql/collectors/configs/receivers/mysql.yaml` Task 1 Step 4 area — verify against `receiver/nrmysqlreceiver/config.go` whether this is a real declared config field before including it).

- [ ] **Step 1: Verify the `explain_mode: procedure` lead against code**

```bash
grep -n "explain_mode\|ExplainMode" receiver/nrmysqlreceiver/config.go receiver/nrmysqlreceiver/scraper.go
```
If it's a real declared config field, check whether the Confluence spec's §7.3 (EXPLAIN privilege problem) or §2 (Configuration Example) mentions it. If it doesn't, this is Deliverable-1 discrepancy #4.

- [ ] **Step 1b: Verify the `mysql.buffer_pool.usage` spec-index lead**

While building Task 7, `grep -o "buffer_pool.usage" <fetched-Confluence-body>` (re-fetch via
`mcp__plugin_atlassian_atlassian__getConfluencePage`, page `UoIuWQE`, cloudId
`newrelic.atlassian.net`) returned only 2 matches across the entire ~62KB document — suspicious
for a real, enabled-by-default metric that should appear at least once in §6.1's per-metric
breakdown and once in §6.12's consolidated index (3+ if also referenced in §6.1's own narrative
text). Confirm whether `mysql.buffer_pool.usage` is actually missing from the §6.12 consolidated
table specifically (re-fetch the page, search the §6.12 markdown table rows for it) — if
confirmed missing, this is Deliverable-1 discrepancy #5: the spec's own "single-table view of
every metric" is incomplete for at least one enabled-by-default metric.

- [ ] **Step 2: Write the doc**

```markdown
# MySQL clean-room dashboard — documentation gap analysis

**Date:** 2026-08-14
**Context:** found while independently re-deriving every dashboard widget's NRQL from
`receiver/nrmysqlreceiver` source, per
`docs/superpowers/specs/2026-08-14-mysql-clean-room-dashboard-design.md`. Code is treated as
ground truth throughout; every gap below is a doc lagging behind code, never the reverse.

## 1. Confluence spec vs. code (`https://newrelic.atlassian.net/wiki/x/UoIuWQE`)

1. **Retired attributes still documented as current.** §7.1 documents
   `mysql.blocking.blocker.thread_id` / `.session_id` as live NR-fork attributes. Both are
   retired in code (commit `44776db2ea`) — code now emits `mysql.blocking.blockers` (JSON array
   of `{thread_id, session_id}` tuples) and `mysql.blocking.blocker.count` (int) instead. Neither
   replacement attribute is mentioned anywhere in the spec.
2. **Undocumented fork attributes.** `mysql.wait_event` / `mysql.wait_event_type` are emitted by
   code on `db.server.query_sample` and confirmed absent from upstream
   `receiver/mysqlreceiver/metadata.yaml` (so they are NR-fork additions), but are not documented
   anywhere in the spec — not as baseline, not as fork-only.
3. **Stale fork-attribute count.** The spec's "13 fork-only attributes" claim (§7, NR fork note)
   is stale: 2 of the 13 are retired (see #1), and at least 2 fork-only attributes the code
   currently emits (see #2) are missing from the count.
4. **[Fill in based on Step 1's finding on `explain_mode: procedure`, if confirmed real and
   undocumented.]**
5. **[Fill in based on Step 1b's finding on whether `mysql.buffer_pool.usage` is missing from
   the spec's §6.12 consolidated metric index.]**

## 2. Local `docs/mysql-receiver/*.md` vs. code

[Populated from anything noticed while building Tasks 2–7 without consulting these docs for
content — e.g. if a widget's NRQL derived fresh from code turned out to differ from what
`dashboard-widget-query-reference.md` or `mysql-metrics-by-category.md` describes for the same
attribute. Every entry needs: which doc, what it says, what the code actually does, and the
commit/file reference proving it.]
```

Replace the two bracketed placeholders (items 4 and 5) with real findings from Steps 1 and 1b
before committing — do not leave them as placeholder text in the committed file. If either step
found nothing, remove that item entirely rather than leaving a "not applicable" filler line.

- [ ] **Step 3: Update `docs/mysql-receiver/README.md`'s file-index table** to add a row for the new doc, following the existing table's format (`| [file](./file.md) | one-line focus |`).

- [ ] **Step 4: Commit**

```bash
git add docs/mysql-receiver/dashboard-clean-room-gap-analysis-2026-08-14.md docs/mysql-receiver/README.md
git commit -m "$(cat <<'EOF'
docs: [mysql-receiver] add clean-room dashboard gap analysis (spec vs code, docs vs code)

Assisted-by: Claude Sonnet 5
EOF
)"
```

- [ ] **Step 5: Final report to the user**

State the dashboard's GUID, its `https://staging.onenr.io/...` URL (from Task 9 Step 3), the page/widget counts confirmed live (Task 9 Step 2), and a one-line pointer to the gap-analysis doc.

---

## Part 2: Post-launch rework — remove variables, fix layout

**Trigger:** user reviewed the live dashboard (Tasks 1-10 delivered it) and asked for two changes: (1) remove the `{{endpoint}}` and `{{queryHash}}` dashboard variables, using FACET-based widgets to show the filtering breakdown instead; (2) fix the widget layout across all 6 pages — the per-type row-packing algorithm from Part 1 left large unused gaps whenever adjacent widgets differed in type (e.g. a lone billboard on its own row after a row of charts that had 4 unused columns to spare).

### Part 2 Global Constraints (supersede Part 1's for these items; everything else in Part 1's Global Constraints — account, credentials, "code is truth," never touch the two pre-existing dashboards — still applies)

**Variable removal → FACET rule:**
- Every widget currently containing `` `mysql.instance.endpoint` = {{endpoint}} `` (or ``AND `mysql.instance.endpoint` = {{endpoint}}``) must have that WHERE clause removed entirely.
  - If the widget already has a `FACET ...` clause: add `mysql.instance.endpoint` as an additional facet dimension (e.g. `FACET kind` → `FACET kind, mysql.instance.endpoint`).
  - If the widget has no `FACET` clause at all (most billboards): add `FACET mysql.instance.endpoint`.
    - Validate live how the widget's existing visualization renders a faceted result. `viz.billboard` often cannot render more than one facet value sensibly (it may show only one arbitrarily, or error). If validation shows the billboard doesn't render the facet breakdown usefully, change that widget's `visualization.id` to `viz.table` instead (a two-column table: instance, value) and note the viz-type change in your report. If it does render acceptably as a faceted billboard (some NerdGraph versions show small-multiples), keep it as a billboard.
- Page 5 (Execution Plans) widgets 2/3 currently filter `` AND `db.query.text.normalized.hash` = {{queryHash}} `` with `LIMIT 1` to show one query's plan. Remove that filter and the `LIMIT 1`; instead add `FACET db.query.text.normalized.hash` (or the digest attribute already used elsewhere on that page) with `LIMIT 25`, so the table shows many queries' plans at once — consistent with how other pages already present "top N" breakdowns.
- The `endpoint` and `queryHash` variable definitions in `assemble-and-create.sh`'s `variables` array (Task 8/17) are deleted entirely — the dashboard has zero template variables after this rework.

**Layout algorithm v2 (replaces Part 1's algorithm):**

12-column grid, same as before, but packed by width regardless of visualization type within a "section" (the run of widgets between one markdown header and the next, or from the page's first widget/last markdown to the next markdown/table/end of page). Maintain `row` and `col` cursors, and `rowHeight` (the height of whatever's currently occupying the row, 0 if the row is empty):

1. **Markdown widget** (always width 12, height 1): if `col > 1` (something's already in this row), advance `row += rowHeight`, reset `col = 1`. Place at `(col=1, row)`, width 12, height 1. Then `row += 1`, `col = 1`, `rowHeight = 0` (markdown always fully occupies its row and the next widget starts fresh).
2. **Table widget** (always width 12, height 4): same rule — if `col > 1`, advance `row += rowHeight` and reset `col = 1` first. Place at `(col=1, row)`, width 12, height 4. Then `row += 4`, `col = 1`, `rowHeight = 0`.
3. **Billboard/line/bar/pie widget** (billboard width 3 height 3; line/bar/pie width 4 height 3 — all share height 3): if `col + width - 1 > 12` (doesn't fit in remaining row space) OR `rowHeight` is currently 4 or 1 (the row was started by a table/markdown, can't pack into it), advance `row += rowHeight` (or `+= 3` if `rowHeight` was 0, i.e. first widget on a fresh row) and reset `col = 1`. Place at `(col, row)` with its own width/height. Then `col += width`, `rowHeight = 3`.

Worked example (mixed billboard+chart packing that Part 1's algorithm got wrong): a section with two `line` widgets (width 4 each) followed by one `billboard` (width 3) — v1 put the billboard on its own fresh row (9 columns wasted); v2 packs it into the same row at column 9 (4+4+3=11 ≤ 12), wasting only 1 column.

This is a mechanical, deterministic algorithm — apply it in one pass per page, in the widgets' existing order (do not reorder widgets; only recompute their `layout` blocks and add/adjust FACET clauses).

**Redeploy mechanism:** the live dashboard already exists (GUID `NzU0NDk1fFZJWnxEQVNIQk9BUkR8ZGE6MTE4MDQ5NA`). Task 17 handles replacing it — either update in place or delete-and-recreate, whichever proves to work live (see Task 17). Tasks 11-16 only touch the local `page-*.json` files; they do not talk to the live API themselves except for widget-level NRQL validation (same live-validation discipline as Part 1: substitute `{{endpoint}}`/`{{queryHash}}` are GONE now, so validate the new FACET-based queries directly, no substitution needed).

---

### Task 11: Rework Page 1 (Overview & Instance Health) — remove variables, fix layout

**Files:**
- Modify: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-1-overview.json`

**Interfaces:**
- Consumes: `lib.sh`'s `nrgraphql()` (Task 1) for live validation of the new FACET-based queries.
- Produces: an updated `page-1-overview.json` (same 22 widgets, no `{{endpoint}}` anywhere, FACET-based instead, re-laid-out per Layout algorithm v2), consumed by Task 17's redeploy.

- [ ] **Step 1: Apply the variable-removal → FACET rule to every widget** (per Part 2 Global Constraints). This page has no `{{queryHash}}` usage, only `{{endpoint}}` — every one of the 18 real widgets needs its `` `mysql.instance.endpoint` = {{endpoint}} `` clause removed and `mysql.instance.endpoint` added to its FACET (or a new `FACET mysql.instance.endpoint` added if it had none).

- [ ] **Step 2: Validate every modified widget's new query live** via `nrgraphql` (no endpoint substitution needed anymore — the query no longer references any variable). Confirm no `errors`, confirm the facet breakdown actually returns multiple instance rows (the account has 5 live MySQL endpoints per Task 1's findings) where data exists. For widgets that were billboards with no prior FACET (Uptime, Active connections, Threads running, Queries/min, Slow queries, Buffer pool usage, Max used connections, Buffer pool page flushes, Seconds behind source, SQL delay — check the file for the exact list), validate live whether `viz.billboard` renders the faceted result sensibly; if not, switch to `viz.table` per the Global Constraints rule and note it.

- [ ] **Step 3: Recompute every widget's `layout` block using Layout algorithm v2**, applied to the widgets in their existing order. Do not change widget order, titles, or which widgets exist — only `layout` coordinates and (per Steps 1-2) query text and possibly `visualization.id`.

- [ ] **Step 4: Confirm valid JSON and exactly 22 widgets** (`jq '.widgets | length' page-1-overview.json` → 22).

- [ ] **Step 5: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-1-overview.json
git commit -m "$(cat <<'EOF'
fix: [docs/mysql-receiver] rework page 1 — remove endpoint variable, fix layout packing

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 12: Rework Page 2 (Query Performance — Top Queries) — remove variables, fix layout

**Files:**
- Modify: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-2-top-queries.json`

**Interfaces:**
- Consumes: `lib.sh`'s `nrgraphql()`.
- Produces: updated `page-2-top-queries.json` (same 9 widgets), consumed by Task 17.

- [ ] **Step 1: Apply the variable-removal → FACET rule** to every one of the 6 real widgets (all currently use `{{endpoint}}`; none use `{{queryHash}}` on this page). All 6 already have an existing `FACET` clause (on digest or digest_text) — add `mysql.instance.endpoint` to each.

- [ ] **Step 2: Validate every modified widget's new query live** via `nrgraphql`.

- [ ] **Step 3: Recompute every widget's `layout` block using Layout algorithm v2**, same order as today.

- [ ] **Step 4: Confirm valid JSON and exactly 9 widgets.**

- [ ] **Step 5: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-2-top-queries.json
git commit -m "$(cat <<'EOF'
fix: [docs/mysql-receiver] rework page 2 — remove endpoint variable, fix layout packing

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 13: Rework Page 3 (Live Sessions & Query Samples) — remove variables, fix layout

**Files:**
- Modify: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-3-live-sessions.json`

**Interfaces:**
- Consumes: `lib.sh`'s `nrgraphql()`.
- Produces: updated `page-3-live-sessions.json` (same 8 widgets), consumed by Task 17.

- [ ] **Step 1: Apply the variable-removal → FACET rule** to every one of the 5 real widgets. Widgets already faceted (session status, client driver, APM-correlated sessions) get `mysql.instance.endpoint` added to their FACET list. The "Currently running queries" table (faceted on `mysql.event_id`) also gets it added.

- [ ] **Step 2: Validate every modified widget's new query live** via `nrgraphql`.

- [ ] **Step 3: Recompute every widget's `layout` block using Layout algorithm v2.**

- [ ] **Step 4: Confirm valid JSON and exactly 8 widgets.**

- [ ] **Step 5: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-3-live-sessions.json
git commit -m "$(cat <<'EOF'
fix: [docs/mysql-receiver] rework page 3 — remove endpoint variable, fix layout packing

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 14: Rework Page 4 (Wait & Blocking Analysis) — remove variables, fix layout

**Files:**
- Modify: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-4-wait-blocking.json`

**Interfaces:**
- Consumes: `lib.sh`'s `nrgraphql()`.
- Produces: updated `page-4-wait-blocking.json` (same 14 widgets), consumed by Task 17.

- [ ] **Step 1: Apply the variable-removal → FACET rule** to every one of the 11 real widgets (mix of `Log` and `Metric` sources — the rule is the same regardless of source). The "Sessions currently blocked" billboard has no existing FACET — validate live whether it renders sensibly as a faceted billboard or needs `viz.table`.

- [ ] **Step 2: Validate every modified widget's new query live** via `nrgraphql`.

- [ ] **Step 3: Recompute every widget's `layout` block using Layout algorithm v2.**

- [ ] **Step 4: Confirm valid JSON and exactly 14 widgets.**

- [ ] **Step 5: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-4-wait-blocking.json
git commit -m "$(cat <<'EOF'
fix: [docs/mysql-receiver] rework page 4 — remove endpoint variable, fix layout packing

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 15: Rework Page 5 (Execution Plans) — remove BOTH variables, fix layout

**Files:**
- Modify: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-5-execution-plans.json`

**Interfaces:**
- Consumes: `lib.sh`'s `nrgraphql()`.
- Produces: updated `page-5-execution-plans.json` (same 7 widgets), consumed by Task 17.

This is the only page using `{{queryHash}}`, in addition to `{{endpoint}}` — both must be removed.

- [ ] **Step 1: Rework widgets 2/3** ("Query text + plan" for query samples / top queries): remove `` AND `db.query.text.normalized.hash` = {{queryHash}} `` and `LIMIT 1`; add `FACET db.query.text.normalized.hash` (or `mysql.events_statements_current.digest` / the digest attribute already available on that event — pick whichever the widget already references elsewhere) with `LIMIT 25`, so the table shows many queries' plans. Also apply the `{{endpoint}}` → FACET rule to these two widgets (add `mysql.instance.endpoint` to the same FACET list).

- [ ] **Step 2: Rework widgets 6/7** ("Query samples with a plan (%)" / "Top queries with a plan (%)" billboards): apply the `{{endpoint}}` → FACET rule (no existing FACET on these — validate live whether a faceted billboard renders sensibly, else switch to `viz.table`).

- [ ] **Step 3: Validate every modified widget's new query live** via `nrgraphql`.

- [ ] **Step 4: Recompute every widget's `layout` block using Layout algorithm v2.**

- [ ] **Step 5: Confirm valid JSON and exactly 7 widgets.**

- [ ] **Step 6: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-5-execution-plans.json
git commit -m "$(cat <<'EOF'
fix: [docs/mysql-receiver] rework page 5 — remove both variables, fix layout packing

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 16: Rework Page 6 (Storage Engine & Capacity) — remove variables, fix layout

**Files:**
- Modify: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-6-storage-capacity.json`

**Interfaces:**
- Consumes: `lib.sh`'s `nrgraphql()`.
- Produces: updated `page-6-storage-capacity.json` (same 26 widgets — the largest page), consumed by Task 17.

- [ ] **Step 1: Apply the variable-removal → FACET rule** to every one of the 22 real widgets. Several billboards have no existing FACET (Buffer pool limit, Buffer pool page flushes, Buffer pool data pages, InnoDB page size, Opened resources) — validate live whether each renders sensibly as a faceted billboard or needs `viz.table`. The 7 "Top N" table widgets (already faceted by schema/table/index) just get `mysql.instance.endpoint` appended to their existing FACET list.

- [ ] **Step 2: Validate every modified widget's new query live** via `nrgraphql` — this page is the largest, don't skip any of the 22.

- [ ] **Step 3: Recompute every widget's `layout` block using Layout algorithm v2.**

- [ ] **Step 4: Confirm valid JSON and exactly 26 widgets.**

- [ ] **Step 5: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-6-storage-capacity.json
git commit -m "$(cat <<'EOF'
fix: [docs/mysql-receiver] rework page 6 — remove endpoint variable, fix layout packing

Assisted-by: Claude Sonnet 5
EOF
)"
```

---

### Task 17: Redeploy the reworked dashboard and re-verify

**Files:**
- Modify: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/assemble-and-create.sh`
- Modify (if needed): `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/verify.sh`

**Interfaces:**
- Consumes: `lib.sh` (Task 1), all six reworked `page-*.json` files (Tasks 11-16), the existing `dashboard-guid.txt` (Task 8's original GUID, `NzU0NDk1fFZJWnxEQVNIQk9BUkR8ZGE6MTE4MDQ5NA`).
- Produces: the live dashboard updated to the reworked version (same GUID if updated in place, or a new GUID if delete+recreate proves necessary).

- [ ] **Step 1: Remove the `variables` array entirely** from `assemble-and-create.sh`'s Python heredoc — the `dashboard` dict should no longer have an `endpoint`/`queryHash` `variables` key at all (or set it to `[]` if the NerdGraph schema requires the key present).

- [ ] **Step 2: Try updating the live dashboard in place first.** NerdGraph has a `dashboardUpdate(guid: ID!, dashboard: DashboardInput!)` mutation (distinct from `dashboardUpdateWidgetsInPage`, which is the one that historically hit `FORBIDDEN_OPERATION` on this account per `project_mysql_dashboard_write_api_blocked` — that history does NOT necessarily apply to this different, dashboard-level mutation). Try:
```json
{"query": "mutation($guid: EntityGuid!, $dashboard: DashboardInput!) { dashboardUpdate(guid: $guid, dashboard: $dashboard) { entityResult { guid name } errors { description type } } }", "variables": {"guid": "<GUID from dashboard-guid.txt>", "dashboard": <the same assembled dashboard object, minus variables>}}
```
  via `nrgraphql`. If this succeeds (non-null guid, no errors), the GUID and URL stay the same — done, skip to Step 4.

- [ ] **Step 3: If Step 2 hits a permissions error (`FORBIDDEN_OPERATION` or similar) or any other hard failure**, fall back to delete-and-recreate: run `dashboardDelete(guid: ...)` for the current GUID, then rerun the (now-variable-free) `assemble-and-create.sh` fresh — this exact `dashboardCreate` path already proved to work without permission issues in Task 8. Overwrite `dashboard-guid.txt` with the new GUID. Note in your report that the GUID changed and why.

- [ ] **Step 4: Re-run `verify.sh`** against whichever GUID is now current. Confirm 6 pages, same widget counts as before (22, 9, 8, 14, 7, 26 — the rework didn't add/remove widgets, only their queries/layout), and confirm the dashboard's `variables` are now empty (query the entity for a `variables` field if the schema exposes one via the same entity query, or note that the payload sent had none).

- [ ] **Step 5: Derive the (possibly-changed) human-facing URL** the same way Task 9 did (NerdGraph entity `permalink` field, not a guessed domain).

- [ ] **Step 6: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/assemble-and-create.sh docs/mysql-receiver/scripts/mysql-clean-room-dashboard/verify.sh
git commit -m "$(cat <<'EOF'
fix: [docs/mysql-receiver] redeploy dashboard without variables after layout/facet rework

Assisted-by: Claude Sonnet 5
EOF
)"
```

- [ ] **Step 7: Final report to the user** — confirm the GUID (same or new, and why), the URL, that all 6 pages/widget counts are unchanged, that no dashboard variables remain, and a one-line summary of the layout fix (tighter packing, no more large gaps).

---

## Part 3: Restore aggregate KPI billboards (UX follow-up)

**Trigger:** final Part 2 review flagged that all 17 billboards converted to tables, leaving zero at-a-glance KPI tiles. User asked for best judgment on customer experience. Decision: add a SMALL set of unfaceted (aggregate-across-all-instances) billboards to Page 1's top, in ADDITION to the existing faceted tables — not replacing them. Gives a fast top-line health check plus the detailed per-instance breakdown when needed.

### Task 18: Add aggregate KPI billboards to Page 1

**Files:**
- Modify: `docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-1-overview.json`

**Interfaces:**
- Consumes: `lib.sh`'s `nrgraphql()` (Task 1).
- Produces: updated `page-1-overview.json` (23 existing widgets + 6 new billboards = 29 widgets), consumed by Task 19's redeploy.

- [ ] **Step 1: Add 6 new billboard widgets** at the TOP of the page, immediately after the page's opening markdown header (before the existing "At a Glance" table conversions), each with NO facet (aggregate across all instances — the whole point is a fleet-wide top-line number, distinct from the detailed per-instance tables already on this page):

| Title | Query |
|---|---|
| Monitored instances | `` FROM Metric SELECT uniqueCount(`mysql.instance.endpoint`) WHERE `metricName` = 'mysql.uptime' `` |
| Total active connections | `` FROM Metric SELECT sum(`mysql.threads`) WHERE `metricName` = 'mysql.threads' AND kind = 'connected' `` |
| Total threads running | `` FROM Metric SELECT sum(`mysql.threads`) WHERE `metricName` = 'mysql.threads' AND kind = 'running' `` |
| Total queries/min (all instances) | `` FROM Metric SELECT rate(sum(`mysql.query.count`), 1 minute) WHERE `metricName` = 'mysql.query.count' `` |
| Total slow queries (cumulative) | `` FROM Metric SELECT sum(`mysql.query.slow.count`) WHERE `metricName` = 'mysql.query.slow.count' `` |
| Total buffer pool usage (bytes) | `` FROM Metric SELECT sum(`mysql.buffer_pool.usage`) WHERE `metricName` = 'mysql.buffer_pool.usage' `` |

Validate each live via `nrgraphql` (no `{{endpoint}}` substitution needed — these are intentionally unfaceted/aggregate, not per-instance). Each is `viz.billboard`, width 3, height 3.

- [ ] **Step 2: Recompute the WHOLE page's layout using Layout algorithm v2** (defined in Part 2 Global Constraints above) — the 6 new billboards go right after the opening markdown, packing 4-per-row before the existing widgets, which all shift down accordingly. Do not change the order or content of any of the 23 existing widgets — only insert the 6 new ones after the header and re-run the layout pass over the resulting 29-widget sequence.

- [ ] **Step 3: Confirm valid JSON and exactly 29 widgets** (`jq '.widgets | length'` → 29).

- [ ] **Step 4: Commit**

```bash
git add docs/mysql-receiver/scripts/mysql-clean-room-dashboard/page-1-overview.json
git commit -m "$(cat <<'EOF'
feat: [docs/mysql-receiver] add aggregate KPI billboards to page 1

Assisted-by: Claude Sonnet 5
EOF
)"
```

### Task 19: Redeploy with new KPI billboards, re-verify

**Files:**
- None (uses existing `assemble-and-create.sh`/ad-hoc `dashboardUpdate` mechanism from Task 17).

**Interfaces:**
- Consumes: `lib.sh` (Task 1), all six current `page-*.json` files (page-1 now updated by Task 18), `dashboard-guid.txt`.

- [ ] **Step 1: Redeploy via `dashboardUpdate`** (same mutation shape Task 17 used successfully — update in place, GUID unchanged). Assemble the dashboard payload from the 6 current page files (still zero `variables`) and push it.

- [ ] **Step 2: Re-run `verify.sh`.** Expected counts now: Overview & Instance Health=**29**, Query Performance (Top Queries)=9, Live Sessions & Query Samples=8, Wait & Blocking Analysis=14, Execution Plans=7, Storage Engine & Capacity=26. **Total = 93.**

- [ ] **Step 3: Confirm the 6 new billboards render as real scalars** (not faceted/broken) by checking their values in the entity query response.

- [ ] **Step 4: Final report** — confirm GUID/URL unchanged, new total widget count (93), and that the 6 new billboards are visible alongside the existing detailed tables.
