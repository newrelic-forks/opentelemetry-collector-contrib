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
4. **Undocumented `explain_mode: procedure` config field, and its purpose.** `receiver/nrmysqlreceiver/config.go`
   declares a real `Config.ExplainMode string \`mapstructure:"explain_mode"\`` field, validated to
   accept only `"inline"` (default) or `"procedure"`. In `procedure` mode, `EXPLAIN` is routed
   through a `SQL SECURITY DEFINER` stored procedure (`<schema>.explain_statement`) so write
   statements can be explained without granting DML to the monitoring user, falling back to
   inline `EXPLAIN` when the procedure is absent for a schema. The spec's §7.3 ("Query plan
   collection (`EXPLAIN`) mechanics") describes the exact problem this field solves in detail —
   "Database privileges — a real, non-obvious requirement" — including the `ERROR 1142` a
   read-only monitoring user hits trying to `EXPLAIN` an `INSERT`/`UPDATE`/`DELETE`/`REPLACE`, and
   frames the only workaround as granting the monitoring user the real write privilege. It never
   mentions `explain_mode` or the SQL SECURITY DEFINER procedure as an alternative that avoids
   that privilege tradeoff entirely. §2 ("Configuration Example") also omits the field from its
   sample config block. This is the fork's actual answer to a problem the spec spends a full
   subsection describing — and the spec doesn't know it exists.

## 2. Local `docs/mysql-receiver/*.md` vs. code

No discrepancies were noticed while building Tasks 2–7. Each page's widget NRQL was derived
directly from `receiver/nrmysqlreceiver` source (`metadata.yaml`, `scraper.go`, `client.go`) per
the clean-room brief — the existing reference docs (`mysql-metrics-by-category.md`,
`core-metrics-cardinality.md`, `queries-executed.md`, `dashboard-terminology-glossary.md`,
`01-architecture.md`) were deliberately not consulted for widget content, so this section
reflects an absence of *noticed* drift rather than a confirmed absence of drift — a targeted
doc-vs-code diff of those files was out of scope for Tasks 2–7 and this task alike.
