---
description: Sync nroracledbreceiver release changes into oracle-otel/config.yml — diffs grants/metrics/logs against Confluence source of truth, tests via Docker Oracle 23c, updates Confluence, and raises PR on success.
---

# Oracle OTel Sync

Automates the bi-weekly sync of `nroracledbreceiver` release changes into `oracle-otel/config.yml` in `shared-component-framework-configs`.

## Trigger

Invoked as `/oracle-sync [release-tag]` — e.g. `/oracle-sync receiver/nroracledbreceiver/v0.157.2`.

If no tag provided, auto-detect the latest tag:
```bash
git -C "$OTEL_REPO" tag --sort=-version:refname \
  | grep 'receiver/nroracledbreceiver/' | head -1
```

## Configuration

At the start of every run, resolve these variables. Use Bash to detect values; only ask the developer when auto-detection fails.

```bash
# 1. OTEL_REPO: the repo this skill lives in
OTEL_REPO=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")

# 2. SC_REPO: try sibling directory first
SC_REPO="$(dirname "$OTEL_REPO")/shared-component-framework-configs"

# If sibling doesn't exist, check saved local config
if [ ! -d "$SC_REPO" ]; then
  SC_REPO=$(grep '^SC_REPO=' "$OTEL_REPO/.claude/oracle-sync.local" 2>/dev/null | cut -d= -f2)
fi

# If still not found, ask the developer and save for next time
if [ ! -d "$SC_REPO" ]; then
  # Ask: "Where is your local clone of shared-component-framework-configs? (absolute path)"
  # Save answer: echo "SC_REPO=/their/path" >> "$OTEL_REPO/.claude/oracle-sync.local"
fi

# 3. Derived paths
RECEIVER_DIR="$OTEL_REPO/receiver/nroracledbreceiver"
CONFIG_YML="$SC_REPO/shared-component/configs/data-sources/oracle-otel/config.yml"

# 4. Tags
RELEASE_TAG="<tag argument or auto-detected>"

# 5. NRDOT binary path — check oracle-sync.local, else ask once and save
# NRDOT_PATH=<absolute path to NRDOT binary>

# 6. Confluence — check oracle-sync.local, else ask once and save
# CONFLUENCE_SPACE=<space key, e.g. GROWTHCXP>
# CONFLUENCE_PARENT_ID=<numeric parent page ID>
```

---

## Step 1 — DIFF

### 1a. Extract required views from all sources

Run all commands from `$OTEL_REPO`. Collect results into three named lists.

**`readme_grants`** — documented grants (self-hosted, Metrics collection section only):
```bash
awk '/^### Metrics collection/,/^## /' "$RECEIVER_DIR/README.md" \
  | grep -oE 'GRANT SELECT ON [A-Z_$\.]+' \
  | grep -oE '(V_\$|GV_\$|DBA_|CDB_|ALL_)[A-Z_$]+' | sort -u
```

**`source_views`** — views queried by metric SQL (scraper.go + instance_info.go):
```bash
grep -hiE '\bFROM\s+(v\$|gv\$|dba_|cdb_|all_)[a-z_]+' \
  "$RECEIVER_DIR/scraper.go" "$RECEIVER_DIR/instance_info.go" \
  | grep -oiE '(v\$|gv\$|dba_|cdb_|all_)[a-z_]+' \
  | tr '[:lower:]' '[:upper:]' \
  | sed 's/^V\$/V_$/; s/^GV\$/GV_$/' | sort -u
```

**`template_views`** — views queried by log event SQL (all .tmpl files):
```bash
grep -hiE '\bFROM\s+(v\$|gv\$|dba_|cdb_)[a-z_]+' \
  "$RECEIVER_DIR/templates/"*.tmpl \
  | grep -oiE '(v\$|gv\$|dba_|cdb_)[a-z_]+' \
  | tr '[:lower:]' '[:upper:]' \
  | sed 's/^V\$/V_$/; s/^GV\$/GV_$/' | sort -u
```

**`required_views`** — union of all three lists, deduplicated:
```bash
sort -u <(echo "$readme_grants") <(echo "$source_views") <(echo "$template_views")
```

**`config_grants`** — current known-good grants from the Confluence source of truth page.

Use the `mcp__plugin_nr_atlassian-confluence__getConfluencePage` tool with `cloudId: "newrelic.atlassian.net"` and `pageId: "5987043050"`.
Extract every `GRANT SELECT ON` line from the **Multitenant Architecture (CDB/PDB)** section only (not PDB-only or ADB sections), normalise to bare view names (strip `SYS.`, `c##<USER_NAME>`, `CONTAINER=ALL`), sort and deduplicate.

Also read the `metadata.yaml` baseline (metrics/logs enabled state) from the Config.yaml section of that same Confluence page — this is the PREV state for the metric/log diff.

Compute and display all four sections:

**[GRANT GAPS]** — views in `required_views` but not in `config_grants` (Confluence baseline):
```bash
comm -23 <(echo "$required_views" | sort) <(echo "$config_grants" | sort)
```

**[README LAGS]** — views in source/templates but not yet documented in README:
```bash
comm -23 \
  <(sort -u <(echo "$source_views") <(echo "$template_views")) \
  <(echo "$readme_grants" | sort)
```

### 1b. Detect metric and log changes vs Confluence baseline

Read the metrics/logs baseline from the Confluence source of truth page (ID `5987043050`).
Read the current state from `metadata.yaml` at `$RELEASE_TAG`:

```bash
git -C "$OTEL_REPO" show "$RELEASE_TAG:receiver/nroracledbreceiver/metadata.yaml" \
  > /tmp/metadata_curr.yaml
```

Diff the Confluence baseline metrics/logs against `/tmp/metadata_curr.yaml`.

**[METRIC CHANGES]** — any metric where `enabled:` differs from the Confluence baseline.
**[LOG CHANGES]** — any log type added or removed vs the Confluence baseline.

Display all four labelled sections clearly. Do not proceed until the developer has seen them.

---

## Step 2 — REVIEW

For each item across all four sections, ask the developer one group at a time:

```
[GRANT GAPS] — N view(s) required by receiver but missing from Confluence baseline:
  SYS.V_$OSSTAT   (found in: scraper.go)
  DBA_PROCEDURES  (found in: templates/oracleQuerySampleSql.tmpl)
Add all missing grants? (y/n — or list specific ones to skip)

[README LAGS] — N view(s) in source but not documented in README.md:
  SYS.V_$OSSTAT
Flag these for README update in the PR description? (y/n)

[METRIC CHANGES] — N metric(s) changed enabled state:
  oracledb.cpu.time: false → true
Apply metric flag changes to config.yml? (y/n)

[LOG CHANGES] — N log type(s) added/removed:
  db.server.session.wait_sample: added
Note these in the Confluence page? (y/n)
```

Collect all approvals before writing anything to disk.

---

## Step 3 — APPLY

### 3a. Add approved grants to config.yml

The grant block is inside the `step5` content node under the label
`Grant Monitoring Privileges for Multitenant Database`.

For each approved view, format the new line as:
- `V_$<NAME>` or `GV_$<NAME>` →
  `                  GRANT SELECT ON SYS.V_$<NAME> TO c##${{ state.dbUsername.value }} CONTAINER=ALL;`
- `DBA_<NAME>`, `CDB_<NAME>`, `ALL_<NAME>`, `GLOBAL_NAME` →
  `                  GRANT SELECT ON <NAME> TO c##${{ state.dbUsername.value }} CONTAINER=ALL;`

Insert each new line in alphabetical order within the existing grant block using the Edit tool.
Do not touch any lines outside the grant block.

### 3b. Update metric/log flags

For each approved METRIC CHANGE, locate the `enable_query_monitoring:` or equivalent flag
in the otel-collector-config.yaml snippet within config.yml and update its boolean value.

---

> **HARD GATE: Do NOT update Confluence, do NOT raise a PR, until Step 4 TEST passes.
> Step 4 must complete with PASS before any write to Confluence or any git operation.
> If TEST fails, stop at Step 5a (failure snapshot only). Never skip Step 4.**

---

## Step 4 — TEST

Uses `gvenzl/oracle-free:slim-faststart` (Oracle 23c free) via Docker — no external lab needed.
Requires: `docker` CLI, NRDOT Linux binary, and `$NR_LICENSE_KEY` set (ask developer if not).

### 4a. Spin up Oracle container

```bash
docker pull gvenzl/oracle-free:slim-faststart
docker network create oracle-sync-net 2>/dev/null || true
docker run -d --name oracle-sync-db \
  --network oracle-sync-net \
  -e ORACLE_PASSWORD=SyncTest1234 \
  gvenzl/oracle-free:slim-faststart

until docker logs oracle-sync-db 2>&1 | grep -q "DATABASE IS READY TO USE!"; do
  sleep 10
done
echo "Oracle container ready"
```

### 4b. Create monitoring user and apply all grants

Extract every `GRANT SELECT ON` line from config.yml step5 (including newly added ones from Step 3), substitute `c##${{ state.dbUsername.value }}` with `c##newrelic`:

```bash
docker exec -i oracle-sync-db sqlplus system/SyncTest1234@FREE <<'EOF'
CREATE USER c##newrelic IDENTIFIED BY "NRTest1234";
GRANT CONNECT TO c##newrelic CONTAINER=ALL;
GRANT CREATE SESSION TO c##newrelic CONTAINER=ALL;
GRANT SET CONTAINER TO c##newrelic CONTAINER=ALL;
<all GRANT SELECT lines from config.yml step5 with c##newrelic substituted>
EOF
```

### 4c. Start NRDOT collector in a Linux Docker container

Since the NRDOT binary is Linux-only, run it inside a container on the same Docker network:

```bash
docker run -d --name oracle-sync-collector \
  --network oracle-sync-net \
  -e NR_LICENSE_KEY="$NR_LICENSE_KEY" \
  -v "$(pwd)/otel-collector-config-test.yaml:/config.yaml" \
  ubuntu:22.04 \
  bash -c "apt-get install -y libaio1 && <NRDOT_BINARY> --config=/config.yaml"
```

Generate `otel-collector-config-test.yaml` from the otel config snippet in config.yml, substituting:
- endpoint: `oracle-sync-db:1521` (Docker network hostname), username: `c##newrelic`, password: `NRTest1234`
- CDB service: `FREE`, PDB service: `FREEPDB1`
- OTLP api-key: `$NR_LICENSE_KEY`, OTLP endpoint: `https://otlp.nr-data.net:4318`

Resolve NRDOT binary path from `.claude/oracle-sync.local` (`NRDOT_PATH=...`) or ask developer once.

### 4d. Verify data reaches New Relic

Wait 90 seconds, then query NR using `mcp__plugin_nr_nr-mcp-server__execute_nrql_query`:
```
SELECT count(*) FROM Metric WHERE metricName LIKE 'oracledb%' SINCE 5 minutes ago
```

**PASS** if count > 0. Retry every 60 seconds for up to 5 minutes before declaring FAIL.

### 4e. Cleanup

```bash
docker stop oracle-sync-db oracle-sync-collector
docker rm oracle-sync-db oracle-sync-collector
docker network rm oracle-sync-net
rm -f otel-collector-config-test.yaml /tmp/metadata_curr.yaml
```

---

## Step 5a — On FAILURE

Create a Confluence page using `mcp__plugin_nr_atlassian-confluence__createConfluencePage`:

```
space_key:  $CONFLUENCE_SPACE
parent_id:  $CONFLUENCE_PARENT_ID
title:      Oracle OTel $RELEASE_TAG — FAILED — <today YYYY-MM-DD>
```

```markdown
## Result: FAILED

**Release tag:** $RELEASE_TAG
**Date:** <today>

## Changes Applied
<bullet list of grants added and metric flags changed in Step 3>

## Test Output
<full captured stdout/stderr>

## Notes
config.yml changes are staged locally. No PR was raised.
```

Do NOT raise a PR.

---

## Step 5b — On SUCCESS (only reached if Step 4 TEST returned PASS)

### Update Confluence source of truth

Update page ID `5987043050` (Oracle Automation: Grants and Config.yaml Source of truth) using `mcp__plugin_nr_atlassian-confluence__updateConfluencePage`:
- Add new grants to the grants list
- Update the config.yaml snippet with metric/log changes
- Add a version tag entry: `Last synced: $RELEASE_TAG — <today>`

### Create versioned release page

Create a new Confluence page under `$CONFLUENCE_PARENT_ID`:

```markdown
## Result: PASS

**Release tag:** $RELEASE_TAG
**Date:** <today>
**NR Link:** <captured URL if any>

## Config Changes
<git diff of config.yml>

## Grants (full list as applied)
| Grant |
|-------|
<one row per GRANT SELECT line, sorted>

## Metrics
| Metric | Enabled | Description |
|--------|---------|-------------|
<one row per metric from /tmp/metadata_curr.yaml>

## Logs
| Log Type | Template File | Views Queried |
|----------|---------------|---------------|
<one row per .tmpl file>

## Test Result
PASS — count: <NRQL count>
```

### Commit and notify

```bash
cd "$SC_REPO"
VERSION=$(echo "$RELEASE_TAG" | grep -oE 'v[0-9.]+$')
git checkout -b "oracle-otel-sync-${VERSION}"
git add shared-component/configs/data-sources/oracle-otel/config.yml
git commit -m "feat(oracle-otel): sync grants and metrics for ${RELEASE_TAG}"
```

Tell the developer:
> "Changes committed to branch `oracle-otel-sync-${VERSION}`. Confluence updated: <release page URL>
> Please review the diff and raise the PR when ready."

Do NOT run `gh pr create`. The developer raises the PR manually.
