# Oracle Sync Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a project-scoped Claude skill `/oracle-sync` that automates the bi-weekly sync of `nroracledbreceiver` release changes into `oracle-otel/config.yml` — diffing grants/metrics/logs, applying changes, running the test lab, updating Confluence, and raising a PR.

**Architecture:** A single skill file at `.claude/skills/oracle-sync.md` provides step-by-step instructions for Claude. Claude reads source files via Bash, reasons about diffs, patches config.yml via the Edit tool, invokes the Terraform test lab via shell, calls Confluence MCP tools, and raises a PR via `gh`. No separate scripts — all parsing is Bash grep commands Claude runs inline.

**Tech Stack:** Claude Code skill (Markdown), Bash (grep/regex), Confluence MCP (`mcp__mcp-atlassian-write__confluence_*`), GitHub CLI `gh`

## Global Constraints

- Self-hosted Oracle only — no RDS, no OCI grants
- CDB/PDB multitenant: all V_$/GV_$ grants use prefix `SYS.` and suffix `CONTAINER=ALL`
- `enable_query_monitoring` always enabled — treat all template views as unconditionally required
- Skill path: `opentelemetry-collector-contrib/.claude/skills/oracle-sync.md`
- Tags are scoped: `receiver/nroracledbreceiver/v0.157.2` — NOT bare `v0.157.2`
- Config to patch: `shared-component-framework-configs/shared-component/configs/data-sources/oracle-otel/config.yml` — step5 grant block (~lines 160–211)
- Grant line format in config.yml: `GRANT SELECT ON SYS.V_$<NAME> TO c##${{ state.dbUsername.value }} CONTAINER=ALL;`
- DBA_/CDB_/ALL_ views: no `SYS.` prefix, no `CONTAINER=ALL` suffix

---

### Task 1: Skill scaffold + DIFF step

**Files:**
- Create: `opentelemetry-collector-contrib/.claude/skills/oracle-sync.md`

**Interfaces:**
- Produces: Skill with a working DIFF step that outputs four labelled sections: `[GRANT GAPS]`, `[README LAGS]`, `[METRIC CHANGES]`, `[LOG CHANGES]`

- [ ] **Step 1: Verify all parsing commands produce correct output before embedding in skill**

Run these from `opentelemetry-collector-contrib/` to confirm each pattern works:

```bash
cd /path/to/opentelemetry-collector-contrib

# README grants (self-hosted section only — stop at "### Hosting type")
awk '/^### Metrics collection/,/^##/' receiver/nroracledbreceiver/README.md \
  | grep -oE 'GRANT SELECT ON [A-Z_$\.]+' \
  | grep -oE '(V_\$|GV_\$|DBA_|CDB_|ALL_)[A-Z_$]+' | sort -u

# Metric SQL views from scraper.go + instance_info.go
grep -hiE '\bFROM\s+(v\$|gv\$|dba_|cdb_|all_)[a-z_]+' \
  receiver/nroracledbreceiver/scraper.go \
  receiver/nroracledbreceiver/instance_info.go \
  | grep -oiE '(v\$|gv\$|dba_|cdb_|all_)[a-z_]+' \
  | tr '[:lower:]' '[:upper:]' \
  | sed 's/^V\$/V_$/; s/^GV\$/GV_$/' | sort -u

# Log SQL views from templates
grep -hiE '\bFROM\s+(v\$|gv\$|dba_|cdb_)[a-z_]+' \
  receiver/nroracledbreceiver/templates/*.tmpl \
  | grep -oiE '(v\$|gv\$|dba_|cdb_)[a-z_]+' \
  | tr '[:lower:]' '[:upper:]' \
  | sed 's/^V\$/V_$/; s/^GV\$/GV_$/' | sort -u

# Current config.yml grants (normalised to bare view names)
grep -oE 'SYS\.(V_|GV_)\$[A-Z_]+|DBA_[A-Z_]+|CDB_[A-Z_]+|ALL_[A-Z_]+|GLOBAL_NAME' \
  /path/to/shared-component-framework-configs/shared-component/configs/data-sources/oracle-otel/config.yml \
  | sed 's/^SYS\.//' | sort -u
```

Expected: each command returns a non-empty list of view names in uppercase.

- [ ] **Step 2: Create `.claude/skills/` directory**

```bash
mkdir -p opentelemetry-collector-contrib/.claude/skills/
```

- [ ] **Step 3: Write the skill file with header and DIFF step**

Create `opentelemetry-collector-contrib/.claude/skills/oracle-sync.md`:

```markdown
# Oracle OTel Sync

Automates the bi-weekly sync of `nroracledbreceiver` release changes into `oracle-otel/config.yml`.

## Trigger

Invoked as `/oracle-sync [release-tag]` — e.g. `/oracle-sync receiver/nroracledbreceiver/v0.157.2`.
If no tag provided, detect latest tag:
```bash
git -C /path/to/opentelemetry-collector-contrib tag --sort=-version:refname \
  | grep 'receiver/nroracledbreceiver/' | head -1
```

## Configuration

Set these at the start — ask the developer if unsure:
- `OTEL_REPO`: absolute path to `opentelemetry-collector-contrib`
- `SC_REPO`: absolute path to `shared-component-framework-configs`
- `CONFIG_YML`: `$SC_REPO/shared-component/configs/data-sources/oracle-otel/config.yml`
- `RECEIVER_DIR`: `$OTEL_REPO/receiver/nroracledbreceiver`
- `RELEASE_TAG`: tag argument, e.g. `receiver/nroracledbreceiver/v0.157.2`
- `PREV_TAG`: previous tag — detect with:
  ```bash
  git -C $OTEL_REPO tag --sort=-version:refname \
    | grep 'receiver/nroracledbreceiver/' | sed -n '2p'
  ```
- `CONFLUENCE_SPACE`: space key for release pages (ask developer on first run)
- `CONFLUENCE_PARENT_ID`: parent page ID for release pages (ask developer on first run)

## Step 1 — DIFF

### 1a. Extract required views from all sources

Run the following Bash commands. Collect all view names into a single `required_views` list.

**README grants** (self-hosted section — `### Metrics collection` to end of permissions section):
```bash
awk '/^### Metrics collection/,/^##/' $RECEIVER_DIR/README.md \
  | grep -oE 'GRANT SELECT ON [A-Z_$\.]+' \
  | grep -oE '(V_\$|GV_\$|DBA_|CDB_|ALL_)[A-Z_$]+' | sort -u
```

**Metric SQL views** (scraper.go + instance_info.go):
```bash
grep -hiE '\bFROM\s+(v\$|gv\$|dba_|cdb_|all_)[a-z_]+' \
  $RECEIVER_DIR/scraper.go $RECEIVER_DIR/instance_info.go \
  | grep -oiE '(v\$|gv\$|dba_|cdb_|all_)[a-z_]+' \
  | tr '[:lower:]' '[:upper:]' \
  | sed 's/^V\$/V_$/; s/^GV\$/GV_$/' | sort -u
```

**Log SQL views** (all `.tmpl` files):
```bash
grep -hiE '\bFROM\s+(v\$|gv\$|dba_|cdb_)[a-z_]+' \
  $RECEIVER_DIR/templates/*.tmpl \
  | grep -oiE '(v\$|gv\$|dba_|cdb_)[a-z_]+' \
  | tr '[:lower:]' '[:upper:]' \
  | sed 's/^V\$/V_$/; s/^GV\$/GV_$/' | sort -u
```

Union all three lists. Deduplicate.

**Current config.yml grants** (normalised, no SYS. prefix):
```bash
grep -oE 'SYS\.(V_|GV_)\$[A-Z_]+|DBA_[A-Z_]+|CDB_[A-Z_]+|ALL_[A-Z_]+|GLOBAL_NAME' \
  $CONFIG_YML | sed 's/^SYS\.//' | sort -u
```

Compute and display:

**[GRANT GAPS]** — views in `required_views` but not in `config_grants`:
```bash
comm -23 <(echo "$required_views" | sort) <(echo "$config_grants" | sort)
```

**[README LAGS]** — views in source/templates but not in README grants:
```bash
comm -23 <(echo "$source_and_template_views" | sort) \
         <(echo "$readme_grants" | sort)
```

### 1b. Detect metric and log changes

Extract enabled state from metadata.yaml at both tags:
```bash
git -C $OTEL_REPO show $PREV_TAG:receiver/nroracledbreceiver/metadata.yaml \
  > /tmp/metadata_prev.yaml
git -C $OTEL_REPO show $RELEASE_TAG:receiver/nroracledbreceiver/metadata.yaml \
  > /tmp/metadata_curr.yaml
diff /tmp/metadata_prev.yaml /tmp/metadata_curr.yaml
```

From the diff, identify:

**[METRIC CHANGES]** — any metric under `metrics:` where `enabled:` value changed.
**[LOG CHANGES]** — any signal under `logs:` that was added or removed.

Display all four sections clearly before proceeding.

## Step 2 — REVIEW

For each item in `[GRANT GAPS]`, `[METRIC CHANGES]`, and `[LOG CHANGES]`, ask the developer:

```
[GRANT GAPS]
  SYS.V_$OSSTAT — found in scraper.go, missing from config.yml
  Add this grant? (y/n)

  DBA_PROCEDURES — found in templates, missing from config.yml
  Add this grant? (y/n)

[README LAGS]
  SYS.V_$OSSTAT — in source but not in README.md
  Flag for README update? (y/n)

[METRIC CHANGES]
  oracledb.cpu.time: false → true
  Update config.yml? (y/n)
```

Collect approvals before writing anything.

## Step 3 — APPLY

### 3a. Add approved grant gaps to config.yml

The grant block in config.yml lives in the `step5` section under the label
`Grant Monitoring Privileges for Multitenant Database`.

For each approved view:
- If view is `V_$<NAME>` or `GV_$<NAME>`: insert as
  `                  GRANT SELECT ON SYS.<VIEW> TO c##${{ state.dbUsername.value }} CONTAINER=ALL;`
- If view is `DBA_<NAME>`, `CDB_<NAME>`, or `ALL_<NAME>`: insert as
  `                  GRANT SELECT ON <VIEW> TO c##${{ state.dbUsername.value }} CONTAINER=ALL;`

Insert new lines in alphabetical order within the existing grant block. Use the Edit tool.

### 3b. Update metric/log flags

For each approved METRIC CHANGE, find the corresponding `enable_<metric_name>:` line
in the otel-collector-config.yaml snippet within config.yml and update its boolean value.

## Step 4 — TEST

Ask the developer:
> "What is the command to run the Terraform test lab? (e.g. `cd /path/to/test-lab && terraform apply -auto-approve`)"

Run the command. Capture stdout/stderr. Poll every 30 seconds for up to 15 minutes.
The test passes when the lab emits a success signal (confirm the exact signal with developer on first run).

If the lab outputs a New Relic link or entity URL, capture it for the Confluence page.

## Step 5a — On FAILURE

Create a Confluence page using `mcp__mcp-atlassian-write__confluence_create_page`:
- `space_key`: `$CONFLUENCE_SPACE`
- `parent_id`: `$CONFLUENCE_PARENT_ID`
- `title`: `Oracle OTel $RELEASE_TAG — FAILED — <today's date>`
- `content` (Markdown):

```markdown
## Result: FAILED

**Release tag:** $RELEASE_TAG
**Date:** <today>

## Changes Applied
<list of grants/metrics changed in step 3>

## Test Output
<captured stdout/stderr from test lab>

## Notes
Config.yml changes are staged locally but no PR was raised.
Use this page to root-cause the failure before retrying.
```

Do NOT raise a PR.

## Step 5b — On SUCCESS

### Update Confluence

Create a Confluence page using `mcp__mcp-atlassian-write__confluence_create_page`:
- `space_key`: `$CONFLUENCE_SPACE`
- `parent_id`: `$CONFLUENCE_PARENT_ID`
- `title`: `Oracle OTel $RELEASE_TAG — <today's date>`
- `content` (Markdown):

```markdown
## Result: PASS

**Release tag:** $RELEASE_TAG
**Date:** <today>

## Config Changes
<diff of what was applied to config.yml vs previous release>

## Grants (full list)
| Grant |
|-------|
<one row per GRANT SELECT line currently in config.yml>

## Metrics
| Metric | Enabled | Description |
|--------|---------|-------------|
<parse all metrics from /tmp/metadata_curr.yaml — one row per metric>

## Logs
| Log Type | Template File | Views Queried |
|----------|---------------|---------------|
<one row per .tmpl file: name, filename, comma-separated views from step 1>

## Test Result
PASS — <NR link if captured>
```

### Raise PR

```bash
cd $SC_REPO
git checkout -b oracle-otel-sync-$(echo $RELEASE_TAG | grep -oE 'v[0-9.]+$')
git add shared-component/configs/data-sources/oracle-otel/config.yml
git commit -m "feat(oracle-otel): sync grants and metrics for $RELEASE_TAG"
gh pr create \
  --title "feat(oracle-otel): sync grants and metrics for $(echo $RELEASE_TAG | grep -oE 'v[0-9.]+$')" \
  --body "Automated sync from nroracledbreceiver $RELEASE_TAG.

Confluence: <Confluence page URL from step above>

Changes:
<list grants added, metrics changed>"
```
```

- [ ] **Step 4: Verify the skill is discoverable**

With Claude Code open in `opentelemetry-collector-contrib`, type `/oracle-sync` and confirm it appears in the autocomplete list.

---

### Task 2: REVIEW + APPLY steps (already in skill file above — validate via dry-run)

**Files:**
- Modify: `opentelemetry-collector-contrib/.claude/skills/oracle-sync.md` (steps 2–3 already written in Task 1; this task validates them)

**Interfaces:**
- Consumes: DIFF output from Task 1
- Produces: Correctly patched `config.yml` with new grant lines in alphabetical order

- [ ] **Step 1: Run the skill through DIFF + REVIEW against the current tags**

Invoke: `/oracle-sync receiver/nroracledbreceiver/v0.157.2`

Confirm the skill:
1. Produces non-empty `[GRANT GAPS]` or correctly reports "no gaps"
2. Asks for approval before writing anything
3. Does NOT modify config.yml until you answer `y`

- [ ] **Step 2: Approve one grant gap and verify config.yml is patched correctly**

In the review prompt, approve adding one view (e.g. `SYS.V_$OSSTAT` if it's a gap).

After APPLY, check the grant was inserted in the correct location and format:
```bash
grep "V_\$OSSTAT" \
  /path/to/shared-component-framework-configs/shared-component/configs/data-sources/oracle-otel/config.yml
```

Expected output:
```
                  GRANT SELECT ON SYS.V_$OSSTAT TO c##${{ state.dbUsername.value }} CONTAINER=ALL;
```

- [ ] **Step 3: Verify alphabetical ordering**

```bash
grep "GRANT SELECT ON SYS.V_\$" \
  /path/to/shared-component-framework-configs/shared-component/configs/data-sources/oracle-otel/config.yml \
  | sort -c
```

Expected: `sort -c` exits 0 (already sorted, no disorder).

- [ ] **Step 4: Revert config.yml change (do not commit yet — leave for end-to-end test)**

```bash
git -C /path/to/shared-component-framework-configs checkout -- \
  shared-component/configs/data-sources/oracle-otel/config.yml
```

---

### Task 3: TEST + Confluence + PR steps (validate end-to-end)

**Files:**
- Modify: `opentelemetry-collector-contrib/.claude/skills/oracle-sync.md` (steps 4–5 already written; this task validates them with the real test lab)

**Interfaces:**
- Consumes: Patched config.yml from Task 2
- Produces: Confluence page created, PR raised in `shared-component-framework-configs`

- [ ] **Step 1: Confirm test lab command with the developer**

Ask: "What is the exact command to run the Terraform test lab for oracle-otel?"

Document the answer in the skill's `## Configuration` section under a `TEST_LAB_CMD` variable.

- [ ] **Step 2: Confirm Confluence space and parent page**

Ask: "What Confluence space key and parent page ID should release pages be created under?"

Update the skill's `## Configuration` section with `CONFLUENCE_SPACE` and `CONFLUENCE_PARENT_ID`.

- [ ] **Step 3: Run the full skill end-to-end**

Invoke: `/oracle-sync receiver/nroracledbreceiver/v0.157.2`

Walk through all steps. Verify:
1. DIFF produces the four sections
2. REVIEW pauses for approval
3. APPLY patches config.yml correctly
4. TEST runs the lab and returns pass/fail
5. On success: Confluence page created with grants table, metrics table, logs table
6. On success: PR raised in `shared-component-framework-configs` with correct title and body

- [ ] **Step 4: Check the Confluence page was created**

Using `mcp__mcp-atlassian-write__confluence_search`, search for `Oracle OTel receiver/nroracledbreceiver/v0.157.2` and confirm the page exists with all five sections (Result, Config Changes, Grants, Metrics, Logs).

- [ ] **Step 5: Check the PR was raised**

```bash
gh pr list --repo <org>/shared-component-framework-configs \
  --search "oracle-otel-sync"
```

Expected: one open PR with title containing `sync grants and metrics`.
