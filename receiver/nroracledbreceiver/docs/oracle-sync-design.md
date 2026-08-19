# Oracle Sync Skill Design

**Date**: 2026-08-05  
**Author**: Jyothi Surampudi  
**Team**: JumpStart (NR1 Dev Experience)

## Problem

Every ~2 weeks a new `nroracledbreceiver` binary is released. The release may add new metrics, new log event types, or new SQL queries that require additional Oracle view grants. The developer must manually:

1. Read the receiver README and source code for grant changes
2. Diff against `oracle-otel/config.yml` in `shared-component-framework-configs`
3. Update the config with new grants and metric/log flags
4. Run the Terraform test lab to verify data flows to NR
5. Update a Confluence page with the release snapshot
6. Raise a PR in `shared-component-framework-configs`

This is error-prone and time-consuming. The README can lag behind the actual source, meaning grants get missed silently.

## Goal

A project-scoped Claude skill `/oracle-sync` that any team member can invoke to run the full release sync cycle end-to-end. Stored at `.claude/skills/oracle-sync.md` in this repo — available to everyone who works here.

## Scope

- Self-hosted Oracle only (no RDS, no OCI)
- `nroracledbreceiver` only (not upstream `oracledbreceiver`)
- Multitenant (CDB + PDB) grant format: `CONTAINER=ALL`
- `enable_query_monitoring` is always enabled — no conditional grant logic needed

## Source Files

| File | What it provides |
|------|-----------------|
| `receiver/nroracledbreceiver/README.md` | Documented grants (self-hosted section) |
| `receiver/nroracledbreceiver/scraper.go` | Metric SQL queries and their views |
| `receiver/nroracledbreceiver/instance_info.go` | Instance detection SQL and views |
| `receiver/nroracledbreceiver/templates/*.tmpl` | Log event SQL queries and views (4 templates) |
| `receiver/nroracledbreceiver/metadata.yaml` | Enabled/disabled metrics and log types per release |

## Skill: `/oracle-sync`

**Invocation**: `/oracle-sync v1.3.0` or `/oracle-sync` (auto-detects latest tag)  
**Who runs it**: Any team member, every ~2 weeks on new binary release

### Step 1 — DIFF

At the given release tag, parse all source files and extract the full required grant set:

```
required_views = union(
  README.md grants (self-hosted section only),
  scraper.go SQL views,
  instance_info.go SQL views,
  templates/*.tmpl SQL views
)
```

Also parse `metadata.yaml` to extract which metrics and log types are enabled/disabled.

Diff against `shared-component-framework-configs/shared-component/configs/data-sources/oracle-otel/config.yml`:

- **[GRANT GAPS]** — views in `required_views` but missing from config.yml grant block
- **[README LAGS]** — views found in source/templates but absent from README (flag for README update too)
- **[METRIC CHANGES]** — metrics newly enabled or disabled vs previous release tag
- **[LOG CHANGES]** — log types added or removed vs previous release tag

### Step 2 — REVIEW

Present each delta to the developer interactively. Developer approves or skips each change before anything is written.

### Step 3 — APPLY

Patch `oracle-otel/config.yml` with approved changes:
- Add missing `GRANT SELECT ON` lines to the step5 grant block
- Update any metric enable/disable flags in the otel collector config snippet

### Step 4 — TEST

Invoke the Terraform test lab:
- Creates Oracle env, seeds data, checks NR ingest
- Poll for pass/fail result

### Step 5a — On FAILURE

Create a Confluence page with:
- Release tag and date
- Full diff that was applied
- Test result and error output
- No PR raised — failure snapshot preserved for root cause analysis

### Step 5b — On SUCCESS

Update Confluence with a versioned snapshot containing:
- Release tag and date
- Full grants list (as applied to config.yml)
- Metrics list (name + enabled/disabled state from metadata.yaml)
- Logs list (log types and their template queries)
- config.yml diff (what changed vs previous release)
- Test result: pass

Then raise a PR in `shared-component-framework-configs` with the config.yml changes.

## Flow Diagram

```
/oracle-sync v1.3.0
        │
        ▼
  1. DIFF
     README + scraper.go + instance_info.go + templates/*.tmpl + metadata.yaml
     → [GRANT GAPS] [README LAGS] [METRIC CHANGES] [LOG CHANGES]
        │
        ▼
  2. REVIEW  (developer approves each delta)
        │
        ▼
  3. APPLY   (patch config.yml in shared-component-framework-configs)
        │
        ▼
  4. TEST    (Terraform test lab)
        │
   ┌────┴────┐
 FAIL      PASS
   │          │
   ▼          ▼
Confluence  Confluence versioned snapshot
failure     (grants, metrics, logs, config diff, test result)
snapshot         │
                 ▼
            PR in shared-component-framework-configs
```

## Confluence Page Structure

Each release gets a versioned page:

```
Oracle OTel Release vX.Y.Z — YYYY-MM-DD
├── Test Result: PASS / FAIL
├── Config Changes (diff from previous release)
├── Grants List (full, as applied)
├── Metrics (name | enabled | description)
├── Logs (type | template | views queried)
└── Raw Diff Output (for root cause if FAIL)
```

## Out of Scope

- RDS or OCI hosting type grants
- Upstream `oracledbreceiver` (non-NR fork)
- Automated CI trigger (future upgrade path once skill is proven)
- Single-tenant (non-CDB) grant format
