# Feature: {Feature Name}

**Receiver:** {receiver name}
**Jira:** {ticket ID}
**Spec section:** References {receiver}-spec.md Section {N}
**Status:** Draft | Approved | Implemented

## What

{1-2 sentences: what this feature does}

## Why

{Why this is needed — reference competitive analysis or customer ask}

## How

### Implementation Approach

{Technical approach — which files change, what the code does}

### Files Modified

| File | Change Type | Description |
|------|------------|-------------|
| `scraper.go` | modify | {what changes} |
| `client.go` | modify | {what changes} |
| `scraper_test.go` | modify | {new test cases} |

### New Dependencies

{Any new packages needed, or "None"}

### Config Changes

```yaml
# New or modified config fields
{yaml}
```

### Database Requirements

```sql
-- New permissions or extensions needed
{sql}
```

## Acceptance Criteria

- [ ] {specific, testable criterion}
- [ ] {specific, testable criterion}
- [ ] Tests pass: unit + integration
- [ ] Spec updated if approach deviated

## Change Log

| Date | PR | What Changed | Why |
|------|-----|-------------|-----|
