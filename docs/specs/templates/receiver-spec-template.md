# {Database} Receiver Spec

## Status: Draft | Approved | Living
Last updated: {date} via PR #{number} ({JIRA-ticket})
Approved by: {name}

---

## Receiver Identity

| Field | Value |
|-------|-------|
| Component | receiver/{name}receiver |
| Stability | Metrics: {alpha/beta} / Logs: {development/alpha/beta} |
| Database versions supported | {e.g., PostgreSQL 12+, Oracle 19c+} |
| Driver | {go package and version} |
| Priority | {HIGH/MEDIUM} |

---

## Metrics & Log Events

Defined in `metadata.yaml` — the single source of truth for metric names, types, units,
enabled/disabled defaults, attributes, and log event schemas. Currently: **{N} metrics**
({M} enabled, {K} disabled), **{L} log events** (both disabled by default).

Do NOT duplicate the metrics catalog here. Any new metric or attribute change starts
in `metadata.yaml`, then gets wired through the implementation patterns below.

### Adding

| OTel Name | Type | Unit | Enabled | Source Query | Priority | Jira | Status |
|-----------|------|------|---------|-------------|----------|------|--------|
| — | — | — | — | — | — | — | — |

---

## Query Source Map

Each metric group is sourced from a specific SQL query. The query functions are in `{queries file}`.

| Query Function / Constant | Source View / Table | Metrics Group | Notes |
|--------------------------|---------------------|---------------|-------|
| {function or constant name} | {DMV, system view, or table} | {metric names or group} | {filter, join, or template info} |

---

## Configuration

### Schema

```yaml
receivers:
  {name}:
    # Connection
    {fields with defaults and comments}

    # Collection
    collection_interval: 10s
    initial_delay: 1s

    # Top query collection (if applicable)
    top_query_collection:
      {fields}

    # Query sample collection (if applicable)
    query_sample_collection:
      {fields}
```

### Validation Rules (from `config.go:Validate()`)

| Rule | Error |
|------|-------|
| {condition} | {error message or behavior} |

### Connection String Construction (from `factory.go` or `client.go`)

{Describe how the connection string is built from config fields}

---

## Implementation Patterns

### How Scrapers Are Created

{Describe the factory → scraper creation flow specific to this receiver.
Include: what triggers scraper creation, how metrics/logs scrapers differ,
any feature gates that affect creation.}

### Traced Example: Adding a Metric from {Primary Source}

To add `{receiver}.new_metric` sourced from `{primary stats view}`:

**Step 1: metadata.yaml** — Add the metric definition.
**Step 2: Run `make generate`** in receiver directory.
**Step 3: {queries/client file}** — Add the query or column extraction.
**Step 4: scraper.go** — Add recording logic.
**Step 5: factory.go** — Wire metric enablement check.
**Step 6: Tests** — Add test data and golden files.

{Include code snippets showing the exact pattern used in this receiver}

### Traced Example: Adding a Metric from {Alternative Source} (if applicable)

{Same pattern for a different collection path, e.g., new DMV, new stats view}

### How Cache and Delta Computation Works (if applicable)

{Describe the caching strategy: key format, delta logic, cache size, eviction}

### How Query Obfuscation Works

{Describe obfuscation: library used, DBMS mode, what gets obfuscated, failure behavior}

### How Resource Attributes Are Set

{Describe how resource attributes are populated from config and query results}

### Feature Gates (if applicable)

| Gate ID | Stage | Effect |
|---------|-------|--------|
| {gate ID} | {alpha/beta/stable} | {what it does} |

### Receiver-Specific Patterns (if applicable)

{Document any unique patterns: multi-database iteration, trace context propagation,
connection pooling, platform-specific behavior, etc.}

---

## Test Patterns

### Unit Tests

Pattern: {describe the primary test pattern — mock client, fake data, etc.}

{Include a representative code example showing how to add a new test case}

**To add test data for a new query:**
1. {step 1}
2. {step 2}
3. {step 3}

### Integration Tests

Pattern: {testcontainers-go, docker-compose, etc.}

{Describe setup: container image, init scripts, build tags}

### Safety Tests (if applicable)

{Describe any meta-tests that enforce consistency, e.g., metric count assertions}

---

## Error Handling

| Scenario | Behavior | Code Location |
|----------|----------|---------------|
| Connection refused | {behavior} | {file:function} |
| Auth failure | {behavior} | {file:function} |
| Query timeout | {behavior} | {file:function} |
| Permission denied | {behavior} | {file:function} |
| {receiver-specific scenarios} | {behavior} | {file:function} |

---

## Permissions

### Minimum (metrics only)

```sql
{exact GRANT statements}
```

### Query samples (additional)

```sql
{exact GRANT statements}
```

### Top queries (additional)

```sql
{exact GRANT statements or extension requirements}
```

---

## Dependencies on Shared Code

| Package | Used For |
|---------|----------|
| {package path} | {what it provides} |

---

## Rollout Phases

### Phase 1: Foundation (P0)
- Metrics: {count and description}
- Config: {new fields or "no new fields"}
- Jira epic: TBD

### Phase 2: Advanced (P1)
- Metrics: TBD
- Jira epic: TBD

### Phase 3: Polish (P2)
- Metrics: TBD
- Jira epic: TBD

---

## Open Questions

| # | Question | Owner | Status |
|---|----------|-------|--------|
| 1 | {question} | {PM/arch} | Open |

---

## Change Log

| Date | PR | Section | What Changed | Why |
|------|-----|---------|-------------|-----|
