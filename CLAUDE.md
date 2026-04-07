@AGENTS.md

# New Relic Database Receiver Development

## Project Context

We are developing production-grade enhancements to 4 database receivers in this
OpenTelemetry Collector Contrib fork: sqlserverreceiver, oracledbreceiver,
postgresqlreceiver, and mysqlreceiver.

**Priority order:** SQL Server, Oracle (customer-driven), then PostgreSQL, MySQL.

**Development model:** Spec-anchored. Claude Code writes all code, specs, and tests.
Humans provide intent, review, and approve. No code is written by hand.

**What spec-anchored means:**
- Specs are written before code
- Specs are maintained alongside code as features evolve
- Specs and code travel together in the same PR
- Humans review and edit both spec and code
- Specs guide but do not replace code — code is the executable artifact

## Team Structure

| Role | Scope |
|------|-------|
| Platform architect (principal) | Root CLAUDE.md, spec templates, cross-receiver patterns, final review |
| SQL Server team (lead + junior) | receiver/sqlserverreceiver/ |
| Oracle team (senior + junior) | receiver/oracledbreceiver/ |
| PostgreSQL team (2 juniors) | receiver/postgresqlreceiver/ |
| MySQL team (1 junior) | receiver/mysqlreceiver/ |
| PM | Confluence: PRD, competitive analysis, customer asks |

## Source of Truth Hierarchy

When information conflicts, follow this priority:

1. `docs/specs/{receiver}-spec.md` — most specific, wins
2. `docs/specs/decisions/*.md` — architectural decisions (ADRs)
3. `docs/specs/patterns.md` — cross-receiver shared patterns
4. `receiver/{name}/CLAUDE.md` — receiver-specific context and known issues
5. This file (root CLAUDE.md) — global process and conventions
6. `AGENTS.md` — upstream OTel AI contribution rules
7. `CONTRIBUTING.md` — upstream build/test/lint instructions

## Workflow Rules

### Before Writing Any Code

1. Read the receiver spec: `docs/specs/{receiver}-spec.md`
2. Read the receiver CLAUDE.md: `receiver/{name}/CLAUDE.md`
3. Read any relevant ADRs: `docs/specs/decisions/`
4. Read the Jira ticket for the current task
5. Understand what exists before changing it

### Workflow Tiering

Not every change needs spec ceremony:

- **Bug fix / small tweak:** Read spec, fix code, PR. Update spec only if fix reveals spec was wrong.
- **New metric / config option:** Add row to spec, implement, PR with both.
- **New feature:** Write feature section in spec, get approval, implement, PR with both.
- **Cross-cutting change:** Write ADR, get architect approval, implement across receivers.

### Branching

- NEVER commit directly to `main`
- Create feature branches: `feat/{receiver-short}/{feature-name}`
  - Examples: `feat/sqlserver/connection-pooling`, `feat/oracle/query-obfuscation`
- Bug fix branches: `fix/{receiver-short}/{bug-description}`
- One branch per Jira ticket
- Branch from `main` unless building on another feature

### Commits

- Include Jira ticket in commit message: `[DBMON-XXX] description`
- Add AI disclosure trailer per AGENTS.md:
  ```
  Assisted-by: Claude Opus 4.6
  ```
- Small, focused commits — one logical change per commit
- Run tests before committing: `cd receiver/{name} && make test`
- Run lint before committing: `cd receiver/{name} && make lint`

### Pull Requests

- Title format: `[receiver/{name}] Short description (DBMON-XXX)`
- PR body must reference: Jira ticket, which spec section this implements, any spec changes
- NEVER merge — only create PRs for human review

### Spec Maintenance

Specs are living documents. They travel with code:

- If implementation reveals the spec is wrong or incomplete: STOP coding
- Document what the spec says vs what reality requires
- Update the spec in the SAME branch/PR as the code change
- Mark spec changes with a row in the spec's Change Log table
- Spec changes require PM or platform architect approval in PR review

### What Claude Must NEVER Do Autonomously

- Merge branches or PRs
- Modify root CLAUDE.md (only platform architect does this)
- Modify another receiver's files (stay in your receiver)
- Skip tests or lint
- Ignore spec — if spec doesn't cover your task, ask the engineer
- Push to main
- Delete branches

## Coding Standards

### Follow Existing Patterns

These receivers already exist with established patterns. Follow them:

- Factory pattern: `factory.go` — do not restructure
- Scraper pattern: `scraper.go` — follow existing collection approach
- Config pattern: `config.go` — extend, don't replace
- Metadata: `metadata.yaml` — use mdatagen for metric definitions

### Testing Requirements

- Every code change MUST have tests
- Unit tests: use existing patterns (sqlmock, fake clients, table-driven tests)
- Integration tests: use testcontainers where the receiver already has them
- Run full receiver test suite before committing, not just new tests

### Quality Gates (must pass before PR)

1. `make lint` passes in receiver directory
2. `make test` passes in receiver directory
3. Spec is consistent with implementation
4. No secrets, credentials, or sensitive data in code or comments

## Shared Patterns (see docs/specs/patterns.md)

All receivers share these patterns. Use them consistently:

- Query obfuscation via DataDog obfuscate package
- LRU caching via hashicorp/golang-lru
- Metric definitions via metadata.yaml + mdatagen
- Error handling: wrap with context, never swallow
- Logging: use `zap.Logger` from receiver settings

When adding a new cross-cutting pattern, propose it as an ADR in
`docs/specs/decisions/` and get platform architect approval.

## Build & Test Reference

```bash
# Build entire collector
make otelcontribcol

# Test a single receiver
cd receiver/{name} && make test

# Lint a single receiver
cd receiver/{name} && make lint

# Generate code from metadata.yaml
cd receiver/{name} && make generate

# Create changelog entry
make chlog-new
```

## Confluence & Jira

Product requirements, competitive analysis, customer asks, and UI mocks are in
Confluence (private). Claude can access these via MCP tools when writing or
updating specs.

Jira project: [TO BE FILLED]
Confluence space: [TO BE FILLED]

## Updating This File

Only the platform architect modifies this file. If you believe a process change
is needed, raise it in your PR description or Jira comment — don't edit CLAUDE.md
directly.
