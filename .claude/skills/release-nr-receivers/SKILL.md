---
name: release-nr-receivers
description: "Use when cutting a new tagged release of the newrelic-forks nr-prefixed receiver ecosystem (internal/nrcommon, internal/nrsqlquery, nroracledbreceiver, nrsqlserverreceiver, nrpostgresqlreceiver, and future nr-prefixed forks) on the bi-weekly cadence NRDOT depends on — independent of whether sync-and-port-nr-receivers found anything to port this cycle. Covers version derivation, always re-tagging internal modules, bumping receiver go.mod deps (including versioned pkg/* deps that pseudo-version alignment misses), reconciling upstream + fork-authored breaking changes, drafting NR_CHANGELOG.md, and — only after explicit user sign-off — tagging and pushing."
---

# Release & Tag NR-Prefixed Receivers

Cuts a new release of the `newrelic-forks` receiver ecosystem — `internal/nrcommon`,
`internal/nrsqlquery`, and every `nr`-prefixed receiver (`receiver/nrsqlserverreceiver`,
`receiver/nroracledbreceiver`, `receiver/nrpostgresqlreceiver`, and future forks) — on the same
version number, independent of whether any of them actually changed this cycle.

This exists because NRDOT (the downstream consumer) bumps to a new upstream contrib release every
~2 weeks and cannot bump past whatever version the `nr`-prefixed forks are pinned at (OCB requires
every bundled component to match the core/contrib minor). NRDOT Platform (Kristof Bauer / Ansen
Garvin, 2026-07-30) asked for exactly this: a release "on a regular basis... independent of whether
you made changes," plus a changelog they can point to for breaking changes. Run this on the same
bi-weekly cadence as upstream contrib releases — do not wait for [[sync-and-port-nr-receivers]] to
find something to port; run this even when Phase 2 there was a no-op.

**Relationship to [[sync-and-port-nr-receivers]]:** that skill answers "did we pull in upstream's
new metrics/queries." This skill answers "is there a tagged release NRDOT can consume, and does its
changelog say what changed." Run sync-and-port first if there's a new upstream release to absorb;
either way, run this skill every cycle to cut the release.

**Stop-and-wait point:** Phase 3 (drafting `NR_CHANGELOG.md`) is the last step you do without
explicit sign-off. Do not tag or push (Phase 4) until the user has reviewed the changelog draft and
told you to proceed — they will say so explicitly ("go ahead", "tag it", etc.). Everything through
Phase 3 can run to completion on its own; Phase 4 requires a stop.

## Environment quirks (same as sync-and-port-nr-receivers)

- `go` is often NOT on PATH in the tool shell. Use `/usr/local/go/bin/go`.
- Do NOT `cd` inside compound commands. Use `go <cmd> -C <dir>` and absolute paths.
- Tag names follow `<module-path>/vX.Y.Z`, e.g. `internal/nrcommon/v0.157.1`,
  `receiver/nrsqlserverreceiver/v0.157.1` — this is the existing convention (`git tag -l` to confirm
  before assuming a format). Do not invent a different tag shape.
- Never `git commit` on the user's behalf unless they've asked you to in this specific session. Tags
  can point at a commit the user made themselves (check `git log -1` — if the port work already
  landed as a commit outside your actions, that's fine and expected; don't second-guess it).

## Phase 1 — Determine the target version

1. Fetch `upstream` and `origin`. Find the newest `vX.Y.Z` tag reachable from `origin/main` (or
   `upstream/main` if they're equal — confirm equality first, same check as sync-and-port Phase 1
   step 1). That is the target version for this cycle, e.g. if `origin/main` is at contrib `v0.157.0`,
   the target is `v0.157.0` (or `v0.157.1` if `internal/nrcommon`/`internal/nrsqlquery` need a patch
   bump distinct from the receivers — see step 2).
2. Check the *current* tags on `internal/nrcommon` and `internal/nrsqlquery`
   (`git tag -l "internal/nrcommon/*" "internal/nrsqlquery/*" | sort -V`) and on each receiver
   (`git tag -l "receiver/nr<name>receiver/*" | sort -V`). This just tells you the starting point —
   every module gets re-tagged at the target version this cycle regardless (see Phase 2), so this
   step is about knowing what's changing, not deciding whether to act.
3. Report the target version and the current state (what's tagged now vs. what will be tagged) before
   proceeding — this is informational, not a stop point.

## Phase 2 — Tag `internal/nrcommon` and `internal/nrsqlquery`, then update receiver deps

Always re-tag both internal modules every cycle, even with zero source changes — the goal is a
version number that moves forward every release, per NRDOT's ask. A tag with no code change behind
it is still a legitimate release; do not skip it because "nothing changed."

1. For each of `internal/nrcommon`, `internal/nrsqlquery`:
   - `go mod tidy -C <mod>` — must produce zero diff. If it produces a diff, something is actually
     stale; investigate before tagging (the tidy fix belongs in the tag).
   - `go build -C <mod> ./...` and `go test -C <mod> ./...` — must be green.
   - `go mod verify -C <mod>` — must pass.
   - Confirm `git status --short <mod>` is clean (no uncommitted changes to tag around — if there
     are, that's the user's call whether to commit first; don't assume).
   - Tag `HEAD` at the target version: `git tag internal/nrcommon/vX.Y.Z HEAD` (same for nrsqlquery).
2. For each nr-prefixed receiver (`receiver/nrsqlserverreceiver`, `receiver/nroracledbreceiver`,
   `receiver/nrpostgresqlreceiver`, and any future ones — re-derive this list from the directory
   listing, don't hardcode a count):
   - `go mod edit -C <receiver> -require=.../internal/nrcommon@vX.Y.Z` (and `nrsqlquery` if the
     receiver depends on it — check with `grep nrsqlquery <receiver>/go.mod` first, not every
     receiver does, e.g. `nroracledbreceiver` doesn't).
   - Check the base receiver's own `pkg/*` deps for the SAME versioned (not pseudo-versioned)
     contrib packages the fork also depends on — `pkg/golden`, `pkg/pdatatest`,
     `pkg/winperfcounters` (sqlserver only), and any others: `grep 'opentelemetry-collector-contrib/pkg/'
     receiver/<base>/go.mod` vs the fork's. These carry real version numbers (e.g. `v0.157.0`), NOT
     pseudo-versions, so they drift silently and sync-and-port's pseudo-version alignment step does
     NOT catch them — this is a distinct check every cycle, not covered elsewhere. Bump any that
     lag behind base with `go mod edit -C <receiver> -require=.../pkg/<name>@vX.Y.0`.
   - `go mod tidy -C <receiver>` — should produce zero *unexpected* diff (the version bumps
     themselves are expected; anything beyond that needs investigation).
   - `go build -C <receiver> ./...` and `go test -C <receiver> ./...` — green.

## Phase 3 — Breaking-change reconciliation + draft `NR_CHANGELOG.md`

1. For each fork↔base pair, find every `.chloggen/*.yaml` entry added to the base receiver's history
   between the previous cycle's tracked upstream version and this cycle's target version:
   `git log --format=%H <prev-upstream-tag>..<new-upstream-tag> -- .chloggen/`, then for each commit,
   `git show --diff-filter=A --name-only <commit> -- .chloggen/` to find newly-added files, then read
   each for `component:` matching `receiver/sqlserver`, `receiver/oracledb`, `receiver/postgresql`,
   `receiver/mysql` (or whichever base receivers have an nr-prefixed fork) and `change_type: breaking`.
   ("Previous cycle's tracked upstream version" — read it from last cycle's `NR_CHANGELOG.md` section
   header, e.g. "Tracks upstream contrib v0.156.0 and v0.157.0" tells you the last cycle covered up
   to v0.157.0, so this cycle starts there.)
2. For each breaking-change entry found: check whether the fork already matches upstream's new
   behavior (same technique as sync-and-port Phase 2 — diff the specific query/template/metric
   definition named in the chloggen note) or whether it needs porting. If it needs porting, that's
   sync-and-port-nr-receivers' job — pause and hand off / ask the user whether to run that skill first,
   don't duplicate its porting logic here.
3. Separately, check each fork's own git history since its last tag for fork-authored breaking
   changes (metric/attribute removals or format changes made only in the fork, not inherited from
   upstream) — `git log <last-fork-tag>..HEAD --oneline -- receiver/<fork>/`, look for anything that
   removes or reshapes a fork-specific metric/attribute.
4. Draft a new `## vX.Y.Z` section at the top of `/NR_CHANGELOG.md` (create the file at repo root,
   matching the header/structure of the base `CHANGELOG.md`, if it doesn't exist yet), right after
   the `<!-- next version -->` marker. **Filename must NOT match `CHANGELOG*.md`** —
   `.github/workflows/changelog.yml`'s "Ensure no changes to the CHANGELOG.md or CHANGELOG-API.md"
   step diffs `./CHANGELOG*.md` unconditionally on every PR and fails the build if anything matching
   that glob changed (a first attempt at `NR_CHANGELOG.md` hit exactly this and had to be renamed).
   Structure:
   - A line noting which upstream releases this cycle tracks (e.g. "Tracks upstream contrib v0.156.0
     and v0.157.0") — this is what lets the next cycle know where to resume the chloggen sweep.
   - `### 🛑 Breaking changes 🛑` — one bullet per item from steps 1–3. For adopted-from-upstream
     items, ALWAYS state the verdict explicitly: "already matched, no fork change needed" or "ported:
     <what changed>". Do not omit the ones where nothing needed to change — that confirmation is the
     valuable signal, not a skippable formality.
   - `### 🚩 New components 🚩` (reuse only if there's something to list) — additive metrics/queries
     ported this cycle, one bullet per fork, referencing the upstream issue/PR.
5. Leave `NR_CHANGELOG.md` uncommitted. **Stop here.** Report the draft to the user and wait for
   explicit approval before Phase 4. Do not proceed on your own judgment that the draft "looks done."

## Phase 4 — Tag receivers and push (only after user sign-off)

1. Confirm the user has reviewed and approved the `NR_CHANGELOG.md` draft, and — if they wanted the
   go.mod bumps / changelog committed first — that a commit exists. Check `git log -1` and
   `git status` to see what's actually committed vs. still unstaged; don't assume either way.
2. Tag each nr-prefixed receiver at the target version, pointing at the commit that contains the
   changelog + go.mod bumps: `git tag receiver/nrsqlserverreceiver/vX.Y.Z <commit>` (same pattern for
   every other nr-prefixed receiver).
3. Before pushing anything, confirm with the user which remote (`origin` only, unless told otherwise)
   and get explicit go-ahead — tag pushes are visible to every consumer (including NRDOT) the moment
   they land, and are not something to undo casually.
4. `git push origin <tag1> <tag2> ...` — push all of this cycle's tags (internal modules from Phase 2
   plus receivers from this phase) in one go, in one message, so a partial push isn't left half-done
   if you have to stop and ask something mid-way.
5. Report: target version, which modules got tagged today vs. carried forward with no code change,
   the changelog section that shipped, and the pushed tag list.

## Output

Report per cycle: target version and how it was derived, Phase 2 build/test/tidy results per module,
the breaking-change reconciliation findings (adopted vs. needs-porting vs. fork-authored), the
`NR_CHANGELOG.md` draft, and — once approved — the final tag list and push confirmation. If Phase 3
surfaces a breaking change that still needs porting, say so clearly and suggest running
sync-and-port-nr-receivers before finishing this cycle's release, rather than silently skipping it.
