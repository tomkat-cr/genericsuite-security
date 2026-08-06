# Handoff: repo-scanner skills

**Written:** 2026-08-06 · **Branch:** `develop` · **Last commit at handoff:** `3a7e0e4`

This note exists so a fresh session — on web, mobile, or another machine — can
pick this work up without the original conversation.

## Start here

Read the approved design first:

```
docs/superpowers/specs/2026-08-06-repo-scanner-skills-design.md
```

Then invoke the `superpowers:writing-plans` skill to turn **phase 1 only**
(`repo-corpus`) into an implementation plan. Do not plan all three skills at
once — the spec's "Implementation sequencing" section explains why, and the
phases are deliberately ordered so each one is independently verifiable.

Suggested opening prompt:

> Read `docs/superpowers/specs/2026-08-06-repo-scanner-skills-design.md`, then
> use the writing-plans skill to create an implementation plan for phase 1,
> `repo-corpus`.

## Where things stand

**Done:**

- `CLAUDE.md` for this package (committed `c89b3a3`)
- Design spec brainstormed, reviewed, and committed (`3a7e0e4`)

**Not started:** all implementation. No scanner code exists yet.

**Next:** implementation plan for phase 1 (`repo-corpus`), then phase 2
(`repo-docker-scanner`), then phase 3 (`repo-packages-scanner`).

## Phase 1 scope at a glance

`repo-corpus` turns "an org, a user, or this directory" into safe, attributable
checkouts plus a `corpus.json` manifest. It produces **no findings** — that
separation is what makes single-repo lint mode and org-wide audit the same code
path in the two scanners that follow.

Roughly:

- `scripts/build_corpus.py` — `gh repo list` enumeration; parallel hardened
  clones; `--local` mode for a single existing checkout
- `scripts/_walk.py` — shared file walking with vendored-path pruning and
  unreadable-path counting
- `tests/selftest.py` — proves the hardening actually holds
- `SKILL.md`
- Fix the wrong skill path in `.claude-plugin/marketplace.json` and register the
  new skills

The security-sensitive part is the clone hardening: cloned repositories are
hostile input, and nothing from a clone is ever executed. The spec's
"Cloning: cloned repos are hostile input" section has the exact flags and the
three non-obvious details behind them (inline credential helper, clone-to-temp
then rename, depth-1 across all branches). Do not simplify those away — each one
is there because of a specific failure.

## Decisions already made — don't relitigate

Four choices were made explicitly during brainstorming. Three carry costs that
are documented in the spec's "Recorded trade-offs" section, so they look like
mistakes if you meet them without context:

1. **Independent per-skill reports**, no cross-scan combiner — duplicates SARIF
   and baseline code across two skills, chosen for skill self-containment.
2. **All branches cloned by default** — costs bandwidth for a blind spot the
   source playbook calls marginal. `--default-branch-only` is the escape hatch.
3. **`run_gh_scan.sh` moves to `repo-packages-scanner`** — domain-mismatched
   (it detects compromise, not unpinned deps), explicitly requested, and to be
   documented in a clearly separate `SKILL.md` section.
4. **No auto-fix branches or PRs in v1** — deliberately deferred as the riskiest
   surface with no detection value.

## Open questions the author flagged

Two things were called out as most worth a second look, and neither has been
resolved:

- **`repo-corpus` scope defaults.** Currently broad (archived, forks, and
  non-default branches all included), following the principle already
  load-bearing in `supply-chain-ioc-scan`: narrowing scope is how a scan misses
  what it was run to find.
- **The P0/P1/P2 priority models** in both scanners. This is what turns "400
  findings" into something a maintainer acts on. If the tier boundaries are
  wrong, the reports are noise.

## Context worth knowing

- This package is a **git submodule** of the `genericsuite` superproject. Opened
  standalone, you get this package's `CLAUDE.md` but not the monorepo-wide one
  at the superproject root. Everything phase 1 needs is package-local.
- The source material for `repo-docker-scanner` is
  `tmp/unpinned-image-detection-playbook.md` (tracked in git, so it travels with
  the repo). Phase 2 is essentially an implementation of that playbook,
  including its false-positive catalogue and the four grep-filter bugs it
  documents — those become regression assertions, not prose.
- `skills/supply-chain-ioc-scan/` is the house style reference. Match its
  conventions rather than inventing new ones: JSON policy profiles, a self-test
  that proves detection works, Python over bash, exit codes `0`/`1`/`2`, and
  reports that state their own blind spots.
