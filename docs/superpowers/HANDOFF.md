# Handoff: repo-scanner skills

**Written:** 2026-08-06 · **Updated:** 2026-08-06 (phase 1 plan written)
**Branch:** `claude/handoff-docs-review-evioh5`

This note exists so a fresh session — on web, mobile, or another machine — can
pick this work up without the original conversation.

## Start here

Read the approved design, then the phase 1 plan:

```
docs/superpowers/specs/2026-08-06-repo-scanner-skills-design.md
docs/superpowers/plans/2026-08-06-repo-corpus-implementation-plan.md
```

The plan is written and ready to execute — **do not re-plan phase 1**. Work
its eight tasks in order; each states its acceptance check before the work, and
a task is done when the check passes, not when the code looks finished.

Suggested opening prompt:

> Read `docs/superpowers/plans/2026-08-06-repo-corpus-implementation-plan.md`
> and implement it, task by task.

Phases 2 and 3 get their own plans, written only once the phase before them
passes its self-test. Do not plan all three skills at once — the spec's
"Implementation sequencing" section explains why, and the phases are
deliberately ordered so each one is independently verifiable.

## Where things stand

**Done:**

- `CLAUDE.md` for this package (committed `c89b3a3`)
- Design spec brainstormed, reviewed, and committed (`3a7e0e4`)
- Phase 1 implementation plan for `repo-corpus`

**Not started:** all implementation. No scanner code exists yet.

**Next:** execute the phase 1 plan, then plan and build phase 2
(`repo-docker-scanner`), then phase 3 (`repo-packages-scanner`).

> Note on tooling: the plan was asked for via the `superpowers:writing-plans`
> skill, which was not installed in the session that wrote it. It was written
> directly against the spec in that skill's structure. If you have the skill
> available, use it for phases 2 and 3.

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

Two things were called out as most worth a second look:

- **`repo-corpus` scope defaults.** *Resolved in the phase 1 plan (D6):* keep
  them broad — archived, forks, and non-default branches all included —
  following the principle already load-bearing in `supply-chain-ioc-scan`, that
  narrowing scope is how a scan misses what it was run to find. The bandwidth
  cost gets measured during Task 8 and quoted in `SKILL.md`, so revisiting the
  default later is an argument about numbers rather than taste.
- **The P0/P1/P2 priority models** in both scanners. **Still open**, and
  deliberately not addressed by the phase 1 plan — it belongs to phases 2 and
  3. This is what turns "400 findings" into something a maintainer acts on. If
  the tier boundaries are wrong, the reports are noise.

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
