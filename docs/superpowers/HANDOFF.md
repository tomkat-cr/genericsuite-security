# Handoff: repo-scanner skills

**Written:** 2026-08-06 · **Updated:** 2026-08-06 (phase 1 plan written)
**Branch:** `claude/handoff-docs-review-evioh5`

This note exists so a fresh session — on web, mobile, or another machine — can
pick this work up without the original conversation.

## Start here

Read the approved design, then the phase 1 plan's "Outcome" section (it records
what shipped and, more importantly, what was *not* verified):

```
docs/superpowers/specs/2026-08-06-repo-scanner-skills-design.md
docs/superpowers/plans/2026-08-06-repo-corpus-implementation-plan.md
```

**Phase 1 is implemented.** `skills/repo-corpus/` exists and its self-test
passes 31/31. Next is phase 2, `repo-docker-scanner`, which begins by consuming
a corpus.

Suggested opening prompt:

> Read `docs/superpowers/specs/2026-08-06-repo-scanner-skills-design.md` and
> `tmp/unpinned-image-detection-playbook.md`, then create an implementation
> plan for phase 2, `repo-docker-scanner`.

Phase 3 gets its own plan after that. Do not plan both at once — the spec's
"Implementation sequencing" section explains why.

## Verified on real hardware

Phase 1's last outstanding acceptance check is closed. On macOS (git 2.21,
bash 3.2), `./scripts/run_corpus.sh --org tomkat-cr --include prico` enumerated
100 repositories, selected and cloned 5, and reported a complete corpus. The
`gh` enumeration path, which the self-test can only cover via `--repos-json`,
now has a real run behind it.

Two things that run surfaced, both fixed:

- The driver crashed on macOS's bash 3.2 (empty-array expansion under `set -u`)
  and then reported the crash as "PARTIAL CORPUS" — a verdict about
  repositories for a run that never reached them. The driver now refuses to
  report any corpus outcome without a manifest to back it.
- Enumeration returned exactly 100, which is `gh`'s page size. Nothing warned.
  A capped list is the one incompleteness a manifest cannot express as a
  failure, so `build_corpus.py` now warns on `--limit` hits and on exact
  page-boundary counts.

**Still worth collecting:** corpus size with and without
`--default-branch-only` across a full org. `SKILL.md` quotes a one-repo sample,
which is not enough to revisit the D6 scope defaults on.

## Where things stand

**Done:**

- `CLAUDE.md` for this package (committed `c89b3a3`)
- Design spec brainstormed, reviewed, and committed (`3a7e0e4`)
- Phase 1 implementation plan for `repo-corpus`
- **Phase 1 implemented**: `skills/repo-corpus/` — `build_corpus.py`,
  `_walk.py`, `run_corpus.sh`, `SKILL.md`, self-test; marketplace path fixed
  and now guarded by an assertion

**Next:** plan and build phase 2 (`repo-docker-scanner`), then phase 3
(`repo-packages-scanner`).

> Note on tooling: the phase 1 plan was asked for via the
> `superpowers:writing-plans` skill, which was not installed in the session
> that wrote it. It was written directly against the spec in that skill's
> structure. If you have the skill available, use it for phases 2 and 3.

## What phase 1 built (the interface phase 2 consumes)

`repo-corpus` turns "an org, a user, or this directory" into safe, attributable
checkouts plus a `corpus.json` manifest. It produces **no findings** — that
separation is what makes single-repo lint mode and org-wide audit the same code
path in the two scanners that follow.

- `scripts/build_corpus.py` — `gh repo list` enumeration (or `--repos-json`);
  parallel hardened clones; `--local` mode for existing checkouts
- `scripts/_walk.py` — shared walking: prune counting, unreadable-path
  counting, and no symlink ever escaping its root
- `tests/selftest.py` — proves the hardening holds; 31 assertions
- `SKILL.md` — the manifest contract, in the section "The Manifest Is the
  Interface". Phase 2 should be written against those three rules.

Exit codes differ from the scanners in one way worth knowing before you write
phase 2: `1` means **partial corpus**, not findings. A scanner consuming a
corpus must read `totals.failed` and carry it into its own blind-spot section.

The security-sensitive part is the clone hardening: cloned repositories are
hostile input, and nothing from a clone is ever executed. Every flag is
asserted by the self-test, and each one was verified to fail the suite when
deleted. Do not simplify them away — each is there because of a specific
failure.

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
