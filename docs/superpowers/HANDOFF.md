# Handoff: repo-scanner skills

**Written:** 2026-08-06 · **Updated:** 2026-08-06 (phase 1 plan written)
**Branch:** `claude/handoff-docs-review-evioh5`

This note exists so a fresh session — on web, mobile, or another machine — can
pick this work up without the original conversation.

## Start here

Read the approved design, then the phase 2 plan's Outcome section:

```
docs/superpowers/specs/2026-08-06-repo-scanner-skills-design.md
docs/superpowers/plans/2026-08-07-repo-docker-scanner-implementation-plan.md
```

**Phases 1 and 2 are implemented.** `repo-corpus` (54 assertions) and
`repo-docker-scanner` (54 assertions) both pass their self-tests. Next is
phase 3, `repo-packages-scanner`, which reuses every convention settled in
phase 2 and absorbs `run_gh_scan.sh` from `supply-chain-ioc-scan`.

Suggested opening prompt:

> Read `docs/superpowers/specs/2026-08-06-repo-scanner-skills-design.md` and
> `skills/repo-docker-scanner/`, then create an implementation plan for
> phase 3, `repo-packages-scanner`.

## Calibration: first real signal in, one real gap found and fixed

The author ran `./scripts/run_docker_scan.sh --org tomkat-cr --include prico
--branch develop` on real hardware and shared the three report files back. That
is a first slice of Task 12's calibration run — one repo (`prico`; the other
four `prico*` repos were correctly skipped for lacking a `develop` branch,
which is `--branch`'s designed behaviour, not a bug) — and it found a real
tier-boundary gap on the first try:

A docker reference inside a CloudFormation template
(`server/scripts/aws_ec2_elb/template-cf-ec2-elb.yml`) landed at **P1
"default when no rule matches"** instead of P0, because no `priority_rules`
glob named that directory as production. The same class of gap `*.tf` was
supposed to close for Terraform had no CloudFormation equivalent. Fixed by
content-sniffing CloudFormation (`AWSTemplateFormatVersion`, or a `Type:
AWS::…` resource block) the same way a renamed Dockerfile is caught by content
rather than filename — so it tiers P0 regardless of where in the tree it
lives, instead of trying to enumerate every IaC directory-naming convention by
glob.

The same run also surfaced a cosmetic-but-trust-eroding bug: a
template-composed reference (`${ECRRepositoryName}` etc., class `unresolved`)
was having the image-reference normalizer run on it, which lowercased one
`${...}` segment while leaving another untouched in the same string — reading
as the tool corrupting the user's own text. Unresolved references are now
reported and inventoried verbatim.

**Still open — the wider calibration.** This was one repo. Run the full org
scan and read the tier histogram:

```bash
cd skills/repo-docker-scanner
./scripts/run_docker_scan.sh --org tomkat-cr
```

If P0 still lights up with dozens of findings, the boundary is wrong
regardless of how defensible it looks — the gate gets switched off and the
scanner becomes decoration. Retuning is a `policy/images.json` edit, never a
code change. Then run `probe.py` with two or three image names known to be in
use; every unexplained hit is a detector bug.

One more thing worth knowing before reading a baseline-suppressed report: two
findings for the *same reference in the same file* on different lines share
one fingerprint (deliberately — see `SKILL.md`'s Baseline section), so
baselining one occurrence baselines every occurrence of that reference in that
file, not just the line reviewed.

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
