# Handoff: repo-scanner skills

**Written:** 2026-08-06 · **Updated:** 2026-08-08 (phase 3 implemented — all
three phases of the design are now complete)
**Branch:** `claude/handoff-docs-review-evioh5`

This note exists so a fresh session — on web, mobile, or another machine — can
pick this work up without the original conversation.

## All three phases are implemented

`repo-corpus` (54 assertions), `repo-docker-scanner` (63 assertions),
`repo-packages-scanner` (63 assertions) all pass their self-tests. The
sequencing the spec's "Implementation sequencing" section called for is
complete. What's left is calibration and hardening, not new skills — see below.

Read the design spec first, then whichever phase's plan is relevant:

```
docs/superpowers/specs/2026-08-06-repo-scanner-skills-design.md
docs/superpowers/plans/2026-08-08-repo-packages-scanner-implementation-plan.md   (phase 3, latest)
docs/superpowers/plans/2026-08-07-repo-docker-scanner-implementation-plan.md      (phase 2)
docs/superpowers/plans/2026-08-06-repo-corpus-implementation-plan.md              (phase 1)
```

## A lesson worth internalizing before touching any of these reports

A hand-written "Priority tiers explained" section was added directly to
`repo-docker-scanner`'s report (bypassing this session) and immediately
described the **wrong scanner** — its P0/P1/P2 prose was `repo-packages-scanner`'s
tier language from the design spec, copy-pasted into the container-image
scanner's own report. It shipped live and wrong before anyone read it closely.

The fix, applied to both scanners: the priority-tier legend in `report.md` is
**generated from `policy/*.json`'s `priority_rules`**, never hand-written
prose. `repo-packages-scanner` was built with this from its first commit
(`_report.py`'s `_priority_legend_lines()`), specifically so it would not
repeat the mistake its sibling had just made. If you ever find yourself typing
a `- **P0** — ...` line by hand into either scanner's `_report.py`, stop — add
or edit a `priority_rules` entry in the policy JSON instead. Both self-tests
assert every distinct rule reason appears in the rendered legend, so a
generator that stops reading the policy correctly also fails loudly.

## What each report now states, right after the summary (both scanners)

Requested explicitly and load-bearing for anyone reading a report cold:

1. **Scan command** — the literal top-level invocation
   (`./scripts/run_*_scan.sh --org … --branch …`), captured by the driver
   *before* it consumes or rewrites any argument, since `--org`/`--include`/
   `--branch` resolve into a `--corpus` path long before the Python scanner
   ever sees its own argv. Falls back to reconstructing argv when the Python
   script is run directly.
2. **Repositories and branches analyzed** — every repo/branch/HEAD SHA the
   scan actually walked, not just a count. A `--branch`- or `--include`-
   filtered corpus can mean "no findings" covers one repo out of forty.
3. **Priority tiers** — the generated legend described above.

Both scan_command and repos_analyzed also land in `findings.json`.

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

- **Phase 2 implemented**: `skills/repo-docker-scanner/` — mutable
  container-image detection, tiered P0/P1/P2, 63 assertions.
- **Phase 3 implemented**: `skills/repo-packages-scanner/` — unpinned GitHub
  Actions, npm/PyPI/Go/Rust/Ruby dependencies, unpinned remote code execution,
  tiered P0/P1/P2, 63 assertions. Absorbed `run_gh_scan.sh` from
  `supply-chain-ioc-scan` via `git mv` (byte-identical, per decision 3 below).

**Next:** calibration and hardening — see "Open questions" below. No new
skills are planned; the design's three phases are all built.

> Note on tooling: the phase 1 plan was asked for via the
> `superpowers:writing-plans` skill, which was not installed in the session
> that wrote it. It was written directly against the spec in that skill's
> structure. Phases 2 and 3 followed the same approach for consistency.

## What phase 3 built

`repo-packages-scanner` closes the design: every detection pass named in the
spec's Skill 2 table has a corresponding detector and a self-test fixture case.

- `scripts/_actions.py`, `_npm.py`, `_pypi.py`, `_remote_exec.py`,
  `_other_langs.py` — one module per pass, each independently testable
- `scripts/_classify.py` — the only genuinely shared logic (commit-SHA check,
  fingerprinting); unlike the docker scanner there is no single mutability
  table, each ecosystem classifies its own grammar
- "Missing lockfile" (repo-tree fact) and "install-not-ci" (CI-content fact)
  are two different finding classes, not merged — a repo can have a committed
  lockfile and still run `npm install` in CI, ignoring it entirely
- `--resolve` is the only network call (personal-account / archived-upstream
  Actions via `gh api`), opt-in, never required — mirrors the docker
  scanner's digest-resolution contract exactly
- `pyproject.toml` and `Cargo.toml` are read by small state-machine section
  scanners, not a real TOML parser (`tomllib` needs Python 3.11+, this
  package has no version floor that high) — same "subset reader, not an
  implementation" approach as the docker scanner's `_yamlish.py`

**Not verified here:** `--resolve` against a live `gh api` — no `gh` CLI in
the implementing environment, same gap phase 1 and 2 both carried at their
own implementation time. The plumbing (caching, graceful no-op when `gh` is
absent, never aborting the run) is real but only proven against a synthetic
non-network path.

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
   (it detects compromise, not unpinned deps), explicitly requested, and
   documented in a clearly separate `SKILL.md` section. *Done*, via `git mv`,
   unchanged byte-for-byte.
4. **No auto-fix branches or PRs in v1** — deliberately deferred as the riskiest
   surface with no detection value.

## Open questions the author flagged

- **`repo-corpus` scope defaults.** *Resolved* (phase 1 plan, D6): kept broad
  — archived, forks, and non-default branches all included. The bandwidth
  cost is quoted in that skill's `SKILL.md` from a real measurement.
- **The P0/P1/P2 priority models.** *Partially calibrated.* Both scanners'
  tier boundaries are now real code (`priority_rules` in each policy JSON,
  rendered into every report as a generated legend — see the lesson above),
  and the docker scanner has one real-org calibration data point (see below).
  **`repo-packages-scanner` has zero calibration runs against a real org** —
  everything about its tier boundaries is verified only against the synthetic
  self-test fixture. Run it against `tomkat-cr` (or any real org) and read the
  tier histogram before trusting `--fail-on P0` as a CI gate. If P0 lights up
  with dozens of findings, the boundary is wrong regardless of how defensible
  it looks in the abstract — retuning is a `policy/packages.json` edit, never
  a code change.
- **`--resolve` is unverified against live `gh api`** (see "What phase 3
  built" above) — worth a real run once `gh` is available.

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
