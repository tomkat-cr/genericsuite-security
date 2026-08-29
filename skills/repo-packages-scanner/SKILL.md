---
name: repo-packages-scanner
description: Use when auditing GitHub Actions and language dependencies for mutability — finding unpinned `uses:` refs, floating npm/PyPI ranges, missing lockfiles, and unpinned remote code execution (`curl | bash`) across one repo or a whole GitHub org. Triggers: "unpinned actions", "are our GitHub Actions pinned", "unpinned dependencies", "floating dependency versions", "missing lockfile", "curl pipe bash", "dependency supply chain audit", "pin our actions". Also covers scanning a user/org for compromise indicators (run_gh_scan.sh) — see that section below. Not for container images — that is repo-docker-scanner.
license: MIT
metadata:
  author: tomkat-cr
  version: "1.0"
---

# Repo Packages Scanner

## Overview

Find every **mutable** GitHub Action reference and language-dependency
specifier across a corpus, and every unpinned remote-code-execution pattern
(`curl | bash` and its relatives) — then prioritise by where it executes.
Static analysis only by default: nothing from a scanned repository is ever
executed, and no network call is made unless `--resolve` is passed explicitly.

A reference is mutable unless it names an immutable identity: a commit SHA for
an Action, an exact pinned version (backed by a lockfile) for a package.
Anyone who can push to a moving tag — a stolen npm/PyPI token, a compromised
Action publisher, an abandoned personal account — silently changes what your
CI runs and what gets installed, **with no commit in your repository**. That
is the same threat class `repo-docker-scanner` addresses for container images;
this skill covers everything that isn't an image.

## When to Use

- Auditing Action/dependency pinning across an org, or enforcing it on one
  repo in CI
- After a registry-token or Action-publisher compromise, to find what could
  have been redirected
- Checking whether a user/org shows markers of a specific disclosed
  compromise — via the `run_gh_scan.sh` section below
- **Not for**: container image references — that is `repo-docker-scanner`

## Quick Start

```bash
./scripts/run_packages_scan.sh --org tomkat-cr          # builds a corpus, then scans
./scripts/run_packages_scan.sh --local .                # one checkout, CI lint mode
./scripts/run_packages_scan.sh --corpus path/corpus.json
./scripts/run_packages_scan.sh --corpus path/corpus.json --resolve   # + gh api ownership
```

The driver runs the self-test first and refuses to scan if it fails. Reports
land next to the corpus in `packages-scan/`: `report.md`, `findings.json`, and
`findings.sarif`.

Exit `0` no findings at the threshold, `1` findings, `2` error.
`--fail-on` defaults to `P0`; `--fail-on none` reports without failing.

This skill consumes a corpus from `repo-corpus` and shares its `_walk.py` by
path rather than by copy — install both side by side.

Right after the summary, `report.md` states exactly what produced it and what
it covers, before any findings table:

- **Scan command** — the literal top-level invocation, captured before any
  argument is consumed or rewritten (`--org`/`--include`/`--branch` resolve
  into a `--corpus` path before `scan_packages.py` ever sees them).
- **Repositories and branches analyzed** — every repo, branch, and HEAD SHA
  actually walked. A "no findings" statement is scoped to exactly this list,
  never to the org.
- **Priority tiers** — a P0/P1/P2 legend **generated from
  `policy/packages.json`'s `priority_rules`**, never hand-written prose. A
  hand-written version of this exact section shipped once in
  `repo-docker-scanner`'s report and immediately described the wrong
  scanner's tiers; generating it from the policy that actually governs
  classification makes that drift structurally impossible.

Both scan command and repos-analyzed are also in `findings.json`, as
`scan_command` and `repos_analyzed`.

## Detection Passes

| Pass | Detects |
|---|---|
| `actions` | `uses: org/action@v4`/`@main`/`@branch` rather than a 40-hex commit SHA — in workflows, composite `action.yml`, and reusable-workflow calls (same YAML key, no special-casing needed). Also `uses: docker://` with no digest. |
| `npm` | `^`, `~`, `*`, `x`, `latest`, bare `>=`/`>` ranges; a repo with `package.json` but no committed lockfile; `npm install`/`yarn install` (without `--frozen-lockfile`) used in CI in place of `npm ci`; `.npmrc` registry overrides; `overrides`/`resolutions`; `preinstall`/`postinstall` hooks. |
| `pypi` | Bare or `>=`-constrained `requirements*.txt` entries; missing `--require-hashes` when any entry is unpinned; Poetry `^`/bare-`*`; unbounded PEP 621 `[project.dependencies]`; a Poetry/uv project with no committed lockfile; `--index-url`/`--extra-index-url` overrides. |
| `remote-exec` | `curl \| bash`, `wget \| sh` (including `sudo`), remote scripts sourced via process substitution (`source <(curl …)`), `pip install` from a URL/git+ ref, `go install` with no `@version` or `@latest`. |
| `other-langs` | Go: `replace` directives, `@latest`-style requires, `go.mod` with no committed `go.sum`. Rust: bare `*` constraints (including the table form), a binary crate (`[[bin]]`) with no committed `Cargo.lock`. Ruby: a `gem` line with no version constraint, a `Gemfile` with no committed `Gemfile.lock`. |

**"Missing lockfile" and "install-not-ci" are two different findings from two
different signals, not one.** The first is a repo-tree fact (no lockfile
committed at all); the second is a CI-workflow-content fact (a workflow step
still invokes a resolving install). A repo can have both, or either alone — a
committed lockfile does not protect a CI job that runs `npm install` instead
of `npm ci` and ignores it.

**`--resolve` is the only network call, and it is optional.** Per-Action
ownership (personal account vs. organization, archived upstream) has no
static, file-content signal the way Docker Hub's `library/` namespace does for
images — it requires `gh api users/{owner}` and `gh api repos/{owner}/{repo}`.
Static findings are complete and correct without it; `--resolve` only adds
`personal-account`/`archived-upstream` flags to existing findings, never
required, never aborts the run on a failed lookup.

## Priority Tiers

Per the design spec's model — see `policy/packages.json`'s `priority_rules`
for the authoritative, machine-checked version (the report's legend is
generated from exactly this):

- **P0** — an unpinned reference in a release/publish workflow (filename or
  content containing "release"/"publish"/"deploy"/"cd"), or anything that
  otherwise runs in CI with credentials.
- **P1** — developer machines and build time: manifest files themselves
  (`package.json`, `requirements*.txt`, `go.mod`, `Cargo.toml`, `Gemfile`).
- **P2** — examples, demos, documentation, and archived repositories.

## Triage Rules

- **A `uses:` with no `@` at all is reported, never silently dropped** — it
  is malformed or worth a second look either way.
- **`file:`/`link:`/`workspace:`/`npm:`/`portal:` npm specifiers are not
  registry ranges.** They point at a version-controlled local path or
  workspace member, not a moving upstream target, and are excluded before
  classification rather than misclassified.
- **A local action (`uses: ./path`) has no external supply-chain exposure**
  and is never a finding — it is version-controlled with the rest of the repo.
- **`~=` in PyPI (`~=1.4.2`) pins the patch train**, unlike npm's `~`, and is
  treated as acceptable — PEP 440's compatible-release operator, not a
  floating range.

## Baseline

Same shape as `repo-docker-scanner`: `{"accepted": [{"fingerprint": "…",
"reason": "…", "owner": "…", "date": "…"}]}`. Findings are fingerprinted on
`(repo, file, normalized reference, class)` — deliberately **not** the line
number, so accepted risk stays accepted when a file shifts. Two findings for
the same reference in the same file on different lines therefore share a
fingerprint; baselining one accepts both.

## `scripts/run_gh_scan.sh`

Moved **unchanged** from `supply-chain-ioc-scan`. It scans a GitHub user's or
organization's repositories for Shai-Hulud campaign markers in repository
descriptions and for suspiciously recent repository creation:

```bash
./scripts/run_gh_scan.sh <username> [<keyword-regex> <since-date>]
```

**This answers "are we compromised", not "are our dependencies pinned."** It
sits oddly in this skill by domain, and it is here by explicit decision, not
oversight — documented in the design spec's recorded trade-offs. It has no
callers inside this skill and no dependency on anything else here; moving it
again later is cheap.

## Self-Test

```bash
python3 tests/selftest.py
```

Builds a synthetic repository with a known positive for every pass and asserts
each fires, then asserts the documented benign lookalikes do not: a
40-hex-pinned Action, an exact npm/PyPI version, a `file:`-protocol npm
specifier, a local `./`-path action, a PyPI `~=` compatible-release
constraint. Also asserts the priority-tier legend is generated from policy and
contains no vocabulary belonging to `repo-docker-scanner`'s tier model — the
exact regression class that shipped once already in that scanner's report.

## Remediation

- Pin Actions to a commit SHA: `uses: owner/repo@<sha> # v4.1.1` — keep the
  tag as a comment, Renovate/Dependabot both bump pinned SHAs automatically.
- Commit a lockfile and use its strict-install form in CI (`npm ci`, `yarn
  install --frozen-lockfile`, `pip install --require-hashes`, `poetry
  install`) rather than a resolving install.
- Replace `curl | bash`/`wget | sh` with a pinned, hash-verified download step.
- Fix shared and reusable workflows first — one pin there covers every
  consuming repository.
