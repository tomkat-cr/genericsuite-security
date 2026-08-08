# Implementation Plan: Phase 3 — `repo-packages-scanner`

**Date:** 2026-08-08
**Status:** Ready to implement
**Spec:** `docs/superpowers/specs/2026-08-06-repo-scanner-skills-design.md`, "Skill 2:
`repo-packages-scanner`" and "Conventions shared by both scanners"
**Depends on:** phase 1 (`repo-corpus`) and phase 2 (`repo-docker-scanner`), both
complete — this phase reuses every convention phase 2 settled, including the
fix just applied to it (see D0 below).

## D0 — the lesson phase 2 just paid for, applied here from the start

A hand-written "Priority tiers explained" section was added to phase 2's
report and immediately described the wrong scanner — it was this skill's tier
language, copy-pasted into `repo-docker-scanner`'s report. The fix was to
generate the legend from the policy's own `priority_rules` instead of writing
prose that can drift. Phase 3 builds that generator **from the first commit**,
not as a follow-up fix. The same applies to the other two report features this
phase must carry from the start (per this session's request):

1. **Scan command** — the literal top-level invocation, captured by
   `run_packages_scan.sh` before it consumes or rewrites any argument, with
   `scan_packages.py` falling back to reconstructing its own argv when run
   directly. Identical mechanism to phase 2's `DOCKER_SCAN_INVOKED_CMD` /
   `PACKAGES_SCAN_INVOKED_CMD`.
2. **Repositories and branches analyzed** — every repo/branch/HEAD the scan
   actually walked, identical shape to phase 2's `repos_analyzed`.
3. **Priority tiers legend** — generated from `policy/packages.json`'s
   `priority_rules`, identical shape to phase 2's `_priority_legend_lines()`.

All three are implemented once, shared in spirit with phase 2 but duplicated in
code per the spec's recorded trade-off (independent per-skill reports, chosen
for skill self-containment).

## What phase 3 delivers

```
skills/repo-packages-scanner/
├── SKILL.md
├── policy/packages.json
├── scripts/
│   ├── _actions.py         GitHub Actions `uses:` detection
│   ├── _npm.py              npm / package.json detection
│   ├── _pypi.py             PyPI / Python detection
│   ├── _remote_exec.py      curl|bash and friends
│   ├── _other_langs.py      Go / Rust / Ruby
│   ├── _classify.py         pin classification + fingerprinting shared by all passes
│   ├── _report.py           report.md / findings.json / findings.sarif
│   ├── scan_packages.py     driver: corpus in, findings out
│   ├── run_gh_scan.sh       moved UNCHANGED from supply-chain-ioc-scan (D3)
│   └── run_packages_scan.sh self-test, then corpus, then scan
└── tests/
    └── selftest.py
```

Consumes a `repo-corpus` corpus exactly as phase 2 does: reuses `_walk.py` by
path, same exit codes (`0`/`1`/`2`), same `--fail-on`, `--exclude`,
`--baseline`, `--sarif` CLI shape.

## Detection passes (spec table, verbatim scope)

| Pass | Detects |
|---|---|
| `actions` | `uses: org/action@v4`/`@main`/`@branch` rather than a 40-hex commit SHA, in workflows, composite `action.yml`, reusable-workflow calls; `uses: docker://` references |
| `npm` | `^`,`~`,`*`,`x`,`latest`, bare `>=`; missing lockfile; `npm install` (not `npm ci`) in CI; `.npmrc` registry overrides; `overrides`/`resolutions`; `preinstall`/`postinstall` hooks |
| `pypi` | Bare/`>=` `requirements*.txt`; missing `--require-hashes`; Poetry `^`/`*`; unbounded PEP 621; missing `poetry.lock`/`uv.lock`/`Pipfile.lock`; `--index-url`/`--extra-index-url` overrides |
| `remote-exec` | `curl \| bash`, `wget \| sh`, `pip install <url>`, `go install` without version, remote scripts sourced in CI |
| `other-langs` | Go: missing `go.sum`, `replace` directives, `@latest`. Rust: `*` constraints, missing `Cargo.lock` for binaries. Ruby: unpinned `Gemfile`, missing `Gemfile.lock` |

## Decisions this plan settles

### D1 — Action ownership flags (personal account / archived upstream) are `--resolve`-only

The spec: "the `actions` pass separately flags actions owned by personal
accounts and actions whose upstream repository is archived." Both require
knowing about a *different* repository than anything in the corpus — GitHub
has no static, file-content signal equivalent to Docker Hub's `library/`
namespace for telling a personal account from an organization. This is
identical in kind to phase 2's `--resolve` (`gh api
repos/{owner}/{repo}/git/ref/tags/{tag}`): static and offline by default,
network-backed enrichment behind an explicit flag. Default runs report
unpinned refs; `--resolve` additionally calls `gh api users/{owner}` (type
`User` vs `Organization`) and `gh api repos/{owner}/{repo}` (`archived`),
merges the flags into existing findings, and never aborts the run on a
resolution failure — identical contract to phase 2's digest resolution.

### D2 — `npm ci` vs `npm install` is a CI-context check, not a lockfile check

"missing lockfile" and "`npm install` rather than `npm ci` in CI" are two
different findings from two different signals: the first is a repo-tree fact
(no `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`), the second is a
CI-workflow-content fact (a workflow `run:` step invoking `npm install`/`yarn
install` without `--frozen-lockfile` rather than `npm ci`). Both are real
findings and both ship; conflating them would hide a repo that has a lockfile
but a CI job that still resolves fresh versions.

### D3 — `run_gh_scan.sh` moves, it does not copy

Per the spec's explicit decision. `git mv` from
`skills/supply-chain-ioc-scan/scripts/run_gh_scan.sh` to
`skills/repo-packages-scanner/scripts/run_gh_scan.sh`, unchanged.
`supply-chain-ioc-scan/SKILL.md` and `CLAUDE.md`'s command list are updated to
point at the new location. `repo-packages-scanner/SKILL.md` carries a clearly
separated section — per the spec's own instruction — explaining this script
answers "are we compromised", not "are dependencies pinned", and lives here by
explicit decision, not oversight.

### D4 — Priority tiers, verbatim from the spec, expressed as data

```jsonc
"priority_rules": [
  {"tier": "P0", "when": {"path_glob": "**/.github/workflows/*", "content_contains_any": ["release", "publish", "deploy"]}, "why": "unpinned action in a release/publish workflow"},
  {"tier": "P0", "when": {"path_glob": "**/.github/workflows/*"}, "why": "runs in CI with credentials"},
  ... (remote-exec in CI, npm install in a publish pipeline -> P0)
  {"tier": "P1", "when": {}, "why": "developer machines and build time (default)"}
  P2: examples/demos/docs/archived, same shape as phase 2
]
```

The "release/publish workflow" distinction needs a second `when` predicate
beyond `path_glob` (phase 2 only ever needed path). `priority_for()` gains a
`content_contains_any` check against the raw file text, evaluated only when
present — additive, does not change phase 2's engine (separate file).

### D5 — Fingerprint shape matches phase 2 exactly

`(repo, file, normalized_reference, class)`, SHA-256, first 16 hex, line
number deliberately excluded. Same consequence phase 2's `SKILL.md` now
documents explicitly: two findings for the same reference in the same file on
different lines share a fingerprint.

## The four things this phase must not repeat

Lessons phase 1 and phase 2 already paid for, restated as checklist items
rather than left to be rediscovered:

- [ ] Self-test is hermetic (isolated `HOME`, neutralized global git config)
      and every fixture command is checked — an unchecked fixture turned one
      setup failure into five confusing assertion failures in phase 1.
- [ ] No bash arrays in `run_packages_scan.sh` — macOS bash 3.2 crashes on an
      empty array under `set -u`, and a crash must never be reported as a scan
      verdict. `run_docker_scan.sh` is the template to copy the guard from.
- [ ] The driver never reports a corpus/scan outcome without a manifest/report
      file to back it — same "no manifest → exit 2, not a verdict" contract.
- [ ] The priority legend is generated from policy, never hand-written (D0).

## Verification before phase 3 is called done

```bash
cd skills/repo-packages-scanner
python3 tests/selftest.py                              # every pass + negatives
python3 scripts/scan_packages.py --corpus <local-corpus.json>   # real-tree smoke test
./scripts/run_packages_scan.sh --local ../..            # end-to-end via driver
```

Mutation-test the tier-legend generator and the scan-command capture the same
way phase 2's were verified: revert the fix, confirm the assertion fails.

## Explicitly out of scope

- Auto-fix branches or PRs (deferred org-wide, per the spec's recorded
  trade-offs).
- A cross-scanner combined report (recorded trade-off: independent per-skill
  reports).
- Editing `run_gh_scan.sh`'s behavior — it moves unchanged (D3).
