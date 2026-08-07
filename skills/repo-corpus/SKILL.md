---
name: repo-corpus
description: Use when a security scan must cover many repositories at once — building safe local checkouts of an entire GitHub org or user, plus a manifest describing exactly what was obtained. Triggers: "scan my whole org", "clone all my repos", "audit every repository", "build a repo corpus", "check all our repos for", "org-wide scan". Not for scanning a machine for a known compromise — that is supply-chain-ioc-scan.
license: MIT
metadata:
  author: tomkat-cr
  version: "1.0"
---

# Repo Corpus

## Overview

Turn "an organization, a user, or this directory" into safe, attributable
checkouts plus a `corpus.json` manifest describing them.

**This skill produces no findings.** That is the point. Scanners consume a
corpus and never learn how it was built, which makes single-repo lint mode and
org-wide audit the same code path instead of two implementations of every
detector that drift apart.

Two principles it inherits from `supply-chain-ioc-scan`:

1. **Cloned repositories are hostile input.** Nothing from a clone is ever
   executed, and the mechanisms by which a repo could execute something are
   disabled at clone time.
2. **A gap in coverage must be visible in the output.** A repo that failed to
   clone, a directory that could not be read, a subtree that was pruned — each
   is recorded and counted. Silence about what a scan missed is how a partial
   scan gets reported as a clean one.

## When to Use

- Before any org-wide audit: the two scanners in this plugin both take a corpus
- To scan a single checkout in CI (`--local .`), using the same code path
- **Not for**: scanning a machine for a disclosed compromise — that is
  `supply-chain-ioc-scan`, which walks `$HOME`, not repositories

## Quick Start

```bash
./scripts/run_corpus.sh --org tomkat-cr        # whole org
./scripts/run_corpus.sh --user someone --no-forks
./scripts/run_corpus.sh --local .              # this checkout, no cloning
```

`run_corpus.sh` runs the self-test first and refuses to build a corpus if it
fails. Reports the manifest path on stdout, progress on stderr, so
`build_corpus.py … | jq` works.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Every selected repository materialized |
| `1` | **Partial corpus** — at least one repo failed; every scan over it has a blind spot |
| `2` | No usable manifest (bad arguments, `gh` missing or unauthenticated, output unwritable) |

`1` is not "findings" — this skill has none. It means the corpus has a hole,
and it exists so `run_corpus.sh && scan_*.py` stops rather than scanning around
one silently.

Check scope before committing to a large clone:

```bash
python3 scripts/build_corpus.py --org tomkat-cr --list-only
```

## Cloned Repositories Are Hostile Input

Every clone runs with these flags. Each one prevents a specific failure; none
is decoration, and the self-test fails if any is removed.

| Flag | Prevents |
|---|---|
| `core.hooksPath=/dev/null` | A hook executing during clone. The whole hostile-input premise rests on this one. |
| `filter.lfs.smudge=cat`, `filter.lfs.process=`, `filter.lfs.required=false`, `GIT_LFS_SKIP_SMUDGE=1` | An LFS smudge filter — a command the repository gets to name — running on checkout. |
| `credential.helper=` then `credential.helper=!gh auth git-credential` | Not a convenience. Parallel HTTPS clones on macOS trigger one Keychain prompt **per git process**. Clearing the helper and setting it inline uses the `gh` token directly, prompts zero times, and never touches global git config. |
| `--depth 1 --no-single-branch` | Full branch coverage without full history. |
| `--no-tags` | Tags are mutable and irrelevant to scanning a tree. |
| `GIT_TERMINAL_PROMPT=0` | A parallel run blocking forever on an auth prompt. |

Three further protections, none of them obvious:

- **Clone to staging, rename on success.** An interrupted clone must never be
  mistaken for a complete one — that is a silently incomplete corpus, which is
  a falsely clean verdict with extra steps.
- **Repository names are validated before becoming path components.** A name is
  chosen by whoever created the repository; one containing `../` is refused and
  recorded, not written.
- **Symlinks never escape a repo.** `_walk.py` refuses any path resolving
  outside its root, so a repo containing `keys -> ~/.ssh` cannot induce a
  scanner into reading — or reporting — a file the repo does not own.

## The Manifest Is the Interface

`corpus.json` is what every scanner is written against. Three rules they rely
on:

1. **A repo missing from `repos[]` means "not selected", never "silently
   failed".** Failures and empty repos are recorded with a reason.
2. **`path` is always relative to `root`.** A corpus stays valid when moved or
   inspected from another machine.
3. **`status: "failed"` implies no usable tree.** Scanners skip those entries
   and must carry the count into their own report's blind-spot section.

Per repo it records local path, branch list, HEAD SHA per branch, clone status,
and GitHub metadata. Recording HEAD SHAs is what makes every downstream finding
attributable to an exact snapshot; recording stars and `pushedAt` lets a
maintainer triage by whether anyone actually uses the repository.

`schema_version` is `1`. Consumers should check it.

## Scope Defaults Are Broad On Purpose

Archived repos, forks, and non-default branches are **all included** by
default. Narrowing is explicit: `--no-archived`, `--no-forks`,
`--default-branch-only`, `--include`/`--exclude`.

Narrowing scope is how a scan misses what it was run to find. An archived repo
still has a workflow that runs with a token. A fork is still a place a
maintainer's credentials execute.

The cost of `--no-single-branch` is bandwidth, so it is measured rather than
argued. On `tomkat-cr/genericsuite-security` (4 branches): **316 KB all
branches vs 236 KB default-branch-only, ~1.3x, no measurable time difference**
at depth 1. That is a single small repository and not a load-bearing sample —
re-measure across a full org before treating the multiplier as general. If it
turns out severe on a large corpus, `--default-branch-only` is the cheaper path
and flipping the default is a one-line change.

## What a Corpus Does Not Tell You

Every scanner built on this must carry these into its own report:

- **A truncated repository list.** The worst one, because it cannot be
  expressed as a failure: repos past the cut are not "failed", they are simply
  absent, indistinguishable from "not selected". `build_corpus.py` warns into
  `warnings[]` when the count hits `--limit`, or lands on an exact multiple of
  the 100-per-page size `gh` uses. **Read `warnings[]` before trusting
  `totals`.**
- **Failed clones.** In the manifest with their error, counted in
  `totals.failed`. Exit `1` exists to make this impossible to miss.
- **Empty repositories.** Recorded `status: "skipped"`, never dropped.
- **Pruned directories.** `_walk.py` prunes `node_modules/`, `vendor/`,
  `dist/`, `build/`, `.git/`, `__pycache__/`, `.venv/`, `venv/` by default.
  `build/` and `dist/` legitimately hold Dockerfiles and compose files — that
  is an acceptable default and an unacceptable secret, so `WalkStats.prune_counts`
  records it. Override with `no_prune=True` or `extra_prune=`.
- **Unreadable paths.** Counted in `WalkStats.unreadable`;
  `clean_coverage` goes False. Unreadable is not clean.
- **Files over 2 MB.** `read_text` records them as skipped rather than reading
  them.
- **Anything not in a repository.** Deploy-time configuration, CI variables,
  and gitops overlays are outside a corpus by construction.

## `scripts/_walk.py`

Shared walking for both scanners. Not `os.walk()`, for three reasons that each
produce a scan reporting clean over ground it never covered:

```python
stats = _walk.WalkStats()
for abspath, relpath in _walk.walk_files(repo_path, stats=stats):
    text = _walk.read_text(abspath, stats)
    if text is None:
        continue          # reason already recorded in stats
print(stats.summary())    # "1234 file(s), 12 dir(s) pruned, 3 PATH(S) COULD NOT BE READ"
```

- `os.walk()` swallows `PermissionError` by default; here every unreadable path
  is counted.
- Directory symlinks are never descended and nothing resolving outside the root
  is ever yielded.
- `os.walk()` on a *file* yields nothing, so a root passed as a file would scan
  zero bytes and report clean. That exact bug is in this package's history; it
  is handled rather than inherited.

## Self-Test

```bash
python3 tests/selftest.py
```

Because this skill produces no findings, it has no "did it detect anything?"
signal. What it has instead are security properties that look identical to
working code right up until a hostile repository is cloned. The self-test is
the only thing that notices when one silently stops holding.

It asserts hooks do not execute during clone (**with a control clone proving
the hook fixture actually fires** — without that, the assertion passes whenever
the fixture is broken), that every hardening flag is present in the argv, that
a failed clone leaves nothing under `repos/` and appears in the manifest with
an error, that unsafe repo names are refused, that `--local` produces a valid
manifest, and that symlinks cannot escape a walk root.

**The self-test is hermetic, and its fixtures are checked.** It builds local
git repositories to clone, with `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM`
neutralized and an isolated `HOME`, so your own git configuration cannot decide
whether it passes — a global `core.hooksPath` would otherwise suppress the
control hook and make the hardening assertion pass for the wrong reason. Every
fixture command is checked, and a preflight builds one repository before any
assertion runs: if the environment cannot produce a git repository at all, you
get one clear "CANNOT BUILD TEST FIXTURES" message naming the failing git
command, rather than five downstream assertions describing it badly. It also
avoids `git init -b`, which needs git ≥ 2.28 — macOS ships whatever git came
with Xcode, and this package already has scars from macOS shipping decade-old
tooling.

**A skipped assertion is not a passed one.** Running as root, the
unreadable-path assertion cannot work — `chmod 000` does not block root — so it
skips loudly and is excluded from the pass count rather than passing vacuously.
A self-test that silently passes without testing is a false claim that a
security property was verified.

It also asserts that every skill path in `.claude-plugin/marketplace.json`
exists on disk. That file previously registered a path that did not exist,
which is why the check is a permanent assertion rather than a one-off fix.

## Common Mistakes

- **Treating exit `1` as "findings".** It means the corpus is incomplete.
- **Scanning a corpus without reading `totals.failed`.** Every clean verdict
  over a partial corpus needs that caveat attached.
- **Narrowing scope to make a run cheaper.** Prefer `--limit` or `--include`,
  which are visible in `source.filters` in the manifest, over quietly dropping
  archived repos and forks.
- **Assuming a corpus is current.** It is a snapshot; `generated_at` and the
  per-branch HEAD SHAs say exactly which one.
- **Executing anything from a clone.** Do not run `npm install`, do not
  evaluate a config file, do not trust a path from a repo as a path on disk.
