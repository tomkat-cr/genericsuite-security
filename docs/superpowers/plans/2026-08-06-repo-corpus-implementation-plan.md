# Implementation Plan: Phase 1 — `repo-corpus`

**Date:** 2026-08-06
**Status:** Implemented — see "Outcome" at the end for what shipped and what
the acceptance checks could not cover
**Spec:** `docs/superpowers/specs/2026-08-06-repo-scanner-skills-design.md`
**Scope:** Phase 1 only. Phases 2 (`repo-docker-scanner`) and 3
(`repo-packages-scanner`) are out of scope and get their own plans.

> The handoff asked for this plan to be produced with the
> `superpowers:writing-plans` skill. That skill is not installed in the session
> that wrote this, so the plan was written directly against the spec, in the
> structure that skill produces: ordered tasks, each independently verifiable,
> with the acceptance check stated before the work.

## What phase 1 delivers

`repo-corpus` turns "an organization, a user, or this directory" into safe,
attributable checkouts plus a `corpus.json` manifest. It produces **no
findings**. That separation is the whole point: it makes single-repo lint mode
and org-wide audit the same code path for the two scanners that follow.

Deliverables:

```
skills/repo-corpus/
├── SKILL.md
├── scripts/
│   ├── build_corpus.py      enumerate → clone → manifest
│   ├── _walk.py             shared walking, pruning, unreadable counting
│   └── run_corpus.sh        thin driver: self-test, then build
└── tests/
    └── selftest.py          proves the hardening actually holds
.claude-plugin/marketplace.json   path fix + registration
```

Nothing here is network-dependent to test: every self-test fixture is a local
`git init` repo cloned over `file://`, and enumeration is fed a canned payload.

## Non-goals for this phase

- No detectors, no findings, no SARIF, no baseline. Those are phases 2 and 3.
- No registration of `repo-docker-scanner` / `repo-packages-scanner` in
  `marketplace.json` — registering directories that do not exist is precisely
  the bug this phase fixes. They are registered by the phase that creates them.

---

## Decisions this plan settles

The spec left some interface-level details open. Implementing against
guesswork produces two scanners that disagree about the manifest, so they are
pinned here.

### D1 — Exit codes for a skill that produces no findings

The house contract is `0` clean / `1` findings / `2` error. `repo-corpus` has
no findings, so `1` maps to **partial corpus**:

| Code | Meaning |
|---|---|
| `0` | Manifest written; every selected repo materialized |
| `1` | Manifest written; ≥1 selected repo failed to clone — a scan over this corpus has a known hole |
| `2` | No usable manifest (bad args, `gh` missing/unauthenticated, output dir unwritable) |

This keeps "you must look at this before trusting a downstream clean verdict"
on `1`, which is the same semantics the scanners use, and it means
`run_corpus.sh && scan_*.py` short-circuits on an incomplete corpus rather than
scanning a hole silently.

### D2 — Enumeration is injectable, so it is testable offline

`build_corpus.py` reads repository metadata from `gh repo list … --json …`, but
accepts `--repos-json PATH` to read the identical payload from a file. The
self-test uses the file path; production uses `gh`. Without this, the
enumeration, filtering, and manifest code is only exercisable against a live
GitHub account, which means in practice it is not exercised at all.

### D3 — `--local` accepts multiple paths

The spec describes `--local <path>` as single-repo mode. Accepting
`--local PATH [PATH …]` costs nothing, makes "scan these three checkouts I
already have" work without cloning, and keeps the manifest shape identical.
Single-repo lint mode is the one-argument case.

### D4 — Symlinks are never followed out of the repo root

Not in the spec, but it belongs to phase 1 because `_walk.py` lives here.
A cloned repository is hostile input, and a repo may contain `evil -> /` or
`keys -> ~/.ssh`. `_walk.py` does not follow directory symlinks at all, and
resolves every yielded path to assert it stays under the repo root. A scanner
that reads `~/.ssh/id_rsa` because a hostile repo asked it to is a worse
outcome than any missed finding.

### D5 — Pruned directories are counted and reported, not silently dropped

The spec's prune list (`node_modules/`, `vendor/`, `dist/`, `build/`, `.git/`)
contains two directories that legitimately hold scannable content: a
`Dockerfile` under `build/` or a compose file under `dist/` is not exotic.
Pruning them is still right by default — but the count is recorded per repo in
`WalkStats`, `--prune-extra` adds to the list, and `--no-prune` disables it, so
every downstream report can state this blind spot instead of inheriting it
invisibly.

### D6 — Broad scope defaults stand (open question 1, resolved)

The handoff flagged `repo-corpus` scope defaults as worth a second look.
Keep them broad — archived repos, forks, and non-default branches all included,
narrowing only via explicit `--no-archived` / `--no-forks` /
`--default-branch-only`. Rationale unchanged from the spec, and load-bearing in
`supply-chain-ioc-scan`: narrowing scope is how a scan misses what it was run
to find. An archived repo still has a workflow with a `GITHUB_TOKEN`, and a
fork is still a place a maintainer's credentials execute.

The cost is real and is bandwidth, so it is measurable rather than argued:
Task 8 records wall time and on-disk size for the `tomkat-cr` run with and
without `--default-branch-only`, and `SKILL.md` quotes both numbers. If the
multiplier turns out to be severe, flipping the default is a one-line change
with the evidence already in hand.

The second open question — the P0/P1/P2 priority models — belongs to phases 2
and 3 and is deliberately not addressed here.

---

## The manifest — `corpus.json`

This is the interface between `repo-corpus` and every scanner, so it is fixed
before any code is written.

```jsonc
{
  "schema_version": 1,
  "generated_at": "2026-08-06T14:03:11Z",
  "generator": "repo-corpus/build_corpus.py 1.0",
  "root": "/var/folders/…/repo-corpus-20260806-140311",
  "source": {
    "mode": "org",                       // "org" | "user" | "local"
    "target": "tomkat-cr",
    "filters": {
      "archived": true, "forks": true,
      "default_branch_only": false,
      "limit": 1000, "include": null, "exclude": null
    }
  },
  "totals": { "enumerated": 47, "selected": 42, "cloned": 40, "failed": 2 },
  "repos": [
    {
      "name": "genericsuite",
      "name_with_owner": "tomkat-cr/genericsuite",
      "url": "https://github.com/tomkat-cr/genericsuite",
      "path": "repos/genericsuite",        // ALWAYS relative to "root"
      "status": "cloned",                  // cloned | failed | local | skipped
      "error": null,                       // populated iff status == "failed"
      "default_branch": "main",
      "head": "3a7e0e4…",                  // default branch HEAD, convenience
      "branches": [ { "name": "main", "head": "3a7e0e4…" } ],
      "clone_duration_s": 3.24,
      "github": {
        "isFork": false, "isArchived": false, "isEmpty": false,
        "stargazerCount": 12, "pushedAt": "2026-08-01T09:12:44Z",
        "visibility": "PUBLIC"
      }
    }
  ],
  "warnings": []
}
```

Three rules the scanners may rely on:

1. **A repo missing from `repos[]` means "not selected", never "silently
   failed".** Every enumerated-and-selected repo appears, including failures.
2. **`path` is relative to `root`.** A corpus stays valid when the directory is
   moved or inspected from another machine.
3. **`status: "failed"` implies no usable tree.** Scanners skip those entries
   and must carry the count into their own report's blind-spot section.

For `--local`, `root` is the common parent, `path` points at the existing
working tree, `status` is `"local"`, `github` is `null`, and `branches` holds
the currently checked-out branch only.

---

## Task sequence

Each task states its acceptance check first. A task is done when its check
passes, not when the code looks finished.

### Task 1 — `scripts/_walk.py`

**Check:** importable standalone; `python3 -c "import _walk"` from
`scripts/`; behaviour verified by Task 6's assertions.

Surface:

```python
DEFAULT_PRUNE = {".git", "node_modules", "vendor", "dist", "build",
                 "__pycache__", ".venv", "venv"}

class WalkStats:
    files_seen: int
    dirs_pruned: int
    prune_counts: dict[str, int]   # basename -> times pruned
    unreadable: list[tuple[str, str]]   # (path, reason)
    symlinks_skipped: int

def walk_files(root, *, prune=DEFAULT_PRUNE, extra_prune=(), no_prune=False,
               stats=None) -> Iterator[tuple[str, str]]:
    """Yield (abspath, relpath). Never follows directory symlinks. Never
    yields a path that resolves outside `root`. Records unreadable dirs."""

def read_text(path, stats, max_bytes=2_000_000) -> str | None:
    """Return decoded text, or None while recording the reason in stats."""
```

Notes:

- `os.walk(..., followlinks=False)` plus an explicit
  `os.path.realpath(...).startswith(realpath(root))` guard. `followlinks=False`
  alone still yields *file* symlinks pointing anywhere.
- `os.walk`'s `onerror` must be wired to `stats.unreadable`. The default
  swallows `PermissionError` — that is the `supply-chain-ioc-scan` "unreadable
  is not clean" bug, and inheriting it here would hand both scanners a falsely
  clean verdict.
- Binary files: decode as UTF-8 with `errors="replace"`, cap at `max_bytes`,
  and record oversize skips in `stats.unreadable`. Silence is the failure mode.

### Task 2 — enumeration in `build_corpus.py`

**Check:** `--repos-json tests/fixtures/gh-repo-list.json --list-only` prints
the selected repos, and each filter flag changes the selection as expected.

- Runs `gh repo list <target> --limit N --json name,defaultBranchRef,isFork,isArchived,isEmpty,stargazerCount,pushedAt,visibility,url`.
- `--repos-json` substitutes a file for that call (D2).
- Fails with exit `2` and an actionable message when `gh` is absent or
  unauthenticated — not a stack trace, and never an empty corpus reported as
  success.
- Filters: `--no-archived`, `--no-forks`, `--include REGEX`, `--exclude REGEX`.
  `isEmpty` repos are selected but recorded `status: "skipped"` with a reason;
  cloning them is pointless and dropping them silently breaks rule 1.
- `--list-only` prints the selection and exits `0` without cloning. This is how
  someone checks scope before committing to 40 clones.

### Task 3 — hardened cloning

**Check:** Task 6's hook-canary and argv assertions pass.

Exact command, from the spec — do not simplify:

```bash
GIT_LFS_SKIP_SMUDGE=1 git \
  -c core.hooksPath=/dev/null \
  -c filter.lfs.smudge=cat -c filter.lfs.process= -c filter.lfs.required=false \
  -c credential.helper= -c 'credential.helper=!gh auth git-credential' \
  clone --quiet --depth 1 --no-single-branch --no-tags <url> <tmpdir>
```

Build the argv in one function, `clone_argv(url, dest)`, so the self-test can
assert on it directly. Each flag carries a comment naming the failure it
prevents (Keychain prompt storm; hostile `post-checkout` hook; LFS smudge
filter as an execution vector).

- **Clone to `<root>/.staging/<name>.<pid>`, `os.replace` into
  `<root>/repos/<name>` only on success.** An interrupted clone must never be
  mistaken for a complete one — that is a silently incomplete corpus, which is
  a falsely clean verdict with extra steps.
- Leftover `.staging` entries are removed at start and at exit.
- `--default-branch-only` swaps `--no-single-branch` for `--single-branch`.
- Per-clone timeout (`--timeout`, default 300s); a timeout is a `failed` entry
  with `error: "timeout after 300s"`, never a hang that outlives the run.
- Repo names are sanitized before use as a path component: reject anything
  containing `/`, `..`, or a leading `.`, and record it as `failed` with the
  reason. Enumeration output is remote-controlled data.

### Task 4 — parallelism and branch/HEAD recording

**Check:** a fixture corpus of ≥3 local repos clones under `--jobs 4`,
and every entry has a non-empty `head` and `branches`.

- `concurrent.futures.ThreadPoolExecutor`, `--jobs` default 8. Threads are
  right here: this is subprocess-bound, and the GIL is released.
- Per-repo failures never abort the pool — they become `failed` entries.
- After each successful clone, record branches and per-branch HEADs from
  `git for-each-ref --format='%(refname:short) %(objectname)' refs/remotes/origin`,
  filtering `origin/HEAD`. Recording HEAD SHAs is what makes every downstream
  finding attributable to an exact snapshot.
- Progress goes to stderr, the manifest path to stdout, so
  `build_corpus.py … | jq` works.

### Task 5 — `--local` mode and manifest writing

**Check:** `--local .` on this repository emits a valid one-entry manifest with
`status: "local"`, the real current branch, and the real HEAD.

- No cloning, no network, no `gh`.
- `root` is the common parent of the given paths; `path` entries relative to it.
- A path that is not a git working tree is still admitted (a plain directory of
  config files is a legitimate scan target) with `head: null`, `branches: []`,
  and a warning in `warnings[]`.
- Manifest write is atomic: temp file plus `os.replace`. A half-written
  `corpus.json` read by a scanner is a corrupt run reported as a partial one.

### Task 6 — `tests/selftest.py`

**Check:** `python3 tests/selftest.py` exits `0`; deleting any single hardening
flag from `clone_argv` makes it exit `1`.

Fixtures are local repos built with `git init` and cloned over `file://` — no
network, no GitHub account, no `gh`.

| # | Assertion | Why it exists |
|---|---|---|
| 1 | A `post-checkout` hook in the source repo does **not** run during clone (canary file absent) | `core.hooksPath=/dev/null` is the single most important flag; the spec's whole "hostile input" premise rests on it |
| 2 | `clone_argv()` contains every hardening flag verbatim | Catches a future edit that deletes one; assertion 1 alone would not fail for an LFS-filter regression |
| 3 | An interrupted clone leaves nothing under `repos/` and yields `status: "failed"` | A partial tree promoted into the corpus is a silent blind spot |
| 4 | A repo that cannot be cloned appears in the manifest with a non-null `error`, and the process exits `1` | Rule 1 of the manifest contract |
| 5 | `--local` produces a schema-valid single-entry manifest with a real HEAD | The path both scanners' lint mode depends on |
| 6 | `_walk` does not descend a symlink pointing outside the root (`evil -> /`) | D4; hostile repos are the threat model |
| 7 | `_walk` counts an unreadable directory rather than skipping it | The `supply-chain-ioc-scan` bug this package already paid for once |
| 8 | Every `skills[]` path in `.claude-plugin/marketplace.json` exists on disk | The exact bug Task 7 fixes, turned into a regression guard |
| 9 | A repo name containing `../` is rejected, not written outside `repos/` | Enumeration output is remote-controlled |

**Assertion 7 must skip loudly when running as root** (`os.geteuid() == 0`),
because `chmod 000` does not block root and the assertion would pass without
testing anything. Print `SKIP (running as root — unreadable-path detection not
exercised)` and exclude it from the pass count. A vacuous pass in a self-test
is worse than a missing test: it is a false claim that detection was proven.

### Task 7 — marketplace registration

**Check:** self-test assertion 8 passes.

In `.claude-plugin/marketplace.json`:

```diff
   "skills": [
-    "./skills/supply-chain-security"
+    "./skills/supply-chain-ioc-scan",
+    "./skills/repo-corpus"
   ]
```

Phases 2 and 3 add their own entries when their directories exist.

### Task 8 — `SKILL.md` and `run_corpus.sh`

**Check:** a real run against `tomkat-cr` completes and produces a manifest
whose totals match `gh repo list tomkat-cr --limit 1000 --json name | jq length`
after filters.

`run_corpus.sh` mirrors `run_scan.sh`: run the self-test first, refuse to build
a corpus if it fails, then build and print the manifest path. A corpus built by
unverified hardening is not a corpus anyone should scan.

`SKILL.md` follows the house structure — Overview, When to Use, Quick Start,
then the sections that carry the reasoning:

- **Cloned repositories are hostile input.** The flag table, one row per flag,
  each naming the failure it prevents.
- **The manifest is the interface.** The three rules above, verbatim, since
  both scanners are written against them.
- **What a corpus does not tell you.** Failed clones, `isEmpty` repos, pruned
  directories (D5), and the fact that `repo-corpus` produces no findings at all.
- **Scope defaults are broad on purpose**, with the measured cost of
  `--default-branch-only` from this task's run.

The `description:` frontmatter needs trigger phrases distinct from
`supply-chain-ioc-scan`'s, or the two skills compete: "clone all my repos",
"scan my whole org", "build a repo corpus", "audit every repository".

---

## Verification before phase 1 is called done

```bash
cd skills/repo-corpus
python3 tests/selftest.py                       # exit 0, no vacuous SKIPs
python3 scripts/build_corpus.py --local ../..   # valid one-entry manifest
./scripts/run_corpus.sh --org tomkat-cr         # real corpus, totals reconcile
```

Then, as an end-to-end proof that the interface is actually usable, walk every
file of the resulting corpus via `_walk.py` and print per-repo file counts and
unreadable counts. Phase 2 begins by consuming exactly this.

## Risks

| Risk | Mitigation |
|---|---|
| Self-test passes vacuously as root in CI | Assertion 7 skips loudly and is excluded from the pass count |
| `gh` output shape changes | Enumeration reads named JSON fields, missing fields become `null` with a warning rather than a `KeyError` |
| Disk exhaustion on a large org | `--limit`, `--default-branch-only`, measured sizes in `SKILL.md`; clone failures degrade to exit `1`, never a crash |
| Manifest drift once two scanners consume it | `schema_version` is checked by consumers from phase 2 onward |

---

## Outcome

All eight tasks implemented. `python3 tests/selftest.py` passes 31/31
assertions.

**Two bugs the acceptance checks caught**, both of which would have shipped:

1. **Phantom branch in the manifest.** git shortens `refs/remotes/origin/HEAD`
   to `origin`, not to `origin/HEAD`, so filtering on the short name recorded
   the symbolic HEAD as a branch named `origin`. The self-test missed it
   because its branch assertion was a subset check; it is now an exact
   comparison, which fails against the old code. Found by the end-to-end walk
   this plan requires — which is the entire reason that step is in the plan.
2. **`--local` wrote its manifest into the parent of the checkout.** Lint mode
   runs in CI, where that directory is frequently not writable. `root` (which
   anchors relative paths) and the manifest location are now separate; a
   regression assertion runs `--local` under a read-only parent.

**Verification beyond the plan's checks:**

- Each hardening flag was deleted from `clone_argv` in turn; every deletion
  fails the self-test. The `core.hooksPath` deletion fails the end-to-end hook
  canary too, not just the argv assertion.
- The root-skipped unreadable-path assertion was run as uid 65534 to confirm it
  is skipped rather than broken: it detects the locked directory and sets
  `clean_coverage` False.

**Task 8's acceptance check, completed later on real hardware.** The
implementing environment had no `gh` and single-repo GitHub scope, so the org
run happened on the author's macOS machine (git 2.21, bash 3.2):
`run_corpus.sh --org tomkat-cr --include prico` enumerated 100, cloned 5,
complete corpus. Three bugs only that environment could surface:

1. `git init -b main` — `-b` needs git 2.28; macOS ships what Xcode shipped.
   The fixture silently produced non-repositories, and because
   `make_source_repo` ignored exit status, one setup failure presented as five
   unrelated assertion failures.
2. The driver's `"${ARR[@]}"` on an empty array under `set -u` aborts on bash
   3.2 — the exact macOS trap this package documents for the other scanners.
   Worse, the resulting exit 1 was announced as "PARTIAL CORPUS".
3. Enumeration returned exactly 100 — `gh`'s page size — with nothing warning
   that the list might be capped.

The lesson for phases 2 and 3: this package's target platform is macOS with
decade-old system tooling, and a Linux CI green is not evidence about it.

**Not verified here — carry into phase 2:**

- **The `--default-branch-only` cost measurement is a one-repo sample** (316 KB
  vs 236 KB, ~1.3x, no measurable time difference at depth 1) and is quoted as
  such in `SKILL.md`. The D6 scope-defaults decision was meant to be revisitable
  against a real org-wide number; that number still needs collecting.
- **The macOS Keychain behaviour** the inline credential helper exists for
  cannot be reproduced on Linux. The flag is asserted present, not observed
  working.
