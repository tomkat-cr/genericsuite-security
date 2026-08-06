# Design: Organization-Wide Repository Scanner Skills

**Date:** 2026-08-06
**Status:** Approved, pending implementation plan
**Package:** `genericsuite-security`

## Problem

OSS maintainers have no cheap way to answer "across all my repositories, what is
unpinned?" — neither for language dependencies (npm, PyPI, GitHub Actions) nor
for container images. Existing tooling either scans one repo at a time
(Dependabot), reports known CVEs rather than mutability (`npm audit`), or
requires cluster access and image pulls.

Mutability is the gap. A reference is mutable unless it names an immutable
identity: a digest for images, a commit SHA for Actions, an exact version plus
lockfile for packages. Anyone who can push to a tag — via a stolen registry
token, a compromised maintainer account, or an abandoned namespace — silently
changes what CI runs and what production deploys, with no commit in any repo.
The 2026 Shai-Hulud worm steals exactly those tokens, which is what makes every
`:latest` and every `@v4` an open door.

This design adds three skills to the `gs-security-suite` plugin that answer that
question over an arbitrary corpus, from a single checkout up to an entire
GitHub organization, using static analysis only.

## Scope

**In scope:** static detection of mutable references; prioritization by
execution context; Markdown, JSON, and SARIF reporting; a baseline mechanism for
accepted risk; opt-in resolution of tags to digests/SHAs for copy-pasteable
remediation; a single-repo lint mode for CI enforcement.

**Out of scope for v1:** automated fix branches or pull requests (deliberately
deferred — writing to repositories is the riskiest surface and adds no detection
value); cluster or registry runtime inspection; Helm chart rendering; resolving
gitops overlay patterns (Argo/Flux) to determine deployed tags.

## Prior art in this package

The existing `supply-chain-ioc-scan` skill establishes conventions these skills
inherit rather than reinvent:

- **A clean verdict is only evidence if detection is proven.** Every scanner
  ships `tests/selftest.py` that builds a synthetic positive fixture and asserts
  each detector fires. The worst scanner failure is checking nothing and
  reporting clean; two real instances of that bug were caught only by a
  self-test.
- **Unreadable is not clean.** Walkers count paths they could not read and
  downgrade the verdict accordingly instead of silently skipping them.
- **Campaign/policy specifics live in a JSON profile**, never in scanner code.
  The scanners are policy-agnostic; only the profile is opinionated.
- **Findings are tiered**, separating machine-confirmable facts from things a
  human must judge.
- **Python, not bash.** macOS ships bash 3.2, which lacks associative arrays;
  under `set -u` the failures land on stderr while the report records nothing —
  a check that appears to have run and found nothing.
- **Exit codes:** `0` clean, `1` findings, `2` error.

## Architecture

Three new skills under `skills/`, alongside the existing `supply-chain-ioc-scan`:

```
skills/
├── supply-chain-ioc-scan/      existing; loses scripts/run_gh_scan.sh
├── repo-corpus/                shared foundation: enumerate + clone + manifest
├── repo-packages-scanner/      unpinned language dependencies
└── repo-docker-scanner/        unpinned container images
```

`repo-corpus` produces a corpus; the two scanners consume one. Neither scanner
knows how a corpus was built, and `repo-corpus` produces no findings. This is
what makes single-repo lint mode and org-wide audit the same code path.

All three skills are registered in `.claude-plugin/marketplace.json`. That file
currently lists a nonexistent `./skills/supply-chain-security` path; the correct
path (`./skills/supply-chain-ioc-scan`) is fixed as part of this work.

### Data flow

```
gh repo list ──► build_corpus.py ──► corpus.json + repos/<name>/
                                          │
                        ┌─────────────────┴─────────────────┐
                        ▼                                   ▼
              scan_packages.py                      scan_images.py
                        │                                   │
                        ▼                                   ▼
        report.md / findings.json / findings.sarif  (per skill, independent)
```

---

## Skill 1: `repo-corpus`

**Single responsibility:** turn "an organization, a user, or this directory"
into a set of safe, attributable checkouts plus a manifest describing them.

### Enumeration

```
gh repo list <ORG> --limit <N> --json \
  name,defaultBranchRef,isFork,isArchived,isEmpty,stargazerCount,pushedAt,visibility,url
```

### Cloning: cloned repos are hostile input

Every clone disables the mechanisms that let a repository execute code on the
scanning machine:

```
GIT_LFS_SKIP_SMUDGE=1 git \
  -c core.hooksPath=/dev/null \
  -c filter.lfs.smudge=cat -c filter.lfs.process= -c filter.lfs.required=false \
  -c credential.helper= -c 'credential.helper=!gh auth git-credential' \
  clone --quiet --depth 1 --no-single-branch --no-tags <url> <tmpdir>
```

Nothing from a clone is ever executed. Three non-obvious details:

- **The inline credential helper is not a convenience.** Parallel HTTPS clones
  on macOS trigger one Keychain prompt per git process. Overriding
  `credential.helper` inline uses the `gh` token directly, prompts zero times,
  and never touches global git config.
- **Clone to a temp directory, rename on success.** An interrupted clone must
  never be mistaken for a complete one — that is a silently incomplete corpus,
  which is a falsely clean verdict with extra steps.
- **`--depth 1 --no-single-branch`** fetches every branch at depth 1. Full
  branch coverage without full history.

Cloning is parallelized with a thread pool (default 8 workers).

### Manifest: `corpus.json`

The manifest is the interface between `repo-corpus` and every scanner. Per repo
it records: local path, branch list, HEAD SHA per branch, clone status, and the
GitHub metadata (stars, `pushedAt`, visibility, archived, fork). Recording HEAD
SHAs makes every scan attributable to an exact snapshot; recording metadata lets
a maintainer triage by whether anyone actually uses a repository.

Repos that failed to clone are recorded with their error, never omitted. A repo
missing from the manifest must mean "not selected", never "silently failed".

### Scope defaults

Defaults are deliberately broad, following the principle already load-bearing in
`supply-chain-ioc-scan`: narrowing scope is how a scan misses what it was run to
find. Archived repos, forks, and non-default branches are all **included** by
default. Narrowing is explicit: `--no-archived`, `--no-forks`,
`--default-branch-only`.

*Recorded trade-off:* `--no-single-branch` multiplies clone size for what the
source playbook classifies as a marginal blind spot. This was chosen
deliberately; `--default-branch-only` exists for users who want the cheaper run.

### Single-repo mode

`build_corpus.py --local <path>` emits a one-entry manifest pointing at an
existing working tree, with no cloning. This is what makes CI lint mode free
rather than a second implementation of every detector.

### `scripts/_walk.py`

Shared file walking for both scanners: prunes `node_modules/`, `vendor/`,
`dist/`, `build/`, `.git/`, and **counts unreadable paths** so a
permission-denied subtree can never be reported as clean.

### Self-test

Asserts hooks are disabled during clone, that an interrupted clone is not
promoted into the corpus, that failed clones appear in the manifest with an
error, and that `--local` produces a valid single-entry manifest.

---

## Skill 2: `repo-packages-scanner`

Detects mutable language-dependency references. Each pass is an independent
detector module operating on a corpus.

| Pass | Detects |
|---|---|
| `actions` | `uses: org/action@v4` / `@main` / `@branch` rather than a 40-hex commit SHA — in `.github/workflows/*.yml`, composite `action.yml`, and reusable-workflow calls. Also `uses: docker://` references |
| `npm` | `^`, `~`, `*`, `x`, `latest`, bare `>=` ranges; missing lockfile; `npm install` rather than `npm ci` in CI; `.npmrc` registry overrides; `overrides` / `resolutions`; dependency `preinstall` / `postinstall` hooks |
| `pypi` | Bare or `>=`-constrained `requirements*.txt` entries; missing `--require-hashes`; Poetry `^` and `*`; unbounded PEP 621 constraints; missing `poetry.lock` / `uv.lock` / `Pipfile.lock`; `--index-url` / `--extra-index-url` overrides (dependency-confusion surface) |
| `remote-exec` | `curl \| bash`, `wget \| sh`, `pip install <url>`, `go install` without a version, remote scripts sourced in CI — unpinned remote code execution, the same threat class as an unpinned dependency |
| `other-langs` | Go: missing `go.sum`, `replace` directives, `@latest`. Rust: `*` constraints, missing `Cargo.lock` for binary crates. Ruby: unpinned `Gemfile`, missing `Gemfile.lock` |

**Independent of pinning**, the `actions` pass separately flags actions owned by
personal accounts and actions whose upstream repository is archived. A
SHA-pinned action from an abandoned personal account is still a supply-chain
risk, and pinning does not address it.

### `scripts/run_gh_scan.sh`

Moved unchanged from `supply-chain-ioc-scan`. It scans a GitHub user's or
organization's repositories for Shai-Hulud campaign markers in repository
descriptions and for suspiciously recent repository creation.

*Recorded trade-off:* this script answers "are we compromised", not "are our
dependencies pinned", and therefore sits oddly in this skill. It was moved here
by explicit decision. `SKILL.md` carries a clearly separated section explaining
what it does and why it lives here, so a reader is not left guessing. Revisiting
its placement later is cheap — it has no callers inside the skill.

### Priority model

Adapted from the source playbook's mutability × execution-context scoring:

- **P0** — executes in CI with credentials, or affects a published artifact:
  unpinned actions in release or publish workflows, `curl | bash` in CI,
  `npm install` in a publishing pipeline.
- **P1** — developer machines and build time: unpinned dev dependencies, local
  install scripts, contributor setup docs.
- **P2** — documentation, examples, demos, and dead repositories. The correct
  fix is often archiving the repository rather than editing it.

---

## Skill 3: `repo-docker-scanner`

Implements the unpinned-image-detection playbook developed during the 2026
Shai-Hulud incident response. Static analysis only: no cluster access, no image
pulls, no chart rendering.

### Mutability classification

Lives in the policy profile, not in code:

| Reference | Class | Mutable |
|---|---|---|
| `img@sha256:…` | digest | No |
| `img:1.27.4` | version | Yes, low risk |
| `img:14`, `img:pg16` | major-only | Yes |
| `img:bullseye-slim`, `ubuntu:trusty` | codename | Yes, patch-mutable; names a fixed release |
| `img:stable`, `:main`, `:nightly` | floating alias | Yes, high risk |
| `img:alpine`, `img:slim` | versionless variant | Yes — this *is* latest on that track |
| `img:latest` | latest | Yes, highest risk |
| `img` (no tag) | untagged | Identical to `:latest` |

The acceptable/unacceptable boundary is a profile setting, and **every report
states the boundary it applied**, so reviewers argue with the policy rather than
with the data.

### Detection passes

**Dockerfiles are parsed, never grepped.** The parser joins backslash
continuations, collects `ARG name=default` and substitutes `$VAR` / `${VAR}` in
`FROM` lines, records stage aliases so `FROM builder` is skipped while
`FROM node` is not, strips `--platform`, skips `scratch`, and additionally reads
`COPY --from=` and `RUN --mount=from=` for non-stage image sources. Discovery is
by filename (`Dockerfile*`, `*.dockerfile`, `Containerfile*`) *and* by content
sniffing for files whose early lines are `# syntax=` / comments / `ARG`
followed by `FROM`, so a renamed Dockerfile cannot evade every name-based pass.

Two grep-filter bugs from the original incident response become explicit
regression assertions in the self-test: excluding lines containing ` AS `
deleted real findings such as `FROM whitfin/geoipupdate AS geoip`, and excluding
one-word `FROM` targets deleted genuine untagged images such as `FROM node`.

**YAML is parsed, not grepped.** Image keys are matched by case-insensitive
`image` substring over the parse tree, which catches `postgresImage:`,
`lbCronImage:`, and `imageReference:` without a hand-maintained key list, and
allows the dbt `reference:` column collision (800+ false positives in the
original run) to be excluded structurally rather than by eye. GitLab CI declares
services as `- name: <image>` rather than `image:`; that form gets its own
sweep, having caught an untagged CI service every `image:` grep missed.

Remaining passes:

- Explicit `:latest` in YAML.
- Floating alias tags (`stable`, `main`, `master`, `edge`, `nightly`, `dev`,
  `develop`, `staging`, `prod`, `production`).
- Digitless variant tags, with codenames separated out per the profile's
  known-codename list.
- Inline `docker pull|run|create` in shell scripts, Makefiles, `package.json`
  scripts, and workflow `run:` blocks — joining multi-line `docker run \`
  continuations, since the image frequently sits on a continuation line. In the
  original run this pass produced the single most serious finding: an untagged
  personal-account image pulled and executed in CI with secrets in scope.
- Registry-hostname sweep across **all** file types (`ghcr.io`, `quay.io`,
  `gcr.io`, `registry.k8s.io`, `mcr.microsoft.com`, `docker.elastic.co`,
  `public.ecr.aws`, `registry.gitlab.com`, `docker.io`, ECR hostnames),
  producing a deduplicated inventory of every registry-qualified reference. Even
  when it finds nothing new this is the primary validation pass.
- Structured configuration: the Helm `repository:` + `tag:` mapping form
  (invisible to every single-line grep, and a *missing* `tag:` means the
  upstream chart default decides what deploys), Kustomize `images:` overrides
  and remote bases, Terraform `image` attributes, `devcontainer.json`, ECS task
  definitions, runner toolset JSON, and build DSLs (Tilt, Bazel, Skaffold,
  Earthly).

**Independent of tag class**, the scanner separately flags personal-account
images (`someuser/tool`) and abandoned namespaces (`bitnamilegacy/…`) in
anything that executes.

### `scripts/probe.py` — adversarial verification as a command

The playbook's most important step, and the one every comparable tool omits.
Given an image name known to be in use, `probe.py <name>` traces it through
every file in the corpus and lists every hit the scan did not explain. Each
unexplained hit is either a false negative — fix the detector, then re-sweep the
whole corpus for that pattern class, not just the one hit — or a correct
exclusion that the report should state a reason for.

This exists because the detection passes will have bugs. In the original run
they had four, and this technique found all four.

### Priority model

- **P0** — CI with credentials (job containers, services, inline `docker run` in
  workflows), production desired state, or shared infrastructure such as
  self-hosted runner images and cluster controllers.
- **P1** — developer machines: compose files, dev CLIs mounting credentials,
  local charts. Developer machines are the actual blast radius of token-stealing
  worms; this tier is not dismissible.
- **P2** — demos, sandboxes, dead pipelines.

---

## Conventions shared by both scanners

Implemented independently per skill (see recorded trade-off below).

### Policy profile

A JSON profile per skill, mirroring the `iocs/*.json` pattern already
established in `supply-chain-ioc-scan`: mutability classes, the acceptable
boundary, registry and namespace ownership, known-benign collisions, known
codenames. Scanners are policy-agnostic; changing policy never means changing
scanner code.

### Outputs

- `report.md` — per-row table (repo, file:line, reference, class, priority,
  note) plus the applied policy and an explicit statement of residual blind
  spots. Checklists get actioned; prose gets read once.
- `findings.json` — machine-readable, for diffing one run against the next.
- `findings.sarif` — uploadable to GitHub code scanning via `gh api`, so
  findings land in each repository's Security tab rather than a file in
  `TMPDIR`. Emitting the file is the default; uploading is opt-in.

Every report states its **residual blind spots** explicitly: tags injected at
deploy time by CI or gitops, upstream chart defaults, template-composed
reference strings, and any repository that failed to clone.

### Baseline / allowlist

A checked-in baseline records accepted risk with a reason, an owner, and a date,
so repeat runs surface only new findings. Findings are fingerprinted on
`(repo, file, normalized reference, class)` — deliberately **not** line number,
so accepted risk stays accepted when a file shifts.

### Opt-in resolution

Static and offline by default. `--resolve` produces copy-pasteable remediation:

- GitHub Actions: `gh api repos/{owner}/{repo}/git/ref/tags/{tag}` →
  `uses: owner/repo@<sha> # v4.1.1`
- Container images: anonymous registry bearer token via stdlib `urllib` →
  `image:tag@sha256:…`, keeping the tag for readability since the digest is what
  is enforced.

Resolution failures are reported per finding and never abort the run.

### Self-test

`tests/selftest.py` per skill builds a synthetic fixture repository containing a
known positive for **every** pass, plus known-benign lookalikes that must not
fire, and asserts both directions. The false-negative assertions matter as much
as the positive ones: a detector that fires on everything is as useless as one
that fires on nothing.

### Exit codes and lint mode

`0` clean, `1` findings, `2` error — matching `supply-chain-ioc-scan`. In
single-repo lint mode the failure threshold defaults to P0 and is configurable
via `--fail-on`. Each skill ships a paste-in GitHub Actions workflow so a
maintainer can enforce pinning on every push rather than auditing once.

### Remediation guidance

Each skill's `SKILL.md` documents that pinning by digest or SHA does not mean
freezing: Renovate and Dependabot both support automated digest and SHA bumps.
The highest-leverage fixes are shared and reusable CI workflows and images,
where one pin covers every consuming repository.

---

## Recorded trade-offs

Three decisions were made explicitly and are cheap to revisit:

1. **Independent per-skill reports.** Each scanner owns its own SARIF, Markdown,
   and baseline implementation, and there is no cross-scan combiner. This
   duplicates fiddly rendering code across two skills. It was chosen for skill
   self-containment and portability. Moving the renderers into `repo-corpus`
   later would not change any detector.
2. **All branches cloned by default.** Costs bandwidth for a blind spot the
   source playbook classifies as marginal. `--default-branch-only` is the
   cheaper path.
3. **`run_gh_scan.sh` in `repo-packages-scanner`.** Domain-mismatched but
   explicitly requested; documented in a separate `SKILL.md` section and
   dependency-free within the skill.

## Implementation sequencing

This spec covers three skills and roughly a dozen detectors, which is more than
one implementation pass should attempt at once. The work decomposes into three
phases, each independently useful and independently verifiable:

1. **`repo-corpus`** — nothing else can be tested without it, and it carries the
   security-sensitive code (hostile-input clone hardening, credential handling).
   Ships with `--local` mode, so both scanners can be developed against a single
   checkout before any org-wide clone is attempted.
2. **`repo-docker-scanner`** — fully specified by the source playbook, including
   its known bugs and false-positive catalogue. Building it second means the
   shared conventions (policy profile, report shapes, baseline, self-test
   structure) get proven on the better-specified of the two scanners.
3. **`repo-packages-scanner`** — reuses every convention settled in phase 2, and
   absorbs `run_gh_scan.sh`.

Marketplace registration, including the existing incorrect
`./skills/supply-chain-security` path, is fixed in phase 1.

## Success criteria

- Both scanners run clean against a synthetic fixture and detect every seeded
  positive, verified by `tests/selftest.py`.
- Neither scanner fires on the documented benign lookalikes: Unicode data
  tables, `motion-dom` helper files, dbt `reference:` columns, Ansible AMI ids,
  asset paths, and Dockerfile stage aliases.
- The four historical grep-filter bugs are covered by explicit regression
  assertions.
- Every detection pass named in the playbook has a corresponding detector and a
  fixture case; no pass is silently dropped during implementation.
- Running either scanner against the `tomkat-cr` organization completes and
  produces an attributable, reviewable report.
- SARIF output validates against the SARIF 2.1.0 schema.
