---
name: repo-docker-scanner
description: Use when auditing container image references for mutability — finding every `:latest`, untagged, or floating-tag image across one repo or a whole GitHub org, and prioritising by where it executes. Triggers: "unpinned images", "are our docker images pinned", "find :latest", "image digest pinning", "container supply chain audit", "which images are mutable", "pin our docker images". Not for detecting a known compromise — that is supply-chain-ioc-scan.
license: MIT
metadata:
  author: tomkat-cr
  version: "1.0"
---

# Repo Docker Scanner

## Overview

Find every **mutable** container-image reference across a corpus and prioritise
it by where it executes. Static analysis only: no cluster access, no image
pulls, no chart rendering, and nothing from a scanned repository is executed.

A reference is mutable unless it names an immutable identity — a digest.
Anyone who can push to a tag (a stolen registry token, a compromised maintainer
account, an abandoned namespace) silently changes what CI runs and what
production deploys, **with no commit in any repository**. That is why every
`:latest` in a pipeline holding credentials is an open door.

Risk is not uniform. Every finding is scored on two axes: **how mutable** (the
class) and **where it executes** (the tier).

## When to Use

- Auditing pinning across an org, or enforcing it on one repo in CI
- After a registry-token compromise, to find what an attacker could have
  redirected
- **Not for**: determining whether a specific disclosed campaign touched a
  machine — that is `supply-chain-ioc-scan`

## Quick Start

```bash
./scripts/run_docker_scan.sh --org tomkat-cr          # builds a corpus, then scans
./scripts/run_docker_scan.sh --local .                # one checkout, CI lint mode
./scripts/run_docker_scan.sh --corpus path/corpus.json
```

The driver runs the self-test first and refuses to scan if it fails. Reports
land next to the corpus in `docker-scan/`: `report.md`, `findings.json`, and
`findings.sarif` (uploadable via `gh api`, so findings appear in each
repository's Security tab).

Exit `0` no findings at the threshold, `1` findings, `2` error.
`--fail-on` defaults to `P0`; `--fail-on none` reports without failing.

This skill consumes a corpus from `repo-corpus` and shares its `_walk.py` by
path rather than by copy — install both side by side.

## What Counts as Unpinned

| Reference | Class | Mutable |
|---|---|---|
| `img@sha256:…` | `digest` | No |
| `img:1.27.4` | `version` | Yes, low risk |
| `img:14`, `img:pg16` | `major_only` | Yes — tracks releases |
| `img:bullseye-slim`, `ubuntu:trusty` | `codename` | Yes, patch-mutable; names a fixed release |
| `img:stable`, `:main`, `:nightly` | `floating_alias` | Yes, high risk |
| `img:alpine`, `img:slim` | `versionless_variant` | Yes — **this IS latest** on that track |
| `img:latest` | `latest` | Yes, highest risk |
| `img` | `untagged` | Identical to `:latest` |
| `${IMAGE}:x` | `unresolved` | Unknown — composed at deploy time |

The **acceptable boundary is policy, not code**: `policy/images.json` sets it
(default `digest`, `version`, `codename`), and every report states which
boundary it applied, so reviewers argue with the policy rather than the data.

`unresolved` exists so the scanner never implies it checked something it could
not see.

## Priority Tiers

- **P0** — runs in CI with credentials (workflows, GitLab CI, composite
  actions), production desired state (Kustomize, Terraform, ECS), or shared
  infrastructure (self-hosted runner toolsets).
- **P1** — developer machines: compose files, devcontainers, Dockerfiles.
  **Developer machines are the actual blast radius of token-stealing worms;
  this tier is not dismissible.**
- **P2** — examples, demos, docs, archived repositories. The right fix for an
  archived repo is usually deleting it, not editing it.

Tiers are an ordered rule list in the profile (first match wins), so retuning
is a profile edit, never a code change.

## Detection Passes

**Dockerfiles are parsed, never grepped.** The parser joins `\` continuations,
substitutes `ARG` defaults into `FROM`, records stage aliases so `FROM builder`
is skipped while `FROM node` is not, strips `--platform`, skips `scratch`, and
reads `COPY --from=` and `RUN --mount=…,from=`. Discovery is by filename **and**
by content sniff, so a renamed Dockerfile cannot evade every name-based pass.
Filename matching is by **prefix and case-insensitive** — `Dockerfile.dev`,
`Dockerfile-api`, `api.dockerfile`, and a plain `dockerfile` from a
case-insensitive checkout (macOS, Windows) are all recognised, because a missed
Dockerfile is a whole file's worth of `FROM` lines silently absent from the
report. The `**/Dockerfile*` priority rule matches the same way, so a
case-varied Dockerfile still lands in its real tier instead of falling through
to the P1 default.

**YAML is read structurally.** Image keys are matched by case-insensitive
`image` substring over key paths, which catches `postgresImage:`,
`lbCronImage:` and `imageReference:` with no hand-maintained key list — and
structurally excludes the dbt `reference:` collision that produced 800+ false
positives in the original run. GitLab CI's `- name:` services form gets its own
sweep; it caught an untagged CI service every `image:` grep missed.

Also: Helm `repository:` + `tag:` mapping (invisible to any single-line grep,
and a **missing** `tag:` is its own finding — the upstream chart decides what
deploys), inline `docker pull|run|create` with continuation lines joined,
JSON config (devcontainer, ECS task definitions, runner toolsets), and a
registry-hostname sweep across **all** file types.

**The passes deliberately overlap.** The structural YAML reader cannot see
inside a `run: |` block scalar; the inline-command pass reads raw text and does
not care about YAML at all. Redundancy is the point — a single pass with a
blind spot produces a clean report.

## Verify With Adversarial Probes

The most important step, and the one every comparable tool omits:

```bash
python3 scripts/probe.py --corpus corpus.json --findings docker-scan/findings.json nginx
```

Pick an image you **know** is in use and trace it through every file; the probe
prints every hit the scan does not explain. Each is either a false negative —
fix the detector, then **re-sweep the whole corpus for that pattern class**, not
just that one hit — or a correct exclusion the report should give a reason for.

This exists because the detection passes will have bugs. In the original
incident response they had four, and this technique found all four. Probe with
names from different ecosystems and stop when probes keep coming back explained.

## What This Scanner Cannot See

Stated in every report, because a reader who does not know them will over-read
a clean result:

- **Tags injected at deploy time** by CI or gitops. An empty `tag:` in values
  says nothing about what production actually runs.
- **Upstream Helm chart defaults.**
- **Template-composed references** — reported as `unresolved`, never clean.
- **YAML anchors/aliases, flow mappings, and block-scalar bodies.** The reader
  is an indentation reader, not a YAML implementation (stdlib-only by house
  rule). Inline `docker` commands inside a `run: |` block are still caught by
  the raw-text pass.
- **Repositories that failed to clone**, and every branch other than the one
  checked out in the corpus. Use `repo-corpus --branch` to pin which one.
- **Files that could not be parsed** — listed as their own report section.
  Neither clean nor dirty: unexamined.
- **Deliberately excluded files** — counted and listed. A silent exclusion is
  how a real finding disappears.

## Triage Rules

**A filename or a key name is never a finding by itself.** The four grep-filter
bugs from the original run all *deleted* true findings and all made the report
look cleaner. Each is now a named regression assertion:

| Bug | What it deleted |
|---|---|
| Excluding ` AS ` lines | `FROM whitfin/geoipupdate AS geoip` — an untagged personal image in a production build |
| Excluding one-word `FROM` | `FROM node` — a genuine untagged image |
| Path-prefix exclusions | every hit under the searched directory |
| Generic `reference:` key | collided with 800+ dbt columns |

**Namespace flags are separate from mutability.** An `abandoned_namespace`
(`bitnamilegacy/…`) is a finding regardless of tag — pinning does not address
abandonment. An `unverified_namespace` is **not** a finding: it describes most
of Docker Hub, and promoting each one would bury the unpinned references the
report exists to surface. Those go to a watch list. The scanner deliberately
does not claim to know whether a Docker Hub namespace is a person or an
organisation — that cannot be determined statically, and false precision in a
report meant to be acted on is worse than none.

## Baseline

Accepted risk lives in a checked-in baseline so repeat runs surface only what
is new:

```json
{"accepted": [{"fingerprint": "…", "reason": "…", "owner": "…", "date": "…"}]}
```

Findings are fingerprinted on `(repo, file, normalized reference, class)` —
deliberately **not** the line number, so accepted risk stays accepted when a
file shifts. Baselined findings are counted in the report, never hidden.

## Self-Test

```bash
python3 tests/selftest.py
```

Builds a synthetic repository with a known positive for **every** pass and
asserts each fires, then asserts the documented benign lookalikes do not:
digest-pinned images, codename tags, dbt `reference:` columns, Ansible AMI ids,
asset paths, chart repo URLs, `FROM scratch`, and stage aliases. The negative
assertions matter as much as the positive ones — a detector that fires on
everything is as useless as one that fires on nothing.

## Remediation

- Pin by digest: `image:1.2.3@sha256:…`. The tag stays for readability; the
  digest is what is enforced. Renovate and Dependabot both bump digests, so
  **pinning is not freezing**.
- Fix shared and reusable CI workflows and images first — one pin there covers
  every consuming repository.
- Replace unverified-namespace images with official images or an org-controlled
  mirror (e.g. an ECR pull-through cache), then pin the mirror.
