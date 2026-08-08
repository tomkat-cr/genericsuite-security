# Implementation Plan: Phase 2 — `repo-docker-scanner`

**Date:** 2026-08-07
**Status:** Ready to implement
**Spec:** `docs/superpowers/specs/2026-08-06-repo-scanner-skills-design.md`
**Source playbook:** `tmp/unpinned-image-investigation.md`
**Depends on:** phase 1 (`repo-corpus`), complete

Phase 3 (`repo-packages-scanner`) is out of scope and gets its own plan.

## What phase 2 delivers

A scanner that consumes a corpus and reports every mutable container-image
reference in it, prioritised by execution context. Static analysis only: no
cluster access, no image pulls, no chart rendering.

```
skills/repo-docker-scanner/
├── SKILL.md
├── policy/images.json            mutability classes, boundary, registries, codenames
├── scripts/
│   ├── scan_images.py            driver: corpus in, findings out
│   ├── _dockerfile.py            the parser (NOT grep)
│   ├── _yamlish.py               indentation YAML reader (stdlib-only)
│   ├── _detectors.py             one function per pass
│   ├── _report.py                report.md / findings.json / findings.sarif
│   ├── probe.py                  adversarial verification as a command
│   └── run_docker_scan.sh        self-test, then corpus, then scan
└── tests/
    ├── selftest.py
    └── fixtures/                 a synthetic repo with a positive per pass
```

It reuses `repo-corpus`'s `_walk.py` by path (`../repo-corpus/scripts`), not by
copy — with a fallback error message if the sibling skill is missing.

---

## Decisions this plan settles

### E1 — YAML is parsed by a stdlib-only subset reader, and says so

The spec says "YAML is parsed, not grepped." Python's stdlib has no YAML
parser, and this package's house rule is stdlib-only — no venv, no
`requirements.txt`. So `_yamlish.py` is a purpose-built **indentation reader**,
not a YAML implementation. It yields `(key_path, value, line_no)` for scalars
and handles: nested mappings, `- ` sequence items, `- name: x` (the GitLab CI
services form), quoted scalars, inline `#` comments, and document separators.

It deliberately does **not** implement: anchors/aliases, flow mappings
(`{a: b}`), multi-line block scalars (`|`/`>` — their content is skipped, not
parsed), or merge keys. Each is a **stated blind spot in every report**, not a
silent gap. A block scalar containing a `docker run` is still caught, because
the inline-command pass (Task 6) reads raw text and does not depend on YAML
structure at all — the two passes overlap deliberately.

*Rejected:* optional PyYAML with fallback. Two parsers means two behaviours,
two sets of findings, and a self-test that only ever exercises one of them.

### E2 — Priority is computed from path + context, and lives in the profile

The playbook's P0/P1/P2 tiers are execution-context judgements. The mapping
from "where the file is" to "what tier" lives in `policy/images.json` as an
ordered rule list (first match wins), so retuning is a profile edit:

```jsonc
"priority_rules": [
  {"tier": "P0", "when": {"path_glob": ".github/workflows/*"},   "why": "CI with credentials"},
  {"tier": "P0", "when": {"path_glob": "**/kustomization.yaml"}, "why": "production desired state"},
  {"tier": "P1", "when": {"path_glob": "**/docker-compose*.y*ml"}, "why": "developer machines"},
  {"tier": "P2", "when": {"repo_archived": true}, "why": "dead repository"},
  {"tier": "P1", "when": {}, "why": "default"}
]
```

The open question the handoff flagged — are the tier boundaries right? — is
**not resolved by this plan**, deliberately. It is resolved by Task 12:
running against the real `tomkat-cr` corpus and reading the tier histogram. A
P0 tier that lights up 200 findings on first run is wrong regardless of how
defensible it looks in the abstract, because the gate gets switched off. The
numbers come back to the author with a recommendation.

`--fail-on` defaults to `P0` per the spec. Whether that default is livable is
the same Task 12 question.

### E3 — Findings are fingerprinted without line numbers

Per the spec: `(repo, file, normalized_reference, class)`, SHA-256, first 16
hex. Line numbers deliberately excluded so accepted risk survives a file
shifting. The normalized reference lowercases the registry/name, keeps the tag
verbatim (tags are case-sensitive), and strips a `docker.io/` /
`index.docker.io/` prefix and a bare `library/` namespace so `nginx`,
`docker.io/nginx` and `docker.io/library/nginx` fingerprint identically.

### E4 — A file that cannot be parsed is a finding of its own

If `_dockerfile.py` or `_yamlish.py` raises on a file, that file is recorded in
`unparsed[]` with the exception, counted in the report, and the run's verdict is
downgraded exactly as unreadable paths are. A parser that crashes quietly on
20 files is the "silent clean" failure this package exists to prevent.

### E5 — `probe.py` is scoped to a corpus, and reports *unexplained* hits

`probe.py --corpus <corpus.json> <name>` greps every walked file for the name,
then subtracts every hit the scan already explains (a finding, or an explicit
exclusion with a reason). What remains is printed as UNEXPLAINED. Exit `1` when
anything is unexplained — so a probe can run in the self-test and fail it.

---

## Task sequence

Each task states its acceptance check first.

### Task 1 — `policy/images.json`

**Check:** loads; self-test asserts every key the detectors read is present.

Contents: mutability classes and the boundary (`acceptable: [digest, version,
codename]`), floating alias tags, known codenames (`wheezy`…`bookworm`),
registry hostnames, ECR hostname pattern, official-namespace list, known
abandoned namespaces (`bitnamilegacy`), `priority_rules`, and
`known_benign_collisions` (dbt `reference:`, `ami-*`, asset extensions).

### Task 2 — `_dockerfile.py`

**Check:** the two historical grep bugs are regression assertions —
`FROM whitfin/geoipupdate AS geoip` **is** reported, and `FROM node` **is**
reported; `FROM builder` (a stage alias) is not.

Joins `\` continuations; collects `ARG name=default` and substitutes
`$VAR`/`${VAR}` (including `${VAR:-default}`) in `FROM`; records stage aliases
and skips later references to them; strips `--platform=`; skips `scratch`;
also reads `COPY --from=` and `RUN --mount=...,from=`. Discovery by filename
(`Dockerfile*`, `*.dockerfile`, `Containerfile*`) **and** by content sniff
(early lines are `# syntax=`/comment/`ARG`, then `FROM`).

### Task 3 — `_yamlish.py`

**Check:** yields correct `(key_path, value, line)` for a nested fixture; a
`|` block scalar's body is not misread as keys; `- name: img` is reached.

### Task 4 — classification

**Check:** every row of the spec's mutability table maps to its class, asserted
one row per assertion. `redis:alpine` → versionless variant (not "tagged,
fine"); `ubuntu:trusty` → codename; `img` → untagged; `img:1.2.3@sha256:…` →
digest.

### Task 5 — YAML detectors

**Check:** finds `:latest`, untagged image-ish keys, floating aliases,
digitless variants, and the GitLab `- name:` services form; does **not** fire
on the documented false positives.

Image keys matched by case-insensitive `image` substring over key paths — which
catches `postgresImage:`, `lbCronImage:`, `imageReference:` without a
hand-maintained list. The dbt `reference:` collision is excluded
**structurally** (it is not an `image`-substring key) rather than by eye.

### Task 6 — inline `docker pull|run|create`

**Check:** an image on a `docker run \` continuation line is found — the
playbook's single most serious finding was of exactly this shape.

Reads raw text (not YAML), joins continuations, and scans `*.sh`, `Makefile*`,
`package.json` scripts, and workflow `run:` blocks.

### Task 7 — registry sweep + structured config

**Check:** produces a deduplicated inventory across all file types; Helm
`repository:`+`tag:` pairs are matched, and a **missing** `tag:` is its own
finding class.

Plus Kustomize `images:`/remote bases, Terraform `image`, `devcontainer.json`,
ECS task definitions, runner toolset JSON, Tilt/Bazel/Skaffold/Earthly.

### Task 8 — ownership flags

**Check:** `someuser/tool` flags as personal-account; `bitnamilegacy/keycloak`
flags as abandoned namespace; `nginx` and `ghcr.io/org/x` do not.

Independent of tag class — a digest-pinned image from a dead personal account
is still a supply-chain risk.

### Task 9 — priority, baseline, fingerprints

**Check:** the same finding keeps its fingerprint when its line moves; a
baselined finding is suppressed; an un-baselined one is not.

### Task 10 — reports

**Check:** `findings.sarif` validates against SARIF 2.1.0 (structural
assertion in the self-test: required properties present, `ruleId` resolvable);
`report.md` states the applied policy boundary and the blind-spot list.

### Task 11 — `probe.py`, `run_docker_scan.sh`, `SKILL.md`, registration

**Check:** `probe.py --corpus … nginx` on the fixture returns 0 unexplained;
marketplace registers the new skill and the phase 1 assertion still passes.

### Task 12 — calibration run

**Check:** run against the real `tomkat-cr` corpus (`--include prico` at
minimum) and produce the tier histogram.

Report back: findings per tier, the ten highest-priority rows, and whether
`--fail-on P0` is livable. This is the evidence the E2 open question needs.

---

## The four historical bugs become assertions

Non-negotiable; each is a named self-test assertion:

1. ` AS ` exclusion deleted `FROM whitfin/geoipupdate AS geoip`.
2. One-word `FROM` exclusion deleted `FROM node`.
3. Path-prefix exclusions silently discarded every hit in the searched
   directory — asserted by scanning a corpus rooted at a path containing an
   excluded-looking segment (e.g. `.../tilt/...`) and requiring findings.
4. A generic `reference:` key collided with 800+ dbt columns — asserted as a
   negative on a dbt-shaped fixture.

## Known-benign negatives (must not fire)

Unicode data tables, `motion-dom` helpers, dbt `reference:` columns, Ansible
`ami-…`, asset paths (`image: logo.png`), Dockerfile stage aliases,
`FROM scratch`, and commented-out lines.

## Risks

| Risk | Mitigation |
|---|---|
| The subset YAML reader mis-parses real files | Unparsed files become findings (E4); the raw-text passes overlap the structural ones; limits stated in every report |
| Tier boundaries wrong → 400-finding P0 | Task 12 measures before the default is trusted; rules live in the profile |
| Detector bugs (the playbook had four) | `probe.py` is shipped as a command and run in the self-test |
| macOS/old-git environment differences | Phase 1's lesson: verify on the author's machine, not only in CI |
