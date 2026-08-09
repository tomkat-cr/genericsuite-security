# Weakness Analysis Methodology

How every project handed to this skill is scored. The goal: from a pile of
projects, surface which are **ready and safe** to run in production — and
which need work first.

Everything is reproducible: the exact scan command is captured and printed in
every report (see `SKILL.md`'s "Output" section). Scores are AI-generated from
the actual source tree — a strong, evidence-based first pass, **not** ground
truth. Re-running is cheap, and re-running is how a finding gets verified
rather than assumed.

## Adapted from

This methodology is adapted from an internal OSS-project-triage pipeline
(`tmp/project-analysis/analysis/METHODOLOGY.md` in this checkout). That source
targeted deciding which of many submitted community projects were polished
enough to feature and promote — a different question from "is this safe to
run in production." `tmp/` is gitignored in this package, so nothing under it
survives a fresh clone; this file is the surviving, adapted copy, rewritten
for a production-readiness and security audience.

Three things were carried over deliberately, because they hold regardless of
what the score is used for:

- **One agent per project per axis**, so no agent sees another project's score
  and there is no ranking contamination.
- **Evidence-based scoring.** Score what the code actually contains, not what
  the README claims. Boilerplate and empty scaffolding score low on purpose.
- **The re-audit loop.** On a repeat run, every previous finding is re-checked
  against the current code and marked `resolved` / `partial` / `open`. This is
  what tells apart a project that actually fixed an issue from one that did
  not, and it is what makes the skill a living check rather than a one-shot
  report.

Everything specific to choosing what to feature — live-demo fetching, a
readiness-to-feature rubric, promotional tiers, and a marketing-style
single-sentence summary — was dropped entirely. None of it answers whether a
project is safe to run.

## The pipeline (5 stages)

```
1. Collect   → discover every project, walk its tree, gather deterministic signals
2. Analyze   → read the CODE; score architecture & production-readiness
3. Security  → audit for secrets/auth/PII gaps; re-check prior findings
4. Merge     → validate agent output, join with evidence, derive verdicts
5. Report    → write the report, the flat projection, and the SARIF file
```

Each project gets its **own AI agent** at stages 2 and 3 (one agent, one
project, one axis) so judgments stay independent and parallel — the analyze
agent never sees the security agent's output or vice versa. Agents are told to
be skeptical and **evidence-based**: score what the code contains, not what
documentation claims. Boilerplate and empty scaffolding score low on purpose.

## Stage 1 — Collect (deterministic, no AI)

- **Resolve the input.** Whichever of the five input modes was given
  (`--root`, `--projects`, `--corpus`, `--org`, `--db`) resolves to the same
  `corpus.json` manifest shape the sibling scanners already consume.
- **Walk + measure.** For each project: lines of code by language, file
  count, manifests and lockfiles present, test/CI/README/LICENSE presence,
  deploy configuration, `.env*` files tracked in git, and a deterministic
  secret-candidate scan.
- **Reuse, don't rediscover.** `repo-docker-scanner` and `repo-packages-scanner`
  are run over the same corpus and their findings are folded into each
  project's evidence bundle, so the agents start from what a script can
  already prove instead of re-deriving it.
- **Unreadable is not clean.** Pruned directories and unreadable paths are
  counted, not skipped silently, and surface in the report's blind-spot
  section.

## Stage 2 — Analyze the code (one AI agent per project)

The agent inspects the actual source — manifests/lockfiles, Dockerfile/CI, the
DB access layer (ORM vs. raw SQL vs. BaaS client), auth, error handling,
secret management, tests — and returns:

| Dimension | Scale | What it measures |
|---|---|---|
| **Maturity** | 1–5 | Real product vs. boilerplate (README/tests/CI, iterated commits) |
| **Production-readiness** | 1–5 | Auth, error handling, logging, env/secrets, deploy config |
| **Code organization** | 1–5 | Structure, naming, documentation quality |
| **Maintainability** | 1–5 | Can a new maintainer safely change this — coupling, dead code, dependency freshness |

**Rubric:** `1` = empty skeleton · `2` = early prototype · `3` = working MVP ·
`4` = polished/usable · `5` = production-grade.

Plus stack detection, an architecture assessment (pattern, ORM usage,
separation of concerns), explicit `weaknesses[]` and `red_flags[]`, and a
one-paragraph summary. Reasoning fields are capped at 1–3 sentences so a
batch of many projects stays reviewable.

## Stage 3 — Security audit + re-audit (one AI agent per project)

A separate axis from readiness, scored by a separate agent that never sees the
analyze agent's output. The auditor hunts for the failure modes that matter
before anything goes live:

- Committed secrets (service-role keys, API keys, DB URLs, signing secrets)
- Missing auth on state-changing endpoints; mass assignment
- PII exposure via public/anon access or over-broad API responses
- Row-level security disabled / anon write access; over-broad CORS
- Injection, SSRF, open proxies, unrestricted upload, path traversal
- Insecure defaults: debug mode on, verbose errors to clients, weak password
  hashing
- Dependency risk escalated from the sibling scanners' findings, judged in
  context

Each project gets an overall **security risk**
(critical / high / medium / low / none) = the severity of its worst
still-open finding. Every finding must cite a file and line; a finding that
cannot be pointed at in the actual code is not reported.

**Re-audit (what makes this a living check).** On a repeat run, the agent does
not just re-scan from scratch — for every *previous* finding it opens the
current code and marks it:

- **resolved** — properly fixed
- **partial** — mitigated but still exploitable
- **open** — unchanged

...then scans for **new** issues. The report shows each finding's status and
the risk delta versus the last audit (e.g. "was high"). This is how the report
tells a project that *actually fixed* its issues apart from one that did not.
No previous finding is ever dropped from the record, even once resolved.

## Stage 4 — Merge (deterministic, no AI)

Analyze output, security output, and the deterministic evidence bundle are
validated against their schemas and joined per project. A project whose agent
output is missing or fails schema validation is marked `unknown` — a blocking
state, never a neutral or clean one. Readiness tiers are derived from
`policy/weakness.json`'s `readiness_rules`; security risk is derived from the
worst still-open finding. Neither axis is ever averaged into the other.

## Stage 5 — Report (deterministic, plus one optional digest agent)

The per-project records are rendered into `WEAKNESS-REPORT.md`, the flat
projection (`insights-table.json`/`.csv`), and `findings.sarif`. One optional
haiku agent reads the merged result and writes a short executive rollup — it
makes no per-project judgment and cannot change a score, a tier, or the exit
code; if it fails, the report is generated without it and says so.

## What the scores are — and aren't

- **A strong first pass, not a verdict.** Every score is AI-generated from one
  snapshot of the source tree. Treat it as a first pass, not a final grade.
- **Independent per project.** No agent sees another project's scores, so
  there is no ranking contamination — but also no cross-project calibration
  beyond the shared rubric.
- **Point-in-time.** Code changes; a score reflects it at the commit scanned.
  The security section additionally records when it was (re-)audited, so a
  stale audit is visible rather than assumed current.
- **Two separate axes.** A project can be well-built and organized *and* carry
  a critical security risk — those are reported independently, on purpose,
  and never averaged into one number.
