---
name: project-weakness-analysis
description: Use when deciding whether one or many projects are ready and safe to run in production — scoring production-readiness and auditing security weaknesses across a directory of projects, an explicit list, a GitHub org, or a project registry table. Triggers: "is this ready for production", "audit my projects", "production readiness review", "security weaknesses in my projects", "which of my projects are safe to deploy", "scan all projects in this folder". Not for mutable-reference auditing — that is repo-docker-scanner and repo-packages-scanner.
license: MIT
metadata:
  author: tomkat-cr
  version: "1.0"
---

# Project Weakness Analysis

## Overview

Score whether a project is ready and safe to run in production, across two
axes that are reported side by side and **never averaged**:

- **Readiness** — is this a real, well-built application, or boilerplate with
  a good README? Auth, error handling, tests, CI, code organization.
- **Security risk** — does it leak secrets, skip auth on state-changing
  endpoints, expose PII, or carry an unpinned supply-chain dependency?

A project can be an excellent, well-organized application *and* carry a
critical security risk. Averaging those into one number would hide exactly
the case this skill exists to surface, so nothing in the pipeline ever does.
Both axes are reported per project, independently.

## When to Use

- Before deploying a project, or before pointing a client/user at it
- Triaging a directory of many projects — your own apps, forks, client work,
  experiments — to see which need work before anything else
- Re-running after fixes land, to verify which findings actually resolved
- **Not for**: auditing whether container images or GitHub Actions/dependency
  references are pinned to an immutable identity — that is `repo-docker-scanner`
  and `repo-packages-scanner`. This skill consumes their findings as evidence
  for the security axis; it does not duplicate their detectors.

## Quick Start

Exactly one input mode, five to choose from:

```bash
./scripts/run_weakness_analysis.sh --root ~/dev              # discover every project under a directory
./scripts/run_weakness_analysis.sh --projects ~/a ~/b ~/c    # an explicit list
./scripts/run_weakness_analysis.sh --corpus path/corpus.json # an existing repo-corpus manifest
./scripts/run_weakness_analysis.sh --org tomkat-cr           # clone a GitHub org via repo-corpus
./scripts/run_weakness_analysis.sh --db                      # read a project registry table (optional)
```

**No database is required.** `--db` is optional — one of five ways to obtain
a project list, and the only one that touches a database. `--root`,
`--projects`, `--corpus`, and `--org` involve no database at all, need no
credentials, and make no DB-related network call. Reach for `--db` only when
the list of projects to scan already lives in a Supabase/Postgres table; every
other case is `--root` or `--projects`.

The driver runs `tests/selftest.py` first and refuses to run if it fails —
the same refusal every scanner in this plugin applies.

## The Two-Phase Run

A skill's own scripts cannot spawn subagents — a Claude Code session can, but
a shell script invoked from one cannot start another one. So this cannot be
one command end to end. It is two:

```bash
./scripts/run_weakness_analysis.sh --root ~/dev     # phase 1: collect
# → prints insights/.work/agents/tasks.json and stops
# → Claude (you) dispatch every task in it as a subagent — see Dispatch Protocol below
./scripts/run_weakness_analysis.sh --phase merge    # phases 3-5: merge, report, gate
```

Phase 1 (`collect`, the default for every input flag) is fully deterministic:
it resolves the input into a corpus, walks every project, collects evidence,
runs the sibling scanners, and writes the task manifest. Nothing after that
point is a shell script's job — the two scoring axes are AI judgments, and
they are dispatched from this Claude Code session, not from the driver.
`--phase merge` then joins the agents' output, derives verdicts, writes the
report, and applies the gate.

## Dispatch Protocol

This is the section you (Claude) follow after phase 1 completes.

1. Read `insights/.work/agents/tasks.json`. It is a JSON array; each entry
   carries everything needed to dispatch it — `id`, `stage` (`analyze` or
   `security`), `project_slug`, `model`, `agent_type`, `output_path`,
   `schema`, and a full literal `prompt`.
2. Dispatch every task as a subagent, using its own `model` and `agent_type`
   verbatim — do not substitute your judgment for the manifest's. Run at most
   `dispatch.max_parallel` (from `policy/weakness.json`, default 6) at a time.
3. Give each subagent its `prompt` unmodified, and instruct it to write JSON
   matching `schema` to its `output_path`, returning only a one-line
   confirmation. Findings travel through files, not through your own context —
   that is what keeps a batch of many projects feasible.
4. **Never write a task's output file yourself.** If a subagent fails, errors,
   or times out, leave `output_path` absent. Do not fill it in with a
   plausible-looking result. `merge_insights.py` records the gap as `unknown`
   and it is counted in the blind-spot section — a dispatcher inventing a
   result is the worst failure mode this skill has, because it turns an
   honest "we don't know" into a false "clean."
5. Optionally, once all tasks are dispatched and phase 1's evidence is merged,
   write a short executive rollup to `insights/.work/digest.md` using a haiku
   agent reading the merged `insights.json`. It makes no per-project judgment
   and **cannot change a score, a tier, or the exit code** — if it fails or is
   skipped, `gen_report.py` produces the report without it and says so.

## Verdict Model

| Axis | Values | Derived from |
|---|---|---|
| **Readiness** | tiers in `policy/weakness.json`'s `readiness_order` | the `analyze` agent's sub-scores, via `readiness_rules` |
| **Security risk** | severities in `policy/weakness.json`'s `severity_order`, or `none` | the `security` agent's still-open findings (`open`/`partial`/`new`) |

`unknown` is a **blocking** readiness tier, not a neutral one. A project no
agent successfully scored is not a project known to be safe — the same rule
`repo-corpus` applies to a partial corpus, here applied per project. See
`policy/weakness.json`'s `readiness_rules` for the exact score thresholds and
`severity_order` for the risk ladder — this file is the source of truth for
both; nothing here or in the generated report hand-types a boundary that could
drift from it.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Every project passes both gates |
| `1` | At least one project is **blocked** — never "error" |
| `2` | Error — no report produced (bad arguments, unreadable output path, no usable corpus, no projects discovered) |

Exit `1` has exactly one meaning across both gates: `--fail-on SEVERITY`
(security) blocked a project, or `--fail-on-readiness TIER` (readiness)
blocked one, or both did. Either way it is reported as **blocked**, not as an
error — a run that could not produce a report must never look like a run that
found problems, and a run that found problems must never look like it
crashed.

## Output

Everything lands under `./insights` (override with `--out PATH`). Nothing is
ever written inside a scanned project.

```
insights/
  WEAKNESS-REPORT.md      human-readable, all projects
  insights.json           machine-readable master record (nested)
  insights-table.json     flat projection, one row per project
  insights-table.csv      the same rows, spreadsheet-openable
  security-audit.json     per-project findings + status; read by the NEXT run
  projects/<slug>.json    one record per project
  findings.sarif          for GitHub code-scanning upload
  .work/                  corpus, evidence, agent I/O - regenerable (--keep-work to preserve)
```

The flat projection (`insights-table.json` / `.csv`, and the report's Project
matrix table) is the **same column set**, in the same order, as
`references/project-insights.sql` — one column per entry in
`policy/weakness.json`'s `table_columns`. That DDL is provided for anyone who
wants to load the projection into their own database; the skill never runs it
and never writes to a database itself.

## Re-audit

Run the skill a second time over the same (or updated) projects and it
verifies its own prior findings rather than starting over. When
`insights/security-audit.json` exists from a previous run, each project's
prior findings are inlined into its security prompt, and the agent's primary
job becomes checking each one against the current code: `resolved` (properly
fixed), `partial` (mitigated but still exploitable), or `open` (unchanged).

**No prior finding is ever dropped.** A resolved finding is still listed, with
its status updated — it does not vanish from the record. New issues found this
run are added with status `new`. A prior finding that the agent's output
simply omits is treated as still open, not as fixed by silence; a finding
disappearing between runs is the one failure mode that would make re-audit
actively harmful, since it would read as "fixed" without anyone having checked.

## Policy and Profiles

Everything opinionated — project markers, readiness rules, severity order,
gate defaults, dispatch concurrency, secret patterns and their benign-lookalike
exclusions, and the flat-projection column list — lives in
`policy/weakness.json`. Scanner code stays policy-agnostic.

- `--profile generic` (default) — framework-neutral, works on any project in
  any language.
- `--profile genericsuite` — adds this ecosystem's non-negotiables as agent
  instructions: scrypt-only password hashing, the standard
  `{"error", "error_message", "resultset"}` return shape, parameterized SQL
  with identifier quoting, `is_safe_url()`/`is_safe_local_path()` guards, and
  log-injection prevention.
- `--profile ./my-rules.json` — any path loads a bring-your-own overlay.

A profile may **add** checks and agent instructions. It may never remove a
generic check or lower a severity — narrowing a scan to make it pass is how a
scan stops being worth running.

## Blind Spots

The report's Blind Spots section states what a "no findings" result does not
cover:

- Any project the corpus failed to obtain (`repo-corpus`'s `totals.failed`)
- Any project marked `unknown` because its agent output was missing or failed
  schema validation — counted and named, never silently dropped
- Any sibling scanner (`repo-docker-scanner`, `repo-packages-scanner`) that
  was unavailable, not installed, or failed — named with its reason
- Pruned directories, unreadable paths, and oversized files from the walk
- Any discovery truncation — `--max-depth` or `--limit` hit
- That every score is AI-generated from a point-in-time snapshot: a strong
  first pass, not ground truth. Re-running is cheap and is how findings get
  verified, not assumed.

A report never states "no findings" more broadly than the list of projects it
actually walked.

## Self-Test

```bash
python3 tests/selftest.py
```

The driver runs this automatically before phase 1 and refuses to analyze if
it fails — the same refusal `run_corpus.sh`, `run_docker_scan.sh`, and
`run_packages_scan.sh` already apply. A "clean" result from a driver that
hasn't passed its own self-test is unknown, not clean.

## Common Mistakes

- **Treating exit `1` as an error.** It means at least one project is
  blocked — findings, not failure. Exit `2` is the error code.
- **Treating `unknown` readiness as clean.** An unscanned or invalidly-scanned
  project is not a project known to be safe; it blocks by default.
- **Writing a subagent's output file by hand** when it fails or times out.
  Leave it absent — a dispatcher inventing a plausible result is worse than an
  honest gap, because `merge_insights.py` can no longer tell the difference.
- **Assuming `--db` is required.** It is the one optional input mode; four
  others need no database, no credentials, and no DB-related network call.
- **Narrowing scope to make a run pass.** Prefer `--limit`, `--include`, or a
  smaller `--projects` list — all visible in the report — over quietly
  excluding the project that would have failed the gate.
