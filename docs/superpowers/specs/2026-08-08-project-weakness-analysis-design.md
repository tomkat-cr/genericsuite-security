# Design: `project-weakness-analysis` Skill

**Date:** 2026-08-08
**Status:** Approved, pending implementation plan
**Package:** `genericsuite-security`
**Plugin:** `gs-security-suite`

## Problem

A GenericSuite user with a directory full of projects — their own apps, client
work, forks, experiments — has no cheap way to answer the only question that
matters before deploying any of them:

> **Is this project ready and safe to run in production, or does it need work
> first?**

Existing tooling answers adjacent questions. `npm audit` reports known CVEs in
dependencies. The three skills already in this plugin answer mutability
questions: is this image pinned, is this Action pinned, did this machine touch a
known compromise. None of them answer whether the *application itself* is
production-grade — whether it has auth on its write endpoints, whether secrets
are in `.env` or in git, whether errors are handled, whether anything is tested,
whether it is a real product or an empty scaffold with a good README.

That judgment currently requires a human reading each repository. This skill
makes it a repeatable, evidence-based first pass across many projects at once.

## Source material

The methodology is adapted from `tmp/project-analysis/analysis/METHODOLOGY.md`
and the nine tool scripts plus three AI workflow scripts under
`tmp/project-analysis/analysis/tools/`, which implement a six-stage pipeline
(Collect → Analyze → Evaluate → Security → Merge → Publish) for triaging OSS
projects.

**`tmp/` is gitignored in this package** (`.gitignore:226`) and nothing under it
is tracked, so the source material does not survive a fresh clone. An adapted
copy therefore lands in `skills/project-weakness-analysis/references/methodology.md`
as part of the implementation, so the skill's rationale travels with the repo.

Three things were carried over deliberately:

- **One agent per project per axis**, so no agent sees another's scores and
  there is no ranking contamination.
- **Evidence-based scoring.** Score what the code contains, not what the README
  claims. Boilerplate and empty scaffolding score low on purpose.
- **The re-audit loop.** On a repeat run, every previous finding is re-checked
  against current code and marked `resolved` / `partial` / `open`. This is what
  distinguishes projects that actually fixed their issues from projects that did not,
  and it is the feature that makes the skill a living check rather than a
  one-shot report.

Three things were deliberately dropped or replaced:

- **Stage 3 "Evaluate" in its original form.** Live-demo fetching, "diffusion
  readiness", the marketing one-line pitch, and the
  `spotlight`/`promote`/`deprioritize` tiers are promotional concerns, not
  production-safety ones. Removed entirely.
- **`backfill-insights.ts`'s write path.** The upsert into a `project_insights`
  table is replaced by a flat projection written into `./insights` — see
  "Flat projection" under Output. The row shape is deliberately identical to
  the original table's columns, so adding a real DB upsert later is an isolated
  addition rather than a redesign. The skill writes nothing outside its own
  output tree.
- **The `Workflow` tool** (`pipeline()` / `agent()` in the `.workflow.js`
  files) — a proprietary orchestration primitive not available here. Replaced
  by the task-manifest contract described under "Agent dispatch" below.

And one carried over in adapted form:

- **The DB-driven collector** (`extract-repos.ts`, `export-meta.ts`) is kept as
  a **read-only** fifth input mode. The originals ran under `bun` with Drizzle
  over `DATABASE_URL`, which this package cannot do — no Node toolchain, no
  Python DB driver. Reimplemented over Supabase's PostgREST endpoint using
  stdlib `urllib`, with a `psql` fallback. See "Input mode: `--db`".

## Scope

**No database is required.** Four of the five input modes (`--root`,
`--projects`, `--corpus`, `--org`) involve no database at all, and `--db` is a
purely optional fifth way to obtain the project list. Every output is a file
under `./insights`; nothing is ever written to a database, and the analysis
itself has no database dependency in any mode.

**In scope:** discovering projects under a root directory or an explicit list;
optionally enumerating them read-only from a Supabase/Postgres table and joining
its metadata; deterministic per-project signal collection; a deterministic
secret-candidate scan; reuse of `repo-docker-scanner` and
`repo-packages-scanner` findings as evidence; two AI scoring axes
(production-readiness and security risk) reported independently; a re-audit loop
against the previous run; Markdown, JSON, CSV, and SARIF output under
`./insights`; a CI gate with configurable thresholds; an optional policy profile
for GenericSuite house rules.

**Out of scope for v1:** running or building any scanned project; executing its
tests; fetching live demos; opening fix branches or pull requests; writing
anything inside a scanned project; **any database write** — the DB connection is
read-only in both directions of the design, and the results projection that the
source pipeline upserted into `project_insights` is written to `./insights`
instead; any network call other than the DB read, what `repo-corpus` makes to
clone (`--org` mode), and what the security agent makes via `gh` to check a
tracking issue's state.

## Prior art in this package

`supply-chain-ioc-scan` is the house style reference; `repo-corpus`,
`repo-docker-scanner`, and `repo-packages-scanner` establish the conventions
this skill inherits rather than reinvents:

- **A clean verdict is only evidence if detection is proven.** Every scanner
  ships `tests/selftest.py` building a synthetic positive fixture and asserting
  each detector fires — and asserting documented benign lookalikes do not.
- **Unreadable is not clean.** Walkers count what they could not read and
  downgrade the verdict rather than silently skipping.
- **Everything opinionated lives in a JSON policy**, never in scanner code.
- **Findings are tiered**, separating machine-confirmable facts from things a
  human must judge.
- **Python, not bash**, for anything with logic. macOS ships bash 3.2, which
  lacks associative arrays; under `set -u` those failures land on stderr while
  the report records nothing — a check that appears to have run and found
  nothing.
- **Exit codes** `0` / `1` / `2`, with `1` meaning "the thing this skill looks
  for was found".
- **Report legends are generated from policy, never hand-written prose.** See
  `docs/superpowers/HANDOFF.md` — a hand-written "Priority tiers" section
  shipped once describing the *wrong scanner's* tiers. Any legend, rubric, or
  threshold table in this skill's report is rendered from
  `policy/weakness.json`, and the self-test asserts it.
- **The report states its own blind spots**, the scan command that produced it,
  and exactly which projects at which commits it covered.

## Architecture

Five stages. Two of them are AI; the other three are deterministic and
reproducible.

```
1. Collect   (deterministic)          input → corpus.json → evidence bundle
2. Analyze   (sonnet × N projects)    readiness axis
3. Security  (sonnet × N projects)    risk axis + re-audit of prior findings
4. Merge     (deterministic)          validate agent JSON, join, write records
5. Report    (deterministic + 1 haiku) WEAKNESS-REPORT.md, findings.sarif
```

The two AI axes are scored by **separate agents that never see each other's
output**. A project can be an excellent, well-organized application *and* carry
a critical security risk; those are reported independently, on purpose. Nothing
in the pipeline averages them into a single number.

### Data flow

```
--root ~/dev | --projects A B C | --corpus PATH | --org NAME | --db
        │
        │  discover_projects.py  (--root only)
        │  db_collect.py         (--db only, read-only)
        ▼
   build_corpus.py  (from repo-corpus)
        ▼
insights/.work/corpus.json
        │
        │  collect_signals.py + _secrets.py + _siblings.py
        ▼
insights/.work/evidence/<slug>.json
        │
        │  build_tasks.py
        ▼
insights/.work/agents/tasks.json  ──────►  Claude dispatches subagents
        │                                          │
        │                                          ▼
        │                        insights/.work/agents/out/<slug>.analyze.json
        │                        insights/.work/agents/out/<slug>.security.json
        │  merge_insights.py  ◄────────────────────┘
        │  (+ previous insights/security-audit.json, for re-audit)
        ▼
insights/insights.json
insights/projects/<slug>.json
insights/security-audit.json
        │
        │  gen_report.py  (+ one haiku digest agent for the rollup)
        ▼
insights/WEAKNESS-REPORT.md
insights/findings.sarif
```

### Components

```
skills/project-weakness-analysis/
  SKILL.md
  references/
    methodology.md              adapted from tmp/ (which is gitignored)
    project-insights.sql        CREATE TABLE for the flat projection; never run
  policy/
    weakness.json               project_markers, readiness_rules, readiness_order,
                                severity_order, gate_defaults, dispatch.max_parallel,
                                secret patterns + benign exclusions, table_columns,
                                db_source
    profiles/generic.json       default, framework-neutral
    profiles/genericsuite.json  scrypt-only, {error,error_message,resultset},
                                parameterized SQL, is_safe_url/is_safe_local_path
  scripts/
    run_weakness_analysis.sh    driver: phases, gate, exit codes, redacted
                                scan-command capture
    discover_projects.py        root dir → project dirs, via project_markers
    db_collect.py               PostgREST / psql reader, URL extraction, metadata
    collect_signals.py          deterministic per-project facts
    _secrets.py                 regex secret candidates, offline, tiered
    _siblings.py                runs repo-docker-scanner / repo-packages-scanner
    build_tasks.py              emits agents/tasks.json
    merge_insights.py           schema validation, verdict derivation, re-audit
    gen_report.py               WEAKNESS-REPORT.md, flat projection, CSV, SARIF
    _schemas.py                 the two agent schemas, single source of truth
  tests/
    selftest.py
    fixtures/                   three synthetic projects, agent-output fixtures,
                                a saved DB payload for --db-rows-json
```

`_walk.py` is imported from `repo-corpus` by path, exactly as the two sibling
scanners already do — the three skills must be installed side by side.

## Input: five ways in, one contract out

Every input mode resolves to a `corpus.json` with `schema_version: 1` — the
same manifest `repo-docker-scanner` and `repo-packages-scanner` already consume.
This is why single-project analysis and a 40-project batch are the same code
path rather than two implementations that drift apart.

| Flag | Behaviour |
|---|---|
| `--root PATH` | Discover every project under `PATH`, then `build_corpus.py --local <each>` |
| `--projects A B C` | Explicit list → `build_corpus.py --local A B C` |
| `--corpus PATH` | Use an existing manifest as-is |
| `--org NAME` / `--user NAME` | `build_corpus.py --org/--user` — clones, with `repo-corpus`'s hardening |
| `--db` | Read a projects table, extract one GitHub URL per row, then clone as `--org` does |

Exactly one input mode may be given; the driver errors with exit `2` otherwise.
If no input flag is given at all, the driver prints the five options and exits
`2` rather than guessing — a scan of the wrong tree is worse than no scan.

### `discover_projects.py`

`repo-corpus --local` accepts a list of paths but has no "expand this root into
projects" mode. That expansion is the one genuinely new input capability here.

A directory is a project if it contains any marker: `.git/`, `package.json`,
`pyproject.toml`, `requirements.txt`, `Pipfile`, `go.mod`, `Cargo.toml`,
`Gemfile`, `composer.json`, `pom.xml`, `build.gradle`, `pubspec.yaml`,
`Dockerfile`, `docker-compose.yml`. The marker list lives in
`policy/weakness.json` under `project_markers`, not in code.

Rules, each preventing a specific wrong answer:

- **Descent stops at the first match.** A repo containing a `frontend/` and a
  `backend/` is one project, not three. `--split-monorepo` opts into treating
  each marker-bearing subdirectory as its own project.
- **Depth is capped** (`--max-depth`, default 3) so a discovery run over a home
  directory terminates.
- **`node_modules/`, `.git/`, `vendor/`, `dist/`, `build/`, `.venv/`, `venv/`,
  `__pycache__/` are never descended.** A `package.json` inside `node_modules`
  is not a project.
- **Symlinked directories are not followed**, and nothing resolving outside the
  root is yielded — the same rule `_walk.py` enforces.
- **Unreadable directories are counted, not skipped silently.** They appear in
  the report's blind-spot section.
- **`--limit N` caps the number of projects** and, when the cap is hit, records
  it as a blind spot. A truncated list is the one incompleteness that cannot be
  expressed as a failure — projects past the cut are simply absent,
  indistinguishable from "not selected". `repo-corpus` learned this the hard
  way; the warning is inherited rather than rediscovered.
- **`--list-only` prints what would be analyzed and exits `0`** without building
  anything, so scope can be checked before committing to a large run.

### Input mode: `--db` (Supabase / Postgres, read-only, entirely optional)

**This mode is optional and nothing else depends on it.** It exists only when
the list of projects to scan already lives in a Supabase/Postgres table. Skip it
and the skill is fully functional through `--root`, `--projects`, `--corpus`, or
`--org`; no Supabase credentials, no `psql`, no network call. The self-test does
not require a database either — it runs against a saved payload.

**What the table holds is a project registry, not a project's own database.**
`--db` reads rows that each *name* a project and point at its repository; it
never inspects, connects to, or cares about whatever database a scanned project
uses internally. A project written in Go against MongoDB is scanned exactly the
same way once its row supplies a repository URL. Whether a scanned project uses
Supabase is a *security* question — RLS disabled, anon keys with write access —
and is handled by the security agent in stage 3, not by the input layer.

`db_collect.py` replaces `extract-repos.ts` and `export-meta.ts`, which together
read a `projects` table, derived one GitHub URL per row from a fallback chain of
columns, and exported the remaining columns as per-project metadata. Both ran
under `bun` with Drizzle over `DATABASE_URL`; neither approach is available in a
stdlib-Python package.

**Transport, in order of preference:**

1. **Supabase PostgREST** over stdlib `urllib` — `SUPABASE_URL` plus
   `SUPABASE_SERVICE_ROLE_KEY` or `SUPABASE_ANON_KEY`. Issues `GET
   /rest/v1/<table>?select=…` and nothing else. No dependency, works from
   anywhere.
2. **`psql`** — used only when no Supabase env vars are set and `psql` is on
   `PATH`, reading `DATABASE_URL`. Every query runs inside `BEGIN; SET
   TRANSACTION READ ONLY;`, so the read-only guarantee is enforced by the
   database rather than by the query text.

If neither is configured, the driver exits `2` naming exactly which environment
variables it looked for. It never falls back to scanning something else.

**Credentials come from the environment only, never from a flag.** The report
captures the literal scan command, so a connection string passed as an argument
would be written into a file people share. As defence in depth, the captured
command is redacted regardless: anything matching a `postgres://` /
`postgresql://` URI, or the value of an argument whose name contains `key`,
`token`, `secret`, `password`, or `url`, becomes `<redacted>`. The self-test
asserts a connection string cannot reach the report.

**Schema mapping is configuration, not code.** `--db-config PATH` loads a JSON
file; `policy/weakness.json`'s `db_source` block holds the default, whose shape
matches the source pipeline's table:

```json
{
  "table": "projects",
  "slug_column": "slug",
  "name_column": "name",
  "repo_url_columns": ["contribute_in_url", "project_url", "description_markdown"],
  "metadata_columns": ["lifecycle_status", "status", "project_url", "video_url",
                       "countries", "participant_name", "description_markdown"],
  "filter": null,
  "page_size": 1000
}
```

**Repo-URL extraction** follows the original heuristic exactly: the first
`https?://github.com/…` match in each of `repo_url_columns` in order, trailing
punctuation (`.,);`) stripped, then normalized by lowercasing and dropping a
trailing `.git` or `/` for deduplication. The winning column name is recorded as
`repo_source_field`, so a surprising result is traceable to the column it came
from.

Three departures from the original, each closing a silent-coverage hole:

- **A row with no GitHub URL is recorded, not dropped.** The original `continue`d
  past it; the source README then had to state its coverage ("88 projects → 46
  had a repo → 43 reachable") from manual counting. Here those rows land in the
  manifest with `status: "skipped"`, reason `no-repo-url`, and are counted in the
  report's blind-spot section.
- **A row whose URL duplicates an earlier row is recorded as `skipped`** with
  reason `duplicate-of:<slug>`, rather than vanishing. Two projects pointing at
  one repository is a data-quality fact worth seeing.
- **Pagination is explicit and its limits are visible.** PostgREST caps
  responses (1000 rows by default) and `--db-limit` caps them further; both are
  paged through, and a result landing on an exact page boundary emits a warning.
  This is the same truncation lesson `repo-corpus` learned against `gh`'s
  100-per-page default, applied before it can bite again.

Extracted rows produce a repo list that is handed to `build_corpus.py` exactly
as `--org` mode does, so clone hardening and the corpus contract are shared
rather than duplicated. The metadata columns are attached to each project's
evidence bundle under `db_metadata` and surface in the report, giving the
analyze and security agents the project's own description of what it is
meant to do — context they otherwise have to infer from the README.

**The self-test covers this hermetically**, with no live database:
`--db-rows-json PATH` substitutes a saved payload for the transport layer, the
same escape hatch `repo-corpus` uses with `--repos-json` to exercise enumeration
without a GitHub account.

## Stage 1: Collect (deterministic, no AI)

For each project in the corpus, `collect_signals.py` writes
`insights/.work/evidence/<slug>.json`. Nothing here is a judgment call; every
field is a fact a script can prove, and every one of them is something an agent
would otherwise burn tokens rediscovering.

| Group | Fields |
|---|---|
| Identity | slug, path, HEAD SHA, branch, remote URL, GitHub metadata when the corpus has it |
| Size | lines of code by language, file count, largest files |
| Manifests | which manifests exist, which lockfiles are committed, declared dependency counts |
| Quality markers | test files/dirs present, CI workflow present, README present and length, LICENSE present, `.gitignore` present, typed-language config present |
| Deploy | Dockerfile, compose file, IaC files, deploy config, `Procfile`, serverless config |
| Config hygiene | `.env*` files **tracked in git**, `.env.example` present, count of env vars referenced in code |
| Secrets | secret candidates from `_secrets.py` |
| Structure | top-level directory layout, a bounded file-tree sample (200 paths, matching the source collector) |
| Sibling findings | `repo-docker-scanner` and `repo-packages-scanner` results for this project |

Walking uses `_walk.py` imported from `repo-corpus` by path — the same
side-by-side installation requirement the two existing scanners already have.
Its `WalkStats` (prune counts, unreadable paths, files over 2 MB) is carried
into the evidence bundle and from there into the report's blind-spot section.

### `_secrets.py` — tiered, like every other finding in this package

Regex-based, offline, no network, no entropy-only rules.

- **`CONFIRMED`** — a repo-tree fact: an `.env`, `.env.local`, `.env.<stage>`,
  `*.pem`, `*.p12`, `id_rsa`, or service-account JSON **tracked in git**. That a
  file is committed is not a matter of opinion.
- **`REVIEW`** — a content match on a known credential shape (AWS access key id,
  Google API key, Slack token, GitHub PAT, Stripe key, JWT signing secret, a
  database URL with an inline password, a Supabase `service_role` key). A regex
  cannot prove a string is live, so this is surfaced for a human read and never
  auto-labelled a breach.

Documented benign lookalikes that must **not** fire, asserted by the self-test:
`.env.example` and `.env.sample`; a placeholder value (`xxx`, `changeme`,
`your-key-here`, `<REDACTED>`, `${...}`); a base64 blob in a lockfile
`integrity` field; a test fixture under a path matching `test`/`fixture`/`mock`
when the value is a placeholder.

Values are **never printed in full** — findings carry file, line, pattern name,
and a masked prefix. A security report that leaks the secret it found is a new
incident.

### `_siblings.py` — deterministic findings feed the agents

Runs `repo-docker-scanner` and `repo-packages-scanner` over the **same corpus**,
with `--fail-on none` so their exit codes never abort this pipeline, and folds
their findings into each project's evidence bundle.

This is the point of the pre-pass: an unpinned `:latest` in a production
Dockerfile is provable by a script, so it is never left to an LLM's judgment.
The agents start from those findings instead of rediscovering them, which makes
them both cheaper and better grounded.

**Degradation is graceful and visible.** If a sibling skill is not installed, or
its run fails, the evidence bundle records
`{"available": false, "reason": "..."}` and the report's blind-spot section
names it. It never silently records "no findings" for a scanner that never ran —
that is the falsely-clean verdict this whole package exists to prevent.

## Stages 2 and 3: agent dispatch

A skill's own scripts cannot spawn subagents. The bridge is a **task manifest**:
`build_tasks.py` writes `insights/.work/agents/tasks.json`, and `SKILL.md`
instructs Claude to dispatch exactly those tasks.

Each task entry carries everything the dispatcher needs, so the dispatching
model makes no decisions of its own:

```json
{
  "id": "analyze:my-project",
  "stage": "analyze",
  "project_slug": "my-project",
  "model": "sonnet",
  "agent_type": "Explore",
  "output_path": "insights/.work/agents/out/my-project.analyze.json",
  "schema": { "...": "JSON Schema, from _schemas.py" },
  "prompt": "…full literal prompt, evidence path inlined…"
}
```

Rules the dispatcher follows, stated in `SKILL.md`:

- **Dispatch tasks in parallel**, in batches (default 6 concurrent, from
  `policy/weakness.json`'s `dispatch.max_parallel`).
- **Every subagent writes its JSON to `output_path`** and returns only a short
  confirmation. Findings travel through files, not through the dispatcher's
  context — which is what keeps a 40-project batch feasible.
- **Never write a task's output file yourself.** If a subagent fails, leave the
  file absent; `merge_insights.py` records the gap. A dispatcher filling in a
  plausible result is the worst possible failure mode here.
- **`analyze` tasks use the read-only `Explore` agent type.** They score, they
  do not edit.

### Stage 2 — Analyze (sonnet, `Explore`)

One agent per project. Reads the evidence bundle first, then the actual source:
manifests and lockfiles, Dockerfile and CI, the DB access layer (ORM vs. raw SQL
vs. BaaS client), auth, error handling, logging, env/secret management, tests,
directory layout.

Returns, on the source methodology's 1–5 rubric (`1` = empty skeleton, `2` =
early prototype, `3` = working MVP, `4` = polished/usable, `5` =
production-grade):

| Field | Type | Measures |
|---|---|---|
| `maturity.score` | 1–5 | Real product vs. boilerplate — README, tests, CI, iterated commits |
| `production_readiness.score` | 1–5 | Auth, error handling, logging, env/secrets, deploy config |
| `code_organization.score` | 1–5 | Structure, naming, documentation quality |
| `maintainability.score` | 1–5 | Can a new maintainer safely change this — coupling, dead code, dependency freshness |

Plus booleans that make each score auditable (`has_auth`, `has_error_handling`,
`has_logging`, `has_env_config`, `has_deploy_config`, `has_tests`, `has_ci`,
`has_readme`), a `stack` object, an `architecture` object (pattern, `uses_orm`,
`orm_or_db_layer`, `api_design`, `separation_of_concerns`), `weaknesses[]`,
`red_flags[]`, and a one-paragraph `summary`. Reasoning fields are capped at 1–3
sentences.

This mirrors `analyze.workflow.js`'s schema, minus the OSS-specific
`viability`, `domain_tags`, and `merge_potential` fields, plus
`maintainability`.

### Stage 3 — Security (sonnet, `general-purpose`)

One agent per project, dispatched independently of stage 2 and never given its
output. Reads the evidence bundle — including the `CONFIRMED`/`REVIEW` secret
candidates and the sibling scanners' findings — then audits the code for:

- Committed secrets: service-role keys, API keys, DB URLs, JWT signing secrets,
  `.env` files in git
- Missing authentication/authorization on state-changing endpoints
  (`POST`/`PATCH`/`PUT`/`DELETE`)
- Mass assignment — a raw request body passed into a DB insert/update with no
  field whitelist
- PII exposure through public/anon access or over-broad API responses
- Row-level security disabled, anon keys with write access, over-broad CORS
- Injection (SQL, command, template), SSRF, open proxies, unrestricted file
  upload, path traversal
- Insecure defaults: debug mode on, verbose errors to clients, permissive
  cookies, missing TLS enforcement, weak password hashing
- Dependency risk escalated from the sibling scanners' findings, judged in
  context

Every finding must cite a **file path and line**, and carry a `severity`
(`critical`/`high`/`medium`/`low`), a `title`, `evidence`, and a
`remediation`. A finding that cannot be pointed at in the actual code is not
reported — the source methodology's "skeptical and evidence-based" rule, kept
verbatim.

The agent also checks the tracking issue's state via `gh issue list` when the
project has a GitHub remote, setting `issueState` to `open`/`closed`/`none`.
When `gh` is unavailable this degrades to `none` with a note; it never aborts.

### Re-audit — what makes it a living check

When `insights/security-audit.json` exists from a previous run, each project's
prior findings are inlined into that project's security prompt, and the agent's
**primary** job becomes verifying each one against current code:

- **`resolved`** — properly fixed
- **`partial`** — mitigated but still exploitable, with an explanation
- **`open`** — unchanged

**No previous finding may be dropped.** A resolved finding is still listed, with
`status: "resolved"`. New issues are added with `status: "new"`. The self-test
asserts that a prior finding absent from the agent's output is caught by
`merge_insights.py` rather than silently disappearing — a finding that vanishes
between runs reads as "fixed" and is the one failure mode that would make this
feature actively harmful.

`merge_insights.py` carries `auditedAt` forward from the prior record and stamps
`reauditedAt`, `previousRisk`, and the agent's `reauditNote`.

### Stage 5's haiku digest

One haiku agent, once per run, reads the merged `insights.json` and produces the
report's executive rollup: which projects are blocked and why, the common
weaknesses across the batch, and a suggested remediation order. It makes **no
per-project judgments** and its output cannot change any score, tier, or exit
code — if it fails, the report is generated without the rollup and says so.

## Verdict model

Two axes, reported side by side, never averaged.

### Readiness

Derived by `merge_insights.py` from the analyze agent's sub-scores using
`readiness_rules` in `policy/weakness.json`. The rules are data, and the
report's legend is rendered from them.

| Tier | Rule |
|---|---|
| `production-ready` | `production_readiness >= 4` and `maturity >= 4` and `code_organization >= 3` and no `critical`/`high` open security finding |
| `needs-work` | `production_readiness >= 2` and `maturity >= 2` |
| `not-ready` | anything lower, or the analyze agent judged it boilerplate/empty scaffolding |
| `unknown` | the analyze agent's output is missing or failed schema validation |

`unknown` is a **blocking** state, not a neutral one. A project nobody
successfully scanned is not a project known to be safe. This is the same rule as
`repo-corpus`'s exit `1` for a partial corpus, applied per project.

`production-ready` is the one tier that reads across both axes — it is the tier
that means "ship it", and a critical open finding disqualifies a project from it
regardless of how good the code is. Every other tier is computed from the
readiness axis alone.

### Security risk

`security_risk` = the severity of the worst **still-open** finding, where
still-open means `status` in `open`, `partial`, or `new`. `none` when everything
is resolved or nothing was found. Resolved findings never contribute.

### The gate and exit codes

| Code | Meaning |
|---|---|
| `0` | Every project passes both thresholds |
| `1` | At least one project is blocked |
| `2` | Error — no report produced (bad arguments, unreadable output path, no usable corpus) |

Thresholds, both configurable:

- `--fail-on SEVERITY` — default `high`. Blocks any project whose
  `security_risk` is at or above it. `none` disables the security gate.
- `--fail-on-readiness TIER` — default `not-ready`. Tiers are ordered
  `production-ready` > `needs-work` > `not-ready` > `unknown`, and a project is
  blocked when its tier is **at or below** the named one. The default therefore
  blocks `not-ready` and `unknown` while letting `needs-work` through;
  `--fail-on-readiness needs-work` additionally blocks `needs-work`; `none`
  disables the readiness gate. The ordering lives in `policy/weakness.json` as
  `readiness_order`, so the report's legend and the gate read the same list.

Exit `2` is never returned for findings, and exit `1` is never returned for an
error. A run that could not produce a report must not look like a run that found
problems, and vice versa.

## Policy and profiles

Everything opinionated lives in `policy/weakness.json`: `project_markers`,
`readiness_rules`, `severity_order`, `gate_defaults`, `dispatch.max_parallel`,
secret pattern definitions with their benign-lookalike exclusions, and the
evidence fields collected. Scanner code stays policy-agnostic.

Profiles overlay additional agent instructions and checks:

- **`policy/profiles/generic.json`** (default) — framework-neutral. Works on any
  project in any language.
- **`policy/profiles/genericsuite.json`** — opt in with `--profile
  genericsuite`. Adds the ecosystem's stated non-negotiables from the monorepo
  `CLAUDE.md`: scrypt-only password hashing (never bcrypt or MD5); the standard
  `{"error": bool, "error_message": str|None, "resultset": Any}` return shape;
  parameterized SQL with identifier quoting; `is_safe_url()` /
  `is_safe_local_path()` guards around AI-generated URLs and file paths;
  stage-specific `.env` files with no hardcoded secrets; log-injection
  prevention (newline sanitization before logging).
- **`--profile ./my-rules.json`** — any path loads a user-supplied overlay, so
  a project can encode its own conventions without forking the skill.

A profile can add checks and agent instructions. It cannot remove a generic
check or lower a severity — narrowing a scan to make it pass is how a scan stops
being worth running.

## Output

Everything lands under `./insights` in the current working directory, overridable
with `--out PATH`. **Nothing is ever written inside a scanned project**; the
self-test asserts this against its fixtures.

```
insights/
  WEAKNESS-REPORT.md      human-readable, all projects
  insights.json           machine-readable master record (nested)
  insights-table.json     flat projection, one row per project
  insights-table.csv      the same rows, spreadsheet-openable
  security-audit.json     per-project findings + status; read by the NEXT run
  projects/<slug>.json    one record per project
  findings.sarif          for GitHub code-scanning upload
  .work/                  corpus, evidence, agent I/O — regenerable
```

### Flat projection

`insights.json` is nested and awkward to sort, diff, or paste into a
spreadsheet. `insights-table.json` and `insights-table.csv` are the same data
flattened to one row per project, and the report renders those rows as a
**Project matrix** table right after the executive summary.

Columns, defined once in `policy/weakness.json` as `table_columns` so the JSON,
the CSV, and the report's matrix cannot drift apart:

```
project_slug · name · repo_url · repo_source_field · path · branch · head_sha
stars · forks · contributors · commit_count · code_loc · license
primary_language · project_type · uses_orm · orm_or_db_layer
maturity_score · production_readiness_score · code_organization_score
maintainability_score · readiness · security_risk · previous_risk
open_findings · resolved_findings · red_flags_count · blocked
audited_at · reaudited_at
```

This is deliberately the column set `backfill-insights.ts` upserted into
`project_insights`, minus the dropped promo fields and plus the security axis.
Keeping the shapes aligned means a future DB upsert is a new writer over an
existing row, not a new data model. `references/project-insights.sql` ships the
matching `CREATE TABLE` for anyone who wants to load it themselves; the skill
never runs it.

A project whose readiness is `unknown` still gets a row, with the missing
fields null and `blocked` true. An absent row would read as "not scanned",
which is the same silence the whole blind-spot discipline exists to prevent.

`.work/` is disposable and its contents are regenerable; `--keep-work` preserves
it for debugging, and the implementation adds an `insights/.work/` entry to the
package `.gitignore`.

`WEAKNESS-REPORT.md` opens with, in this order:

1. **Executive summary** — the counts per readiness tier and risk level, and the
   blocked-project list, followed by the **Project matrix** described above.
2. **Scan command** — the literal top-level invocation, redacted, captured by the driver
   *before* it consumes or rewrites any argument. `--root`/`--org` resolve into
   a `--corpus` path long before the Python scripts see their own argv, which is
   exactly the failure `repo-docker-scanner` and `repo-packages-scanner` already
   solved this way.
3. **Projects analyzed** — every project, path, branch, and HEAD SHA actually
   walked. A "no findings" statement is scoped to exactly this list.
4. **Blind spots** — the mandatory section, below.
5. **Readiness tiers and risk levels** — a legend **generated from
   `policy/weakness.json`'s `readiness_rules` and `severity_order`**, never
   hand-written prose.
6. Per-project detail, then the cross-project rollup.

Both `scan_command` and `projects_analyzed` also land in `insights.json`.

### The blind-spot section is mandatory

- Corpus `totals.failed` from `repo-corpus` — a partial corpus is a partial scan
- Projects marked `unknown` because agent output was missing or invalid,
  **counted and named, never dropped**
- Any sibling scanner that was unavailable or failed, with its reason
- Pruned directories, unreadable paths, and files over 2 MB, from `WalkStats`
- Any discovery truncation — `--max-depth` or `--limit` hit
- The source methodology's own caveat, restated: scores are AI-generated from a
  single snapshot; this is triage, not ground truth. Re-running is cheap.

## Driver: `scripts/run_weakness_analysis.sh`

One entry point, three phases. The AI stages sit between phase 1 and phase 3 and
are dispatched by Claude, so no single invocation runs the whole pipeline
unattended — see recorded trade-off 1.

```bash
./scripts/run_weakness_analysis.sh --root ~/dev                 # phase 1
# → Claude dispatches the tasks in insights/.work/agents/tasks.json
./scripts/run_weakness_analysis.sh --phase merge                # phases 3–5
```

`--phase collect` is the default and is what every input flag implies.
`--phase merge` runs merge + report + gate against an existing `--out`
directory. `--phase all` is accepted and behaves as `collect`, printing what
must be dispatched next and exiting `0`; it exists so the obvious guess does
something sensible rather than erroring.

| Flag | Default | Purpose |
|---|---|---|
| `--root PATH` | — | Discover projects under a root |
| `--projects A B C` | — | Explicit project list |
| `--corpus PATH` | — | Reuse an existing manifest |
| `--org NAME` / `--user NAME` | — | Clone via `repo-corpus` |
| `--db` | — | Enumerate from a projects table, read-only |
| `--db-config PATH` | `db_source` in policy | Table and column mapping |
| `--db-limit N` | none | Cap rows read, recorded as a blind spot when hit |
| `--db-rows-json PATH` | — | Substitute a saved payload for the DB call (self-test, offline reruns) |
| `--out PATH` | `./insights` | Output tree |
| `--profile NAME\|PATH` | `generic` | Policy overlay |
| `--phase collect\|merge\|all` | `collect` | Pipeline phase |
| `--max-depth N` | `3` | Discovery depth cap |
| `--limit N` | none | Cap projects, recorded as a blind spot when hit |
| `--split-monorepo` | off | Each marker-bearing subdirectory is its own project |
| `--list-only` | off | Print what would be analyzed, exit `0` |
| `--fail-on SEVERITY` | `high` | Security gate threshold |
| `--fail-on-readiness TIER` | `not-ready` | Readiness gate threshold |
| `--keep-work` | off | Preserve `.work/` |
| `--no-siblings` | off | Skip the sibling scanners, recorded as a blind spot |

The driver runs `tests/selftest.py` first and refuses to analyze if it fails —
the same refusal `run_corpus.sh`, `run_docker_scan.sh`, and
`run_packages_scan.sh` already implement. It captures the literal top-level
invocation before consuming any argument, writes progress to stderr and the
output path to stdout, and never reports an outcome it has no artifact to back.

## Error handling

| Failure | Behaviour |
|---|---|
| Agent output file absent | Project's axis is `unknown`; recorded in blind spots; run continues; exit ≥ `1` |
| Agent output fails schema validation | **Rejected**, treated as absent, and the raw file preserved under `.work/agents/rejected/` |
| Sibling scanner missing or failing | `{"available": false, "reason": …}` in evidence; named in blind spots |
| A project fails to clone (`--org` mode) | `repo-corpus` records it; carried into blind spots |
| `gh` unavailable | Issue-state check degrades to `none` with a note; never aborts |
| Neither Supabase env vars nor `psql` available under `--db` | Exit `2` naming the variables looked for; never falls back to scanning something else |
| DB row has no GitHub URL | Recorded `skipped` / `no-repo-url`, counted in blind spots |
| DB row duplicates another's repo | Recorded `skipped` / `duplicate-of:<slug>` |
| DB read hits a page boundary or `--db-limit` | Warning into the blind-spot section — a truncated list cannot be expressed as a failure |
| Unwritable output path | Exit `2` before any work |
| No projects discovered | Exit `2` with the discovery root echoed back — a scan of zero projects must never report clean |
| Haiku digest fails | Report generated without the rollup, and says so |

Two invariants hold across all of it:

- **Nothing from a scanned project is ever executed.** No `npm install`, no test
  run, no evaluating a config file, no trusting a path found in a repo as a path
  on disk. Scanned projects are hostile input, exactly as cloned repos are in
  `repo-corpus`.
- **Nothing is ever written inside a scanned project.**

## Self-test

`tests/selftest.py`, run automatically by the driver, which refuses to analyze
if it fails. It builds three synthetic projects — a production-grade one, a
boilerplate skeleton, and a leaky one with a committed `.env` — and asserts:

**Discovery**
- All three are found under a root; `node_modules/` and `.git/` are not
  descended
- A repo with `frontend/` and `backend/` counts as one project, and as two under
  `--split-monorepo`
- A symlink pointing outside the root is not followed
- `--max-depth` truncation is recorded, not silent

**DB collector** (hermetic, via `--db-rows-json`, no live database)
- The URL fallback chain picks `contribute_in_url` over `project_url` over
  `description_markdown`, and records which column won
- Trailing punctuation is stripped and `.git` / trailing-slash duplicates
  collapse to one project
- A row with no GitHub URL is recorded `skipped` / `no-repo-url` — not dropped
- A duplicate row is recorded `skipped` / `duplicate-of:<slug>` — not dropped
- `db_metadata` reaches the evidence bundle and the report
- A page-boundary result and a `--db-limit` hit both emit a truncation warning
- **A connection string in the environment never reaches the report**, and a
  redacted scan command survives a `postgres://…` argument
- Column mapping comes from `--db-config`; a config naming a missing column
  fails loudly rather than silently yielding null

**Evidence**
- Tests, CI, Dockerfile, and lockfile presence are detected correctly in the
  production-grade fixture and correctly absent in the skeleton
- The secret detector fires `CONFIRMED` on the committed `.env` and `REVIEW` on
  each known key shape
- It does **not** fire on `.env.example`, on `EXAMPLE_API_KEY=xxx`, on a base64
  `integrity` field in a lockfile, or on a placeholder in a test fixture
- No finding contains a full secret value

**Merge and verdict**
- A project with a missing agent output is marked `unknown` and appears in blind
  spots — not dropped
- Agent JSON that fails schema validation is rejected, not trusted, and
  preserved under `.work/agents/rejected/`
- Re-audit carries every prior finding forward; a prior finding absent from the
  agent's response is flagged, not silently lost
- `previousRisk` and `reauditedAt` are stamped; `auditedAt` is carried forward
- `security_risk` ignores `resolved` findings and reflects the worst still-open
  one

**Gate**
- A critical open finding exits `1` at `--fail-on high` and `0` at `--fail-on
  none`
- A project marked `unknown` exits `1` at the default readiness threshold
- An error path exits `2`, never `1`

**Report and packaging**
- `insights-table.json`, `insights-table.csv`, and the report's Project matrix
  all carry the same columns in the same order, from `table_columns`
- A project with readiness `unknown` still has a row, with `blocked` true
- The readiness-tier legend is generated from `policy/weakness.json` and
  contains no vocabulary belonging to `repo-docker-scanner`'s or
  `repo-packages-scanner`'s P0/P1/P2 tier model — the exact regression class
  documented in `HANDOFF.md`
- The blind-spot section is present even on a fully clean run
- The scan command and every project's HEAD SHA appear in both the report and
  `insights.json`
- Nothing was written inside any fixture project
- `marketplace.json` registers this skill's path and it exists on disk

The self-test is hermetic: isolated `HOME`, `GIT_CONFIG_GLOBAL` and
`GIT_CONFIG_SYSTEM` neutralized, no network, no agent dispatch (agent outputs
are supplied as fixtures). A skipped assertion is reported as skipped and
excluded from the pass count, never counted as a pass.

## Recorded trade-offs

1. **The AI stages cannot be run by the driver.** `--phase all` is not a single
   unattended command; it stops after `collect` and prints what Claude must
   dispatch. This is the cost of not shelling out to a headless CLI, and it
   means the skill is driven from a Claude Code session rather than from cron.
   Chosen for reproducibility and consistency with the rest of the plugin.
2. **Two sonnet agents per project** is roughly twice the cost of one combined
   agent. Bought deliberately: a single context that just praised a project's
   architecture is a biased judge of its security, and the source methodology
   split these stages for exactly that reason.
3. **Scores are AI-generated and point-in-time.** Two runs over unchanged code
   can differ. The report says so, and the deterministic axis (evidence bundle,
   sibling scanner findings, secret candidates) is stable across runs — which is
   why the pre-pass exists.
4. **Coupling to three sibling skills.** `_walk.py` from `repo-corpus` is a hard
   dependency; `repo-docker-scanner` and `repo-packages-scanner` are soft ones
   that degrade visibly. Same side-by-side installation requirement the existing
   scanners already carry.
5. **No auto-fix, no PRs.** Consistent with the existing scanners' v1 decision:
   writing to repositories is the riskiest surface and adds no detection value.
6. **The DB connection is read-only, so results do not flow back into the
   database.** The source pipeline closed that loop by upserting
   `project_insights`; here the equivalent projection lands in
   `insights-table.json` / `.csv` and a project wanting it in Postgres loads it
   themselves with the shipped DDL. Bought for a blast radius that ends at the
   output directory — a scanner that writes to a production database is a
   scanner nobody can safely run on a whim. The column shapes are kept
   deliberately aligned so adding the writer later is additive.
7. **Supabase-first, not Postgres-general.** PostgREST is the only
   dependency-free transport available to a stdlib-Python package; `psql` covers
   plain Postgres only when it happens to be installed. A project on a database
   with neither gets exit `2` and can use `--projects` or `--org` instead.

## Implementation sequencing

1. Skill skeleton, `policy/weakness.json`, both profiles, `_schemas.py`,
   `references/methodology.md`, marketplace registration
2. `discover_projects.py` + its self-test assertions
3. `collect_signals.py`, `_secrets.py`, `_siblings.py` + assertions
4. `db_collect.py` — PostgREST reader, `psql` fallback, URL extraction,
   redaction, `--db-rows-json` + assertions
5. `build_tasks.py` + `SKILL.md`'s dispatch protocol
6. `merge_insights.py` — validation, verdict derivation, re-audit + assertions
7. `gen_report.py` — Markdown, flat projection, CSV, SARIF, generated legends
   + assertions
8. `run_weakness_analysis.sh` — phases, gate, exit codes, scan-command capture
9. `SKILL.md` in full, `references/project-insights.sql`, `CHANGELOG.md`,
   calibration run against real projects

Step 4 is independent of steps 2–3 and 5–7 and can be built in parallel with
them; everything else is sequential.

## Success criteria

- `--root PATH` over a directory of mixed projects produces a report naming
  every project, its readiness tier, and its security risk, with no project
  silently absent
- A project with a committed `.env` is `CONFIRMED` without an agent involved
- A second run over unchanged code marks every prior finding `resolved`,
  `partial`, or `open`, and drops none
- A missing agent output produces `unknown` and exit `1`, never a clean verdict
- The self-test fails if any detector is removed
- The report's tier legend changes when `policy/weakness.json` changes, with no
  code edit
- `--db` over a Supabase table enumerates every row, extracts one repo URL per
  row via the documented fallback chain, and accounts for every row that
  produced no project
- No database is ever written to, and no credential appears in any output file
- `insights-table.csv` opens in a spreadsheet with one row per project,
  including projects that failed to score
- Nothing is written inside any scanned project, and nothing from one is
  executed
