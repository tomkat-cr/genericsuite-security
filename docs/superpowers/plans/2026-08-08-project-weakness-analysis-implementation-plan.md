# `project-weakness-analysis` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Claude Code skill that scans one or many projects and reports, per project, whether it is ready and safe for production — on two independent axes (readiness tier, security risk) — with all output under `./insights`.

**Architecture:** Five stages. Three are deterministic Python (collect → merge → report); two are AI stages dispatched by Claude from a task manifest the collect stage writes. Input resolves to a `corpus.json` from the sibling `repo-corpus` skill, so single-project and 40-project runs are the same code path. Everything opinionated lives in `policy/weakness.json`.

**Tech Stack:** Python 3 standard library only. Bash 3.2-compatible driver. `git` and (optionally) `gh` / `psql` as external binaries. No package manager, no venv, no dependencies.

**Spec:** `docs/superpowers/specs/2026-08-08-project-weakness-analysis-design.md` — read it before Task 1. Every decision below traces to it.

## Global Constraints

Every task's requirements implicitly include this section.

- **Python 3 standard library only.** No `pip install`, no `requirements.txt`, no venv. This rules out `jsonschema` (Task 7 writes a minimal validator instead) and `tomllib` (needs Python 3.11+; this package sets no such floor).
- **No bash arrays anywhere.** macOS ships bash 3.2, where `"${a[@]}"` on an empty array under `set -u` aborts with "unbound variable" — and a crash inside a command substitution can look like an exit-1 verdict rather than a broken run. `repo-docker-scanner` shipped that bug; do not repeat it.
- **Exit codes:** `0` = passed at threshold, `1` = at least one project blocked, `2` = error, no report produced. An error must never look like findings, and findings must never look like an error.
- **Report legends are generated from `policy/weakness.json`, never hand-written prose.** See `docs/superpowers/HANDOFF.md`: a hand-written tier legend shipped once describing the wrong scanner's tiers. If you find yourself typing a tier description into `gen_report.py`, stop and edit the policy instead.
- **Nothing from a scanned project is ever executed.** No `npm install`, no test run, no evaluating a config file, no trusting a path found in a repo as a path on disk.
- **Nothing is ever written inside a scanned project.** All output goes under `--out` (default `./insights`).
- **No database is ever written to.** `--db` is read-only and optional.
- **Secret values are never printed in full** — file, line, pattern name, and a masked prefix only.
- **Vocabulary is project-centric.** Never "team", "teams", "hackathon", "victim", "donor", "spotlight", "promote", "diffusion". The source material is full of these; the adapted copy in `references/methodology.md` must be scrubbed.
- **`_walk.py` is imported from `repo-corpus` by path**, never copied. The three skills must be installed side by side.
- **Test command is `python3 tests/selftest.py`** from the skill directory. There is no pytest, no CI runner. Assertions accumulate in one file across tasks.

## Suggested Executor Per Task

Dispatch each task to a fresh subagent. Model guidance:

| Task | Executor | Why |
|---|---|---|
| 1. Skeleton, policy, profiles | **haiku** | Mechanical: JSON files and a fixed harness, all content given verbatim below |
| 2. `discover_projects.py` | **sonnet** | Walk logic with real edge cases (symlinks, depth, monorepo) |
| 3. `_secrets.py` | **sonnet** | Regex design plus a false-positive catalogue that must hold |
| 4. `collect_signals.py` | **sonnet** | Many small detectors; needs judgment about file layout |
| 5. `_siblings.py` | **sonnet** | Subprocess handling and graceful degradation |
| 6. `db_collect.py` | **sonnet** | Two transports, pagination, redaction |
| 7. `_schemas.py` + `build_tasks.py` | **sonnet** | Hand-rolled validator is subtle |
| 8. `merge_insights.py` | **sonnet** | Verdict derivation and re-audit reconciliation — the highest-stakes logic |
| 9. `gen_report.py` | **sonnet** | Three output formats that must stay column-aligned |
| 10. `run_weakness_analysis.sh` | **sonnet** | bash 3.2 constraints are easy to violate |
| 11. `SKILL.md` + references | **sonnet** | Prose quality matters; must scrub source vocabulary |
| 12. `CHANGELOG.md` + verification | **haiku** | Mechanical once everything passes |

Tasks 2–6 are independent of each other and can run in parallel after Task 1. Tasks 7–12 are sequential.

## File Structure

```
skills/project-weakness-analysis/
  SKILL.md                        Task 11
  references/
    methodology.md                Task 11  — adapted, vocabulary scrubbed
    project-insights.sql          Task 11  — DDL, never executed by the skill
  policy/
    weakness.json                 Task 1   — all thresholds, rules, patterns, columns
    profiles/generic.json          Task 1
    profiles/genericsuite.json     Task 1
  scripts/
    _policy.py                    Task 1   — policy + profile loading and merging
    _redact.py                    Task 1   — credential redaction (shared by 6, 9, 10)
    discover_projects.py          Task 2   — root dir → project dirs
    _secrets.py                   Task 3   — tiered secret candidates
    collect_signals.py            Task 4   — deterministic per-project facts
    _siblings.py                  Task 5   — runs the two sibling scanners
    db_collect.py                 Task 6   — PostgREST / psql reader (optional mode)
    _schemas.py                   Task 7   — agent schemas + minimal validator
    build_tasks.py                Task 7   — emits agents/tasks.json
    merge_insights.py             Task 8   — validation, verdicts, re-audit
    gen_report.py                 Task 9   — Markdown, flat projection, CSV, SARIF
    run_weakness_analysis.sh      Task 10  — driver, phases, gate
  tests/
    selftest.py                   Task 1 creates; every task appends
    fixtures/
      db-rows.json                Task 6
```

Responsibility boundaries: `_policy.py`, `_redact.py`, `_schemas.py` are leaf modules with no intra-skill imports. `discover_projects.py`, `_secrets.py`, `_siblings.py`, `db_collect.py` each own one input or one detector and import only leaves. `collect_signals.py`, `merge_insights.py`, `gen_report.py` compose them. Nothing imports the driver.

---

### Task 1: Skill skeleton, policy, profiles, and the self-test harness

**Files:**
- Create: `skills/project-weakness-analysis/policy/weakness.json`
- Create: `skills/project-weakness-analysis/policy/profiles/generic.json`
- Create: `skills/project-weakness-analysis/policy/profiles/genericsuite.json`
- Create: `skills/project-weakness-analysis/scripts/_policy.py`
- Create: `skills/project-weakness-analysis/scripts/_redact.py`
- Create: `skills/project-weakness-analysis/tests/selftest.py`
- Modify: `.claude-plugin/marketplace.json`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `_policy.load_policy(profile="generic") -> dict` — merged policy; profile overlay adds to `agent_instructions` and `extra_checks`, and may never remove a key or lower a severity.
  - `_policy.SKILL_DIR` — absolute path to the skill directory.
  - `_redact.redact_command(cmd: str) -> str`
  - `_redact.mask_value(value: str) -> str` — returns first 4 chars + `…` + length, e.g. `"AKIA…(40)"`.
  - `tests/selftest.py` exposes `check(name, condition, detail="")` and a `results` list, matching `repo-packages-scanner/tests/selftest.py`.

- [ ] **Step 1: Create the policy file**

Create `skills/project-weakness-analysis/policy/weakness.json`:

```json
{
  "schema_version": 1,
  "project_markers": [
    ".git", "package.json", "pyproject.toml", "requirements.txt", "Pipfile",
    "go.mod", "Cargo.toml", "Gemfile", "composer.json", "pom.xml",
    "build.gradle", "pubspec.yaml", "Dockerfile", "docker-compose.yml"
  ],
  "prune_dirs": [
    "node_modules", ".git", "vendor", "dist", "build", ".venv", "venv",
    "__pycache__", ".next", ".tox", "target"
  ],
  "discovery": { "max_depth": 3, "split_monorepo": false },
  "readiness_order": ["production-ready", "needs-work", "not-ready", "unknown"],
  "severity_order": ["critical", "high", "medium", "low", "none"],
  "readiness_rules": [
    {
      "tier": "production-ready",
      "reason": "production_readiness >= 4 and maturity >= 4 and code_organization >= 3, with no critical or high open security finding",
      "min_scores": { "production_readiness": 4, "maturity": 4, "code_organization": 3 },
      "max_open_severity": "medium"
    },
    {
      "tier": "needs-work",
      "reason": "production_readiness >= 2 and maturity >= 2",
      "min_scores": { "production_readiness": 2, "maturity": 2 },
      "max_open_severity": null
    },
    {
      "tier": "not-ready",
      "reason": "scores below the needs-work threshold, or judged boilerplate or empty scaffolding",
      "min_scores": {},
      "max_open_severity": null
    }
  ],
  "unknown_reason": "the analyze agent produced no output, or output that failed schema validation; an unscanned project is not a safe one",
  "gate_defaults": { "fail_on": "high", "fail_on_readiness": "not-ready" },
  "dispatch": { "max_parallel": 6, "analyze_model": "sonnet", "analyze_agent_type": "Explore", "security_model": "sonnet", "security_agent_type": "general-purpose", "digest_model": "haiku" },
  "open_statuses": ["open", "partial", "new"],
  "table_columns": [
    "project_slug", "name", "repo_url", "repo_source_field", "path", "branch",
    "head_sha", "stars", "forks", "contributors", "commit_count", "code_loc",
    "license", "primary_language", "project_type", "uses_orm", "orm_or_db_layer",
    "maturity_score", "production_readiness_score", "code_organization_score",
    "maintainability_score", "readiness", "security_risk", "previous_risk",
    "open_findings", "resolved_findings", "red_flags_count", "blocked",
    "audited_at", "reaudited_at"
  ],
  "db_source": {
    "table": "projects",
    "slug_column": "slug",
    "name_column": "name",
    "repo_url_columns": ["contribute_in_url", "project_url", "description_markdown"],
    "metadata_columns": ["lifecycle_status", "status", "project_url", "video_url", "countries", "participant_name", "description_markdown"],
    "filter": null,
    "page_size": 1000
  },
  "secrets": {
    "confirmed_tracked_files": [
      "^\\.env$", "^\\.env\\.local$", "^\\.env\\.(dev|qa|staging|prod|production|test)$",
      "\\.pem$", "\\.p12$", "(^|/)id_rsa$", "(^|/)id_dsa$",
      "(^|/)service-account.*\\.json$"
    ],
    "review_patterns": [
      { "name": "aws-access-key-id", "regex": "\\bAKIA[0-9A-Z]{16}\\b" },
      { "name": "google-api-key", "regex": "\\bAIza[0-9A-Za-z_\\-]{35}\\b" },
      { "name": "slack-token", "regex": "\\bxox[baprs]-[0-9A-Za-z-]{10,}\\b" },
      { "name": "github-pat", "regex": "\\bgh[pousr]_[0-9A-Za-z]{36,}\\b" },
      { "name": "stripe-key", "regex": "\\b[sr]k_(live|test)_[0-9A-Za-z]{16,}\\b" },
      { "name": "private-key-block", "regex": "-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----" },
      { "name": "db-url-with-password", "regex": "\\b(postgres|postgresql|mysql|mongodb)(\\+srv)?://[^\\s:@/]+:[^\\s:@/]+@" },
      { "name": "supabase-service-role", "regex": "\"?service_role\"?\\s*[:=]\\s*[\"']?eyJ[0-9A-Za-z_\\-]{20,}" },
      { "name": "jwt-signing-secret", "regex": "\\b(JWT_SECRET|SECRET_KEY|SIGNING_SECRET)\\s*[:=]\\s*[\"']?[0-9A-Za-z_\\-!@#$%^&*]{12,}" }
    ],
    "benign_filenames": ["^\\.env\\.example$", "^\\.env\\.sample$", "^\\.env\\.template$"],
    "benign_value_patterns": [
      "^x{3,}$", "^changeme$", "^your[-_].*$", "^<.*>$", "^\\$\\{.*\\}$",
      "^example$", "^placeholder$", "^dummy$", "^test$", "^\\.\\.\\.$"
    ],
    "benign_context_patterns": [
      "\"integrity\"\\s*:", "\"resolved\"\\s*:", "^\\s*#", "^\\s*//"
    ],
    "benign_path_patterns": ["(^|/)(tests?|fixtures?|mocks?|__tests__|examples?)(/|$)"],
    "max_file_bytes": 2097152
  }
}
```

- [ ] **Step 2: Create the two profiles**

`policy/profiles/generic.json`:

```json
{
  "name": "generic",
  "description": "Framework-neutral. Applies to any project in any language.",
  "agent_instructions": { "analyze": [], "security": [] },
  "extra_checks": []
}
```

`policy/profiles/genericsuite.json`:

```json
{
  "name": "genericsuite",
  "description": "Adds the GenericSuite ecosystem's stated non-negotiables from the monorepo CLAUDE.md.",
  "agent_instructions": {
    "analyze": [
      "This project may follow GenericSuite conventions. Check whether backend functions return the standard shape {\"error\": bool, \"error_message\": str|None, \"resultset\": Any}, and note every deviation in weaknesses[].",
      "Check whether CRUD entities, menus, and DB schemas are defined in JSON configuration rather than per-entity code. Hand-written per-entity code where JSON config was intended is a maintainability weakness."
    ],
    "security": [
      "Password hashing MUST be scrypt. Report any use of bcrypt, MD5, SHA-1, or an unsalted hash as a high-severity finding.",
      "SQL MUST use parameterized queries with identifier quoting. Report string-interpolated SQL as critical.",
      "Any AI-generated or user-supplied URL passed to a fetch must be wrapped by is_safe_url(); any file path by is_safe_local_path(). Report an unwrapped call as high (SSRF or LFI).",
      "Secrets MUST come from stage-specific .env files, never hardcoded. Report any hardcoded credential as critical.",
      "Log statements MUST sanitize newlines before logging user-controlled values. Report unsanitized logging as medium (log injection)."
    ]
  },
  "extra_checks": []
}
```

- [ ] **Step 3: Write `_policy.py`**

```python
#!/usr/bin/env python3
"""
_policy.py - Load policy/weakness.json and merge an optional profile overlay.

WHY THIS EXISTS
    Everything opinionated in this skill is data, not code: tier boundaries,
    secret patterns, table columns, gate defaults. A profile may ADD agent
    instructions and extra checks. It may never remove a generic check or
    lower a severity - narrowing a scan to make it pass is how a scan stops
    being worth running.
"""
import json
import os

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(SCRIPTS_DIR)
POLICY_PATH = os.path.join(SKILL_DIR, "policy", "weakness.json")
PROFILE_DIR = os.path.join(SKILL_DIR, "policy", "profiles")


class PolicyError(Exception):
    """Raised when policy or a profile cannot be loaded. Callers exit 2."""


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise PolicyError("not found: %s" % path)
    except ValueError as e:
        raise PolicyError("invalid JSON in %s: %s" % (path, e))


def resolve_profile_path(profile):
    """A bare name resolves inside policy/profiles/; anything else is a path."""
    if os.sep in profile or profile.endswith(".json"):
        return os.path.abspath(profile)
    return os.path.join(PROFILE_DIR, profile + ".json")


def load_policy(profile="generic"):
    policy = _read_json(POLICY_PATH)
    prof = _read_json(resolve_profile_path(profile))

    for key in ("analyze", "security"):
        added = prof.get("agent_instructions", {}).get(key, [])
        if not isinstance(added, list):
            raise PolicyError("profile agent_instructions.%s must be a list" % key)
        policy.setdefault("agent_instructions", {}).setdefault(key, [])
        policy["agent_instructions"][key].extend(added)

    policy["extra_checks"] = list(prof.get("extra_checks", []))
    policy["profile_name"] = prof.get("name", profile)
    return policy


def severity_rank(policy, severity):
    """Lower rank == more severe. Unknown severities sort last, never first."""
    order = policy["severity_order"]
    return order.index(severity) if severity in order else len(order)


def readiness_rank(policy, tier):
    order = policy["readiness_order"]
    return order.index(tier) if tier in order else len(order)
```

- [ ] **Step 4: Write `_redact.py`**

```python
#!/usr/bin/env python3
"""
_redact.py - Keep credentials out of every artifact this skill writes.

WHY THIS EXISTS
    The report states the literal command that produced it, so a connection
    string passed as an argument would land in a file people share. Credentials
    are supposed to come from the environment, but defence in depth means the
    captured command is redacted regardless.
"""
import re

_URI = re.compile(r"\b(postgres|postgresql|mysql|mongodb)(\+srv)?://[^\s'\"]+", re.I)
_SENSITIVE_FLAG = re.compile(
    r"(--[\w-]*(key|token|secret|password|url)[\w-]*)([= ])(\S+)", re.I)

REDACTED = "<redacted>"


def redact_command(cmd):
    """Redact connection URIs and the values of credential-shaped flags."""
    if not cmd:
        return ""
    out = _URI.sub(REDACTED, cmd)
    out = _SENSITIVE_FLAG.sub(lambda m: m.group(1) + m.group(3) + REDACTED, out)
    return out


def mask_value(value):
    """Never print a secret in full. Four leading chars plus the length."""
    if value is None:
        return ""
    s = str(value)
    if len(s) <= 4:
        return "*" * len(s)
    return "%s…(%d)" % (s[:4], len(s))
```

- [ ] **Step 5: Create the self-test harness**

Create `tests/selftest.py`. Later tasks append test functions and call them from `main()`.

```python
#!/usr/bin/env python3
"""
selftest.py - Positive control for project-weakness-analysis.

WHY THIS EXISTS
    A scanner that reports "clean" on everything is indistinguishable from a
    working one when the projects are genuinely clean. This builds synthetic
    projects with known positives, asserts every detector fires, and asserts
    the documented benign lookalikes do NOT. It also asserts the readiness
    legend is generated from policy rather than hand-written - the exact bug
    that shipped once already in repo-docker-scanner's report.

Exit: 0 all assertions passed, 1 something is broken (do not trust a scan).
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
SCRIPTS = os.path.join(SKILL, "scripts")
PACKAGE_ROOT = os.path.dirname(os.path.dirname(SKILL))
CORPUS_SCRIPTS = os.path.join(os.path.dirname(SKILL), "repo-corpus", "scripts")

sys.path.insert(0, SCRIPTS)
sys.path.insert(0, CORPUS_SCRIPTS)

import _policy   # noqa: E402
import _redact   # noqa: E402

GREEN, RED, YELLOW, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"
results = []
skipped = []


def check(name, condition, detail=""):
    results.append((name, bool(condition)))
    tag = "%sPASS%s" % (GREEN, RESET) if condition else "%sFAIL%s" % (RED, RESET)
    print("  [%s] %s" % (tag, name) + (("\n         " + detail) if detail and not condition else ""))


def skip(name, why):
    """A skipped assertion is NOT a passed one. Excluded from the count."""
    skipped.append((name, why))
    print("  [%sSKIP%s] %s - %s" % (YELLOW, RESET, name, why))


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def test_policy_loads():
    p = _policy.load_policy()
    check("policy loads with the generic profile", p["schema_version"] == 1)
    check("readiness_order has four tiers", len(p["readiness_order"]) == 4)
    check("unknown is the last readiness tier", p["readiness_order"][-1] == "unknown")
    check("severity_order starts at critical", p["severity_order"][0] == "critical")
    check("every readiness rule carries a reason",
          all(r.get("reason") for r in p["readiness_rules"]))
    gs = _policy.load_policy("genericsuite")
    check("genericsuite profile adds security instructions",
          any("scrypt" in i for i in gs["agent_instructions"]["security"]))
    check("generic profile adds none",
          _policy.load_policy()["agent_instructions"]["security"] == [])


def test_redaction():
    cmd = "./run.sh --db --db-url postgres://u:pw@host/db"
    out = _redact.redact_command(cmd)
    check("connection URI is redacted", "postgres://u:pw@host/db" not in out)
    check("flag value is redacted", "pw" not in out)
    check("masked value hides the secret",
          _redact.mask_value("AKIAIOSFODNN7EXAMPLE").startswith("AKIA")
          and "IOSFODNN7EXAMPLE" not in _redact.mask_value("AKIAIOSFODNN7EXAMPLE"))


def test_marketplace_registration():
    import json
    path = os.path.join(PACKAGE_ROOT, ".claude-plugin", "marketplace.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    paths = [s for p in data["plugins"] for s in p.get("skills", [])]
    check("skill is registered in marketplace.json",
          "./skills/project-weakness-analysis" in paths)
    for rel in paths:
        check("registered path exists: %s" % rel,
              os.path.isdir(os.path.join(PACKAGE_ROOT, rel)))


def main():
    print("Policy and profiles")
    test_policy_loads()
    print("\nRedaction")
    test_redaction()
    print("\nRegistration")
    test_marketplace_registration()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print("\n%d/%d assertions passed" % (passed, total))
    if skipped:
        print("%d skipped (NOT counted as passes)" % len(skipped))
    if passed != total:
        print("\n%sSELF-TEST FAILED - do not trust a scan from this code.%s" % (RED, RESET))
        return 1
    print("\n%sAll assertions passed.%s" % (GREEN, RESET))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Run the self-test — it must fail on registration**

```bash
cd skills/project-weakness-analysis && python3 tests/selftest.py
```

Expected: policy and redaction assertions PASS; `skill is registered in marketplace.json` FAILS. Exit `1`.

- [ ] **Step 7: Register the skill**

In `.claude-plugin/marketplace.json`, add `"./skills/project-weakness-analysis"` to the `skills` array (after `"./skills/repo-packages-scanner"`), and update the plugin `description` to `"GenericSuite security suite — supply chain security and production-readiness analysis for projects"`.

- [ ] **Step 8: Ignore generated output**

Append to `.gitignore`:

```
# project-weakness-analysis working directory (regenerable)
insights/.work/
```

- [ ] **Step 9: Run the self-test — all green**

```bash
cd skills/project-weakness-analysis && python3 tests/selftest.py
```

Expected: all assertions PASS, exit `0`.

- [ ] **Step 10: Commit**

```bash
git add skills/project-weakness-analysis .claude-plugin/marketplace.json .gitignore
git commit -m "feat(project-weakness-analysis): skill skeleton, policy, profiles, self-test harness"
```

---

### Task 2: `discover_projects.py` — a root directory becomes a project list

**Files:**
- Create: `skills/project-weakness-analysis/scripts/discover_projects.py`
- Modify: `skills/project-weakness-analysis/tests/selftest.py`

**Interfaces:**
- Consumes: `_policy.load_policy()` → `project_markers`, `prune_dirs`, `discovery.max_depth`.
- Produces:
  - `discover(root, policy, max_depth=None, split_monorepo=False, limit=None) -> (list[str], DiscoveryStats)` — absolute paths, sorted.
  - `class DiscoveryStats` with attributes `unreadable: list[str]`, `truncated: str|None`, `pruned: int`, and method `summary() -> str`.
  - CLI: `python3 discover_projects.py --root PATH [--max-depth N] [--limit N] [--split-monorepo] [--list-only] [--profile NAME]`, printing one absolute path per line to stdout.

- [ ] **Step 1: Write the failing tests**

Append to `tests/selftest.py`, before `main()`:

```python
def build_discovery_fixture(base):
    """A root holding: a normal project, a monorepo, a nested node_modules trap."""
    write(os.path.join(base, "alpha", "package.json"), '{"name":"alpha"}')
    write(os.path.join(base, "alpha", "node_modules", "dep", "package.json"), '{"name":"dep"}')
    write(os.path.join(base, "beta", "pyproject.toml"), "[project]\nname='beta'\n")
    write(os.path.join(base, "mono", "frontend", "package.json"), '{"name":"fe"}')
    write(os.path.join(base, "mono", "backend", "pyproject.toml"), "[project]\nname='be'\n")
    os.makedirs(os.path.join(base, "mono", ".git"), exist_ok=True)
    write(os.path.join(base, "notaproject", "README.md"), "# just docs\n")
    return base


def test_discovery():
    import tempfile
    import discover_projects
    policy = _policy.load_policy()
    with tempfile.TemporaryDirectory() as base:
        build_discovery_fixture(base)
        found, stats = discover_projects.discover(base, policy)
        names = sorted(os.path.basename(p) for p in found)
        check("finds every marker-bearing project", names == ["alpha", "beta", "mono"],
              "got %s" % names)
        check("a package.json inside node_modules is not a project",
              not any("node_modules" in p for p in found))
        check("a directory with no marker is not a project", "notaproject" not in names)

        split, _ = discover_projects.discover(base, policy, split_monorepo=True)
        split_names = sorted(os.path.basename(p) for p in split)
        check("--split-monorepo yields the subdirectories",
              "frontend" in split_names and "backend" in split_names,
              "got %s" % split_names)

        shallow, sstats = discover_projects.discover(base, policy, max_depth=0)
        check("max_depth=0 finds nothing under the root", shallow == [])
        check("depth truncation is recorded", sstats.truncated is not None)

        capped, cstats = discover_projects.discover(base, policy, limit=1)
        check("--limit caps the list", len(capped) == 1)
        check("--limit truncation is recorded", cstats.truncated is not None)


def test_discovery_symlink_escape():
    import tempfile
    import discover_projects
    policy = _policy.load_policy()
    with tempfile.TemporaryDirectory() as outside:
        write(os.path.join(outside, "secret", "package.json"), "{}")
        with tempfile.TemporaryDirectory() as base:
            write(os.path.join(base, "real", "package.json"), "{}")
            link = os.path.join(base, "escape")
            try:
                os.symlink(os.path.join(outside, "secret"), link)
            except (OSError, NotImplementedError):
                skip("symlinks cannot escape the discovery root", "symlink unsupported here")
                return
            found, _ = discover_projects.discover(base, policy)
            check("symlinks cannot escape the discovery root",
                  all(os.path.realpath(p).startswith(os.path.realpath(base)) for p in found),
                  "got %s" % found)
```

Register them in `main()` after the policy block:

```python
    print("\nDiscovery")
    test_discovery()
    test_discovery_symlink_escape()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'discover_projects'`.

- [ ] **Step 3: Write the implementation**

Create `scripts/discover_projects.py`:

```python
#!/usr/bin/env python3
"""
discover_projects.py - Expand a root directory into the projects beneath it.

WHY THIS EXISTS
    repo-corpus's --local takes a list of paths but has no "expand this root"
    mode. That expansion is the one genuinely new input capability this skill
    needs, and it is the step where a wrong answer is invisible: a project that
    is never discovered is never scanned, and nothing in the output says so.
    Hence every limit here is recorded rather than applied silently.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _policy  # noqa: E402


class DiscoveryStats(object):
    def __init__(self):
        self.unreadable = []
        self.truncated = None
        self.pruned = 0

    def summary(self):
        bits = []
        if self.pruned:
            bits.append("%d dir(s) pruned" % self.pruned)
        if self.unreadable:
            bits.append("%d PATH(S) COULD NOT BE READ" % len(self.unreadable))
        if self.truncated:
            bits.append("TRUNCATED: %s" % self.truncated)
        return ", ".join(bits) if bits else "no limits hit"

    def as_dict(self):
        return {"unreadable": self.unreadable, "truncated": self.truncated,
                "pruned": self.pruned}


def _has_marker(path, markers):
    for m in markers:
        if os.path.exists(os.path.join(path, m)):
            return True
    return False


def _listdir(path, stats):
    try:
        return sorted(os.listdir(path))
    except OSError:
        stats.unreadable.append(path)
        return []


def discover(root, policy, max_depth=None, split_monorepo=False, limit=None):
    """Return (sorted absolute project paths, DiscoveryStats).

    Descent stops at the first directory carrying a marker, so a repo holding
    frontend/ and backend/ is ONE project - unless split_monorepo is set.
    """
    root = os.path.realpath(root)
    markers = policy["project_markers"]
    prune = set(policy["prune_dirs"])
    if max_depth is None:
        max_depth = policy["discovery"]["max_depth"]

    stats = DiscoveryStats()
    found = []

    def walk(path, depth):
        if depth > max_depth:
            stats.truncated = "max_depth=%d reached at %s" % (max_depth, path)
            return
        for name in _listdir(path, stats):
            if name in prune:
                stats.pruned += 1
                continue
            child = os.path.join(path, name)
            if not os.path.isdir(child):
                continue
            if os.path.islink(child):
                continue
            if not os.path.realpath(child).startswith(root + os.sep):
                continue
            if _has_marker(child, markers):
                if split_monorepo:
                    subs = [os.path.join(child, n) for n in _listdir(child, stats)
                            if n not in prune
                            and os.path.isdir(os.path.join(child, n))
                            and not os.path.islink(os.path.join(child, n))
                            and _has_marker(os.path.join(child, n), markers)]
                    if subs:
                        found.extend(subs)
                        continue
                found.append(child)
                continue
            walk(child, depth + 1)

    if max_depth >= 1:
        walk(root, 1)
    else:
        stats.truncated = "max_depth=0: nothing below the root was examined"

    found = sorted(set(found))
    if limit is not None and len(found) > limit:
        stats.truncated = "--limit=%d hit; %d project(s) were not analyzed" % (
            limit, len(found) - limit)
        found = found[:limit]
    return found, stats


def main(argv=None):
    ap = argparse.ArgumentParser(description="Expand a root directory into projects.")
    ap.add_argument("--root", required=True)
    ap.add_argument("--max-depth", type=int, default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--split-monorepo", action="store_true")
    ap.add_argument("--list-only", action="store_true")
    ap.add_argument("--profile", default="generic")
    ap.add_argument("--stats-json", default=None, help="write DiscoveryStats here")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.root):
        sys.stderr.write("not a directory: %s\n" % args.root)
        return 2
    try:
        policy = _policy.load_policy(args.profile)
    except _policy.PolicyError as e:
        sys.stderr.write("%s\n" % e)
        return 2

    found, stats = discover(args.root, policy, args.max_depth,
                            args.split_monorepo, args.limit)
    for p in found:
        sys.stdout.write(p + "\n")
    sys.stderr.write("discovered %d project(s); %s\n" % (len(found), stats.summary()))
    if args.stats_json:
        with open(args.stats_json, "w", encoding="utf-8") as f:
            json.dump(stats.as_dict(), f, indent=2)
    if not found:
        sys.stderr.write("no projects found under %s - refusing to report a clean scan "
                         "of nothing\n" % args.root)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: all assertions PASS (or the symlink one SKIPs on a filesystem without symlink support), exit `0`.

- [ ] **Step 5: Verify the CLI by hand**

```bash
cd skills/project-weakness-analysis
python3 scripts/discover_projects.py --root ../.. --max-depth 2
```
Expected: one absolute path per line on stdout, a `discovered N project(s)` line on stderr, exit `0`.

- [ ] **Step 6: Commit**

```bash
git add skills/project-weakness-analysis/scripts/discover_projects.py skills/project-weakness-analysis/tests/selftest.py
git commit -m "feat(project-weakness-analysis): discover projects under a root directory"
```

---

### Task 3: `_secrets.py` — tiered secret candidates

**Files:**
- Create: `skills/project-weakness-analysis/scripts/_secrets.py`
- Modify: `skills/project-weakness-analysis/tests/selftest.py`

**Interfaces:**
- Consumes: `_policy.load_policy()` → `secrets` block; `_redact.mask_value`.
- Produces:
  - `tracked_files(project_path) -> list[str]` — repo-relative paths from `git ls-files`; `[]` when the path is not a git repo.
  - `scan_project(project_path, policy, tracked=None) -> list[dict]` — each finding is `{"tier": "CONFIRMED"|"REVIEW", "file": str, "line": int, "pattern": str, "masked": str}`. `line` is `0` for `CONFIRMED` filename findings.

- [ ] **Step 1: Write the failing tests**

Append to `tests/selftest.py`:

```python
def build_secrets_fixture(base):
    proj = os.path.join(base, "leaky")
    write(os.path.join(proj, ".env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    write(os.path.join(proj, ".env.example"), "AWS_ACCESS_KEY_ID=your-key-here\n")
    write(os.path.join(proj, "src", "config.js"),
          "const k = 'AKIAIOSFODNN7EXAMPLE';\n"
          "const db = 'postgres://admin:hunter2@db.example.com/app';\n")
    write(os.path.join(proj, "package-lock.json"),
          '{"integrity": "sha512-AIzaSyA1234567890123456789012345678901"}\n')
    write(os.path.join(proj, "tests", "fixture.js"), "const k = 'xxx';\n")
    write(os.path.join(proj, "docs", "setup.md"), "# set SECRET_KEY = changeme\n")
    return proj


def test_secrets():
    import tempfile
    import _secrets
    policy = _policy.load_policy()
    with tempfile.TemporaryDirectory() as base:
        proj = build_secrets_fixture(base)
        tracked = [".env", ".env.example", "src/config.js", "package-lock.json",
                   "tests/fixture.js", "docs/setup.md"]
        f = _secrets.scan_project(proj, policy, tracked=tracked)
        by_file = {}
        for x in f:
            by_file.setdefault(x["file"], []).append(x)

        check("a tracked .env is CONFIRMED",
              any(x["tier"] == "CONFIRMED" for x in by_file.get(".env", [])))
        check("an AWS key in source is REVIEW",
              any(x["pattern"] == "aws-access-key-id" and x["tier"] == "REVIEW"
                  for x in by_file.get("src/config.js", [])))
        check("a db URL with an inline password is REVIEW",
              any(x["pattern"] == "db-url-with-password"
                  for x in by_file.get("src/config.js", [])))

        check("BENIGN: .env.example does not fire", ".env.example" not in by_file)
        check("BENIGN: a lockfile integrity blob does not fire",
              "package-lock.json" not in by_file)
        check("BENIGN: a placeholder in a test fixture does not fire",
              "tests/fixture.js" not in by_file)
        check("BENIGN: a commented placeholder does not fire",
              "docs/setup.md" not in by_file)

        check("no finding contains a full secret value",
              all("IOSFODNN7EXAMPLE" not in x["masked"] for x in f))
        check("every finding carries file, line, pattern and mask",
              all(set(("tier", "file", "line", "pattern", "masked")) <= set(x) for x in f))


def test_secrets_untracked_env_is_not_confirmed():
    import tempfile
    import _secrets
    policy = _policy.load_policy()
    with tempfile.TemporaryDirectory() as base:
        proj = os.path.join(base, "clean")
        write(os.path.join(proj, ".env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
        f = _secrets.scan_project(proj, policy, tracked=[])
        check("an UNTRACKED .env is not CONFIRMED",
              not any(x["tier"] == "CONFIRMED" for x in f))
```

Register in `main()`:

```python
    print("\nSecrets")
    test_secrets()
    test_secrets_untracked_env_is_not_confirmed()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: FAIL with `ModuleNotFoundError: No module named '_secrets'`.

- [ ] **Step 3: Write the implementation**

Create `scripts/_secrets.py`:

```python
#!/usr/bin/env python3
"""
_secrets.py - Offline, tiered secret candidates. No network, no entropy rules.

WHY TWO TIERS
    That a file is committed to git is a repo-tree FACT - not a matter of
    opinion - so a tracked .env is CONFIRMED. A regex hit on a credential
    shape cannot prove the string is live, so it is REVIEW: surfaced for a
    human, never auto-labelled a breach. Conflating the two is how a scanner
    earns a reputation for crying wolf and then gets switched off.

    Values are never printed in full. A security report that leaks the secret
    it found is a new incident.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _redact  # noqa: E402


def tracked_files(project_path):
    """Repo-relative paths git knows about. Empty list when not a git repo."""
    try:
        proc = subprocess.run(
            ["git", "-C", project_path, "ls-files"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    return [l for l in proc.stdout.decode("utf-8", "replace").splitlines() if l]


def _compile(patterns):
    return [(p["name"], re.compile(p["regex"])) for p in patterns]


def _is_benign_value(value, benign_value_res):
    v = value.strip().strip("'\"").strip()
    return any(r.match(v) for r in benign_value_res)


def scan_project(project_path, policy, tracked=None):
    cfg = policy["secrets"]
    if tracked is None:
        tracked = tracked_files(project_path)
    tracked_set = set(tracked)

    confirmed_res = [re.compile(r) for r in cfg["confirmed_tracked_files"]]
    benign_name_res = [re.compile(r) for r in cfg["benign_filenames"]]
    benign_value_res = [re.compile(r, re.I) for r in cfg["benign_value_patterns"]]
    benign_ctx_res = [re.compile(r) for r in cfg["benign_context_patterns"]]
    benign_path_res = [re.compile(r) for r in cfg["benign_path_patterns"]]
    review_res = _compile(cfg["review_patterns"])

    findings = []

    # Tier 1: CONFIRMED - the file itself is committed.
    for rel in sorted(tracked_set):
        name = os.path.basename(rel)
        if any(r.match(name) for r in benign_name_res):
            continue
        if any(r.search(rel) or r.search(name) for r in confirmed_res):
            findings.append({"tier": "CONFIRMED", "file": rel, "line": 0,
                             "pattern": "tracked-credential-file",
                             "masked": _redact.mask_value(name)})

    # Tier 2: REVIEW - a credential shape appears in tracked content.
    for rel in sorted(tracked_set):
        name = os.path.basename(rel)
        if any(r.match(name) for r in benign_name_res):
            continue
        in_benign_path = any(r.search(rel) for r in benign_path_res)
        abspath = os.path.join(project_path, rel)
        try:
            if os.path.getsize(abspath) > cfg["max_file_bytes"]:
                continue
            with open(abspath, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        for i, line in enumerate(lines, start=1):
            if any(r.search(line) for r in benign_ctx_res):
                continue
            for pname, rx in review_res:
                m = rx.search(line)
                if not m:
                    continue
                if _is_benign_value(m.group(0), benign_value_res):
                    continue
                if in_benign_path:
                    continue
                findings.append({"tier": "REVIEW", "file": rel, "line": i,
                                 "pattern": pname,
                                 "masked": _redact.mask_value(m.group(0))})
    return findings
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: all assertions PASS, exit `0`.

If `BENIGN: a placeholder in a test fixture does not fire` fails, the value `'xxx'` is being matched by a `review_patterns` entry rather than caught by `benign_path_patterns` — confirm `tests/fixture.js` matches `(^|/)(tests?|fixtures?|mocks?|__tests__|examples?)(/|$)`.

- [ ] **Step 5: Commit**

```bash
git add skills/project-weakness-analysis/scripts/_secrets.py skills/project-weakness-analysis/tests/selftest.py
git commit -m "feat(project-weakness-analysis): tiered secret candidate detection"
```

---

### Task 4: `collect_signals.py` — deterministic per-project facts

**Files:**
- Create: `skills/project-weakness-analysis/scripts/collect_signals.py`
- Modify: `skills/project-weakness-analysis/tests/selftest.py`

**Interfaces:**
- Consumes: `_policy.load_policy()`; `_secrets.scan_project`, `_secrets.tracked_files`; `_walk` from `repo-corpus/scripts/_walk.py` (`_walk.WalkStats()`, `_walk.walk_files(root, stats=stats)`, `_walk.read_text(abspath, stats)`).
- Produces:
  - `collect(project_path, slug, policy, corpus_entry=None) -> dict` — the evidence bundle. Guaranteed top-level keys: `project_slug`, `path`, `branch`, `head_sha`, `remote_url`, `size`, `manifests`, `quality`, `deploy`, `config_hygiene`, `secrets`, `structure`, `walk_stats`, `db_metadata`, `siblings`. `siblings` is `{}` here; Task 5 fills it.
  - CLI: `python3 collect_signals.py --corpus PATH --out DIR [--profile NAME]`, writing `DIR/<slug>.json` per project.

Corpus entry fields relied on (from `repo-corpus`'s `corpus.json`): `repos[].name`, `repos[].path` (relative to `root`), `repos[].status`, `repos[].checked_out`, `repos[].branches[].name`, `repos[].branches[].head`, and top-level `root`. Entries with `status == "failed"` are skipped and counted.

- [ ] **Step 1: Write the failing tests**

Append to `tests/selftest.py`:

```python
def build_signals_fixtures(base):
    """Three projects: production-grade, boilerplate skeleton, leaky."""
    good = os.path.join(base, "good")
    write(os.path.join(good, "package.json"),
          '{"name":"good","dependencies":{"express":"4.18.2"}}')
    write(os.path.join(good, "package-lock.json"), '{"lockfileVersion":3}')
    write(os.path.join(good, "README.md"), "# good\n" + ("detail\n" * 40))
    write(os.path.join(good, "LICENSE"), "MIT\n")
    write(os.path.join(good, ".gitignore"), ".env\n")
    write(os.path.join(good, "Dockerfile"), "FROM node:20-alpine\n")
    write(os.path.join(good, ".github", "workflows", "ci.yml"), "on: push\n")
    write(os.path.join(good, "tests", "app.test.js"), "test('x', () => {});\n")
    write(os.path.join(good, "src", "app.js"), "const e = require('express');\n" * 20)
    write(os.path.join(good, ".env.example"), "PORT=3000\n")

    skel = os.path.join(base, "skeleton")
    write(os.path.join(skel, "package.json"), '{"name":"skeleton"}')
    write(os.path.join(skel, "README.md"), "# skeleton\n")

    return good, skel


def test_collect_signals():
    import tempfile
    import collect_signals
    policy = _policy.load_policy()
    with tempfile.TemporaryDirectory() as base:
        good, skel = build_signals_fixtures(base)

        g = collect_signals.collect(good, "good", policy, corpus_entry=None)
        check("detects a committed lockfile", g["manifests"]["lockfiles"] == ["package-lock.json"],
              "got %s" % g["manifests"]["lockfiles"])
        check("detects tests", g["quality"]["has_tests"] is True)
        check("detects CI", g["quality"]["has_ci"] is True)
        check("detects a Dockerfile", g["deploy"]["has_dockerfile"] is True)
        check("detects a README with real length", g["quality"]["readme_bytes"] > 100)
        check("detects LICENSE", g["quality"]["has_license"] is True)
        check("counts lines of code", g["size"]["code_loc"] > 0)
        check("records .env.example", g["config_hygiene"]["has_env_example"] is True)
        check("siblings starts empty", g["siblings"] == {})
        check("walk_stats is carried", "unreadable" in g["walk_stats"])

        s = collect_signals.collect(skel, "skeleton", policy, corpus_entry=None)
        check("skeleton has no tests", s["quality"]["has_tests"] is False)
        check("skeleton has no CI", s["quality"]["has_ci"] is False)
        check("skeleton has no lockfile", s["manifests"]["lockfiles"] == [])
        check("skeleton has no Dockerfile", s["deploy"]["has_dockerfile"] is False)


def test_collect_signals_writes_nothing_into_projects():
    import tempfile
    import collect_signals
    policy = _policy.load_policy()
    with tempfile.TemporaryDirectory() as base:
        good, _ = build_signals_fixtures(base)
        before = set()
        for r, d, fs in os.walk(good):
            for x in fs:
                before.add(os.path.join(r, x))
        collect_signals.collect(good, "good", policy, corpus_entry=None)
        after = set()
        for r, d, fs in os.walk(good):
            for x in fs:
                after.add(os.path.join(r, x))
        check("collecting writes nothing inside a scanned project", before == after,
              "added: %s" % (after - before))
```

Register in `main()`:

```python
    print("\nSignals")
    test_collect_signals()
    test_collect_signals_writes_nothing_into_projects()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'collect_signals'`.

- [ ] **Step 3: Write the implementation**

Create `scripts/collect_signals.py`:

```python
#!/usr/bin/env python3
"""
collect_signals.py - Per-project facts a script can prove, for the evidence bundle.

WHY THIS EXISTS
    Every field here is something an agent would otherwise burn tokens
    rediscovering, and would sometimes get wrong. A committed lockfile either
    exists or does not. Grounding the agents in proven facts is what makes them
    both cheaper and more trustworthy - and it means findings a machine can
    prove are never left to an LLM's judgment.
"""
import argparse
import json
import os
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(SCRIPTS_DIR)
CORPUS_SCRIPTS = os.path.join(os.path.dirname(SKILL_DIR), "repo-corpus", "scripts")
sys.path.insert(0, SCRIPTS_DIR)
sys.path.insert(0, CORPUS_SCRIPTS)

import _policy   # noqa: E402
import _secrets  # noqa: E402
import _walk     # noqa: E402

MANIFESTS = ["package.json", "pyproject.toml", "requirements.txt", "Pipfile",
             "go.mod", "Cargo.toml", "Gemfile", "composer.json", "pom.xml",
             "build.gradle", "pubspec.yaml"]
LOCKFILES = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
             "uv.lock", "Pipfile.lock", "go.sum", "Cargo.lock", "Gemfile.lock",
             "composer.lock"]
CODE_EXT = {".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript",
            ".jsx": "JavaScript", ".py": "Python", ".go": "Go", ".rb": "Ruby",
            ".php": "PHP", ".java": "Java", ".rs": "Rust", ".swift": "Swift",
            ".kt": "Kotlin", ".dart": "Dart", ".vue": "Vue", ".svelte": "Svelte",
            ".cs": "C#", ".c": "C", ".cpp": "C++", ".sh": "Shell"}
TEST_HINTS = ("test", "tests", "spec", "specs", "__tests__")
IAC_HINTS = (".tf", ".tfvars")
DEPLOY_FILES = ["Procfile", "serverless.yml", "serverless.yaml", "vercel.json",
                "netlify.toml", "fly.toml", "render.yaml", "app.yaml"]
COMPOSE = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
FILE_TREE_SAMPLE = 200


def _exists(root, name):
    return os.path.exists(os.path.join(root, name))


def _is_test_path(rel):
    parts = rel.replace("\\", "/").lower().split("/")
    if any(p in TEST_HINTS for p in parts[:-1]):
        return True
    base = parts[-1]
    return ".test." in base or ".spec." in base or base.startswith("test_")


def collect(project_path, slug, policy, corpus_entry=None):
    project_path = os.path.abspath(project_path)
    stats = _walk.WalkStats()

    loc_by_lang = {}
    code_loc = 0
    file_count = 0
    tree_sample = []
    has_tests = False
    has_iac = False
    largest = []

    for abspath, relpath in _walk.walk_files(project_path, stats=stats):
        file_count += 1
        if len(tree_sample) < FILE_TREE_SAMPLE:
            tree_sample.append(relpath)
        if _is_test_path(relpath):
            has_tests = True
        ext = os.path.splitext(relpath)[1].lower()
        if ext in IAC_HINTS:
            has_iac = True
        if ext in CODE_EXT:
            text = _walk.read_text(abspath, stats)
            if text is None:
                continue
            n = text.count("\n") + 1
            code_loc += n
            lang = CODE_EXT[ext]
            loc_by_lang[lang] = loc_by_lang.get(lang, 0) + n
            largest.append((n, relpath))

    largest.sort(reverse=True)
    tracked = _secrets.tracked_files(project_path)
    tracked_set = set(tracked)

    env_tracked = sorted(p for p in tracked_set
                         if os.path.basename(p).startswith(".env")
                         and not os.path.basename(p).endswith(
                             ("example", "sample", "template")))

    branch = head = remote = None
    if corpus_entry:
        branch = corpus_entry.get("checked_out") or corpus_entry.get("default_branch")
        for b in corpus_entry.get("branches", []):
            if b.get("name") == branch:
                head = b.get("head")
                break
        remote = corpus_entry.get("url") or corpus_entry.get("remote_url")

    primary = max(loc_by_lang.items(), key=lambda kv: kv[1])[0] if loc_by_lang else None

    return {
        "project_slug": slug,
        "path": project_path,
        "branch": branch,
        "head_sha": head,
        "remote_url": remote,
        "size": {"file_count": file_count, "code_loc": code_loc,
                 "loc_by_language": loc_by_lang, "primary_language": primary,
                 "largest_files": [{"lines": n, "file": f} for n, f in largest[:10]]},
        "manifests": {
            "present": [m for m in MANIFESTS if _exists(project_path, m)],
            "lockfiles": [l for l in LOCKFILES if _exists(project_path, l)],
        },
        "quality": {
            "has_tests": has_tests,
            "has_ci": os.path.isdir(os.path.join(project_path, ".github", "workflows"))
                      or _exists(project_path, ".gitlab-ci.yml")
                      or _exists(project_path, ".circleci"),
            "has_readme": _exists(project_path, "README.md"),
            "readme_bytes": (os.path.getsize(os.path.join(project_path, "README.md"))
                             if _exists(project_path, "README.md") else 0),
            "has_license": _exists(project_path, "LICENSE") or _exists(project_path, "LICENSE.md"),
            "has_gitignore": _exists(project_path, ".gitignore"),
            "has_typed_config": _exists(project_path, "tsconfig.json") or _exists(project_path, "mypy.ini"),
        },
        "deploy": {
            "has_dockerfile": _exists(project_path, "Dockerfile"),
            "has_compose": any(_exists(project_path, c) for c in COMPOSE),
            "has_iac": has_iac,
            "deploy_files": [d for d in DEPLOY_FILES if _exists(project_path, d)],
        },
        "config_hygiene": {
            "env_files_tracked": env_tracked,
            "has_env_example": _exists(project_path, ".env.example")
                               or _exists(project_path, ".env.sample"),
        },
        "secrets": _secrets.scan_project(project_path, policy, tracked=tracked),
        "structure": {
            "top_level": sorted(n for n in os.listdir(project_path)
                                if not n.startswith(".git")),
            "file_tree_sample": tree_sample,
        },
        "walk_stats": {"unreadable": list(getattr(stats, "unreadable", [])),
                       "prune_counts": dict(getattr(stats, "prune_counts", {}) or {}),
                       "summary": stats.summary()},
        "db_metadata": {},
        "siblings": {},
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Collect deterministic per-project signals.")
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--profile", default="generic")
    args = ap.parse_args(argv)

    try:
        policy = _policy.load_policy(args.profile)
        with open(args.corpus, "r", encoding="utf-8") as f:
            corpus = json.load(f)
    except (_policy.PolicyError, OSError, ValueError) as e:
        sys.stderr.write("%s\n" % e)
        return 2

    os.makedirs(args.out, exist_ok=True)
    root = corpus.get("root", "")
    written = skipped = 0
    for entry in corpus.get("repos", []):
        slug = entry.get("name")
        if entry.get("status") == "failed" or not entry.get("path"):
            skipped += 1
            continue
        path = os.path.join(root, entry["path"])
        if not os.path.isdir(path):
            skipped += 1
            continue
        bundle = collect(path, slug, policy, corpus_entry=entry)
        with open(os.path.join(args.out, slug + ".json"), "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)
        written += 1
    sys.stderr.write("evidence: %d written, %d skipped\n" % (written, skipped))
    return 0 if written else 2


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: all assertions PASS, exit `0`.

If `_walk` import fails, `repo-corpus` is not installed alongside — that is the documented side-by-side requirement, not a bug to work around by copying the file.

- [ ] **Step 5: Commit**

```bash
git add skills/project-weakness-analysis/scripts/collect_signals.py skills/project-weakness-analysis/tests/selftest.py
git commit -m "feat(project-weakness-analysis): deterministic per-project signal collection"
```

---

### Task 5: `_siblings.py` — fold the sibling scanners' findings into the evidence

**Files:**
- Create: `skills/project-weakness-analysis/scripts/_siblings.py`
- Modify: `skills/project-weakness-analysis/scripts/collect_signals.py`
- Modify: `skills/project-weakness-analysis/tests/selftest.py`

**Interfaces:**
- Consumes: `corpus.json` path; the sibling skill directories `../repo-docker-scanner` and `../repo-packages-scanner`.
- Produces:
  - `run_all(corpus_path, work_dir) -> dict` keyed by scanner name (`"docker"`, `"packages"`), each value `{"available": bool, "reason": str, "by_project": {slug: [finding, ...]}}`.
  - `attach(evidence_dir, siblings) -> None` — writes each bundle's `siblings` key in place.
- Consumed by: Task 9's blind-spot section reads `available` and `reason`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/selftest.py`:

```python
def test_siblings_absent_is_visible():
    import tempfile
    import _siblings
    with tempfile.TemporaryDirectory() as base:
        corpus = os.path.join(base, "corpus.json")
        write(corpus, '{"schema_version":1,"root":"%s","repos":[]}' % base)
        out = _siblings.run_all(corpus, base, skill_dirs={"docker": os.path.join(base, "nope")})
        check("a missing sibling scanner is recorded as unavailable",
              out["docker"]["available"] is False)
        check("a missing sibling scanner records a reason",
              bool(out["docker"]["reason"]))
        check("a missing sibling scanner never reports zero findings as fact",
              out["docker"].get("by_project") == {})


def test_siblings_attach():
    import tempfile
    import json as _json
    import _siblings
    with tempfile.TemporaryDirectory() as base:
        ev = os.path.join(base, "evidence")
        os.makedirs(ev)
        with open(os.path.join(ev, "alpha.json"), "w", encoding="utf-8") as f:
            _json.dump({"project_slug": "alpha", "siblings": {}}, f)
        siblings = {"docker": {"available": True, "reason": "",
                               "by_project": {"alpha": [{"priority": "P0", "ref": "nginx:latest"}]}}}
        _siblings.attach(ev, siblings)
        with open(os.path.join(ev, "alpha.json"), "r", encoding="utf-8") as f:
            bundle = _json.load(f)
        check("sibling findings are attached to the evidence bundle",
              bundle["siblings"]["docker"]["findings"][0]["ref"] == "nginx:latest")
        check("attach records availability per scanner",
              bundle["siblings"]["docker"]["available"] is True)
```

Register in `main()`:

```python
    print("\nSibling scanners")
    test_siblings_absent_is_visible()
    test_siblings_attach()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: FAIL with `ModuleNotFoundError: No module named '_siblings'`.

- [ ] **Step 3: Write the implementation**

Create `scripts/_siblings.py`:

```python
#!/usr/bin/env python3
"""
_siblings.py - Run repo-docker-scanner and repo-packages-scanner over the same
corpus and fold their findings into each project's evidence bundle.

WHY DEGRADATION MUST BE VISIBLE
    If a sibling scanner is missing or crashes, this records available=false
    with a reason. It NEVER records "no findings" for a scanner that never ran.
    That distinction is the whole point of this package: a falsely clean
    verdict is worse than no verdict.
"""
import json
import os
import subprocess
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(SCRIPTS_DIR)
SKILLS_ROOT = os.path.dirname(SKILL_DIR)

DEFAULT_SKILL_DIRS = {
    "docker": os.path.join(SKILLS_ROOT, "repo-docker-scanner"),
    "packages": os.path.join(SKILLS_ROOT, "repo-packages-scanner"),
}
SCANNER_SCRIPT = {"docker": "scan_images.py", "packages": "scan_packages.py"}
TIMEOUT_SECONDS = 900


def _empty(reason):
    return {"available": False, "reason": reason, "by_project": {}}


def run_one(name, skill_dir, corpus_path, work_dir):
    script = os.path.join(skill_dir, "scripts", SCANNER_SCRIPT[name])
    if not os.path.isfile(script):
        return _empty("not installed: %s" % script)

    findings_path = os.path.join(work_dir, "siblings", "%s-findings.json" % name)
    os.makedirs(os.path.dirname(findings_path), exist_ok=True)
    cmd = ["python3", script, "--corpus", corpus_path,
           "--findings", findings_path, "--fail-on", "none"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError) as e:
        return _empty("failed to run: %s" % e)
    if proc.returncode == 2:
        return _empty("exited 2 (error): %s"
                      % proc.stderr.decode("utf-8", "replace").strip()[:300])
    try:
        with open(findings_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        return _empty("no readable findings file: %s" % e)

    by_project = {}
    for finding in data.get("findings", []):
        slug = finding.get("repo") or finding.get("project_slug")
        if not slug:
            continue
        by_project.setdefault(slug, []).append(finding)
    return {"available": True, "reason": "", "by_project": by_project}


def run_all(corpus_path, work_dir, skill_dirs=None):
    dirs = dict(DEFAULT_SKILL_DIRS)
    if skill_dirs:
        dirs.update(skill_dirs)
    return {name: run_one(name, path, corpus_path, work_dir)
            for name, path in dirs.items()}


def attach(evidence_dir, siblings):
    """Write each scanner's per-project findings into the evidence bundles."""
    for fname in sorted(os.listdir(evidence_dir)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(evidence_dir, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                bundle = json.load(f)
        except (OSError, ValueError):
            continue
        slug = bundle.get("project_slug") or os.path.splitext(fname)[0]
        bundle["siblings"] = {
            name: {"available": res["available"], "reason": res["reason"],
                   "findings": res["by_project"].get(slug, [])}
            for name, res in siblings.items()}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.stderr.write("usage: _siblings.py CORPUS_JSON WORK_DIR EVIDENCE_DIR\n")
        sys.exit(2)
    res = run_all(sys.argv[1], sys.argv[2])
    attach(sys.argv[3], res)
    for n, r in res.items():
        sys.stderr.write("%s: %s\n" % (n, "ok" if r["available"] else r["reason"]))
    sys.exit(0)
```

- [ ] **Step 4: Wire it into `collect_signals.py`**

In `collect_signals.py`'s `main()`, after the per-project write loop and before the summary line, add:

```python
    if not args.no_siblings:
        import _siblings
        res = _siblings.run_all(args.corpus, os.path.dirname(os.path.abspath(args.out)))
        _siblings.attach(args.out, res)
        for n, r in res.items():
            sys.stderr.write("sibling %s: %s\n" % (n, "ok" if r["available"] else r["reason"]))
```

And add the flag to the parser, immediately after `--profile`:

```python
    ap.add_argument("--no-siblings", action="store_true",
                    help="skip the sibling scanners; recorded as a blind spot")
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: all assertions PASS, exit `0`.

- [ ] **Step 6: Commit**

```bash
git add skills/project-weakness-analysis/scripts/_siblings.py skills/project-weakness-analysis/scripts/collect_signals.py skills/project-weakness-analysis/tests/selftest.py
git commit -m "feat(project-weakness-analysis): fold sibling scanner findings into evidence"
```

---

### Task 6: `db_collect.py` — the optional Supabase/Postgres input mode

**Files:**
- Create: `skills/project-weakness-analysis/scripts/db_collect.py`
- Create: `skills/project-weakness-analysis/tests/fixtures/db-rows.json`
- Modify: `skills/project-weakness-analysis/tests/selftest.py`

**Read first:** the spec's "Input mode: `--db`" section. Two things there are easy to get backwards:

1. The table is a **project registry** naming repositories. It has nothing to do with what database a scanned project uses internally. Do **not** build a Supabase-usage detector.
2. This mode is **optional**. Nothing else in the skill may import or require it.

**Interfaces:**
- Consumes: `_policy.load_policy()` → `db_source`; `_redact`.
- Produces:
  - `normalize_repo_url(url) -> str` — lowercased, trailing `.git` and `/` removed.
  - `extract_repo_url(row, cfg) -> (url|None, source_column|None)`
  - `build_repo_list(rows, cfg, limit=None) -> (selected, skipped, warnings)` where `selected` is `[{"slug", "name", "repo_url", "repo_source_field", "db_metadata"}]` and `skipped` is `[{"slug", "reason"}]`.
  - `fetch_rows(cfg, rows_json=None) -> (rows, warnings)` — raises `DbError` when no transport is configured.
  - `attach_metadata(evidence_dir, selected) -> None` — merges each project's `name` and `repo_source_field` into its evidence bundle's `db_metadata` dict (Task 4's `collect()` always writes `db_metadata: {}`; nothing else populates it, so this is the only place the registry's metadata ever reaches an evidence bundle). Consumed by Task 10's driver in `--db` mode, after `collect_signals.py` has already written the evidence files. A slug in `selected` with no matching evidence file (e.g. it failed to clone) is skipped, not an error — the corpus is the source of truth for who actually got scanned.
  - CLI: `python3 db_collect.py --out PATH [--db-config PATH] [--db-rows-json PATH] [--db-limit N] [--profile NAME]`, writing `{"selected": [...], "skipped": [...], "warnings": [...]}`.

**Why `attach_metadata` exists — a gap the controller caught between tasks:** Task 4's `collect()` (already implemented) leaves `db_metadata` as an empty dict with no wiring documented for who fills it. Task 8's `merge_insights.py` (not yet implemented) reads `ev.get("db_metadata", {}).get("name")` and `ev.get("db_metadata", {}).get("repo_source_field")` — i.e. it expects `name` and `repo_source_field` NESTED inside `db_metadata` on the evidence bundle, not as separate top-level fields. `attach_metadata` is what actually produces that shape; without it, `--db` mode would silently run without ever surfacing the registry's metadata to the agents or the report, even though `db_collect.py` collected it correctly. This does not affect the other four input modes.

- [ ] **Step 1: Create the fixture**

Create `tests/fixtures/db-rows.json` — six rows exercising every path:

```json
[
  {"slug": "alpha", "name": "Alpha", "contribute_in_url": "https://github.com/acme/alpha",
   "project_url": "https://alpha.example.com", "description_markdown": "Alpha does things.",
   "lifecycle_status": "active"},
  {"slug": "beta", "name": "Beta", "contribute_in_url": null,
   "project_url": "https://github.com/acme/beta.git", "description_markdown": "Beta.",
   "lifecycle_status": "active"},
  {"slug": "gamma", "name": "Gamma", "contribute_in_url": null, "project_url": null,
   "description_markdown": "Code at https://github.com/acme/gamma), see there.",
   "lifecycle_status": "paused"},
  {"slug": "delta", "name": "Delta", "contribute_in_url": null, "project_url": "https://delta.example.com",
   "description_markdown": "No repository yet.", "lifecycle_status": "idea"},
  {"slug": "alpha-dup", "name": "Alpha Duplicate", "contribute_in_url": "https://github.com/ACME/Alpha/",
   "project_url": null, "description_markdown": "Same repo as alpha.", "lifecycle_status": "active"},
  {"slug": "epsilon", "name": "Epsilon", "contribute_in_url": "https://gitlab.com/acme/epsilon",
   "project_url": null, "description_markdown": "Not on GitHub.", "lifecycle_status": "active"}
]
```

- [ ] **Step 2: Write the failing tests**

Append to `tests/selftest.py`:

```python
def test_db_collect():
    import db_collect
    policy = _policy.load_policy()
    cfg = policy["db_source"]
    fixture = os.path.join(HERE, "fixtures", "db-rows.json")
    rows, warnings = db_collect.fetch_rows(cfg, rows_json=fixture)
    selected, skipped, warns = db_collect.build_repo_list(rows, cfg)

    by_slug = {s["slug"]: s for s in selected}
    skips = {s["slug"]: s["reason"] for s in skipped}

    check("contribute_in_url wins over project_url",
          by_slug["alpha"]["repo_source_field"] == "contribute_in_url")
    check("project_url is used when contribute_in_url is empty",
          by_slug["beta"]["repo_source_field"] == "project_url")
    check("a URL is found inside description_markdown",
          by_slug["gamma"]["repo_source_field"] == "description_markdown")
    check("trailing punctuation is stripped",
          by_slug["gamma"]["repo_url"].endswith("/acme/gamma"),
          "got %s" % by_slug["gamma"]["repo_url"])
    check("a .git suffix does not create a second project",
          "alpha-dup" not in by_slug)
    check("a duplicate row is recorded, not dropped",
          skips.get("alpha-dup", "").startswith("duplicate-of:"))
    check("a row with no GitHub URL is recorded, not dropped",
          skips.get("delta") == "no-repo-url")
    check("a non-GitHub URL is recorded as no-repo-url",
          skips.get("epsilon") == "no-repo-url")
    check("every input row is accounted for",
          len(selected) + len(skipped) == len(rows))
    check("db_metadata is carried through",
          by_slug["alpha"]["db_metadata"].get("lifecycle_status") == "active")


def test_db_limit_and_pagination_warn():
    import db_collect
    policy = _policy.load_policy()
    cfg = dict(policy["db_source"])
    fixture = os.path.join(HERE, "fixtures", "db-rows.json")
    rows, _ = db_collect.fetch_rows(cfg, rows_json=fixture)
    selected, skipped, warns = db_collect.build_repo_list(rows, cfg, limit=1)
    check("--db-limit caps the selection", len(selected) == 1)
    check("--db-limit truncation warns", any("limit" in w.lower() for w in warns))

    cfg_page = dict(cfg)
    cfg_page["page_size"] = len(rows)
    _, _, page_warns = db_collect.build_repo_list(rows, cfg_page)
    check("a page-boundary result warns",
          any("page" in w.lower() for w in page_warns))


def test_db_requires_no_credentials_in_argv():
    import db_collect
    policy = _policy.load_policy()
    cfg = dict(policy["db_source"])
    try:
        db_collect.fetch_rows(cfg, rows_json=None, env={})
        check("no transport configured raises DbError", False, "no exception raised")
    except db_collect.DbError as e:
        msg = str(e)
        check("no transport configured raises DbError", True)
        check("the error names SUPABASE_URL", "SUPABASE_URL" in msg)
        check("the error names DATABASE_URL", "DATABASE_URL" in msg)


def test_db_config_rejects_missing_column():
    import db_collect
    cfg = {"table": "projects", "slug_column": "nope", "name_column": "name",
           "repo_url_columns": ["project_url"], "metadata_columns": [],
           "filter": None, "page_size": 1000}
    rows = [{"slug": "a", "name": "A", "project_url": "https://github.com/x/y"}]
    try:
        db_collect.build_repo_list(rows, cfg)
        check("a config naming a missing column fails loudly", False, "no exception")
    except db_collect.DbError:
        check("a config naming a missing column fails loudly", True)


def test_db_attach_metadata():
    import tempfile
    import json as _json
    import db_collect
    with tempfile.TemporaryDirectory() as base:
        ev = os.path.join(base, "evidence")
        os.makedirs(ev)
        with open(os.path.join(ev, "alpha.json"), "w", encoding="utf-8") as f:
            _json.dump({"project_slug": "alpha", "db_metadata": {}}, f)
        selected = [{"slug": "alpha", "name": "Alpha", "repo_url": "https://github.com/acme/alpha",
                    "repo_source_field": "contribute_in_url",
                    "db_metadata": {"lifecycle_status": "active"}}]
        db_collect.attach_metadata(ev, selected)
        with open(os.path.join(ev, "alpha.json"), "r", encoding="utf-8") as f:
            bundle = _json.load(f)
        check("attach_metadata merges name into db_metadata",
              bundle["db_metadata"]["name"] == "Alpha")
        check("attach_metadata merges repo_source_field into db_metadata",
              bundle["db_metadata"]["repo_source_field"] == "contribute_in_url")
        check("attach_metadata preserves the original metadata columns",
              bundle["db_metadata"]["lifecycle_status"] == "active")


def test_db_attach_metadata_skips_missing_evidence():
    import tempfile
    import db_collect
    with tempfile.TemporaryDirectory() as base:
        ev = os.path.join(base, "evidence")
        os.makedirs(ev)
        selected = [{"slug": "ghost", "name": "Ghost", "repo_url": "https://github.com/acme/ghost",
                    "repo_source_field": "project_url", "db_metadata": {}}]
        db_collect.attach_metadata(ev, selected)  # must not raise
        check("attach_metadata does not create a file for a project with no evidence",
              not os.path.isfile(os.path.join(ev, "ghost.json")))
```

Register in `main()`:

```python
    print("\nDB collector (optional mode, no live database)")
    test_db_collect()
    test_db_limit_and_pagination_warn()
    test_db_requires_no_credentials_in_argv()
    test_db_config_rejects_missing_column()
    test_db_attach_metadata()
    test_db_attach_metadata_skips_missing_evidence()
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'db_collect'`.

- [ ] **Step 4: Write the implementation**

Create `scripts/db_collect.py`:

```python
#!/usr/bin/env python3
"""
db_collect.py - OPTIONAL input mode: read a project registry from Supabase or
Postgres, extract one GitHub URL per row, and carry the rest as metadata.

WHAT THIS READS
    A registry table that NAMES projects and points at their repositories. It
    has nothing to do with whatever database a scanned project uses internally
    - that is a security question for the stage 3 agent, not an input concern.

READ-ONLY, ALWAYS
    PostgREST access is GET-only. The psql path wraps every query in
    BEGIN; SET TRANSACTION READ ONLY; so the guarantee is enforced by the
    database rather than by the query text.

CREDENTIALS COME FROM THE ENVIRONMENT, NEVER A FLAG
    The report states the command that produced it. A connection string passed
    as an argument would be written into a file people share.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _policy  # noqa: E402

GH_RE = re.compile(r"https?://(?:www\.)?github\.com/[^\s)\"'<>]+", re.I)
TRAILING_JUNK = ".,);:"
HTTP_TIMEOUT = 60


class DbError(Exception):
    """Raised when the DB cannot be read. Callers exit 2."""


def normalize_repo_url(url):
    u = url.strip().rstrip(TRAILING_JUNK)
    u = u.split("#")[0].split("?")[0]
    u = u.rstrip("/")
    if u.lower().endswith(".git"):
        u = u[:-4]
    return u.lower()


def extract_repo_url(row, cfg):
    for col in cfg["repo_url_columns"]:
        value = row.get(col)
        if not value or not isinstance(value, str):
            continue
        m = GH_RE.search(value)
        if m:
            return m.group(0).rstrip(TRAILING_JUNK), col
    return None, None


def build_repo_list(rows, cfg, limit=None):
    """Return (selected, skipped, warnings). Every input row lands in one list."""
    slug_col, name_col = cfg["slug_column"], cfg["name_column"]
    if rows and slug_col not in rows[0]:
        raise DbError("db_config slug_column %r is not in the result columns: %s"
                      % (slug_col, sorted(rows[0].keys())))

    selected, skipped, warnings = [], [], []
    seen = {}
    for row in rows:
        slug = row.get(slug_col)
        if not slug:
            skipped.append({"slug": "<no-slug>", "reason": "no-slug"})
            continue
        url, source = extract_repo_url(row, cfg)
        if not url:
            skipped.append({"slug": slug, "reason": "no-repo-url"})
            continue
        norm = normalize_repo_url(url)
        if norm in seen:
            skipped.append({"slug": slug, "reason": "duplicate-of:%s" % seen[norm]})
            continue
        seen[norm] = slug
        selected.append({
            "slug": slug,
            "name": row.get(name_col) or slug,
            "repo_url": url,
            "repo_source_field": source,
            "db_metadata": {c: row.get(c) for c in cfg["metadata_columns"] if c in row},
        })

    page_size = cfg.get("page_size")
    if page_size and len(rows) % page_size == 0 and len(rows) > 0:
        warnings.append(
            "row count %d is an exact multiple of page_size %d - the result may be "
            "TRUNCATED. Rows past the cut are absent, not failed, and no scan of "
            "them can report clean." % (len(rows), page_size))
    if limit is not None and len(selected) > limit:
        warnings.append("--db-limit=%d hit; %d project(s) were not analyzed"
                        % (limit, len(selected) - limit))
        selected = selected[:limit]
    return selected, skipped, warnings


def attach_metadata(evidence_dir, selected):
    """Merge each project's name and repo_source_field into its evidence
    bundle's db_metadata, so merge_insights.py can read both from one place.
    A project with no matching evidence file (e.g. it failed to clone) is
    skipped, not an error - the corpus, not the registry, decides who
    actually got scanned.
    """
    by_slug = {row["slug"]: row for row in selected}
    for fname in sorted(os.listdir(evidence_dir)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(evidence_dir, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                bundle = json.load(f)
        except (OSError, ValueError):
            continue
        slug = bundle.get("project_slug") or os.path.splitext(fname)[0]
        row = by_slug.get(slug)
        if not row:
            continue
        merged = dict(row.get("db_metadata") or {})
        merged["name"] = row.get("name")
        merged["repo_source_field"] = row.get("repo_source_field")
        bundle["db_metadata"] = merged
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)


def _fetch_postgrest(cfg, env):
    base = env["SUPABASE_URL"].rstrip("/")
    key = env.get("SUPABASE_SERVICE_ROLE_KEY") or env["SUPABASE_ANON_KEY"]
    columns = sorted(set([cfg["slug_column"], cfg["name_column"]]
                         + list(cfg["repo_url_columns"])
                         + list(cfg["metadata_columns"])))
    page = int(cfg.get("page_size") or 1000)
    rows, offset, warnings = [], 0, []
    while True:
        q = {"select": ",".join(columns), "limit": str(page), "offset": str(offset)}
        if cfg.get("filter"):
            q.update(urllib.parse.parse_qsl(cfg["filter"]))
        url = "%s/rest/v1/%s?%s" % (base, cfg["table"], urllib.parse.urlencode(q))
        req = urllib.request.Request(url, method="GET")
        req.add_header("apikey", key)
        req.add_header("Authorization", "Bearer %s" % key)
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                batch = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise DbError("PostgREST returned HTTP %s for table %r"
                          % (e.code, cfg["table"]))
        except (urllib.error.URLError, ValueError) as e:
            raise DbError("PostgREST read failed: %s" % e)
        rows.extend(batch)
        if len(batch) < page:
            break
        offset += page
    return rows, warnings


def _fetch_psql(cfg, env):
    columns = sorted(set([cfg["slug_column"], cfg["name_column"]]
                         + list(cfg["repo_url_columns"])
                         + list(cfg["metadata_columns"])))
    ident = lambda c: '"%s"' % c.replace('"', '""')
    where = " WHERE %s" % cfg["filter"] if cfg.get("filter") else ""
    sql = ("BEGIN; SET TRANSACTION READ ONLY; "
           "SELECT coalesce(json_agg(t), '[]'::json) FROM "
           "(SELECT %s FROM %s%s) t; COMMIT;"
           % (", ".join(ident(c) for c in columns), ident(cfg["table"]), where))
    try:
        proc = subprocess.run(["psql", env["DATABASE_URL"], "-At", "-c", sql],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=300)
    except (OSError, subprocess.SubprocessError) as e:
        raise DbError("psql failed: %s" % e)
    if proc.returncode != 0:
        raise DbError("psql exited %d: %s" % (
            proc.returncode, proc.stderr.decode("utf-8", "replace").strip()[:300]))
    payload = [l for l in proc.stdout.decode("utf-8", "replace").splitlines() if l.strip()]
    try:
        return json.loads(payload[-1]), []
    except (IndexError, ValueError) as e:
        raise DbError("could not parse psql output as JSON: %s" % e)


def fetch_rows(cfg, rows_json=None, env=None):
    """Rows from a saved payload, PostgREST, or psql - in that order."""
    if rows_json:
        try:
            with open(rows_json, "r", encoding="utf-8") as f:
                return json.load(f), ["rows read from %s, not from a live database"
                                      % rows_json]
        except (OSError, ValueError) as e:
            raise DbError("could not read --db-rows-json: %s" % e)

    env = os.environ if env is None else env
    if env.get("SUPABASE_URL") and (env.get("SUPABASE_SERVICE_ROLE_KEY")
                                    or env.get("SUPABASE_ANON_KEY")):
        return _fetch_postgrest(cfg, env)
    if env.get("DATABASE_URL"):
        try:
            subprocess.run(["psql", "--version"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30)
        except (OSError, subprocess.SubprocessError):
            raise DbError("DATABASE_URL is set but psql is not on PATH")
        return _fetch_psql(cfg, env)
    raise DbError(
        "no database transport configured. Set SUPABASE_URL plus "
        "SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_ANON_KEY), or set DATABASE_URL "
        "with psql on PATH. Credentials are read from the environment only, "
        "never from a command-line flag. --db is optional: use --root, "
        "--projects, --corpus, or --org instead.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read a project registry, read-only.")
    ap.add_argument("--out", required=True)
    ap.add_argument("--db-config", default=None)
    ap.add_argument("--db-rows-json", default=None)
    ap.add_argument("--db-limit", type=int, default=None)
    ap.add_argument("--profile", default="generic")
    args = ap.parse_args(argv)

    try:
        policy = _policy.load_policy(args.profile)
        cfg = dict(policy["db_source"])
        if args.db_config:
            with open(args.db_config, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        rows, warnings = fetch_rows(cfg, rows_json=args.db_rows_json)
        selected, skipped, warns = build_repo_list(rows, cfg, limit=args.db_limit)
    except (_policy.PolicyError, DbError, OSError, ValueError) as e:
        sys.stderr.write("%s\n" % e)
        return 2

    payload = {"selected": selected, "skipped": skipped,
               "warnings": list(warnings) + list(warns),
               "row_count": len(rows)}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    sys.stderr.write("db: %d row(s) -> %d project(s), %d skipped\n"
                     % (len(rows), len(selected), len(skipped)))
    for w in payload["warnings"]:
        sys.stderr.write("WARNING: %s\n" % w)
    return 0 if selected else 2


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: all assertions PASS, exit `0`.

- [ ] **Step 6: Verify the CLI with the fixture, and that it never needs a database**

```bash
cd skills/project-weakness-analysis
python3 scripts/db_collect.py --db-rows-json tests/fixtures/db-rows.json --out /tmp/db.json
cat /tmp/db.json
env -u SUPABASE_URL -u DATABASE_URL python3 scripts/db_collect.py --out /tmp/x.json; echo "exit=$?"
```
Expected: first writes 3 selected / 3 skipped and exits `0`; second prints the "no database transport configured" message naming both variables and exits `2`.

- [ ] **Step 7: Commit**

```bash
git add skills/project-weakness-analysis/scripts/db_collect.py skills/project-weakness-analysis/tests/fixtures/db-rows.json skills/project-weakness-analysis/tests/selftest.py
git commit -m "feat(project-weakness-analysis): optional read-only project registry input"
```

---

### Task 7: `_schemas.py` + `build_tasks.py` — the agent contract

**Files:**
- Create: `skills/project-weakness-analysis/scripts/_schemas.py`
- Create: `skills/project-weakness-analysis/scripts/build_tasks.py`
- Modify: `skills/project-weakness-analysis/tests/selftest.py`

**Why a hand-rolled validator:** `jsonschema` is a third-party package and this skill is stdlib-only. The validator below supports exactly the keywords the two schemas use — `type`, `required`, `properties`, `additionalProperties: false`, `enum`, `minimum`, `maximum`, `items`. Do not add keywords the schemas do not use.

**Interfaces:**
- Consumes: `_policy.load_policy()` → `dispatch`, `agent_instructions`, `open_statuses`.
- Produces:
  - `_schemas.ANALYZE_SCHEMA`, `_schemas.SECURITY_SCHEMA` — dicts.
  - `_schemas.validate(obj, schema, path="$") -> list[str]` — human-readable error strings; `[]` means valid.
  - `build_tasks.build(evidence_dir, policy, out_dir, prior_audit=None) -> dict` — the manifest `{"schema_version": 1, "generated_at": str, "max_parallel": int, "tasks": [...]}`.
  - CLI: `python3 build_tasks.py --evidence DIR --out PATH [--prior-audit PATH] [--profile NAME]`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/selftest.py`:

```python
def test_validator():
    import _schemas
    ok = {"type": "object", "additionalProperties": False,
          "required": ["a"],
          "properties": {"a": {"type": "integer", "minimum": 1, "maximum": 5},
                         "b": {"type": "string", "enum": ["x", "y"]},
                         "c": {"type": "array", "items": {"type": "string"}}}}
    check("valid object passes", _schemas.validate({"a": 3}, ok) == [])
    check("missing required field is caught", _schemas.validate({}, ok) != [])
    check("wrong type is caught", _schemas.validate({"a": "3"}, ok) != [])
    check("out-of-range integer is caught", _schemas.validate({"a": 9}, ok) != [])
    check("bad enum value is caught", _schemas.validate({"a": 1, "b": "z"}, ok) != [])
    check("unknown property is caught",
          _schemas.validate({"a": 1, "zzz": 1}, ok) != [])
    check("bad array item type is caught",
          _schemas.validate({"a": 1, "c": [1]}, ok) != [])
    check("a boolean is not an integer",
          _schemas.validate({"a": True}, ok) != [])


def test_schemas_shape():
    import _schemas
    a = _schemas.ANALYZE_SCHEMA["properties"]
    for f in ("maturity", "production_readiness", "code_organization", "maintainability"):
        check("analyze schema has %s.score 1-5" % f,
              a[f]["properties"]["score"]["minimum"] == 1
              and a[f]["properties"]["score"]["maximum"] == 5)
    check("analyze schema has no promo fields",
          not set(("viability", "domain_tags", "merge_potential", "diffusion",
                   "one_line_pitch", "overall_recommendation")) & set(a))
    s = _schemas.SECURITY_SCHEMA["properties"]
    check("security schema enumerates finding status",
          set(s["findings"]["items"]["properties"]["status"]["enum"])
          == set(("open", "partial", "resolved", "new")))
    check("security findings require file and line",
          set(("file", "line")) <= set(s["findings"]["items"]["required"]))
    check("security schema has a risk enum including none",
          "none" in s["risk"]["enum"])


def test_build_tasks():
    import tempfile
    import json as _json
    import build_tasks
    policy = _policy.load_policy()
    with tempfile.TemporaryDirectory() as base:
        ev = os.path.join(base, "evidence")
        os.makedirs(ev)
        for slug in ("alpha", "beta"):
            with open(os.path.join(ev, slug + ".json"), "w", encoding="utf-8") as f:
                _json.dump({"project_slug": slug, "path": "/tmp/" + slug,
                            "remote_url": "https://github.com/acme/" + slug}, f)
        out = os.path.join(base, "agents")
        manifest = build_tasks.build(ev, policy, out)
        ids = sorted(t["id"] for t in manifest["tasks"])
        check("one analyze and one security task per project",
              ids == ["analyze:alpha", "analyze:beta", "security:alpha", "security:beta"],
              "got %s" % ids)
        by_id = {t["id"]: t for t in manifest["tasks"]}
        check("analyze uses the read-only Explore agent",
              by_id["analyze:alpha"]["agent_type"] == "Explore")
        check("security uses general-purpose",
              by_id["security:alpha"]["agent_type"] == "general-purpose")
        check("both stages use sonnet",
              by_id["analyze:alpha"]["model"] == "sonnet"
              and by_id["security:alpha"]["model"] == "sonnet")
        check("every task names an output path",
              all(t["output_path"].endswith(".json") for t in manifest["tasks"]))
        check("every task carries its schema",
              all("properties" in t["schema"] for t in manifest["tasks"]))
        check("every prompt inlines the evidence path",
              all("evidence" in t["prompt"] for t in manifest["tasks"]))
        check("manifest states max_parallel", manifest["max_parallel"] >= 1)


def test_build_tasks_inlines_prior_findings():
    import tempfile
    import json as _json
    import build_tasks
    policy = _policy.load_policy()
    with tempfile.TemporaryDirectory() as base:
        ev = os.path.join(base, "evidence")
        os.makedirs(ev)
        with open(os.path.join(ev, "alpha.json"), "w", encoding="utf-8") as f:
            _json.dump({"project_slug": "alpha", "path": "/tmp/alpha"}, f)
        prior = {"alpha": {"risk": "high", "auditedAt": "2026-01-01",
                           "findings": [{"severity": "high", "title": "No auth on POST /items",
                                         "status": "open"}]}}
        m = build_tasks.build(ev, policy, os.path.join(base, "agents"), prior_audit=prior)
        sec = [t for t in m["tasks"] if t["id"] == "security:alpha"][0]
        check("prior findings are inlined into the security prompt",
              "No auth on POST /items" in sec["prompt"])
        check("the prompt forbids dropping a prior finding",
              "resolved" in sec["prompt"] and "do not drop" in sec["prompt"].lower())
        ana = [t for t in m["tasks"] if t["id"] == "analyze:alpha"][0]
        check("the analyze prompt never sees security findings",
              "No auth on POST /items" not in ana["prompt"])


def test_build_tasks_applies_profile_instructions():
    import tempfile
    import json as _json
    import build_tasks
    policy = _policy.load_policy("genericsuite")
    with tempfile.TemporaryDirectory() as base:
        ev = os.path.join(base, "evidence")
        os.makedirs(ev)
        with open(os.path.join(ev, "alpha.json"), "w", encoding="utf-8") as f:
            _json.dump({"project_slug": "alpha", "path": "/tmp/alpha"}, f)
        m = build_tasks.build(ev, policy, os.path.join(base, "agents"))
        sec = [t for t in m["tasks"] if t["id"] == "security:alpha"][0]
        check("profile instructions reach the security prompt", "scrypt" in sec["prompt"])
```

Register in `main()`:

```python
    print("\nSchemas and task manifest")
    test_validator()
    test_schemas_shape()
    test_build_tasks()
    test_build_tasks_inlines_prior_findings()
    test_build_tasks_applies_profile_instructions()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: FAIL with `ModuleNotFoundError: No module named '_schemas'`.

- [ ] **Step 3: Write `_schemas.py`**

```python
#!/usr/bin/env python3
"""
_schemas.py - The two agent output schemas, and a minimal validator.

WHY A HAND-ROLLED VALIDATOR
    jsonschema is third-party and this skill is stdlib-only. This supports
    exactly the keywords the schemas below use. Do not extend it speculatively.

WHY VALIDATION IS NOT OPTIONAL
    An agent's JSON is untrusted input. Merging an unvalidated object means a
    malformed score silently becomes a verdict. Rejected output is treated as
    ABSENT, which produces readiness "unknown" - a blocking state.
"""
SCORE = {"type": "integer", "minimum": 1, "maximum": 5}


def _scored(extra_props, extra_required):
    props = {"score": SCORE, "reasoning": {"type": "string"}}
    props.update(extra_props)
    return {"type": "object", "additionalProperties": False,
            "required": ["score", "reasoning"] + extra_required,
            "properties": props}


ANALYZE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["summary", "project_type", "stack", "architecture",
                 "code_organization", "production_readiness", "maturity",
                 "maintainability", "weaknesses", "red_flags"],
    "properties": {
        "summary": {"type": "string"},
        "project_type": {"type": "string"},
        "stack": {
            "type": "object", "additionalProperties": False,
            "required": ["frontend", "backend", "database", "infra_deploy", "languages"],
            "properties": {
                "frontend": {"type": "array", "items": {"type": "string"}},
                "backend": {"type": "array", "items": {"type": "string"}},
                "database": {"type": "array", "items": {"type": "string"}},
                "infra_deploy": {"type": "array", "items": {"type": "string"}},
                "languages": {"type": "array", "items": {"type": "string"}},
            }},
        "architecture": {
            "type": "object", "additionalProperties": False,
            "required": ["pattern", "uses_orm", "orm_or_db_layer", "api_design",
                         "separation_of_concerns"],
            "properties": {
                "pattern": {"type": "string"},
                "uses_orm": {"type": "boolean"},
                "orm_or_db_layer": {"type": "string"},
                "api_design": {"type": "string"},
                "separation_of_concerns": {"type": "string"},
            }},
        "code_organization": _scored(
            {"directory_structure": {"type": "string"},
             "naming_quality": {"type": "string"},
             "documentation_quality": {"type": "string"}},
            ["directory_structure", "naming_quality", "documentation_quality"]),
        "production_readiness": _scored(
            {"has_auth": {"type": "boolean"},
             "has_error_handling": {"type": "boolean"},
             "has_logging": {"type": "boolean"},
             "has_env_config": {"type": "boolean"},
             "has_deploy_config": {"type": "boolean"},
             "secrets_handling": {"type": "string"}},
            ["has_auth", "has_error_handling", "has_logging", "has_env_config",
             "has_deploy_config", "secrets_handling"]),
        "maturity": _scored(
            {"has_readme": {"type": "boolean"},
             "has_tests": {"type": "boolean"},
             "has_ci": {"type": "boolean"},
             "is_real_or_boilerplate": {"type": "string",
                                        "enum": ["real", "partial", "boilerplate"]}},
            ["has_readme", "has_tests", "has_ci", "is_real_or_boilerplate"]),
        "maintainability": _scored({}, []),
        "weaknesses": {"type": "array", "items": {"type": "string"}},
        "red_flags": {"type": "array", "items": {"type": "string"}},
    },
}

SECURITY_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["risk", "findings", "issueState", "reauditNote"],
    "properties": {
        "risk": {"type": "string",
                 "enum": ["critical", "high", "medium", "low", "none"]},
        "findings": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["severity", "title", "status", "file", "line",
                             "evidence", "remediation"],
                "properties": {
                    "severity": {"type": "string",
                                 "enum": ["critical", "high", "medium", "low"]},
                    "title": {"type": "string"},
                    "status": {"type": "string",
                               "enum": ["open", "partial", "resolved", "new"]},
                    "file": {"type": "string"},
                    "line": {"type": "integer", "minimum": 0},
                    "evidence": {"type": "string"},
                    "remediation": {"type": "string"},
                }}},
        "issueState": {"type": "string", "enum": ["open", "closed", "none"]},
        "issueUrl": {"type": ["string", "null"]},
        "reauditNote": {"type": "string"},
    },
}

_TYPES = {"object": dict, "array": list, "string": str, "integer": int,
          "number": (int, float), "boolean": bool, "null": type(None)}


def _type_ok(value, expected):
    names = expected if isinstance(expected, list) else [expected]
    for name in names:
        py = _TYPES.get(name)
        if py is None:
            continue
        # bool is a subclass of int in Python; an integer field must reject True.
        if name in ("integer", "number") and isinstance(value, bool):
            continue
        if isinstance(value, py):
            return True
    return False


def validate(obj, schema, path="$"):
    """Return a list of human-readable errors. Empty list means valid."""
    errors = []
    expected = schema.get("type")
    if expected and not _type_ok(obj, expected):
        return ["%s: expected %s, got %s" % (path, expected, type(obj).__name__)]

    if "enum" in schema and obj not in schema["enum"]:
        errors.append("%s: %r is not one of %s" % (path, obj, schema["enum"]))
    if isinstance(obj, int) and not isinstance(obj, bool):
        if "minimum" in schema and obj < schema["minimum"]:
            errors.append("%s: %d < minimum %d" % (path, obj, schema["minimum"]))
        if "maximum" in schema and obj > schema["maximum"]:
            errors.append("%s: %d > maximum %d" % (path, obj, schema["maximum"]))

    if isinstance(obj, dict):
        for req in schema.get("required", []):
            if req not in obj:
                errors.append("%s: missing required property %r" % (path, req))
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in obj:
                if key not in props:
                    errors.append("%s: unknown property %r" % (path, key))
        for key, sub in props.items():
            if key in obj:
                errors.extend(validate(obj[key], sub, "%s.%s" % (path, key)))

    if isinstance(obj, list) and "items" in schema:
        for i, item in enumerate(obj):
            errors.extend(validate(item, schema["items"], "%s[%d]" % (path, i)))
    return errors
```

- [ ] **Step 4: Write `build_tasks.py`**

```python
#!/usr/bin/env python3
"""
build_tasks.py - Emit the manifest Claude dispatches as subagents.

WHY A MANIFEST
    A skill's own scripts cannot spawn subagents. Everything the dispatcher
    needs - prompt, schema, model, agent type, output path - is written here,
    so the dispatching model makes no decisions of its own and two runs of the
    same scan dispatch the same work.
"""
import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _policy    # noqa: E402
import _schemas   # noqa: E402

RUBRIC = ("Scoring rubric: 1 = empty skeleton, 2 = early prototype, "
          "3 = working MVP, 4 = polished/usable, 5 = production-grade.")


def _analyze_prompt(slug, ev_path, project_path, policy):
    extra = "\n".join("- " + i for i in policy.get("agent_instructions", {}).get("analyze", []))
    return """You are performing a production-readiness review of ONE project. Be rigorous, skeptical, and evidence-based: score what the CODE actually contains, not what the README claims. AI-generated boilerplate or empty scaffolding with no real logic scores low - say so plainly.

READ FIRST - the deterministic evidence bundle: {ev}
It already records lines of code, manifests, committed lockfiles, tests, CI, Dockerfile, tracked .env files, secret candidates, and findings from the container-image and dependency scanners. Do not re-derive those facts; start from them.

Then inspect the actual source at: {path}
Look at manifests and lockfiles, Dockerfile and CI config, the database access layer (ORM vs raw SQL vs BaaS client), authentication, error handling, logging, environment and secret management, tests, and directory layout.

{rubric}

Score maturity, production_readiness, code_organization, and maintainability on 1-5. Fill EVERY field of the schema. Keep every reasoning field to 1-3 sentences. List concrete weaknesses in weaknesses[] and anything alarming in red_flags[].
{extra}

Write your JSON result to the output path you were given. Return only a one-line confirmation - not the JSON itself.""".format(
        ev=ev_path, path=project_path, rubric=RUBRIC, extra=("\n" + extra if extra else ""))


def _security_prompt(slug, ev_path, project_path, repo, policy, prior):
    extra = "\n".join("- " + i for i in policy.get("agent_instructions", {}).get("security", []))
    if prior and prior.get("findings"):
        listed = "\n".join("  %d. [%s] %s" % (i + 1, f.get("severity"), f.get("title"))
                           for i, f in enumerate(prior["findings"]))
        prior_block = """This project was audited on {when} with overall risk "{risk}". Previously reported findings:
{listed}

YOUR PRIMARY JOB: for EACH previous finding, open the current code and decide whether it is now:
  - "resolved" (properly fixed),
  - "partial" (mitigated but still exploitable - explain how), or
  - "open" (unchanged, still fully exploitable).
Carry EVERY previous finding forward in your findings array with its verdict in `status`. Do not drop a previous finding - if it is fixed, still list it with status "resolved". A finding that disappears between runs reads as "fixed" to whoever reads the report.""".format(
            when=prior.get("auditedAt", "an earlier run"),
            risk=prior.get("risk", "unknown"), listed=listed)
    else:
        prior_block = ("This project has NOT been audited before. Do a thorough "
                       "first-time audit and mark every finding status \"new\".")

    issue_block = (
        "Check the tracking issue state with: gh issue list --repo %s --state all "
        "--limit 20 --json number,title,state,url\nSet issueState to \"open\"/\"closed\" "
        "for a security tracking issue, or \"none\" if there is none. If gh is "
        "unavailable, set \"none\" and say so in reauditNote - never abort." % repo
        if repo else
        "This project has no GitHub remote recorded. Set issueState to \"none\" and issueUrl to null.")

    return """You are a rigorous application-security auditor reviewing ONE project that may be deployed to production. Be skeptical and evidence-based: only report an issue you can point to in the actual code.

READ FIRST - the deterministic evidence bundle: {ev}
It records CONFIRMED secret findings (credential files committed to git) and REVIEW candidates (regex matches that a human must judge), plus findings from the container-image and dependency scanners. Treat CONFIRMED entries as established fact and judge their real impact; verify REVIEW entries before reporting them.

Project source: {path}

{prior_block}

ALSO scan fresh for NEW high-impact issues regardless of history:
  - Committed secrets: service-role keys, API keys, database URLs, JWT signing secrets, .env files in git
  - Missing authentication or authorization on state-changing endpoints (POST/PATCH/PUT/DELETE)
  - Mass assignment: a raw request body passed into a database insert or update with no field whitelist
  - Personal-data exposure through public/anon access or over-broad API responses
  - Row-level security disabled, anon keys with write access, over-broad CORS
  - Injection (SQL, command, template), SSRF, open proxies, unrestricted file upload, path traversal
  - Insecure defaults: debug mode on, verbose errors returned to clients, permissive cookies, missing TLS enforcement, weak password hashing
  - Dependency and image risk escalated from the scanner findings in the evidence bundle, judged in context
{extra}

EVERY finding must cite a real `file` and `line` in this project, with `evidence` (what makes it exploitable) and `remediation` (the concrete fix). A finding you cannot point at in the code is not a finding - drop it.

Set `risk` to the CURRENT overall risk: the severity of the worst STILL-OPEN finding (status open, partial, or new). Use "none" if everything is resolved or nothing was found.

{issue_block}

In reauditNote (1-3 sentences) summarize what changed since the last audit: what was fixed, what remains.

Write your JSON result to the output path you were given. Return only a one-line confirmation - not the JSON itself.""".format(
        ev=ev_path, path=project_path, prior_block=prior_block,
        extra=("\n" + extra if extra else ""), issue_block=issue_block)


def build(evidence_dir, policy, out_dir, prior_audit=None):
    d = policy["dispatch"]
    prior_audit = prior_audit or {}
    tasks = []
    for fname in sorted(os.listdir(evidence_dir)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(evidence_dir, fname), "r", encoding="utf-8") as f:
            ev = json.load(f)
        slug = ev.get("project_slug") or os.path.splitext(fname)[0]
        ev_path = os.path.abspath(os.path.join(evidence_dir, fname))
        project_path = ev.get("path", "")
        repo = ""
        if ev.get("remote_url", "") and "github.com/" in ev["remote_url"]:
            repo = ev["remote_url"].split("github.com/", 1)[1].strip("/")

        tasks.append({
            "id": "analyze:%s" % slug, "stage": "analyze", "project_slug": slug,
            "model": d["analyze_model"], "agent_type": d["analyze_agent_type"],
            "output_path": os.path.join(out_dir, "out", "%s.analyze.json" % slug),
            "schema": _schemas.ANALYZE_SCHEMA,
            "prompt": _analyze_prompt(slug, ev_path, project_path, policy)})
        tasks.append({
            "id": "security:%s" % slug, "stage": "security", "project_slug": slug,
            "model": d["security_model"], "agent_type": d["security_agent_type"],
            "output_path": os.path.join(out_dir, "out", "%s.security.json" % slug),
            "schema": _schemas.SECURITY_SCHEMA,
            "prompt": _security_prompt(slug, ev_path, project_path, repo, policy,
                                       prior_audit.get(slug))})

    return {"schema_version": 1,
            "generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "max_parallel": d["max_parallel"],
            "profile": policy.get("profile_name", "generic"),
            "tasks": tasks}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Emit the agent task manifest.")
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--out", required=True, help="path to tasks.json")
    ap.add_argument("--prior-audit", default=None)
    ap.add_argument("--profile", default="generic")
    args = ap.parse_args(argv)

    try:
        policy = _policy.load_policy(args.profile)
    except _policy.PolicyError as e:
        sys.stderr.write("%s\n" % e)
        return 2
    prior = {}
    if args.prior_audit and os.path.isfile(args.prior_audit):
        try:
            with open(args.prior_audit, "r", encoding="utf-8") as f:
                prior = json.load(f)
        except (OSError, ValueError) as e:
            sys.stderr.write("WARNING: prior audit unreadable, treating every "
                             "project as a first audit: %s\n" % e)

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(os.path.join(out_dir, "out"), exist_ok=True)
    manifest = build(args.evidence, policy, out_dir, prior_audit=prior)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    sys.stderr.write("tasks: %d for %d project(s)\n"
                     % (len(manifest["tasks"]), len(manifest["tasks"]) // 2))
    return 0 if manifest["tasks"] else 2


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: all assertions PASS, exit `0`.

- [ ] **Step 6: Commit**

```bash
git add skills/project-weakness-analysis/scripts/_schemas.py skills/project-weakness-analysis/scripts/build_tasks.py skills/project-weakness-analysis/tests/selftest.py
git commit -m "feat(project-weakness-analysis): agent schemas, validator, and task manifest"
```

---

### Task 8: `merge_insights.py` — validation, verdicts, and the re-audit reconciliation

**Files:**
- Create: `skills/project-weakness-analysis/scripts/merge_insights.py`
- Modify: `skills/project-weakness-analysis/tests/selftest.py`

**This is the highest-stakes file in the skill.** Three rules it must never break:

1. **Missing or invalid agent output produces `unknown`, never a default score.** `unknown` blocks. An unscanned project is not a safe one.
2. **No prior finding may vanish.** If the agent's response omits one, `merge_insights.py` re-adds it with status `open` and records that the agent dropped it. A finding that disappears reads as "fixed".
3. **`security_risk` counts only still-open findings** (`open`, `partial`, `new`). Resolved findings never contribute.

**Interfaces:**
- Consumes: `_policy`, `_schemas.validate`.
- Produces:
  - `worst_open_severity(findings, policy) -> str`
  - `derive_readiness(analysis, security_risk, policy) -> (tier, reason)`
  - `reconcile_findings(prior_findings, agent_findings) -> (findings, dropped_titles)`
  - `load_agent_output(path, schema, rejected_dir) -> (obj|None, error|None)`
  - `merge(evidence_dir, agents_out_dir, policy, prior_audit=None) -> dict` with keys `projects` (list), `audit` (dict by slug), `blind_spots` (list of str).
  - CLI: `python3 merge_insights.py --evidence DIR --agents DIR --out DIR [--prior-audit PATH] [--profile NAME]`, writing `insights.json`, `projects/<slug>.json`, `security-audit.json`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/selftest.py`:

```python
def _valid_analysis(pr=4, mat=4, org=4, boiler="real"):
    return {"summary": "s", "project_type": "web app",
            "stack": {"frontend": [], "backend": [], "database": [],
                      "infra_deploy": [], "languages": ["Python"]},
            "architecture": {"pattern": "mvc", "uses_orm": True,
                             "orm_or_db_layer": "sqlalchemy", "api_design": "rest",
                             "separation_of_concerns": "good"},
            "code_organization": {"score": org, "reasoning": "r",
                                  "directory_structure": "d", "naming_quality": "n",
                                  "documentation_quality": "q"},
            "production_readiness": {"score": pr, "reasoning": "r", "has_auth": True,
                                     "has_error_handling": True, "has_logging": True,
                                     "has_env_config": True, "has_deploy_config": True,
                                     "secrets_handling": "env"},
            "maturity": {"score": mat, "reasoning": "r", "has_readme": True,
                         "has_tests": True, "has_ci": True,
                         "is_real_or_boilerplate": boiler},
            "maintainability": {"score": 4, "reasoning": "r"},
            "weaknesses": [], "red_flags": []}


def _valid_security(risk="none", findings=None):
    return {"risk": risk, "findings": findings or [], "issueState": "none",
            "issueUrl": None, "reauditNote": "n"}


def _finding(sev, title, status):
    return {"severity": sev, "title": title, "status": status, "file": "a.py",
            "line": 1, "evidence": "e", "remediation": "r"}


def _merge_fixture(base, analyses, securities):
    import json as _json
    ev = os.path.join(base, "evidence")
    ag = os.path.join(base, "agents", "out")
    os.makedirs(ev)
    os.makedirs(ag)
    for slug in set(list(analyses) + list(securities)):
        with open(os.path.join(ev, slug + ".json"), "w", encoding="utf-8") as f:
            _json.dump({"project_slug": slug, "path": "/tmp/" + slug,
                        "size": {"code_loc": 100, "primary_language": "Python"},
                        "siblings": {}}, f)
    for slug, obj in analyses.items():
        if obj is None:
            continue
        with open(os.path.join(ag, slug + ".analyze.json"), "w", encoding="utf-8") as f:
            _json.dump(obj, f)
    for slug, obj in securities.items():
        if obj is None:
            continue
        with open(os.path.join(ag, slug + ".security.json"), "w", encoding="utf-8") as f:
            _json.dump(obj, f)
    return ev, os.path.join(base, "agents")


def test_verdict_derivation():
    import tempfile
    import merge_insights
    policy = _policy.load_policy()
    with tempfile.TemporaryDirectory() as base:
        ev, ag = _merge_fixture(base,
            {"ready": _valid_analysis(4, 4, 4),
             "work": _valid_analysis(3, 3, 3),
             "notready": _valid_analysis(1, 1, 1, boiler="boilerplate"),
             "risky": _valid_analysis(5, 5, 5)},
            {"ready": _valid_security("none"),
             "work": _valid_security("medium", [_finding("medium", "m", "open")]),
             "notready": _valid_security("none"),
             "risky": _valid_security("critical", [_finding("critical", "c", "open")])})
        res = merge_insights.merge(ev, ag, policy)
        by = {p["project_slug"]: p for p in res["projects"]}
        check("high scores with no findings are production-ready",
              by["ready"]["readiness"] == "production-ready")
        check("middling scores are needs-work", by["work"]["readiness"] == "needs-work")
        check("skeleton scores are not-ready", by["notready"]["readiness"] == "not-ready")
        check("a critical open finding disqualifies production-ready",
              by["risky"]["readiness"] != "production-ready",
              "got %s" % by["risky"]["readiness"])
        check("security_risk reflects the worst open finding",
              by["risky"]["security_risk"] == "critical")
        check("no findings means risk none", by["ready"]["security_risk"] == "none")


def test_missing_and_invalid_agent_output():
    import tempfile
    import merge_insights
    policy = _policy.load_policy()
    with tempfile.TemporaryDirectory() as base:
        ev, ag = _merge_fixture(base,
            {"missing": None, "bad": {"summary": "only this key"},
             "good": _valid_analysis()},
            {"missing": _valid_security(), "bad": _valid_security(),
             "good": _valid_security()})
        res = merge_insights.merge(ev, ag, policy)
        by = {p["project_slug"]: p for p in res["projects"]}
        check("missing analyze output yields unknown", by["missing"]["readiness"] == "unknown")
        check("invalid analyze output yields unknown", by["bad"]["readiness"] == "unknown")
        check("a project with no agent output is still present, not dropped",
              set(("missing", "bad", "good")) <= set(by))
        check("missing output appears in blind spots",
              any("missing" in b for b in res["blind_spots"]))
        check("invalid output appears in blind spots",
              any("bad" in b for b in res["blind_spots"]))
        rejected = os.path.join(base, "agents", "rejected", "bad.analyze.json")
        check("rejected agent output is preserved for inspection",
              os.path.isfile(rejected))


def test_missing_security_output_is_unknown_risk():
    import tempfile
    import merge_insights
    policy = _policy.load_policy()
    with tempfile.TemporaryDirectory() as base:
        ev, ag = _merge_fixture(base, {"a": _valid_analysis()}, {"a": None})
        res = merge_insights.merge(ev, ag, policy)
        p = res["projects"][0]
        check("missing security output does not silently mean risk none",
              p["security_risk"] != "none", "got %s" % p["security_risk"])
        check("missing security output blocks the project", p["blocked"] is True)


def test_reaudit_carries_findings_forward():
    import tempfile
    import merge_insights
    policy = _policy.load_policy()
    prior = {"a": {"risk": "high", "auditedAt": "2026-01-01",
                   "findings": [{"severity": "high", "title": "F1", "status": "open"},
                                {"severity": "low", "title": "F2", "status": "open"}]}}
    with tempfile.TemporaryDirectory() as base:
        # The agent resolves F1 and forgets F2 entirely.
        ev, ag = _merge_fixture(base, {"a": _valid_analysis()},
            {"a": _valid_security("none", [_finding("high", "F1", "resolved")])})
        res = merge_insights.merge(ev, ag, policy, prior_audit=prior)
        titles = {f["title"]: f for f in res["audit"]["a"]["findings"]}
        check("a resolved prior finding is kept, not dropped",
              titles["F1"]["status"] == "resolved")
        check("a prior finding the agent omitted is re-added",
              "F2" in titles, "got %s" % sorted(titles))
        check("a re-added finding stays open, never assumed fixed",
              titles.get("F2", {}).get("status") == "open")
        check("dropping a prior finding is recorded as a blind spot",
              any("F2" in b for b in res["blind_spots"]))
        check("risk reflects the still-open F2, not the resolved F1",
              res["audit"]["a"]["risk"] == "low",
              "got %s" % res["audit"]["a"]["risk"])
        check("previousRisk is stamped", res["audit"]["a"]["previousRisk"] == "high")
        check("auditedAt is carried forward", res["audit"]["a"]["auditedAt"] == "2026-01-01")
        check("reauditedAt is stamped", bool(res["audit"]["a"].get("reauditedAt")))


def test_resolved_findings_do_not_raise_risk():
    import merge_insights
    policy = _policy.load_policy()
    findings = [_finding("critical", "old", "resolved"), _finding("low", "new", "open")]
    check("resolved findings never contribute to risk",
          merge_insights.worst_open_severity(findings, policy) == "low")
    check("all-resolved means risk none",
          merge_insights.worst_open_severity(
              [_finding("critical", "old", "resolved")], policy) == "none")
```

Register in `main()`:

```python
    print("\nMerge, verdicts and re-audit")
    test_verdict_derivation()
    test_missing_and_invalid_agent_output()
    test_missing_security_output_is_unknown_risk()
    test_reaudit_carries_findings_forward()
    test_resolved_findings_do_not_raise_risk()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'merge_insights'`.

- [ ] **Step 3: Write the implementation**

```python
#!/usr/bin/env python3
"""
merge_insights.py - Validate agent output, derive both verdicts, reconcile the
re-audit, and write the machine-readable records.

THREE RULES THIS FILE MUST NEVER BREAK
    1. Missing or invalid agent output produces readiness "unknown" - a
       BLOCKING state. Never a default score. An unscanned project is not a
       safe one.
    2. No prior finding may vanish. If the agent omits one, it is re-added as
       "open" and the omission is recorded. A finding that disappears between
       runs reads as "fixed" to whoever reads the report, which would make the
       re-audit feature actively harmful.
    3. security_risk counts only still-open findings (open, partial, new).
       Resolved findings never contribute.
"""
import argparse
import datetime
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _policy    # noqa: E402
import _schemas   # noqa: E402

UNKNOWN = "unknown"


def _today():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d")


def worst_open_severity(findings, policy):
    """Severity of the worst STILL-OPEN finding. Resolved never counts."""
    open_statuses = set(policy["open_statuses"])
    order = policy["severity_order"]
    worst = "none"
    for f in findings or []:
        if f.get("status") not in open_statuses:
            continue
        sev = f.get("severity")
        if sev in order and order.index(sev) < order.index(worst):
            worst = sev
    return worst


def derive_readiness(analysis, security_risk, policy):
    """Return (tier, reason). Rules come from policy, never from code."""
    if analysis is None:
        return UNKNOWN, policy["unknown_reason"]

    scores = {
        "production_readiness": analysis["production_readiness"]["score"],
        "maturity": analysis["maturity"]["score"],
        "code_organization": analysis["code_organization"]["score"],
        "maintainability": analysis["maintainability"]["score"],
    }
    boilerplate = analysis["maturity"].get("is_real_or_boilerplate") == "boilerplate"
    order = policy["severity_order"]

    for rule in policy["readiness_rules"]:
        if rule["tier"] == "not-ready":
            continue
        if boilerplate:
            continue
        if any(scores.get(k, 0) < v for k, v in rule["min_scores"].items()):
            continue
        cap = rule.get("max_open_severity")
        if cap is not None and order.index(security_risk) < order.index(cap):
            continue
        return rule["tier"], rule["reason"]

    fallback = [r for r in policy["readiness_rules"] if r["tier"] == "not-ready"][0]
    return fallback["tier"], fallback["reason"]


def reconcile_findings(prior_findings, agent_findings):
    """Every prior finding survives. Returns (findings, titles the agent dropped)."""
    agent_findings = list(agent_findings or [])
    by_title = {f.get("title"): f for f in agent_findings}
    dropped = []
    for pf in prior_findings or []:
        title = pf.get("title")
        if title in by_title:
            continue
        carried = dict(pf)
        carried["status"] = "open"
        carried.setdefault("file", "")
        carried.setdefault("line", 0)
        carried.setdefault("evidence", "")
        carried.setdefault("remediation", "")
        carried["carried_forward"] = True
        agent_findings.append(carried)
        dropped.append(title)
    return agent_findings, dropped


def load_agent_output(path, schema, rejected_dir):
    """Return (obj, error). A schema failure is treated exactly like absence."""
    if not os.path.isfile(path):
        return None, "no output file at %s" % path
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except (OSError, ValueError) as e:
        obj, err = None, "unreadable JSON: %s" % e
    else:
        errs = _schemas.validate(obj, schema)
        if not errs:
            return obj, None
        obj, err = None, "failed schema validation: %s" % "; ".join(errs[:4])

    os.makedirs(rejected_dir, exist_ok=True)
    try:
        shutil.copy2(path, os.path.join(rejected_dir, os.path.basename(path)))
    except OSError:
        pass
    return None, err


def merge(evidence_dir, agents_dir, policy, prior_audit=None):
    prior_audit = prior_audit or {}
    out_dir = os.path.join(agents_dir, "out")
    rejected_dir = os.path.join(agents_dir, "rejected")
    projects, audit, blind_spots = [], {}, []

    for fname in sorted(os.listdir(evidence_dir)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(evidence_dir, fname), "r", encoding="utf-8") as f:
            ev = json.load(f)
        slug = ev.get("project_slug") or os.path.splitext(fname)[0]

        analysis, aerr = load_agent_output(
            os.path.join(out_dir, "%s.analyze.json" % slug),
            _schemas.ANALYZE_SCHEMA, rejected_dir)
        security, serr = load_agent_output(
            os.path.join(out_dir, "%s.security.json" % slug),
            _schemas.SECURITY_SCHEMA, rejected_dir)

        if aerr:
            blind_spots.append("%s: analyze output unusable - %s" % (slug, aerr))
        if serr:
            blind_spots.append("%s: security output unusable - %s" % (slug, serr))

        prior = prior_audit.get(slug)
        if security is None:
            findings, dropped = list((prior or {}).get("findings") or []), []
            security_risk = UNKNOWN
        else:
            findings, dropped = reconcile_findings(
                (prior or {}).get("findings"), security.get("findings"))
            security_risk = worst_open_severity(findings, policy)
        for title in dropped:
            blind_spots.append(
                "%s: the security agent omitted the prior finding %r; it was "
                "re-added as open rather than assumed fixed" % (slug, title))

        readiness, reason = derive_readiness(
            analysis, "none" if security_risk == UNKNOWN else security_risk, policy)
        if security_risk == UNKNOWN and readiness == "production-ready":
            readiness, reason = UNKNOWN, policy["unknown_reason"]

        record = {
            "project_slug": slug,
            "name": ev.get("db_metadata", {}).get("name") or slug,
            "path": ev.get("path"),
            "branch": ev.get("branch"),
            "head_sha": ev.get("head_sha"),
            "repo_url": ev.get("remote_url"),
            "repo_source_field": ev.get("db_metadata", {}).get("repo_source_field"),
            "signals": ev.get("size", {}),
            "db_metadata": ev.get("db_metadata", {}),
            "siblings": ev.get("siblings", {}),
            "walk_stats": ev.get("walk_stats", {}),
            "secrets": ev.get("secrets", []),
            "analysis": analysis,
            "readiness": readiness,
            "readiness_reason": reason,
            "security_risk": security_risk,
            "findings": findings,
        }
        projects.append(record)

        entry = {"risk": security_risk,
                 "auditedAt": (prior or {}).get("auditedAt") or _today(),
                 "issueUrl": (security or {}).get("issueUrl") or (prior or {}).get("issueUrl"),
                 "issueState": (security or {}).get("issueState", "none"),
                 "findings": [{"severity": f.get("severity"), "title": f.get("title"),
                               "status": f.get("status")} for f in findings]}
        if prior:
            entry["reauditedAt"] = _today()
            entry["previousRisk"] = prior.get("risk")
        if security and security.get("reauditNote"):
            entry["reauditNote"] = security["reauditNote"]
        audit[slug] = entry

        for name, res in (ev.get("siblings") or {}).items():
            if not res.get("available", True):
                blind_spots.append("%s: %s scanner did not run - %s"
                                   % (slug, name, res.get("reason", "unknown")))
        unreadable = (ev.get("walk_stats") or {}).get("unreadable") or []
        if unreadable:
            blind_spots.append("%s: %d path(s) could not be read; unreadable is not clean"
                               % (slug, len(unreadable)))

    return {"projects": projects, "audit": audit, "blind_spots": blind_spots}


def apply_gate(projects, policy, fail_on, fail_on_readiness):
    """Mark each project blocked, and return True if any is."""
    order = policy["severity_order"]
    rorder = policy["readiness_order"]
    any_blocked = False
    for p in projects:
        blocked = False
        if fail_on != "none":
            risk = p["security_risk"]
            rank = order.index(risk) if risk in order else -1
            if rank >= 0 and rank <= order.index(fail_on):
                blocked = True
            if risk == UNKNOWN:
                blocked = True
        if fail_on_readiness != "none":
            if rorder.index(p["readiness"]) >= rorder.index(fail_on_readiness):
                blocked = True
        p["blocked"] = blocked
        any_blocked = any_blocked or blocked
    return any_blocked


def main(argv=None):
    ap = argparse.ArgumentParser(description="Merge agent output into insight records.")
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--agents", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--prior-audit", default=None)
    ap.add_argument("--profile", default="generic")
    ap.add_argument("--fail-on", default=None)
    ap.add_argument("--fail-on-readiness", default=None)
    args = ap.parse_args(argv)

    try:
        policy = _policy.load_policy(args.profile)
    except _policy.PolicyError as e:
        sys.stderr.write("%s\n" % e)
        return 2

    prior = {}
    if args.prior_audit and os.path.isfile(args.prior_audit):
        try:
            with open(args.prior_audit, "r", encoding="utf-8") as f:
                prior = json.load(f)
        except (OSError, ValueError) as e:
            sys.stderr.write("WARNING: prior audit unreadable: %s\n" % e)

    res = merge(args.evidence, args.agents, policy, prior_audit=prior)
    fail_on = args.fail_on or policy["gate_defaults"]["fail_on"]
    fail_readiness = args.fail_on_readiness or policy["gate_defaults"]["fail_on_readiness"]
    apply_gate(res["projects"], policy, fail_on, fail_readiness)

    os.makedirs(os.path.join(args.out, "projects"), exist_ok=True)
    with open(os.path.join(args.out, "insights.json"), "w", encoding="utf-8") as f:
        json.dump({"schema_version": 1, "generated_at": _today(),
                   "profile": policy.get("profile_name"),
                   "blind_spots": res["blind_spots"],
                   "projects": res["projects"]}, f, indent=2)
    with open(os.path.join(args.out, "security-audit.json"), "w", encoding="utf-8") as f:
        json.dump(res["audit"], f, indent=2)
    for p in res["projects"]:
        with open(os.path.join(args.out, "projects", p["project_slug"] + ".json"),
                  "w", encoding="utf-8") as f:
            json.dump(p, f, indent=2)

    sys.stderr.write("merged %d project(s), %d blind spot(s)\n"
                     % (len(res["projects"]), len(res["blind_spots"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: all assertions PASS, exit `0`.

If `risk reflects the still-open F2` fails with `none`, `reconcile_findings` is not re-adding the omitted finding — that is rule 2 broken, and it is the single most important assertion in this file.

- [ ] **Step 5: Commit**

```bash
git add skills/project-weakness-analysis/scripts/merge_insights.py skills/project-weakness-analysis/tests/selftest.py
git commit -m "feat(project-weakness-analysis): verdict derivation and re-audit reconciliation"
```

---

### Task 9: `gen_report.py` — Markdown, flat projection, CSV, SARIF

**Files:**
- Create: `skills/project-weakness-analysis/scripts/gen_report.py`
- Modify: `skills/project-weakness-analysis/tests/selftest.py`

**The legend rule:** `readiness_legend_lines(policy)` renders the tier legend from `policy["readiness_rules"]`. Never type a `- **production-ready** — …` line by hand. `docs/superpowers/HANDOFF.md` records what happened last time someone did: a hand-written legend shipped describing a different scanner's tiers.

**Interfaces:**
- Consumes: `_policy`, `_redact.redact_command`; `insights.json` from Task 8.
- Produces:
  - `readiness_legend_lines(policy) -> list[str]` — one line per rule, text taken from `rule["reason"]`.
  - `flat_rows(insights, policy) -> list[dict]` — keys are exactly `policy["table_columns"]`, in order.
  - `render_markdown(insights, policy, scan_command, digest=None) -> str`
  - `render_sarif(insights) -> dict`
  - CLI: `python3 gen_report.py --insights PATH --out DIR [--scan-command STR] [--digest PATH] [--profile NAME]`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/selftest.py`:

```python
def _insights_fixture():
    return {"schema_version": 1, "generated_at": "2026-08-08", "profile": "generic",
            "blind_spots": ["beta: analyze output unusable - no output file"],
            "projects": [
                {"project_slug": "alpha", "name": "Alpha", "path": "/tmp/alpha",
                 "branch": "main", "head_sha": "abc123", "repo_url": "https://github.com/acme/alpha",
                 "repo_source_field": None, "signals": {"code_loc": 900, "primary_language": "Python"},
                 "db_metadata": {}, "siblings": {}, "walk_stats": {}, "secrets": [],
                 "analysis": _valid_analysis(), "readiness": "production-ready",
                 "readiness_reason": "r", "security_risk": "low", "blocked": False,
                 "findings": [_finding("low", "Verbose errors", "open")]},
                {"project_slug": "beta", "name": "Beta", "path": "/tmp/beta",
                 "branch": "main", "head_sha": "def456", "repo_url": None,
                 "repo_source_field": None, "signals": {}, "db_metadata": {},
                 "siblings": {}, "walk_stats": {}, "secrets": [], "analysis": None,
                 "readiness": "unknown", "readiness_reason": "u",
                 "security_risk": "unknown", "blocked": True, "findings": []}]}


def test_report_generation():
    import tempfile
    import gen_report
    policy = _policy.load_policy()
    ins = _insights_fixture()
    md = gen_report.render_markdown(ins, policy,
                                    "./run.sh --db --db-url postgres://u:pw@h/d")

    check("report states the scan command", "Scan command" in md)
    check("the scan command is redacted in the report", "pw@h" not in md)
    check("report names every project analyzed",
          "alpha" in md and "beta" in md)
    check("report states head SHAs", "abc123" in md and "def456" in md)
    check("report always has a blind-spot section", "Blind spots" in md)
    check("report carries the blind spot through", "analyze output unusable" in md)
    check("report has a project matrix", "Project matrix" in md)

    for rule in policy["readiness_rules"]:
        check("legend line for %s comes from policy" % rule["tier"],
              rule["reason"][:40] in md, "missing: %s" % rule["reason"][:40])
    for word in ("P0", "P1", "P2", "spotlight", "diffusion", "promote"):
        check("report contains no %r vocabulary from another scanner" % word,
              word not in md)


def test_flat_projection():
    import gen_report
    policy = _policy.load_policy()
    rows = gen_report.flat_rows(_insights_fixture(), policy)
    check("one row per project, including unscored ones", len(rows) == 2)
    check("row columns match table_columns exactly and in order",
          all(list(r.keys()) == policy["table_columns"] for r in rows))
    by = {r["project_slug"]: r for r in rows}
    check("an unknown project still has a row", "beta" in by)
    check("an unknown project is marked blocked", by["beta"]["blocked"] is True)
    check("unscored fields are null, not zero", by["beta"]["maturity_score"] is None)
    check("scores are carried from the analysis", by["alpha"]["maturity_score"] == 4)
    check("open findings are counted", by["alpha"]["open_findings"] == 1)


def test_csv_and_sarif():
    import tempfile
    import csv as _csv
    import json as _json
    import gen_report
    policy = _policy.load_policy()
    ins = _insights_fixture()
    with tempfile.TemporaryDirectory() as out:
        gen_report.write_all(ins, policy, out, "./run.sh --root .", digest=None)
        with open(os.path.join(out, "insights-table.csv"), "r", encoding="utf-8") as f:
            rows = list(_csv.DictReader(f))
        check("CSV has one row per project", len(rows) == 2)
        check("CSV header matches table_columns",
              list(rows[0].keys()) == policy["table_columns"])
        with open(os.path.join(out, "findings.sarif"), "r", encoding="utf-8") as f:
            sarif = _json.load(f)
        check("SARIF has the required version", sarif["version"] == "2.1.0")
        check("SARIF carries one result per finding",
              len(sarif["runs"][0]["results"]) == 1)
        check("report, table json, table csv and sarif all written",
              all(os.path.isfile(os.path.join(out, n)) for n in
                  ("WEAKNESS-REPORT.md", "insights-table.json",
                   "insights-table.csv", "findings.sarif")))


def test_report_without_digest_says_so():
    import gen_report
    policy = _policy.load_policy()
    md = gen_report.render_markdown(_insights_fixture(), policy, "./run.sh", digest=None)
    check("a missing rollup is stated, not silently omitted",
          "rollup" in md.lower())
```

Register in `main()`:

```python
    print("\nReport, projection, CSV and SARIF")
    test_report_generation()
    test_flat_projection()
    test_csv_and_sarif()
    test_report_without_digest_says_so()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'gen_report'`.

- [ ] **Step 3: Write the implementation**

```python
#!/usr/bin/env python3
"""
gen_report.py - Render the report, the flat projection, the CSV, and SARIF.

THE LEGEND RULE
    readiness_legend_lines() renders the tier legend FROM policy. Never type a
    tier description by hand here. A hand-written legend shipped once in this
    package describing a different scanner's tiers - see
    docs/superpowers/HANDOFF.md. Generating it makes that drift impossible.

WHAT EVERY REPORT MUST STATE
    The scan command that produced it (redacted), every project and HEAD SHA it
    actually covered, and its own blind spots - present even on a clean run.
    A "no findings" statement is scoped to exactly the projects listed.
"""
import argparse
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _policy   # noqa: E402
import _redact   # noqa: E402


def readiness_legend_lines(policy):
    lines = ["- **%s** — %s" % (r["tier"], r["reason"]) for r in policy["readiness_rules"]]
    lines.append("- **unknown** — %s" % policy["unknown_reason"])
    return lines


def severity_legend_lines(policy):
    return ["- **%s**" % s for s in policy["severity_order"]]


def _score(analysis, group):
    if not analysis:
        return None
    return analysis.get(group, {}).get("score")


def flat_rows(insights, policy):
    open_statuses = set(policy["open_statuses"])
    audit_defaults = {"previous_risk": None, "audited_at": None, "reaudited_at": None}
    rows = []
    for p in insights["projects"]:
        a = p.get("analysis")
        findings = p.get("findings") or []
        sig = p.get("signals") or {}
        values = {
            "project_slug": p.get("project_slug"),
            "name": p.get("name"),
            "repo_url": p.get("repo_url"),
            "repo_source_field": p.get("repo_source_field"),
            "path": p.get("path"),
            "branch": p.get("branch"),
            "head_sha": p.get("head_sha"),
            "stars": sig.get("stars"),
            "forks": sig.get("forks"),
            "contributors": sig.get("contributors"),
            "commit_count": sig.get("commit_count"),
            "code_loc": sig.get("code_loc"),
            "license": sig.get("license"),
            "primary_language": sig.get("primary_language"),
            "project_type": a.get("project_type") if a else None,
            "uses_orm": a["architecture"]["uses_orm"] if a else None,
            "orm_or_db_layer": a["architecture"]["orm_or_db_layer"] if a else None,
            "maturity_score": _score(a, "maturity"),
            "production_readiness_score": _score(a, "production_readiness"),
            "code_organization_score": _score(a, "code_organization"),
            "maintainability_score": _score(a, "maintainability"),
            "readiness": p.get("readiness"),
            "security_risk": p.get("security_risk"),
            "previous_risk": p.get("previous_risk"),
            "open_findings": sum(1 for f in findings if f.get("status") in open_statuses),
            "resolved_findings": sum(1 for f in findings if f.get("status") == "resolved"),
            "red_flags_count": len(a.get("red_flags", [])) if a else None,
            "blocked": p.get("blocked", False),
            "audited_at": p.get("audited_at"),
            "reaudited_at": p.get("reaudited_at"),
        }
        values.update({k: values.get(k, v) for k, v in audit_defaults.items()})
        rows.append({col: values.get(col) for col in policy["table_columns"]})
    return rows


def _md_table(columns, rows):
    out = ["| " + " | ".join(columns) + " |",
           "|" + "|".join("---" for _ in columns) + "|"]
    for r in rows:
        out.append("| " + " | ".join(
            "" if r.get(c) is None else str(r.get(c)) for c in columns) + " |")
    return out


def render_markdown(insights, policy, scan_command, digest=None):
    projects = insights["projects"]
    rows = flat_rows(insights, policy)
    L = []
    A = L.append

    A("# Project Weakness Analysis Report")
    A("")
    A("Production-readiness and security-risk triage across %d project(s). "
      "Generated %s with the `%s` profile."
      % (len(projects), insights.get("generated_at", "?"), insights.get("profile", "generic")))
    A("")

    A("## 1. Executive summary")
    A("")
    for tier in policy["readiness_order"]:
        n = sum(1 for p in projects if p["readiness"] == tier)
        if n:
            A("- **%s**: %d project(s)" % (tier, n))
    A("")
    for sev in policy["severity_order"]:
        n = sum(1 for p in projects if p["security_risk"] == sev)
        if n:
            A("- security risk **%s**: %d project(s)" % (sev, n))
    blocked = [p for p in projects if p.get("blocked")]
    A("")
    if blocked:
        A("**%d project(s) blocked at the configured thresholds:**" % len(blocked))
        A("")
        for p in blocked:
            A("- **%s** — readiness `%s`, security risk `%s`"
              % (p["project_slug"], p["readiness"], p["security_risk"]))
    else:
        A("No project is blocked at the configured thresholds.")
    A("")

    A("### Project matrix")
    A("")
    compact = ["project_slug", "readiness", "security_risk", "production_readiness_score",
               "maturity_score", "code_organization_score", "maintainability_score",
               "open_findings", "code_loc", "blocked"]
    L.extend(_md_table(compact, rows))
    A("")
    A("Full column set in `insights-table.json` and `insights-table.csv`.")
    A("")

    A("## 2. Scan command")
    A("")
    A("```")
    A(_redact.redact_command(scan_command or "(not recorded)"))
    A("```")
    A("")

    A("## 3. Projects analyzed")
    A("")
    A("Every statement in this report is scoped to exactly these projects at "
      "exactly these commits.")
    A("")
    L.extend(_md_table(["project_slug", "path", "branch", "head_sha"], rows))
    A("")

    A("## 4. Blind spots")
    A("")
    A("What this run did not or could not cover. Read this before treating any "
      "result as complete.")
    A("")
    for b in insights.get("blind_spots") or []:
        A("- %s" % b)
    if not insights.get("blind_spots"):
        A("- No coverage gaps were recorded for this run.")
    A("")
    A("- Scores on the readiness axis are AI-generated from a single snapshot of "
      "each project. This is triage, not ground truth. Re-running is cheap; do it "
      "whenever the code changes.")
    A("")

    A("## 5. Readiness tiers and risk levels")
    A("")
    A("Generated from `policy/weakness.json`; edit the policy, not this report.")
    A("")
    L.extend(readiness_legend_lines(policy))
    A("")
    A("Security risk is the severity of the worst still-open finding "
      "(status %s). Resolved findings never contribute."
      % ", ".join("`%s`" % s for s in policy["open_statuses"]))
    A("")

    A("## 6. Per-project detail")
    A("")
    for p in sorted(projects, key=lambda x: x["project_slug"]):
        a = p.get("analysis")
        A("### %s" % p["project_slug"])
        A("")
        A("- **Readiness:** `%s` — %s" % (p["readiness"], p.get("readiness_reason", "")))
        A("- **Security risk:** `%s`" % p["security_risk"])
        if a:
            A("- **Summary:** %s" % a.get("summary", ""))
            A("- **Scores:** production-readiness %s/5 · maturity %s/5 · "
              "organization %s/5 · maintainability %s/5"
              % (_score(a, "production_readiness"), _score(a, "maturity"),
                 _score(a, "code_organization"), _score(a, "maintainability")))
            if a.get("weaknesses"):
                A("- **Weaknesses:** %s" % "; ".join(a["weaknesses"]))
            if a.get("red_flags"):
                A("- **Red flags:** %s" % "; ".join(a["red_flags"]))
        else:
            A("- No usable analysis was produced for this project. It is reported "
              "as `unknown`, which blocks — an unscanned project is not a safe one.")
        findings = p.get("findings") or []
        if findings:
            A("")
            A("| severity | status | title | file:line |")
            A("|---|---|---|---|")
            for f in findings:
                A("| %s | %s | %s | %s:%s |" % (f.get("severity"), f.get("status"),
                                                f.get("title"), f.get("file"), f.get("line")))
        A("")

    A("## 7. Cross-project rollup")
    A("")
    A(digest if digest else
      "The rollup agent produced no output for this run, so this section is "
      "empty. Every per-project result above is unaffected — the rollup is "
      "presentational and can never change a score, a tier, or the exit code.")
    A("")
    return "\n".join(L) + "\n"


def render_sarif(insights):
    results = []
    for p in insights["projects"]:
        for f in p.get("findings") or []:
            if f.get("status") == "resolved":
                continue
            level = {"critical": "error", "high": "error",
                     "medium": "warning", "low": "note"}.get(f.get("severity"), "note")
            results.append({
                "ruleId": "weakness/%s" % (f.get("severity") or "unknown"),
                "level": level,
                "message": {"text": "%s — %s" % (f.get("title"), f.get("evidence", ""))},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "%s/%s" % (p["project_slug"],
                                                           f.get("file") or "")},
                    "region": {"startLine": max(1, int(f.get("line") or 1))}}}]})
    return {"version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "project-weakness-analysis",
                                          "informationUri": "https://github.com/tomkat-cr/genericsuite-security",
                                          "rules": []}},
                      "results": results}]}


def write_all(insights, policy, out_dir, scan_command, digest=None):
    os.makedirs(out_dir, exist_ok=True)
    rows = flat_rows(insights, policy)
    cols = policy["table_columns"]

    with open(os.path.join(out_dir, "WEAKNESS-REPORT.md"), "w", encoding="utf-8") as f:
        f.write(render_markdown(insights, policy, scan_command, digest))
    with open(os.path.join(out_dir, "insights-table.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    with open(os.path.join(out_dir, "insights-table.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    with open(os.path.join(out_dir, "findings.sarif"), "w", encoding="utf-8") as f:
        json.dump(render_sarif(insights), f, indent=2)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render the report and data files.")
    ap.add_argument("--insights", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--scan-command", default="")
    ap.add_argument("--digest", default=None)
    ap.add_argument("--profile", default="generic")
    args = ap.parse_args(argv)

    try:
        policy = _policy.load_policy(args.profile)
        with open(args.insights, "r", encoding="utf-8") as f:
            insights = json.load(f)
    except (_policy.PolicyError, OSError, ValueError) as e:
        sys.stderr.write("%s\n" % e)
        return 2

    digest = None
    if args.digest and os.path.isfile(args.digest):
        try:
            with open(args.digest, "r", encoding="utf-8") as f:
                digest = f.read().strip()
        except OSError:
            digest = None

    write_all(insights, policy, args.out, args.scan_command, digest)
    sys.stdout.write(os.path.join(args.out, "WEAKNESS-REPORT.md") + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: all assertions PASS, exit `0`.

- [ ] **Step 5: Commit**

```bash
git add skills/project-weakness-analysis/scripts/gen_report.py skills/project-weakness-analysis/tests/selftest.py
git commit -m "feat(project-weakness-analysis): report, flat projection, CSV and SARIF output"
```

---

### Task 10: `run_weakness_analysis.sh` — the driver

**Files:**
- Create: `skills/project-weakness-analysis/scripts/run_weakness_analysis.sh`
- Modify: `skills/project-weakness-analysis/tests/selftest.py`

**bash 3.2 rules, non-negotiable:** no arrays, no `declare -A`, no `${var,,}`, no `mapfile`, no `readarray`. Build argument strings by concatenation and pass them through `eval` only where quoted by hand, or prefer calling Python with fixed positional arguments. `set -uo pipefail` — **not** `set -e`, which turns a benign non-zero into a silent abort mid-pipeline.

**Interfaces:**
- Consumes: every script from Tasks 2–9.
- Produces: the `--phase collect` and `--phase merge` entry points, the gate, and exit codes `0`/`1`/`2`.
- Exports `WEAKNESS_INVOKED_CMD` before consuming any argument, so `gen_report.py` can state and redact it.

- [ ] **Step 1: Write the failing tests**

Append to `tests/selftest.py`:

```python
def test_driver_bash32_safe():
    path = os.path.join(SCRIPTS, "run_weakness_analysis.sh")
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    for bad, why in (("declare -A", "associative arrays need bash 4"),
                     ("mapfile", "needs bash 4"),
                     ("readarray", "needs bash 4"),
                     ("${!", "indirect expansion is bash 4 in this form")):
        check("driver avoids %s (%s)" % (bad, why), bad not in src)
    check("driver does not use set -e (it masks pipeline stage failures)",
          "set -e" not in src.replace("set -eu", "").replace("set -euo", ""))
    check("driver captures the invocation before parsing",
          "WEAKNESS_INVOKED_CMD" in src)
    check("driver runs the self-test", "selftest.py" in src)


def test_driver_no_input_exits_2():
    import subprocess
    path = os.path.join(SCRIPTS, "run_weakness_analysis.sh")
    proc = subprocess.run(["bash", path], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=120)
    out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    check("no input mode exits 2", proc.returncode == 2, "got %d" % proc.returncode)
    check("usage names all five input modes",
          all(m in out for m in ("--root", "--projects", "--corpus", "--org", "--db")))


def test_gate_exit_codes():
    import tempfile
    import json as _json
    import merge_insights
    policy = _policy.load_policy()
    projects = [{"project_slug": "a", "readiness": "production-ready", "security_risk": "low"},
                {"project_slug": "b", "readiness": "needs-work", "security_risk": "critical"},
                {"project_slug": "c", "readiness": "unknown", "security_risk": "none"}]
    import copy
    p1 = copy.deepcopy(projects)
    check("a critical finding blocks at --fail-on high",
          merge_insights.apply_gate(p1, policy, "high", "not-ready") is True)
    check("the critical project is the blocked one",
          [x["project_slug"] for x in p1 if x["blocked"]] == ["b", "c"],
          "got %s" % [x["project_slug"] for x in p1 if x["blocked"]])
    p2 = copy.deepcopy(projects)
    check("--fail-on none disables the security gate for b",
          merge_insights.apply_gate(p2, policy, "none", "none") is False)
    p3 = copy.deepcopy(projects)
    merge_insights.apply_gate(p3, policy, "none", "not-ready")
    check("readiness unknown blocks at the default readiness threshold",
          [x["project_slug"] for x in p3 if x["blocked"]] == ["c"])
    p4 = copy.deepcopy(projects)
    merge_insights.apply_gate(p4, policy, "none", "needs-work")
    check("--fail-on-readiness needs-work also blocks needs-work",
          set(x["project_slug"] for x in p4 if x["blocked"]) == set(("b", "c")))
```

Register in `main()`:

```python
    print("\nDriver and gate")
    test_driver_bash32_safe()
    test_driver_no_input_exits_2()
    test_gate_exit_codes()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: FAIL — `run_weakness_analysis.sh` does not exist.

- [ ] **Step 3: Write the driver**

```bash
#!/usr/bin/env bash
# run_weakness_analysis.sh - Verify detection works, then analyze projects.
#
# Usage:
#   ./run_weakness_analysis.sh --root ~/dev
#   ./run_weakness_analysis.sh --projects ~/a ~/b
#   ./run_weakness_analysis.sh --corpus path/corpus.json
#   ./run_weakness_analysis.sh --org acme
#   ./run_weakness_analysis.sh --db                     # optional registry mode
#   ./run_weakness_analysis.sh --phase merge            # after agents have run
#
# Exit: 0 nothing blocked at the thresholds, 1 at least one project blocked,
#       2 error (no report produced).
#
# NO BASH ARRAYS ANYWHERE IN THIS FILE. macOS ships bash 3.2, where "${a[@]}"
# on an EMPTY array under `set -u` aborts with "unbound variable" - and a crash
# inside a command substitution can look like a verdict rather than a broken
# run. repo-docker-scanner shipped exactly that bug.
#
# NOT `set -e`: a benign non-zero from one stage would abort the pipeline
# silently, which is the same failure wearing a different hat.
set -uo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$SKILL_DIR/scripts"
CORPUS_SKILL="$(cd "$SKILL_DIR/../repo-corpus" 2>/dev/null && pwd || true)"

# Capture the exact top-level invocation BEFORE any argument is consumed.
# --root/--org/--db all resolve into a --corpus path long before the Python
# scripts run, so their own argv would only show the internal call.
# gen_report.py redacts this before writing it anywhere.
WEAKNESS_INVOKED_CMD="./scripts/run_weakness_analysis.sh"
for _a in "$@"; do
  _q="$(printf '%s' "$_a" | sed "s/'/'\\\\''/g")"
  WEAKNESS_INVOKED_CMD="$WEAKNESS_INVOKED_CMD '$_q'"
done
export WEAKNESS_INVOKED_CMD
unset _a _q 2>/dev/null || true

command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }

usage() {
  cat >&2 <<'USAGE'
Usage: run_weakness_analysis.sh <input mode> [options]

Input modes (exactly one; --db is optional and needs a database, the others do not):
  --root PATH              discover every project under PATH
  --projects A B C         an explicit list of project directories
  --corpus PATH            an existing repo-corpus manifest
  --org NAME | --user NAME clone from GitHub via repo-corpus
  --db                     read a project registry table (Supabase/Postgres, read-only)

Options:
  --out PATH               output tree (default ./insights)
  --profile NAME|PATH      policy overlay (default generic)
  --phase collect|merge|all
  --max-depth N            discovery depth cap (default 3)
  --limit N                cap discovered projects
  --db-config PATH         table and column mapping
  --db-limit N             cap rows read
  --db-rows-json PATH      use a saved payload instead of a live database
  --split-monorepo         treat each marker-bearing subdirectory as a project
  --list-only              print what would be analyzed, then exit 0
  --fail-on SEVERITY       critical|high|medium|low|none (default high)
  --fail-on-readiness TIER production-ready|needs-work|not-ready|none (default not-ready)
  --no-siblings            skip the sibling scanners (recorded as a blind spot)
  --keep-work              preserve .work/
USAGE
}

OUT="./insights"; PROFILE="generic"; PHASE="collect"
MODE=""; ROOT=""; CORPUS=""; ORG=""; USERNAME=""; PROJECTS=""
MAX_DEPTH=""; LIMIT=""; DB_CONFIG=""; DB_LIMIT=""; DB_ROWS=""
SPLIT=""; LIST_ONLY=""; NO_SIBLINGS=""; KEEP_WORK=""
FAIL_ON=""; FAIL_ON_READINESS=""

[ $# -eq 0 ] && { usage; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --root) MODE="root"; ROOT="$2"; shift 2 ;;
    --corpus) MODE="corpus"; CORPUS="$2"; shift 2 ;;
    --org) MODE="org"; ORG="$2"; shift 2 ;;
    --user) MODE="org"; USERNAME="$2"; shift 2 ;;
    --db) MODE="db"; shift ;;
    --projects)
      MODE="projects"; shift
      while [ $# -gt 0 ]; do
        case "$1" in --*) break ;; *) PROJECTS="$PROJECTS $1"; shift ;; esac
      done ;;
    --out) OUT="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --phase) PHASE="$2"; shift 2 ;;
    --max-depth) MAX_DEPTH="$2"; shift 2 ;;
    --limit) LIMIT="$2"; shift 2 ;;
    --db-config) DB_CONFIG="$2"; shift 2 ;;
    --db-limit) DB_LIMIT="$2"; shift 2 ;;
    --db-rows-json) DB_ROWS="$2"; shift 2 ;;
    --split-monorepo) SPLIT="1"; shift ;;
    --list-only) LIST_ONLY="1"; shift ;;
    --no-siblings) NO_SIBLINGS="1"; shift ;;
    --keep-work) KEEP_WORK="1"; shift ;;
    --fail-on) FAIL_ON="$2"; shift 2 ;;
    --fail-on-readiness) FAIL_ON_READINESS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[ "$PHASE" = "all" ] && PHASE="collect"

if [ "$PHASE" = "collect" ] && [ -z "$MODE" ]; then
  echo "no input mode given - refusing to guess what to scan." >&2
  usage; exit 2
fi

WORK="$OUT/.work"
EVIDENCE="$WORK/evidence"
AGENTS="$WORK/agents"
mkdir -p "$WORK" "$EVIDENCE" "$AGENTS/out" || { echo "cannot write to $OUT" >&2; exit 2; }

# The self-test is the only evidence that the detectors detect. A scanner that
# checks nothing and reports clean looks exactly like a working one.
if [ "${WEAKNESS_SKIP_SELFTEST:-0}" = "1" ]; then
  echo "### Step 1: SELF-TEST SKIPPED (WEAKNESS_SKIP_SELFTEST=1)"
  echo "    Detection is NOT verified in this run."
else
  echo "### Step 1: self-test (proves every detector still fires)"
  if ! python3 "$SKILL_DIR/tests/selftest.py"; then
    echo >&2
    echo "  SELF-TEST FAILED - not analyzing. A clean verdict from an unverified" >&2
    echo "  scanner is indistinguishable from one that checked nothing." >&2
    exit 2
  fi
fi

if [ "$PHASE" = "collect" ]; then
  echo "### Step 2: resolve input to a corpus"
  CORPUS_JSON="$WORK/corpus.json"
  BUILD="$CORPUS_SKILL/scripts/build_corpus.py"

  case "$MODE" in
    corpus)
      CORPUS_JSON="$CORPUS" ;;
    root)
      DEPTH_ARG=""; [ -n "$MAX_DEPTH" ] && DEPTH_ARG="--max-depth $MAX_DEPTH"
      LIMIT_ARG="";  [ -n "$LIMIT" ] && LIMIT_ARG="--limit $LIMIT"
      SPLIT_ARG="";  [ -n "$SPLIT" ] && SPLIT_ARG="--split-monorepo"
      # shellcheck disable=SC2086
      FOUND="$(python3 "$SCRIPTS/discover_projects.py" --root "$ROOT" --profile "$PROFILE" \
                 --stats-json "$WORK/discovery.json" $DEPTH_ARG $LIMIT_ARG $SPLIT_ARG)" || exit 2
      [ -n "$LIST_ONLY" ] && { printf '%s\n' "$FOUND"; exit 0; }
      [ -f "$BUILD" ] || { echo "repo-corpus not installed at $CORPUS_SKILL" >&2; exit 2; }
      # shellcheck disable=SC2086
      python3 "$BUILD" --local $FOUND --out "$CORPUS_JSON" >/dev/null || true ;;
    projects)
      [ -n "$LIST_ONLY" ] && { printf '%s\n' $PROJECTS; exit 0; }
      [ -f "$BUILD" ] || { echo "repo-corpus not installed at $CORPUS_SKILL" >&2; exit 2; }
      # shellcheck disable=SC2086
      python3 "$BUILD" --local $PROJECTS --out "$CORPUS_JSON" >/dev/null || true ;;
    org)
      [ -f "$BUILD" ] || { echo "repo-corpus not installed at $CORPUS_SKILL" >&2; exit 2; }
      if [ -n "$ORG" ]; then
        python3 "$BUILD" --org "$ORG" --out "$CORPUS_JSON" >/dev/null || true
      else
        python3 "$BUILD" --user "$USERNAME" --out "$CORPUS_JSON" >/dev/null || true
      fi ;;
    db)
      DBC_ARG=""; [ -n "$DB_CONFIG" ] && DBC_ARG="--db-config $DB_CONFIG"
      DBL_ARG=""; [ -n "$DB_LIMIT" ] && DBL_ARG="--db-limit $DB_LIMIT"
      DBR_ARG=""; [ -n "$DB_ROWS" ] && DBR_ARG="--db-rows-json $DB_ROWS"
      # shellcheck disable=SC2086
      python3 "$SCRIPTS/db_collect.py" --out "$WORK/db-projects.json" \
        --profile "$PROFILE" $DBC_ARG $DBL_ARG $DBR_ARG || exit 2
      [ -n "$LIST_ONLY" ] && { python3 -c "import json,sys;[sys.stdout.write(p['repo_url']+'\n') for p in json.load(open('$WORK/db-projects.json'))['selected']]"; exit 0; }
      [ -f "$BUILD" ] || { echo "repo-corpus not installed at $CORPUS_SKILL" >&2; exit 2; }
      python3 -c "import json;d=json.load(open('$WORK/db-projects.json'));json.dump([{'name':p['slug'],'url':p['repo_url']} for p in d['selected']],open('$WORK/repo-list.json','w'))"
      python3 "$BUILD" --repos-json "$WORK/repo-list.json" --out "$CORPUS_JSON" >/dev/null || true ;;
  esac

  [ -s "$CORPUS_JSON" ] || { echo "no usable corpus was produced" >&2; exit 2; }

  echo "### Step 3: collect deterministic signals"
  SIB_ARG=""; [ -n "$NO_SIBLINGS" ] && SIB_ARG="--no-siblings"
  # shellcheck disable=SC2086
  python3 "$SCRIPTS/collect_signals.py" --corpus "$CORPUS_JSON" --out "$EVIDENCE" \
    --profile "$PROFILE" $SIB_ARG || exit 2

  # --db mode only: fold the registry's per-project metadata (name,
  # repo_source_field, and the configured metadata_columns) into the
  # evidence bundles collect_signals.py just wrote. Nothing else populates
  # db_metadata - see Task 6's attach_metadata.
  if [ "$MODE" = "db" ] && [ -s "$WORK/db-projects.json" ]; then
    python3 -c "
import json, sys
sys.path.insert(0, '$SCRIPTS')
import db_collect
d = json.load(open('$WORK/db-projects.json'))
db_collect.attach_metadata('$EVIDENCE', d['selected'])
" || exit 2
  fi

  echo "### Step 4: build the agent task manifest"
  PRIOR="$OUT/security-audit.json"
  PRIOR_ARG=""; [ -f "$PRIOR" ] && PRIOR_ARG="--prior-audit $PRIOR"
  # shellcheck disable=SC2086
  python3 "$SCRIPTS/build_tasks.py" --evidence "$EVIDENCE" --out "$AGENTS/tasks.json" \
    --profile "$PROFILE" $PRIOR_ARG || exit 2

  echo
  echo "COLLECT COMPLETE. The two AI stages are dispatched by Claude, not by this script."
  echo
  echo "  Task manifest: $AGENTS/tasks.json"
  echo "  Dispatch every task in it as a parallel subagent (see SKILL.md),"
  echo "  then finish with:"
  echo
  echo "      $0 --phase merge --out $OUT --profile $PROFILE"
  echo
  exit 0
fi

if [ "$PHASE" = "merge" ]; then
  echo "### Step 5: merge agent output and derive verdicts"
  PRIOR="$OUT/security-audit.json"
  PRIOR_ARG=""; [ -f "$PRIOR" ] && PRIOR_ARG="--prior-audit $PRIOR"
  FO_ARG="";  [ -n "$FAIL_ON" ] && FO_ARG="--fail-on $FAIL_ON"
  FR_ARG="";  [ -n "$FAIL_ON_READINESS" ] && FR_ARG="--fail-on-readiness $FAIL_ON_READINESS"
  # shellcheck disable=SC2086
  python3 "$SCRIPTS/merge_insights.py" --evidence "$EVIDENCE" --agents "$AGENTS" \
    --out "$OUT" --profile "$PROFILE" $PRIOR_ARG $FO_ARG $FR_ARG || exit 2

  echo "### Step 6: render the report"
  DIGEST_ARG=""; [ -f "$WORK/digest.md" ] && DIGEST_ARG="--digest $WORK/digest.md"
  # shellcheck disable=SC2086
  python3 "$SCRIPTS/gen_report.py" --insights "$OUT/insights.json" --out "$OUT" \
    --profile "$PROFILE" --scan-command "$WEAKNESS_INVOKED_CMD" $DIGEST_ARG || exit 2

  BLOCKED="$(python3 -c "
import json,sys
d=json.load(open('$OUT/insights.json'))
n=sum(1 for p in d['projects'] if p.get('blocked'))
print(n)")"
  [ -z "$KEEP_WORK" ] && echo "(.work/ kept for inspection; remove it yourself if unwanted)"

  echo
  if [ "$BLOCKED" -gt 0 ] 2>/dev/null; then
    echo "$BLOCKED project(s) blocked. See $OUT/WEAKNESS-REPORT.md"
    exit 1
  fi
  echo "No project blocked at the configured thresholds. See $OUT/WEAKNESS-REPORT.md"
  exit 0
fi

echo "unknown --phase: $PHASE (expected collect, merge, or all)" >&2
exit 2
```

- [ ] **Step 4: Make it executable and run the tests**

```bash
cd skills/project-weakness-analysis
chmod +x scripts/run_weakness_analysis.sh
python3 tests/selftest.py
```
Expected: all assertions PASS, exit `0`.

- [ ] **Step 5: End-to-end smoke test with no agents**

```bash
cd skills/project-weakness-analysis
mkdir -p /tmp/pwa-demo/proj-a && echo '{"name":"a"}' > /tmp/pwa-demo/proj-a/package.json
./scripts/run_weakness_analysis.sh --root /tmp/pwa-demo --out /tmp/pwa-out
./scripts/run_weakness_analysis.sh --phase merge --out /tmp/pwa-out; echo "exit=$?"
```
Expected: collect exits `0` and prints the manifest path; merge exits `1` because the project has no agent output and is therefore `unknown` (blocking). `/tmp/pwa-out/WEAKNESS-REPORT.md` names the project and lists the missing output under Blind spots. **This exit `1` is the correct behaviour, not a failure of the smoke test.**

- [ ] **Step 6: Commit**

```bash
git add skills/project-weakness-analysis/scripts/run_weakness_analysis.sh skills/project-weakness-analysis/tests/selftest.py
git commit -m "feat(project-weakness-analysis): driver, phases, gate and exit codes"
```

---

### Task 11: `SKILL.md`, `references/`, and the dispatch protocol

**Files:**
- Create: `skills/project-weakness-analysis/SKILL.md`
- Create: `skills/project-weakness-analysis/references/methodology.md`
- Create: `skills/project-weakness-analysis/references/project-insights.sql`
- Modify: `skills/project-weakness-analysis/tests/selftest.py`

**Vocabulary warning:** `tmp/project-analysis/analysis/METHODOLOGY.md` is the source for `references/methodology.md`, and it is written for a hackathon triage context — "teams", "victims", "donors", "spotlight", "promote", "diffusion readiness", "ready to promote". Every one of those must go. `tmp/` is gitignored, so this adapted copy is the only version that survives a fresh clone.

- [ ] **Step 1: Write the failing tests**

Append to `tests/selftest.py`:

```python
def test_skill_md_and_references():
    import re
    skill_md = os.path.join(SKILL, "SKILL.md")
    check("SKILL.md exists", os.path.isfile(skill_md))
    with open(skill_md, "r", encoding="utf-8") as f:
        md = f.read()
    check("SKILL.md has YAML frontmatter", md.startswith("---\n"))
    for field in ("name:", "description:", "license:"):
        check("SKILL.md frontmatter has %s" % field, field in md.split("---")[1])
    check("SKILL.md names the skill correctly",
          re.search(r"^name:\s*project-weakness-analysis\s*$", md, re.M) is not None)
    check("SKILL.md documents the dispatch protocol",
          "tasks.json" in md and "output_path" in md)
    check("SKILL.md forbids the dispatcher writing agent output itself",
          "never write" in md.lower() or "do not write" in md.lower())
    check("SKILL.md states that --db is optional",
          "optional" in md.lower() and "--db" in md)
    check("SKILL.md documents both exit-1 meanings",
          "exit" in md.lower() and "blocked" in md.lower())

    meth = os.path.join(SKILL, "references", "methodology.md")
    check("references/methodology.md exists", os.path.isfile(meth))
    with open(meth, "r", encoding="utf-8") as f:
        mtext = f.read().lower()
    for word in ("victim", "donor", "spotlight", "diffusion", "hackathon", "one-line pitch"):
        check("methodology.md is scrubbed of %r" % word, word not in mtext)

    sql = os.path.join(SKILL, "references", "project-insights.sql")
    check("references/project-insights.sql exists", os.path.isfile(sql))
    with open(sql, "r", encoding="utf-8") as f:
        sqltext = f.read()
    policy = _policy.load_policy()
    for col in policy["table_columns"]:
        check("DDL has a column for %s" % col, col in sqltext)


def test_no_team_vocabulary_anywhere():
    import re
    bad = re.compile(r"\b(teams?|hackathon|victims?|donors?)\b", re.I)
    offenders = []
    for root, dirs, files in os.walk(SKILL):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
        for fn in files:
            if not fn.endswith((".md", ".py", ".json", ".sh", ".sql")):
                continue
            p = os.path.join(root, fn)
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    if bad.search(line):
                        offenders.append("%s:%d" % (os.path.relpath(p, SKILL), i))
    check("no hackathon-era vocabulary anywhere in the skill",
          not offenders, "found at %s" % ", ".join(offenders[:5]))
```

Register in `main()`:

```python
    print("\nDocumentation")
    test_skill_md_and_references()
    test_no_team_vocabulary_anywhere()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: FAIL — `SKILL.md exists` is false.

- [ ] **Step 3: Write `SKILL.md`**

Frontmatter must be exactly this shape (match the sibling skills):

```markdown
---
name: project-weakness-analysis
description: Use when deciding whether one or many projects are ready and safe to run in production — scoring production-readiness and auditing security weaknesses across a directory of projects, an explicit list, a GitHub org, or a project registry table. Triggers: "is this ready for production", "audit my projects", "production readiness review", "security weaknesses in my projects", "which of my projects are safe to deploy", "scan all projects in this folder". Not for mutable-reference auditing — that is repo-docker-scanner and repo-packages-scanner.
license: MIT
metadata:
  author: tomkat-cr
  version: "1.0"
---
```

Body sections, in this order. Write each in the voice of `repo-packages-scanner/SKILL.md` — explain *why*, not just *what*:

1. **Overview** — two independent axes, never averaged. A project can be well-built and carry a critical risk.
2. **When to Use** — and when not to (the two mutable-reference scanners).
3. **Quick Start** — the five input modes, with `--db` marked optional. State plainly: *no database is required; four of the five modes involve no database at all.*
4. **The Two-Phase Run** — why one command cannot do it all: a skill's scripts cannot spawn subagents. Show the collect → dispatch → merge sequence.
5. **Dispatch Protocol** — the section Claude follows. It must state, verbatim in substance:
   - Read `insights/.work/agents/tasks.json`.
   - Dispatch every task as a subagent using its `model` and `agent_type`, at most `max_parallel` at a time.
   - Give each subagent its `prompt` and instruct it to write JSON matching `schema` to `output_path`, returning only a one-line confirmation.
   - **Never write a task's output file yourself.** If a subagent fails, leave the file absent — `merge_insights.py` records the gap. A dispatcher inventing a plausible result is the worst failure mode this skill has.
   - Optionally write a short rollup to `insights/.work/digest.md` using a haiku agent; it can never change a score, a tier, or the exit code.
6. **Verdict Model** — the two axes table, and that `unknown` blocks.
7. **Exit Codes** — `0` / `1` / `2`, and that `1` means blocked, never "error".
8. **Output** — the file tree, and that the flat projection is the same column set as `references/project-insights.sql`.
9. **Re-audit** — how a second run verifies prior findings, and that no prior finding is ever dropped.
10. **Policy and Profiles** — `--profile genericsuite`, bring-your-own overlay, and that a profile may add checks but never remove one.
11. **Blind Spots** — what a report cannot tell you, mirroring `repo-corpus`'s section.
12. **Self-Test** — `python3 tests/selftest.py`, and that the driver refuses to run if it fails.
13. **Common Mistakes** — at minimum: treating exit `1` as an error; treating `unknown` as clean; writing agent output by hand; assuming `--db` is required; narrowing scope to make a run pass.

- [ ] **Step 4: Write `references/methodology.md`**

Adapt `tmp/project-analysis/analysis/METHODOLOGY.md`. Keep: the staged pipeline shape, the 1–5 rubric with its five rung definitions, "one agent per project per axis so judgments stay independent", evidence-based scoring, the re-audit status vocabulary, and the "what the scores are and aren't" caveats (strong first pass not ground truth; point-in-time; two separate axes). Replace the six-stage OSS pipeline with this skill's five stages. Delete every promotional stage and all hackathon vocabulary. Add a short "Adapted from" note explaining that the original targeted OSS project triage and that `tmp/` is gitignored, so this is the surviving copy.

- [ ] **Step 5: Write `references/project-insights.sql`**

A `CREATE TABLE IF NOT EXISTS project_insights (...)` with one column per entry in `policy/weakness.json`'s `table_columns`, plus `id`, `created_at`, `updated_at`. Use `text` for identifiers and enums, `integer` for scores and counts, `boolean` for `blocked` and `uses_orm`, `timestamptz` for the date columns. Add a leading comment: this DDL is provided for anyone who wants to load the flat projection themselves — **the skill never runs it, and never writes to a database.**

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd skills/project-weakness-analysis && python3 tests/selftest.py`
Expected: all assertions PASS, exit `0`. If `no hackathon-era vocabulary anywhere` fails, it prints the offending `file:line` — fix those, do not weaken the assertion.

- [ ] **Step 7: Commit**

```bash
git add skills/project-weakness-analysis/SKILL.md skills/project-weakness-analysis/references skills/project-weakness-analysis/tests/selftest.py
git commit -m "docs(project-weakness-analysis): SKILL.md, adapted methodology, and projection DDL"
```

---

### Task 12: `CHANGELOG.md`, handoff, and the calibration run

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `CLAUDE.md`
- Modify: `docs/superpowers/HANDOFF.md`

- [ ] **Step 1: Verify the whole suite passes**

```bash
cd skills/project-weakness-analysis && python3 tests/selftest.py; echo "exit=$?"
```
Expected: `exit=0`, and the final line reports the total assertion count. Record that number — it goes in the handoff.

- [ ] **Step 2: Verify the sibling skills still pass**

```bash
cd ../repo-corpus && python3 tests/selftest.py
cd ../repo-docker-scanner && python3 tests/selftest.py
cd ../repo-packages-scanner && python3 tests/selftest.py
```
Expected: all three exit `0`. Task 1 modified `marketplace.json`, which `repo-corpus`'s self-test asserts against — if it fails there, the registration is wrong.

- [ ] **Step 3: Update `CHANGELOG.md`**

Add a new entry at the top, matching the existing format in that file. Content:

```markdown
### Added
* New skill `project-weakness-analysis`: decides whether projects are ready and safe to run in production, scoring production-readiness and auditing security weaknesses across many projects at once.
  * Five input modes — a root directory (`--root`), an explicit list (`--projects`), an existing corpus (`--corpus`), a GitHub org or user (`--org`/`--user`), and an optional read-only project registry table (`--db`, Supabase PostgREST or psql). No database is required; four of the five modes involve none.
  * Two independent verdict axes, never averaged: a readiness tier (`production-ready` / `needs-work` / `not-ready` / `unknown`) and a security risk level (`critical` … `none`). `unknown` blocks — an unscanned project is not a safe one.
  * A deterministic pre-pass (per-project signals, tiered secret candidates, and findings from `repo-docker-scanner` and `repo-packages-scanner`) grounds two sonnet agents per project; a haiku agent writes the cross-project rollup.
  * A re-audit loop: a second run verifies every prior finding as `resolved` / `partial` / `open`, and no prior finding is ever dropped.
  * Output under `./insights`: `WEAKNESS-REPORT.md`, `insights.json`, a flat `insights-table.json` / `insights-table.csv` projection, `security-audit.json`, `projects/<slug>.json`, and `findings.sarif`.
  * Optional `--profile genericsuite` checks the ecosystem's non-negotiables (scrypt-only hashing, the standard result shape, parameterized SQL, `is_safe_url()` / `is_safe_local_path()` guards).
  * Adapted from an OSS project-triage methodology; the promotional scoring stage was dropped and the adapted methodology now ships in the skill's `references/`.

### Changed
* `.claude-plugin/marketplace.json` registers the new skill; the plugin description now covers production-readiness analysis alongside supply-chain security.
```

- [ ] **Step 4: Update `CLAUDE.md`**

In the package `CLAUDE.md`: change "ships four skills" to five and add a bullet for `project-weakness-analysis`; add its commands to the Commands section (`./scripts/run_weakness_analysis.sh --root ~/dev`, `--phase merge`, `python3 tests/selftest.py`), noting exit `1` means blocked projects; and note in Work In Progress that this skill is complete but has had no calibration run.

- [ ] **Step 5: Update `HANDOFF.md`**

Add a section recording: the assertion count; that `--db` is unverified against a live Supabase or psql (only against the saved payload); that the readiness thresholds in `readiness_rules` have **zero calibration runs against real projects**; and that retuning them is a `policy/weakness.json` edit, never a code change.

- [ ] **Step 6: Commit**

```bash
git add CHANGELOG.md CLAUDE.md docs/superpowers/HANDOFF.md
git commit -m "docs: changelog, package guidance and handoff for project-weakness-analysis"
```

- [ ] **Step 7: Calibration run (requires a human decision, do not automate)**

Run the collect phase against a real directory of projects, dispatch the agents, and merge:

```bash
cd skills/project-weakness-analysis
./scripts/run_weakness_analysis.sh --root ~/some/projects --out ~/insights-calibration
# dispatch tasks.json per SKILL.md, then:
./scripts/run_weakness_analysis.sh --phase merge --out ~/insights-calibration
```

Then read the tier histogram. **If nearly every project lands in one tier, the boundaries are wrong regardless of how defensible they look in the abstract** — a gate that blocks everything gets switched off, and a gate that blocks nothing is decoration. Retune `readiness_rules` in `policy/weakness.json`; never edit `merge_insights.py` to change a threshold. Report the histogram back before treating `--fail-on` as a CI gate.

---

## Plan Self-Review

**Spec coverage.** Every spec section maps to a task: Components → the file map; five input modes → Tasks 2, 6, 10; Stage 1 Collect → Tasks 3, 4, 5; agent dispatch → Tasks 7, 11; Stages 2/3 schemas → Task 7; re-audit → Task 8; haiku digest → Tasks 10, 11; verdict model and gate → Tasks 8, 10; policy and profiles → Task 1; output and flat projection → Task 9; driver flags → Task 10; error-handling table → Tasks 5, 6, 8, 10; self-test list → assertions distributed across all tasks; sequencing → task order; success criteria → Task 12.

**Two gaps found and closed while reviewing:**

- The spec's error table says a missing security output must not silently mean risk `none`. The first draft of Task 8 had no assertion for it; `test_missing_security_output_is_unknown_risk` was added, along with the `security_risk == UNKNOWN` branch in `merge()` and the `UNKNOWN` case in `apply_gate`.
- The spec requires the report to state when the rollup is absent rather than omitting it. `test_report_without_digest_says_so` and the explanatory fallback text in `render_markdown` section 7 were added.

**Type consistency.** Checked across tasks: `load_policy` / `PolicyError` (1→all); `discover(...) -> (list, DiscoveryStats)` (2→10); `scan_project(path, policy, tracked=)` (3→4); `collect(...)` bundle keys `project_slug` / `path` / `siblings` / `walk_stats` (4→5, 7, 8); `run_all` / `attach` (5→4); `build_repo_list -> (selected, skipped, warnings)` (6→10); `validate(obj, schema)` (7→8); `worst_open_severity` / `derive_readiness` / `apply_gate` (8→9, 10); `table_columns` drives `flat_rows`, the CSV header, and the DDL (1→9→11).

**Known deviation from house style:** the three existing plans in this package are decision-records, not step-by-step TDD documents. This one follows the `writing-plans` skill's checkbox format instead, because it was explicitly requested that a less capable model be able to execute it without asking questions.

---

## Execution Handoff

Two execution options:

1. **Subagent-Driven (recommended)** — a fresh subagent per task, reviewed between tasks. Use the per-task model column above: haiku for Tasks 1 and 12, sonnet for Tasks 2–11. Tasks 2–6 can run in parallel after Task 1.
2. **Inline Execution** — tasks executed in the current session with checkpoints.
