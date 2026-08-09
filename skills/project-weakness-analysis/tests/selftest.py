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


def build_crashing_stub_scanner(base):
    """A fake 'docker' sibling scanner that crashes uncaught (exit 1) without
    writing findings.json - the failure mode run_one() must never confuse
    with success."""
    scripts_dir = os.path.join(base, "stub_docker", "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    script_path = os.path.join(scripts_dir, "scan_images.py")
    write(script_path,
          "raise RuntimeError('simulated scanner crash - never completed')\n")
    return os.path.dirname(scripts_dir)


def test_siblings_stale_findings_not_reused_after_crash():
    import tempfile
    import json as _json
    import _siblings
    with tempfile.TemporaryDirectory() as base:
        corpus = os.path.join(base, "corpus.json")
        write(corpus, '{"schema_version":1,"root":"%s","repos":[]}' % base)

        skill_dir = build_crashing_stub_scanner(base)
        work_dir = os.path.join(base, "work")
        out_dir = os.path.join(work_dir, "siblings", "docker")
        os.makedirs(out_dir, exist_ok=True)
        stale = os.path.join(out_dir, "findings.json")
        with open(stale, "w", encoding="utf-8") as f:
            _json.dump({"findings": [{"repo": "alpha",
                                       "ref": "SHOULD-NOT-SURVIVE-A-CRASH"}]}, f)

        result = _siblings.run_one("docker", skill_dir, corpus, work_dir)

        check("a scanner crash (exit 1, not 0 or 2) is never reported as available",
              result["available"] is False,
              "got %s" % result)
        check("a scanner crash never leaks a stale prior run's findings",
              "alpha" not in result.get("by_project", {}),
              "got %s" % result.get("by_project"))
        check("the stale findings.json is removed before the crash (proves pre-run deletion)",
              not os.path.exists(stale))


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


def test_db_psql_credentials_never_reach_argv():
    """_fetch_psql must pass DATABASE_URL's credentials to the psql child
    process via its environment (PGUSER/PGPASSWORD/...), never as argv - argv
    is world-readable via `ps` for the process lifetime, unlike the env of a
    process you don't have permission to inspect."""
    import subprocess as _subprocess
    import db_collect
    policy = _policy.load_policy()
    cfg = dict(policy["db_source"])

    captured = {}

    class FakeCompletedProcess:
        returncode = 0
        stdout = b"[]"
        stderr = b""

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs.get("env")
        return FakeCompletedProcess()

    real_run = _subprocess.run
    db_collect.subprocess.run = fake_run
    try:
        env = {"DATABASE_URL": "postgres://testuser:testpass123@testhost:5432/testdb"}
        db_collect._fetch_psql(cfg, env)
    finally:
        db_collect.subprocess.run = real_run

    argv = captured.get("args") or []
    child_env = captured.get("env") or {}
    check("psql is invoked (fake_run was reached)", "args" in captured)
    check("the password is absent from argv",
          not any("testpass123" in str(a) for a in argv), "argv=%s" % argv)
    check("the username is absent from argv",
          not any("testuser" in str(a) for a in argv), "argv=%s" % argv)
    check("the raw DATABASE_URL is absent from argv",
          not any("testuser:testpass123" in str(a) for a in argv), "argv=%s" % argv)
    check("the password is passed via the child process env instead",
          child_env.get("PGPASSWORD") == "testpass123", "env=%s" % child_env)
    check("the username is passed via the child process env instead",
          child_env.get("PGUSER") == "testuser", "env=%s" % child_env)
    check("host and dbname are also passed via env, not argv",
          child_env.get("PGHOST") == "testhost" and child_env.get("PGDATABASE") == "testdb",
          "env=%s" % child_env)


def test_db_psql_percent_encoded_credentials_and_query_options():
    """DATABASE_URL credentials may be percent-encoded (e.g. %40 for a
    literal @, common in generated Postgres/Supabase secrets) and libpq
    query-string options like sslmode/connect_timeout must survive into the
    child env as PGSSLMODE/PGCONNECT_TIMEOUT - previously both were silently
    dropped/mangled when the URI was parsed instead of passed to psql whole."""
    import subprocess as _subprocess
    import db_collect
    policy = _policy.load_policy()
    cfg = dict(policy["db_source"])

    captured = {}

    class FakeCompletedProcess:
        returncode = 0
        stdout = b"[]"
        stderr = b""

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs.get("env")
        return FakeCompletedProcess()

    real_run = _subprocess.run
    db_collect.subprocess.run = fake_run
    try:
        env = {"DATABASE_URL":
               "postgres://us%40er:pa%40ss@testhost:5432/testdb"
               "?sslmode=require&connect_timeout=10"}
        db_collect._fetch_psql(cfg, env)
    finally:
        db_collect.subprocess.run = real_run

    argv = captured.get("args") or []
    child_env = captured.get("env") or {}
    check("psql is invoked (fake_run was reached)", "args" in captured)
    check("PGUSER is percent-decoded",
          child_env.get("PGUSER") == "us@er", "env=%s" % child_env)
    check("PGPASSWORD is percent-decoded",
          child_env.get("PGPASSWORD") == "pa@ss", "env=%s" % child_env)
    check("query string sslmode becomes PGSSLMODE",
          child_env.get("PGSSLMODE") == "require", "env=%s" % child_env)
    check("query string connect_timeout becomes PGCONNECT_TIMEOUT",
          child_env.get("PGCONNECT_TIMEOUT") == "10", "env=%s" % child_env)
    check("the decoded username is absent from argv",
          not any("us@er" in str(a) for a in argv), "argv=%s" % argv)
    check("the decoded password is absent from argv",
          not any("pa@ss" in str(a) for a in argv), "argv=%s" % argv)
    check("the raw percent-encoded password is absent from argv",
          not any("pa%40ss" in str(a) for a in argv), "argv=%s" % argv)
    check("the raw DATABASE_URL is absent from argv",
          not any("us%40er:pa%40ss" in str(a) for a in argv), "argv=%s" % argv)


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


def main():
    print("Policy and profiles")
    test_policy_loads()
    print("\nRedaction")
    test_redaction()
    print("\nRegistration")
    test_marketplace_registration()

    print("\nDiscovery")
    test_discovery()
    test_discovery_symlink_escape()

    print("\nSecrets")
    test_secrets()
    test_secrets_untracked_env_is_not_confirmed()

    print("\nSignals")
    test_collect_signals()
    test_collect_signals_writes_nothing_into_projects()

    print("\nSibling scanners")
    test_siblings_absent_is_visible()
    test_siblings_attach()
    test_siblings_stale_findings_not_reused_after_crash()

    print("\nDB collector (optional mode, no live database)")
    test_db_collect()
    test_db_limit_and_pagination_warn()
    test_db_requires_no_credentials_in_argv()
    test_db_psql_credentials_never_reach_argv()
    test_db_psql_percent_encoded_credentials_and_query_options()
    test_db_config_rejects_missing_column()
    test_db_attach_metadata()
    test_db_attach_metadata_skips_missing_evidence()

    print("\nSchemas and task manifest")
    test_validator()
    test_schemas_shape()
    test_build_tasks()
    test_build_tasks_inlines_prior_findings()
    test_build_tasks_applies_profile_instructions()

    print("\nMerge, verdicts and re-audit")
    test_verdict_derivation()
    test_missing_and_invalid_agent_output()
    test_missing_security_output_is_unknown_risk()
    test_reaudit_carries_findings_forward()
    test_resolved_findings_do_not_raise_risk()

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
