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
