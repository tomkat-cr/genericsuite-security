#!/usr/bin/env python3
"""
selftest.py - Positive control for repo-packages-scanner.

WHY THIS EXISTS
    A scanner that reports "clean" on everything is indistinguishable from a
    working one when the corpus is genuinely clean. This builds a synthetic
    repository containing a known positive for EVERY pass, asserts each fires,
    and asserts the documented benign lookalikes do NOT. It also asserts the
    priority-tier legend is generated from policy and cannot describe a
    different scanner's tiers - the exact bug that shipped once already in
    repo-docker-scanner's report.

Exit: 0 all assertions passed, 1 something is broken (do not trust a scan).
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
SCRIPTS = os.path.join(SKILL, "scripts")
REPO_ROOT = os.path.dirname(os.path.dirname(SKILL))
CORPUS_SCRIPTS = os.path.join(os.path.dirname(SKILL), "repo-corpus", "scripts")

sys.path.insert(0, SCRIPTS)
sys.path.insert(0, CORPUS_SCRIPTS)
import _actions          # noqa: E402
import _npm               # noqa: E402
import _pypi               # noqa: E402
import _remote_exec        # noqa: E402
import _other_langs        # noqa: E402
import _classify            # noqa: E402

GREEN, RED, YELLOW, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"
results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition)))
    tag = f"{GREEN}PASS{RESET}" if condition else f"{RED}FAIL{RESET}"
    print(f"  [{tag}] {name}" + (f"\n         {detail}" if detail and not condition else ""))


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


PINNED_SHA = "8f152de45cc393bb48ce5d89d36b731777c47a68"


def build_fixture(base):
    """One known positive per pass, plus the benign lookalikes that must not fire."""
    repo = os.path.join(base, "repos", "fixture")

    write(os.path.join(repo, ".github", "workflows", "ci.yml"), f"""jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@{PINNED_SHA}
      - uses: ./local-action
      - uses: docker://alpine:3.19
      - run: npm install
      - run: |
          curl -sSL https://get.example.sh | bash
""")
    write(os.path.join(repo, ".github", "workflows", "release.yml"), """jobs:
  publish:
    steps:
      - uses: actions/checkout@main
      - run: npm publish
""")

    write(os.path.join(repo, "package.json"), json.dumps({
        "dependencies": {"lodash": "^4.17.21", "left-pad": "1.3.0",
                         "local-dep": "file:../local-dep"},
        "scripts": {"postinstall": "node scripts/setup.js"},
    }))
    write(os.path.join(repo, ".npmrc"),
          "registry=https://registry.evil.example/\n"
          "@scoped:registry=https://registry.npmjs.org/\n")

    write(os.path.join(repo, "requirements.txt"),
          "requests>=2.0\nflask==2.0.0\n--index-url https://pypi.evil.example/simple\n")

    write(os.path.join(repo, "pyproject.toml"), """[tool.poetry]
name = "fixture"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.31.0"
flask = "2.0.0"
urllib3 = "~=1.26.0"
""")

    write(os.path.join(repo, "go.mod"), """module example.com/fixture
go 1.21

require foo/bar vlatest

replace foo/bar => ../local-fork
""")

    write(os.path.join(repo, "Cargo.toml"), """[package]
name = "fixture"

[[bin]]
name = "fixture"

[dependencies]
serde = "*"
regex = "1.10"
""")

    write(os.path.join(repo, "Gemfile"),
          'gem "rails"\ngem "pg", "~> 1.0"\ngem "priv", git: "https://internal/priv"\n')

    write(os.path.join(repo, "scripts", "setup.sh"),
          "#!/bin/sh\nwget -qO- https://example.com/install.sh | sudo bash\n"
          "pip install git+https://example.com/x.git\n"
          "go install example.com/tool@latest\n"
          "go install example.com/other\n")

    manifest = {
        "schema_version": 1,
        "generated_at": "2026-08-08T00:00:00Z",
        "generator": "selftest",
        "root": os.path.join(base, "repos"),
        "source": {"mode": "local", "target": None, "filters": {}},
        "totals": {"enumerated": 1, "selected": 1, "cloned": 1, "failed": 0},
        "repos": [{
            "name": "fixture", "path": "fixture", "status": "cloned",
            "error": None, "default_branch": "main", "checked_out": "main",
            "head": "0" * 40, "branches": [{"name": "main", "head": "0" * 40}],
            "github": {"isArchived": False, "isFork": False},
        }],
        "warnings": [],
    }
    mpath = os.path.join(base, "corpus.json")
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f)
    return mpath


def run_scan(corpus, out, extra=(), env_overrides=None):
    argv = [sys.executable, os.path.join(SCRIPTS, "scan_packages.py"),
            "--corpus", corpus, "--out", out, "--sarif", *extra]
    env = dict(os.environ)
    env.pop("PACKAGES_SCAN_INVOKED_CMD", None)
    if env_overrides:
        env.update(env_overrides)
    proc = subprocess.run(argv, capture_output=True, text=True, env=env)
    path = os.path.join(out, "findings.json")
    data = json.load(open(path)) if os.path.isfile(path) else {}
    return proc, data


def refs_of(data):
    return {(f["file"].replace(os.sep, "/"), f["reference"], f["class"])
           for f in data.get("findings", [])}


# ---------------------------------------------------------------------------

def test_unit_classify():
    check("a 40-hex string is recognised as a commit SHA",
          _classify.is_commit_sha(PINNED_SHA))
    check("a tag like v4 is NOT a commit SHA", not _classify.is_commit_sha("v4"))
    check("a short hex prefix is NOT a commit SHA (must be full 40)",
          not _classify.is_commit_sha(PINNED_SHA[:7]))

    npm_cases = [("^1.2.3", "caret-range", False), ("~1.2.3", "tilde-range", False),
                 ("*", "floating", False), ("x", "floating", False),
                 (">=1.2.3", "unbounded-range", False), ("1.2.3", "exact", True),
                 ("1.2.x", "range-expression", False)]
    bad = [(s, _classify.npm_range_class(s)) for s, want_cls, want_pin in npm_cases
           if _classify.npm_range_class(s) != (want_cls, want_pin)]
    check("npm range classification matches the spec table", not bad, f"{bad}")

    py_cases = [("^1.2.3", "caret-range", False), ("*", "floating", False),
                ("~=1.4.2", "compatible-release", True), (">=2.0", "unbounded-range", False),
                ("==2.31.0", "exact", True), ("2.31.0", "exact", True)]
    bad = [(s, _classify.pypi_constraint_class(s)) for s, want_cls, want_pin in py_cases
           if _classify.pypi_constraint_class(s) != (want_cls, want_pin)]
    check("PyPI constraint classification matches the spec table "
          "(~= is PEP 440's compatible-release operator, treated as pinned)",
          not bad, f"{bad}")


def test_positives(data):
    r = refs_of(data)
    def has(sub, ref=None, klass=None):
        return any(sub in f and (ref is None or ref == v)
                  and (klass is None or klass == c) for f, v, c in r)

    check("unpinned action (@v4) found", has("ci.yml", "actions/checkout@v4"), f"{sorted(r)}")
    check("pinned action (40-hex SHA) NOT reported",
          not has("ci.yml", f"actions/setup-node@{PINNED_SHA}"))
    check("local action (./local-action) NOT reported", not has("ci.yml", "./local-action"))
    check("unpinned docker:// action step found",
          has("ci.yml", "docker://alpine:3.19"), f"{sorted(r)}")
    check("npm install (not npm ci) in CI workflow found",
          has("ci.yml", klass="npm-install-in-ci"), f"{sorted(r)}")
    check("curl | bash inside a workflow run: BLOCK SCALAR found",
          has("ci.yml", klass="remote-pipe-to-shell"), f"{sorted(r)}")
    check("unpinned action in release.yml found (release/publish escalation target)",
          has("release.yml", "actions/checkout@main"), f"{sorted(r)}")

    check("npm caret-range dependency found", has("package.json", "lodash@^4.17.21"))
    check("npm postinstall hook found", has("package.json", klass="npm-install-hook"))
    check("npm registry override (non-default) in .npmrc found",
          has(".npmrc", "https://registry.evil.example/"), f"{sorted(r)}")
    check("missing npm lockfile found (package.json present, no lockfile committed)",
          has("package.json", klass="npm-missing-lockfile"), f"{sorted(r)}")

    check("PyPI unbounded range (requests>=2.0) found", has("requirements.txt", "requests>=2.0"))
    check("pip --index-url override found", has("requirements.txt", klass="pip-index-override"))
    check("missing --require-hashes found", has("requirements.txt", klass="pypi-missing-require-hashes"))
    check("Poetry caret-range dependency found", has("pyproject.toml", "requests ^2.31.0"))
    check("Poetry project with no lockfile found",
          has("pyproject.toml", klass="pypi-missing-lockfile"), f"{sorted(r)}")

    check("go.mod @latest-style require found", has("go.mod", klass="go-mod-latest"))
    check("go.mod replace directive found", has("go.mod", klass="go-replace-directive"))
    check("go.mod with no go.sum found", has("go.mod", klass="go-missing-sum"), f"{sorted(r)}")

    check("Cargo.toml wildcard dependency found", has("Cargo.toml", 'serde = "*"'))
    check("binary crate with no Cargo.lock found", has("Cargo.toml", klass="cargo-missing-lockfile"),
          f"{sorted(r)}")

    check("Gemfile gem with no version constraint found", has("Gemfile", "rails"))
    check("Gemfile with no Gemfile.lock found", has("Gemfile", klass="gemfile-missing-lockfile"),
          f"{sorted(r)}")

    check("wget | sudo bash found", has("setup.sh", klass="remote-pipe-to-shell"))
    check("pip install from a git+ URL found", has("setup.sh", klass="pip-install-url"))
    check("go install ...@latest found", has("setup.sh", klass="go-install-latest"))
    check("go install with no version at all found", has("setup.sh", klass="go-install-no-version"))


def test_negatives(data):
    r = refs_of(data)
    vals = {v for _, v, _ in r}
    check("a version-pinned npm dependency (left-pad@1.3.0) is not reported",
          "left-pad@1.3.0" not in vals, f"{sorted(vals)}")
    check("an npm file: protocol specifier is not reported",
          not any("local-dep" in v for v in vals), f"{sorted(vals)}")
    check("the default npm registry in .npmrc is not reported",
          not any("registry.npmjs.org" in v for v in vals), f"{sorted(vals)}")
    check("an exact-pinned PyPI requirement (flask==2.0.0) is not reported",
          "flask==2.0.0" not in vals, f"{sorted(vals)}")
    check("a Poetry ~= compatible-release constraint is not reported",
          not any("urllib3" in v for v in vals), f"{sorted(vals)}")
    check("the python interpreter constraint in [tool.poetry.dependencies] "
          "is not reported as a dependency",
          not any(v.startswith("python ") for v in vals), f"{sorted(vals)}")
    check("a pinned Rust dependency (regex = 1.10) is not reported",
          not any("regex" in v for v in vals), f"{sorted(vals)}")
    check("a git-sourced Gemfile entry is not reported",
          not any("priv" in v for v in vals), f"{sorted(vals)}")
    check("npm publish (not npm install) does not fire the install-not-ci pass",
          not any(c == "npm-install-in-ci" and "publish" in v for _, v, c in r))


def test_priority_and_tiers(data, out):
    md = open(os.path.join(out, "report.md"), encoding="utf-8").read()
    check("report states the priority tiers section", "## Priority tiers" in md)

    pol = json.load(open(os.path.join(SKILL, "policy", "packages.json")))
    rule_whys = {r["why"] for r in pol.get("priority_rules", []) if r.get("when") and r.get("why")}
    missing = [w for w in rule_whys if w.lower() not in md.lower()]
    check("every priority_rules reason for THIS policy appears in the legend",
          not missing, f"missing: {missing}")

    # The exact regression class that already shipped once in
    # repo-docker-scanner's report: hand-written prose describing a
    # DIFFERENT scanner's tiers. This policy's own P0 reason mentions
    # release/publish workflows and CI credentials - a leaked docker-scanner
    # vocabulary check here guards the mirror-image mistake.
    # NOT "digest": a docker:// action step (this scanner's own fixture plants
    # one) is legitimately pinned by digest too, so that word alone is not
    # foreign vocabulary here - only phrases specific to image mutability
    # classes are.
    foreign_vocab = ["mutability class", "docker.io", "container image",
                     "codename tag", "namespace watch list", "floating alias"]
    leaked = [v for v in foreign_vocab if v.lower() in md.lower()]
    check("the legend does not describe repo-docker-scanner's tiers "
          "(image/digest/namespace vocabulary has no place in this report)",
          not leaked, f"leaked: {leaked}")

    active = data["findings"]
    check("release/publish-workflow escalation: the unpinned action in "
          "release.yml is tiered P0 for THAT specific reason, not just the "
          "generic 'runs in CI' rule",
          any(f["file"].endswith("release.yml") and f["priority"] == "P0"
              and "release" in f["priority_reason"].lower() for f in active),
          f"{[f for f in active if 'release.yml' in f['file']]}")


def test_scan_command_and_repos_analyzed(corpus, base, data, out):
    check("findings.json records a reconstructed scan command when run directly",
          bool(data.get("scan_command")) and "scan_packages.py" in data["scan_command"]
          and "--corpus" in data["scan_command"], f"{data.get('scan_command')!r}")

    md = open(os.path.join(out, "report.md"), encoding="utf-8").read()
    check("report.md has a 'Scan command' section right after the summary, "
          "before 'Repositories and branches analyzed'",
          "## Scan command" in md
          and md.index("## Scan command") < md.index("## Repositories and branches analyzed"),
          "section missing or out of order")
    check("the reconstructed command appears in the report's command block",
          bool(data.get("scan_command")) and data["scan_command"] in md,
          f"{data.get('scan_command')!r}")

    check("findings.json lists which repo/branch/commit was actually analyzed",
          any(r["repo"] == "fixture" and r["branch"] == "main"
              and (r["head"] or "").startswith("0" * 12)
              for r in data.get("repos_analyzed", [])),
          f"{data.get('repos_analyzed')}")
    section = md.split("## Repositories and branches analyzed")[1].split("## Priority tiers")[0]
    check("report.md's analyzed-repos section lists it too",
          "fixture" in section and "main" in section, section[:200])

    out2 = os.path.join(base, "out-invoked-cmd")
    fake_cmd = "./scripts/run_packages_scan.sh --org tomkat-cr --include prico"
    _, data2 = run_scan(corpus, out2, env_overrides={"PACKAGES_SCAN_INVOKED_CMD": fake_cmd})
    check("PACKAGES_SCAN_INVOKED_CMD from the driver overrides the argv fallback",
          data2.get("scan_command") == fake_cmd, f"{data2.get('scan_command')!r}")


def test_report_shape(data, out, proc):
    check("scan exits 1 when P0 findings exist",
          proc.returncode == 1, f"exit={proc.returncode} stderr={proc.stderr[-300:]}")
    check("findings carry a fingerprint that excludes the line number",
          all(len(f["fingerprint"]) == 16 for f in data["findings"]))

    md = open(os.path.join(out, "report.md"), encoding="utf-8").read()
    check("report states its residual blind spots", "Residual blind spots" in md)

    sarif = json.load(open(os.path.join(out, "findings.sarif"), encoding="utf-8"))
    run = sarif["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    check("SARIF is 2.1.0 with the required structure",
          sarif["version"] == "2.1.0" and "$schema" in sarif
          and run["tool"]["driver"]["name"] and run["results"])
    check("every SARIF result resolves to a declared rule",
          all(res["ruleId"] in rule_ids for res in run["results"]))


def test_malformed_json(base):
    repo = os.path.join(base, "repos", "malformed")
    write(os.path.join(repo, "package.json"), "{ this is not valid json")
    manifest = {
        "schema_version": 1, "root": os.path.join(base, "repos"),
        "source": {"mode": "local", "target": None, "filters": {}}, "warnings": [],
        "totals": {}, "repos": [{
            "name": "malformed", "path": "malformed", "status": "cloned", "error": None,
            "default_branch": "main", "checked_out": "main", "head": "1" * 40,
            "branches": [{"name": "main", "head": "1" * 40}],
            "github": {"isArchived": False, "isFork": False},
        }],
    }
    mpath = os.path.join(base, "corpus-malformed.json")
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f)
    out = os.path.join(base, "out-malformed")
    proc, data = run_scan(mpath, out)
    check("a malformed package.json is recorded as unparsed, not a crash",
          proc.returncode in (0, 1) and data.get("totals", {}).get("unparsed_files") == 1,
          f"exit={proc.returncode} totals={data.get('totals')}")


def test_baseline(corpus, base, data):
    fp = next(f["fingerprint"] for f in data["findings"]
              if f["reference"] == "lodash@^4.17.21")
    bpath = os.path.join(base, "baseline.json")
    with open(bpath, "w", encoding="utf-8") as f:
        json.dump({"accepted": [{"fingerprint": fp, "reason": "demo only",
                                 "owner": "cr", "date": "2026-08-08"}]}, f)
    out2 = os.path.join(base, "out-baseline")
    _, data2 = run_scan(corpus, out2, ("--baseline", bpath))
    check("a baselined finding is suppressed",
          "lodash@^4.17.21" not in {f["reference"] for f in data2["findings"]})
    check("un-baselined findings survive", len(data2["findings"]) > 0)


def test_fail_on_and_unscannable(corpus, base):
    out = os.path.join(base, "out-failon")
    proc, _ = run_scan(corpus, out, ("--fail-on", "none"))
    check("--fail-on none exits 0 despite findings", proc.returncode == 0,
          f"exit={proc.returncode}")

    m = {"schema_version": 1, "root": base, "repos": [
        {"name": "gone", "path": "nope", "status": "failed",
         "error": "clone failed", "github": {}}], "warnings": [], "totals": {}}
    p = os.path.join(base, "empty-corpus.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(m, f)
    proc2, _ = run_scan(p, os.path.join(base, "out-empty"))
    check("a corpus with no scannable repo exits 2, never 0",
          proc2.returncode == 2, f"exit={proc2.returncode}")


def test_marketplace_registration():
    mp = os.path.join(REPO_ROOT, ".claude-plugin", "marketplace.json")
    data = json.load(open(mp))
    missing = []
    for plugin in data.get("plugins", []):
        for rel in plugin.get("skills", []):
            if not os.path.isdir(os.path.join(REPO_ROOT, rel)):
                missing.append(rel)
    check("every skill path registered in marketplace.json exists on disk",
          not missing, f"missing: {missing}")
    check("repo-packages-scanner itself is registered",
          any("repo-packages-scanner" in p for plugin in data.get("plugins", [])
              for p in plugin.get("skills", [])))


def main():
    print("repo-packages-scanner self-test\n")
    if not os.path.isdir(CORPUS_SCRIPTS):
        print(f"  {RED}repo-corpus skill not found at {CORPUS_SCRIPTS}{RESET}")
        return 1

    with tempfile.TemporaryDirectory(prefix="packages-scan-selftest-") as base:
        corpus = build_fixture(base)
        out = os.path.join(base, "out")
        proc, data = run_scan(corpus, out)
        if not data:
            print(f"  {RED}scan produced no findings.json{RESET}\n{proc.stderr}")
            return 1

        print("Unit classification")
        test_unit_classify()
        print("\nDetection passes (every pass must find its planted positive)")
        test_positives(data)
        print("\nKnown-benign lookalikes (must NOT fire)")
        test_negatives(data)
        print("\nPriority tiers (generated from policy, not hand-written)")
        test_priority_and_tiers(data, out)
        print("\nScan command and repos analyzed")
        test_scan_command_and_repos_analyzed(corpus, base, data, out)
        print("\nReport shape")
        test_report_shape(data, out, proc)
        print("\nMalformed input")
        test_malformed_json(base)
        print("\nBaseline and thresholds")
        test_baseline(corpus, base, data)
        test_fail_on_and_unscannable(corpus, base)
        print("\nRegistration")
        test_marketplace_registration()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n{passed}/{total} assertions passed")
    if passed != total:
        print(f"\n{RED}SELF-TEST FAILED - do not trust a scan from this code.{RESET}")
        return 1
    print(f"\n{GREEN}All assertions passed.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
