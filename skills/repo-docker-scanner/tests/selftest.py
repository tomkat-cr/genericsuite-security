#!/usr/bin/env python3
"""
selftest.py - Positive control for repo-docker-scanner.

WHY THIS EXISTS
    A scanner that reports "clean" on everything is indistinguishable from a
    working one when the corpus is genuinely clean. This builds a synthetic
    repository containing a known positive for EVERY pass, asserts each one is
    caught, and asserts that the documented benign lookalikes are NOT.

    The negative assertions matter as much as the positive ones. The source
    playbook's four grep-filter bugs all DELETED true findings, and every one
    of them made the report look cleaner. Each is a named assertion here.

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
import _classify        # noqa: E402
import _dockerfile      # noqa: E402
import _yamlish         # noqa: E402
import _detectors       # noqa: E402
import scan_images      # noqa: E402

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


def build_fixture(base):
    """One known positive per pass, plus the benign lookalikes that must not fire.

    The repo is deliberately rooted under a directory named `tilt`: historical
    bug #3 was a path-based exclusion matching the SEARCHED directory's own
    prefix and silently discarding every hit beneath it.
    """
    repo = os.path.join(base, "tilt", "repos", "fixture")

    write(os.path.join(repo, "Dockerfile"), """# syntax=docker/dockerfile:1
ARG NODE_VERSION=20
FROM node:${NODE_VERSION} AS builder
FROM whitfin/geoipupdate AS geoip
FROM node
FROM scratch
FROM builder AS final
COPY --from=geoip /a /b
COPY --from=busybox:1.36 /x /y
""")

    # A renamed Dockerfile must not evade every name-based pass.
    write(os.path.join(repo, "build", "image.txt"), """# comment first
ARG X=1
FROM ubuntu:latest
""")

    write(os.path.join(repo, "docker-compose.yml"), """services:
  web:
    image: nginx:latest
  db:
    image: postgres
  cache:
    postgresImage: redis:alpine
  ok:
    image: debian:bullseye-slim
  pinned:
    image: alpine@sha256:%s
  logo:
    image: logo.png
  ami:
    image: ami-0123456789abcdef0
""" % ("a" * 64))

    write(os.path.join(repo, ".gitlab-ci.yml"), """job:
  services:
    - name: mysql
      alias: db
""")

    write(os.path.join(repo, ".github", "workflows", "ci.yml"), """jobs:
  build:
    container:
      image: ghcr.io/org/builder:main
    steps:
      - run: |
          docker run --rm -v /tmp:/tmp \\
            someuser/tool \\
            --flag
""")

    write(os.path.join(repo, "chart", "values.yaml"), """image:
  repository: bitnamilegacy/keycloak
other:
  repository: myorg/app
  tag: "1.2.3"
charts:
  repository: https://charts.example.com
""")

    write(os.path.join(repo, "scripts", "dev.sh"), """#!/bin/sh
docker pull redis:latest
docker run --rm -e FOO=bar \\
  quay.io/org/thing:nightly
""")

    write(os.path.join(repo, ".devcontainer", "devcontainer.json"),
          json.dumps({"name": "dev", "image": "mcr.microsoft.com/devcontainers/base:dev"}))

    write(os.path.join(repo, "runner", "toolset-linux.json"),
          json.dumps({"docker": {"images": [{"image": "moby/buildkit:latest"}]}}))

    # Benign lookalikes: dbt columns (historical bug #4 - a generic
    # `reference:` key collided with 800+ of these).
    write(os.path.join(repo, "models", "schema.yml"), """models:
  - name: orders
    columns:
      - name: customer_id
        reference: analytics.customers.id
      - name: product_id
        reference: analytics.products.id
""")

    # A CloudFormation template, deliberately at a path no priority_rules glob
    # names (no .tf, no .github/, no kustomization.yaml). Real org run: a
    # docker reference inside such a file fell through to the P1 default
    # because nothing named "server/scripts/aws_ec2_elb/" as production. The
    # embedded reference is also template-composed, to catch normalize()
    # mangling a ${...} placeholder while classifying it.
    write(os.path.join(repo, "server", "scripts", "aws_ec2_elb", "template-cf-ec2-elb.yml"),
          """AWSTemplateFormatVersion: '2010-09-09'
Resources:
  LaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateData:
        UserData:
          Fn::Base64: !Sub |
            #!/bin/bash
            docker pull ${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/${ECRRepositoryName}:${ECRImageTag}
""")

    # Ordinary YAML that mentions "AWS::" only in prose/values, never as a
    # `Type:` key - must NOT be misidentified as CloudFormation by the sniff.
    write(os.path.join(repo, "docs", "notes.yml"),
          "note: this project deploys to AWS::S3 sometimes\n")

    manifest = {
        "schema_version": 1,
        "generated_at": "2026-08-07T00:00:00Z",
        "generator": "selftest",
        "root": os.path.join(base, "tilt", "repos"),
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
    argv = [sys.executable, os.path.join(SCRIPTS, "scan_images.py"),
            "--corpus", corpus, "--out", out, "--sarif", *extra]
    env = dict(os.environ)
    # Deterministic unless a test opts in: if this self-test were itself run
    # via run_docker_scan.sh, DOCKER_SCAN_INVOKED_CMD would already be set in
    # the environment and silently short-circuit the argv-fallback path below.
    env.pop("DOCKER_SCAN_INVOKED_CMD", None)
    if env_overrides:
        env.update(env_overrides)
    proc = subprocess.run(argv, capture_output=True, text=True, env=env)
    path = os.path.join(out, "findings.json")
    data = json.load(open(path)) if os.path.isfile(path) else {}
    return proc, data


def refs_of(data):
    return {(f["file"].replace(os.sep, "/"), f["reference"]) for f in data.get("findings", [])}


# --------------------------------------------------------------------------

def test_unit_parsers():
    text = "FROM whitfin/geoipupdate AS geoip\nFROM node\nFROM builder\n"
    imgs, _ = _dockerfile.parse("FROM x AS builder\n" + text)
    refs = [i["ref"] for i in imgs]
    check("BUG 1: `FROM <img> AS <alias>` is reported, not filtered out",
          "whitfin/geoipupdate" in refs, f"got {refs}")
    check("BUG 2: a one-word `FROM node` is reported, not filtered out",
          "node" in refs, f"got {refs}")
    check("a genuine stage reference (`FROM builder`) is NOT reported",
          "builder" not in refs, f"got {refs}")

    # Dockerfile discovery is by PREFIX and CASE-INSENSITIVE: `docker build -f`
    # accepts any filename, so per-environment variants (Dockerfile.dev/.prod)
    # are the norm; and macOS/Windows checkouts can carry a lowercase
    # `dockerfile` that behaves identically there while a case-sensitive match
    # silently skips it on Linux. A missed Dockerfile is a whole file's worth of
    # FROM lines absent from the report.
    dockerfile_names = ["Dockerfile", "Dockerfile.dev", "Dockerfile-api",
                        "Dockerfile_test", "api.Dockerfile", "api.dockerfile",
                        "Containerfile", "Containerfile.dev", "dockerfile",
                        "dockerfile.dev", "DOCKERFILE", "Dockerfile.j2",
                        "CONTAINERFILE.prod"]
    missed = [n for n in dockerfile_names if not _dockerfile.looks_like_dockerfile(n)]
    check("Dockerfile discovery matches every case/prefix variant",
          not missed, f"missed: {missed}")
    not_dockerfiles = ["docker-compose.yml", "Makefile", ".dockerignore"]
    false_positives = [n for n in not_dockerfiles if _dockerfile.looks_like_dockerfile(n)]
    check("Dockerfile discovery does not fire on unrelated filenames",
          not false_positives, f"false positives: {false_positives}")

    # The priority tier must not depend on filesystem case either - a Dockerfile
    # matched case-insensitively above still needs to land in the right tier, or
    # the fix above is only cosmetic (the finding exists but is silently
    # mistiered to the P1 default instead of its real rule).
    #
    # Comparing TIER ALONE is not enough here and passed vacuously on a broken
    # build during mutation testing: the Dockerfile-specific rule and the P1
    # catch-all default rule share the same tier, so a case match that falls
    # through to the default still "looks" P1 and hides the regression. The
    # priority_reason distinguishes "matched its own rule" from "fell through
    # to the default", so comparing the full (tier, why) pair is required.
    pol_for_tier = json.load(open(os.path.join(SKILL, "policy", "images.json")))
    entry = {"github": {}}
    expected = scan_images.priority_for("Dockerfile", entry, pol_for_tier)
    mistiered = [p for p in ("Dockerfile", "dockerfile.dev", "DOCKERFILE.prod",
                             "sub/DockerFile")
                if scan_images.priority_for(p, entry, pol_for_tier) != expected]
    check("priority tier AND reason for Dockerfile* is case-insensitive "
          "(not just falling through to the same-tier default)",
          not mistiered, f"mistiered: {mistiered}, expected {expected}")
    ci_tier, ci_why = scan_images.priority_for(".GITHUB/WORKFLOWS/ci.yml", entry, pol_for_tier)
    check("priority tier for CI workflow paths is case-insensitive",
          ci_tier == "P0" and "default" not in ci_why, f"got {(ci_tier, ci_why)}")

    pol = json.load(open(os.path.join(SKILL, "policy", "images.json")))
    table = [("nginx@sha256:" + "a" * 64, "digest"), ("i:1.27.4", "version"),
             ("i:14", "major_only"), ("i:pg16", "major_only"),
             ("i:bullseye-slim", "codename"), ("ubuntu:trusty", "codename"),
             ("i:stable", "floating_alias"), ("i:alpine", "versionless_variant"),
             ("i:latest", "latest"), ("i", "untagged"),
             ("${X}:1", "unresolved")]
    bad = [(r, _classify.classify(r, pol)[0]) for r, want in table
           if _classify.classify(r, pol)[0] != want]
    check("every row of the mutability table classifies as specified",
          not bad, f"mismatches: {bad}")
    check("a registry port is not mistaken for a tag",
          _classify.split_ref("h.io:5000/a/b:1.2")[3] == "1.2")
    check("normalize collapses docker.io/library/nginx and nginx",
          len({_classify.normalize(x) for x in
               ("nginx", "docker.io/nginx", "docker.io/library/nginx")}) == 1)

    got = {".".join(p): v for p, v, _ in _yamlish.walk(
        "a:\n  b:\n    - name: x\n      alias: y\n  c: |\n    image: NOPE\n")}
    check("the YAML reader keeps sequence context for sibling keys",
          got.get("a.b.[].alias") == "y", f"got {got}")
    check("the YAML reader does not read block-scalar bodies as keys",
          not any("NOPE" in v for v in got.values()), f"got {got}")

    check("is_cloudformation() recognises AWSTemplateFormatVersion",
          _detectors.is_cloudformation("AWSTemplateFormatVersion: '2010-09-09'\n"))
    check("is_cloudformation() recognises a `Type: AWS::...` resource block",
          _detectors.is_cloudformation("Resources:\n  X:\n    Type: AWS::EC2::Instance\n"))
    check("is_cloudformation() does NOT fire on prose merely mentioning AWS::",
          not _detectors.is_cloudformation(
              "note: this project deploys to AWS::S3 sometimes\n"))


def test_positives(data):
    r = refs_of(data)
    def has(sub, ref=None):
        return any(sub in f and (ref is None or ref == v) for f, v in r)

    check("Dockerfile: untagged personal-namespace image found",
          ("Dockerfile", "whitfin/geoipupdate") in r, f"{sorted(r)}")
    check("Dockerfile: bare `FROM node` found", ("Dockerfile", "node") in r)
    check("renamed Dockerfile found by content sniff",
          has("build/image.txt", "ubuntu:latest"), f"{sorted(r)}")
    check("compose: explicit :latest found", has("docker-compose.yml", "nginx:latest"))
    check("compose: untagged image found", has("docker-compose.yml", "postgres"))
    check("compose: non-standard image key (postgresImage) found",
          has("docker-compose.yml", "redis:alpine"))
    check("GitLab CI `- name:` service form found",
          has(".gitlab-ci.yml", "mysql"), f"{sorted(r)}")
    check("workflow container image with floating tag found",
          has("ci.yml", "ghcr.io/org/builder:main"))
    check("image on a `docker run \\` CONTINUATION line found",
          has("ci.yml", "someuser/tool"), f"{sorted(r)}")
    check("Helm repository with NO tag key found",
          has("values.yaml", "bitnamilegacy/keycloak"))
    check("inline docker pull in a shell script found",
          has("dev.sh", "redis:latest"))
    check("multi-line docker run in a shell script found",
          has("dev.sh", "quay.io/org/thing:nightly"))
    check("devcontainer.json image found",
          has("devcontainer.json", "mcr.microsoft.com/devcontainers/base:dev"))
    check("runner toolset JSON image found",
          has("toolset-linux.json", "moby/buildkit:latest"))
    check("BUG 3: findings under a path segment named `tilt` are not discarded",
          len(r) > 0 and all("/tilt/" not in f for f, _ in r), f"{sorted(r)}")

    cfn_ref = "${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/${ECRRepositoryName}:${ECRImageTag}"
    check("docker pull inside a CloudFormation UserData block scalar is found",
          has("template-cf-ec2-elb.yml", cfn_ref), f"{sorted(r)}")
    cfn_findings = [f for f in data["findings"] if "template-cf-ec2-elb.yml" in f["file"]]
    check("a CloudFormation-embedded reference is tiered P0 by content, "
          "even though its path matches no priority_rules glob",
          cfn_findings and all(f["priority"] == "P0" for f in cfn_findings)
          and all("CloudFormation" in f["priority_reason"] for f in cfn_findings),
          f"{cfn_findings}")
    check("a template-composed reference is NOT mangled by image-path "
          "normalization - normalize() partially lowercased "
          "${ECRRepositoryName} while leaving ${AWS::Region} untouched, "
          "which reads as the tool corrupting the user's own text",
          cfn_findings and all(f["normalized"] == cfn_ref for f in cfn_findings),
          f"{[f['normalized'] for f in cfn_findings]}")
    check("the same verbatim reference reaches the inventory unmangled",
          any(i["reference"] == cfn_ref for i in data["inventory"]),
          f"{[i['reference'] for i in data['inventory']]}")


def test_negatives(data):
    r = refs_of(data)
    vals = {v for _, v in r}
    files = {f for f, _ in r}
    check("BUG 4: dbt `reference:` columns do not fire",
          not any("schema.yml" in f for f in files),
          f"fired on: {[x for x in r if 'schema.yml' in x[0]]}")
    check("a digest-pinned image is not reported",
          not any(v.startswith("alpine@sha256:") for v in vals), f"{sorted(vals)}")
    check("an acceptable codename tag is not reported",
          "debian:bullseye-slim" not in vals, f"{sorted(vals)}")
    check("an asset path (logo.png) is not reported", "logo.png" not in vals)
    check("an Ansible AMI id is not reported",
          not any(v.startswith("ami-") for v in vals))
    check("`FROM scratch` is not reported", "scratch" not in vals)
    check("a chart repo URL is not reported",
          not any(v.startswith("https://charts") for v in vals))
    # A version-pinned image from an unverified Docker Hub namespace is NOT a
    # mutability finding - it is pinned. It belongs on the watch list, so the
    # unpinned references this report exists to surface stay visible.
    check("a version-pinned Helm mapping is not a mutability finding",
          "myorg/app:1.2.3" not in vals, f"{sorted(vals)}")


def test_watchlist(data):
    wl = {w["reference"]: w for w in data.get("namespace_watchlist", [])}
    check("an unverified namespace still reaches the watch list",
          "myorg/app:1.2.3" in wl, f"watchlist: {sorted(wl)}")
    check("an abandoned namespace is BOTH a finding and on the watch list",
          "bitnamilegacy/keycloak" in wl
          and any(f["reference"] == "bitnamilegacy/keycloak"
                  for f in data["findings"]), f"watchlist: {sorted(wl)}")
    check("an official-library image is not on the watch list",
          not any(w.startswith("nginx") for w in wl), f"watchlist: {sorted(wl)}")


def test_self_exclusion(base, corpus):
    """A scanner must not report its own fixtures - but must SAY it excluded them."""
    repo = os.path.join(base, "tilt", "repos", "fixture")
    write(os.path.join(repo, "skills", "repo-docker-scanner", "tests", "fx.yml"),
          "image: planted/should-not-be-reported:latest\n")
    out = os.path.join(base, "out-exclude")
    _, d = run_scan(corpus, out)
    vals = {f["reference"] for f in d["findings"]}
    check("the scanner does not report its own fixtures",
          "planted/should-not-be-reported:latest" not in vals, f"{sorted(vals)}")
    check("excluded files are COUNTED, not silently dropped",
          d["totals"]["excluded_files"] >= 1, f"{d['totals']}")
    check("excluded files are listed in the report",
          any("fx.yml" in e for e in d["excluded_files"]), f"{d['excluded_files']}")
    md = open(os.path.join(out, "report.md"), encoding="utf-8").read()
    check("the report names the exclusion section",
          "Files deliberately not scanned" in md)

    out2 = os.path.join(base, "out-userexclude")
    _, d2 = run_scan(corpus, out2, ("--exclude", r"docker-compose"))
    check("--exclude REGEX suppresses matching files and counts them",
          not any("docker-compose" in f["file"] for f in d2["findings"])
          and d2["totals"]["excluded_files"] > d["totals"]["excluded_files"],
          f"{d2['totals']}")


def test_report_shape(data, out, proc):
    check("scan exits 1 when P0 findings exist",
          proc.returncode == 1, f"exit={proc.returncode} stderr={proc.stderr[-300:]}")
    check("findings carry a fingerprint that excludes the line number",
          all(len(f["fingerprint"]) == 16 for f in data["findings"]))

    md = open(os.path.join(out, "report.md"), encoding="utf-8").read()
    check("report states the policy boundary it applied", "Policy applied" in md)
    check("report states its residual blind spots", "Residual blind spots" in md)
    check("report includes the registry inventory validation pass",
          "Registry inventory" in md)
    check("report warns that unreadable is not clean, when applicable",
          "Unreadable is not clean" in md or not data["totals"]["unreadable_paths"])

    # The priority-tier legend must be GENERATED from policy/images.json's
    # priority_rules, not hand-written prose. A hand-written version shipped
    # once already describing repo-packages-scanner's tiers (npm publish
    # pipelines, curl | bash) inside repo-docker-scanner's own report - two
    # unrelated scanners, one copy-pasted paragraph. Assert both directions:
    # every distinct rule reason from THIS policy is present, and vocabulary
    # belonging to the other scanner's tier model is absent.
    pol = json.load(open(os.path.join(SKILL, "policy", "images.json")))
    check("report states the priority tiers section", "## Priority tiers" in md)
    rule_whys = {r["why"] for r in pol.get("priority_rules", []) if r.get("when") and r.get("why")}
    missing_whys = [w for w in rule_whys if w.lower() not in md.lower()]
    check("every priority_rules reason for THIS policy appears in the legend",
          not missing_whys, f"missing: {missing_whys}")
    foreign_vocab = ["npm install", "curl | bash", "publish pipeline",
                     "publish workflow", "contributor setup"]
    leaked = [v for v in foreign_vocab if v.lower() in md.lower()]
    check("the legend does not describe repo-packages-scanner's tiers "
          "(npm/curl-bash/publish-pipeline vocabulary has no place in a "
          "container-image report)",
          not leaked, f"leaked: {leaked}")

    sarif = json.load(open(os.path.join(out, "findings.sarif"), encoding="utf-8"))
    run = sarif["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    check("SARIF is 2.1.0 with the required structure",
          sarif["version"] == "2.1.0" and "$schema" in sarif
          and run["tool"]["driver"]["name"] and run["results"])
    check("every SARIF result resolves to a declared rule",
          all(res["ruleId"] in rule_ids for res in run["results"]))
    check("every SARIF result has a location with a start line",
          all(res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
              for res in run["results"]))
    check("ownership flags are independent of tag class",
          any(any(fl["flag"] == "abandoned_namespace" for fl in f["flags"])
              for f in data["findings"]), "bitnamilegacy was not flagged")


def test_scan_command_and_repos_analyzed(corpus, base, data, out):
    # Fallback path: scan_images.py run directly, no DOCKER_SCAN_INVOKED_CMD.
    check("findings.json records a reconstructed scan command when run directly",
          bool(data.get("scan_command"))
          and "scan_images.py" in data["scan_command"]
          and "--corpus" in data["scan_command"],
          f"scan_command={data.get('scan_command')!r}")

    md = open(os.path.join(out, "report.md"), encoding="utf-8").read()
    check("report.md has a 'Scan command' section right after the summary, "
          "before 'Policy applied'",
          "## Scan command" in md
          and md.index("## Scan command") < md.index("## Policy applied"),
          "section missing or out of order")
    check("the reconstructed command appears in the report's command block",
          bool(data.get("scan_command")) and data["scan_command"] in md,
          f"command: {data.get('scan_command')!r}")

    # The fixture manifest declares repo "fixture" checked out on "main" at a
    # HEAD of all zeros (tests/selftest.py's build_fixture).
    check("findings.json lists which repo/branch/commit was actually analyzed",
          any(r["repo"] == "fixture" and r["branch"] == "main"
              and (r["head"] or "").startswith("0" * 12)
              for r in data.get("repos_analyzed", [])),
          f"repos_analyzed={data.get('repos_analyzed')}")
    check("report.md's 'Repositories and branches analyzed' section lists it too",
          "## Repositories and branches analyzed" in md
          and "fixture" in md.split("## Repositories and branches analyzed")[1]
                             .split("## Policy applied")[0]
          and "main" in md.split("## Repositories and branches analyzed")[1]
                          .split("## Policy applied")[0],
          "repo/branch missing from the markdown section")

    # DOCKER_SCAN_INVOKED_CMD (set by run_docker_scan.sh before it rewrites
    # $@) must take precedence over the argv fallback - it is the only way the
    # report can show the top-level command a user actually typed, since --org/
    # --include/--branch never reach scan_images.py's own argv at all.
    out2 = os.path.join(base, "out-invoked-cmd")
    fake_cmd = "./scripts/run_docker_scan.sh --org tomkat-cr --include prico --branch develop"
    _, data2 = run_scan(corpus, out2, env_overrides={"DOCKER_SCAN_INVOKED_CMD": fake_cmd})
    check("DOCKER_SCAN_INVOKED_CMD from the driver overrides the argv fallback",
          data2.get("scan_command") == fake_cmd, f"got {data2.get('scan_command')!r}")


def test_baseline(corpus, base, data):
    fp = next(f["fingerprint"] for f in data["findings"]
              if f["reference"] == "nginx:latest")
    bpath = os.path.join(base, "baseline.json")
    with open(bpath, "w", encoding="utf-8") as f:
        json.dump({"accepted": [{"fingerprint": fp, "reason": "demo only",
                                 "owner": "cr", "date": "2026-08-07"}]}, f)
    out2 = os.path.join(base, "out-baseline")
    _, data2 = run_scan(corpus, out2, ("--baseline", bpath))
    check("a baselined finding is suppressed",
          "nginx:latest" not in {f["reference"] for f in data2["findings"]})
    check("un-baselined findings survive", len(data2["findings"]) > 0)
    check("the baselined count is reported, not hidden",
          data2["totals"]["findings_baselined"] == 1,
          f"{data2['totals']}")


def test_fail_on(corpus, base):
    out = os.path.join(base, "out-failon")
    proc, _ = run_scan(corpus, out, ("--fail-on", "none"))
    check("--fail-on none exits 0 despite findings", proc.returncode == 0,
          f"exit={proc.returncode}")


def test_unscannable_corpus(base):
    """A corpus with nothing scannable must be an error, not a clean result."""
    m = {"schema_version": 1, "root": base, "repos": [
        {"name": "gone", "path": "nope", "status": "failed",
         "error": "clone failed", "github": {}}], "warnings": [], "totals": {}}
    p = os.path.join(base, "empty-corpus.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(m, f)
    proc, _ = run_scan(p, os.path.join(base, "out-empty"))
    check("a corpus with no scannable repo exits 2, never 0",
          proc.returncode == 2, f"exit={proc.returncode}")


def main():
    print("repo-docker-scanner self-test\n")
    if not os.path.isdir(CORPUS_SCRIPTS):
        print(f"  {RED}repo-corpus skill not found at {CORPUS_SCRIPTS}{RESET}")
        return 1

    with tempfile.TemporaryDirectory(prefix="docker-scan-selftest-") as base:
        corpus = build_fixture(base)
        out = os.path.join(base, "out")
        proc, data = run_scan(corpus, out)
        if not data:
            print(f"  {RED}scan produced no findings.json{RESET}\n{proc.stderr}")
            return 1

        print("Parsers and classification")
        test_unit_parsers()
        print("\nDetection passes (every pass must find its planted positive)")
        test_positives(data)
        print("\nKnown-benign lookalikes (must NOT fire)")
        test_negatives(data)
        print("\nNamespace watch list")
        test_watchlist(data)
        print("\nSelf-exclusion")
        test_self_exclusion(base, corpus)
        print("\nReport shape")
        test_report_shape(data, out, proc)
        print("\nScan command and repos analyzed")
        test_scan_command_and_repos_analyzed(corpus, base, data, out)
        print("\nBaseline and thresholds")
        test_baseline(corpus, base, data)
        test_fail_on(corpus, base)
        test_unscannable_corpus(base)

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
