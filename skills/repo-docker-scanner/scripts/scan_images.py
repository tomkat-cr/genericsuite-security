#!/usr/bin/env python3
"""
scan_images.py - Find mutable container-image references across a corpus.

Consumes a corpus built by the repo-corpus skill. Static analysis only: no
cluster access, no image pulls, no chart rendering, and nothing from a scanned
repository is ever executed.

Exit codes:
    0  no findings at or above --fail-on
    1  findings at or above --fail-on
    2  error (bad corpus, unreadable policy, nothing scanned)

A clean result is only meaningful alongside what the scan could NOT see. Every
report ends with its residual blind spots, and the exit code never claims more
than the scan covered.
"""
import argparse
import fnmatch
import hashlib
import re
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
sys.path.insert(0, HERE)

# _walk.py is REUSED from repo-corpus rather than copied: two copies drift, and
# the pruning/unreadable-counting behaviour is exactly what must not differ
# between scanners.
CORPUS_SCRIPTS = os.path.join(os.path.dirname(SKILL), "repo-corpus", "scripts")
sys.path.insert(0, CORPUS_SCRIPTS)
try:
    import _walk
except ImportError:
    sys.stderr.write(
        "ERROR: cannot import _walk from the repo-corpus skill.\n"
        f"  Looked in: {CORPUS_SCRIPTS}\n"
        "  repo-docker-scanner consumes a corpus and shares repo-corpus's file\n"
        "  walking; install both skills side by side.\n")
    sys.exit(2)

import _classify        # noqa: E402
import _detectors       # noqa: E402
import _report          # noqa: E402

VERSION = "1.0"
TIERS = ["P0", "P1", "P2"]

# repo-corpus prunes `build/` and `dist/` by default, which is right for a
# generic walker and WRONG here: a Dockerfile in `build/` or a compose file in
# `dist/` is ordinary, and this scanner exists to find exactly those. The phase
# 1 plan (D5) called this out as the debatable pair and made the prune set
# overridable precisely so a consumer could make this call. The self-test plants
# a renamed Dockerfile under `build/` to keep it made.
PRUNE = {".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__",
         ".venv", "venv"}


def log(msg):
    print(msg, file=sys.stderr)


def load_policy(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def fingerprint(repo, filepath, normalized, klass):
    """Stable across line moves - deliberately excludes the line number, so an
    accepted risk stays accepted when a file shifts."""
    h = hashlib.sha256("\x00".join([repo, filepath, normalized, klass]).encode())
    return h.hexdigest()[:16]


def priority_for(relpath, repo_entry, policy, is_iac=False):
    if repo_entry.get("github", {}) and repo_entry["github"].get("isArchived"):
        return policy.get("archived_repo_tier", "P2"), "archived repository"
    if is_iac:
        # Caught by content, not by path: a CloudFormation template that
        # provisions EC2/ELB/etc is production desired state wherever it lives
        # in the tree, the same reasoning already applied to *.tf. A real org
        # run found exactly this gap - a docker reference inside
        # server/scripts/aws_ec2_elb/template-cf-ec2-elb.yml fell through every
        # path_glob rule to the P1 default, because no glob names
        # infrastructure templates by their content. Naming every possible
        # IaC directory convention is a losing game; sniffing the content the
        # same way Dockerfile discovery does is not.
        return (policy.get("infra_template_tier", "P0"),
               policy.get("infra_template_reason",
                          "CloudFormation template - provisions production infrastructure"))
    posix = relpath.replace(os.sep, "/")
    # Matched case-INsensitively, same reasoning as the Dockerfile name check in
    # _dockerfile.py: a rule glob like "**/Dockerfile*" must still catch
    # "dockerfile.dev" from a case-insensitive filesystem, or a genuine P0
    # workflow file on a filesystem/CI runner that happens to differ in case
    # would silently fall through to the P1 default instead.
    low = posix.lower()
    for rule in policy.get("priority_rules", []):
        when = rule.get("when", {})
        glob = when.get("path_glob")
        if glob is None:
            return rule["tier"], rule.get("why", "")
        glow = glob.lower()
        if fnmatch.fnmatch(low, glow) or fnmatch.fnmatch("/" + low, glow):
            return rule["tier"], rule.get("why", "")
    return "P1", "default"


def _excluded(posix, policy, args):
    """Paths deliberately not scanned.

    A scanner's own fixtures contain a planted example of everything it hunts
    for, so scanning itself reports the tool to itself. Exclusions are returned
    to the caller and COUNTED in the report: a silent exclusion is exactly how a
    real finding disappears (see the playbook's historical bug #3).
    """
    for glob in policy.get("self_exclude_globs", []):
        if fnmatch.fnmatch(posix, glob) or fnmatch.fnmatch("/" + posix, glob):
            return True
    for rx in getattr(args, "exclude", None) or []:
        if re.search(rx, posix):
            return True
    return False


def load_baseline(path):
    if not path or not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {e["fingerprint"]: e for e in data.get("accepted", [])}


def scan_corpus(manifest, policy, args):
    root = manifest["root"]
    findings, inventory, unparsed, watchlist, excluded = [], {}, [], {}, []
    stats_total = _walk.WalkStats()
    scanned_repos, skipped_repos = 0, []

    for entry in manifest.get("repos", []):
        if entry["status"] not in ("cloned", "local"):
            skipped_repos.append((entry["name"], entry["status"], entry.get("error")))
            continue
        repo_path = os.path.join(root, entry["path"])
        if not os.path.isdir(repo_path):
            skipped_repos.append((entry["name"], "missing", f"not on disk: {repo_path}"))
            continue
        scanned_repos += 1

        for abspath, relpath in _walk.walk_files(repo_path, prune=PRUNE,
                                                 stats=stats_total):
            posix = relpath.replace(os.sep, "/")
            if _excluded(posix, policy, args):
                excluded.append(f"{entry['name']}/{posix}")
                continue
            text = _walk.read_text(abspath, stats_total)
            if text is None:
                continue
            try:
                hits = _detectors.detect(relpath, text, policy)
            except Exception as e:                      # noqa: BLE001
                # A parser that crashes quietly on 20 files produces a report
                # that is clean because it looked at nothing. Crashes are data.
                unparsed.append({"repo": entry["name"], "file": relpath,
                                 "error": f"{e.__class__.__name__}: {e}"})
                continue

            is_iac = relpath.endswith(_detectors.YAML_EXT) and _detectors.is_cloudformation(text)

            for hit in hits:
                ref = hit["ref"]
                klass, reason = _classify.classify(ref, policy)
                # A template-composed reference (class "unresolved") is not a
                # real image reference, so running the digest/tag/namespace
                # splitter on it produces nonsense: normalize() partially
                # lowercased "${ECRRepositoryName}" to "${ecrrepositoryname}"
                # while leaving "${AWS::Region}" untouched elsewhere in the
                # same string, because the splitter happened to treat one
                # ${...} segment as the "name" component and another as part of
                # the "registry" host. That reads as the tool corrupting the
                # user's own text, which erodes trust in an otherwise-correct
                # finding. Keep unresolved references verbatim.
                norm = ref if klass == "unresolved" else _classify.normalize(ref)
                inventory[norm] = inventory.get(norm, 0) + 1
                flags = _classify.ownership_flags(ref, policy)
                acceptable = _classify.is_acceptable(klass, policy)
                # The playbook says to flag unverified/abandoned namespaces
                # "separately" - and separately is load-bearing. An abandoned
                # namespace is a concrete, known-dead dependency and is a
                # finding. An unverified Docker Hub namespace is most of Docker
                # Hub; promoting every `myorg/app:1.2.3` to a finding would bury
                # the unpinned ones it exists to surface. Those go to a watch
                # list instead, and still annotate any finding they touch.
                finding_flags = [f for f in flags
                                 if f[0] in policy.get("finding_flags", [])]
                if flags:
                    watchlist.setdefault(norm, {"reference": norm,
                                                "flags": [f[0] for f in flags],
                                                "why": [f[1] for f in flags],
                                                "occurrences": 0})
                    watchlist[norm]["occurrences"] += 1
                if acceptable and not finding_flags:
                    continue
                tier, why = priority_for(relpath, entry, policy, is_iac)
                findings.append({
                    "fingerprint": fingerprint(entry["name"], relpath, norm, klass),
                    "repo": entry["name"],
                    "file": relpath,
                    "line": hit["line"],
                    "reference": ref,
                    "normalized": norm,
                    "class": klass,
                    "class_reason": reason,
                    "acceptable_by_policy": acceptable,
                    "flags": [{"flag": f, "why": w} for f, w in flags],
                    "priority": tier,
                    "priority_reason": why,
                    "pass": hit["pass"],
                    "note": hit["note"],
                    "checked_out": entry.get("checked_out"),
                    "head": entry.get("head"),
                })

    # Deduplicate: passes overlap by design, so the same reference in the same
    # place is found more than once. Keep the first, record how many passes saw
    # it - agreement between passes is signal, not noise.
    seen = {}
    for f in findings:
        key = (f["repo"], f["file"], f["line"], f["normalized"])
        if key in seen:
            seen[key]["found_by"].append(f["pass"])
        else:
            f["found_by"] = [f["pass"]]
            seen[key] = f
    deduped = list(seen.values())

    return (deduped, inventory, unparsed, stats_total, scanned_repos,
            skipped_repos, watchlist, excluded)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Detect mutable container image references across a corpus.",
        epilog="Exit: 0 clean at threshold, 1 findings, 2 error.")
    p.add_argument("--corpus", required=True, metavar="CORPUS_JSON",
                   help="corpus.json produced by the repo-corpus skill")
    p.add_argument("--policy", default=os.path.join(SKILL, "policy", "images.json"))
    p.add_argument("--out", metavar="DIR", help="report directory")
    p.add_argument("--baseline", metavar="PATH", help="accepted-risk baseline JSON")
    p.add_argument("--fail-on", default="P0", choices=TIERS + ["none"],
                   help="lowest tier that makes this exit 1 (default P0)")
    p.add_argument("--exclude", action="append", metavar="REGEX",
                   help="skip paths matching this regex (repeatable); every "
                        "exclusion is counted and listed in the report")
    p.add_argument("--sarif", action="store_true", help="also emit findings.sarif")
    args = p.parse_args(argv)

    try:
        with open(args.corpus, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        log(f"ERROR: cannot read corpus {args.corpus}: {e}")
        return 2
    if manifest.get("schema_version") != 1:
        log(f"ERROR: unsupported corpus schema_version "
            f"{manifest.get('schema_version')!r}; this scanner speaks 1")
        return 2

    try:
        policy = load_policy(args.policy)
    except (OSError, json.JSONDecodeError) as e:
        log(f"ERROR: cannot read policy {args.policy}: {e}")
        return 2

    out = args.out or os.path.join(os.path.dirname(os.path.abspath(args.corpus)),
                                   "docker-scan")
    os.makedirs(out, exist_ok=True)

    (findings, inventory, unparsed, stats, scanned, skipped,
     watchlist, excluded) = scan_corpus(manifest, policy, args)

    baseline = load_baseline(args.baseline)
    for f in findings:
        f["baselined"] = f["fingerprint"] in baseline
        if f["baselined"]:
            f["baseline_reason"] = baseline[f["fingerprint"]].get("reason", "")
    active = [f for f in findings if not f["baselined"]]

    if scanned == 0:
        log("ERROR: no repository in the corpus was scannable - nothing was "
            "examined, so nothing is known.")
        return 2

    _report.write_all(out, active, findings, inventory, unparsed, stats,
                      manifest, policy, scanned, skipped, args, VERSION,
                      watchlist, excluded)

    counts = {t: sum(1 for f in active if f["priority"] == t) for t in TIERS}
    log(f"scanned {scanned} repo(s), {stats.files_seen} file(s)")
    log(f"findings: P0={counts['P0']} P1={counts['P1']} P2={counts['P2']}"
        f" (+{len(findings) - len(active)} baselined)")
    if unparsed:
        log(f"  {len(unparsed)} file(s) COULD NOT BE PARSED - see report")
    if stats.unreadable:
        log(f"  {len(stats.unreadable)} path(s) COULD NOT BE READ - unreadable is not clean")
    print(os.path.join(out, "report.md"))

    if args.fail_on == "none":
        return 0
    threshold = TIERS.index(args.fail_on)
    if any(TIERS.index(f["priority"]) <= threshold for f in active):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
