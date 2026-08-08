#!/usr/bin/env python3
"""
scan_packages.py - Find mutable language-dependency references across a corpus.

Consumes a corpus built by the repo-corpus skill. Static analysis only by
default; nothing from a scanned repository is ever executed. `--resolve`
optionally shells out to `gh api` to enrich unpinned GitHub Actions with
ownership facts a static read cannot produce (D1) - never required, never
aborts the run on failure.

Exit codes (same contract as repo-docker-scanner):
    0  no findings at or above --fail-on
    1  findings at or above --fail-on
    2  error (bad corpus, unreadable policy, nothing scanned)
"""
import argparse
import fnmatch
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
sys.path.insert(0, HERE)

# _walk.py is REUSED from repo-corpus, not copied - see repo-docker-scanner for
# the same reasoning: two copies of pruning/unreadable-counting drift apart.
CORPUS_SCRIPTS = os.path.join(os.path.dirname(SKILL), "repo-corpus", "scripts")
sys.path.insert(0, CORPUS_SCRIPTS)
try:
    import _walk
except ImportError:
    sys.stderr.write(
        "ERROR: cannot import _walk from the repo-corpus skill.\n"
        f"  Looked in: {CORPUS_SCRIPTS}\n"
        "  repo-packages-scanner consumes a corpus and shares repo-corpus's file\n"
        "  walking; install both skills side by side.\n")
    sys.exit(2)

import _actions        # noqa: E402
import _npm             # noqa: E402
import _pypi            # noqa: E402
import _remote_exec     # noqa: E402
import _other_langs     # noqa: E402
import _classify        # noqa: E402
import _report          # noqa: E402

VERSION = "1.0"
TIERS = ["P0", "P1", "P2"]

YAML_EXT = (".yml", ".yaml")
SHELLISH = (".sh", ".bash", ".zsh", ".mk")


def log(msg):
    print(msg, file=sys.stderr)


def load_policy(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def scan_command():
    """The command that produced this report - see repo-docker-scanner's
    identical helper for why the env var takes precedence over argv."""
    env_cmd = os.environ.get("PACKAGES_SCAN_INVOKED_CMD")
    if env_cmd:
        return env_cmd
    return shlex.join([os.path.basename(sys.argv[0])] + sys.argv[1:])


def fingerprint(repo, filepath, normalized, klass):
    h = hashlib.sha256("\x00".join([repo, filepath, normalized, klass]).encode())
    return h.hexdigest()[:16]


def _excluded(posix, policy, args):
    for glob in policy.get("self_exclude_globs", []):
        if fnmatch.fnmatch(posix, glob) or fnmatch.fnmatch("/" + posix, glob):
            return True
    for rx in getattr(args, "exclude", None) or []:
        if re.search(rx, posix):
            return True
    return False


def priority_for(relpath, repo_entry, policy, text=""):
    if repo_entry.get("github", {}) and repo_entry["github"].get("isArchived"):
        return policy.get("archived_repo_tier", "P2"), "archived repository"
    posix = relpath.replace(os.sep, "/")
    haystack = (posix + "\n" + (text or "")).lower()
    for rule in policy.get("priority_rules", []):
        when = rule.get("when", {})
        glob = when.get("path_glob")
        content_any = when.get("content_contains_any")
        if not when:
            return rule["tier"], rule.get("why", "")
        if glob is not None:
            low = posix.lower()
            glow = glob.lower()
            if not (fnmatch.fnmatch(low, glow) or fnmatch.fnmatch("/" + low, glow)):
                continue
        if content_any is not None:
            if not any(marker.lower() in haystack for marker in content_any):
                continue
        return rule["tier"], rule.get("why", "")
    return "P1", "default"


def _basename_matches(basename, patterns):
    low = basename.lower()
    return any(low == p.lower() for p in patterns)


def _is_ci_file(relpath):
    posix = relpath.replace(os.sep, "/")
    base = os.path.basename(posix)
    return ("/.github/workflows/" in "/" + posix and base.endswith((".yml", ".yaml"))) or \
        base.startswith(".gitlab-ci")


def _is_action_definition(relpath):
    base = os.path.basename(relpath)
    posix = relpath.replace(os.sep, "/")
    return base in ("action.yml", "action.yaml") or "/.github/actions/" in "/" + posix


def detect_in_file(relpath, text, policy):
    """Dispatch every pass that applies to this file. Returns raw hits:
    {ref, class, note, line}. May raise on malformed package.json/pyproject -
    the caller records that as unparsed, never a silent skip."""
    base = os.path.basename(relpath)
    low = base.lower()
    hits = []

    if low == "package.json":
        hits += _npm.parse_package_json(text, policy)
    if low == ".npmrc":
        hits += _npm.find_npmrc_registry_overrides(text, policy)
    if _is_ci_file(relpath) or _is_action_definition(relpath):
        for target, ref, line, kind in _actions.find_uses(text):
            if kind == "local":
                continue
            if kind == "docker":
                # A docker:// action reference: flagged unpinned unless it
                # carries a digest. Mutability CLASSIFICATION of the image
                # itself is repo-docker-scanner's job; this is only "is the
                # action step pinned".
                pinned = "@sha256:" in target
                if not pinned:
                    hits.append({"ref": f"docker://{target}", "class": "action-docker-unpinned",
                                "line": line, "note": "docker:// action step, no digest"})
                continue
            if ref is None:
                hits.append({"ref": target, "class": "action-malformed", "line": line,
                             "note": "uses: with no @ref"})
                continue
            if not _classify.is_commit_sha(ref):
                hits.append({"ref": f"{target}@{ref}", "class": "action-unpinned",
                             "line": line, "note": f"uses: {target}@{ref}"})
        if _is_ci_file(relpath):
            hits += _npm.find_ci_install_not_ci(text, relpath)
    if low.startswith("requirements") and low.endswith(".txt"):
        hits += _pypi.find_requirements(text)
    if low == "pyproject.toml":
        hits += _pypi.find_pyproject(text)
    if low == "go.mod":
        hits += _other_langs.find_go_mod(text)
    if low == "cargo.toml":
        hits += _other_langs.find_cargo_toml(text)
    if low == "gemfile":
        hits += _other_langs.find_gemfile(text)
    if (relpath.endswith(SHELLISH) or low.startswith("makefile")
            or _is_ci_file(relpath)):
        hits += _remote_exec.find_remote_exec(text)

    return hits


class RepoState:
    """Per-repo bookkeeping for the repo-level "missing lockfile" facts, which
    are not about any single file."""

    def __init__(self):
        self.package_json = None
        self.npm_lockfile = False
        self.pyproject = None
        self.pyproject_text = ""
        self.requirements = False
        self.pypi_lockfile = False
        self.go_mod = None
        self.go_sum = False
        self.cargo_toml = None
        self.cargo_toml_text = ""
        self.cargo_lockfile = False
        self.gemfile = None
        self.gemfile_lockfile = False

    def observe(self, relpath, text, policy):
        base = os.path.basename(relpath)
        low = base.lower()
        if low == "package.json":
            self.package_json = relpath
        elif low in [n.lower() for n in policy.get("npm_lockfile_names", [])]:
            self.npm_lockfile = True
        elif low == "pyproject.toml":
            self.pyproject = relpath
            self.pyproject_text = text
        elif low.startswith("requirements") and low.endswith(".txt"):
            self.requirements = True
        elif low in [n.lower() for n in policy.get("pypi_lockfile_names", [])]:
            self.pypi_lockfile = True
        elif low == "go.mod":
            self.go_mod = relpath
        elif low == policy.get("go_lockfile_name", "go.sum").lower():
            self.go_sum = True
        elif low == "cargo.toml":
            self.cargo_toml = relpath
            self.cargo_toml_text = text
        elif low == policy.get("rust_lockfile_name", "Cargo.lock").lower():
            self.cargo_lockfile = True
        elif low == "gemfile":
            self.gemfile = relpath
        elif low == policy.get("ruby_lockfile_name", "Gemfile.lock").lower():
            self.gemfile_lockfile = True

    def missing_lockfile_findings(self, policy):
        out = []
        if self.package_json and not self.npm_lockfile:
            out.append((self.package_json, {"ref": "npm lockfile", "class": "npm-missing-lockfile",
                        "line": None, "note": "package.json with no committed lockfile"}))
        if self.pyproject and _pypi.declares_poetry_or_uv(self.pyproject_text) \
                and not self.pypi_lockfile:
            out.append((self.pyproject, {"ref": "pypi lockfile", "class": "pypi-missing-lockfile",
                        "line": None, "note": "poetry/uv project with no committed lockfile"}))
        if self.go_mod and not self.go_sum:
            out.append((self.go_mod, {"ref": "go.sum", "class": "go-missing-sum", "line": None,
                        "note": "go.mod with no committed go.sum"}))
        if self.cargo_toml and _other_langs.has_bin_target(self.cargo_toml_text) \
                and not self.cargo_lockfile:
            out.append((self.cargo_toml, {"ref": "Cargo.lock", "class": "cargo-missing-lockfile",
                        "line": None, "note": "binary crate with no committed Cargo.lock"}))
        if self.gemfile and not self.gemfile_lockfile:
            out.append((self.gemfile, {"ref": "Gemfile.lock", "class": "gemfile-missing-lockfile",
                        "line": None, "note": "Gemfile with no committed Gemfile.lock"}))
        return out


def scan_corpus(manifest, policy, args):
    root = manifest["root"]
    findings, unparsed, excluded, analyzed = [], [], [], []
    stats_total = _walk.WalkStats()
    scanned_repos, skipped_repos = 0, []
    unpinned_actions = []          # for --resolve enrichment

    for entry in manifest.get("repos", []):
        if entry["status"] not in ("cloned", "local"):
            skipped_repos.append((entry["name"], entry["status"], entry.get("error")))
            continue
        repo_path = os.path.join(root, entry["path"])
        if not os.path.isdir(repo_path):
            skipped_repos.append((entry["name"], "missing", f"not on disk: {repo_path}"))
            continue
        scanned_repos += 1
        analyzed.append({
            "repo": entry["name"],
            "branch": entry.get("checked_out") or entry.get("default_branch"),
            "head": entry.get("head"),
            "path": entry.get("path"),
        })
        state = RepoState()

        for abspath, relpath in _walk.walk_files(repo_path, stats=stats_total):
            posix = relpath.replace(os.sep, "/")
            if _excluded(posix, policy, args):
                excluded.append(f"{entry['name']}/{posix}")
                continue
            text = _walk.read_text(abspath, stats_total)
            if text is None:
                continue

            state.observe(relpath, text, policy)

            try:
                hits = detect_in_file(relpath, text, policy)
            except Exception as e:                       # noqa: BLE001
                unparsed.append({"repo": entry["name"], "file": relpath,
                                 "error": f"{e.__class__.__name__}: {e}"})
                continue

            for hit in hits:
                tier, why = priority_for(relpath, entry, policy, text)
                f = _make_finding(entry, relpath, hit, tier, why)
                findings.append(f)
                if hit["class"] == "action-unpinned":
                    unpinned_actions.append(f)

        for filepath, hit in state.missing_lockfile_findings(policy):
            tier, why = priority_for(filepath, entry, policy)
            findings.append(_make_finding(entry, filepath, hit, tier, why))

    if getattr(args, "resolve", False) and unpinned_actions:
        _resolve_action_ownership(unpinned_actions)

    return (findings, unparsed, stats_total, scanned_repos, skipped_repos,
            excluded, analyzed)


def _make_finding(entry, relpath, hit, tier, why):
    ref = hit["ref"]
    norm = ref.strip()
    return {
        "fingerprint": fingerprint(entry["name"], relpath, norm, hit["class"]),
        "repo": entry["name"],
        "file": relpath,
        "line": hit["line"],
        "reference": ref,
        "normalized": norm,
        "class": hit["class"],
        "note": hit["note"],
        "priority": tier,
        "priority_reason": why,
        "flags": [],
        "checked_out": entry.get("checked_out"),
        "head": entry.get("head"),
    }


def _resolve_action_ownership(unpinned_actions):
    """Best-effort, network-backed enrichment: is the action's owner a
    personal account, and is the upstream repo archived? Never required,
    never aborts the run - a failure here is recorded per-action and the
    static findings stand regardless (D1)."""
    if not shutil.which("gh"):
        log("  --resolve: gh CLI not found - action ownership NOT resolved. "
            "Findings above are unaffected; this only skips the enrichment.")
        return

    cache = {}

    def gh_json(*args):
        try:
            proc = subprocess.run(["gh", "api", *args], capture_output=True,
                                  text=True, timeout=15)
            if proc.returncode != 0:
                return None
            return json.loads(proc.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return None

    for f in unpinned_actions:
        target = f["reference"].split("@", 1)[0]
        parts = target.split("/")
        if len(parts) < 2:
            continue
        owner, repo = parts[0], parts[1]
        key = (owner, repo)
        if key not in cache:
            user_info = gh_json(f"users/{owner}")
            repo_info = gh_json(f"repos/{owner}/{repo}")
            cache[key] = {
                "personal": bool(user_info) and user_info.get("type") == "User",
                "archived": bool(repo_info) and repo_info.get("archived") is True,
                "resolved": user_info is not None or repo_info is not None,
            }
        info = cache[key]
        if not info["resolved"]:
            continue
        if info["personal"]:
            f["flags"].append({"flag": "personal-account",
                               "why": f"'{owner}' is a personal GitHub account, not "
                                      f"an organization"})
        if info["archived"]:
            f["flags"].append({"flag": "archived-upstream",
                               "why": f"{owner}/{repo} is archived - unmaintained"})


def load_baseline(path):
    if not path or not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {e["fingerprint"]: e for e in data.get("accepted", [])}


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Detect mutable language-dependency and Action references "
                    "across a corpus.",
        epilog="Exit: 0 clean at threshold, 1 findings, 2 error.")
    p.add_argument("--corpus", required=True, metavar="CORPUS_JSON")
    p.add_argument("--policy", default=os.path.join(SKILL, "policy", "packages.json"))
    p.add_argument("--out", metavar="DIR")
    p.add_argument("--baseline", metavar="PATH")
    p.add_argument("--fail-on", default="P0", choices=TIERS + ["none"])
    p.add_argument("--exclude", action="append", metavar="REGEX")
    p.add_argument("--resolve", action="store_true",
                   help="enrich unpinned Actions with owner/archived status via "
                        "`gh api` (network, best-effort, never required)")
    p.add_argument("--sarif", action="store_true")
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
                                   "packages-scan")
    os.makedirs(out, exist_ok=True)

    (findings, unparsed, stats, scanned, skipped, excluded,
     analyzed) = scan_corpus(manifest, policy, args)

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

    _report.write_all(out, active, findings, unparsed, stats, manifest, policy,
                      scanned, skipped, args, VERSION, excluded, analyzed,
                      scan_command())

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
