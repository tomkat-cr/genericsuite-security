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


def mark_siblings_skipped(evidence_dir, reason):
    """Overwrite every evidence bundle's "siblings" with explicit
    unavailability sentinels - the same shape _siblings.py's own _empty()
    helper produces - so a --no-siblings run is visible as a blind spot
    instead of looking identical to two clean sibling scans."""
    sentinel = {"docker": {"available": False, "reason": reason, "findings": []},
                "packages": {"available": False, "reason": reason, "findings": []}}
    for fname in sorted(os.listdir(evidence_dir)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(evidence_dir, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                bundle = json.load(f)
        except (OSError, ValueError):
            continue
        bundle["siblings"] = sentinel
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Collect deterministic per-project signals.")
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--profile", default="generic")
    ap.add_argument("--no-siblings", action="store_true",
                    help="skip the sibling scanners; recorded as a blind spot")
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

    if not args.no_siblings:
        import _siblings
        res = _siblings.run_all(args.corpus, os.path.dirname(os.path.abspath(args.out)))
        _siblings.attach(args.out, res)
        for n, r in res.items():
            sys.stderr.write("sibling %s: %s\n" % (n, "ok" if r["available"] else r["reason"]))
    else:
        # --no-siblings must be recorded as a blind spot, not just an empty
        # "siblings": {} bundle. merge_insights.py's blind-spot loop only
        # fires on a sibling entry whose "available" key is False; an empty
        # dict has no such key, so a skipped run was previously
        # indistinguishable in the report from a run where both siblings ran
        # and found nothing. Write the same unavailability shape _siblings.py's
        # own _empty() helper produces, so that loop needs no changes.
        mark_siblings_skipped(args.out, "skipped by --no-siblings")

    return 0 if written else 2


if __name__ == "__main__":
    sys.exit(main())
