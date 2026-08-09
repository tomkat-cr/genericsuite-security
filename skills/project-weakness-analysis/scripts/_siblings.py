#!/usr/bin/env python3
"""
_siblings.py - Run repo-docker-scanner and repo-packages-scanner over the same
corpus and fold their findings into each project's evidence bundle.

WHY DEGRADATION MUST BE VISIBLE
    If a sibling scanner is missing or crashes, this records available=false
    with a reason. It NEVER records "no findings" for a scanner that never ran.
    That distinction is the whole point of this package: a falsely clean
    verdict is worse than no verdict.

NOTE ON --out vs --findings
    scan_images.py and scan_packages.py both take `--out DIR` (a report
    directory) and write `findings.json` inside it - there is no `--findings
    PATH` flag on either. This drives them with `--out` and reads
    `<out>/findings.json`, rather than a single-file flag that doesn't exist.
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

    out_dir = os.path.join(work_dir, "siblings", name)
    os.makedirs(out_dir, exist_ok=True)
    findings_path = os.path.join(out_dir, "findings.json")
    # Remove any findings.json left over from a prior run against this same
    # out_dir *before* invoking the scanner. Without this, a scanner crash
    # (uncaught exception -> exit 1, or a signal -> negative returncode) is
    # NOT caught by the `returncode == 2` check below, so run_one() falls
    # through to reading findings_path - silently attributing a stale prior
    # run's findings to this run and reporting available=true. Deleting the
    # file first guarantees a crash leaves nothing to read, so it correctly
    # lands in the `except (OSError, ValueError)` branch below instead.
    try:
        os.remove(findings_path)
    except FileNotFoundError:
        pass
    cmd = ["python3", script, "--corpus", corpus_path,
           "--out", out_dir, "--fail-on", "none"]
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
