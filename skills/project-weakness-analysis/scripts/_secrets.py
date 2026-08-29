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
