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
