#!/usr/bin/env python3
"""
probe.py - Adversarial verification, as a command.

THE MOST IMPORTANT STEP, AND THE ONE EVERY COMPARABLE TOOL OMITS.

The detection passes have bugs. In the original incident response they had
four, and this technique found all four: pick an image you KNOW is in use,
trace it through every file in the corpus, and then explain every hit the scan
did not report.

Each unexplained hit is either
  - a false negative: fix the detector, then re-sweep the WHOLE corpus for that
    pattern class, not just the one hit; or
  - a correct exclusion: the report should be able to say why.

Usage:
    python3 scripts/probe.py --corpus corpus.json nginx
    python3 scripts/probe.py --corpus corpus.json --findings out/findings.json redis

Exit: 0 every hit explained, 1 unexplained hits remain, 2 error.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(SKILL), "repo-corpus", "scripts"))

try:
    import _walk
except ImportError:
    sys.stderr.write("ERROR: repo-corpus skill not found alongside this one.\n")
    sys.exit(2)

from scan_images import PRUNE          # noqa: E402  same scope as the scan


def main(argv=None):
    p = argparse.ArgumentParser(description="Trace an image name through a corpus.")
    p.add_argument("name", help="image name or fragment, e.g. nginx")
    p.add_argument("--corpus", required=True)
    p.add_argument("--findings", help="findings.json from a scan of the same corpus")
    p.add_argument("--context", type=int, default=0, help="characters of line context")
    args = p.parse_args(argv)

    try:
        manifest = json.load(open(args.corpus, encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read corpus: {e}", file=sys.stderr)
        return 2

    explained = set()
    if args.findings and os.path.isfile(args.findings):
        data = json.load(open(args.findings, encoding="utf-8"))
        for f in data.get("findings", []):
            explained.add((f["repo"], f["file"].replace(os.sep, "/"), f["line"]))
        # An inventory entry is also an explanation: the scan saw the reference
        # and classified it as acceptable. Silence about it is a decision, not
        # an oversight - but only if the reference actually appears there.
        inventory = {i["reference"] for i in data.get("inventory", [])}
    else:
        inventory = set()

    rx = re.compile(re.escape(args.name), re.IGNORECASE)
    root = manifest["root"]
    total, unexplained = 0, []

    for entry in manifest.get("repos", []):
        if entry["status"] not in ("cloned", "local"):
            continue
        repo_path = os.path.join(root, entry["path"])
        if not os.path.isdir(repo_path):
            continue
        stats = _walk.WalkStats()
        for abspath, relpath in _walk.walk_files(repo_path, prune=PRUNE, stats=stats):
            text = _walk.read_text(abspath, stats)
            if text is None:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if not rx.search(line):
                    continue
                total += 1
                rel = relpath.replace(os.sep, "/")
                if (entry["name"], rel, i) in explained:
                    continue
                if any(args.name.lower() in inv.lower() for inv in inventory) \
                        and _looks_accounted(line, inventory):
                    continue
                unexplained.append((entry["name"], rel, i, line.strip()[:160]))

    print(f"'{args.name}': {total} hit(s) across the corpus, "
          f"{len(unexplained)} NOT explained by the scan\n")
    for repo, rel, line, txt in unexplained:
        print(f"  {repo}/{rel}:{line}")
        print(f"      {txt}")
    if unexplained:
        print("\nEach hit above is either a FALSE NEGATIVE - fix the detector, then")
        print("re-sweep the whole corpus for that pattern class, not just this hit -")
        print("or a correct exclusion the report should state a reason for.")
        return 1
    print("Every hit is accounted for by a finding or the classified inventory.")
    return 0


def _looks_accounted(line, inventory):
    """True when the line contains a reference the scan already inventoried."""
    return any(inv and inv in line for inv in inventory)


if __name__ == "__main__":
    sys.exit(main())
