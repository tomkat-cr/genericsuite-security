#!/usr/bin/env python3
"""
_scanroots.py - Shared scan-scope policy for both scanners.

Default scope is the whole of $HOME, because payload artifacts are machine-level:
IDE persistence lands in ~/.claude and ~/.vscode, staged runtimes in TMPDIR, and
a compromised checkout can live in any directory, not just the one you thought to
name. Narrowing the scope is how a scan misses the thing it was run to find.

$HOME on macOS is ~2M files, roughly half of it caches and app containers that
cannot hold these IOCs. SKIP_SUFFIXES prunes that bulk. Every entry is either
machine-generated cache or opaque app storage - never source, never a checkout,
never an IDE config. IDE-relevant Library paths are deliberately NOT pruned.
"""
import os

# Directory basenames pruned everywhere.
SKIP_BASENAMES = {".git", ".hg", ".svn", "__pycache__", ".Trash"}

# Path suffixes pruned (matched against the directory's full path).
SKIP_SUFFIXES = (
    "Library/Caches",
    "Library/Containers",
    "Library/Group Containers",
    "Library/Developer/CoreSimulator",
    "Library/Developer/Xcode/DerivedData",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    "Library/Application Support/Slack",
    "Library/Application Support/Steam",
    "Library/Metadata",
    "Library/Mail",
    "Library/Photos",
    "Library/Safari",
    "Library/Suggestions",
)

# Never pruned even if they sit under a skipped parent - IDE persistence surface.
KEEP_SUFFIXES = (
    "Library/Application Support/Code/User",
    "Library/Application Support/Cursor",
    "Library/Application Support/Claude",
)


def default_roots():
    return [os.path.expanduser("~")]


def make_pruner(extra_skips=()):
    """Return prune(dirpath, dirnames) that edits dirnames in place."""
    suffixes = tuple(SKIP_SUFFIXES) + tuple(extra_skips)

    def keep(full):
        return any(full.endswith(k) for k in KEEP_SUFFIXES)

    def prune(dirpath, dirnames):
        out = []
        for d in dirnames:
            if d in SKIP_BASENAMES:
                continue
            full = os.path.join(dirpath, d)
            if d.endswith(".photoslibrary") or d.endswith(".xcodeproj"):
                continue
            if any(full.endswith(s) for s in suffixes) and not keep(full):
                continue
            out.append(d)
        dirnames[:] = out
    return prune
