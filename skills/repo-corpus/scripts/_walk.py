#!/usr/bin/env python3
"""
_walk.py - Shared file walking for every scanner that consumes a corpus.

WHY THIS IS NOT os.walk()
    Three failure modes, each of which produces a scan that reports "clean"
    over ground it never covered:

    1. os.walk() swallows PermissionError by default. A permission-denied
       subtree is silently skipped and the report says nothing. This package
       already paid for that bug once (see supply-chain-ioc-scan SKILL.md,
       "Unreadable is not clean"), so every unreadable path is counted here and
       the caller is expected to degrade its verdict accordingly.
    2. Cloned repositories are hostile input. A repo may contain
       `keys -> /home/you/.ssh` or `escape -> /`. Nothing yielded here ever
       resolves outside the root, so a scanner cannot be induced to read - or
       to report the contents of - a file the repo does not own.
    3. Pruning is invisible unless it is counted. `build/` and `dist/` are
       pruned by default and legitimately hold Dockerfiles and compose files.
       That is an acceptable default and an unacceptable secret, so
       prune_counts records it and reports are expected to state it.

Nothing in this module executes anything from a repository. It reads bytes.
"""
import os

# Pruned everywhere by default. `build`/`dist` are the debatable two: they can
# hold real scannable content, which is why pruning them is counted (see
# WalkStats.prune_counts) rather than assumed harmless.
DEFAULT_PRUNE = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "vendor", "dist", "build",
    "__pycache__", ".venv", "venv",
})

# Files above this are recorded as skipped rather than read. A 400MB vendored
# bundle is not worth the memory, but silently not reading it is how a scanner
# misses the one thing it was pointed at.
DEFAULT_MAX_BYTES = 2_000_000


class WalkStats:
    """Everything a report needs in order to state what the walk did not see."""

    def __init__(self):
        self.files_seen = 0
        self.dirs_pruned = 0
        self.prune_counts = {}
        self.unreadable = []          # (path, reason)
        self.symlinks_skipped = 0     # links resolving outside the root

    def note_pruned(self, basename):
        self.dirs_pruned += 1
        self.prune_counts[basename] = self.prune_counts.get(basename, 0) + 1

    def note_unreadable(self, path, reason):
        self.unreadable.append((str(path), str(reason)))

    @property
    def clean_coverage(self):
        """False when anything was unreadable - i.e. 'clean' needs a caveat."""
        return not self.unreadable

    def as_dict(self):
        return {
            "files_seen": self.files_seen,
            "dirs_pruned": self.dirs_pruned,
            "prune_counts": dict(sorted(self.prune_counts.items())),
            "unreadable": [{"path": p, "reason": r} for p, r in self.unreadable],
            "symlinks_skipped": self.symlinks_skipped,
        }

    def summary(self):
        s = f"{self.files_seen} file(s), {self.dirs_pruned} dir(s) pruned"
        if self.symlinks_skipped:
            s += f", {self.symlinks_skipped} escaping symlink(s) skipped"
        if self.unreadable:
            s += f", {len(self.unreadable)} PATH(S) COULD NOT BE READ"
        return s


def _within(root_real, path):
    """True if `path` resolves inside `root_real`. Hostile-symlink guard."""
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    return real == root_real or real.startswith(root_real + os.sep)


def walk_files(root, *, prune=None, extra_prune=(), no_prune=False, stats=None):
    """Yield (abspath, relpath) for every readable file under `root`.

    Directory symlinks are never descended. Any path - file or directory -
    resolving outside `root` is skipped and counted. Unreadable directories are
    counted, never silently dropped.
    """
    stats = stats if stats is not None else WalkStats()
    root = os.path.abspath(root)
    root_real = os.path.realpath(root)

    if no_prune:
        prune_set = frozenset()
    else:
        prune_set = frozenset(DEFAULT_PRUNE if prune is None else prune) | frozenset(extra_prune)

    if os.path.isfile(root):
        # os.walk() on a file yields nothing at all - a root passed as a file
        # would scan zero bytes and report clean. That exact bug is in this
        # package's history; handle the case rather than inherit it.
        stats.files_seen += 1
        yield root, os.path.basename(root)
        return

    if not os.path.isdir(root):
        stats.note_unreadable(root, "not a file or directory")
        return

    def onerror(err):
        stats.note_unreadable(getattr(err, "filename", root) or root,
                              err.__class__.__name__ + ": " + str(err))

    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror, followlinks=False):
        kept = []
        for d in dirnames:
            if d in prune_set:
                stats.note_pruned(d)
                continue
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                # os.walk(followlinks=False) already refuses to descend, but the
                # entry is still reported to us; count it so the report can say so.
                stats.symlinks_skipped += 1
                continue
            if not _within(root_real, full):
                stats.symlinks_skipped += 1
                continue
            kept.append(d)
        dirnames[:] = kept

        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if not _within(root_real, full):
                stats.symlinks_skipped += 1
                continue
            stats.files_seen += 1
            yield full, os.path.relpath(full, root)


def read_text(path, stats=None, max_bytes=DEFAULT_MAX_BYTES):
    """Decoded text, or None with the reason recorded in `stats`.

    Never raises for an unreadable file: the caller's job is to keep scanning,
    and the report's job is to say what could not be read.
    """
    try:
        size = os.path.getsize(path)
    except OSError as e:
        if stats is not None:
            stats.note_unreadable(path, f"stat failed: {e}")
        return None

    if size > max_bytes:
        if stats is not None:
            stats.note_unreadable(path, f"too large: {size} bytes > {max_bytes}")
        return None

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as e:
        if stats is not None:
            stats.note_unreadable(path, f"read failed: {e}")
        return None
