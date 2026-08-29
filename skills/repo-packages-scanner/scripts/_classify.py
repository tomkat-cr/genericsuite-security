#!/usr/bin/env python3
"""
_classify.py - Shared pin-classification and fingerprinting.

Unlike repo-docker-scanner, there is no single mutability table here: npm
ranges, PyPI constraints, Action refs, and Go/Rust/Ruby version specs each have
their own grammar for "is this pinned". Each pass classifies its own kind of
reference; this module holds only what is genuinely shared - the Action commit
SHA check and fingerprinting - so no pass duplicates it.
"""
import hashlib
import re

SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def is_commit_sha(ref):
    return bool(SHA40_RE.match(ref or ""))


def npm_range_class(spec):
    """Classify an npm/package.json version specifier.

    Returns (class_name, is_pinned). Per the spec table: ^, ~, *, x, latest,
    and bare >= ranges are ALL findings - the only pinned form is an exact
    version. A lockfile does not change this classification; it is reported
    separately (missing-lockfile is a repo-level fact, not a per-range one),
    because CI can still run `npm install` and ignore the lockfile.
    """
    s = (spec or "").strip()
    if not s:
        return "empty", True          # nothing to pin
    if s in ("*", "x", "X", "latest"):
        return "floating", False
    if s.startswith("^"):
        return "caret-range", False
    if s.startswith("~"):
        return "tilde-range", False
    if s.startswith(">=") or s.startswith(">") :
        return "unbounded-range", False
    if s.startswith("<") or s.startswith("<="):
        return "unbounded-range", False
    if "||" in s or " - " in s or "x" in s.lower().replace("0x", ""):
        # A range/OR expression, or an x-range like "1.2.x". Treat any
        # remaining non-exact grammar conservatively as unpinned rather than
        # silently classing it "exact" by falling through.
        return "range-expression", False
    if re.match(r"^\d+(\.\d+){0,2}([-.].+)?$", s):
        return "exact", True
    # A protocol specifier (file:, link:, workspace:, npm:, git+, github:) is
    # not a registry range at all - callers filter these via
    # known_benign_collisions before this is ever reached for that case, but
    # anything unrecognised here is reported rather than silently accepted.
    return "unrecognised", False


def pypi_constraint_class(spec):
    """Classify a PyPI/Poetry version constraint. Same shape as npm_range_class."""
    s = (spec or "").strip()
    if not s:
        return "empty", True
    if s in ("*",):
        return "floating", False
    if s.startswith("^"):
        return "caret-range", False
    if s.startswith("~="):
        return "compatible-release", True     # ~=1.4.2 pins to the 1.4.x patch train
    if s.startswith("~"):
        return "tilde-range", False
    if s.startswith(">=") or s.startswith(">"):
        return "unbounded-range", False
    if s.startswith("=="):
        return "exact", True
    if re.match(r"^\d+(\.\d+){0,2}([a-zA-Z0-9.]+)?$", s):
        return "exact", True               # bare "2.31.0" with no operator
    return "unrecognised", False


def fingerprint(repo, filepath, normalized, klass):
    """Stable across line moves - identical shape to repo-docker-scanner's,
    deliberately excludes the line number so accepted risk stays accepted when
    a file shifts. Two findings for the same reference in the same file on
    different lines therefore share a fingerprint (see SKILL.md)."""
    h = hashlib.sha256("\x00".join([repo, filepath, normalized, klass]).encode())
    return h.hexdigest()[:16]
