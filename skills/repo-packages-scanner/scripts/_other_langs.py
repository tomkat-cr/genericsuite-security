#!/usr/bin/env python3
"""
_other_langs.py - Go, Rust, Ruby. One pass per ecosystem, each scoped to
exactly what the spec table lists - not a general dependency-file parser.
"""
import re

GO_REPLACE_RE = re.compile(r'^\s*replace\s+\S')

CARGO_SECTION_RE = re.compile(r'^\s*\[([^\]]+)\]\s*$')
CARGO_KV_RE = re.compile(r'^\s*([A-Za-z0-9_-]+)\s*=\s*(.+?)\s*$')

GEM_LINE_RE = re.compile(r'^\s*gem\s+["\']([A-Za-z0-9_.-]+)["\']\s*(,\s*(.+))?$')


def find_go_mod(text):
    """go.mod: `replace` directives and `@latest`/`vlatest`-style requires.
    Missing go.sum is a repo-level fact, checked by the caller."""
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if GO_REPLACE_RE.match(stripped):
            findings.append({"ref": stripped[:120], "class": "go-replace-directive",
                             "line": i,
                             "note": "replace directive - what actually builds may "
                                     "not match what go.mod declares"})
        if "latest" in stripped.lower() and stripped.split()[0] not in ("module", "go", "//"):
            findings.append({"ref": stripped[:120], "class": "go-mod-latest",
                             "line": i, "note": "@latest-style requirement"})
    return findings


def find_cargo_toml(text):
    """Cargo.toml: bare `*` version constraints. Whether Cargo.lock is
    expected depends on [[bin]]/[package] "*type" presence, decided by the
    caller (a library crate is not expected to commit it)."""
    findings = []
    section = None
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0]
        stripped = line.strip()
        if not stripped:
            continue
        sm = CARGO_SECTION_RE.match(stripped)
        if sm:
            section = sm.group(1)
            continue
        if section not in ("dependencies", "dev-dependencies", "build-dependencies"):
            continue
        kv = CARGO_KV_RE.match(stripped)
        if not kv:
            continue
        name, value = kv.groups()
        value = value.strip()
        if value == '"*"' or value.strip('"\'') == "*":
            findings.append({"ref": f"{name} = {value}", "class": "cargo-wildcard",
                             "line": i, "note": f"[{section}]"})
        elif value.startswith("{") and '"*"' in value:
            findings.append({"ref": f"{name} = {value}"[:120], "class": "cargo-wildcard",
                             "line": i, "note": f"[{section}] (table form)"})
    return findings


def has_bin_target(text):
    """A crate that builds a binary (not only a library) is the one where an
    uncommitted Cargo.lock actually matters for reproducibility."""
    return bool(re.search(r'^\s*\[\[bin\]\]', text, re.MULTILINE)) or \
        bool(re.search(r'^\s*\[package\]', text, re.MULTILINE)
             and "src/main.rs" in text)


def find_gemfile(text):
    """Gemfile: a `gem` line with no version argument at all."""
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = GEM_LINE_RE.match(stripped)
        if not m:
            continue
        name, _, rest = m.groups()
        if rest and re.search(r'["\']\s*[~<>=]', rest):
            continue           # has a version constraint of some form
        if rest and re.search(r'(git|github|path)\s*:', rest):
            continue           # sourced from git/path, not the version grammar
        findings.append({"ref": name, "class": "gemfile-unpinned", "line": i,
                         "note": "no version constraint"})
    return findings
