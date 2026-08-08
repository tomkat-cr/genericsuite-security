#!/usr/bin/env python3
"""
_remote_exec.py - unpinned remote code execution: the same threat class as an
unpinned dependency, just skipping the package manager entirely.

Reads raw text, not YAML/JSON structure - a `curl | bash` inside a workflow
`run: |` block scalar is exactly the case repo-docker-scanner's inline-docker
pass exists to catch for images, and the same reasoning applies here: any
structural reader would miss it, so this pass never depends on one.
"""
import re

_SHELLS = r"(?:sh|bash|zsh|dash)"
PIPE_TO_SHELL_RE = re.compile(
    r'\b(curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?' + _SHELLS + r'\b')
PROCESS_SUB_SHELL_RE = re.compile(
    r'\b(?:source|\.)\s+<\(\s*(curl|wget)\b')
PIP_URL_RE = re.compile(
    r'\bpip3?\s+install\b[^\n]*\b(https?://|git\+)')
GO_INSTALL_RE = re.compile(r'\bgo\s+install\s+([^\s]+)')


def _join_continuations(text):
    out, buf, start = [], None, None
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if buf is None:
            start, buf = i, line
        else:
            buf += " " + line.strip()
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1]
        else:
            out.append((buf, start))
            buf = None
    if buf is not None:
        out.append((buf, start))
    return out


def find_remote_exec(text):
    findings = []
    for logical, lineno in _join_continuations(text):
        stripped = logical.strip()
        if stripped.startswith("#"):
            continue

        m = PIPE_TO_SHELL_RE.search(logical)
        if m:
            findings.append({"ref": stripped[:160], "class": "remote-pipe-to-shell",
                             "line": lineno,
                             "note": f"{m.group(1)} piped directly into a shell"})

        m = PROCESS_SUB_SHELL_RE.search(logical)
        if m:
            findings.append({"ref": stripped[:160], "class": "remote-process-substitution",
                             "line": lineno,
                             "note": f"remote script sourced via process substitution "
                                     f"({m.group(1)})"})

        m = PIP_URL_RE.search(logical)
        if m:
            findings.append({"ref": stripped[:160], "class": "pip-install-url",
                             "line": lineno,
                             "note": "pip install from a URL rather than a registry version"})

        m = GO_INSTALL_RE.search(logical)
        if m:
            target = m.group(1)
            if "@" not in target:
                findings.append({"ref": target, "class": "go-install-no-version",
                                 "line": lineno, "note": "go install without @version"})
            elif target.endswith("@latest"):
                findings.append({"ref": target, "class": "go-install-latest",
                                 "line": lineno, "note": "go install ...@latest"})
    return findings
