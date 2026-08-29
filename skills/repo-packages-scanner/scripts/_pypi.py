#!/usr/bin/env python3
"""
_pypi.py - PyPI / Python detection.

pyproject.toml is read with a small state-machine section scanner, not a full
TOML parser: Python's stdlib TOML support (`tomllib`) only arrived in 3.11, and
this package is stdlib-only with no version floor guaranteed that high. The
scanner only needs two shapes, both simple enough to track without a real
parser: `[tool.poetry.dependencies]` key/value lines, and PEP 621's
`dependencies = [ "...", ... ]` array. Anything else in the file is left alone,
the same "subset reader, not an implementation" approach as repo-docker-scanner's
_yamlish.py.
"""
import re

import _classify

REQ_LINE_RE = re.compile(
    r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([^\s;#]*)')
SECTION_RE = re.compile(r'^\s*\[([^\]]+)\]\s*$')
POETRY_KV_RE = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.+?)\s*$')


def find_requirements(text):
    """requirements*.txt: bare or >=-constrained entries are findings.
    --require-hashes anywhere in the file suppresses the missing-hashes note.
    """
    findings = []
    has_hashes_flag = "--require-hashes" in text
    has_index_override = False

    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("-r ", "-c ", "--requirement", "--constraint")):
            continue
        if stripped.startswith(("--index-url", "-i ", "--extra-index-url")):
            has_index_override = True
            findings.append({"ref": stripped[:120], "class": "pip-index-override",
                             "line": i,
                             "note": "custom index - dependency-confusion surface"})
            continue
        if stripped.startswith("-e ") or stripped.startswith("--editable"):
            continue           # editable/VCS installs are out of scope here
        if stripped.startswith("-"):
            continue           # other pip flags

        m = REQ_LINE_RE.match(stripped)
        if not m:
            continue
        name, _extras, op, ver = m.groups()
        if not op:
            findings.append({"ref": name, "class": "pypi-bare", "line": i,
                             "note": "no version constraint at all"})
            continue
        spec = op + ver
        if op in (">=", ">"):
            findings.append({"ref": f"{name}{spec}", "class": "pypi-unbounded-range",
                             "line": i, "note": "no upper bound"})
        elif op not in ("==", "~="):
            findings.append({"ref": f"{name}{spec}", "class": "pypi-range",
                             "line": i, "note": f"operator {op}"})

    if not has_hashes_flag and findings:
        findings.append({"ref": "requirements", "class": "pypi-missing-require-hashes",
                         "line": None,
                         "note": "no --require-hashes anywhere in the file"})
    return findings


def find_pyproject(text):
    """[tool.poetry.dependencies] key/value pins, and PEP 621's
    `dependencies = [...]` array. Neither is a full TOML implementation."""
    findings = []
    section = None
    in_pep621_array = False

    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0]
        stripped = line.strip()
        if not stripped:
            continue

        sm = SECTION_RE.match(stripped)
        if sm:
            section = sm.group(1)
            in_pep621_array = False
            continue

        if section == "tool.poetry.dependencies":
            kv = POETRY_KV_RE.match(stripped)
            if not kv:
                continue
            name, value = kv.groups()
            value = value.strip().strip('"\'')
            if name == "python":
                continue           # the interpreter constraint, not a dependency
            klass, pinned = _classify.pypi_constraint_class(value)
            if not pinned and klass != "empty":
                findings.append({"ref": f"{name} {value}", "class": f"poetry-{klass}",
                                 "line": i, "note": "[tool.poetry.dependencies]"})
            continue

        if re.match(r'^dependencies\s*=\s*\[\s*$', stripped):
            in_pep621_array = True
            continue
        if in_pep621_array:
            if stripped.startswith("]"):
                in_pep621_array = False
                continue
            entry = stripped.strip(",").strip().strip('"\'')
            if not entry:
                continue
            m = REQ_LINE_RE.match(entry)
            if not m:
                continue
            name, _extras, op, ver = m.groups()
            if not op:
                findings.append({"ref": entry, "class": "pep621-bare", "line": i,
                                 "note": "[project.dependencies]"})
            elif op in (">=", ">"):
                findings.append({"ref": entry, "class": "pep621-unbounded-range",
                                 "line": i, "note": "[project.dependencies]"})

    return findings


def declares_poetry_or_uv(text):
    return "[tool.poetry]" in text or "[tool.uv]" in text or "[tool.poetry.dependencies]" in text
