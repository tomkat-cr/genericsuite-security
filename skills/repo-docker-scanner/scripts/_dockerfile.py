#!/usr/bin/env python3
"""
_dockerfile.py - A Dockerfile parser, deliberately not a grep.

WHY A PARSER
    The source playbook shipped two grep-filter bugs, both of which DELETED
    real findings, and both of which look reasonable written down:

      1. Excluding lines containing " AS " to skip stage definitions also
         deleted `FROM whitfin/geoipupdate AS geoip` - an untagged
         personal-account image in a production image build.
      2. Excluding one-word FROM targets to skip stage references
         (`FROM builder`) also deleted genuine untagged images (`FROM node`).

    Both are regression assertions in tests/selftest.py. A filter that removes
    true positives is worse than no filter: the report looks cleaner and is
    wrong.

The parser joins backslash continuations, substitutes ARG defaults, tracks
stage aliases so `FROM builder` is skipped while `FROM node` is not, strips
--platform, skips scratch, and additionally reads COPY --from= and
RUN --mount=...,from= for non-stage image sources.
"""
import re

FROM_RE = re.compile(r"^\s*FROM\s+(.*)$", re.IGNORECASE)
ARG_RE = re.compile(r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", re.IGNORECASE)
ARG_BARE_RE = re.compile(r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", re.IGNORECASE)
COPY_FROM_RE = re.compile(r"^\s*COPY\s+.*?--from=([^\s]+)", re.IGNORECASE)
MOUNT_FROM_RE = re.compile(r"^\s*RUN\s+.*?--mount=[^\s]*\bfrom=([A-Za-z0-9._/:@-]+)",
                           re.IGNORECASE)
PLATFORM_RE = re.compile(r"--platform=[^\s]+\s*", re.IGNORECASE)
VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")

# Filenames that are Dockerfiles by name.
NAME_PATTERNS = (
    re.compile(r"^Dockerfile"),
    re.compile(r"\.dockerfile$", re.IGNORECASE),
    re.compile(r"^Containerfile"),
)


def looks_like_dockerfile(basename):
    return any(p.search(basename) for p in NAME_PATTERNS)


def sniff_is_dockerfile(text, max_lines=25):
    """Content sniff for a RENAMED Dockerfile.

    A renamed Dockerfile evades every name-based pass, so the early lines are
    checked: comments, `# syntax=` and ARG may precede the first instruction,
    but a Dockerfile's first real instruction is FROM (or ARG then FROM).
    """
    seen = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        seen += 1
        if seen > max_lines:
            return False
        if FROM_RE.match(line):
            return True
        if ARG_RE.match(line) or ARG_BARE_RE.match(line):
            continue
        return False
    return False


def _join_continuations(text):
    """Yield (logical_line, line_number_of_first_physical_line)."""
    out = []
    buf, start = None, None
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\n")
        stripped = line.strip()
        # A comment inside a continuation is ignored by Docker; drop it so it
        # cannot terminate or corrupt the logical line.
        if buf is not None and stripped.startswith("#"):
            continue
        if buf is None:
            start = i
            buf = line
        else:
            buf += " " + stripped
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1]
        else:
            out.append((buf, start))
            buf, start = None, None
    if buf is not None:
        out.append((buf, start))
    return out


def _substitute(value, args):
    """Replace $VAR / ${VAR} / ${VAR:-default} using collected ARG defaults."""
    def repl(m):
        name = m.group(1) or m.group(3)
        default = m.group(2)
        if name in args and args[name]:
            return args[name]
        if default is not None:
            return default
        return m.group(0)          # unresolved: left visible, flagged upstream
    return VAR_RE.sub(repl, value)


def parse(text):
    """Return (images, stages).

    images: list of dicts {ref, line, instruction, stage_alias}
      - every FROM whose target is NOT a previously defined stage alias
      - every COPY --from= / RUN --mount=from= whose target is not a stage
    stages: the set of stage aliases defined in this file
    """
    args = {}
    stages = set()
    images = []

    for logical, lineno in _join_continuations(text):
        stripped = logical.strip()
        if not stripped or stripped.startswith("#"):
            continue

        m = ARG_RE.match(stripped)
        if m:
            args[m.group(1)] = _substitute(m.group(2).strip().strip('"\''), args)
            continue
        if ARG_BARE_RE.match(stripped):
            continue

        m = FROM_RE.match(stripped)
        if m:
            rest = PLATFORM_RE.sub("", m.group(1)).strip()
            parts = rest.split()
            if not parts:
                continue
            ref = _substitute(parts[0], args)
            alias = None
            # `FROM x AS name` - case-insensitive, and the alias is what makes
            # later `FROM name` a stage reference rather than an image.
            for i, tok in enumerate(parts[1:], 1):
                if tok.upper() == "AS" and i + 1 < len(parts):
                    alias = parts[i + 1]
                    break
            if alias:
                stages.add(alias)
            # NOTE: the ` AS ` clause does NOT disqualify the image. That
            # exclusion is historical bug #1.
            if ref.lower() == "scratch":
                continue
            if ref in stages and ref != (alias or ""):
                continue           # genuine stage reference, e.g. FROM builder
            # NOTE: a one-word ref is NOT disqualified either. `FROM node` is a
            # real untagged image. That exclusion is historical bug #2.
            images.append({"ref": ref, "line": lineno,
                           "instruction": "FROM", "stage_alias": alias})
            continue

        m = COPY_FROM_RE.match(stripped)
        if m:
            ref = _substitute(m.group(1), args)
            if ref not in stages and not ref.isdigit():
                images.append({"ref": ref, "line": lineno,
                               "instruction": "COPY --from", "stage_alias": None})
            continue

        m = MOUNT_FROM_RE.match(stripped)
        if m:
            ref = _substitute(m.group(1), args)
            if ref not in stages and not ref.isdigit():
                images.append({"ref": ref, "line": lineno,
                               "instruction": "RUN --mount=from", "stage_alias": None})

    return images, stages
