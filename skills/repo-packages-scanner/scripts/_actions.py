#!/usr/bin/env python3
"""
_actions.py - GitHub Actions `uses:` detection.

Covers all three shapes the spec names, because they share one YAML key:
  - a step in a workflow:        uses: actions/checkout@v4
  - a composite action's steps:  uses: ./local-action  (skipped - see below)
  - a reusable-workflow call:    jobs.<job>.uses: org/repo/.github/workflows/x.yml@ref
  - a docker-backed action:      uses: docker://alpine:3.19

No YAML structural parser is used. `uses:` has no collision problem the way
`image:`/`reference:` did for repo-docker-scanner - it is not a generic English
word that appears as an unrelated key elsewhere - so a line-oriented scan is
sufficient and avoids needing a second hand-written YAML reader per the
recorded trade-off (each scanner is self-contained).
"""
import re

USES_RE = re.compile(r'^\s*(?:-\s*)?uses:\s*(.+?)\s*(?:#.*)?$')
COMMENT_LINE_RE = re.compile(r'^\s*#')


def _unquote(v):
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def find_uses(text):
    """Yield (target, ref_or_none, line, kind) for every `uses:` value.

    kind is "local" (./path - skipped by the caller, no external exposure),
    "docker" (docker://image[:tag]), or "action" (owner/repo[/path]@ref).
    A `uses:` with no `@` at all (malformed, or a local path without an
    explicit ./) is reported with ref=None so it is never silently dropped.
    """
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        if COMMENT_LINE_RE.match(line):
            continue
        m = USES_RE.match(line)
        if not m:
            continue
        val = _unquote(m.group(1).strip())
        if not val:
            continue

        if val.startswith("./") or val.startswith("../"):
            hits.append((val, None, i, "local"))
            continue
        if val.startswith("docker://"):
            image = val[len("docker://"):]
            hits.append((image, None, i, "docker"))
            continue

        if "@" in val:
            target, _, ref = val.rpartition("@")
            hits.append((target, ref, i, "action"))
        else:
            hits.append((val, None, i, "action"))
    return hits
