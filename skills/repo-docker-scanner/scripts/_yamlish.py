#!/usr/bin/env python3
"""
_yamlish.py - An indentation reader for YAML, NOT a YAML implementation.

WHY THIS EXISTS AND WHAT IT IS NOT
    The design calls for parsing YAML rather than grepping it, because a
    single-line grep cannot see the Helm `repository:` + `tag:` mapping form,
    and cannot tell an `image:` key from a dbt `reference:` column. Python's
    stdlib has no YAML parser, and this package is stdlib-only by house rule.

    So this reads structure, not YAML. It yields (key_path, value, line) for
    scalar values, which is exactly what the detectors need, and it is honest
    about what it cannot see:

      NOT SUPPORTED - reported as blind spots in every scan report:
        - anchors and aliases (&a / *a)
        - flow mappings and sequences ({a: b}, [a, b])
        - multi-line block scalars (| and >): the body is SKIPPED, not parsed
        - merge keys (<<:)
        - multi-document streams beyond splitting on ---

    The block-scalar gap is deliberately covered from the other side: the
    inline-command detector reads raw file text and does not depend on this
    reader at all, so a `docker run` inside a `run: |` block is still found.
    The two passes overlap on purpose.

A malformed file raises YamlishError. The caller records that as an unparsed
file, which is a finding in its own right - a parser that quietly skips 20
files produces a report that is clean because it looked at nothing.
"""
import re

DASH_RE = re.compile(r"^(?P<indent>\s*)(?P<dash>-\s+)(?P<rest>.*)$")
KEY_BODY_RE = re.compile(r"^(?P<key>[^\s#:][^:]*?)\s*:\s*(?P<value>.*?)\s*$")
BLOCK_RE = re.compile(r"^[|>][-+]?\d*\s*$")


class YamlishError(Exception):
    pass


def _strip_comment(value):
    """Remove a trailing # comment that is not inside quotes."""
    out, quote = [], None
    for i, ch in enumerate(value):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (i == 0 or value[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).strip()


def _unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def walk(text):
    """Yield (key_path, value, line_no).

    key_path is a tuple of key names; a sequence item contributes "[]" so
    `services: - name: x` yields ("services", "[]", "name").
    Only scalar values are yielded; a key introducing a nested block yields
    nothing itself.
    """
    stack = []          # list of (indent, key)
    block_indent = None
    lineno = 0

    for raw in text.splitlines():
        lineno += 1
        if block_indent is not None:
            # Inside a block scalar: skip anything indented deeper than the key.
            if raw.strip() and (len(raw) - len(raw.lstrip())) > block_indent:
                continue
            block_indent = None

        line = raw.rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped in ("---", "..."):
            stack = []
            continue

        indent = len(line) - len(line.lstrip())

        # A sequence item pushes a "[]" frame at the DASH's indent, so sibling
        # keys of the item inherit it. Without this, `- name: x` followed by
        # `  alias: y` loses the list context and reports the wrong key path.
        dash = DASH_RE.match(line)
        if dash:
            while stack and stack[-1][0] >= indent:
                stack.pop()
            stack.append((indent, ("[]",)))
            body = dash.group("rest").strip()
            body_indent = indent + len(dash.group("dash"))
        else:
            body = stripped
            body_indent = indent
            while stack and stack[-1][0] >= body_indent:
                stack.pop()

        if not body or body.startswith("#"):
            continue

        prefix = tuple(k for _, ks in stack for k in ks)

        # A quoted scalar may contain a colon ("80:80"); it is a value, not a
        # key. Checked before the key pattern, which would otherwise split it.
        if body[0] in "\"'":
            if dash:
                yield prefix, _unquote(_strip_comment(body)), lineno
            continue

        m = KEY_BODY_RE.match(body)
        if m:
            key = _unquote(m.group("key").strip())
            value = _strip_comment(m.group("value") or "")
            if value == "":
                stack.append((body_indent, (key,)))
                continue
            if BLOCK_RE.match(value):
                block_indent = body_indent
                continue
            yield prefix + (key,), _unquote(value), lineno
            continue

        if dash:
            yield prefix, _unquote(_strip_comment(body)), lineno
        # Anything else (flow mappings, anchors, continuation text) is not
        # something this reader claims to understand. Silence here is fine only
        # because the limitation is stated in the report.
    return
