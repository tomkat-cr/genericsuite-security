#!/usr/bin/env python3
"""
_redact.py - Keep credentials out of every artifact this skill writes.

WHY THIS EXISTS
    The report states the literal command that produced it, so a connection
    string passed as an argument would land in a file people share. Credentials
    are supposed to come from the environment, but defence in depth means the
    captured command is redacted regardless.
"""
import re

_URI = re.compile(r"\b(postgres|postgresql|mysql|mongodb)(\+srv)?://[^\s'\"]+", re.I)
_SENSITIVE_FLAG = re.compile(
    r"(--[\w-]*(key|token|secret|password|url)[\w-]*)([= ])(\S+)", re.I)

REDACTED = "<redacted>"


def redact_command(cmd):
    """Redact connection URIs and the values of credential-shaped flags."""
    if not cmd:
        return ""
    out = _URI.sub(REDACTED, cmd)
    out = _SENSITIVE_FLAG.sub(lambda m: m.group(1) + m.group(3) + REDACTED, out)
    return out


def mask_value(value):
    """Never print a secret in full. Four leading chars plus the length."""
    if value is None:
        return ""
    s = str(value)
    if len(s) <= 4:
        return "*" * len(s)
    return "%s…(%d)" % (s[:4], len(s))
