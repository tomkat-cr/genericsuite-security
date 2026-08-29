#!/usr/bin/env python3
"""
_schemas.py - The two agent output schemas, and a minimal validator.

WHY A HAND-ROLLED VALIDATOR
    jsonschema is third-party and this skill is stdlib-only. This supports
    exactly the keywords the schemas below use. Do not extend it speculatively.

WHY VALIDATION IS NOT OPTIONAL
    An agent's JSON is untrusted input. Merging an unvalidated object means a
    malformed score silently becomes a verdict. Rejected output is treated as
    ABSENT, which produces readiness "unknown" - a blocking state.
"""
SCORE = {"type": "integer", "minimum": 1, "maximum": 5}


def _scored(extra_props, extra_required):
    props = {"score": SCORE, "reasoning": {"type": "string"}}
    props.update(extra_props)
    return {"type": "object", "additionalProperties": False,
            "required": ["score", "reasoning"] + extra_required,
            "properties": props}


ANALYZE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["summary", "project_type", "stack", "architecture",
                 "code_organization", "production_readiness", "maturity",
                 "maintainability", "weaknesses", "red_flags"],
    "properties": {
        "summary": {"type": "string"},
        "project_type": {"type": "string"},
        "stack": {
            "type": "object", "additionalProperties": False,
            "required": ["frontend", "backend", "database", "infra_deploy", "languages"],
            "properties": {
                "frontend": {"type": "array", "items": {"type": "string"}},
                "backend": {"type": "array", "items": {"type": "string"}},
                "database": {"type": "array", "items": {"type": "string"}},
                "infra_deploy": {"type": "array", "items": {"type": "string"}},
                "languages": {"type": "array", "items": {"type": "string"}},
            }},
        "architecture": {
            "type": "object", "additionalProperties": False,
            "required": ["pattern", "uses_orm", "orm_or_db_layer", "api_design",
                         "separation_of_concerns"],
            "properties": {
                "pattern": {"type": "string"},
                "uses_orm": {"type": "boolean"},
                "orm_or_db_layer": {"type": "string"},
                "api_design": {"type": "string"},
                "separation_of_concerns": {"type": "string"},
            }},
        "code_organization": _scored(
            {"directory_structure": {"type": "string"},
             "naming_quality": {"type": "string"},
             "documentation_quality": {"type": "string"}},
            ["directory_structure", "naming_quality", "documentation_quality"]),
        "production_readiness": _scored(
            {"has_auth": {"type": "boolean"},
             "has_error_handling": {"type": "boolean"},
             "has_logging": {"type": "boolean"},
             "has_env_config": {"type": "boolean"},
             "has_deploy_config": {"type": "boolean"},
             "secrets_handling": {"type": "string"}},
            ["has_auth", "has_error_handling", "has_logging", "has_env_config",
             "has_deploy_config", "secrets_handling"]),
        "maturity": _scored(
            {"has_readme": {"type": "boolean"},
             "has_tests": {"type": "boolean"},
             "has_ci": {"type": "boolean"},
             "is_real_or_boilerplate": {"type": "string",
                                        "enum": ["real", "partial", "boilerplate"]}},
            ["has_readme", "has_tests", "has_ci", "is_real_or_boilerplate"]),
        "maintainability": _scored({}, []),
        "weaknesses": {"type": "array", "items": {"type": "string"}},
        "red_flags": {"type": "array", "items": {"type": "string"}},
    },
}

SECURITY_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["risk", "findings", "issueState", "reauditNote"],
    "properties": {
        "risk": {"type": "string",
                 "enum": ["critical", "high", "medium", "low", "none"]},
        "findings": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["severity", "title", "status", "file", "line",
                             "evidence", "remediation"],
                "properties": {
                    "severity": {"type": "string",
                                 "enum": ["critical", "high", "medium", "low"]},
                    "title": {"type": "string"},
                    "status": {"type": "string",
                               "enum": ["open", "partial", "resolved", "new"]},
                    "file": {"type": "string"},
                    "line": {"type": "integer", "minimum": 0},
                    "evidence": {"type": "string"},
                    "remediation": {"type": "string"},
                }}},
        "issueState": {"type": "string", "enum": ["open", "closed", "none"]},
        "issueUrl": {"type": ["string", "null"]},
        "reauditNote": {"type": "string"},
    },
}

_TYPES = {"object": dict, "array": list, "string": str, "integer": int,
          "number": (int, float), "boolean": bool, "null": type(None)}


def _type_ok(value, expected):
    names = expected if isinstance(expected, list) else [expected]
    for name in names:
        py = _TYPES.get(name)
        if py is None:
            continue
        # bool is a subclass of int in Python; an integer field must reject True.
        if name in ("integer", "number") and isinstance(value, bool):
            continue
        if isinstance(value, py):
            return True
    return False


def validate(obj, schema, path="$"):
    """Return a list of human-readable errors. Empty list means valid."""
    errors = []
    expected = schema.get("type")
    if expected and not _type_ok(obj, expected):
        return ["%s: expected %s, got %s" % (path, expected, type(obj).__name__)]

    if "enum" in schema and obj not in schema["enum"]:
        errors.append("%s: %r is not one of %s" % (path, obj, schema["enum"]))
    if isinstance(obj, int) and not isinstance(obj, bool):
        if "minimum" in schema and obj < schema["minimum"]:
            errors.append("%s: %d < minimum %d" % (path, obj, schema["minimum"]))
        if "maximum" in schema and obj > schema["maximum"]:
            errors.append("%s: %d > maximum %d" % (path, obj, schema["maximum"]))

    if isinstance(obj, dict):
        for req in schema.get("required", []):
            if req not in obj:
                errors.append("%s: missing required property %r" % (path, req))
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in obj:
                if key not in props:
                    errors.append("%s: unknown property %r" % (path, key))
        for key, sub in props.items():
            if key in obj:
                errors.extend(validate(obj[key], sub, "%s.%s" % (path, key)))

    if isinstance(obj, list) and "items" in schema:
        for i, item in enumerate(obj):
            errors.extend(validate(item, schema["items"], "%s[%d]" % (path, i)))
    return errors
