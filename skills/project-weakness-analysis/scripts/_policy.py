#!/usr/bin/env python3
"""
_policy.py - Load policy/weakness.json and merge an optional profile overlay.

WHY THIS EXISTS
    Everything opinionated in this skill is data, not code: tier boundaries,
    secret patterns, table columns, gate defaults. A profile may ADD agent
    instructions and extra checks. It may never remove a generic check or
    lower a severity - narrowing a scan to make it pass is how a scan stops
    being worth running.
"""
import json
import os

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(SCRIPTS_DIR)
POLICY_PATH = os.path.join(SKILL_DIR, "policy", "weakness.json")
PROFILE_DIR = os.path.join(SKILL_DIR, "policy", "profiles")


class PolicyError(Exception):
    """Raised when policy or a profile cannot be loaded. Callers exit 2."""


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise PolicyError("not found: %s" % path)
    except ValueError as e:
        raise PolicyError("invalid JSON in %s: %s" % (path, e))


def resolve_profile_path(profile):
    """A bare name resolves inside policy/profiles/; anything else is a path."""
    if os.sep in profile or profile.endswith(".json"):
        return os.path.abspath(profile)
    return os.path.join(PROFILE_DIR, profile + ".json")


def load_policy(profile="generic"):
    policy = _read_json(POLICY_PATH)
    prof = _read_json(resolve_profile_path(profile))

    for key in ("analyze", "security"):
        added = prof.get("agent_instructions", {}).get(key, [])
        if not isinstance(added, list):
            raise PolicyError("profile agent_instructions.%s must be a list" % key)
        policy.setdefault("agent_instructions", {}).setdefault(key, [])
        policy["agent_instructions"][key].extend(added)

    policy["extra_checks"] = list(prof.get("extra_checks", []))
    policy["profile_name"] = prof.get("name", profile)
    return policy


def severity_rank(policy, severity):
    """Lower rank == more severe. Unknown severities sort last, never first."""
    order = policy["severity_order"]
    return order.index(severity) if severity in order else len(order)


def readiness_rank(policy, tier):
    order = policy["readiness_order"]
    return order.index(tier) if tier in order else len(order)
