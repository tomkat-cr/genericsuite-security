#!/usr/bin/env python3
"""
merge_insights.py - Validate agent output, derive both verdicts, reconcile the
re-audit, and write the machine-readable records.

THREE RULES THIS FILE MUST NEVER BREAK
    1. Missing or invalid agent output produces readiness "unknown" - a
       BLOCKING state. Never a default score. An unscanned project is not a
       safe one.
    2. No prior finding may vanish. If the agent omits one, it is re-added as
       "open" and the omission is recorded. A finding that disappears between
       runs reads as "fixed" to whoever reads the report, which would make the
       re-audit feature actively harmful.
    3. security_risk counts only still-open findings (open, partial, new).
       Resolved findings never contribute.
"""
import argparse
import datetime
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _policy    # noqa: E402
import _schemas   # noqa: E402

UNKNOWN = "unknown"


def _today():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d")


def worst_open_severity(findings, policy):
    """Severity of the worst STILL-OPEN finding. Resolved never counts."""
    open_statuses = set(policy["open_statuses"])
    order = policy["severity_order"]
    worst = "none"
    for f in findings or []:
        if f.get("status") not in open_statuses:
            continue
        sev = f.get("severity")
        if sev in order and order.index(sev) < order.index(worst):
            worst = sev
    return worst


def derive_readiness(analysis, security_risk, policy):
    """Return (tier, reason). Rules come from policy, never from code."""
    if analysis is None:
        return UNKNOWN, policy["unknown_reason"]

    scores = {
        "production_readiness": analysis["production_readiness"]["score"],
        "maturity": analysis["maturity"]["score"],
        "code_organization": analysis["code_organization"]["score"],
        "maintainability": analysis["maintainability"]["score"],
    }
    boilerplate = analysis["maturity"].get("is_real_or_boilerplate") == "boilerplate"
    order = policy["severity_order"]

    for rule in policy["readiness_rules"]:
        if rule["tier"] == "not-ready":
            continue
        if boilerplate:
            continue
        if any(scores.get(k, 0) < v for k, v in rule["min_scores"].items()):
            continue
        cap = rule.get("max_open_severity")
        if cap is not None and order.index(security_risk) < order.index(cap):
            continue
        return rule["tier"], rule["reason"]

    fallback = [r for r in policy["readiness_rules"] if r["tier"] == "not-ready"][0]
    return fallback["tier"], fallback["reason"]


def reconcile_findings(prior_findings, agent_findings):
    """Every prior finding survives. Returns (findings, titles the agent dropped)."""
    agent_findings = list(agent_findings or [])
    by_title = {f.get("title"): f for f in agent_findings}
    dropped = []
    for pf in prior_findings or []:
        title = pf.get("title")
        if title in by_title:
            continue
        carried = dict(pf)
        carried["status"] = "open"
        carried.setdefault("file", "")
        carried.setdefault("line", 0)
        carried.setdefault("evidence", "")
        carried.setdefault("remediation", "")
        carried["carried_forward"] = True
        agent_findings.append(carried)
        dropped.append(title)
    return agent_findings, dropped


def load_agent_output(path, schema, rejected_dir):
    """Return (obj, error). A schema failure is treated exactly like absence."""
    if not os.path.isfile(path):
        return None, "no output file at %s" % path
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except (OSError, ValueError) as e:
        obj, err = None, "unreadable JSON: %s" % e
    else:
        errs = _schemas.validate(obj, schema)
        if not errs:
            return obj, None
        obj, err = None, "failed schema validation: %s" % "; ".join(errs[:4])

    os.makedirs(rejected_dir, exist_ok=True)
    try:
        shutil.copy2(path, os.path.join(rejected_dir, os.path.basename(path)))
    except OSError:
        pass
    return None, err


def merge(evidence_dir, agents_dir, policy, prior_audit=None):
    prior_audit = prior_audit or {}
    out_dir = os.path.join(agents_dir, "out")
    rejected_dir = os.path.join(agents_dir, "rejected")
    projects, audit, blind_spots = [], {}, []

    for fname in sorted(os.listdir(evidence_dir)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(evidence_dir, fname), "r", encoding="utf-8") as f:
            ev = json.load(f)
        slug = ev.get("project_slug") or os.path.splitext(fname)[0]

        analysis, aerr = load_agent_output(
            os.path.join(out_dir, "%s.analyze.json" % slug),
            _schemas.ANALYZE_SCHEMA, rejected_dir)
        security, serr = load_agent_output(
            os.path.join(out_dir, "%s.security.json" % slug),
            _schemas.SECURITY_SCHEMA, rejected_dir)

        if aerr:
            blind_spots.append("%s: analyze output unusable - %s" % (slug, aerr))
        if serr:
            blind_spots.append("%s: security output unusable - %s" % (slug, serr))

        prior = prior_audit.get(slug)
        if security is None:
            findings, dropped = list((prior or {}).get("findings") or []), []
            security_risk = UNKNOWN
        else:
            findings, dropped = reconcile_findings(
                (prior or {}).get("findings"), security.get("findings"))
            security_risk = worst_open_severity(findings, policy)
        for title in dropped:
            blind_spots.append(
                "%s: the security agent omitted the prior finding %r; it was "
                "re-added as open rather than assumed fixed" % (slug, title))

        readiness, reason = derive_readiness(
            analysis, "none" if security_risk == UNKNOWN else security_risk, policy)
        if security_risk == UNKNOWN and readiness == "production-ready":
            readiness, reason = UNKNOWN, policy["unknown_reason"]

        record = {
            "project_slug": slug,
            "name": ev.get("db_metadata", {}).get("name") or slug,
            "path": ev.get("path"),
            "branch": ev.get("branch"),
            "head_sha": ev.get("head_sha"),
            "repo_url": ev.get("remote_url"),
            "repo_source_field": ev.get("db_metadata", {}).get("repo_source_field"),
            "signals": ev.get("size", {}),
            "db_metadata": ev.get("db_metadata", {}),
            "siblings": ev.get("siblings", {}),
            "walk_stats": ev.get("walk_stats", {}),
            "secrets": ev.get("secrets", []),
            "analysis": analysis,
            "readiness": readiness,
            "readiness_reason": reason,
            "security_risk": security_risk,
            "findings": findings,
            "previous_risk": (prior or {}).get("risk"),
            "audited_at": (prior or {}).get("auditedAt") or _today(),
            "reaudited_at": _today() if prior else None,
            # Baseline blocking state: an unknown verdict on either axis is
            # blocking per rule 1, independent of any gate policy. main()'s
            # apply_gate() overwrites this with the configured thresholds
            # when it runs; direct callers of merge() (including tests) still
            # get a meaningful value without it.
            "blocked": readiness == UNKNOWN or security_risk == UNKNOWN,
        }
        projects.append(record)

        entry = {"risk": security_risk,
                 "auditedAt": (prior or {}).get("auditedAt") or _today(),
                 "issueUrl": (security or {}).get("issueUrl") or (prior or {}).get("issueUrl"),
                 "issueState": (security or {}).get("issueState", "none"),
                 "findings": [{"severity": f.get("severity"), "title": f.get("title"),
                               "status": f.get("status")} for f in findings]}
        if prior:
            entry["reauditedAt"] = _today()
            entry["previousRisk"] = prior.get("risk")
        if security and security.get("reauditNote"):
            entry["reauditNote"] = security["reauditNote"]
        audit[slug] = entry

        for name, res in (ev.get("siblings") or {}).items():
            if not res.get("available", True):
                blind_spots.append("%s: %s scanner did not run - %s"
                                   % (slug, name, res.get("reason", "unknown")))
        unreadable = (ev.get("walk_stats") or {}).get("unreadable") or []
        if unreadable:
            blind_spots.append("%s: %d path(s) could not be read; unreadable is not clean"
                               % (slug, len(unreadable)))

    return {"projects": projects, "audit": audit, "blind_spots": blind_spots}


def apply_gate(projects, policy, fail_on, fail_on_readiness):
    """Mark each project blocked, and return True if any is."""
    order = policy["severity_order"]
    rorder = policy["readiness_order"]
    any_blocked = False
    for p in projects:
        blocked = False
        if fail_on != "none":
            risk = p["security_risk"]
            rank = order.index(risk) if risk in order else -1
            if rank >= 0 and rank <= order.index(fail_on):
                blocked = True
            if risk == UNKNOWN:
                blocked = True
        if fail_on_readiness != "none":
            if rorder.index(p["readiness"]) >= rorder.index(fail_on_readiness):
                blocked = True
        p["blocked"] = blocked
        any_blocked = any_blocked or blocked
    return any_blocked


def main(argv=None):
    ap = argparse.ArgumentParser(description="Merge agent output into insight records.")
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--agents", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--prior-audit", default=None)
    ap.add_argument("--profile", default="generic")
    ap.add_argument("--fail-on", default=None)
    ap.add_argument("--fail-on-readiness", default=None)
    args = ap.parse_args(argv)

    try:
        policy = _policy.load_policy(args.profile)
    except _policy.PolicyError as e:
        sys.stderr.write("%s\n" % e)
        return 2

    prior = {}
    if args.prior_audit and os.path.isfile(args.prior_audit):
        try:
            with open(args.prior_audit, "r", encoding="utf-8") as f:
                prior = json.load(f)
        except (OSError, ValueError) as e:
            sys.stderr.write("WARNING: prior audit unreadable: %s\n" % e)

    res = merge(args.evidence, args.agents, policy, prior_audit=prior)
    fail_on = args.fail_on or policy["gate_defaults"]["fail_on"]
    fail_readiness = args.fail_on_readiness or policy["gate_defaults"]["fail_on_readiness"]
    apply_gate(res["projects"], policy, fail_on, fail_readiness)

    os.makedirs(os.path.join(args.out, "projects"), exist_ok=True)
    with open(os.path.join(args.out, "insights.json"), "w", encoding="utf-8") as f:
        json.dump({"schema_version": 1, "generated_at": _today(),
                   "profile": policy.get("profile_name"),
                   "blind_spots": res["blind_spots"],
                   "projects": res["projects"]}, f, indent=2)
    with open(os.path.join(args.out, "security-audit.json"), "w", encoding="utf-8") as f:
        json.dump(res["audit"], f, indent=2)
    for p in res["projects"]:
        with open(os.path.join(args.out, "projects", p["project_slug"] + ".json"),
                  "w", encoding="utf-8") as f:
            json.dump(p, f, indent=2)

    sys.stderr.write("merged %d project(s), %d blind spot(s)\n"
                     % (len(res["projects"]), len(res["blind_spots"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
