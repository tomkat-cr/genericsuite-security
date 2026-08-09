#!/usr/bin/env python3
"""
gen_report.py - Render the report, the flat projection, the CSV, and SARIF.

THE LEGEND RULE
    readiness_legend_lines() renders the tier legend FROM policy. Never type a
    tier description by hand here. A hand-written legend shipped once in this
    package describing a different scanner's tiers - see
    docs/superpowers/HANDOFF.md. Generating it makes that drift impossible.

WHAT EVERY REPORT MUST STATE
    The scan command that produced it (redacted), every project and HEAD SHA it
    actually covered, and its own blind spots - present even on a clean run.
    A "no findings" statement is scoped to exactly the projects listed.
"""
import argparse
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _policy   # noqa: E402
import _redact   # noqa: E402


def readiness_legend_lines(policy):
    lines = ["- **%s** — %s" % (r["tier"], r["reason"]) for r in policy["readiness_rules"]]
    lines.append("- **unknown** — %s" % policy["unknown_reason"])
    return lines


def severity_legend_lines(policy):
    return ["- **%s**" % s for s in policy["severity_order"]]


def _score(analysis, group):
    if not analysis:
        return None
    return analysis.get(group, {}).get("score")


def flat_rows(insights, policy):
    open_statuses = set(policy["open_statuses"])
    audit_defaults = {"previous_risk": None, "audited_at": None, "reaudited_at": None}
    rows = []
    for p in insights["projects"]:
        a = p.get("analysis")
        findings = p.get("findings") or []
        sig = p.get("signals") or {}
        values = {
            "project_slug": p.get("project_slug"),
            "name": p.get("name"),
            "repo_url": p.get("repo_url"),
            "repo_source_field": p.get("repo_source_field"),
            "path": p.get("path"),
            "branch": p.get("branch"),
            "head_sha": p.get("head_sha"),
            "stars": sig.get("stars"),
            "forks": sig.get("forks"),
            "contributors": sig.get("contributors"),
            "commit_count": sig.get("commit_count"),
            "code_loc": sig.get("code_loc"),
            "license": sig.get("license"),
            "primary_language": sig.get("primary_language"),
            "project_type": a.get("project_type") if a else None,
            "uses_orm": a["architecture"]["uses_orm"] if a else None,
            "orm_or_db_layer": a["architecture"]["orm_or_db_layer"] if a else None,
            "maturity_score": _score(a, "maturity"),
            "production_readiness_score": _score(a, "production_readiness"),
            "code_organization_score": _score(a, "code_organization"),
            "maintainability_score": _score(a, "maintainability"),
            "readiness": p.get("readiness"),
            "security_risk": p.get("security_risk"),
            "previous_risk": p.get("previous_risk"),
            "open_findings": sum(1 for f in findings if f.get("status") in open_statuses),
            "resolved_findings": sum(1 for f in findings if f.get("status") == "resolved"),
            "red_flags_count": len(a.get("red_flags", [])) if a else None,
            "blocked": p.get("blocked", False),
            "audited_at": p.get("audited_at"),
            "reaudited_at": p.get("reaudited_at"),
        }
        values.update({k: values.get(k, v) for k, v in audit_defaults.items()})
        rows.append({col: values.get(col) for col in policy["table_columns"]})
    return rows


def _md_table(columns, rows):
    out = ["| " + " | ".join(columns) + " |",
           "|" + "|".join("---" for _ in columns) + "|"]
    for r in rows:
        out.append("| " + " | ".join(
            "" if r.get(c) is None else str(r.get(c)) for c in columns) + " |")
    return out


def render_markdown(insights, policy, scan_command, digest=None):
    projects = insights["projects"]
    rows = flat_rows(insights, policy)
    L = []
    A = L.append

    A("# Project Weakness Analysis Report")
    A("")
    A("Production-readiness and security-risk triage across %d project(s). "
      "Generated %s with the `%s` profile."
      % (len(projects), insights.get("generated_at", "?"), insights.get("profile", "generic")))
    A("")

    A("## 1. Executive summary")
    A("")
    for tier in policy["readiness_order"]:
        n = sum(1 for p in projects if p["readiness"] == tier)
        if n:
            A("- **%s**: %d project(s)" % (tier, n))
    A("")
    for sev in policy["severity_order"]:
        n = sum(1 for p in projects if p["security_risk"] == sev)
        if n:
            A("- security risk **%s**: %d project(s)" % (sev, n))
    blocked = [p for p in projects if p.get("blocked")]
    A("")
    if blocked:
        A("**%d project(s) blocked at the configured thresholds:**" % len(blocked))
        A("")
        for p in blocked:
            A("- **%s** — readiness `%s`, security risk `%s`"
              % (p["project_slug"], p["readiness"], p["security_risk"]))
    else:
        A("No project is blocked at the configured thresholds.")
    A("")

    A("### Project matrix")
    A("")
    compact = ["project_slug", "readiness", "security_risk", "production_readiness_score",
               "maturity_score", "code_organization_score", "maintainability_score",
               "open_findings", "code_loc", "blocked"]
    L.extend(_md_table(compact, rows))
    A("")
    A("Full column set in `insights-table.json` and `insights-table.csv`.")
    A("")

    A("## 2. Scan command")
    A("")
    A("```")
    A(_redact.redact_command(scan_command or "(not recorded)"))
    A("```")
    A("")

    A("## 3. Projects analyzed")
    A("")
    A("Every statement in this report is scoped to exactly these projects at "
      "exactly these commits.")
    A("")
    L.extend(_md_table(["project_slug", "path", "branch", "head_sha"], rows))
    A("")

    A("## 4. Blind spots")
    A("")
    A("What this run did not or could not cover. Read this before treating any "
      "result as complete.")
    A("")
    for b in insights.get("blind_spots") or []:
        A("- %s" % b)
    if not insights.get("blind_spots"):
        A("- No coverage gaps were recorded for this run.")
    A("")
    A("- Scores on the readiness axis are AI-generated from a single snapshot of "
      "each project. This is triage, not ground truth. Re-running is cheap; do it "
      "whenever the code changes.")
    A("")

    A("## 5. Readiness tiers and risk levels")
    A("")
    A("Generated from `policy/weakness.json`; edit the policy, not this report.")
    A("")
    L.extend(readiness_legend_lines(policy))
    A("")
    A("Security risk is the severity of the worst still-open finding "
      "(status %s). Resolved findings never contribute."
      % ", ".join("`%s`" % s for s in policy["open_statuses"]))
    A("")

    A("## 6. Per-project detail")
    A("")
    for p in sorted(projects, key=lambda x: x["project_slug"]):
        a = p.get("analysis")
        A("### %s" % p["project_slug"])
        A("")
        A("- **Readiness:** `%s` — %s" % (p["readiness"], p.get("readiness_reason", "")))
        A("- **Security risk:** `%s`" % p["security_risk"])
        if a:
            A("- **Summary:** %s" % a.get("summary", ""))
            A("- **Scores:** production-readiness %s/5 · maturity %s/5 · "
              "organization %s/5 · maintainability %s/5"
              % (_score(a, "production_readiness"), _score(a, "maturity"),
                 _score(a, "code_organization"), _score(a, "maintainability")))
            if a.get("weaknesses"):
                A("- **Weaknesses:** %s" % "; ".join(a["weaknesses"]))
            if a.get("red_flags"):
                A("- **Red flags:** %s" % "; ".join(a["red_flags"]))
        else:
            A("- No usable analysis was produced for this project. It is reported "
              "as `unknown`, which blocks — an unscanned project is not a safe one.")
        findings = p.get("findings") or []
        if findings:
            A("")
            A("| severity | status | title | file:line |")
            A("|---|---|---|---|")
            for f in findings:
                A("| %s | %s | %s | %s:%s |" % (f.get("severity"), f.get("status"),
                                                f.get("title"), f.get("file"), f.get("line")))
        A("")

    A("## 7. Cross-project rollup")
    A("")
    A(digest if digest else
      "The rollup agent produced no output for this run, so this section is "
      "empty. Every per-project result above is unaffected — the rollup is "
      "presentational and can never change a score, a tier, or the exit code.")
    A("")
    return "\n".join(L) + "\n"


def render_sarif(insights):
    results = []
    for p in insights["projects"]:
        for f in p.get("findings") or []:
            if f.get("status") == "resolved":
                continue
            level = {"critical": "error", "high": "error",
                     "medium": "warning", "low": "note"}.get(f.get("severity"), "note")
            results.append({
                "ruleId": "weakness/%s" % (f.get("severity") or "unknown"),
                "level": level,
                "message": {"text": "%s — %s" % (f.get("title"), f.get("evidence", ""))},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "%s/%s" % (p["project_slug"],
                                                           f.get("file") or "")},
                    "region": {"startLine": max(1, int(f.get("line") or 1))}}}]})
    return {"version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "project-weakness-analysis",
                                          "informationUri": "https://github.com/tomkat-cr/genericsuite-security",
                                          "rules": []}},
                      "results": results}]}


def write_all(insights, policy, out_dir, scan_command, digest=None):
    os.makedirs(out_dir, exist_ok=True)
    rows = flat_rows(insights, policy)
    cols = policy["table_columns"]

    with open(os.path.join(out_dir, "WEAKNESS-REPORT.md"), "w", encoding="utf-8") as f:
        f.write(render_markdown(insights, policy, scan_command, digest))
    with open(os.path.join(out_dir, "insights-table.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    with open(os.path.join(out_dir, "insights-table.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    with open(os.path.join(out_dir, "findings.sarif"), "w", encoding="utf-8") as f:
        json.dump(render_sarif(insights), f, indent=2)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render the report and data files.")
    ap.add_argument("--insights", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--scan-command", default="")
    ap.add_argument("--digest", default=None)
    ap.add_argument("--profile", default="generic")
    args = ap.parse_args(argv)

    try:
        policy = _policy.load_policy(args.profile)
        with open(args.insights, "r", encoding="utf-8") as f:
            insights = json.load(f)
    except (_policy.PolicyError, OSError, ValueError) as e:
        sys.stderr.write("%s\n" % e)
        return 2

    digest = None
    if args.digest and os.path.isfile(args.digest):
        try:
            with open(args.digest, "r", encoding="utf-8") as f:
                digest = f.read().strip()
        except OSError:
            digest = None

    write_all(insights, policy, args.out, args.scan_command, digest)
    sys.stdout.write(os.path.join(args.out, "WEAKNESS-REPORT.md") + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
