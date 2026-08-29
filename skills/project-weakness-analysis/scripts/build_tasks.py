#!/usr/bin/env python3
"""
build_tasks.py - Emit the manifest Claude dispatches as subagents.

WHY A MANIFEST
    A skill's own scripts cannot spawn subagents. Everything the dispatcher
    needs - prompt, schema, model, agent type, output path - is written here,
    so the dispatching model makes no decisions of its own and two runs of the
    same scan dispatch the same work.
"""
import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _policy    # noqa: E402
import _schemas   # noqa: E402

RUBRIC = ("Scoring rubric: 1 = empty skeleton, 2 = early prototype, "
          "3 = working MVP, 4 = polished/usable, 5 = production-grade.")


def _analyze_prompt(slug, ev_path, project_path, policy):
    extra = "\n".join("- " + i for i in policy.get("agent_instructions", {}).get("analyze", []))
    return """You are performing a production-readiness review of ONE project. Be rigorous, skeptical, and evidence-based: score what the CODE actually contains, not what the README claims. AI-generated boilerplate or empty scaffolding with no real logic scores low - say so plainly.

READ FIRST - the deterministic evidence bundle: {ev}
It already records lines of code, manifests, committed lockfiles, tests, CI, Dockerfile, tracked .env files, secret candidates, and findings from the container-image and dependency scanners. Do not re-derive those facts; start from them.

Then inspect the actual source at: {path}
Look at manifests and lockfiles, Dockerfile and CI config, the database access layer (ORM vs raw SQL vs BaaS client), authentication, error handling, logging, environment and secret management, tests, and directory layout.

{rubric}

Score maturity, production_readiness, code_organization, and maintainability on 1-5. Fill EVERY field of the schema. Keep every reasoning field to 1-3 sentences. List concrete weaknesses in weaknesses[] and anything alarming in red_flags[].
{extra}

Write your JSON result to the output path you were given. Return only a one-line confirmation - not the JSON itself.""".format(
        ev=ev_path, path=project_path, rubric=RUBRIC, extra=("\n" + extra if extra else ""))


def _security_prompt(slug, ev_path, project_path, repo, policy, prior):
    extra = "\n".join("- " + i for i in policy.get("agent_instructions", {}).get("security", []))
    if prior and prior.get("findings"):
        listed = "\n".join("  %d. [%s] %s" % (i + 1, f.get("severity"), f.get("title"))
                           for i, f in enumerate(prior["findings"]))
        prior_block = """This project was audited on {when} with overall risk "{risk}". Previously reported findings:
{listed}

YOUR PRIMARY JOB: for EACH previous finding, open the current code and decide whether it is now:
  - "resolved" (properly fixed),
  - "partial" (mitigated but still exploitable - explain how), or
  - "open" (unchanged, still fully exploitable).
Carry EVERY previous finding forward in your findings array with its verdict in `status`. Do not drop a previous finding - if it is fixed, still list it with status "resolved". A finding that disappears between runs reads as "fixed" to whoever reads the report.""".format(
            when=prior.get("auditedAt", "an earlier run"),
            risk=prior.get("risk", "unknown"), listed=listed)
    else:
        prior_block = ("This project has NOT been audited before. Do a thorough "
                       "first-time audit and mark every finding status \"new\".")

    issue_block = (
        "Check the tracking issue state with: gh issue list --repo %s --state all "
        "--limit 20 --json number,title,state,url\nSet issueState to \"open\"/\"closed\" "
        "for a security tracking issue, or \"none\" if there is none. If gh is "
        "unavailable, set \"none\" and say so in reauditNote - never abort." % repo
        if repo else
        "This project has no GitHub remote recorded. Set issueState to \"none\" and issueUrl to null.")

    return """You are a rigorous application-security auditor reviewing ONE project that may be deployed to production. Be skeptical and evidence-based: only report an issue you can point to in the actual code.

READ FIRST - the deterministic evidence bundle: {ev}
It records CONFIRMED secret findings (credential files committed to git) and REVIEW candidates (regex matches that a human must judge), plus findings from the container-image and dependency scanners. Treat CONFIRMED entries as established fact and judge their real impact; verify REVIEW entries before reporting them.

Project source: {path}

{prior_block}

ALSO scan fresh for NEW high-impact issues regardless of history:
  - Committed secrets: service-role keys, API keys, database URLs, JWT signing secrets, .env files in git
  - Missing authentication or authorization on state-changing endpoints (POST/PATCH/PUT/DELETE)
  - Mass assignment: a raw request body passed into a database insert or update with no field whitelist
  - Personal-data exposure through public/anon access or over-broad API responses
  - Row-level security disabled, anon keys with write access, over-broad CORS
  - Injection (SQL, command, template), SSRF, open proxies, unrestricted file upload, path traversal
  - Insecure defaults: debug mode on, verbose errors returned to clients, permissive cookies, missing TLS enforcement, weak password hashing
  - Dependency and image risk escalated from the scanner findings in the evidence bundle, judged in context
{extra}

EVERY finding must cite a real `file` and `line` in this project, with `evidence` (what makes it exploitable) and `remediation` (the concrete fix). A finding you cannot point at in the code is not a finding - drop it.

Set `risk` to the CURRENT overall risk: the severity of the worst STILL-OPEN finding (status open, partial, or new). Use "none" if everything is resolved or nothing was found.

{issue_block}

In reauditNote (1-3 sentences) summarize what changed since the last audit: what was fixed, what remains.

Write your JSON result to the output path you were given. Return only a one-line confirmation - not the JSON itself.""".format(
        ev=ev_path, path=project_path, prior_block=prior_block,
        extra=("\n" + extra if extra else ""), issue_block=issue_block)


def build(evidence_dir, policy, out_dir, prior_audit=None):
    d = policy["dispatch"]
    prior_audit = prior_audit or {}
    tasks = []
    for fname in sorted(os.listdir(evidence_dir)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(evidence_dir, fname), "r", encoding="utf-8") as f:
            ev = json.load(f)
        slug = ev.get("project_slug") or os.path.splitext(fname)[0]
        ev_path = os.path.abspath(os.path.join(evidence_dir, fname))
        project_path = ev.get("path", "")
        repo = ""
        if ev.get("remote_url", "") and "github.com/" in ev["remote_url"]:
            repo = ev["remote_url"].split("github.com/", 1)[1].strip("/")

        tasks.append({
            "id": "analyze:%s" % slug, "stage": "analyze", "project_slug": slug,
            "model": d["analyze_model"], "agent_type": d["analyze_agent_type"],
            "output_path": os.path.join(out_dir, "out", "%s.analyze.json" % slug),
            "schema": _schemas.ANALYZE_SCHEMA,
            "prompt": _analyze_prompt(slug, ev_path, project_path, policy)})
        tasks.append({
            "id": "security:%s" % slug, "stage": "security", "project_slug": slug,
            "model": d["security_model"], "agent_type": d["security_agent_type"],
            "output_path": os.path.join(out_dir, "out", "%s.security.json" % slug),
            "schema": _schemas.SECURITY_SCHEMA,
            "prompt": _security_prompt(slug, ev_path, project_path, repo, policy,
                                       prior_audit.get(slug))})

    return {"schema_version": 1,
            "generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "max_parallel": d["max_parallel"],
            "profile": policy.get("profile_name", "generic"),
            "tasks": tasks}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Emit the agent task manifest.")
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--out", required=True, help="path to tasks.json")
    ap.add_argument("--prior-audit", default=None)
    ap.add_argument("--profile", default="generic")
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
            sys.stderr.write("WARNING: prior audit unreadable, treating every "
                             "project as a first audit: %s\n" % e)

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(os.path.join(out_dir, "out"), exist_ok=True)
    manifest = build(args.evidence, policy, out_dir, prior_audit=prior)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    sys.stderr.write("tasks: %d for %d project(s)\n"
                     % (len(manifest["tasks"]), len(manifest["tasks"]) // 2))
    return 0 if manifest["tasks"] else 2


if __name__ == "__main__":
    sys.exit(main())
