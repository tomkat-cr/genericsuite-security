#!/usr/bin/env python3
"""
_report.py - report.md, findings.json, findings.sarif.

The priority-tier legend is GENERATED from policy/packages.json's
priority_rules, never hand-written prose. repo-docker-scanner shipped a
hand-written version of this section first and it immediately described the
wrong scanner (npm-publish-pipeline language inside a container-image report)
- a hand-written second copy of the tier definitions is exactly the kind of
thing that drifts from what the code does. This module is built the same way
from its first commit rather than as a follow-up fix.
"""
import json
import os

TIERS = ["P0", "P1", "P2"]

BLIND_SPOTS = [
    "Transitive dependencies: only manifest-declared direct dependencies and "
    "lockfile PRESENCE are checked, never lockfile CONTENTS or the resolved "
    "dependency graph.",
    "Any repository that failed to clone, and any branch other than the one "
    "checked out in the corpus.",
    "Action ownership (personal-account / archived-upstream) is reported only "
    "with --resolve, since it requires a live `gh api` call this scanner does "
    "not make by default.",
    "Version constraints inside CI matrix expressions, environment variables, "
    "or composed at run time are not evaluated - only literal manifest text.",
]


def _fmt_flags(f):
    return ", ".join(x["flag"] for x in f.get("flags", [])) or ""


def _priority_legend_lines(policy):
    """Render the P0/P1/P2 legend FROM the policy's own priority_rules - see
    module docstring for why this must never be hand-written prose."""
    by_tier = {}
    for rule in policy.get("priority_rules", []):
        tier = rule.get("tier")
        why = (rule.get("why") or "").strip()
        is_catchall = not rule.get("when")
        if not tier or not why or is_catchall:
            continue
        seen = by_tier.setdefault(tier, [])
        if why not in seen:
            seen.append(why)

    lines = []
    for tier in TIERS:
        reasons = by_tier.get(tier, [])
        text = "; ".join(r[0].upper() + r[1:] for r in reasons) if reasons else "—"
        lines.append(f"- **{tier}** — {text}")

    if policy.get("archived_repo_tier"):
        lines.append(f"- A repository the corpus marks **archived** is tiered "
                    f"**{policy['archived_repo_tier']}** regardless of path — "
                    f"overrides every rule above.")
    default_rule = next((r for r in policy.get("priority_rules", [])
                         if not r.get("when")), None)
    if default_rule:
        lines.append(f"- Anything matching none of the above defaults to "
                    f"**{default_rule['tier']}**.")
    return lines


def write_all(out, active, all_findings, unparsed, stats, manifest, policy,
              scanned, skipped, args, version, excluded=None, analyzed=None,
              scan_command=None):
    excluded = excluded or []
    analyzed = analyzed or []
    _write_json(out, active, all_findings, unparsed, stats, manifest, policy,
                scanned, skipped, version, excluded, analyzed, scan_command)
    _write_md(out, active, all_findings, unparsed, stats, manifest, policy,
              scanned, skipped, args, excluded, analyzed, scan_command)
    if getattr(args, "sarif", False):
        _write_sarif(out, active, version)


def _write_json(out, active, all_findings, unparsed, stats, manifest, policy,
                scanned, skipped, version, excluded, analyzed, scan_command):
    payload = {
        "schema_version": 1,
        "generator": f"repo-packages-scanner/scan_packages.py {version}",
        "scan_command": scan_command,
        "repos_analyzed": analyzed,
        "corpus": {"root": manifest.get("root"),
                   "generated_at": manifest.get("generated_at"),
                   "source": manifest.get("source"),
                   "totals": manifest.get("totals"),
                   "warnings": manifest.get("warnings", [])},
        "policy": {"name": policy.get("name")},
        "totals": {
            "repos_scanned": scanned,
            "repos_not_scanned": len(skipped),
            "files_seen": stats.files_seen,
            "findings_active": len(active),
            "findings_baselined": len(all_findings) - len(active),
            "unparsed_files": len(unparsed),
            "unreadable_paths": len(stats.unreadable),
            "excluded_files": len(excluded),
            **{f"findings_{t}": sum(1 for f in active if f["priority"] == t)
               for t in TIERS},
        },
        "findings": sorted(active, key=lambda f: (TIERS.index(f["priority"]),
                                                  f["repo"], f["file"],
                                                  f["line"] or 0)),
        "unparsed": unparsed,
        "unreadable": [{"path": p, "reason": r} for p, r in stats.unreadable],
        "repos_not_scanned": [{"repo": n, "status": s, "error": e}
                              for n, s, e in skipped],
        "walk": stats.as_dict(),
        "excluded_files": sorted(excluded),
        "blind_spots": BLIND_SPOTS,
    }
    with open(os.path.join(out, "findings.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def _write_md(out, active, all_findings, unparsed, stats, manifest, policy,
              scanned, skipped, args, excluded, analyzed, scan_command):
    L = []
    a = L.append
    a("# Unpinned dependencies and Actions")
    a("")
    a(f"- Corpus: `{manifest.get('root')}` "
      f"({manifest.get('source', {}).get('mode')} "
      f"{manifest.get('source', {}).get('target') or ''})")
    a(f"- Repositories scanned: **{scanned}**"
      + (f" — **{len(skipped)} NOT scanned**" if skipped else ""))
    a(f"- Files examined: {stats.files_seen}")
    counts = {t: sum(1 for f in active if f['priority'] == t) for t in TIERS}
    a(f"- Findings: **P0 {counts['P0']} · P1 {counts['P1']} · P2 {counts['P2']}**"
      f" ({len(all_findings) - len(active)} baselined)")
    a("")

    if scan_command:
        a("## Scan command")
        a("")
        a("The exact command that produced this report. Filters resolved into "
          "the corpus (org/user/local, --include, --branch, "
          "--default-branch-only) live in the corpus this scan consumed; see "
          "'Repositories and branches analyzed' below and `corpus.source` in "
          "`findings.json` for what they resolved to.")
        a("")
        a(f"```\n{scan_command}\n```")
        a("")

    a("## Repositories and branches analyzed")
    a("")
    if analyzed:
        a("Every clean statement in this report is scoped to exactly these "
          "repositories, on exactly these branches, at exactly these commits "
          "— not to the org, and not to any other branch. See 'Repositories "
          "NOT scanned' below for what this excludes.")
        a("")
        a("| Repo | Branch | HEAD |")
        a("|---|---|---|")
        cap = 200
        for r in sorted(analyzed, key=lambda x: x["repo"])[:cap]:
            head = (r["head"] or "")[:12] or "—"
            a(f"| {r['repo']} | {r['branch'] or '—'} | `{head}` |")
        if len(analyzed) > cap:
            a(f"| …and {len(analyzed) - cap} more | | (see findings.json) |")
    else:
        a("None — see 'Repositories NOT scanned' below for why.")
    a("")

    a("## Priority tiers")
    a("")
    a("Generated from `policy/packages.json`'s `priority_rules`, not written "
      "by hand — this section states what actually governs the tables below "
      "and cannot drift out of sync with them.")
    a("")
    for line in _priority_legend_lines(policy):
        a(line)
    a("")

    for tier in TIERS:
        rows = [f for f in active if f["priority"] == tier]
        if not rows:
            continue
        a(f"## {tier} ({len(rows)})")
        a("")
        a("| Repo | File:line | Reference | Class | Flags | Note |")
        a("|---|---|---|---|---|---|")
        for f in sorted(rows, key=lambda x: (x["repo"], x["file"], x["line"] or 0)):
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            a(f"| {f['repo']} | `{loc}` | `{f['reference']}` | {f['class']} "
              f"| {_fmt_flags(f)} | {f['note']} |")
        a("")

    if skipped:
        a("## Repositories NOT scanned")
        a("")
        a("Every clean statement above excludes these entirely.")
        a("")
        for n, s, e in skipped:
            a(f"- `{n}` — {s}: {e or 'no reason recorded'}")
        a("")

    if unparsed:
        a("## Files that could not be parsed")
        a("")
        a("These were opened and not understood. They are neither clean nor "
          "dirty — they are unexamined.")
        a("")
        for u in unparsed[:50]:
            a(f"- `{u['repo']}/{u['file']}` — {u['error']}")
        if len(unparsed) > 50:
            a(f"- …and {len(unparsed) - 50} more (see findings.json)")
        a("")

    if stats.unreadable:
        a("## Paths that could not be read")
        a("")
        a(f"{len(stats.unreadable)} path(s). **Unreadable is not clean.**")
        a("")

    if excluded:
        a("## Files deliberately not scanned")
        a("")
        a(f"{len(excluded)} file(s) matched an exclusion. Listed rather than "
          f"silently dropped: a silent exclusion is how a real finding "
          f"disappears.")
        a("")
        for e in sorted(excluded)[:30]:
            a(f"- `{e}`")
        if len(excluded) > 30:
            a(f"- …and {len(excluded) - 30} more (see findings.json)")
        a("")

    a("## Residual blind spots")
    a("")
    for b in BLIND_SPOTS:
        a(f"- {b}")
    a("")
    corpus_warnings = manifest.get("warnings") or []
    if corpus_warnings:
        a("### Inherited from the corpus")
        a("")
        for w in corpus_warnings:
            a(f"- {w}")
        a("")

    a("## Remediation")
    a("")
    a("- Pin GitHub Actions to a commit SHA: "
      "`uses: owner/repo@<sha> # v4.1.1` — keep the tag as a comment for "
      "readability, Renovate/Dependabot both bump pinned SHAs automatically.")
    a("- Commit a lockfile and use its strict-install form in CI "
      "(`npm ci`, `yarn install --frozen-lockfile`, `pip install "
      "--require-hashes`, `poetry install`) rather than a resolving install.")
    a("- Replace `curl | bash` / `wget | sh` with a pinned, hash-verified "
      "download step.")
    a("- Fix shared and reusable workflows first: one pin there covers every "
      "consuming repository.")
    a("")

    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))


def _write_sarif(out, active, version):
    rules, rule_index = [], {}
    for f in active:
        rid = f"unpinned/{f['class']}"
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append({
                "id": rid,
                "name": "Unpinned" + "".join(p.title() for p in f["class"].split("-")),
                "shortDescription": {"text": f"Unpinned reference ({f['class']})"},
                "fullDescription": {"text": f["note"]},
                "defaultConfiguration": {
                    "level": "error" if f["priority"] == "P0" else "warning"},
            })
    results = []
    for f in active:
        rid = f"unpinned/{f['class']}"
        results.append({
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": "error" if f["priority"] == "P0" else "warning",
            "message": {"text": f"{f['reference']} — {f['note']} "
                                f"[{f['priority']}: {f['priority_reason']}]"},
            "partialFingerprints": {"repoPackagesScanner/v1": f["fingerprint"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"{f['repo']}/{f['file']}"},
                    "region": {"startLine": max(1, f["line"] or 1)},
                }
            }],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "repo-packages-scanner",
                "version": version,
                "informationUri": "https://github.com/tomkat-cr/genericsuite-security",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    with open(os.path.join(out, "findings.sarif"), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
