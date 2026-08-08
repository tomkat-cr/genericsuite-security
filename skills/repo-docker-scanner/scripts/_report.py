#!/usr/bin/env python3
"""
_report.py - report.md, findings.json, findings.sarif.

Every report states the policy boundary it applied and its residual blind
spots. A findings list without them invites the reader to treat "no P0" as
"nothing to worry about", which is precisely the inference the data does not
support.
"""
import json
import os

TIERS = ["P0", "P1", "P2"]

# Stated in every report. These are the limits of static analysis over a
# corpus, not bugs - but a reader who does not know them will over-read a
# clean result.
BLIND_SPOTS = [
    "Tags injected at deploy time by CI or gitops: an empty `tag:` in values "
    "says nothing about what production actually runs.",
    "Upstream Helm chart defaults, which decide the image when a chart's "
    "values omit a tag.",
    "Template-composed references (`${VAR}`, `{{ .Values.x }}`) - reported as "
    "class `unresolved`, never as clean.",
    "YAML anchors/aliases, flow mappings (`{a: b}`) and the bodies of block "
    "scalars: the structural reader does not implement them. Inline `docker` "
    "commands inside a `run: |` block ARE still caught, by the raw-text pass.",
    "Any repository that failed to clone, and any branch other than the one "
    "checked out in the corpus.",
]


def _fmt_flags(f):
    return ", ".join(x["flag"] for x in f["flags"]) or ""


def _priority_legend_lines(policy):
    """Render the P0/P1/P2 legend FROM the policy's own priority_rules.

    A hand-written legend is a second copy of the tier definitions that can
    silently say something the rules do not do - which is exactly what
    happened here: the first version of this section described
    repo-packages-scanner's tiers (actions, npm publish pipelines) inside
    repo-docker-scanner's report. Generating it from `priority_rules` makes
    that class of drift structurally impossible: the legend IS what the code
    reads to assign tiers, not a description of it.
    """
    by_tier = {}
    for rule in policy.get("priority_rules", []):
        tier = rule.get("tier")
        why = (rule.get("why") or "").strip()
        is_catchall = not rule.get("when")
        if not tier or not why or is_catchall:
            continue                      # the default rule isn't a "reason"
        seen = by_tier.setdefault(tier, [])
        if why not in seen:
            seen.append(why)

    lines = []
    for tier in TIERS:
        reasons = by_tier.get(tier, [])
        if policy.get("infra_template_tier") == tier:
            extra = policy.get("infra_template_reason")
            if extra and extra not in reasons:
                reasons.append(extra)
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


def write_all(out, active, all_findings, inventory, unparsed, stats, manifest,
              policy, scanned, skipped, args, version, watchlist=None,
              excluded=None, analyzed=None, scan_command=None):
    watchlist = watchlist or {}
    excluded = excluded or []
    analyzed = analyzed or []
    _write_json(out, active, all_findings, inventory, unparsed, stats, manifest,
                policy, scanned, skipped, version, watchlist, excluded,
                analyzed, scan_command)
    _write_md(out, active, all_findings, inventory, unparsed, stats, manifest,
              policy, scanned, skipped, args, watchlist, excluded, analyzed,
              scan_command)
    if getattr(args, "sarif", False):
        _write_sarif(out, active, version)


def _write_json(out, active, all_findings, inventory, unparsed, stats, manifest,
                policy, scanned, skipped, version, watchlist, excluded,
                analyzed, scan_command):
    payload = {
        "schema_version": 1,
        "generator": f"repo-docker-scanner/scan_images.py {version}",
        "scan_command": scan_command,
        "repos_analyzed": analyzed,
        "corpus": {"root": manifest.get("root"),
                   "generated_at": manifest.get("generated_at"),
                   "source": manifest.get("source"),
                   "totals": manifest.get("totals"),
                   "warnings": manifest.get("warnings", [])},
        "policy": {"name": policy.get("name"),
                   "acceptable_classes": policy.get("acceptable_classes")},
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
                                                  f["repo"], f["file"], f["line"])),
        "inventory": [{"reference": k, "occurrences": v}
                      for k, v in sorted(inventory.items(), key=lambda kv: -kv[1])],
        "unparsed": unparsed,
        "unreadable": [{"path": p, "reason": r} for p, r in stats.unreadable],
        "repos_not_scanned": [{"repo": n, "status": s, "error": e}
                              for n, s, e in skipped],
        "walk": stats.as_dict(),
        "excluded_files": sorted(excluded),
        "namespace_watchlist": sorted(watchlist.values(),
                                     key=lambda w: -w["occurrences"]),
        "blind_spots": BLIND_SPOTS,
    }
    with open(os.path.join(out, "findings.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def _write_md(out, active, all_findings, inventory, unparsed, stats, manifest,
              policy, scanned, skipped, args, watchlist, excluded, analyzed,
              scan_command):
    L = []
    a = L.append
    a("# Unpinned container images")
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
          "the corpus (org/user/local, --include, --branch, --default-branch-only) "
          "live in the corpus this scan consumed; see 'Repositories and branches "
          "analyzed' below and `corpus.source` in `findings.json` for what they "
          "resolved to.")
        a("")
        a(f"```\n{scan_command}\n```")
        a("")

    a("## Repositories and branches analyzed")
    a("")
    if analyzed:
        a("Every clean statement in this report is scoped to exactly these "
          "repositories, on exactly these branches, at exactly these commits — "
          "not to the org, and not to any other branch. See 'Repositories NOT "
          "scanned' below for what this excludes.")
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
    a("Generated from `policy/images.json`'s `priority_rules`, not written by "
      "hand — this section states what actually governs the tables below and "
      "cannot drift out of sync with them the way prose describing a different "
      "scanner's tiers would.")
    a("")
    for line in _priority_legend_lines(policy):
        a(line)
    a("")

    a("## Policy applied")
    a("")
    a(f"Acceptable without remediation: "
      f"`{'`, `'.join(policy.get('acceptable_classes', []))}`. Everything else "
      f"is reported. Argue with this boundary in `policy/images.json`, not with "
      f"the rows below.")
    a("")

    for tier in TIERS:
        rows = [f for f in active if f["priority"] == tier]
        if not rows:
            continue
        a(f"## {tier} ({len(rows)})")
        a("")
        a("| Repo | File:line | Reference | Class | Flags | Why this tier |")
        a("|---|---|---|---|---|---|")
        for f in sorted(rows, key=lambda x: (x["repo"], x["file"], x["line"])):
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            a(f"| {f['repo']} | `{loc}` | `{f['reference']}` | {f['class']} "
              f"| {_fmt_flags(f)} | {f['priority_reason']} |")
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

    if inventory:
        a("## Registry inventory")
        a("")
        a("Every distinct reference seen, most frequent first. Even when it "
          "surfaces nothing new this is the primary validation pass: if an "
          "image you know you use is missing here, a detector has a hole.")
        a("")
        a("| Occurrences | Reference |")
        a("|---|---|")
        for k, v in sorted(inventory.items(), key=lambda kv: (-kv[1], kv[0]))[:100]:
            a(f"| {v} | `{k}` |")
        a("")

    if watchlist:
        a("## Namespace watch list")
        a("")
        a("Flagged independently of tag class, because pinning does not address "
          "who controls the namespace. Listed separately rather than mixed into "
          "the findings above: an unverified Docker Hub namespace describes most "
          "of Docker Hub, and promoting each one to a finding would bury the "
          "unpinned references this report exists to surface. An **abandoned** "
          "namespace is a finding and appears in the tables above as well.")
        a("")
        a("| Occurrences | Reference | Flags |")
        a("|---|---|---|")
        for w in sorted(watchlist.values(), key=lambda x: (-x["occurrences"],
                                                           x["reference"]))[:100]:
            a(f"| {w['occurrences']} | `{w['reference']}` | {', '.join(w['flags'])} |")
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
    a("- Pin by digest: `image:1.2.3@sha256:…` — the tag stays for "
      "readability, the digest is what is enforced. Renovate and Dependabot "
      "both bump digests, so pinning is not freezing.")
    a("- Fix shared and reusable CI workflows and images first: one pin there "
      "covers every consuming repository.")
    a("- Replace unverified-namespace images with official images or an "
      "org-controlled mirror, then pin the mirror.")
    a("")

    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))


def _write_sarif(out, active, version):
    """SARIF 2.1.0. Uploadable via `gh api` so findings land in each
    repository's Security tab rather than a file in TMPDIR."""
    rules, rule_index = [], {}
    for f in active:
        rid = f"unpinned-image/{f['class']}"
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append({
                "id": rid,
                "name": f"UnpinnedImage{f['class'].title().replace('_', '')}",
                "shortDescription": {"text": f"Mutable image reference ({f['class']})"},
                "fullDescription": {"text": f["class_reason"]},
                "defaultConfiguration": {
                    "level": "error" if f["priority"] == "P0" else "warning"},
            })
    results = []
    for f in active:
        rid = f"unpinned-image/{f['class']}"
        results.append({
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": "error" if f["priority"] == "P0" else "warning",
            "message": {"text": f"{f['reference']} — {f['class_reason']} "
                                f"[{f['priority']}: {f['priority_reason']}]"},
            "partialFingerprints": {"repoDockerScanner/v1": f["fingerprint"]},
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
                "name": "repo-docker-scanner",
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
