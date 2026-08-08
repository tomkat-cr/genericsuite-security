#!/usr/bin/env python3
"""
_npm.py - npm / package.json detection.

Two different signals are kept as two different finding classes, not merged:
"missing lockfile" is a repo-tree fact (handled at repo level by
scan_packages.py, since it is not about any one file); "npm install rather
than npm ci in CI" is a CI-workflow-content fact. A repo can have a committed
lockfile and STILL run `npm install` in CI, which re-resolves fresh versions
and ignores the lockfile entirely - conflating the two would hide that case.
"""
import json
import re

import _classify

DEP_KEYS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")

NPM_INSTALL_RE = re.compile(r'\bnpm\s+install\b')
NPM_CI_RE = re.compile(r'\bnpm\s+ci\b')
YARN_INSTALL_RE = re.compile(r'\byarn\s+install\b')
YARN_FROZEN_RE = re.compile(r'--frozen-lockfile')


def parse_package_json(text, policy):
    """Findings from a single package.json: dependency ranges, install hooks,
    overrides/resolutions. Raises ValueError on unparseable JSON, which the
    caller records as an unparsed file rather than a silent skip."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("package.json is not a JSON object")

    findings = []
    benign_prefixes = policy.get("known_benign_collisions", {}).get("value_prefixes", [])

    for key in DEP_KEYS:
        deps = data.get(key)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            if any(spec.startswith(p) for p in benign_prefixes):
                continue          # file:/link:/workspace:/npm: - not a registry range
            klass, pinned = _classify.npm_range_class(spec)
            if pinned:
                continue
            findings.append({"ref": f"{name}@{spec}", "class": f"npm-{klass}",
                             "note": f"{key}.{name}", "line": None})

    if isinstance(data.get("overrides"), dict) and data["overrides"]:
        findings.append({"ref": "package.json#overrides", "class": "npm-overrides",
                         "note": "overrides changes resolution for transitive "
                                 "dependencies outside their own manifests",
                         "line": None})
    if isinstance(data.get("resolutions"), dict) and data["resolutions"]:
        findings.append({"ref": "package.json#resolutions", "class": "npm-resolutions",
                         "note": "resolutions changes resolution for transitive "
                                 "dependencies outside their own manifests",
                         "line": None})

    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook in ("preinstall", "postinstall"):
            if scripts.get(hook):
                findings.append({"ref": f"package.json#scripts.{hook}",
                                 "class": "npm-install-hook",
                                 "note": f"runs on every install: {scripts[hook]!r}",
                                 "line": None})
    return findings


def find_npmrc_registry_overrides(text, policy):
    default = policy.get("default_npm_registry", "registry.npmjs.org")
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        m = re.match(r'^(?:(@[\w.-]+):)?registry\s*=\s*(\S+)', stripped)
        if not m:
            continue
        scope, url = m.group(1), m.group(2)
        if default in url:
            continue
        findings.append({"ref": url, "class": "npm-registry-override", "line": i,
                         "note": f"scope {scope}" if scope else "default registry"})
    return findings


def find_ci_install_not_ci(text, relpath):
    """`npm install`/`yarn install` (without --frozen-lockfile) used in place of
    `npm ci` inside what is presumed to be a CI file by the caller."""
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if NPM_CI_RE.search(line):
            continue
        if NPM_INSTALL_RE.search(line):
            findings.append({"ref": stripped[:120], "class": "npm-install-in-ci",
                             "line": i, "note": "npm install (not npm ci) in CI"})
            continue
        if YARN_INSTALL_RE.search(line) and not YARN_FROZEN_RE.search(line):
            findings.append({"ref": stripped[:120], "class": "yarn-install-in-ci",
                             "line": i,
                             "note": "yarn install without --frozen-lockfile in CI"})
    return findings
