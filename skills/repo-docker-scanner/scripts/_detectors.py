#!/usr/bin/env python3
"""
_detectors.py - One function per detection pass.

Every pass returns a list of raw hits: {ref, line, pass, note}. Classification,
priority and fingerprinting happen once, centrally, in scan_images.py - a pass
that classified its own findings would drift from the others.

The passes deliberately OVERLAP. The structural YAML passes cannot see inside a
`run: |` block scalar; the inline-command pass reads raw text and does not care
about YAML at all. Redundancy is the point: a single pass with a blind spot
produces a clean report.
"""
import json
import os
import re

import _dockerfile
import _yamlish

# --- inline docker commands ------------------------------------------------

DOCKER_CMD_RE = re.compile(r"\bdocker\s+(pull|run|create)\b(?P<rest>.*)", re.IGNORECASE)

# Flags that consume the following token; without this list the token after
# `-v` would be mistaken for the image name.
VALUE_FLAGS = {
    "-v", "--volume", "-e", "--env", "-p", "--publish", "--name", "-w",
    "--workdir", "-u", "--user", "--network", "--net", "--entrypoint",
    "--label", "-l", "--mount", "--add-host", "--device", "--env-file",
    "--restart", "--platform", "--log-driver", "--memory", "-m", "--cpus",
}


def _join_shell_continuations(text):
    """Yield (logical_line, first_line_no).

    The playbook's single most serious finding sat on a `docker run \\`
    continuation line: greping line-by-line sees the flags and misses the image.
    """
    out, buf, start = [], None, None
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if buf is None:
            start, buf = i, line
        else:
            buf += " " + line.strip()
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1]
        else:
            out.append((buf, start))
            buf = None
    if buf is not None:
        out.append((buf, start))
    return out


def _image_from_docker_args(rest):
    toks = rest.split()
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in VALUE_FLAGS:
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        return t
    return None


def inline_docker_commands(text):
    hits = []
    for logical, lineno in _join_shell_continuations(text):
        stripped = logical.strip()
        if stripped.startswith("#"):
            continue
        m = DOCKER_CMD_RE.search(logical)
        if not m:
            continue
        ref = _image_from_docker_args(m.group("rest"))
        if ref:
            hits.append({"ref": ref.strip("\"'"), "line": lineno,
                         "pass": "inline-docker",
                         "note": f"docker {m.group(1).lower()} in an executable file"})
    return hits


# --- Dockerfiles -----------------------------------------------------------

def dockerfile(text):
    images, _ = _dockerfile.parse(text)
    return [{"ref": i["ref"], "line": i["line"], "pass": "dockerfile",
             "note": i["instruction"]} for i in images]


# --- YAML ------------------------------------------------------------------

def _is_image_key(key):
    """Case-insensitive 'image' substring over the key name.

    This catches postgresImage:, lbCronImage: and imageReference: without a
    hand-maintained key list - and it structurally excludes the generic
    `reference:` key that collided with 800+ dbt column definitions, because
    'reference' does not contain 'image'.
    """
    return "image" in key.lower()


def _benign(value, policy):
    kb = policy.get("known_benign_collisions", {})
    low = value.lower()
    if any(low.startswith(p.lower()) for p in kb.get("value_prefixes", [])):
        return True
    if any(low.endswith(s.lower()) for s in kb.get("value_suffixes", [])):
        return True
    return False


def yaml_images(text, policy, path=""):
    """Structural YAML pass: image-ish keys, GitLab services, Helm mapping form."""
    hits = []
    scalars = list(_yamlish.walk(text))

    # parent path -> {key: (value, line)} for adjacency questions (Helm)
    parents = {}
    for p, v, ln in scalars:
        if len(p) >= 1:
            parents.setdefault(p[:-1], {})[p[-1]] = (v, ln)

    for p, value, ln in scalars:
        if not value:
            continue
        key = p[-1]

        if _is_image_key(key):
            if _benign(value, policy):
                continue
            hits.append({"ref": value, "line": ln, "pass": "yaml-image-key",
                         "note": f"key {'.'.join(p)}"})
            continue

        # GitLab CI declares services as `- name: <image>`, not `image:`.
        # An untagged CI service was found this way that every image: grep
        # missed, so it gets its own sweep rather than a key-list entry.
        if key == "name" and len(p) >= 3 and p[-2] == "[]" and p[-3] == "services":
            if not _benign(value, policy):
                hits.append({"ref": value, "line": ln, "pass": "yaml-services-name",
                             "note": "GitLab CI service declared as `- name:`"})

    # Helm's dominant form is `repository:` + a separate `tag:` - invisible to
    # every single-line grep. A MISSING tag here is its own finding: the
    # upstream chart's default decides what deploys.
    for parent, keys in parents.items():
        if "repository" not in keys:
            continue
        repo_val, repo_line = keys["repository"]
        if not repo_val or _benign(repo_val, policy):
            continue
        if repo_val.startswith(("http://", "https://", "oci://")):
            continue           # a chart repo URL, not an image
        tag = keys.get("tag", (None, None))[0]
        digest = keys.get("digest", (None, None))[0]
        if digest:
            ref = f"{repo_val}@{digest}"
            note = "Helm repository+digest"
        elif tag:
            ref = f"{repo_val}:{tag}"
            note = "Helm repository+tag mapping"
        else:
            ref = repo_val
            note = ("Helm repository with NO tag key - the upstream chart "
                    "default decides what deploys")
        hits.append({"ref": ref, "line": repo_line, "pass": "helm-mapping",
                     "note": note})
    return hits


# --- JSON structured config -------------------------------------------------

def json_images(text, policy):
    """devcontainer.json, ECS task definitions, runner toolset files.

    `moby/buildkit:latest` was found baked into self-hosted CI runner images
    through a toolset-*.json, which no YAML pass would ever have opened.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    hits = []

    def rec(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str) and _is_image_key(k) and v and not _benign(v, policy):
                    hits.append({"ref": v, "line": 0, "pass": "json-image-key",
                                 "note": f"key {'.'.join(path + [k])}"})
                else:
                    rec(v, path + [k])
        elif isinstance(node, list):
            for i, v in enumerate(node):
                rec(v, path + ["[]"])

    rec(data, [])
    return hits


# --- registry hostname sweep ------------------------------------------------

def registry_sweep(text, policy):
    """Search for WHERE images live rather than what they are called.

    Runs over every file type. Even when it finds nothing new this is the
    primary validation pass: a deduplicated inventory of every
    registry-qualified reference in the corpus.
    """
    hosts = [re.escape(h) for h in policy.get("registry_hosts", [])]
    ecr = policy.get("ecr_host_pattern", "")
    alt = "|".join(hosts)
    if ecr:
        alt += r"|[a-z0-9-]+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com"
    rx = re.compile(r"\b(?:" + alt + r")/[A-Za-z0-9._/-]+(?::[A-Za-z0-9._-]+)?"
                    r"(?:@sha256:[0-9a-f]{64})?")
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        for m in rx.finditer(line):
            hits.append({"ref": m.group(0), "line": i, "pass": "registry-sweep",
                         "note": "registry-qualified reference"})
    return hits


# --- infrastructure-as-code content sniff -----------------------------------

# CloudFormation is recognisable by content regardless of filename or
# directory convention, the same way a renamed Dockerfile is caught by content
# rather than by name. A single top-level AWSTemplateFormatVersion key, or a
# resource block's `Type: AWS::...`, is specific enough that ordinary prose or
# YAML mentioning AWS incidentally will not match it.
CFN_TYPE_RE = re.compile(r'(?m)^\s*Type:\s*["\']?AWS::')


def is_cloudformation(text):
    return "AWSTemplateFormatVersion" in text or bool(CFN_TYPE_RE.search(text))


# --- dispatch ---------------------------------------------------------------

YAML_EXT = (".yml", ".yaml")
SHELLISH = (".sh", ".bash", ".zsh", ".mk")


def detect(relpath, text, policy):
    """Run every pass that applies to this file. Returns raw hits."""
    base = os.path.basename(relpath)
    low = base.lower()
    hits = []

    is_dockerfile = _dockerfile.looks_like_dockerfile(base)
    if not is_dockerfile and not relpath.endswith(YAML_EXT + (".json",)):
        # Content sniff catches a RENAMED Dockerfile, which would otherwise
        # evade every name-based pass.
        is_dockerfile = _dockerfile.sniff_is_dockerfile(text)
    if is_dockerfile:
        hits += dockerfile(text)

    if relpath.endswith(YAML_EXT):
        hits += yaml_images(text, policy, relpath)

    if relpath.endswith(".json"):
        hits += json_images(text, policy)

    if (relpath.endswith(SHELLISH) or low.startswith("makefile")
            or low == "package.json" or relpath.endswith(YAML_EXT)
            or is_dockerfile):
        hits += inline_docker_commands(text)

    hits += registry_sweep(text, policy)
    return hits
