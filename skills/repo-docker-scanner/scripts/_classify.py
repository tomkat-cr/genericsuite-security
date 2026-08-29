#!/usr/bin/env python3
"""
_classify.py - Turn an image reference into a mutability class.

The classes come from the source playbook's table. The BOUNDARY between
acceptable and not is policy, never code: it lives in policy/images.json and
every report states which boundary it applied, so reviewers argue with the
policy instead of the data.
"""
import re

DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$", re.IGNORECASE)
MAJOR_ONLY_RE = re.compile(r"^v?[a-z]*\d+$", re.IGNORECASE)
HAS_DIGIT_RE = re.compile(r"\d")

# Classes, worst last - used for sorting and for the acceptable/unacceptable cut.
CLASS_ORDER = ["digest", "version", "codename", "major_only",
               "versionless_variant", "floating_alias", "latest", "untagged",
               "unresolved"]


def split_ref(ref):
    """(registry, namespace, name, tag, digest). Any part may be None."""
    digest = None
    if "@" in ref:
        base, _, dg = ref.partition("@")
        digest = dg or None
    else:
        base = ref

    registry = None
    rest = base
    head, slash, tail = base.partition("/")
    # A first component is a registry only if it looks like a host: contains a
    # dot or a port, or is localhost. Otherwise it is a Docker Hub namespace.
    if slash and ("." in head or ":" in head or head == "localhost"):
        registry = head
        rest = tail

    tag = None
    # The tag separator is the last colon AFTER the last slash - a registry port
    # (`host:5000/img`) must not be mistaken for a tag.
    last_slash = rest.rfind("/")
    colon = rest.rfind(":")
    if colon > last_slash:
        tag = rest[colon + 1:] or None
        rest = rest[:colon]

    namespace, name = None, rest
    if "/" in rest:
        namespace, _, name = rest.rpartition("/")

    return registry, namespace, name, tag, digest


def normalize(ref):
    """Canonical form for fingerprinting.

    docker.io/library/nginx, docker.io/nginx and nginx must fingerprint
    identically or a baseline entry stops matching when someone spells the same
    image differently. Tags stay verbatim: tags are case-sensitive.
    """
    registry, namespace, name, tag, digest = split_ref(ref)
    if registry in ("docker.io", "index.docker.io", "registry.hub.docker.com"):
        registry = None
    if registry is None and namespace == "library":
        namespace = None
    parts = [p for p in (registry, namespace, name.lower() if name else name) if p]
    out = "/".join(parts)
    if tag:
        out += ":" + tag
    if digest:
        out += "@" + digest
    return out


def classify(ref, policy):
    """Return (class_name, reason)."""
    for marker in policy.get("template_markers", []):
        if marker in ref:
            # A composed reference is not clean and is not a finding about a
            # specific image: it is a hole. Saying "unresolved" keeps the report
            # from implying it checked something it could not see.
            return "unresolved", f"reference is composed at deploy time ({marker}…)"

    if DIGEST_RE.search(ref):
        return "digest", "pinned by digest"

    _, _, _, tag, _ = split_ref(ref)
    if tag is None:
        return "untagged", "no tag: Docker resolves this exactly like :latest"

    low = tag.lower()
    if low == "latest":
        return "latest", "explicit :latest"
    if low in [t.lower() for t in policy.get("floating_alias_tags", [])]:
        return "floating_alias", f"floating alias tag :{tag}"

    codenames = [c.lower() for c in policy.get("known_codenames", [])]
    first_seg = low.split("-")[0]
    if first_seg in codenames:
        return "codename", f"codename tag :{tag} names a fixed OS release"

    if not HAS_DIGIT_RE.search(tag):
        # No digits means nothing is pinned. This is what catches redis:alpine
        # and nginx:alpine, which every "does it have a tag?" pass calls fine.
        return "versionless_variant", (
            f"tag :{tag} has no version component - this IS latest on that track")

    if MAJOR_ONLY_RE.match(tag):
        return "major_only", f"major-only tag :{tag} tracks releases"

    return "version", f"version tag :{tag}"


def ownership_flags(ref, policy):
    """Supply-chain flags independent of tag class.

    A digest-pinned image from an abandoned namespace is still a risk; pinning
    does not address abandonment.
    """
    flags = []
    registry, namespace, name, _, _ = split_ref(ref)

    if namespace and namespace.lower() in [n.lower() for n in
                                           policy.get("abandoned_namespaces", [])]:
        flags.append(("abandoned_namespace",
                      f"namespace '{namespace}' is known-unmaintained"))

    is_hub = registry is None or registry in ("docker.io", "index.docker.io",
                                              "registry.hub.docker.com")
    official = [n.lower() for n in policy.get("official_namespaces", [])]
    owned = [n.lower() for n in policy.get("org_owned_namespaces", [])]
    if is_hub and namespace and namespace.lower() not in official + owned:
        # Deliberately NOT called "personal account": a Docker Hub namespace
        # gives no way to tell a person from an organisation. Claiming to know
        # would be false precision in a report meant to be acted on.
        flags.append(("unverified_namespace",
                      f"Docker Hub namespace '{namespace}' is not an official "
                      f"library nor a declared org-owned namespace; its safety "
                      f"is that account's credentials"))
    return flags


def is_acceptable(class_name, policy):
    return class_name in policy.get("acceptable_classes", [])
