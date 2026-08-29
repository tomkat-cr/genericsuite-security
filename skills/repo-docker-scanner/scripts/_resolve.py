#!/usr/bin/env python3
"""
_resolve.py - Opt-in tag-to-digest resolution via the Registry HTTP API V2.

Per the design spec's "Opt-in resolution" section: static and offline by
default; --resolve produces copy-pasteable remediation using an ANONYMOUS
registry bearer token via stdlib urllib - no docker/skopeo/crane dependency,
consistent with the house rule of stdlib only.

Nothing from the registry response is ever executed. A manifest is JSON
metadata (media type, size, layer digests) - it is read and discarded, never
evaluated, never written to disk, never passed to a shell.

THE FLOW (identical across registries - all speak the same v2 API spec)
    1. GET https://{host}/v2/{repo}/manifests/{tag} with no credentials.
    2. A 401 response carries WWW-Authenticate: Bearer realm="...",
       service="...",scope="...". Parse it - do not hardcode Docker Hub's
       realm, because ghcr.io/quay.io/gcr.io each use a different one.
    3. GET the realm URL with the parsed service+scope query params -> a JSON
       token, anonymously (no credentials for a public image).
    4. Retry step 1 with Authorization: Bearer <token>.
    5. The digest is the Docker-Content-Digest response header. Falling back
       to sha256(body) is deliberately NOT done: a proxy or CDN can alter
       body bytes in transit without changing what the registry considers
       canonical, so the header (what the registry itself asserts) is the
       only trustworthy source - a locally-computed hash of possibly-altered
       bytes would produce a confidently wrong digest, worse than reporting
       failure.

Resolution failures are per-reference and NEVER abort the run (spec, verbatim).
"""
import json
import re
import urllib.error
import urllib.parse
import urllib.request

import _classify

MANIFEST_ACCEPT = ", ".join([
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
])

WWW_AUTH_RE = re.compile(
    r'Bearer\s+realm="([^"]+)"(?:,service="([^"]*)")?(?:,scope="([^"]*)")?')


def _repo_path(registry, namespace, name):
    """The `{repo}` path segment the v2 API expects."""
    if registry is None:
        # Docker Hub, unqualified. An official image (no namespace) lives
        # under the library/ namespace on the actual API even though the
        # short form (`nginx`) omits it.
        return f"{namespace or 'library'}/{name}"
    return f"{namespace}/{name}" if namespace else name


def _registry_host(registry):
    return registry or "registry-1.docker.io"


def _request(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers, method="GET")
    return urllib.request.urlopen(req, timeout=timeout)          # noqa: S310


def _get_anonymous_token(realm, service, scope, timeout):
    params = []
    if service:
        params.append(f"service={urllib.parse.quote(service)}")
    if scope:
        params.append(f"scope={urllib.parse.quote(scope)}")
    url = realm + ("?" + "&".join(params) if params else "")
    with _request(url, {"Accept": "application/json"}, timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
    return data.get("token") or data.get("access_token")


def resolve_digest(ref, timeout=10):
    """Return (digest_or_None, error_or_None) for a single tag reference.

    Never raises. `ref` must already be split - callers pass the parts, not
    the raw string, so this module never re-implements _classify.split_ref's
    parsing (one parser, one place it can be wrong).
    """
    registry, namespace, name, tag, digest = _classify.split_ref(ref)
    if digest:
        return None, "already digest-pinned - nothing to resolve"
    if not tag:
        return None, "no tag to resolve (untagged reference)"

    host = _registry_host(registry)
    repo = _repo_path(registry, namespace, name)
    manifest_url = f"https://{host}/v2/{repo}/manifests/{tag}"
    headers = {"Accept": MANIFEST_ACCEPT}

    try:
        try:
            with _request(manifest_url, headers, timeout) as resp:
                return resp.headers.get("Docker-Content-Digest"), None
        except urllib.error.HTTPError as e:
            if e.code != 401:
                return None, f"HTTP {e.code} from {host}"
            challenge = e.headers.get("WWW-Authenticate", "")
            m = WWW_AUTH_RE.search(challenge)
            if not m:
                return None, f"401 with no parseable WWW-Authenticate: {challenge[:120]!r}"
            realm, service, scope = m.groups()
            token = _get_anonymous_token(realm, service, scope, timeout)
            if not token:
                return None, "auth realm returned no token"
            headers["Authorization"] = f"Bearer {token}"
            with _request(manifest_url, headers, timeout) as resp:
                return resp.headers.get("Docker-Content-Digest"), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code} resolving {repo}:{tag} on {host}"
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as e:
        return None, f"{e.__class__.__name__}: {e}"


class Resolver:
    """Caches resolutions within one run - the same reference can appear in
    many files, and each is a network round trip."""

    def __init__(self, timeout=10):
        self.timeout = timeout
        self._cache = {}

    def resolve(self, ref):
        if ref not in self._cache:
            self._cache[ref] = resolve_digest(ref, self.timeout)
        return self._cache[ref]
