#!/usr/bin/env python3
"""Scan a repo tree for Oct/Nov 2026-class runtime / supply-chain exposures.

Checks Node/Bun floors, Python brotli packages, LiteLLM 1.107.0 (exact + range),
pip/certifi/uv floors, and OPTIMJACK CDN domains/keywords.

Stdlib only. Exit: 0 clean, 1 findings, 2 error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

SKIP_DIR_NAMES = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
    "coverage",
    "vendor",
}

TEXT_SUFFIXES = {
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".txt",
    ".md",
    ".py",
    ".sh",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".html",
    ".htm",
    ".css",
    ".env",
    ".lock",
    ".nvmrc",
    ".node-version",
    ".python-version",
}

SPECIAL_NAMES = {
    "Dockerfile",
    "dockerfile",
    "Makefile",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "package.json",
    "pyproject.toml",
}


@dataclass
class Finding:
    check: str
    severity: str
    path: str
    detail: str
    evidence: str = ""


@dataclass
class Report:
    root: str
    findings: List[Finding] = field(default_factory=list)
    scanned_files: int = 0
    unreadable: int = 0

    @property
    def ok(self) -> bool:
        return not self.findings


def _load_policy(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _parse_version(v: str) -> Tuple[int, ...]:
    cleaned = re.split(r"[^0-9.]", v.strip(), maxsplit=1)[0]
    parts = []
    for p in cleaned.split("."):
        if p.isdigit():
            parts.append(int(p))
        else:
            break
    return tuple(parts) if parts else (0,)


def _cmp_ver(a: str, b: str) -> int:
    aa, bb = _parse_version(a), _parse_version(b)
    n = max(len(aa), len(bb))
    aa = aa + (0,) * (n - len(aa))
    bb = bb + (0,) * (n - len(bb))
    return (aa > bb) - (aa < bb)


def _ver_lt(a: str, b: str) -> bool:
    return _cmp_ver(a, b) < 0


def _ver_le(a: str, b: str) -> bool:
    return _cmp_ver(a, b) <= 0


def _ver_ge(a: str, b: str) -> bool:
    return _cmp_ver(a, b) >= 0


def _walk(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES and not d.startswith(".git")]
        for name in filenames:
            yield Path(dirpath) / name


def _is_candidate(path: Path) -> bool:
    if path.name in SPECIAL_NAMES or path.name.startswith("Dockerfile") or path.name.startswith("requirements"):
        return True
    if path.name in {".nvmrc", ".node-version"}:
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def _read(path: Path, report: Report) -> Optional[str]:
    try:
        data = path.read_bytes()
    except OSError:
        report.unreadable += 1
        return None
    if b"\x00" in data[:2048]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except Exception:
            report.unreadable += 1
            return None


def _rel(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# --- Node / Bun -------------------------------------------------------------

_NVMRC_RE = re.compile(r"^\s*v?(\d+(?:\.\d+){0,2})\s*$", re.M)
_ENGINES_NODE_RE = re.compile(
    r'["\']engines["\']\s*:\s*\{[^}]*["\']node["\']\s*:\s*["\']([^"\']+)["\']',
    re.S,
)
_SETUP_NODE_RE = re.compile(
    r"node-version\s*:\s*['\"]?([^\s'\"]+)|node-version:\s*\n\s*['\"]?([^\s'\"]+)",
    re.I,
)
_BUN_VER_RE = re.compile(r"\bbun[@= ]v?(\d+\.\d+\.\d+)\b", re.I)
_FROM_NODE_RE = re.compile(r"^\s*FROM\s+(?:[^\s]+/)?node:([^\s]+)", re.I | re.M)


def _node_major(ver: str) -> Optional[int]:
    m = re.match(r"v?(\d+)", ver.strip())
    return int(m.group(1)) if m else None


def _node_below_floor(ver: str, floors: dict) -> Optional[str]:
    major = _node_major(ver)
    if major is None or major not in floors["affected_major_lines"]:
        return None
    fixed = floors["fixed_by_major"][str(major)]
    # Bare major ("26") has no patch — treat as below floor.
    if re.fullmatch(r"v?\d+", ver.strip()):
        return f"documents Node {ver} line without patched floor {fixed}"
    if _ver_lt(ver.lstrip("v"), fixed):
        return f"Node {ver} < fixed {fixed}"
    return None


def scan_node_bun(root: Path, text: str, path: Path, policy: dict, report: Report) -> None:
    floors = policy["node"]
    rel = _rel(root, path)

    if path.name in {".nvmrc", ".node-version"}:
        for m in _NVMRC_RE.finditer(text):
            ver = m.group(1)
            why = _node_below_floor(ver, floors)
            if why:
                report.findings.append(
                    Finding("V1-node", "high", rel, why, evidence=ver)
                )

    # Only the project's own package.json engines matter — lockfiles embed
    # transitive package engines and create false-positive floods.
    if path.name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        spec = ((data.get("engines") or {}).get("node") or "").strip()
        if spec and (">=" in spec or "^" in spec or "*" in spec or spec in {"18", "20", "22", "24", "26"}):
            mver = re.search(r"(\d+(?:\.\d+){0,2})", spec)
            if mver:
                ver = mver.group(1)
                major = _node_major(ver)
                if major is not None and major <= 26:
                    # engines ">=18" allows unpatched 22/24/26
                    if major < 22 or (
                        major in floors["affected_major_lines"]
                        and _ver_lt(ver, floors["fixed_by_major"][str(major)])
                    ):
                        report.findings.append(
                            Finding(
                                "V1-node-engines",
                                "medium",
                                rel,
                                f"engines.node '{spec}' allows unpatched 22/24/26 lines",
                                evidence=spec,
                            )
                        )

    if "Dockerfile" in path.name or path.name.lower().startswith("dockerfile"):
        for m in _FROM_NODE_RE.finditer(text):
            tag = m.group(1).split("@")[0]
            # strip alpine/slim suffixes for version compare when numeric
            ver = tag.split("-")[0]
            if re.match(r"^\d+", ver):
                why = _node_below_floor(ver, floors)
                if why:
                    report.findings.append(
                        Finding("V1-node-docker", "high", rel, why, evidence=f"FROM node:{tag}")
                    )

    for m in _SETUP_NODE_RE.finditer(text):
        ver = (m.group(1) or m.group(2) or "").strip()
        if ver and re.match(r"^\d", ver):
            why = _node_below_floor(ver, floors)
            if why:
                report.findings.append(
                    Finding("V1-node-ci", "high", rel, why, evidence=ver)
                )

    bun_max = policy["bun"]["vulnerable_max_inclusive"]
    for m in _BUN_VER_RE.finditer(text):
        ver = m.group(1)
        if _ver_le(ver, bun_max):
            report.findings.append(
                Finding(
                    "V1-bun",
                    "high",
                    rel,
                    f"Bun {ver} <= {bun_max} (Brotli RCE window)",
                    evidence=ver,
                )
            )


# --- Brotli / LiteLLM / certifi / pip / uv ---------------------------------

_POETRY_PKG_RE = re.compile(
    r'\[\[package\]\]\s*\nname\s*=\s*"(?P<name>[^"]+)"\s*\nversion\s*=\s*"(?P<ver>[^"]+)"',
    re.M,
)
_UV_PKG_RE = re.compile(
    r'name\s*=\s*"(?P<name>[^"]+)"\s*\nversion\s*=\s*"(?P<ver>[^"]+)"',
    re.M,
)
_REQ_PIN_RE = re.compile(
    r"^\s*(?P<name>brotli|brotlicffi|Brotli|litellm|certifi|pip|uv)\s*([=<>!~]+)\s*(?P<ver>[^\s;\\]+)",
    re.I | re.M,
)
_LITELLM_RANGE_RE = re.compile(
    r"""litellm["']?\s*[:=]\s*["'\[]?([^"'\]]+)""",
    re.I,
)
_PIP_UPGRADE_RE = re.compile(r"pip install --upgrade pip\b", re.I)


def _brotli_vulnerable(ver: str, policy: dict) -> bool:
    lo, hi = policy["brotli"]["vulnerable_range_inclusive"]
    fixed = set(policy["brotli"]["fixed_versions"])
    if ver in fixed:
        return False
    return _ver_ge(ver, lo) and _ver_le(ver, hi)


def _range_includes_malicious(spec: str, malicious: str) -> bool:
    """Heuristic: does a pep440-ish specifier allow the malicious version?"""
    s = spec.strip().strip("\"'")
    if s == malicious or s.endswith(f"=={malicious}") or f"=={malicious}" in s:
        return True
    if f"!={malicious}" in s:
        return False
    # Lower bound present?
    lower = None
    upper = None
    for m in re.finditer(r">=\s*([0-9][0-9.]*)", s):
        lower = m.group(1)
    for m in re.finditer(r">\s*([0-9][0-9.]*)", s):
        # exclusive lower — still include if malicious > bound
        lower = m.group(1)
    for m in re.finditer(r"<\s*([0-9][0-9.]*)", s):
        upper = m.group(1)
    for m in re.finditer(r"<=\s*([0-9][0-9.]*)", s):
        upper = m.group(1)
    if lower is None and upper is None:
        return False
    ok_lower = True if lower is None else _ver_ge(malicious, lower)
    ok_upper = True
    if upper is not None:
        if "<=" in s and re.search(rf"<=\s*{re.escape(upper)}", s):
            ok_upper = _ver_le(malicious, upper)
        else:
            ok_upper = _ver_lt(malicious, upper)
    return ok_lower and ok_upper


def scan_python_locks(root: Path, text: str, path: Path, policy: dict, report: Report) -> None:
    rel = _rel(root, path)
    name = path.name
    pkgs = []

    if name == "poetry.lock":
        pkgs = [(m.group("name"), m.group("ver")) for m in _POETRY_PKG_RE.finditer(text)]
    elif name == "uv.lock":
        pkgs = [(m.group("name"), m.group("ver")) for m in _UV_PKG_RE.finditer(text)]
    elif name.startswith("requirements") and name.endswith(".txt"):
        for m in _REQ_PIN_RE.finditer(text):
            pkgs.append((m.group("name").lower(), m.group("ver").strip()))
    elif name == "Pipfile.lock":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        for section in ("default", "develop"):
            for pname, meta in (data.get(section) or {}).items():
                ver = (meta.get("version") or "").lstrip("=")
                if ver:
                    pkgs.append((pname, ver))

    malicious = policy["litellm"]["malicious_versions"]
    trust = policy["trust_store"]

    for pname, ver in pkgs:
        pl = pname.lower()
        if pl in {"brotli", "brotlicffi"} and _brotli_vulnerable(ver, policy):
            report.findings.append(
                Finding(
                    "V2-brotli",
                    "critical",
                    rel,
                    f"{pname}=={ver} in vulnerable window; need >= {policy['brotli']['min_safe_on_1_2_line']}",
                    evidence=f"{pname}=={ver}",
                )
            )
        if pl == "litellm" and ver in malicious:
            report.findings.append(
                Finding(
                    "V3.1-litellm",
                    "critical",
                    rel,
                    f"malicious litellm=={ver} locked",
                    evidence=f"litellm=={ver}",
                )
            )
        if pl == "certifi" and _ver_lt(ver, trust["certifi_min"]):
            report.findings.append(
                Finding(
                    "V3.2-certifi",
                    "high",
                    rel,
                    f"certifi=={ver} < {trust['certifi_min']}",
                    evidence=f"certifi=={ver}",
                )
            )
        if pl == "pip" and _ver_lt(ver, trust["pip_min"]):
            report.findings.append(
                Finding(
                    "V3.2-pip",
                    "high",
                    rel,
                    f"pip=={ver} < {trust['pip_min']}",
                    evidence=f"pip=={ver}",
                )
            )
        if pl == "uv" and _ver_lt(ver, trust["uv_min"]):
            report.findings.append(
                Finding(
                    "V3.2-uv",
                    "high",
                    rel,
                    f"uv=={ver} < {trust['uv_min']}",
                    evidence=f"uv=={ver}",
                )
            )


def scan_litellm_ranges(root: Path, text: str, path: Path, policy: dict, report: Report) -> None:
    if path.suffix.lower() not in {".toml", ".md", ".txt", ".yml", ".yaml"} and "Dockerfile" not in path.name:
        return
    rel = _rel(root, path)
    malicious = policy["litellm"]["malicious_versions"][0]
    # Dockerfile pip-style: "litellm>=1.17.0,<2.0.0"
    for m in re.finditer(r"""["']litellm\s*([^"']+)["']|litellm\s*([><=!]=?\s*[^,\s"']+[^\n"']*)""", text, re.I):
        spec = (m.group(1) or m.group(2) or "").strip()
        if not spec:
            continue
        if _range_includes_malicious(spec if "litellm" in spec else f"litellm{spec}", malicious) or _range_includes_malicious(
            f"litellm{spec}", malicious
        ):
            report.findings.append(
                Finding(
                    "V3.1-litellm-range",
                    "critical",
                    rel,
                    f"specifier can resolve to litellm=={malicious}",
                    evidence=spec[:120],
                )
            )


def scan_pip_upgrade_unfloored(root: Path, text: str, path: Path, report: Report) -> None:
    if path.suffix.lower() not in {".sh", ".md"} and "Dockerfile" not in path.name:
        return
    if _PIP_UPGRADE_RE.search(text) and "pip>=26.2.2" not in text and "pip>= 26.2.2" not in text:
        # informational — host may or may not land above floor
        report.findings.append(
            Finding(
                "V3.2-pip-unfloored",
                "medium",
                _rel(root, path),
                "pip install --upgrade pip without floor >= 26.2.2",
                evidence="pip install --upgrade pip",
            )
        )


# --- OPTIMJACK --------------------------------------------------------------

_HIGH_MARKER_RES = [
    ("window._k7", re.compile(r"(?i)(?<![A-Za-z0-9_])window\._k7(?![A-Za-z0-9_])")),
    ("window.__k7b", re.compile(r"(?i)(?<![A-Za-z0-9_])window\.__k7b(?![A-Za-z0-9_])")),
    ("window._cc", re.compile(r"(?i)window\._cc(?![A-Za-z0-9_])")),
    ("window._qxc", re.compile(r"(?i)window\._qxc(?![A-Za-z0-9_])")),
    ("window._shot", re.compile(r"(?i)window\._shot(?![A-Za-z0-9_])")),
    ("obChTK", re.compile(r"(?i)(?<![A-Za-z0-9_])obChTK(?![A-Za-z0-9_])")),
    ("__DAILI_CFG", re.compile(r"(?i)__DAILI_CFG")),
    ("__LDY_CFG", re.compile(r"(?i)__LDY_CFG")),
    ("__cais_ds_eval_ok_v1", re.compile(r"(?i)__cais_ds_eval_ok_v1")),
    ("data-daili-gate", re.compile(r"(?i)data-daili-gate")),
    ("02111110", re.compile(r"(?<![0-9])02111110(?![0-9])")),
    ("d7K9mP2x", re.compile(r"d7K9mP2x")),
    ("ds_sw_fired", re.compile(r"(?i)(?<![A-Za-z0-9_])ds_sw_fired(?![A-Za-z0-9_])")),
    ("ds_vk", re.compile(r"(?i)(?<![A-Za-z0-9_])ds_vk(?![A-Za-z0-9_])")),
    ("BIGNIAO", re.compile(r"(?i)(?<![A-Za-z0-9_])BIGNIAO(?![A-Za-z0-9_])")),
    ("post_exploit.js", re.compile(r"(?i)post_exploit\.js")),
    ("rce_worker_26.x.js", re.compile(r"(?i)rce_worker_26\.x\.js")),
    ("keychain-2.db", re.compile(r"(?i)keychain-2\.db")),
    ("chainFrame", re.compile(r"(?i)(?<![A-Za-z0-9_])chainFrame(?![A-Za-z0-9_])")),
]


def _merge_optimjack_pack(policy: dict, pack: dict) -> None:
    """Merge a full OPTIMJACK IOC pack into policy (in place)."""
    cdn = set(policy.get("optimjack_domains") or [])
    cdn.update(pack.get("poisoned_cdn_hosts") or [])
    policy["optimjack_domains"] = sorted(cdn)
    policy["_optimjack_pack"] = pack


def _load_optimjack_into_policy(policy: dict, skill_dir: Path, json_path: str, xlsx_path: str) -> None:
    pack = None
    if xlsx_path:
        sys.path.insert(0, str(skill_dir / "scripts"))
        from load_optimjack_xlsx import extract_pack  # local sibling

        pack = extract_pack(Path(xlsx_path))
    elif json_path:
        pack = json.loads(Path(json_path).read_text(encoding="utf-8"))
    else:
        rel = policy.get("optimjack_ioc_pack")
        if rel:
            cand = skill_dir / rel
            if cand.is_file():
                pack = json.loads(cand.read_text(encoding="utf-8"))
    if pack:
        _merge_optimjack_pack(policy, pack)


def scan_optimjack(root: Path, text: str, path: Path, policy: dict, report: Report) -> None:
    # Skip this skill's own policy/docs/fixtures to avoid self-hits.
    rel = _rel(root, path)
    if "runtime-supply-chain-audit" in rel.replace("\\", "/"):
        return
    lower = text.lower()
    pack = policy.get("_optimjack_pack") or {}

    for domain in policy.get("optimjack_domains") or []:
        if domain.lower() in lower:
            report.findings.append(
                Finding(
                    "V4-optimjack-cdn",
                    "critical",
                    rel,
                    f"OPTIMJACK poisoned-CDN host present: {domain}",
                    evidence=domain,
                )
            )

    for domain in pack.get("attacker_domains") or []:
        if domain.lower() in lower:
            report.findings.append(
                Finding(
                    "V4-optimjack-attacker-domain",
                    "critical",
                    rel,
                    f"OPTIMJACK attacker domain present: {domain}",
                    evidence=domain,
                )
            )

    for ip in pack.get("attacker_ips") or []:
        idx = text.find(ip)
        if idx < 0:
            continue
        # boundary: not part of a longer dotted number
        start, end = idx, idx + len(ip)
        if start > 0 and (text[start - 1].isdigit() or text[start - 1] == "."):
            continue
        if end < len(text) and (text[end].isdigit() or text[end] == "."):
            continue
        report.findings.append(
            Finding(
                "V4-optimjack-attacker-ip",
                "critical",
                rel,
                f"OPTIMJACK attacker IP present: {ip}",
                evidence=ip,
            )
        )

    for url in pack.get("attacker_urls") or []:
        if url.lower() in lower:
            report.findings.append(
                Finding(
                    "V4-optimjack-attacker-url",
                    "critical",
                    rel,
                    f"OPTIMJACK attacker URL present: {url}",
                    evidence=url[:120],
                )
            )

    for url in pack.get("poisoned_script_urls") or []:
        if url.lower() in lower:
            report.findings.append(
                Finding(
                    "V4-optimjack-poisoned-script",
                    "critical",
                    rel,
                    f"OPTIMJACK historical poisoned script URL present: {url}",
                    evidence=url[:120],
                )
            )

    for h in pack.get("sha256") or []:
        if h.lower() in lower:
            report.findings.append(
                Finding(
                    "V4-optimjack-sha256",
                    "critical",
                    rel,
                    "OPTIMJACK campaign SHA-256 present",
                    evidence=h,
                )
            )

    for w in pack.get("wallets") or []:
        if w and w in text:
            report.findings.append(
                Finding(
                    "V4-optimjack-wallet",
                    "high",
                    rel,
                    "OPTIMJACK campaign wallet address present",
                    evidence=w[:80],
                )
            )

    for label, rx in _HIGH_MARKER_RES:
        if rx.search(text):
            report.findings.append(
                Finding(
                    "V4-optimjack-marker",
                    "high",
                    rel,
                    f"OPTIMJACK high-signal browser marker: {label}",
                    evidence=label,
                )
            )

    # Keyword hits only in HTML/JS/GTM-ish files to reduce false positives in changelogs.
    if path.suffix.lower() in {".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".vue"} or "gtm" in path.name.lower():
        for kw in policy.get("optimjack_keywords") or []:
            if re.search(rf"\b{re.escape(kw)}\b", lower):
                report.findings.append(
                    Finding(
                        "V4-optimjack-keyword",
                        "high",
                        rel,
                        f"OPTIMJACK keyword in web asset: {kw}",
                        evidence=kw,
                    )
                )


def scan_root(root: Path, policy: dict) -> Report:
    report = Report(root=str(root))
    for path in _walk(root):
        if not _is_candidate(path):
            continue
        text = _read(path, report)
        if text is None:
            continue
        report.scanned_files += 1
        scan_node_bun(root, text, path, policy, report)
        scan_python_locks(root, text, path, policy, report)
        scan_litellm_ranges(root, text, path, policy, report)
        scan_pip_upgrade_unfloored(root, text, path, report)
        scan_optimjack(root, text, path, policy, report)
    # Qualify paths with the root basename so multi-root reports stay unambiguous.
    root_label = root.name or str(root)
    for f in report.findings:
        if not f.path.startswith(root_label + "/") and f.path != root_label:
            f.path = f"{root_label}/{f.path}"
    return report


def _dedupe(findings: Sequence[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.check, f.path, f.evidence, f.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def render_markdown(report: Report) -> str:
    lines = [
        f"# Runtime / supply-chain audit",
        "",
        f"- Root: `{report.root}`",
        f"- Files scanned: {report.scanned_files}",
        f"- Unreadable: {report.unreadable}",
        f"- Findings: {len(report.findings)}",
        "",
    ]
    if not report.findings:
        lines.append("**CLEAN** — no policy hits in readable candidates.")
        return "\n".join(lines) + "\n"

    lines.append("| Severity | Check | Path | Detail | Evidence |")
    lines.append("|---|---|---|---|---|")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(report.findings, key=lambda x: (order.get(x.severity, 9), x.check, x.path)):
        lines.append(
            f"| {f.severity} | {f.check} | `{f.path}` | {f.detail} | `{f.evidence}` |"
        )
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+", help="Repository roots to scan")
    parser.add_argument(
        "--policy",
        default=str(Path(__file__).resolve().parents[1] / "policy" / "floors.json"),
        help="Path to floors.json policy",
    )
    parser.add_argument(
        "--optimjack-json",
        default="",
        help="OPTIMJACK IOC pack JSON (overrides policy optimjack_ioc_pack)",
    )
    parser.add_argument(
        "--optimjack-xlsx",
        default="",
        help="OPTIMJACK workbook (.xlsx); parsed via load_optimjack_xlsx.py",
    )
    parser.add_argument("--json-out", default="", help="Write findings JSON to this path")
    parser.add_argument("--md-out", default="", help="Write markdown report to this path")
    args = parser.parse_args(argv)

    policy_path = Path(args.policy)
    if not policy_path.is_file():
        print(f"policy not found: {policy_path}", file=sys.stderr)
        return 2
    policy = _load_policy(policy_path)
    skill_dir = Path(__file__).resolve().parents[1]
    _load_optimjack_into_policy(policy, skill_dir, args.optimjack_json, args.optimjack_xlsx)

    all_findings: List[Finding] = []
    scanned = 0
    unreadable = 0
    roots_ok = []
    for root_s in args.roots:
        root = Path(root_s).resolve()
        if not root.is_dir():
            print(f"not a directory: {root}", file=sys.stderr)
            return 2
        rep = scan_root(root, policy)
        rep.findings = _dedupe(rep.findings)
        all_findings.extend(rep.findings)
        scanned += rep.scanned_files
        unreadable += rep.unreadable
        roots_ok.append(str(root))
        print(render_markdown(rep))

    combined = Report(root=";".join(roots_ok), findings=_dedupe(all_findings), scanned_files=scanned, unreadable=unreadable)
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {
                    "roots": roots_ok,
                    "scanned_files": scanned,
                    "unreadable": unreadable,
                    "findings": [asdict(f) for f in combined.findings],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    if args.md_out:
        Path(args.md_out).write_text(render_markdown(combined), encoding="utf-8")

    return 1 if combined.findings else 0


if __name__ == "__main__":
    sys.exit(main())
