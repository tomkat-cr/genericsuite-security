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

from scan_runtime_supply_chain import scan_root, _load_policy  # noqa: E402


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
        '<script src="https://cdn.optimizely.com/js/123.js"></script>\n',
    )
    write(root / "tools" / "notes.md", "use bun@1.4.3 for local runs\n")


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
            "V4-optimjack-domain",
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

        print(f"PASS — infected findings={len(bad.findings)} clean_findings={len(good.findings)}")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
