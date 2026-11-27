---
name: runtime-supply-chain-audit
description: Use when auditing a repo or monorepo for runtime and supply-chain exposure of the Oct 21 / Nov 13–16 2026 class — Node.js security releases (22/24/26 + Bun Brotli), Python brotli/brotlicffi, LiteLLM 1.107.0, pip/certifi/uv trust-store floors, and OPTIMJACK third-party JS CDN domains. Triggers: "Node October 2026", "Brotli RCE", "Broccoli2Shell", "LiteLLM 1.107.0", "certifi floor", "pip 26.2.2", "OPTIMJACK", "Optimizely CDN compromise", "runtime supply chain audit".
license: MIT
metadata:
  author: tomkat-cr
  version: "1.0"
---

# Runtime / Supply-Chain Audit

## Overview

Re-check a checkout for the **Oct 21 and Nov 13–16 2026** incident class (and similar follow-ons): patched runtime floors, malicious exact package versions, trust-store floors, and third-party JS CDN IOCs.

This is complementary to `supply-chain-ioc-scan` (worm/artifact triage against a campaign profile) and `repo-packages-scanner` (unpinned Actions/deps). Here the policy is a set of **version floors and named IOCs** in `policy/floors.json`.

**Core rules:**

1. Prefer lockfiles, `.nvmrc` / `engines`, Dockerfiles, and CI pins over speculation.
2. A clean verdict is only trustworthy after `tests/selftest.py` passes.
3. Ranges that *can* resolve to a malicious version are findings even when the lock currently pins something else.

## When to Use

- After Node/Python/CDN security advisories that publish patched floors or a single bad version
- Before telling customers “we are not affected”
- When re-auditing after remediation bumps
- **Not for**: generic `npm audit` / Dependabot noise, or worm host-persistence triage (`supply-chain-ioc-scan`)

## Quick Start

```bash
./scripts/run_audit.sh /path/to/genericsuite
./scripts/run_audit.sh /path/to/pkg-a /path/to/pkg-b
```

Exit `0` clean, `1` findings, `2` error. Reports land under `$TMPDIR/runtime-sca-<timestamp>/` (`report.md`, `findings.json`).

Run pieces directly:

```bash
python3 tests/selftest.py
python3 scripts/scan_runtime_supply_chain.py --policy policy/floors.json ROOT
```

## What It Checks

| Check | Sources | Finding when |
|---|---|---|
| V1 Node | `.nvmrc`, `.node-version`, `engines.node`, `FROM node:`, CI `node-version` | Affected majors 22/24/26 below fixed floors (`22.23.4` / `24.22.1` / `26.12.1`), including bare `26` |
| V1 Bun | version mentions | Bun ≤ 1.4.3 |
| V2 Brotli | `poetry.lock`, `uv.lock`, `requirements*.txt`, Pipfile.lock | `brotli`/`brotlicffi` in 1.0.3–1.2.0 and not a listed fixed release |
| V3.1 LiteLLM | locks + Docker/docs ranges | Exact `1.107.0`, or a specifier that can resolve to it |
| V3.2 Trust store | locks + install scripts | `certifi` / `pip` / `uv` below floors; unfloored `pip install --upgrade pip` |
| V4 OPTIMJACK | text/HTML/JS + locks/assets | Poisoned CDN hosts, attacker domains/IPs/URLs, campaign SHA-256s, wallets, high-signal browser markers from `iocs/optimjack-2026-11-17.json` |

## OPTIMJACK IOC pack

The skill ships `iocs/optimjack-2026-11-17.json` extracted from `OPTIMJACK_Complete_IOC_Intelligence_2026-11-17.xlsx`. The scanner loads it by default.

Refresh from a workbook (stdlib xlsx parse):

```bash
python3 scripts/load_optimjack_xlsx.py /path/to/OPTIMJACK_*.xlsx -o iocs/optimjack-2026-11-17.json
python3 scripts/scan_runtime_supply_chain.py --optimjack-xlsx /path/to/OPTIMJACK_*.xlsx ROOT
# or
python3 scripts/scan_runtime_supply_chain.py --optimjack-json iocs/optimjack-2026-11-17.json ROOT
```

Victim brands on the workbook’s Affected Sites sheet are **not** treated as attacker IOCs. Exclusion-list digests are omitted from the SHA-256 set.

## Updating Policy

Edit `policy/floors.json` for runtime floors; refresh `iocs/optimjack-*.json` for OPTIMJACK. Re-run `tests/selftest.py` after either change.

See `references/remediation.md` for ordered customer-facing fix steps.

## Common Mistakes

- Treating bare `.nvmrc` `26` as safe because “latest nvm install is patched” — the documented floor is still missing.
- Ignoring Docker/docs ranges when the lock does not currently resolve LiteLLM.
- Scanning only one package of a monorepo and claiming org-wide cleanliness.
- Skipping the self-test and trusting a quiet scanner.
