# Remediation map (Oct / Nov 2026 class)

Ordered steps agents should recommend after findings. Prefer concrete version floors over “upgrade everything”.

## V1 — Node / Bun

1. Set `.nvmrc` / `.node-version` to a patched release: `26.12.1`, `24.22.1`, or `22.23.4`.
2. Raise `package.json` `engines.node` so it cannot accept unpatched 22/24/26.
3. Rebuild CI images and digest-pin `FROM node:…`.
4. Replace Bun ≤ 1.4.3.

## V2 — Brotli

1. Bump Python `brotli` to ≥ `1.2.1` (and fixed `brotlicffi`); regenerate Poetry/uv locks.
2. Until upgraded, avoid decoding untrusted `Content-Encoding: br`.
3. Node/Bun: fixed by V1 runtime bump.

## V3.1 — LiteLLM `1.107.0`

1. Exclude `!=1.107.0` and pin a known-good version in Docker/docs/extras.
2. Search images and site-packages for the exact version.
3. If ever installed: rotate API keys, cloud tokens, registry creds, and `.env` secrets; rebuild from clean base.

## V3.2 — pip / certifi / uv

1. `certifi >= 2026.10.19`, `pip >= 26.2.2`, `uv >= 0.13.4`.
2. Replace bare `pip install --upgrade pip` with floored installs in scripts/Dockerfiles.
3. Recreate venvs and redeploy.

## V4 — OPTIMJACK

1. Remove script tags / GTM loads for listed CDN domains.
2. Rotate session cookies and payment credentials if a production site loaded them during the window.
3. When a fuller IOC spreadsheet is available, extend `policy/floors.json` and re-scan.
