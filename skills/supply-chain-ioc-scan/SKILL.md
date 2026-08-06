---
name: supply-chain-ioc-scan
description: Use when a compromised npm/PyPI package or supply-chain worm is disclosed and you must determine whether this machine or repo tree is affected. Triggers: "are we affected by", "compromised package", "supply chain attack", "malicious npm version", "Shai-Hulud", "IOC scan", "check for compromised dependencies", "did we install the bad version".
license: MIT
metadata:
  author: tomkat-cr
  version: "1.5"
---

# Supply-Chain IOC Scan

## Overview

Determine whether a disclosed supply-chain compromise actually touched a machine or repo tree, and produce a verdict backed by evidence rather than absence of alarm.

**Two core principles:**

1. **Scan two independent axes.** The *dependency* axis asks "did we resolve a malicious version?" The *artifact* axis asks "did the payload ever run?" Either alone is weak; agreement between both is what makes a verdict trustworthy.
2. **A clean verdict is only evidence if detection is proven.** A scanner that reports "clean" on everything looks identical to a working one when the machine is genuinely clean — the normal case. Run `tests/selftest.py` before trusting any clean result. It builds a synthetic infected tree and asserts every IOC class is caught. This is not ceremony: it caught a bug where the artifact scanner detected **nothing** on a fully infected fixture.

## When to Use

- A CVE, vendor blog, or registry advisory names compromised package versions
- A maintainer account compromise is announced for a dependency you may use
- Before rotating credentials or rebuilding hosts "just in case" — establish exposure first
- **Not for**: generic vulnerability scanning (`npm audit`, Dependabot). This is incident triage against a *specific named campaign*.

## Quick Start

```bash
./scripts/run_scan.sh
```

**With no arguments this scans all of `$HOME`** — the right default, because payload artifacts are machine-level: IDE persistence lands in `~/.claude` and `~/.vscode`, staged runtimes in `TMPDIR`, and a compromised checkout can sit in any directory, not just the one you had in mind. Narrowing scope is how a scan misses what it was run to find. Pass roots only to narrow deliberately:

```bash
./scripts/run_scan.sh ~/desarrollo/genericsuite ~/desarrollo/mediabros_repos/github
```

Each run re-fetches every vendor feed, runs the self-test, then both axes. Exit 0 = clean on both, 1 = findings, 2 = error. Reports land in `$TMPDIR/ioc-scan-<timestamp>/`.

A full `$HOME` scan is ~2M files and takes several minutes. Caches and app containers are pruned (`scripts/_scanroots.py`); IDE config paths under `Library` are deliberately kept. Add more with `--skip`.

Run individually when you need control:

```bash
python3 scripts/fetch_package_lists.py --profile iocs/<campaign>.json --out packages.csv
python3 scripts/scan_dependencies.py --csv packages.csv --other-ecosystems packages.other-ecosystems.csv ROOT
python3 scripts/scan_artifacts.py --profile iocs/<campaign>.json ROOT
```

## Package Lists Refresh Every Run

`fetch_package_lists.py` pulls **every** feed in the profile's `package_list_sources` and emits their union. Vendors differ in shape and refresh rate, so one source means inheriting its lag and its outages:

| Source | Shape | Refresh | Role |
|---|---|---|---|
| Socket.dev | one row per package@version; scoped names split `Namespace`+`Name`; carries non-npm ecosystems | minute-by-minute | primary — the CSV export of Socket's [public incident page](https://socket.dev/supply-chain-attacks/keyv-and-cacheable-compromise) |
| Wiz | one row per package, versions comma-joined | periodic snapshot | cross-check and failover |
| Datadog | `ecosystem,package,versions` | periodic | cross-check; their [payload teardown](https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/) is the source of most host-persistence IOCs |

Column layout is auto-detected from the header, so a vendor reordering columns can't silently break the parse. The newest good merge is cached to `iocs/packages.csv` and used as an offline fallback — with a loud STALE warning.

**Defeat CDN caching, and check freshness against the vendor's own page.** Socket's CSV sits behind Cloudflare; a plain GET returned `cf-cache-status: HIT` with `age: 6007` — a 100-minute-old list (2269 rows) while the live page showed 2274. During an actively spreading worm, that stale window is exactly the set of newly-compromised packages you are scanning for. `fetch_package_lists.py` cache-busts and prints each feed's newest entry timestamp; compare it against the incident page's artifact count before trusting a clean verdict.

**Sanity-check the per-source row counts each run.** They are printed by design: if a vendor changes its CSV shape, header auto-detection degrades to a parse that finds *nothing*, and a source silently contributing 0 rows is a falsely clean verdict. A count that drops sharply or hits zero means fix the parser, not trust the result.

Record where each feed came from in the profile's `provenance` field. A feed handed over by an incident-response team carries different weight than one found in a blog post, and the next person reading the profile cannot tell them apart otherwise. Note that Socket's human-facing incident page is behind Cloudflare bot protection and must be read in a browser; only the `/api/public/` CSV path is script-fetchable.

**Non-npm entries are separated, never dropped.** This campaign reached Go module proxies, which mirror the compromised GitHub repos. Those land in `packages.other-ecosystems.csv`; `scan_dependencies.py` matches them against `go.mod`/`go.sum`. Any ecosystem with no scanner coverage is printed as a warning so it gets manual attention instead of vanishing.

## What Each Axis Covers

| Axis | Sources | Answers |
|---|---|---|
| Dependency | `package-lock.json` (v1/v2/v3), `yarn.lock`, `pnpm-lock.yaml`, installed `node_modules`, `go.mod`/`go.sum`, **`~/.npm/_cacache`** | Did we ever resolve a malicious version? |
| Artifact | Payload SHA-1 **and** SHA-256, IOC path patterns, `package.json` install hooks, IDE persistence configs, C2 domains/strings, `TMPDIR` staging dirs, live processes, npm/pip registry config, GitHub exfil repos | Did the payload run or persist? |

**The npm cache is the highest-value single source.** It records tarballs actually *fetched*, so it catches a malicious install even if the package was later deleted from disk.

**Hash both algorithms.** Vendors publish different hash sets for the same campaign (Wiz used SHA-1, Aikido SHA-256). The profile carries both; the scanner computes both in one read.

**Signed provenance does not clear a package.** `keyv@6.0.0` shipped with *passing* npm provenance — a valid signed SLSA attestation — because the legitimate release workflow built already-trojanized source. Signature verification succeeded on malware, and the worm mints fresh sigstore provenance for each package it republishes. Treat "provenance verified" as evidence the artifact matches its build, never as evidence the source was clean.

**Size catches variants that hashes miss.** Published hashes only match payloads a vendor has already seen. The second stage is an obfuscated ~728 KB blob, while legitimate files sharing its name are ~1 KB — a ~700x separation, so `payload_size_hints` flags new variants by size. Benign collisions are checked first, so a known-good path is never promoted by size alone.

**Unreadable is not clean.** On macOS, TCC blocks reads under `~/Desktop`, `~/Documents`, `~/Downloads` and more unless the running app has **Full Disk Access** — and `os.walk` swallows those errors by default, so a scan happily reports CLEAN over directories it never opened. On this machine that was **422 unreadable directories under `$HOME`, `~/Desktop` among them**, plus individual files where `ls` succeeds (metadata) while `open()` fails. Both scanners now count these and downgrade the verdict to `CLEAN over what was readable — N path(s) COULD NOT BE READ`. If you see that line, grant Full Disk Access to your terminal and re-run before believing the result.

**Absence of a staging dir is not absence of infection.** The loader accepts *any* working `bun` already on the host and only downloads into `bun-dl-*` when Bun is **missing**. On a machine with Bun installed, an empty `bun-dl-*` result proves nothing — lean on hashes, host persistence and the lock file instead.

**Persistence outlives the packages.** The worm plants a dormant `gh-token-monitor` (a macOS LaunchAgent or systemd user unit, plus `~/.config/gh-token-monitor/*`) that keeps running long after `node_modules` is deleted. `scan_artifacts.py` checks these by absolute path regardless of scan roots. A `tmp.dpkg_14527.lock` in the temp dir means the second stage actually executed.

**Findings are tiered.** `CONFIRMED` = hash match, IOC path, oversized payload, or an install hook invoking a known payload. `REVIEW` = content hits and IDE persistence configs — a `SessionStart` hook or `folderOpen` task is a legitimate feature that looks identical to the malicious use, so the scanner surfaces it for a human read and never calls it compromise.

## Triage Rules

**A filename match is not a finding.** Confirm or clear it by hash. Real campaigns reuse ordinary names, and popular libraries ship files with those exact names:

| Looks like | Actually is |
|---|---|
| `.../regenerate-unicode-properties/General_Category/Math_Symbol.js` | Unicode data table. The IOC is specifically `node_modules/keyv/Math_Symbol.js`. |
| `.../motion-dom/dist/es/gestures/utils/setup.mjs` | Motion library helper. The IOC is `setup.mjs` inside `.claude/` or `.vscode/`. |
| System `bun` binary present | Malware ships its *own* Bun into `TMPDIR`; a pre-existing install predating disclosure is not evidence. |
| `eth_call` in project source | Ordinary Web3 code. Only meaningful alongside campaign C2 domains. |

**Only put a filename in `path_patterns` if it has no legitimate use at that path.** `setup.mjs` and `math_init.js` inside `.claude/`/`.vscode/` qualify. `.claude/settings.json` and `.vscode/tasks.json` do **not** — they are ordinary developer files, malicious only by content, so they are confirmed by published hash or by *cross-wiring* (a Claude `SessionStart` hook pointing into `.vscode/`, or a VS Code `folderOpen` task pointing into `.claude/` — the worm writes them crossed). Adding them to `path_patterns` flags every developer's IDE config; the self-test caught exactly that regression.

**Exclude your own tooling and transcripts from content scans.** IOC profiles, this skill's files, and agent transcripts legitimately contain every domain and string. `scan_artifacts.py` excludes them automatically; add more with `--exclude`.

See `references/triage-and-response.md` for the full false-positive catalogue, the semver-range risk check, and how to map findings onto remediation steps.

## Common Mistakes

- **Trusting a stale package list.** These lists grow for days after disclosure. `run_scan.sh` re-fetches every run; a stale list yields a falsely clean verdict.
- **Dropping ecosystems you don't scan.** If a feed lists golang or PyPI entries and your scanner is npm-only, surface them loudly. Silently discarding known-compromised entries is a falsely clean verdict with extra steps.
- **Reporting "clean" from filename absence alone.** Verify by hash and check the cache.
- **Rotating every credential on a clean result.** Remediation guidance is conditioned on malicious code having actually run. Establish that first.
- **Scanning only the repos you were asked about.** Payload artifacts (`~/.claude`, `~/.vscode`, `TMPDIR`, registry config) are machine-level. Default to `$HOME`.
- **Silent-clean bugs.** The worst scanner failure is checking nothing and reporting CLEAN. Two real instances, both caught only by the self-test: `fnmatch`'s `*` crosses `/`, so a `<dir>/*` exclusion swallowed an entire subtree; and `os.walk()` on a file yields nothing, so a file passed as a root scanned zero bytes. Treat any "clean" from an untested scanner as unknown, not clean.
- **Writing the scanner in bash on macOS.** macOS ships bash 3.2 (2007), which has no associative arrays. `declare -A` fails, and with `set -u` the errors land on stderr while the report file records nothing — a hash check that appears to have run and found nothing. Use Python, or verify with `bash --version`. See `references/triage-and-response.md` §7.

## Adding a New Campaign

Copy `iocs/keyv-shai-hulud-2026-08.json`, replace the indicator fields, and pass it via `--profile` (or `PROFILE=`). The scanners are campaign-agnostic; only the profile is campaign-specific. Re-run `tests/selftest.py` afterwards.
