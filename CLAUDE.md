# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

`genericsuite-security` is a Claude Code **plugin** (see `.claude-plugin/marketplace.json`, plugin name `gs-security-suite`) that packages security-response skills for GenericSuite and its ecosystem. It is a submodule of the `genericsuite` monorepo — see `/Users/carlosramirez/desarrollo/genericsuite/CLAUDE.md` for cross-package conventions. This package has no application code of its own; it is entirely skills + supporting Python scripts invoked by those skills.

The plugin currently ships five skills:

- `skills/supply-chain-ioc-scan` — built in response to the Keyv/Cacheable npm supply-chain worm ("Shai-Hulud: Here We Go Again", disclosed 2026-08-04, see `CHANGELOG.md`). Answers "did this campaign touch this machine?"
- `skills/repo-corpus` — turns an org, a user, or a local checkout into safe, attributable clones plus a `corpus.json` manifest. Produces **no findings**; it is the foundation the scanners consume.
- `skills/repo-docker-scanner` — consumes a corpus and reports mutable container-image references, tiered P0/P1/P2 by execution context.
- `skills/repo-packages-scanner` — consumes a corpus and reports unpinned GitHub Actions, npm/PyPI/Go/Rust/Ruby dependencies, and unpinned remote code execution, tiered P0/P1/P2. Also carries `run_gh_scan.sh`, moved unchanged from `supply-chain-ioc-scan` (see that skill's history for why).
- `skills/project-weakness-analysis` — decides whether projects are ready and safe to run in production, scoring production-readiness and auditing security weaknesses across many projects at once, with two independent verdict axes (readiness tier and security risk level) and a re-audit loop.

## Work In Progress

All three planned scanner phases are implemented: `repo-corpus` (phase 1), `repo-docker-scanner` (phase 2), `repo-packages-scanner` (phase 3). The `project-weakness-analysis` skill is complete with 266 passing assertions but has had no calibration run against real projects yet.

**If you are picking this work up, read `docs/superpowers/HANDOFF.md` first** — it names the next concrete step, the decisions already made, and the open questions. The approved design is `docs/superpowers/specs/2026-08-06-repo-scanner-skills-design.md`.

## Commands

There is no build/lint/test toolchain at the repo root (`Makefile` only has `make help`, which prints itself). All commands run from inside the skill directory using `python3` (no venv, no `requirements.txt` — stdlib only).

Run the full supply-chain scan (from `skills/supply-chain-ioc-scan/`):
```bash
./scripts/run_scan.sh                      # scans all of $HOME (deliberate default)
./scripts/run_scan.sh ~/some/repo ~/other  # scan specific roots instead
PROFILE=iocs/other-campaign.json ./scripts/run_scan.sh ~/dev   # non-default IOC profile
```
Exit codes: `0` clean, `1` findings, `2` error. Reports are written to `$TMPDIR/ioc-scan-<timestamp>/`.

Run the self-test before trusting any "clean" result (also run automatically by `run_scan.sh`):
```bash
python3 tests/selftest.py
```
This builds a synthetic infected tree and asserts every IOC class is caught, and that known benign lookalikes are *not* flagged. Treat any "clean" verdict from a scanner that hasn't passed this as unknown, not clean.

Run individual scan axes directly (each has `--help`):
```bash
python3 scripts/fetch_package_lists.py --profile iocs/<campaign>.json --out packages.csv
python3 scripts/scan_dependencies.py --csv packages.csv --other-ecosystems packages.other-ecosystems.csv ROOT
python3 scripts/scan_artifacts.py --profile iocs/<campaign>.json ROOT
```

Scan a corpus for unpinned container images (from `skills/repo-docker-scanner/`):
```bash
./scripts/run_docker_scan.sh --org tomkat-cr     # builds a corpus, then scans
./scripts/run_docker_scan.sh --local .           # CI lint mode, --fail-on P0
python3 scripts/probe.py --corpus corpus.json --findings out/findings.json nginx
python3 tests/selftest.py
```
Exit codes `0` clean at the threshold, `1` findings, `2` error. This skill imports `_walk.py` from `repo-corpus` by path, so the two must be installed side by side. Everything opinionated lives in `policy/images.json` — mutability boundary, priority rules, namespace flags; the scanner code is policy-agnostic.

Scan a corpus for unpinned Actions and dependencies (from `skills/repo-packages-scanner/`):
```bash
./scripts/run_packages_scan.sh --org tomkat-cr     # builds a corpus, then scans
./scripts/run_packages_scan.sh --local .           # CI lint mode, --fail-on P0
./scripts/run_packages_scan.sh --corpus corpus.json --resolve   # + gh api ownership checks
python3 tests/selftest.py
```
Exit codes `0` clean at the threshold, `1` findings, `2` error. Same conventions as `repo-docker-scanner`: shares `_walk.py` by path, `policy/packages.json` holds everything opinionated (priority rules, lockfile names), and `report.md` states the exact scan command and the repos/branches analyzed right after the summary. `--resolve` is the only network-backed check (personal-account/archived-upstream Actions via `gh api`) and is opt-in, never required for a valid scan. Also carries `run_gh_scan.sh`, moved unchanged from `supply-chain-ioc-scan`:
```bash
./scripts/run_gh_scan.sh <username> [<keyword-regex> <since-date>]
```

Build a repository corpus (from `skills/repo-corpus/`):
```bash
./scripts/run_corpus.sh --org tomkat-cr      # runs the self-test, then clones
./scripts/run_corpus.sh --local .            # existing checkout, no cloning
python3 scripts/build_corpus.py --org tomkat-cr --list-only   # check scope first
python3 tests/selftest.py
```
Exit codes here are `0` complete corpus, `1` **partial** corpus (some repos failed — every scan over it has a blind spot), `2` error. Note `1` does not mean "findings": `repo-corpus` produces none. Enumeration normally shells out to `gh`; `--repos-json PATH` substitutes a saved payload, which is how the self-test exercises enumeration without a live GitHub account.

Analyze many projects for production readiness and security weaknesses (from `skills/project-weakness-analysis/`):
```bash
./scripts/run_weakness_analysis.sh --root ~/projects          # scan a local directory tree
./scripts/run_weakness_analysis.sh --projects a.json          # scan an explicit list
./scripts/run_weakness_analysis.sh --corpus corpus.json       # scan an existing corpus
./scripts/run_weakness_analysis.sh --org myorg                # scan a GitHub org or user
./scripts/run_weakness_analysis.sh --db postgresql://...      # scan projects from a database
./scripts/run_weakness_analysis.sh --phase merge              # merge agent outputs without re-scanning
python3 tests/selftest.py
```
Exit codes: `0` all projects pass, `1` blocked projects found (readiness gate or security gate failed), `2` error. Output under `./insights/` includes `WEAKNESS-REPORT.md`, `insights.json`, `insights-table.json`/`.csv`, `security-audit.json`, per-project JSON, and `findings.sarif`. Optional `--db` mode is unverified against live Supabase/psql (self-test uses a saved payload).

## Architecture

### Two independent detection axes

The scan is built around a hard rule stated in `SKILL.md`: a clean verdict is only trustworthy if it comes from *agreement between two independent axes*, not from the absence of alarms on one.

- **Dependency axis** (`scan_dependencies.py`) — "did we resolve a malicious version?" Checks lockfiles (`package-lock.json` v1/v2/v3, `yarn.lock`, `pnpm-lock.yaml`), installed `node_modules`, `go.mod`/`go.sum`, and — highest-value single source — `~/.npm/_cacache`, which records tarballs actually fetched even if later deleted from disk.
- **Artifact axis** (`scan_artifacts.py`) — "did the payload run or persist?" Checks payload SHA-1 *and* SHA-256 hashes, IOC path patterns, `package.json` install hooks, IDE persistence configs (`.claude/`, `.vscode/`), C2 domains/strings, `TMPDIR` staging dirs, live processes, registry config, and GitHub exfil repos.

Both scripts share root-walking logic in `scripts/_scanroots.py` (pruning, `--skip`, unreadable-path tracking) and accept `roots...` positionally (default `$HOME`).

### IOC profiles drive everything; scripts are campaign-agnostic

`iocs/<campaign>.json` is the single source of campaign-specific truth: `package_list_sources` (vendor feeds), `domains`, `strings`, `file_hashes_sha1`/`sha256`, `install_hook_patterns`, `ide_persistence`, `process_patterns`, `path_patterns`, `known_benign_collisions`, `payload_size_hints`, `host_persistence_paths`, etc. To cover a new campaign, copy `iocs/keyv-shai-hulud-2026-08.json`, replace the indicator fields, point `--profile`/`PROFILE=` at it, and re-run `tests/selftest.py` — no script changes needed.

### Package-list fetching merges multiple vendor feeds

`fetch_package_lists.py` fetches **every** feed listed in the profile's `package_list_sources` (currently Socket.dev, Wiz, Datadog) and unions them, auto-detecting each vendor's column layout. This is deliberate: any single vendor feed can lag, go stale behind a CDN cache, or silently change shape. The newest good merge is cached to `iocs/packages.csv` as an offline fallback (with a loud STALE warning if used). Non-npm entries (e.g. Go modules) are kept separate in `packages.other-ecosystems.csv` rather than dropped.

### Findings are tiered, not binary

- `CONFIRMED` — hash match, IOC path, oversized payload, or an install hook invoking a known payload.
- `REVIEW` — content hits and IDE persistence configs (e.g. a `SessionStart` hook or `folderOpen` task) that are legitimate features indistinguishable from malicious use by pattern alone; these are surfaced for human read, never auto-labeled compromise.

A filename match alone is never a finding — see the false-positive catalogue in `references/triage-and-response.md` and the "Triage Rules" section of `skills/supply-chain-ioc-scan/SKILL.md` before adding new `path_patterns` (a pattern must have *no legitimate use* at that path, e.g. `setup.mjs` inside `.claude/`; ordinary developer files like `.claude/settings.json` are confirmed by hash or IDE cross-wiring, never by path alone).

### Known platform gotcha

Scripts are Python by design, not bash — macOS ships bash 3.2, which lacks associative arrays (`declare -A` fails silently under `set -u` in ways that look like a completed, clean scan). See `references/triage-and-response.md` §7.

## GitHub Actions

`.github/workflows/claude.yml` and `.github/workflows/claude-code-review.yml` wire up `@claude` mention-triggered assistance and automatic PR review via `anthropics/claude-code-action@v1`. Both require the `CLAUDE_CODE_OAUTH_TOKEN` secret.
