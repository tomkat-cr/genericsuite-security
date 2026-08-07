# CHANGELOG

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/) and [Keep a Changelog](http://keepachangelog.com/).


## [Unreleased] - YYYY-MM-DD

### Added
- `repo-corpus` skill (phase 1 of the org-wide repository scanner design): enumerates an org or user via `gh`, clones with hardened flags, and emits a `corpus.json` manifest. Ships `scripts/_walk.py` (shared walking with prune counting and unreadable-path tracking) and a self-test that proves the clone hardening holds.
- Design spec and phase 1 implementation plan under `docs/superpowers/`.

### Changed
- `repo-corpus` and the two planned scanners consume a corpus rather than enumerating repositories themselves, so single-repo lint mode and org-wide audit share one code path.

### Fixed
- `run_corpus.sh` crashed on macOS's bash 3.2 (empty-array expansion under `set -u`) and then reported the crash as `PARTIAL CORPUS` — a verdict about repositories for a run that never reached them. It now uses positional parameters, and refuses to report any corpus outcome without a manifest to back it.
- The self-test built fixture repositories with `git init -b`, which requires git 2.28; macOS ships older. Fixture commands are now checked, and a preflight reports an unusable environment as a setup failure instead of five unrelated assertion failures.
- Clone failures recorded git's trailing boilerplate rather than the line naming the cause.
- `.claude-plugin/marketplace.json` registered `./skills/supply-chain-security`, a path that does not exist; corrected to `./skills/supply-chain-ioc-scan`. A self-test assertion now fails if any registered skill path is missing from disk.

### Removed

### Security
- `build_corpus.py` warns when the repository list may be truncated (count hits `--limit`, or lands on an exact multiple of gh's 100-per-page size). A capped list is the one incompleteness a manifest cannot express as a failure: missing repos are indistinguishable from unselected ones.
- The self-test is hermetic with respect to the developer's git configuration; a global `core.hooksPath` would otherwise have made the central hook-hardening assertion pass for the wrong reason.
- Cloned repositories are treated as hostile input: hooks, LFS smudge/process filters and interactive credential prompts are disabled at clone time; clones are staged and promoted only on success; repository names are validated before use as path components; and file walking never follows a symlink out of its root.


## [1.0.0] - 2026-08-05

### Added
- Project ideation and initial development as a response to the Keyv and Cacheable NPM supply chain attack [GS-339].
