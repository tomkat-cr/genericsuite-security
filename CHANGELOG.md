# CHANGELOG

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/) and [Keep a Changelog](http://keepachangelog.com/).


## [Unreleased] - YYYY-MM-DD

### Added
- `repo-docker-scanner` report.md now states, right after the summary, the exact command that produced it and the full list of repositories/branches/HEAD commits actually analyzed (also in findings.json as `scan_command` and `repos_analyzed`). `--org`/`--include`/`--branch` are resolved into a corpus path before scan_images.py ever sees them, so run_docker_scan.sh captures the top-level invocation before it rewrites any argument; running scan_images.py directly falls back to reconstructing its own argv.
- `repo-corpus` skill (phase 1 of the org-wide repository scanner design): enumerates an org or user via `gh`, clones with hardened flags, and emits a `corpus.json` manifest. Ships `scripts/_walk.py` (shared walking with prune counting and unreadable-path tracking) and a self-test that proves the clone hardening holds.
- Design spec and phase 1 implementation plan under `docs/superpowers/`.
- `repo-docker-scanner` skill (phase 2): detects mutable container image references across a corpus and prioritises them by execution context. Dockerfiles are parsed rather than grepped; YAML is read structurally by a stdlib-only indentation reader; passes deliberately overlap so a block scalar the structural reader skips is still covered by the raw-text pass. Emits `report.md`, `findings.json` and SARIF 2.1.0, with a checked-in baseline for accepted risk and `probe.py` for adversarial verification. The four historical grep-filter bugs from the source playbook are regression assertions.
- `build_corpus.py --branch NAME` pins the corpus to one branch across every repository, checking it out as the working tree scanners walk. Repositories without that branch are recorded as `skipped` with a reason and summarised in `warnings[]`, never dropped and never counted as failures. Manifest entries gain `checked_out` (the branch on disk) alongside `default_branch` (the repository's own default).

### Changed
- `repo-corpus` and the two planned scanners consume a corpus rather than enumerating repositories themselves, so single-repo lint mode and org-wide audit share one code path.

### Fixed
- `repo-docker-scanner`'s new "Priority tiers explained" section described the wrong scanner: hand-written prose about npm publish pipelines, `curl | bash`, and contributor setup docs — `repo-packages-scanner`'s tier model, not this scanner's. Replaced with a legend generated from `policy/images.json`'s own `priority_rules`, so the text shown can never again describe rules that are not the ones actually applied.
- `repo-docker-scanner` was not tiering infrastructure-as-code templates as P0 unless their path happened to match an existing glob (`*.tf`, `.github/workflows/`, etc). A real org run found a docker reference inside a CloudFormation template (`server/scripts/aws_ec2_elb/template-cf-ec2-elb.yml`) fall through to the P1 default because nothing named that directory as production. CloudFormation is now detected by content (`AWSTemplateFormatVersion`, or a `Type: AWS::…` resource block) the same way a renamed Dockerfile is caught by content rather than name, and tiered P0 regardless of where it lives in the tree.
- `repo-docker-scanner` was lowercasing part of template-composed references (class `unresolved`) when reporting them: `${ECRRepositoryName}` became `${ecrrepositoryname}` while `${AWS::Region}` elsewhere in the same string stayed untouched, because the image-reference normalizer was run on a string that is not an image reference. Unresolved references are now reported and inventoried verbatim.
- `repo-docker-scanner` Dockerfile discovery and its `**/Dockerfile*` priority rule now match by prefix and case-insensitively (`Dockerfile.dev`, `Dockerfile-api`, and a plain `dockerfile` from a case-insensitive checkout), so a missed Dockerfile can no longer silently drop a whole file's worth of `FROM` lines from the report or mistier a real one to the P1 default.
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
