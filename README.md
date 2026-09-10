# GenericSuite Security Suite (`gs-security-suite`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Claude Code Plugin](https://img.shields.io/badge/Claude_Code-Plugin-purple.svg)](.claude-plugin/marketplace.json)
[![Antigravity Compatible](https://img.shields.io/badge/Google_Antigravity-Compatible-4285F4.svg)](#google-antigravity-agy)

**`genericsuite-security`** is a security auditing and production-readiness suite for software repositories and developer environments. It provides **a set of specialized AI agent skills** backed by zero-dependency Python 3 standard library scripts.

Whether used interactively through AI coding assistants (**Claude Code**, **Google Antigravity**, **Cursor**, **Windsurf**, etc.) or directly as standalone CLI tools in CI/CD pipelines, this package helps developers audit supply chain dependencies, pin container references, eliminate unpinned GitHub Actions, and verify project readiness before production deployment.

---

## Table of Contents

- [Overview & Architecture](#overview--architecture)
- [Included Skills](#included-skills)
- [AI Agent Installation Guide](#ai-agent-installation-guide)
  - [Claude Code](#claude-code)
  - [Skills CLI](#skills-cli)
  - [Google Antigravity (AGY)](#google-antigravity-agy)
  - [Cursor](#cursor)
  - [Windsurf & Other Open-Skill Agents](#windsurf--other-open-skill-agents)
- [Skill Reference & Usage](#skill-reference--usage)
  - [1. Supply-Chain IOC Scan](#1-supply-chain-ioc-scan)
  - [2. Repo Corpus](#2-repo-corpus)
  - [3. Repo Docker Scanner](#3-repo-docker-scanner)
  - [4. Repo Packages Scanner](#4-repo-packages-scanner)
  - [5. Project Weakness Analysis](#5-project-weakness-analysis)
- [Standalone CLI Usage (No AI Required)](#standalone-cli-usage-no-ai-required)
- [Verification & Self-Testing](#verification--self-testing)
- [License & Support](#license--support)

---

## Overview & Architecture

The suite is built around core security engineering principles:

1. **Zero External Dependencies**: Scanners are written in standard library Python 3 (`python3`). No `pip install`, virtual environments, or native toolchains are required to run scans.
2. **Two Independent Detection Axes**: Compromise detection validates both the *dependency axis* ("did we resolve a malicious package version?") and the *artifact axis* ("did the payload execute or persist?"). A verdict requires agreement across both.
3. **Corpus-Driven Static Analysis**: Scanners separate repository enumeration (`repo-corpus`) from detection logic. Repositories are cloned into safe, isolated directories with execution mechanisms disabled.
4. **Self-Testing Verification**: Every scanner carries a synthetic test suite (`tests/selftest.py`). A "clean" scan result is only trusted if the scanner first passes its self-test against known synthetic indicators.

---

## Included Skills

| Skill | Directory | Description | Triggers / Prompts |
|---|---|---|---|
| **`supply-chain-ioc-scan`** | [skills/supply-chain-ioc-scan](skills/supply-chain-ioc-scan) | Triage disclosed supply-chain attacks and npm/PyPI worms (e.g. Shai-Hulud) across local disk & caches. | *"Are we affected by [campaign]?"*, *"Check for compromised dependencies"*, *"Did we install the bad version?"* |
| **`repo-corpus`** | [skills/repo-corpus](skills/repo-corpus) | Enumerate & clone a GitHub org, user, or local directory into safe checkouts with a `corpus.json` manifest. | *"Clone all repos in my org"*, *"Audit every repository"*, *"Build a repo corpus"* |
| **`repo-docker-scanner`** | [skills/repo-docker-scanner](skills/repo-docker-scanner) | Scan container references for mutable tags (`:latest`, floating tags) tiered by execution context (P0/P1/P2). | *"Are our docker images pinned?"*, *"Find :latest tags"*, *"Image digest pinning"* |
| **`repo-packages-scanner`** | [skills/repo-packages-scanner](skills/repo-packages-scanner) | Scan GitHub Actions (`uses:`) & package lockfiles for unpinned versions, floating ranges, and `curl \| bash`. | *"Are our GitHub Actions pinned?"*, *"Unpinned dependencies"*, *"Missing lockfile"*, *"curl pipe bash"* |
| **`project-weakness-analysis`** | [skills/project-weakness-analysis](skills/project-weakness-analysis) | Score production-readiness and security risk per project across independent, non-averaged axes. | *"Is this ready for production?"*, *"Audit my projects"*, *"Production readiness review"* |

---

## AI Agent Installation Guide

The skills follow the standard **Agent Skills / Open Skill Specification** format (`SKILL.md` with YAML frontmatter). Below are instructions for installing and enabling the plugin across different AI agents.

### Claude Code

Using the Claude Code **plugin marketplace**:

```bash
claude

/plugin marketplace add tomkat-cr/genericsuite-security

/plugin install gs-security-suite@genericsuite-security
```

### Skills CLI

Using the **Vercel Skills CLI ([skills.sh](https://skills.sh))**:

```bash
npx skills add tomkat-cr/genericsuite-security
```

---

### Google Antigravity (AGY)

Google Antigravity discovers skills placed inside standard skill paths or plugin configurations.

#### Option A: Global Skills Installation (User Level)
Symlink or copy the `skills` directory into your Antigravity skills path:
```bash
# Create the global skills folder if it doesn't exist
mkdir -p ~/.gemini/antigravity/skills

# Symlink all skills from this repository
ln -s /path/to/genericsuite-security/skills/* ~/.gemini/antigravity/skills/
```

#### Option B: Workspace-Specific Installation
To enable the security skills for a single Antigravity workspace:
```bash
mkdir -p .gemini/skills
cp -r /path/to/genericsuite-security/skills/* .gemini/skills/
```

#### Option C: Antigravity Plugin Manager
Place or link the repository under the Antigravity plugin directory:
```bash
mkdir -p ~/.gemini/config/plugins/
ln -s /path/to/genericsuite-security ~/.gemini/config/plugins/genericsuite-security
```

Once installed, ask Antigravity to run any security task (e.g., *"Antigravity, audit all GitHub Actions in my repo for unpinned commits"*).

---

### Cursor

Cursor uses `.cursor/rules/` or project context files (`.cursorrules`) to guide AI behavior.

#### Option A: Project Rules (`.cursor/rules/`)
Link or copy the `SKILL.md` files into your project's `.cursor/rules/` directory:
```bash
mkdir -p .cursor/rules

# Example: Enable Project Weakness Analysis skill in Cursor
cp /path/to/genericsuite-security/skills/project-weakness-analysis/SKILL.md .cursor/rules/project-weakness-analysis.mdc
cp /path/to/genericsuite-security/skills/repo-packages-scanner/SKILL.md .cursor/rules/repo-packages-scanner.mdc
```

#### Option B: Direct File Reference in Cursor Chat
In Cursor chat (`Cmd+L` or `Ctrl+L`), reference the desired `SKILL.md` file using `@`:
```text
@skills/supply-chain-ioc-scan/SKILL.md Please check if our repository is affected by the recent npm supply chain disclosure.
```

---

### Windsurf & Other Open-Skill Agents

Any AI agent that adheres to the standard Agent Skills format can use these skills directly.

1. **Add Skills Path**: Point your agent's custom skills setting or workspace instructions to the `skills/` directory of this repo.
2. **Direct Context Prompting**: Attach `skills/<skill-name>/SKILL.md` to your agent session.

---

## Skill Reference & Usage

### 1. Supply-Chain IOC Scan

- **Directory**: [skills/supply-chain-ioc-scan](skills/supply-chain-ioc-scan)
- **Purpose**: Rapid incident triage when an npm, PyPI, or vendor supply-chain attack (e.g., Keyv / Cacheable Shai-Hulud worm) is disclosed.
- **Key Features**:
  - Scans both **dependency axis** (lockfiles, `~/.npm/_cacache`, `node_modules`) and **artifact axis** (SHA-1/256 payload hashes, C2 domains, IDE hooks, processes).
  - Merges vendor indicator feeds (Socket.dev, Wiz, Datadog) with offline fallback.
  - Produces evidence-backed verdicts (`CONFIRMED` vs `REVIEW`).

#### Invocation via AI Agent
> *"Scan my machine for exposure to the recent Shai-Hulud npm supply chain worm."*

#### Standalone CLI Execution
```bash
cd skills/supply-chain-ioc-scan

# Run full scan (scans $HOME by default)
./scripts/run_scan.sh

# Scan specific directories
./scripts/run_scan.sh ~/projects/app1 ~/projects/app2

# Scan with a custom IOC profile
PROFILE=iocs/custom-campaign.json ./scripts/run_scan.sh ~/projects
```
- **Exit Codes**: `0` Clean, `1` Findings detected, `2` Error.
- **Output**: Reports saved to `$TMPDIR/ioc-scan-<timestamp>/`.

---

### 2. Repo Corpus

- **Directory**: [skills/repo-corpus](skills/repo-corpus)
- **Purpose**: Phase 1 foundation for org-wide scanning. Safely clones repositories from a GitHub organization, user, or directory tree into an attributable `corpus.json` manifest.
- **Key Features**:
  - Zero-trust git clone flags (prevents execution of hooks, submodules, or malicious code during clone).
  - Explicit tracking of pruned trees, unreadable directories, or failed clones (no silent gaps).
  - Branch pinning (`--branch NAME`) for multi-repo cross-auditing.

#### Invocation via AI Agent
> *"Build a repository corpus for the GitHub organization `my-org`."*

#### Standalone CLI Execution
```bash
cd skills/repo-corpus

# Clone an entire GitHub organization
./scripts/run_corpus.sh --org my-org

# Build a corpus from an existing local folder (no cloning)
./scripts/run_corpus.sh --local ~/my-projects

# Check scope only without cloning
python3 scripts/build_corpus.py --org my-org --list-only
```
- **Exit Codes**: `0` Complete corpus, `1` Partial corpus (failures logged), `2` Error.
- **Output**: Writes `corpus.json` and clones repos under `corpus/`.

---

### 3. Repo Docker Scanner

- **Directory**: [skills/repo-docker-scanner](skills/repo-docker-scanner)
- **Purpose**: Phase 2 static analysis scanner. Detects mutable container image references (`:latest`, floating tags, missing digests) and tiers findings by execution context.
- **Key Features**:
  - Context-aware priority tiering:
    - **P0**: Production deployments, CI release pipelines, IaC templates (Terraform, CloudFormation).
    - **P1**: Development CI, test suites, base image Dockerfiles.
    - **P2**: Examples, local dev-compose, documentation.
  - Opt-in tag-to-digest resolution (`--resolve`) via anonymous registry OAuth API calls (Docker Hub, GHCR, Quay).
  - Policy baseline support (`policy/images.json`) for accepted risks.

#### Invocation via AI Agent
> *"Find all unpinned container images across our GitHub organization repos."*

#### Standalone CLI Execution
```bash
cd skills/repo-docker-scanner

# Build corpus & scan an entire organization
./scripts/run_docker_scan.sh --org my-org

# CI lint mode on local repository (fails if P0 findings exist)
./scripts/run_docker_scan.sh --local . --fail-on P0

# Scan existing corpus with registry resolution enabled
./scripts/run_docker_scan.sh --corpus ../repo-corpus/corpus.json --resolve
```
- **Exit Codes**: `0` Clean (under threshold), `1` Findings above threshold, `2` Error.
- **Output**: Generates `report.md`, `findings.json`, and SARIF format `findings.sarif`.

---

### 4. Repo Packages Scanner

- **Directory**: [skills/repo-packages-scanner](skills/repo-packages-scanner)
- **Purpose**: Phase 3 static analysis scanner. Audits GitHub Actions (`uses:` refs) and package dependencies across npm, PyPI, Go, Rust, Ruby, and Poetry.
- **Key Features**:
  - Flags unpinned GitHub Actions (must use 40-character commit SHA, e.g. `actions/checkout@a5ac7e5...`).
  - Detects floating dependency ranges, missing lockfiles, and `npm install` in CI (instead of `npm ci`).
  - Detects unpinned remote code execution (`curl | bash`, `wget | sh`).
  - Includes `run_gh_scan.sh` for scanning GitHub user/org public repositories for compromise keywords.

#### Invocation via AI Agent
> *"Check if any of our GitHub Actions use mutable tags or floating dependency ranges."*

#### Standalone CLI Execution
```bash
cd skills/repo-packages-scanner

# Scan an organization
./scripts/run_packages_scan.sh --org my-org

# CI lint mode on local repository
./scripts/run_packages_scan.sh --local . --fail-on P0

# Scan corpus with Action publisher resolution via GitHub API
./scripts/run_packages_scan.sh --corpus ../repo-corpus/corpus.json --resolve

# User / Org account compromise scan
./scripts/run_gh_scan.sh username "malicious-keyword" 2026-01-01
```
- **Exit Codes**: `0` Clean, `1` Findings above threshold, `2` Error.
- **Output**: Generates `report.md`, `findings.json`, and SARIF format `findings.sarif`.

---

### 5. Project Weakness Analysis

- **Directory**: [skills/project-weakness-analysis](skills/project-weakness-analysis)
- **Purpose**: Evaluates whether software projects are ready and safe for production deployment.
- **Key Features**:
  - **Two Independent Axes (Never Averaged)**:
    - **Readiness Tier**: `production-ready` \| `needs-work` \| `not-ready` \| `unknown`. Evaluates auth, error handling, tests, CI, code organization.
    - **Security Risk Level**: `critical` \| `high` \| `medium` \| `low` \| `none`. Evaluates secret leaks, auth bypass, PII exposure, unpinned supply-chain dependencies.
  - **5 Flexible Input Modes**: Local tree (`--root`), explicit directory list (`--projects`), existing corpus (`--corpus`), GitHub org/user (`--org`), or project database (`--db`).
  - **Re-audit Loop**: Second pass verifies prior findings (`resolved` \| `partial` \| `open`).

#### Invocation via AI Agent
> *"Perform a production-readiness and security review on all projects in ~/projects."*

#### Standalone CLI Execution
```bash
cd skills/project-weakness-analysis

# Scan local project tree
./scripts/run_weakness_analysis.sh --root ~/projects

# Scan explicit list of directories
./scripts/run_weakness_analysis.sh --projects ~/dev/app1 ~/dev/app2

# Scan an existing corpus
./scripts/run_weakness_analysis.sh --corpus ../repo-corpus/corpus.json

# Merge prior scan outputs without re-scanning
./scripts/run_weakness_analysis.sh --phase merge
```
- **Exit Codes**: `0` All projects passed gates, `1` Gate failures / blocked projects, `2` Error.
- **Output**: Generated in `./insights/`:
  - `WEAKNESS-REPORT.md` (Human-readable summary)
  - `insights.json` & `security-audit.json`
  - `insights-table.csv` / `.json` (Flat tabular export)
  - `findings.sarif` (SARIF format for IDE / GitHub Security integration)

---

## Standalone CLI Usage (No AI Required)

All tools in `genericsuite-security` are fully functional as standalone shell and Python commands. They require only **Python 3.8+** (standard library only) and **git**.

```bash
# Example 1: Quick security check on local repo
cd skills/repo-packages-scanner
./scripts/run_packages_scan.sh --local /path/to/my/project

# Example 2: Container image audit
cd skills/repo-docker-scanner
./scripts/run_docker_scan.sh --local /path/to/my/project

# Example 3: Full supply-chain IOC scan
cd skills/supply-chain-ioc-scan
./scripts/run_scan.sh /path/to/my/project
```

---

## Verification & Self-Testing

Before trusting any scanner output, run its built-in self-test suite. Self-tests create synthetic infected test fixtures to verify that detection logic catches all synthetic indicators and produces no false positives on benign lookalikes.

```bash
# Self-test supply-chain IOC scanner
python3 skills/supply-chain-ioc-scan/tests/selftest.py

# Self-test corpus builder
python3 skills/repo-corpus/tests/selftest.py

# Self-test docker scanner
python3 skills/repo-docker-scanner/tests/selftest.py

# Self-test packages scanner
python3 skills/repo-packages-scanner/tests/selftest.py

# Self-test weakness analysis
python3 skills/project-weakness-analysis/tests/selftest.py
```

---

## License & Support

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

For generic suite ecosystem guidance, security disclosures, or contributions, visit the [GenericSuite Repository](https://github.com/genericsuite) or contact [info@genericsuite.com](mailto:info@genericsuite.com).
