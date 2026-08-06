# Triage and Response Reference

Companion to `SKILL.md`. Read when interpreting scan output or deciding on remediation.

---

## 1. Confirming vs clearing a candidate

Work down this ladder. Stop at the first line that decides.

| Check | Decides |
|---|---|
| SHA-1 matches a published payload hash | **CONFIRMED.** Authoritative, no further debate. |
| File sits at an exact IOC path (`node_modules/keyv/Math_Symbol.js`, `.claude/setup.mjs`) | **CONFIRMED** unless the profile lists it as a benign collision. |
| Filename matches but path and hash do not | **CLEARED.** Record the reason. |
| Content contains a C2 domain or campaign string | **REVIEW.** Read it yourself — never auto-confirm. |

The scanner never promotes a content hit to CONFIRMED, because your own security notes, IOC lists, and agent transcripts contain those strings verbatim.

## 2. False-positive catalogue

Observed during the 2026-08-04 keyv/cacheable investigation:

- **`regenerate-unicode-properties/General_Category/Math_Symbol.js`** — legitimate Unicode general-category table. Ships in any tree with Babel. The IOC is specifically `node_modules/keyv/Math_Symbol.js`. Confirm by checking the `keyv/` directory: a clean `keyv` contains only `README.md`, `package.json`, `src/` — **no top-level `.js` at all**.
- **`motion-dom/dist/es/gestures/utils/setup.mjs`** — legitimate `motion` gesture helper. The IOC is `setup.mjs` inside `.claude/` or `.vscode/`.
- **A system `bun` install** — the malware downloads its own Bun into `TMPDIR/bun-dl-*` and sends a `Bun/1.3.13` user-agent. A pre-existing install whose binary predates disclosure is not evidence.
- **`eth_call` in project source** — normal Web3 code. The campaign's on-chain C2 lookup only matters alongside its RPC domains.
- **Kiro/MCP `autoApprove: []`** — a standard MCP config field, unrelated to the VS Code `chat.tools.autoApprove` IDE-persistence key.
- **Your own transcripts and IOC files** — will match every domain and string. Exclude them.

## 3. Forward-looking risk: the semver check

A clean *current* state does not mean a future `npm install` is safe. After confirming no exact matches, ask whether anything can *reach* the malicious version:

```bash
python3 - <<'EOF'
import json, os, csv
ioc = {r[0].strip(): {v.strip() for v in r[1].split(",")}
       for r in list(csv.reader(open("packages.csv")))[1:] if len(r) > 1}
FIELDS = ["dependencies","devDependencies","peerDependencies",
          "optionalDependencies","resolutions","overrides"]
for root in ["."]:
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git","node_modules")]
        if "package.json" in fns:
            p = os.path.join(dp,"package.json")
            try: d = json.load(open(p, errors="replace"))
            except Exception: continue
            for f in FIELDS:
                for name, rng in (d.get(f) or {}).items():
                    if name in ioc:
                        print(f"{name} {rng}  [{f}] {p}  malicious={sorted(ioc[name])}")
EOF
```

Interpretation:

- **No output** → every IOC package is transitive-only. Nothing you declare can pull the bad version directly.
- **Malicious versions are major-version jumps** (e.g. `keyv` 6.0.0 vs your 4.5.4) → caret ranges cannot cross majors. Low risk.
- **A declared range spans the malicious version**, or a range is `*` / `latest` → real risk. Pin it or add an `overrides` entry.

Lockfiles pin transitives, so `npm ci` is safe where `npm install` may re-resolve. Prefer `npm ci` until a campaign settles.

## 4. Mapping findings to remediation

**Two campaign facts that change standard advice:**

*Provenance checks do not help here.* `keyv@6.0.0` carried a valid signed SLSA attestation because the real release workflow compiled already-trojanized source. Advisories that recommend "enable provenance/attestation verification" as a control against this campaign are wrong on this point — verification passed on the malware, and the worm mints fresh sigstore provenance for every package it republishes. Provenance proves artifact-matches-build, not source-is-clean.

*If the payload ran, these are the credentials it targeted* (per Socket's incident page) — rotate exactly these rather than guessing: AWS instance metadata credentials, HashiCorp Vault tokens, Kubernetes service-account tokens, GitHub Actions secrets, and npm tokens. Exfiltration is AES-256-GCM under an operator public key, sent to threat-actor GitHub repos and DNS-resolved destinations, so absence of plaintext secrets in logs proves nothing.


Vendor advisories typically list steps 1–6 (remove versions, rebuild hosts, rotate credentials, audit access, monitor IOCs, harden supply chain). **Steps 1–4 are conditioned on malicious code having actually executed.** Do not perform them on a clean result — credential rotation across cloud, GitHub, SSH, and CI is expensive and disruptive.

| Scan result | Response |
|---|---|
| Exact version match **or** confirmed artifact | Full incident response. Treat the host as compromised: rebuild, rotate every credential the payload could reach, audit cloud/VCS access logs from first-install time. |
| Content hits only, all explained on manual read | No remediation. Record why each was cleared. |
| Clean on both axes | Monitoring and hardening only (steps 5–6). Re-scan as the package list grows. |

Supporting evidence that strengthens a clean verdict:

- npm cache holds **zero** malicious tarballs across all cached versions
- `~/.npmrc` auth token mtime predates the campaign window
- No repo exists under the account bearing the campaign's exfil description
- `npm config get registry` and pip config are unmodified

## 5. Scope reminder

Payload artifacts are **machine-level**, not repo-level. Even when asked about specific repos, also check:

- `~/.claude/`, `~/.vscode/`, `~/.cursor/` — IDE persistence payloads
- Real `TMPDIR` — on macOS this is `/var/folders/...`, **not** `/tmp`; check both
- `~/.npmrc`, `~/.npm/_cacache`, pip configs — registry hijack and fetch history
- The GitHub account itself — exfil repos are created under the compromised identity

## 6. Reviewing another scanner's report

Community IOC scripts circulate fast during an incident and are worth running — but audit them before believing a verdict. Failure modes seen in a real one (`scan_keyv_shaihulud_ioc.sh`, 2026-08-05):

**Verify the authoritative check actually produced output.** Its hash-verification section printed *nothing at all* — no match, no mismatch, not even the "hash differs" line for the ten candidate files it had just listed. An empty section reads like "nothing to report"; here it meant the check never ran.

Root cause: macOS ships **bash 3.2.57**, which predates associative arrays.

```bash
declare -A KNOWN_HASHES=(["54dc7ea…"]="setup.mjs")
# bash 3.2: parsed as an INDEXED array; the hex subscript is evaluated as
# arithmetic -> "value too great for base" -> array never populated.
# Then ${KNOWN_HASHES[$SUM]:-} throws the same error inside the while-loop
# subshell, killing the iteration before any log line is written.
```

Because the errors go to stderr and `log()` only writes what it is handed, the report file shows a clean-looking empty section. The script had no `set -e`, so it sailed on to the next section. Check `bash --version` before trusting any bash-based scanner on macOS.

**Check whether a "verdict" is derived from evidence or from noise.** That script sets `FOUND_ANYTHING=1` on *filename* matches alone. Ten benign files (`regenerate-unicode-properties/…/Math_Symbol.js`, `motion-dom/…/setup.mjs`) tripped it, so the summary declared the machine "potentially compromised" and recommended rotating npm, GitHub, AWS/GCP/Azure, Vault, Kubernetes, Slack and Stripe credentials. On a clean machine. Escalating filename collisions to a compromise verdict is the single most expensive mistake in this class of tooling.

**Check the cache logic.** Its npm-cache section searched for files *named* `*setup.mjs*` or `*Math_Symbol*`. `_cacache` is content-addressed — every blob is named by its hash, so no original filename exists anywhere in it. That check cannot ever fire: a guaranteed false negative on the highest-value evidence source. Parse `index-v5` for tarball URLs instead.

**Check list coverage.** Its 17 hardcoded package names cover 4% of the 443 in the Wiz list — 426 compromised packages it cannot name. It also reports every hit as `[?] verify manually` with no version comparison, producing 32 lines of noise where a version check answers the question outright.

Worth keeping from it: the `preinstall: node setup.mjs` hook check, `.claude`/`.vscode` persistence paths, the live-process check, and Aikido's SHA-256 hash set — all now folded into this skill.

## 7. Ecosystems beyond npm

Feeds may list entries your scanners don't cover. For this campaign Socket.dev carries 8 golang modules — Go proxy mirrors of the compromised GitHub repos (`github.com/jaredwray/keyv`, `.../cacheable`, `.../ecto`), reachable by any Go project that imported them.

`fetch_package_lists.py` writes these to `packages.other-ecosystems.csv` and prints a warning. `scan_dependencies.py` matches golang entries against `go.mod`/`go.sum`. If a future feed adds PyPI, RubyGems or Cargo entries, the warning fires with no matching scanner — check those manifests by hand and treat the gap as known, not absent.

## 8. Post-execution artifacts (if the payload ran)

From Datadog's teardown. These persist independently of the packages, so check them even after cleanup:

| Artifact | Meaning |
|---|---|
| `tmp.dpkg_14527.lock` in the temp dir | single-instance lock — the second stage executed |
| `~/.local/bin/gh-token-monitor.sh`, `~/.config/gh-token-monitor/*` | dormant token monitor |
| `~/Library/LaunchAgents/com.user.gh-token-monitor.plist` (macOS) | persistence across reboots |
| `~/.config/systemd/user/gh-token-monitor.service` (Linux) | same, systemd |
| `_NODE_RUNTIME_INIT=1` in a process env | detached-child recursion guard |

In a compromised GitHub repo, also look for the branch `dependabot/github_actions/format/setup-formatter`, the file `.github/workflows/codeql_analysis.yml`, and an artifact `format-results.txt`. The run and branch are deleted after exfiltration, but **audit-log, workflow-run and artifact records survive** — so absence of the branch does not clear a repo.

Two scoping notes that change how far remediation must go:

*Rotation is not enough on its own.* The C2 response body is `eval`'d unsandboxed and unsigned, making the implant a general remote code-execution channel rather than only a credential stealer. If it ran, you cannot bound what else it did from the payload's fixed code.

*The lock and staging checks have a blind spot.* The loader reuses any installed `bun` and only creates `bun-dl-*` when Bun is absent, so on a Bun-equipped host that check is silently uninformative.

## 9. Coverage gaps that masquerade as clean verdicts

A scanner reports on what it read. Anything it could not read is *unknown*, and conflating the two is the most dangerous bug in this class of tooling. Three instances found while building this skill, none visible in the output until specifically hunted:

**macOS TCC.** `~/Desktop`, `~/Documents`, `~/Downloads`, `~/Library/Application Support/...` and app containers are protected. Without Full Disk Access, `os.walk` raises per-directory errors that it **silently discards** unless you pass `onerror=`, and `open()` on an individual file fails with `PermissionError: Operation not permitted` even though `ls -l` shows it fine. A `$HOME` scan on this machine hit 422 such directories. Fix: System Settings → Privacy & Security → Full Disk Access → add your terminal, then re-run. Verify with:

```bash
python3 -c "
import os
err=[]
for _ in os.walk(os.path.expanduser('~'), onerror=lambda e: err.append(e)): pass
print(len(err), 'unreadable directories')"
```

**Permission errors disguised as parse errors.** The dependency scanner originally reported an unreadable lockfile as `!! unparseable`. Those are different facts: a malformed file is probably harmless, an unreadable one is a hole in coverage. They are now counted separately.

**`os.walk()` on a file yields nothing.** Passing a file as a scan root scanned zero bytes and returned CLEAN. Both scanners now special-case files.

The general rule: after any scan, ask *what did this not look at?* — and make the tool answer it rather than inferring silence means safety.

## 10. Re-scanning

Compromised-package lists grow for days after disclosure — the keyv worm reached 400+ packages while still propagating. A verdict is valid only against the list version used. Re-run `run_scan.sh` (it re-fetches automatically) for several days after any disclosure.
