#!/usr/bin/env python3
"""
scan_artifacts.py - Hunt payload artifacts, C2 indicators and registry tampering.

This is the SECOND, INDEPENDENT axis of a supply-chain investigation. The package
list tells you if you installed a bad version; this tells you if the payload ever
ran. Run both - agreement between two independent axes is what makes a clean
verdict trustworthy.

Checks performed:
  1. SHA-1 AND SHA-256 of every candidate file vs known payload hashes (authoritative)
  2. IOC path patterns (e.g. node_modules/keyv/Math_Symbol.js, .claude/setup.mjs)
  3. Malicious install hooks in package.json (the campaign's infection vector)
  4. IDE persistence configs: .claude SessionStart, .vscode folderOpen  [REVIEW tier]
  5. Orphan payload filenames (setup_bun.js, bun_environment.js, ...)
  6. C2 domains + campaign strings in file contents
  7. Malware staging dirs in the real TMPDIR (macOS uses /var/folders, not /tmp)
  8. Live processes referencing payload filenames (point-in-time)
  9. npm / pip registry config tampering (mirror hijack)
 10. GitHub repos matching the campaign's exfil description

Filename matches are NOT findings. They are triaged against the profile's
known_benign_collisions and then confirmed or cleared by hash.

Usage:
  scan_artifacts.py --profile iocs/keyv-shai-hulud-2026-08.json ROOT [ROOT ...]
  scan_artifacts.py --profile p.json --json out.json ROOT

Exit codes: 0 = clean, 1 = CONFIRMED artifact found, 2 = error.
"""
import argparse, collections, fnmatch, glob, hashlib, json, os, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scanroots import default_roots, make_pruner
# Content-scan only these; avoids hashing gigabytes of binaries.
TEXT_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".yml", ".yaml",
            ".sh", ".bash", ".zsh", ".py", ".md", ".mdc", ".txt", ".toml", ".cfg",
            ".ini", ".conf", ".env", ".lock", ""}
MAX_CONTENT_BYTES = 4 * 1024 * 1024


def digests(path):
    """Return {'sha1': hex, 'sha256': hex} in a single read.

    Vendors publish different algorithms for the same campaign (Wiz used SHA-1,
    Aikido SHA-256). Computing both means one profile can carry every vendor's
    hashes, and a payload is caught whichever set you happen to have.
    """
    h1, h256 = hashlib.sha1(), hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h1.update(chunk)
                h256.update(chunk)
    except Exception:
        return {}
    return {"sha1": h1.hexdigest(), "sha256": h256.hexdigest()}


class ArtifactScanner:
    def __init__(self, profile, exclude_globs=(), exclude_files=(), exclude_dirs=()):
        self.p = profile
        # NOTE: fnmatch's '*' crosses '/' separators (unlike shell globs), so a
        # pattern like "<dir>/*" silently excludes that dir's ENTIRE subtree.
        # Self-exclusion therefore uses exact files and directory prefixes, and
        # only user-supplied patterns go through fnmatch.
        self.exclude_globs = list(exclude_globs)
        self.exclude_files = {os.path.realpath(f) for f in exclude_files}
        self.exclude_dirs = [os.path.realpath(d).rstrip(os.sep) + os.sep for d in exclude_dirs]
        self.confirmed = []   # hash match / IOC path match -> real finding
        self.review = []      # content hits needing human read
        self.cleared = []     # name collision explained by profile
        self.unreadable = []  # paths the OS refused - NOT the same as "clean"
        self.stats = collections.defaultdict(int)

        self.hashes = {}
        for algo in ("file_hashes_sha1", "file_hashes_sha256"):
            for k, v in (profile.get(algo) or {}).items():
                self.hashes[k.lower()] = v
        self.size_hints = {h["filename"]: h for h in profile.get("payload_size_hints", [])}
        self.hook_re = self._compile(profile.get("install_hook_patterns"))
        self.proc_re = self._compile(profile.get("process_patterns"))
        self.cand_names = set()
        for pat in profile.get("path_patterns", []):
            self.cand_names.add(os.path.basename(pat.replace("**/", "")))
        self.cand_names |= set(profile.get("orphan_filenames", []))
        terms = list(profile.get("domains", [])) + list(profile.get("strings", []))
        self.content_re = re.compile("|".join(re.escape(t) for t in terms)) if terms else None

    @staticmethod
    def _compile(patterns):
        return re.compile("|".join(patterns), re.I) if patterns else None

    def excluded(self, path):
        rp = os.path.realpath(path)
        if rp in self.exclude_files:
            return True
        if any(rp.startswith(d) for d in self.exclude_dirs):
            return True
        return any(fnmatch.fnmatch(path, g) for g in self.exclude_globs)

    def benign(self, path):
        for c in self.p.get("known_benign_collisions", []):
            if c["path_contains"] in path:
                return c["reason"]
        return None

    def ioc_path_match(self, path):
        norm = path.replace(os.sep, "/")
        for pat in self.p.get("path_patterns", []):
            if pat.startswith("**/"):
                if os.path.basename(norm) == os.path.basename(pat[3:]):
                    return pat
            elif norm.endswith("/" + pat.lstrip("/")) or ("/" + pat.strip("/") + "/") in norm + "/":
                return pat
        return None

    def check_install_hooks(self, path):
        """Malicious install hooks in package.json - the campaign's infection vector.

        Matches hook COMMANDS against payload patterns, not merely the presence
        of a hook: legitimate packages routinely ship postinstall scripts.
        """
        if not self.hook_re:
            return
        try:
            d = json.load(open(path, errors="replace"))
        except Exception:
            return
        scripts = d.get("scripts")
        if not isinstance(scripts, dict):
            return
        self.stats["manifests_checked"] += 1
        # The worm REPLACES the whole scripts object when republishing a stolen
        # package, so an exact match is a strong standalone signal.
        for sig in self.p.get("exact_scripts_signatures", []):
            if scripts == sig["scripts"]:
                self.confirmed.append({
                    "type": "scripts-rewrite", "path": path,
                    "detail": f"scripts == {json.dumps(sig['scripts'])} - {sig['detail']}"})
        for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
            cmd = scripts.get(hook)
            if isinstance(cmd, str) and self.hook_re.search(cmd):
                self.confirmed.append({
                    "type": "install-hook", "path": path,
                    "detail": f'"{hook}": "{cmd}" references a known payload'})

    def check_ide_persistence(self, path):
        """IDE persistence configs. REVIEW tier, never CONFIRMED.

        SessionStart hooks and folderOpen tasks are legitimate features that many
        developers use intentionally. Flagging them as compromise would reproduce
        exactly the false-positive problem this skill exists to avoid.
        """
        norm = path.replace(os.sep, "/")
        for rule in self.p.get("ide_persistence", []):
            if not norm.endswith(rule["path_suffix"]):
                continue
            try:
                txt = open(path, errors="replace").read()
            except Exception:
                return
            hits = [m for m in rule["markers"] if m in txt]
            if not hits:
                continue
            self.stats["ide_configs_flagged"] += 1

            # Datadog published hashes for the malicious tasks.json / settings.json,
            # so these can now be CONFIRMED outright instead of left for a human.
            dg = digests(path)
            matched = next((self.hashes[v] for v in dg.values()
                            if v and v.lower() in self.hashes), None)
            if matched:
                self.confirmed.append({
                    "type": "ide-persistence-hash", "path": path,
                    "sha256": dg.get("sha256"), "detail": matched})
                return

            # Cross-wiring is the worm's signature: the VS Code task runs
            # node .claude/setup.mjs and the Claude hook runs node .vscode/setup.mjs.
            # Each pointing into the OTHER tool's directory is highly anomalous.
            for cw in self.p.get("ide_cross_wiring", []):
                if norm.endswith(cw["path_suffix"]) and cw["must_not_reference"] in txt:
                    self.confirmed.append({
                        "type": "ide-cross-wiring", "path": path,
                        "detail": f"references {cw['must_not_reference']} - {cw['detail']}"})
                    return

            self.review.append({
                "path": path, "indicators": hits,
                "note": "IDE persistence surface - legitimate hooks look identical. "
                        "Read the command it runs and confirm you added it."})

    def scan_file(self, path):
        self.stats["files_walked"] += 1
        base = os.path.basename(path)
        ext = os.path.splitext(base)[1].lower()

        if base == "package.json":
            self.check_install_hooks(path)
        if base in ("settings.json", "settings.local.json", "tasks.json"):
            self.check_ide_persistence(path)

        # --- hash check on candidates ---
        if base in self.cand_names:
            dg = digests(path)
            self.stats["files_hashed"] += 1
            reason = self.benign(path)
            hit_path = self.ioc_path_match(path)
            matched = next((self.hashes[v] for v in dg.values()
                            if v and v.lower() in self.hashes), None)
            # Size heuristic catches UNKNOWN variants: hashes only match payloads
            # a vendor has already published. Benign collisions are checked first,
            # so a known-good path is never promoted by size alone.
            hint = self.size_hints.get(base)
            big = False
            if hint and not reason:
                try:
                    big = os.path.getsize(path) >= hint["min_bytes"]
                except OSError:
                    big = False
            if matched:
                self.confirmed.append({
                    "type": "payload-hash", "path": path,
                    "sha1": dg.get("sha1"), "sha256": dg.get("sha256"),
                    "detail": matched})
            elif big:
                self.confirmed.append({
                    "type": "payload-size", "path": path,
                    "sha1": dg.get("sha1"), "sha256": dg.get("sha256"),
                    "detail": f"{os.path.getsize(path)} bytes - {hint['note']}"})
            elif hit_path and not reason:
                self.confirmed.append({
                    "type": "ioc-path", "path": path,
                    "sha1": dg.get("sha1"), "sha256": dg.get("sha256"),
                    "detail": f"matches IOC path pattern {hit_path}"})
            elif reason:
                self.cleared.append({"path": path, "sha1": dg.get("sha1"), "reason": reason})
            else:
                self.cleared.append({
                    "path": path, "sha1": dg.get("sha1"),
                    "reason": "filename collision; neither SHA-1 nor SHA-256 matches a known payload"})

        # --- content check ---
        if self.content_re and ext in TEXT_EXT:
            try:
                if os.path.getsize(path) > MAX_CONTENT_BYTES:
                    return
                txt = open(path, errors="replace").read()
            except PermissionError:
                self.unreadable.append(path)
                return
            except Exception:
                return
            self.stats["files_grepped"] += 1
            hits = sorted(set(self.content_re.findall(txt)))
            if hits:
                self.review.append({"path": path, "indicators": hits})

    def walk(self, root, prune=None):
        prune = prune or make_pruner()
        # A file passed as a root must be scanned directly: os.walk() on a file
        # yields nothing, which would silently report CLEAN having checked nothing.
        if os.path.isfile(root):
            if not self.excluded(root):
                self.scan_file(root)
            return
        def on_walk_error(e):
            self.unreadable.append(getattr(e, "filename", str(e)))
        for dp, dns, fns in os.walk(root, onerror=on_walk_error):
            prune(dp, dns)
            for fn in fns:
                p = os.path.join(dp, fn)
                if not self.excluded(p):
                    self.scan_file(p)

    # ---------- environment checks ----------
    def check_tmp(self):
        """NOTE: the loader only creates bun-dl-* when bun is ABSENT; it reuses any
        working bun already on the host. On a machine with Bun installed, an empty
        result here is NOT evidence of non-infection."""
        out = []
        tmpdirs = {"/tmp", "/private/tmp", os.environ.get("TMPDIR", "").rstrip("/")}
        for t in filter(None, tmpdirs):
            for g in self.p.get("tmp_dir_globs", []):
                for hit in glob.glob(os.path.join(t, g)):
                    out.append(hit)
                    self.confirmed.append({
                        "type": "staging-dir", "path": hit,
                        "detail": "malware download/staging directory"})
        return out

    def check_processes(self):
        """Live processes referencing payload filenames. Point-in-time only:
        catches an in-progress infection, never one that already exited."""
        if not self.proc_re:
            return "(no process patterns configured)"
        try:
            r = subprocess.run(["ps", "-axo", "pid,ppid,command"],
                               capture_output=True, text=True, timeout=30)
        except Exception as e:
            return f"(ps unavailable: {e})"
        me = str(os.getpid())
        hits = []
        for line in r.stdout.splitlines()[1:]:
            if not self.proc_re.search(line):
                continue
            # Skip this scanner and any grep/editor viewing the patterns.
            if line.split()[:1] == [me] or "scan_artifacts" in line or "selftest" in line:
                continue
            hits.append(line.strip())
            self.confirmed.append({
                "type": "live-process", "path": line.strip(),
                "detail": "running process references a known payload filename"})
        return hits or "none"

    def check_host_persistence(self):
        """Dormant gh-token-monitor persistence and runtime locks (Datadog).

        This survives removal of the packages entirely - a LaunchAgent or systemd
        user unit keeps running long after node_modules is cleaned - so it is
        checked by absolute path regardless of the scan roots."""
        found = []
        for raw in self.p.get("host_persistence_paths", []):
            pth = os.path.expanduser(raw)
            if os.path.exists(pth):
                found.append(pth)
                self.confirmed.append({
                    "type": "host-persistence", "path": pth,
                    "detail": "dormant token-monitor persistence artifact"})
        rt = self.p.get("runtime_markers", {})
        tmpdirs = {"/tmp", "/private/tmp", os.environ.get("TMPDIR", "").rstrip("/")}
        for lock in rt.get("lock_files", []):
            for t in filter(None, tmpdirs):
                cand = os.path.join(t, lock)
                if os.path.exists(cand):
                    found.append(cand)
                    self.confirmed.append({
                        "type": "runtime-lock", "path": cand,
                        "detail": "payload single-instance lock - implies the second stage ran"})
        return found or "none"

    def check_registries(self):
        res = {}
        exp = self.p.get("expected_registries", {})
        try:
            r = subprocess.run(["npm", "config", "get", "registry"],
                               capture_output=True, text=True, timeout=30)
            actual = r.stdout.strip()
            res["npm"] = actual
            if exp.get("npm") and actual and actual.rstrip("/") != exp["npm"].rstrip("/"):
                self.confirmed.append({
                    "type": "registry-tamper", "path": "npm config registry",
                    "detail": f"expected {exp['npm']}, got {actual}"})
        except Exception as e:
            res["npm"] = f"(could not query: {e})"

        pip_cfgs = [os.path.expanduser("~/.pip/pip.conf"),
                    os.path.expanduser("~/.config/pip/pip.conf"),
                    "/Library/Application Support/pip/pip.conf"]
        found = []
        for c in pip_cfgs:
            if os.path.isfile(c):
                body = open(c, errors="replace").read()
                found.append({"path": c, "body": body})
                for d in self.p.get("domains", []):
                    if d in body:
                        self.confirmed.append({
                            "type": "registry-tamper", "path": c,
                            "detail": f"pip config references IOC domain {d}"})
        res["pip_configs"] = found or "(none - default PyPI)"
        return res

    def check_github(self):
        markers = [m.lower() for m in self.p.get("github_repo_description_markers", [])]
        if not markers:
            return "(no markers configured)"
        try:
            r = subprocess.run(
                ["gh", "repo", "list", "--limit", "300", "--json", "name,description,createdAt,visibility"],
                capture_output=True, text=True, timeout=90)
            if r.returncode != 0:
                return f"(gh unavailable: {r.stderr.strip()[:120]})"
            repos = json.loads(r.stdout or "[]")
        except Exception as e:
            return f"(gh unavailable: {e})"
        bad = [x for x in repos
               if x.get("description") and any(m in x["description"].lower() for m in markers)]
        for b in bad:
            self.confirmed.append({
                "type": "exfil-repo", "path": b["name"],
                "detail": f"repo description matches campaign marker: {b['description']!r}"})
        return {"repos_checked": len(repos), "exfil_repos": bad}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("roots", nargs="*", help="default: $HOME")
    ap.add_argument("--profile", required=True)
    ap.add_argument("--json")
    ap.add_argument("--exclude", action="append", default=[],
                    help="glob to exclude from content scan (repeatable)")
    ap.add_argument("--skip", action="append", default=[],
                    help="extra directory path-suffix to prune (repeatable)")
    ap.add_argument("--no-env", action="store_true",
                    help="skip TMPDIR / registry / GitHub environment checks")
    a = ap.parse_args()

    profile = json.load(open(a.profile))
    roots = a.roots or default_roots()
    prune = make_pruner(a.skip or ())

    # Always exclude the scanner's own IOC data and agent transcripts: they
    # legitimately contain every domain and string and would self-match.
    # Exact files + directory prefixes only - see ArtifactScanner.__init__.
    exclude_files = [os.path.abspath(a.profile)]
    exclude_dirs = [
        # The whole skill dir: its IOC profile, docs and self-test fixtures all
        # legitimately contain every domain and string, and would self-match.
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        os.path.expanduser("~/.claude/projects"),
        os.path.expanduser("~/.claude/history"),
    ]
    exclude_globs = list(a.exclude) + ["*keyv-packages.csv"]

    sc = ArtifactScanner(profile, exclude_globs, exclude_files, exclude_dirs)
    print("=" * 72)
    print(f"Campaign : {profile.get('campaign')}")
    print(f"Roots    : {', '.join(roots)}")
    print("=" * 72)

    for r in roots:
        if not os.path.exists(r):
            sys.exit(f"ERROR: root does not exist: {r}")
        sc.walk(r, prune)

    env = {}
    if not a.no_env:
        env["tmp_staging"] = sc.check_tmp()
        env["processes"] = sc.check_processes()
        env["host_persistence"] = sc.check_host_persistence()
        env["registries"] = sc.check_registries()
        env["github"] = sc.check_github()

    print(f"\nCoverage: {dict(sc.stats)}")

    print(f"\n### CONFIRMED ARTIFACTS: {len(sc.confirmed)}")
    for c in sc.confirmed:
        print(f"  [!!] {c['type']}: {c['path']}\n       {c['detail']}")
    if not sc.confirmed:
        print("  none")

    print(f"\n### CONTENT HITS - read each manually: {len(sc.review)}")
    for r_ in sc.review:
        print(f"  [??] {r_['path']}\n       indicators: {', '.join(r_['indicators'])}")
        if r_.get("note"):
            print(f"       {r_['note']}")
    if not sc.review:
        print("  none")

    print(f"\n### CLEARED name collisions (hash-verified benign): {len(sc.cleared)}")
    for c in sc.cleared[:20]:
        print(f"  [ok] {os.path.basename(c['path'])}  sha1={(c['sha1'] or '?')[:12]}...\n       {c['reason']}\n       {c['path']}")
    if len(sc.cleared) > 20:
        print(f"  ... +{len(sc.cleared)-20} more")

    if not a.no_env:
        print("\n### ENVIRONMENT")
        print(f"  TMPDIR staging dirs : {env['tmp_staging'] or 'none'}")
        print(f"  live processes      : {env['processes']}")
        print(f"  host persistence    : {env['host_persistence']}")
        print(f"  npm registry        : {env['registries'].get('npm')}")
        print(f"  pip configs         : {env['registries'].get('pip_configs')}")
        print(f"  GitHub              : {env['github']}")

    if a.json:
        json.dump({"confirmed": sc.confirmed, "review": sc.review,
                   "cleared": sc.cleared, "env": env, "stats": dict(sc.stats),
                   "unreadable": sc.unreadable},
                  open(a.json, "w"), indent=2, default=str)
        print(f"\nJSON report -> {a.json}")

    if sc.unreadable:
        print(f"\n### UNREADABLE - NOT SCANNED, NOT CLEAN: {len(sc.unreadable)}")
        print("  macOS TCC blocks these without Full Disk Access. Sample:")
        for pth in sc.unreadable[:8]:
            print(f"    {pth}")
        if len(sc.unreadable) > 8:
            print(f"    ... +{len(sc.unreadable)-8} more")

    if sc.confirmed:
        verdict = "ARTIFACTS FOUND"
    elif sc.unreadable:
        verdict = f"CLEAN over what was readable - {len(sc.unreadable)} path(s) COULD NOT BE READ"
    elif sc.review:
        verdict = "CLEAN (review content hits above)"
    else:
        verdict = "CLEAN"
    print("\nVERDICT:", verdict)
    return 1 if sc.confirmed else 0


if __name__ == "__main__":
    sys.exit(main())
