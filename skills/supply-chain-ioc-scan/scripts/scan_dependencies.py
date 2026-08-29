#!/usr/bin/env python3
"""
scan_dependencies.py - Match a tree's resolved dependencies against a compromised-package list.

Covers four independent evidence sources:
  1. package-lock.json  (lockfileVersion 1, 2 and 3)
  2. yarn.lock          (v1 and berry)
  3. pnpm-lock.yaml
  4. installed node_modules/<pkg>/package.json  (ground truth on disk)
  5. ~/.npm/_cacache    (tarballs ever FETCHED - survives deletion from disk)

The npm cache is the highest-value source: it proves whether a malicious tarball
was ever downloaded, even if the package was later removed.

Usage:
  scan_dependencies.py --csv keyv-packages.csv ROOT [ROOT ...]
  scan_dependencies.py --csv list.csv --no-cache ROOT      # skip npm cache
  scan_dependencies.py --csv list.csv --json report.json ROOT

CSV format: header row, column 1 = package name, column 2 = comma-separated
malicious versions (quoted). This is the shape Wiz/StepSecurity publish.

Exit codes: 0 = clean, 1 = COMPROMISED (exact match), 2 = error.
"""
import argparse, csv, json, os, re, sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scanroots import default_roots, make_pruner


def load_iocs(path):
    ioc = {}
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if not row or len(row) < 2:
                continue
            name, vers = row[0].strip(), row[1]
            if not name or name.lower() in ("package", "name"):
                continue
            ioc[name] = {v.strip() for v in vers.split(",") if v.strip()}
    if not ioc:
        sys.exit("ERROR: IOC list parsed to zero packages - wrong file or format?")
    return ioc


class Scanner:
    def __init__(self, ioc, go_ioc=None):
        self.ioc = ioc
        self.go_ioc = go_ioc or {}
        self.unreadable = []  # paths the OS refused - NOT the same as "clean"
        self.exact = []       # (name, version, source, kind) -> COMPROMISED
        self.name_only = []   # IOC package, non-malicious version
        self.stats = defaultdict(int)

    def record(self, name, version, source, kind):
        mal = self.ioc.get(name)
        if mal is None:
            return
        if version in mal:
            self.exact.append((name, version, source, kind))
        else:
            self.name_only.append((name, version, source, kind))

    # ---------- lockfiles ----------
    def package_lock(self, path):
        try:
            data = json.load(open(path, errors="replace"))
        except PermissionError as e:
            # macOS TCC denies reads under Desktop/Documents/Downloads unless the
            # running app has Full Disk Access. Unreadable is NOT clean.
            self.unreadable.append((path, str(e)))
            return
        except Exception as e:
            print(f"  !! unparseable {path}: {e}", file=sys.stderr)
            return
        self.stats["package-lock.json"] += 1
        for key, meta in (data.get("packages") or {}).items():
            if not key or not isinstance(meta, dict):
                continue
            name = meta.get("name")
            if not name:
                m = re.search(r"node_modules/(.+)$", key)
                name = m.group(1) if m else None
            if name and meta.get("version"):
                self.record(name, meta["version"], path, "package-lock")

        def walk(deps):
            for name, meta in (deps or {}).items():
                if isinstance(meta, dict):
                    if meta.get("version"):
                        self.record(name, meta["version"], path, "package-lock")
                    walk(meta.get("dependencies"))
        walk(data.get("dependencies"))

    def yarn_lock(self, path):
        self.stats["yarn.lock"] += 1
        try:
            txt = open(path, errors="replace").read()
        except PermissionError as e:
            self.unreadable.append((path, str(e)))
            return
        except Exception:
            return
        cur = []
        for line in txt.splitlines():
            if line and not line.startswith((" ", "#", "\t")) and line.rstrip().endswith(":"):
                cur = []
                for spec in line.rstrip(":").split(","):
                    spec = spec.strip().strip('"')
                    at = spec.rfind("@")
                    if at > 0:
                        cur.append(spec[:at])
            elif cur:
                m = re.match(r'\s+"?version"?:?\s+"?([^"\s]+)"?', line)
                if m:
                    for name in set(cur):
                        self.record(name, m.group(1), path, "yarn.lock")
                    cur = []

    def pnpm_lock(self, path):
        self.stats["pnpm-lock.yaml"] += 1
        try:
            txt = open(path, errors="replace").read()
        except PermissionError as e:
            self.unreadable.append((path, str(e)))
            return
        except Exception:
            return
        for m in re.finditer(r"^\s{2,4}/?(@?[^\s:/@][^\s:]*?)@([0-9][^\s:(]*)[:(]", txt, re.M):
            self.record(m.group(1).lstrip("/"), m.group(2), path, "pnpm-lock")

    # ---------- go modules ----------
    def go_mod(self, path):
        """go.mod / go.sum. This campaign reached Go module proxies, which mirror
        the compromised GitHub repos, so a Go project can pull the same payload."""
        if not self.go_ioc:
            return
        try:
            txt = open(path, errors="replace").read()
        except PermissionError as e:
            self.unreadable.append((path, str(e)))
            return
        except Exception:
            return
        self.stats[os.path.basename(path)] += 1
        for m in re.finditer(r"^\s*(?:require\s+)?([\w.\-]+(?:\.[\w.\-]+)*/[^\s]+)\s+(v[^\s/]+)",
                             txt, re.M):
            mod, ver = m.group(1), m.group(2).rstrip("/go.mod")
            mal = self.go_ioc.get(mod)
            if mal is None:
                continue
            if ver in mal:
                self.exact.append((mod, ver, path, "go-module"))
            else:
                self.name_only.append((mod, ver, path, "go-module"))

    # ---------- installed packages ----------
    def installed(self, path):
        try:
            d = json.load(open(path, errors="replace"))
        except PermissionError as e:
            self.unreadable.append((path, str(e)))
            return
        except Exception:
            return
        n, v = d.get("name"), d.get("version")
        if n and v:
            self.stats["installed"] += 1
            self.record(n, v, path, "installed")

    # ---------- npm cache ----------
    def npm_cache(self, cache_dir):
        idx = os.path.join(cache_dir, "index-v5")
        if not os.path.isdir(idx):
            print(f"  (no npm cache index at {idx})", file=sys.stderr)
            return
        seen = set()
        for dp, _, fns in os.walk(idx):
            for fn in fns:
                try:
                    txt = open(os.path.join(dp, fn), errors="replace").read()
                except Exception:
                    continue
                for m in re.finditer(r"registry\.npmjs\.org/(.+?)/-/[^\"/]*?-([0-9][^\"/]*?)\.tgz", txt):
                    seen.add((m.group(1), m.group(2)))
        for name, ver in seen:
            self.stats["npm-cache"] += 1
            self.record(name, ver, f"{cache_dir} (fetched tarball)", "npm-cache")

    # ---------- driver ----------
    def walk_root(self, root, prune=None):
        prune = prune or make_pruner()
        if os.path.isfile(root):
            fn = os.path.basename(root)
            if fn == "package-lock.json": self.package_lock(root)
            elif fn == "yarn.lock": self.yarn_lock(root)
            elif fn == "pnpm-lock.yaml": self.pnpm_lock(root)
            elif fn in ("go.mod", "go.sum"): self.go_mod(root)
            elif fn == "package.json": self.installed(root)
            return
        def on_walk_error(e):
            self.unreadable.append((getattr(e, "filename", str(e)), str(e)))
        for dp, dns, fns in os.walk(root, onerror=on_walk_error):
            prune(dp, dns)
            base = os.path.basename(dp)
            in_nm = (os.sep + "node_modules" + os.sep) in (dp + os.sep)
            for fn in fns:
                p = os.path.join(dp, fn)
                if fn == "package-lock.json":
                    self.package_lock(p)
                elif fn == "yarn.lock":
                    self.yarn_lock(p)
                elif fn == "pnpm-lock.yaml":
                    self.pnpm_lock(p)
                elif fn in ("go.mod", "go.sum"):
                    self.go_mod(p)
                elif fn == "package.json" and in_nm and base != "node_modules":
                    self.installed(p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("roots", nargs="*", help="default: $HOME")
    ap.add_argument("--csv", required=True, help="compromised-package CSV (npm)")
    ap.add_argument("--other-ecosystems",
                    help="CSV of non-npm compromised modules (Ecosystem,Module,Versions)")
    ap.add_argument("--skip", action="append", default=[],
                    help="extra directory path-suffix to prune (repeatable)")
    ap.add_argument("--no-cache", action="store_true", help="skip ~/.npm/_cacache scan")
    ap.add_argument("--cache-dir", default=os.path.expanduser("~/.npm/_cacache"))
    ap.add_argument("--json", help="write machine-readable report here")
    a = ap.parse_args()

    roots = a.roots or default_roots()
    prune = make_pruner(a.skip or ())
    ioc = load_iocs(a.csv)
    go_ioc = {}
    if a.other_ecosystems and os.path.isfile(a.other_ecosystems):
        for row in csv.DictReader(open(a.other_ecosystems)):
            if (row.get("Ecosystem") or "").strip() == "golang":
                go_ioc[(row.get("Module") or "").strip()] = {
                    v.strip() for v in (row.get("Malicious Versions") or "").split(",") if v.strip()}
    sc = Scanner(ioc, go_ioc)
    for r in roots:
        if not os.path.exists(r):
            sys.exit(f"ERROR: root does not exist: {r}")
        sc.walk_root(r, prune)
    if not a.no_cache:
        sc.npm_cache(a.cache_dir)

    print("=" * 72)
    print(f"IOC packages loaded : {len(ioc)} npm" +
          (f", {len(go_ioc)} golang" if go_ioc else ""))
    print(f"Roots scanned       : {', '.join(roots)}")
    print(f"Coverage            : {dict(sc.stats)}")
    print("=" * 72)

    uniq_exact = sorted(set(sc.exact))
    print(f"\n### COMPROMISED (name + malicious version): {len(uniq_exact)}")
    for n, v, s, k in uniq_exact:
        print(f"  [!!] {n}@{v}\n       via {k}: {s}")
    if not uniq_exact:
        print("  none")

    agg = defaultdict(set)
    for n, v, s, k in sc.name_only:
        agg[(n, v)].add(s)
    print(f"\n### IOC-family packages at SAFE versions: {len(agg)}")
    for (n, v), srcs in sorted(agg.items()):
        print(f"  [ok] {n}@{v}  (malicious: {sorted(ioc[n])})  refs={len(srcs)}")

    if a.json:
        json.dump({
            "compromised": [{"name": n, "version": v, "source": s, "kind": k} for n, v, s, k in uniq_exact],
            "safe_versions": [{"name": n, "version": v, "refs": sorted(s)} for (n, v), s in sorted(agg.items())],
            "coverage": dict(sc.stats),
            "unreadable": [{"path": p_, "error": e_} for p_, e_ in sc.unreadable],
            "ioc_count": len(ioc),
        }, open(a.json, "w"), indent=2)
        print(f"\nJSON report -> {a.json}")

    if sc.unreadable:
        print(f"\n### UNREADABLE - NOT SCANNED, NOT CLEAN: {len(sc.unreadable)}")
        print("  macOS TCC blocks Desktop/Documents/Downloads and others unless the")
        print("  running app has Full Disk Access. Grant it, or scan these as a user")
        print("  who can read them, then re-run. Sample:")
        for pth, err in sc.unreadable[:8]:
            print(f"    {pth}")
        if len(sc.unreadable) > 8:
            print(f"    ... +{len(sc.unreadable)-8} more")

    verdict = "COMPROMISED" if uniq_exact else "CLEAN (no malicious versions present)"
    if not uniq_exact and sc.unreadable:
        verdict = f"CLEAN over what was readable - {len(sc.unreadable)} path(s) COULD NOT BE READ"
    print("\nVERDICT:", verdict)
    return 1 if uniq_exact else 0


if __name__ == "__main__":
    sys.exit(main())
