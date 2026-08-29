#!/usr/bin/env python3
"""
fetch_package_lists.py - Fetch every vendor's compromised-package feed and merge them.

Vendors publish the same campaign in different shapes and at different refresh
rates. Socket.dev updates minute-by-minute and splits scoped names across
columns; Wiz publishes a periodic snapshot with versions comma-joined. Relying
on one source means inheriting its lag and its outages, so this fetches all of
them, normalizes to a common form, and emits the UNION.

Column layout is auto-detected from the header, so a vendor reordering columns
does not silently break the parse.

Non-npm entries (this campaign reached Go module proxies) are written to a
separate file rather than dropped - dropping known-compromised entries is how a
scanner reports a falsely clean verdict.

Usage:
  fetch_package_lists.py --profile iocs/campaign.json --out packages.csv
  fetch_package_lists.py --url NAME=URL --url NAME2=URL2 --out packages.csv

Exit codes: 0 = at least one source OK, 2 = every source failed.
"""
import argparse, csv, io, json, os, sys, time, urllib.request
from collections import defaultdict

TIMEOUT = 60
UA = "supply-chain-ioc-scan/1.1 (+security triage)"


def fetch(url):
    """Fetch a feed, defeating CDN caching.

    Socket's CSV sits behind Cloudflare. A plain GET returns
    cf-cache-status: HIT with an age of over an hour - observed serving a
    100-minute-old list (2269 rows) while the live incident page showed 2274.
    During an actively spreading worm that stale window is exactly the set of
    newly-compromised packages you are scanning for, and the scan reports CLEAN
    against a list that predates them. Both the cache-busting query parameter
    and the no-cache headers are needed; neither alone reliably misses the edge.
    """
    sep = "&" if "?" in url else "?"
    busted = f"{url}{sep}_cb={int(time.time())}"
    req = urllib.request.Request(busted, headers={
        "User-Agent": UA,
        "Cache-Control": "no-cache, no-store, max-age=0",
        "Pragma": "no-cache",
    })
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        age = r.headers.get("Age")
        cf = r.headers.get("cf-cache-status")
        if cf and cf.upper() == "HIT" and age and int(age) > 300:
            print(f"    WARNING: CDN served a cached copy (age {age}s, cf-cache-status {cf}). "
                  f"List may be stale.", file=sys.stderr)
        return r.read().decode("utf-8", errors="replace")


def newest_timestamp(text):
    """Latest Detected/Published value, so freshness can be cross-checked
    against the vendor's incident page rather than assumed."""
    best = ""
    rdr = csv.DictReader(io.StringIO(text))
    for row in rdr:
        for k in ("Detected", "Published"):
            v = (row.get(k) or "").strip()
            if v > best:
                best = v
    return best


def normalize(text, source):
    """Yield (ecosystem, package, version) from any recognized vendor layout."""
    rdr = csv.reader(io.StringIO(text))
    try:
        header = [h.strip().lower() for h in next(rdr)]
    except StopIteration:
        return
    idx = {h: i for i, h in enumerate(header)}

    def col(row, key):
        i = idx.get(key)
        return row[i].strip() if i is not None and i < len(row) else ""

    # Socket.dev: Ecosystem,Namespace,Name,Version,Artifact,Published,Detected
    if "name" in idx and "version" in idx:
        for row in rdr:
            if not row:
                continue
            ns, nm = col(row, "namespace"), col(row, "name")
            ver = col(row, "version")
            eco = col(row, "ecosystem") or "npm"
            if not nm or not ver:
                continue
            yield eco, (f"{ns}/{nm}" if ns else nm), ver
        return

    # Wiz: Package,Malicious Versions ("1.0.1, 1.0.2")
    pkg_i = idx.get("package", 0)
    ver_i = next((idx[k] for k in ("malicious versions", "versions", "version")
                  if k in idx), 1)
    for row in rdr:
        if not row or len(row) <= max(pkg_i, ver_i):
            continue
        name = row[pkg_i].strip()
        if not name:
            continue
        for v in row[ver_i].split(","):
            v = v.strip()
            if v:
                yield "npm", name, v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile")
    ap.add_argument("--url", action="append", default=[],
                    help="NAME=URL (repeatable); adds to profile sources")
    ap.add_argument("--out", required=True)
    ap.add_argument("--fallback", help="cached CSV to use if every source fails")
    a = ap.parse_args()

    sources = []
    if a.profile:
        p = json.load(open(a.profile))
        for s in p.get("package_list_sources", []):
            sources.append((s.get("name", s["url"]), s["url"]))
        if not sources and p.get("package_list_url"):      # legacy single-URL
            sources.append(("profile", p["package_list_url"]))
    for spec in a.url:
        name, _, url = spec.partition("=")
        sources.append((name or url, url or name))

    if not sources:
        sys.exit("ERROR: no sources configured")

    merged = defaultdict(lambda: defaultdict(set))   # eco -> pkg -> versions
    per_source, failures = {}, []

    for name, url in sources:
        try:
            text = fetch(url)
            n = 0
            for eco, pkg, ver in normalize(text, name):
                merged[eco][pkg].add(ver)
                n += 1
            per_source[name] = n
            ts = newest_timestamp(text)
            print(f"  [ok]   {name}: {n} package@version rows" +
                  (f"  (newest entry {ts})" if ts else ""))
            if n == 0:
                print(f"    WARNING: {name} contributed ZERO rows - the feed's format may "
                      f"have changed. A source silently contributing nothing is a "
                      f"falsely clean verdict.", file=sys.stderr)
        except Exception as e:
            failures.append((name, e))
            print(f"  [FAIL] {name}: {e}", file=sys.stderr)

    if not per_source:
        print("ERROR: every source failed.", file=sys.stderr)
        if a.fallback and os.path.isfile(a.fallback):
            print(f"  falling back to cached {a.fallback} - LIST IS STALE", file=sys.stderr)
            with open(a.fallback) as fsrc, open(a.out, "w") as fdst:
                fdst.write(fsrc.read())
            return 0
        return 2

    npm = merged.get("npm", {})
    with open(a.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Package", "Malicious Versions"])
        for pkg in sorted(npm):
            w.writerow([pkg, ", ".join(sorted(npm[pkg]))])

    other = {e: v for e, v in merged.items() if e != "npm"}
    other_path = os.path.splitext(a.out)[0] + ".other-ecosystems.csv"
    if other:
        with open(other_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Ecosystem", "Module", "Malicious Versions"])
            for eco in sorted(other):
                for pkg in sorted(other[eco]):
                    w.writerow([eco, pkg, ", ".join(sorted(other[eco][pkg]))])

    print(f"\n  merged npm    : {len(npm)} packages, "
          f"{sum(len(v) for v in npm.values())} package@versions -> {a.out}")
    for eco in sorted(other):
        cnt = sum(len(v) for v in other[eco].values())
        print(f"  merged {eco:7}: {len(other[eco])} modules, {cnt} versions -> {other_path}")
        print(f"    !! {eco} is OUTSIDE the npm scanners' coverage - "
              f"check {eco} manifests manually (see SKILL.md)")
    if failures:
        print(f"  WARNING: {len(failures)} source(s) failed; "
              f"list may lag: {[n for n, _ in failures]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
