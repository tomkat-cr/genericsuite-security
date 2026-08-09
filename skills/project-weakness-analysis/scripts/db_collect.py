#!/usr/bin/env python3
"""
db_collect.py - OPTIONAL input mode: read a project registry from Supabase or
Postgres, extract one GitHub URL per row, and carry the rest as metadata.

WHAT THIS READS
    A registry table that NAMES projects and points at their repositories. It
    has nothing to do with whatever database a scanned project uses internally
    - that is a security question for the stage 3 agent, not an input concern.

READ-ONLY, ALWAYS
    PostgREST access is GET-only. The psql path wraps every query in
    BEGIN; SET TRANSACTION READ ONLY; so the guarantee is enforced by the
    database rather than by the query text.

CREDENTIALS COME FROM THE ENVIRONMENT, NEVER A FLAG
    The report states the command that produced it. A connection string passed
    as an argument would be written into a file people share.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _policy  # noqa: E402

GH_RE = re.compile(r"https?://(?:www\.)?github\.com/[^\s)\"'<>]+", re.I)
TRAILING_JUNK = ".,);:"
HTTP_TIMEOUT = 60


class DbError(Exception):
    """Raised when the DB cannot be read. Callers exit 2."""


def normalize_repo_url(url):
    u = url.strip().rstrip(TRAILING_JUNK)
    u = u.split("#")[0].split("?")[0]
    u = u.rstrip("/")
    if u.lower().endswith(".git"):
        u = u[:-4]
    return u.lower()


def extract_repo_url(row, cfg):
    for col in cfg["repo_url_columns"]:
        value = row.get(col)
        if not value or not isinstance(value, str):
            continue
        m = GH_RE.search(value)
        if m:
            return m.group(0).rstrip(TRAILING_JUNK), col
    return None, None


def build_repo_list(rows, cfg, limit=None):
    """Return (selected, skipped, warnings). Every input row lands in one list."""
    slug_col, name_col = cfg["slug_column"], cfg["name_column"]
    if rows and slug_col not in rows[0]:
        raise DbError("db_config slug_column %r is not in the result columns: %s"
                      % (slug_col, sorted(rows[0].keys())))

    selected, skipped, warnings = [], [], []
    seen = {}
    for row in rows:
        slug = row.get(slug_col)
        if not slug:
            skipped.append({"slug": "<no-slug>", "reason": "no-slug"})
            continue
        url, source = extract_repo_url(row, cfg)
        if not url:
            skipped.append({"slug": slug, "reason": "no-repo-url"})
            continue
        norm = normalize_repo_url(url)
        if norm in seen:
            skipped.append({"slug": slug, "reason": "duplicate-of:%s" % seen[norm]})
            continue
        seen[norm] = slug
        selected.append({
            "slug": slug,
            "name": row.get(name_col) or slug,
            "repo_url": url,
            "repo_source_field": source,
            "db_metadata": {c: row.get(c) for c in cfg["metadata_columns"] if c in row},
        })

    page_size = cfg.get("page_size")
    if page_size and len(rows) % page_size == 0 and len(rows) > 0:
        warnings.append(
            "row count %d is an exact multiple of page_size %d - the result may be "
            "TRUNCATED. Rows past the cut are absent, not failed, and no scan of "
            "them can report clean." % (len(rows), page_size))
    if limit is not None and len(selected) > limit:
        warnings.append("--db-limit=%d hit; %d project(s) were not analyzed"
                        % (limit, len(selected) - limit))
        selected = selected[:limit]
    return selected, skipped, warnings


def attach_metadata(evidence_dir, selected):
    """Merge each project's name and repo_source_field into its evidence
    bundle's db_metadata, so merge_insights.py can read both from one place.
    A project with no matching evidence file (e.g. it failed to clone) is
    skipped, not an error - the corpus, not the registry, decides who
    actually got scanned.
    """
    by_slug = {row["slug"]: row for row in selected}
    for fname in sorted(os.listdir(evidence_dir)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(evidence_dir, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                bundle = json.load(f)
        except (OSError, ValueError):
            continue
        slug = bundle.get("project_slug") or os.path.splitext(fname)[0]
        row = by_slug.get(slug)
        if not row:
            continue
        merged = dict(row.get("db_metadata") or {})
        merged["name"] = row.get("name")
        merged["repo_source_field"] = row.get("repo_source_field")
        bundle["db_metadata"] = merged
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)


def _fetch_postgrest(cfg, env):
    base = env["SUPABASE_URL"].rstrip("/")
    key = env.get("SUPABASE_SERVICE_ROLE_KEY") or env["SUPABASE_ANON_KEY"]
    columns = sorted(set([cfg["slug_column"], cfg["name_column"]]
                         + list(cfg["repo_url_columns"])
                         + list(cfg["metadata_columns"])))
    page = int(cfg.get("page_size") or 1000)
    rows, offset, warnings = [], 0, []
    while True:
        q = {"select": ",".join(columns), "limit": str(page), "offset": str(offset)}
        if cfg.get("filter"):
            q.update(urllib.parse.parse_qsl(cfg["filter"]))
        url = "%s/rest/v1/%s?%s" % (base, cfg["table"], urllib.parse.urlencode(q))
        req = urllib.request.Request(url, method="GET")
        req.add_header("apikey", key)
        req.add_header("Authorization", "Bearer %s" % key)
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                batch = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise DbError("PostgREST returned HTTP %s for table %r"
                          % (e.code, cfg["table"]))
        except (urllib.error.URLError, ValueError) as e:
            raise DbError("PostgREST read failed: %s" % e)
        rows.extend(batch)
        if len(batch) < page:
            break
        offset += page
    return rows, warnings


def _fetch_psql(cfg, env):
    columns = sorted(set([cfg["slug_column"], cfg["name_column"]]
                         + list(cfg["repo_url_columns"])
                         + list(cfg["metadata_columns"])))
    ident = lambda c: '"%s"' % c.replace('"', '""')
    where = " WHERE %s" % cfg["filter"] if cfg.get("filter") else ""
    sql = ("BEGIN; SET TRANSACTION READ ONLY; "
           "SELECT coalesce(json_agg(t), '[]'::json) FROM "
           "(SELECT %s FROM %s%s) t; COMMIT;"
           % (", ".join(ident(c) for c in columns), ident(cfg["table"]), where))
    try:
        proc = subprocess.run(["psql", env["DATABASE_URL"], "-At", "-c", sql],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=300)
    except (OSError, subprocess.SubprocessError) as e:
        raise DbError("psql failed: %s" % e)
    if proc.returncode != 0:
        raise DbError("psql exited %d: %s" % (
            proc.returncode, proc.stderr.decode("utf-8", "replace").strip()[:300]))
    payload = [l for l in proc.stdout.decode("utf-8", "replace").splitlines() if l.strip()]
    try:
        return json.loads(payload[-1]), []
    except (IndexError, ValueError) as e:
        raise DbError("could not parse psql output as JSON: %s" % e)


def fetch_rows(cfg, rows_json=None, env=None):
    """Rows from a saved payload, PostgREST, or psql - in that order."""
    if rows_json:
        try:
            with open(rows_json, "r", encoding="utf-8") as f:
                return json.load(f), ["rows read from %s, not from a live database"
                                      % rows_json]
        except (OSError, ValueError) as e:
            raise DbError("could not read --db-rows-json: %s" % e)

    env = os.environ if env is None else env
    if env.get("SUPABASE_URL") and (env.get("SUPABASE_SERVICE_ROLE_KEY")
                                    or env.get("SUPABASE_ANON_KEY")):
        return _fetch_postgrest(cfg, env)
    if env.get("DATABASE_URL"):
        try:
            subprocess.run(["psql", "--version"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30)
        except (OSError, subprocess.SubprocessError):
            raise DbError("DATABASE_URL is set but psql is not on PATH")
        return _fetch_psql(cfg, env)
    raise DbError(
        "no database transport configured. Set SUPABASE_URL plus "
        "SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_ANON_KEY), or set DATABASE_URL "
        "with psql on PATH. Credentials are read from the environment only, "
        "never from a command-line flag. --db is optional: use --root, "
        "--projects, --corpus, or --org instead.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read a project registry, read-only.")
    ap.add_argument("--out", required=True)
    ap.add_argument("--db-config", default=None)
    ap.add_argument("--db-rows-json", default=None)
    ap.add_argument("--db-limit", type=int, default=None)
    ap.add_argument("--profile", default="generic")
    args = ap.parse_args(argv)

    try:
        policy = _policy.load_policy(args.profile)
        cfg = dict(policy["db_source"])
        if args.db_config:
            with open(args.db_config, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        rows, warnings = fetch_rows(cfg, rows_json=args.db_rows_json)
        selected, skipped, warns = build_repo_list(rows, cfg, limit=args.db_limit)
    except (_policy.PolicyError, DbError, OSError, ValueError) as e:
        sys.stderr.write("%s\n" % e)
        return 2

    payload = {"selected": selected, "skipped": skipped,
               "warnings": list(warnings) + list(warns),
               "row_count": len(rows)}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    sys.stderr.write("db: %d row(s) -> %d project(s), %d skipped\n"
                     % (len(rows), len(selected), len(skipped)))
    for w in payload["warnings"]:
        sys.stderr.write("WARNING: %s\n" % w)
    return 0 if selected else 2


if __name__ == "__main__":
    sys.exit(main())
