#!/usr/bin/env python3
"""
build_corpus.py - Turn an org, a user, or a local checkout into a scannable corpus.

This produces NO findings. It produces safe, attributable checkouts plus a
corpus.json manifest describing exactly what was and was not obtained. That
separation is deliberate: it makes single-repo lint mode and org-wide audit the
same code path for every scanner built on top of it.

CLONED REPOSITORIES ARE HOSTILE INPUT
    Nothing from a clone is ever executed here. Every clone disables the
    mechanisms by which a repository can run code on the scanning machine - see
    clone_argv() for the flags and the specific failure each one prevents.

Exit codes (see the phase 1 plan, D1 - this skill has no findings, so `1` means
a corpus with a known hole rather than a clean/dirty verdict):
    0  manifest written; every selected repo materialized
    1  manifest written; at least one selected repo FAILED - any scan over this
       corpus has a blind spot and must say so
    2  no usable manifest (bad arguments, gh missing, output not writable)
"""
import argparse
import concurrent.futures
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

VERSION = "1.0"
SCHEMA_VERSION = 1

GH_FIELDS = ("name,defaultBranchRef,isFork,isArchived,isEmpty,"
             "stargazerCount,pushedAt,visibility,url")


def log(msg):
    """Progress goes to stderr so `build_corpus.py ... | jq` works on stdout."""
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------
# Enumeration
# --------------------------------------------------------------------------

def gh_repo_list(target, limit):
    """Enumerate via the gh CLI. Raises RuntimeError with an actionable message."""
    if not shutil.which("gh"):
        raise RuntimeError(
            "gh CLI not found. Install it (https://cli.github.com) and run "
            "`gh auth login`, or pass --repos-json with a saved "
            f"`gh repo list <target> --json {GH_FIELDS}` payload.")
    argv = ["gh", "repo", "list", target, "--limit", str(limit), "--json", GH_FIELDS]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise RuntimeError("gh repo list timed out after 120s")
    if proc.returncode != 0:
        err = (proc.stderr or "").strip()
        hint = ""
        if "auth" in err.lower() or "401" in err:
            hint = " - run `gh auth login`"
        raise RuntimeError(f"gh repo list failed{hint}: {err or 'no stderr'}")
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"gh returned unparseable JSON: {e}")
    if not isinstance(data, list):
        raise RuntimeError("gh returned a non-list payload")
    return data


def load_repos_json(path):
    """Read the identical payload from a file. This is what makes enumeration,
    filtering and manifest construction testable without a live GitHub account."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise RuntimeError(f"could not read --repos-json {path}: {e}")
    if not isinstance(data, list):
        raise RuntimeError(f"--repos-json {path} must contain a JSON list")
    return data


def check_enumeration_truncated(enumerated, args, warnings):
    """Warn when the repository list looks cut short.

    A truncated enumeration is the worst failure this tool can have: the repos
    past the cut are not "failed" (which the manifest records and exit 1
    announces) - they are simply absent, indistinguishable from "not selected".
    Every scan over the corpus then reports clean on repositories nobody ever
    looked at. Cheap to warn about, expensive to discover later.
    """
    if enumerated >= args.limit:
        msg = (f"enumeration returned {enumerated} repo(s), which is the --limit "
               f"({args.limit}). The list is probably truncated and this corpus "
               f"is probably incomplete. Re-run with a higher --limit.")
        warnings.append(msg)
        log(f"  WARNING: {msg}")
    elif enumerated > 0 and enumerated % 100 == 0:
        # gh pages at 100. Landing on an exact page boundary is either a
        # coincidence or a cap, and the two are indistinguishable from here.
        target = args.org or args.user or "<target>"
        msg = (f"enumeration returned exactly {enumerated} repo(s), a multiple of "
               f"the 100-per-page size gh uses. If {target} has more than that, the "
               f"list was capped and this corpus is incomplete. Verify with: "
               f"gh repo list {target} --limit {args.limit} --json name | jq length")
        warnings.append(msg)
        log(f"  NOTE: {msg}")


# --------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------

# Enumeration output is remote-controlled data: a repository name is chosen by
# whoever created the repository. It becomes a path component, so it is
# validated rather than trusted.
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


def name_is_safe(name):
    return bool(name) and bool(SAFE_NAME.match(name)) and not name.startswith(".") \
        and ".." not in name


def select(repos, args, warnings):
    """Apply scope filters. Returns the selected list, in enumeration order.

    Defaults are deliberately broad (plan D6): archived repos, forks and
    non-default branches are all included. Narrowing scope is how a scan misses
    what it was run to find - an archived repo still has a workflow that runs
    with a token.
    """
    inc = re.compile(args.include) if args.include else None
    exc = re.compile(args.exclude) if args.exclude else None
    out = []
    for r in repos:
        name = r.get("name")
        if not name:
            warnings.append("enumeration entry without a name was dropped")
            continue
        if args.no_archived and r.get("isArchived"):
            continue
        if args.no_forks and r.get("isFork"):
            continue
        if inc and not inc.search(name):
            continue
        if exc and exc.search(name):
            continue
        out.append(r)
    return out


# --------------------------------------------------------------------------
# Cloning - the security-sensitive part
# --------------------------------------------------------------------------

def clone_argv(url, dest, default_branch_only=False):
    """Build the hardened clone command.

    Kept as one function so the self-test can assert on the argv directly: an
    end-to-end test only fails for the flag whose failure it happens to
    simulate, whereas deleting any flag here must fail a test.

    Flag by flag, and the failure each one prevents:

      core.hooksPath=/dev/null   A hook must never execute during clone. This
                                 is the flag the whole "hostile input" premise
                                 rests on.
      filter.lfs.*, GIT_LFS_SKIP_SMUDGE
                                 An LFS smudge filter is a command the repo
                                 gets to name. Disable the filter, do not fetch
                                 LFS content.
      credential.helper= then
      !gh auth git-credential    Not a convenience. Parallel HTTPS clones on
                                 macOS trigger one Keychain prompt PER git
                                 process. Clearing the helper first, then
                                 setting it inline, uses the gh token directly,
                                 prompts zero times, and never touches global
                                 git config.
      --depth 1 --no-single-branch
                                 Every branch at depth 1: full branch coverage
                                 without full history.
      --no-tags                  Tags are mutable and not needed to scan a tree.
    """
    return [
        "git",
        "-c", "core.hooksPath=/dev/null",
        "-c", "filter.lfs.smudge=cat",
        "-c", "filter.lfs.process=",
        "-c", "filter.lfs.required=false",
        "-c", "credential.helper=",
        "-c", "credential.helper=!gh auth git-credential",
        "clone", "--quiet", "--depth", "1",
        "--single-branch" if default_branch_only else "--no-single-branch",
        "--no-tags", url, dest,
    ]


def git_error_summary(proc):
    """The most useful line of a git failure, not the last one.

    git's clone failures end with "Please make sure you have the correct access
    rights / and the repository exists." - so taking the last line records
    "and the repository exists." and throws away the `fatal:` line that says
    what actually went wrong. A manifest full of that is a manifest that cannot
    be triaged.
    """
    text = (proc.stderr or "").strip() or (proc.stdout or "").strip()
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return "git clone failed with no output"
    for ln in lines:
        if ln.startswith(("fatal:", "error:", "remote: ")):
            return ln[:400]
    return lines[-1][:400]


def clone_env():
    env = os.environ.copy()
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"   # never block a parallel run on a prompt
    return env


def branches_of(path):
    """[{name, head}] for every remote branch in a clone.

    Filtering is on the FULL refname, not the short one. git shortens
    `refs/remotes/origin/HEAD` to `origin` - not to `origin/HEAD` - so matching
    on the short name lets the symbolic HEAD through as a phantom branch called
    "origin". That reached a real manifest before the end-to-end run caught it.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", path, "for-each-ref",
             "--format=%(refname)\t%(refname:short)\t%(objectname)",
             "refs/remotes/origin"],
            capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError):
        return []
    if proc.returncode != 0:
        return []
    out = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        full, short, sha = parts
        if full == "refs/remotes/origin/HEAD":
            continue
        out.append({"name": short[len("origin/"):] if short.startswith("origin/") else short,
                    "head": sha})
    return out


def clone_one(repo, root, args):
    """Clone a single repo. Never raises - a failure becomes a manifest entry.

    Clones into a staging directory and renames on success only. An interrupted
    clone must never be mistaken for a complete one: that is a silently
    incomplete corpus, which is a falsely clean verdict with extra steps.
    """
    name = repo.get("name")
    url = repo.get("url") or ""
    entry = {
        "name": name,
        "name_with_owner": repo.get("nameWithOwner") or f"{args._owner}/{name}",
        "url": url,
        "path": None,
        "status": "failed",
        "error": None,
        "default_branch": (repo.get("defaultBranchRef") or {}).get("name"),
        "head": None,
        "branches": [],
        "clone_duration_s": None,
        "github": {
            "isFork": repo.get("isFork"),
            "isArchived": repo.get("isArchived"),
            "isEmpty": repo.get("isEmpty"),
            "stargazerCount": repo.get("stargazerCount"),
            "pushedAt": repo.get("pushedAt"),
            "visibility": repo.get("visibility"),
        },
    }

    if not name_is_safe(name):
        entry["error"] = f"unsafe repository name refused: {name!r}"
        return entry

    if repo.get("isEmpty"):
        # Recorded, never dropped: a repo missing from the manifest must mean
        # "not selected", never "silently failed".
        entry["status"] = "skipped"
        entry["error"] = "repository is empty"
        return entry

    if not url:
        entry["error"] = "enumeration entry has no url"
        return entry

    final = os.path.join(root, "repos", name)
    if os.path.exists(final):
        entry["error"] = f"destination already exists: repos/{name}"
        return entry

    staging = os.path.join(root, ".staging")
    os.makedirs(staging, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=f"{name}.", dir=staging)

    started = time.time()
    try:
        proc = subprocess.run(
            clone_argv(url, tmp, args.default_branch_only),
            capture_output=True, text=True, env=clone_env(), timeout=args.timeout)
        if proc.returncode != 0:
            entry["error"] = git_error_summary(proc)
            return entry
    except subprocess.TimeoutExpired:
        entry["error"] = f"timeout after {args.timeout}s"
        return entry
    except OSError as e:
        entry["error"] = f"could not run git: {e}"
        return entry
    finally:
        entry["clone_duration_s"] = round(time.time() - started, 2)
        if entry["error"] is not None:
            shutil.rmtree(tmp, ignore_errors=True)

    try:
        os.makedirs(os.path.join(root, "repos"), exist_ok=True)
        os.replace(tmp, final)          # promote only after a complete clone
    except OSError as e:
        entry["error"] = f"could not promote clone into corpus: {e}"
        shutil.rmtree(tmp, ignore_errors=True)
        return entry

    entry["status"] = "cloned"
    entry["path"] = os.path.join("repos", name)
    entry["branches"] = branches_of(final)
    default = entry["default_branch"]
    for b in entry["branches"]:
        if b["name"] == default:
            entry["head"] = b["head"]
    if entry["head"] is None and entry["branches"]:
        entry["head"] = entry["branches"][0]["head"]
    return entry


# --------------------------------------------------------------------------
# Local mode
# --------------------------------------------------------------------------

def git_out(path, *argv):
    try:
        proc = subprocess.run(["git", "-C", path, *argv],
                              capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def local_entry(path, root, warnings):
    """One manifest entry for an existing working tree. No network, no gh."""
    path = os.path.abspath(path)
    name = os.path.basename(path.rstrip(os.sep)) or path
    entry = {
        "name": name,
        "name_with_owner": None,
        "url": None,
        "path": os.path.relpath(path, root),
        "status": "local",
        "error": None,
        "default_branch": None,
        "head": None,
        "branches": [],
        "clone_duration_s": None,
        "github": None,
    }
    if not os.path.isdir(path):
        entry["status"] = "failed"
        entry["error"] = f"not a directory: {path}"
        return entry

    head = git_out(path, "rev-parse", "HEAD")
    branch = git_out(path, "rev-parse", "--abbrev-ref", "HEAD")
    if head is None:
        # A plain directory of config files is a legitimate scan target; it just
        # cannot be attributed to a commit, and the report must be able to say so.
        warnings.append(f"{entry['path']}: not a git working tree - "
                        "findings cannot be attributed to a commit")
        return entry

    entry["head"] = head
    if branch and branch != "HEAD":
        entry["default_branch"] = branch
        entry["branches"] = [{"name": branch, "head": head}]
    else:
        entry["branches"] = [{"name": "(detached)", "head": head}]
    return entry


# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------

def write_manifest(manifest, path):
    """Atomic write. A half-written corpus.json read by a scanner is a corrupt
    run reported as a partial one."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)),
                               prefix=".corpus.", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=False)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="Build a scannable repository corpus + corpus.json manifest.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit: 0 complete corpus, 1 corpus with failed repos, 2 error.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--org", help="GitHub organization to enumerate")
    src.add_argument("--user", help="GitHub user to enumerate")
    src.add_argument("--local", nargs="+", metavar="PATH",
                     help="use existing working tree(s); no cloning, no network")
    p.add_argument("--repos-json", metavar="PATH",
                   help="read enumeration from a saved gh payload instead of "
                        "calling gh (used by the self-test)")
    p.add_argument("--out", metavar="DIR", help="corpus directory "
                   "(default $TMPDIR/repo-corpus-<timestamp>)")
    p.add_argument("--json", metavar="PATH", help="manifest path (default <out>/corpus.json)")
    p.add_argument("--limit", type=int, default=1000, help="max repos to enumerate (default 1000)")
    p.add_argument("--jobs", type=int, default=8, help="parallel clones (default 8)")
    p.add_argument("--timeout", type=int, default=300, help="per-clone timeout seconds (default 300)")
    p.add_argument("--no-archived", action="store_true", help="exclude archived repos")
    p.add_argument("--no-forks", action="store_true", help="exclude forks")
    p.add_argument("--default-branch-only", action="store_true",
                   help="clone only the default branch (cheaper; narrower)")
    p.add_argument("--include", metavar="REGEX", help="only repos whose name matches")
    p.add_argument("--exclude", metavar="REGEX", help="skip repos whose name matches")
    p.add_argument("--list-only", action="store_true",
                   help="print the selection and exit without cloning")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    warnings = []

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    default_out = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"repo-corpus-{stamp}")

    if args.local:
        # `root` anchors the relative paths in the manifest and is NOT where the
        # manifest is written. Defaulting the manifest into the parent of the
        # user's checkout would litter it - or fail outright in CI, where that
        # directory is frequently not writable. Lint mode is the main use of
        # --local, so the manifest goes somewhere disposable unless asked.
        root = os.path.abspath(
            os.path.commonpath([os.path.abspath(p) for p in args.local])
            if len(args.local) > 1
            else os.path.dirname(os.path.abspath(args.local[0])))
        manifest_default_dir = os.path.abspath(args.out) if args.out else default_out
    else:
        root = os.path.abspath(args.out) if args.out else default_out
        manifest_default_dir = root

    manifest_path = os.path.abspath(args.json) if args.json \
        else os.path.join(manifest_default_dir, "corpus.json")

    # ---- local mode -------------------------------------------------------
    if args.local:
        entries = [local_entry(p, root, warnings) for p in args.local]
        failed = sum(1 for e in entries if e["status"] == "failed")
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": now_iso(),
            "generator": f"repo-corpus/build_corpus.py {VERSION}",
            "root": root,
            "source": {"mode": "local", "target": None,
                       "filters": {"archived": None, "forks": None,
                                   "default_branch_only": None, "limit": None,
                                   "include": None, "exclude": None}},
            "totals": {"enumerated": len(entries), "selected": len(entries),
                       "cloned": sum(1 for e in entries if e["status"] == "local"),
                       "failed": failed},
            "repos": entries,
            "warnings": warnings,
        }
        try:
            write_manifest(manifest, manifest_path)
        except OSError as e:
            log(f"ERROR: could not write manifest: {e}")
            return 2
        print(manifest_path)
        log(f"corpus: {len(entries)} local tree(s), {failed} failed")
        return 1 if failed else 0

    # ---- enumeration ------------------------------------------------------
    target = args.org or args.user
    args._owner = target
    try:
        repos = load_repos_json(args.repos_json) if args.repos_json \
            else gh_repo_list(target, args.limit)
    except RuntimeError as e:
        log(f"ERROR: {e}")
        return 2

    # --limit means the same thing whatever the source, so the truncation guard
    # below applies uniformly - and stays testable without a live gh.
    if args.repos_json and len(repos) > args.limit:
        repos = repos[:args.limit]

    enumerated = len(repos)
    check_enumeration_truncated(enumerated, args, warnings)
    selected = select(repos, args, warnings)
    log(f"enumerated {enumerated}, selected {len(selected)}")

    if args.list_only:
        for r in selected:
            flags = ",".join(k for k, v in (("archived", r.get("isArchived")),
                                            ("fork", r.get("isFork")),
                                            ("empty", r.get("isEmpty"))) if v)
            print(f"{r.get('name')}\t{r.get('visibility') or '-'}\t{flags or '-'}")
        return 0

    # ---- clone ------------------------------------------------------------
    try:
        os.makedirs(root, exist_ok=True)
    except OSError as e:
        log(f"ERROR: could not create corpus directory {root}: {e}")
        return 2

    staging = os.path.join(root, ".staging")
    shutil.rmtree(staging, ignore_errors=True)   # never inherit a previous run's debris

    entries = []
    if selected:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            futures = {pool.submit(clone_one, r, root, args): r for r in selected}
            done = 0
            for fut in concurrent.futures.as_completed(futures):
                entry = fut.result()      # clone_one never raises
                entries.append(entry)
                done += 1
                mark = {"cloned": "ok", "skipped": "--", "failed": "FAIL"}.get(entry["status"], "?")
                log(f"  [{done}/{len(selected)}] {mark} {entry['name']}"
                    + (f" - {entry['error']}" if entry["error"] else ""))

    shutil.rmtree(staging, ignore_errors=True)
    order = {r.get("name"): i for i, r in enumerate(selected)}
    entries.sort(key=lambda e: order.get(e["name"], 0))

    cloned = sum(1 for e in entries if e["status"] == "cloned")
    failed = sum(1 for e in entries if e["status"] == "failed")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now_iso(),
        "generator": f"repo-corpus/build_corpus.py {VERSION}",
        "root": root,
        "source": {
            "mode": "org" if args.org else "user",
            "target": target,
            "filters": {
                "archived": not args.no_archived,
                "forks": not args.no_forks,
                "default_branch_only": args.default_branch_only,
                "limit": args.limit,
                "include": args.include,
                "exclude": args.exclude,
            },
        },
        "totals": {"enumerated": enumerated, "selected": len(selected),
                   "cloned": cloned, "failed": failed},
        "repos": entries,
        "warnings": warnings,
    }
    try:
        write_manifest(manifest, manifest_path)
    except OSError as e:
        log(f"ERROR: could not write manifest: {e}")
        return 2

    print(manifest_path)
    log(f"corpus: {cloned} cloned, {failed} failed, root {root}")
    if failed:
        log("PARTIAL CORPUS - any scan over it has a blind spot and must say so.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
