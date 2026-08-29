#!/usr/bin/env python3
"""
selftest.py - Positive control for repo-corpus.

WHY THIS EXISTS
    repo-corpus produces no findings, so it has no "did it detect anything?"
    signal to sanity-check. What it has instead is a set of security properties
    that are invisible when they hold and catastrophic when they silently stop
    holding: hooks disabled during clone, partial clones never promoted, failed
    clones never omitted from the manifest, symlinks never escaping a repo.

    Every one of those looks exactly the same as working code right up until a
    hostile repository is cloned. This file is the only thing standing between
    "the flags are still there" and "someone tidied one away".

Run before trusting a corpus:
    python3 tests/selftest.py

Exit: 0 all assertions passed, 1 something is broken (do not build a corpus).
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
SCRIPTS = os.path.join(SKILL, "scripts")
REPO_ROOT = os.path.dirname(os.path.dirname(SKILL))
BUILD = os.path.join(SCRIPTS, "build_corpus.py")

sys.path.insert(0, SCRIPTS)
import _walk                      # noqa: E402
from build_corpus import clone_argv, clone_env, name_is_safe   # noqa: E402

GREEN, RED, YELLOW, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"
results = []          # (name, passed)
skipped = []          # (name, why)


def check(name, condition, detail=""):
    results.append((name, bool(condition)))
    tag = f"{GREEN}PASS{RESET}" if condition else f"{RED}FAIL{RESET}"
    print(f"  [{tag}] {name}" + (f"\n         {detail}" if detail and not condition else ""))


def skip(name, why):
    """A skipped assertion is NOT a passed one, and must never be counted as one.

    A vacuous pass in a self-test is worse than a missing test: it is a false
    claim that a security property was verified.
    """
    skipped.append((name, why))
    print(f"  [{YELLOW}SKIP{RESET}] {name}\n         {why}")


def run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


class FixtureError(RuntimeError):
    """The test fixture could not be built. Not a scanner failure - a setup one,
    and it must be reported as such rather than as five mystery assertions."""


# Filled in by main(): an isolated HOME so fixture git commands cannot be
# affected by - or affect - the developer's global git configuration.
_HERMETIC_HOME = None


def git_env(extra=None):
    """Environment for every fixture git command.

    HERMETIC ON PURPOSE. The developer's own git config must not decide whether
    this self-test passes. A global `core.hooksPath` would suppress the control
    hook and make the hardening assertion pass for the wrong reason; a global
    `commit.gpgsign` would break fixture commits; `init.templateDir` would plant
    unexpected hooks. None of that is this test's subject.
    """
    e = dict(os.environ)
    e.pop("GIT_TEMPLATE_DIR", None)
    e.update(hermetic_overrides())
    if extra:
        e.update(extra)
    return e


def hermetic_overrides():
    """The isolation keys, separable so they can be layered over clone_env()
    (which copies os.environ and would otherwise restore the real HOME)."""
    o = {
        "GIT_AUTHOR_NAME": "selftest", "GIT_AUTHOR_EMAIL": "selftest@example.com",
        "GIT_COMMITTER_NAME": "selftest", "GIT_COMMITTER_EMAIL": "selftest@example.com",
        "GIT_CONFIG_NOSYSTEM": "1",          # every git version
        "GIT_CONFIG_SYSTEM": os.devnull,     # git >= 2.32
        "GIT_CONFIG_GLOBAL": os.devnull,     # git >= 2.32
        "GIT_TERMINAL_PROMPT": "0",
    }
    if _HERMETIC_HOME:                       # older git reads config via $HOME
        o["HOME"] = _HERMETIC_HOME
        o["XDG_CONFIG_HOME"] = _HERMETIC_HOME
    return o


def git(*argv, cwd=None, env=None, check=False):
    proc = run(["git", *argv], cwd=cwd, env=git_env(env))
    if check and proc.returncode != 0:
        raise FixtureError(
            f"`git {' '.join(argv)}` failed (exit {proc.returncode}) in {cwd}:\n"
            f"  {(proc.stderr or proc.stdout or '').strip()}")
    return proc


def make_source_repo(path, extra_branch=None):
    """A real local repo, cloneable over file://.

    Every step is checked. An unchecked fixture that quietly produces a
    directory which is not a git repository turns one setup problem into five
    unrelated-looking assertion failures - which is exactly what it did.

    `git init -b main` is deliberately NOT used: -b arrived in git 2.28 (2020),
    and macOS ships whatever git came with Xcode. This package already carries
    scars from macOS shipping decade-old tooling (bash 3.2, see
    supply-chain-ioc-scan). symbolic-ref works on every version.
    """
    os.makedirs(path, exist_ok=True)
    git("init", "--quiet", cwd=path, check=True)
    git("symbolic-ref", "HEAD", "refs/heads/main", cwd=path, check=True)
    with open(os.path.join(path, "README.md"), "w") as f:
        f.write("# fixture\n")
    git("add", "-A", cwd=path, check=True)
    git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "initial",
        cwd=path, check=True)
    if extra_branch:
        git("checkout", "--quiet", "-b", extra_branch, cwd=path, check=True)
        with open(os.path.join(path, "second.txt"), "w") as f:
            f.write("second\n")
        git("add", "-A", cwd=path, check=True)
        git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "second",
            cwd=path, check=True)
        git("checkout", "--quiet", "main", cwd=path, check=True)

    # Prove the fixture is what the rest of the file assumes it is, rather than
    # letting a downstream clone failure explain it badly.
    head = git("rev-parse", "HEAD", cwd=path)
    if head.returncode != 0 or len(head.stdout.strip()) != 40:
        raise FixtureError(f"fixture repo at {path} has no HEAD commit after setup")
    return path


def make_hook_template(path, canary):
    """A git template dir whose post-checkout hook writes a canary on execution."""
    hooks = os.path.join(path, "hooks")
    os.makedirs(hooks, exist_ok=True)
    hook = os.path.join(hooks, "post-checkout")
    with open(hook, "w") as f:
        f.write("#!/bin/sh\ntouch " + canary + "\n")
    os.chmod(hook, os.stat(hook).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


# ---------------------------------------------------------------------------
# 1 + 2: clone hardening
# ---------------------------------------------------------------------------

def test_hooks_disabled(base):
    src = make_source_repo(os.path.join(base, "src-hook"))
    tpl = make_hook_template(os.path.join(base, "tpl"), os.path.join(base, "CANARY-CONTROL"))

    # CONTROL FIRST. Without this, assertion 1 passes whenever the fixture is
    # broken - which is the same failure mode the whole file exists to prevent.
    control_dest = os.path.join(base, "clone-control")
    proc = git("clone", "--quiet", f"file://{src}", control_dest,
               env={"GIT_TEMPLATE_DIR": tpl})
    control_fired = os.path.exists(os.path.join(base, "CANARY-CONTROL"))
    check("control: an unhardened clone DOES run the planted post-checkout hook",
          control_fired,
          "the hook never ran, so the hardened assertion below proves nothing. "
          f"clone exit={proc.returncode}: {(proc.stderr or '').strip()[:300]}")

    # Now the hardened path, with the same hook template in scope. Same hermetic
    # environment as the control, so the comparison isolates our flags and
    # nothing else - a developer's global core.hooksPath must not be what makes
    # this pass.
    tpl2 = make_hook_template(os.path.join(base, "tpl2"), os.path.join(base, "CANARY-HARDENED"))
    hardened_dest = os.path.join(base, "clone-hardened")
    env = clone_env()                       # the environment under test
    env.update(hermetic_overrides())        # layered on top: clone_env copies os.environ
    env["GIT_TEMPLATE_DIR"] = tpl2
    proc = run(clone_argv(f"file://{src}", hardened_dest), env=env)
    check("the hardened clone itself succeeded (otherwise the next assertion is vacuous)",
          proc.returncode == 0 and os.path.isdir(hardened_dest),
          f"exit={proc.returncode}: {(proc.stderr or '').strip()[:300]}")
    check("hardened clone does NOT run a post-checkout hook (core.hooksPath)",
          not os.path.exists(os.path.join(base, "CANARY-HARDENED")),
          "A HOOK EXECUTED DURING CLONE. Cloned repos are hostile input.")


def test_clone_argv_flags():
    argv = clone_argv("https://example.com/x.git", "/tmp/dest")
    joined = " ".join(argv)
    required = [
        "core.hooksPath=/dev/null",
        "filter.lfs.smudge=cat",
        "filter.lfs.process=",
        "filter.lfs.required=false",
        "credential.helper=",
        "credential.helper=!gh auth git-credential",
        "--depth",
        "--no-single-branch",
        "--no-tags",
    ]
    missing = [r for r in required if r not in argv and r not in joined]
    check("clone_argv carries every hardening flag", not missing,
          f"missing: {missing}")
    check("GIT_LFS_SKIP_SMUDGE is set in the clone environment",
          clone_env().get("GIT_LFS_SKIP_SMUDGE") == "1")
    check("--default-branch-only swaps in --single-branch",
          "--single-branch" in clone_argv("u", "d", True))


# ---------------------------------------------------------------------------
# 3 + 4 + 9: failure handling and the manifest contract
# ---------------------------------------------------------------------------

def test_failed_clone(base):
    """A clone that fails leaves nothing behind, is recorded, and exits 1."""
    good = make_source_repo(os.path.join(base, "src-good"))
    payload = [
        {"name": "good", "url": f"file://{good}",
         "defaultBranchRef": {"name": "main"}, "isFork": False, "isArchived": False,
         "isEmpty": False, "stargazerCount": 1, "pushedAt": "2026-08-01T00:00:00Z",
         "visibility": "PUBLIC"},
        {"name": "broken", "url": f"file://{base}/does-not-exist",
         "defaultBranchRef": {"name": "main"}, "isFork": False, "isArchived": False,
         "isEmpty": False, "stargazerCount": 0, "pushedAt": "2026-08-01T00:00:00Z",
         "visibility": "PUBLIC"},
        {"name": "../escape", "url": f"file://{good}",
         "defaultBranchRef": {"name": "main"}, "isFork": False, "isArchived": False,
         "isEmpty": False, "stargazerCount": 0, "pushedAt": "2026-08-01T00:00:00Z",
         "visibility": "PUBLIC"},
    ]
    pj = os.path.join(base, "payload.json")
    with open(pj, "w") as f:
        json.dump(payload, f)

    out = os.path.join(base, "corpus-fail")
    proc = run([sys.executable, BUILD, "--org", "fixture", "--repos-json", pj,
                "--out", out, "--jobs", "2"])
    check("a corpus containing a failed clone exits 1 (partial corpus)",
          proc.returncode == 1, f"exit={proc.returncode} stderr={proc.stderr[-300:]}")

    manifest = json.load(open(os.path.join(out, "corpus.json")))
    by_name = {r["name"]: r for r in manifest["repos"]}

    check("the failed repo appears in the manifest with a non-null error",
          by_name.get("broken", {}).get("status") == "failed"
          and by_name["broken"].get("error"),
          f"entry: {by_name.get('broken')}")
    # git's clone failure ends with boilerplate ("...and the repository
    # exists."). Recording the LAST line captured exactly that and discarded the
    # fatal: line saying what went wrong, producing manifests nobody could
    # triage. The error must name the cause.
    broken_err = by_name.get("broken", {}).get("error") or ""
    check("the recorded error names the cause, not git's trailing boilerplate",
          broken_err.startswith(("fatal:", "error:", "remote: ")),
          f"error was: {broken_err!r}")
    check("a failed clone leaves nothing under repos/",
          not os.path.exists(os.path.join(out, "repos", "broken")))
    check("the staging directory is cleaned up",
          not os.path.exists(os.path.join(out, ".staging")))
    check("the successful repo is cloned with a recorded HEAD",
          by_name.get("good", {}).get("status") == "cloned"
          and bool(by_name["good"].get("head")),
          f"entry: {by_name.get('good')}")
    check("an unsafe repository name is refused, not turned into a path",
          by_name.get("../escape", {}).get("status") == "failed"
          and "unsafe" in (by_name.get("../escape", {}).get("error") or ""),
          f"entry: {by_name.get('../escape')}")
    check("no directory escaped the corpus root",
          not os.path.exists(os.path.join(os.path.dirname(out), "escape")))
    check("name_is_safe rejects traversal and hidden names",
          not name_is_safe("../x") and not name_is_safe(".hidden")
          and not name_is_safe("a/b") and name_is_safe("ok-repo_1.2"))


def test_branch_coverage(base):
    """--no-single-branch means every branch, at depth 1."""
    src = make_source_repo(os.path.join(base, "src-branches"), extra_branch="feature-x")
    payload = [{"name": "multi", "url": f"file://{src}",
                "defaultBranchRef": {"name": "main"}, "isFork": False,
                "isArchived": False, "isEmpty": False, "stargazerCount": 0,
                "pushedAt": "2026-08-01T00:00:00Z", "visibility": "PUBLIC"}]
    pj = os.path.join(base, "payload-branches.json")
    with open(pj, "w") as f:
        json.dump(payload, f)
    out = os.path.join(base, "corpus-branches")
    proc = run([sys.executable, BUILD, "--org", "fixture", "--repos-json", pj, "--out", out])
    manifest = json.load(open(os.path.join(out, "corpus.json")))
    names = {b["name"] for b in manifest["repos"][0]["branches"]}
    # EXACT equality, not a subset check. A subset check passed while
    # refs/remotes/origin/HEAD was being recorded as a phantom branch named
    # "origin" - git shortens that ref to "origin", so filtering on the short
    # name silently missed it. Only an exact comparison catches a spurious entry.
    check("all branches are cloned and recorded, with no phantom refs",
          names == {"main", "feature-x"},
          f"got branches: {names} (expected exactly main + feature-x) exit={proc.returncode}")
    check("a complete corpus exits 0", proc.returncode == 0, f"exit={proc.returncode}")


def test_branch_filter(base):
    """--branch pins the corpus to one branch: it must be the tree on disk."""
    src = make_source_repo(os.path.join(base, "src-bf"), extra_branch="feature-x")
    payload = [
        {"name": "hasbranch", "url": f"file://{src}",
         "defaultBranchRef": {"name": "main"}, "isFork": False, "isArchived": False,
         "isEmpty": False, "stargazerCount": 0, "pushedAt": "2026-08-01T00:00:00Z",
         "visibility": "PUBLIC"},
    ]
    pj = os.path.join(base, "bf.json")
    with open(pj, "w") as f:
        json.dump(payload, f)

    out = os.path.join(base, "corpus-branch")
    proc = run([sys.executable, BUILD, "--org", "fixture", "--repos-json", pj,
                "--out", out, "--branch", "feature-x"])
    m = json.load(open(os.path.join(out, "corpus.json")))
    e = m["repos"][0]

    check("--branch clones only the named branch", proc.returncode == 0
          and [b["name"] for b in e["branches"]] == ["feature-x"],
          f"branches={e['branches']} exit={proc.returncode}")
    # The point of the flag: scanners walk the working tree, so the named branch
    # must actually be checked out. Recording it in metadata alone would mean
    # scanning the default branch while the manifest claims otherwise.
    check("--branch checks the named branch out as the working tree",
          os.path.isfile(os.path.join(out, e["path"], "second.txt")),
          "second.txt exists only on feature-x; the tree on disk is not that branch")
    check("checked_out names the branch on disk, and default_branch still names the repo's",
          e.get("checked_out") == "feature-x" and e.get("default_branch") == "main",
          f"checked_out={e.get('checked_out')} default_branch={e.get('default_branch')}")
    check("head attributes to the checked-out branch",
          e["head"] == e["branches"][0]["head"] and len(e["head"]) == 40)
    check("the branch filter is recorded in the manifest",
          m["source"]["filters"].get("branch") == "feature-x")

    # A repo that simply has no such branch is a fact, not a malfunction: it must
    # not inflate the partial-corpus signal that means "something went wrong".
    out2 = os.path.join(base, "corpus-nobranch")
    proc2 = run([sys.executable, BUILD, "--org", "fixture", "--repos-json", pj,
                 "--out", out2, "--branch", "no-such-branch"])
    m2 = json.load(open(os.path.join(out2, "corpus.json")))
    e2 = m2["repos"][0]
    check("a repo lacking the branch is 'skipped', not 'failed'",
          e2["status"] == "skipped" and "no branch" in (e2["error"] or ""),
          f"entry={e2}")
    check("a missing branch does not report a partial corpus",
          proc2.returncode == 0, f"exit={proc2.returncode}")
    check("skipped-for-branch repos are summarised in warnings",
          any("no branch" in w for w in m2.get("warnings", [])),
          f"warnings={m2.get('warnings')}")
    check("an empty corpus warns that scans over it will find nothing",
          any("corpus is empty" in w for w in m2.get("warnings", [])),
          f"warnings={m2.get('warnings')}")
    check("a repo lacking the branch leaves nothing under repos/",
          not os.path.exists(os.path.join(out2, "repos", "hasbranch")))

    check("--branch and --default-branch-only are refused together",
          run([sys.executable, BUILD, "--org", "f", "--repos-json", pj,
               "--branch", "x", "--default-branch-only"]).returncode == 2)
    # Strict: the flag and its value must be adjacent, --single-branch must be
    # present, and --no-single-branch must NOT be - the two contradict, and git
    # would silently honour the last one rather than error.
    argv = clone_argv("u", "d", branch="dev")
    paired = any(argv[i] == "--branch" and argv[i + 1] == "dev"
                 for i in range(len(argv) - 1))
    check("clone_argv wires --branch to --single-branch, with no contradiction",
          paired and "--single-branch" in argv and "--no-single-branch" not in argv,
          f"argv={argv}")
    check("the hardening flags survive --branch",
          all(f in argv for f in ("core.hooksPath=/dev/null", "filter.lfs.smudge=cat",
                                  "--no-tags", "--depth")),
          f"argv={argv}")


def test_empty_repo_recorded(base):
    """An empty repo is skipped but never silently dropped (manifest rule 1)."""
    pj = os.path.join(HERE, "fixtures", "gh-repo-list.json")
    out = os.path.join(base, "corpus-listonly")
    proc = run([sys.executable, BUILD, "--org", "tomkat-cr", "--repos-json", pj,
                "--out", out, "--list-only"])
    check("--list-only prints the selection and exits 0",
          proc.returncode == 0 and "genericsuite" in proc.stdout,
          f"exit={proc.returncode} stdout={proc.stdout!r}")

    proc = run([sys.executable, BUILD, "--org", "tomkat-cr", "--repos-json", pj,
                "--out", out + "-f", "--list-only", "--no-archived", "--no-forks"])
    check("--no-archived / --no-forks narrow the selection",
          "old-experiment" not in proc.stdout and "forked-action" not in proc.stdout
          and "genericsuite" in proc.stdout,
          f"stdout={proc.stdout!r}")


def test_enumeration_truncation(base):
    """A capped repo list is the one incompleteness the manifest cannot express
    as a failure: missing repos look exactly like unselected ones."""
    pj = os.path.join(base, "many.json")
    with open(pj, "w") as f:
        json.dump([{"name": f"r{i}", "url": "", "defaultBranchRef": {"name": "main"},
                    "isFork": False, "isArchived": False, "isEmpty": True,
                    "stargazerCount": 0, "pushedAt": "2026-08-01T00:00:00Z",
                    "visibility": "PUBLIC"} for i in range(5)], f)

    out = os.path.join(base, "trunc")
    proc = run([sys.executable, BUILD, "--org", "fixture", "--repos-json", pj,
                "--out", out, "--limit", "5"])
    m = json.load(open(os.path.join(out, "corpus.json")))
    warned = any("truncated" in w for w in m.get("warnings", []))
    check("hitting --limit warns that the corpus is probably incomplete",
          warned, f"warnings: {m.get('warnings')} exit={proc.returncode}")
    check("the truncation warning is recorded in the manifest, not just printed",
          warned and "--limit" in " ".join(m.get("warnings", [])))

    out2 = os.path.join(base, "notrunc")
    run([sys.executable, BUILD, "--org", "fixture", "--repos-json", pj,
         "--out", out2, "--limit", "50"])
    m2 = json.load(open(os.path.join(out2, "corpus.json")))
    check("a list comfortably under the limit does not warn",
          not any("truncated" in w for w in m2.get("warnings", [])),
          f"warnings: {m2.get('warnings')}")


def test_local_mode(base):
    """--local: the path both scanners' lint mode depends on."""
    src = make_source_repo(os.path.join(base, "src-local"))
    mf = os.path.join(base, "local-corpus.json")
    proc = run([sys.executable, BUILD, "--local", src, "--json", mf])
    check("--local exits 0", proc.returncode == 0,
          f"exit={proc.returncode} stderr={proc.stderr[-300:]}")
    m = json.load(open(mf))
    entry = m["repos"][0] if m.get("repos") else {}
    check("--local produces a valid single-entry manifest with a real HEAD",
          m.get("schema_version") == 1 and len(m["repos"]) == 1
          and entry.get("status") == "local" and len(entry.get("head") or "") == 40
          and entry.get("branches"),
          f"manifest: {json.dumps(m)[:400]}")
    check("--local records a path relative to root, not an absolute one",
          not os.path.isabs(entry.get("path") or "/abs"),
          f"path={entry.get('path')!r}")

    # Lint mode runs in CI, where the parent of the checkout is often not
    # writable. --local must not default its manifest into that directory.
    nested = os.path.join(base, "ro-parent", "checkout")
    make_source_repo(nested)
    os.chmod(os.path.join(base, "ro-parent"), 0o555)
    try:
        out = os.path.join(base, "local-out")
        proc = run([sys.executable, BUILD, "--local", nested, "--out", out])
        check("--local does not write its manifest into the checkout's parent",
              proc.returncode == 0
              and os.path.exists(os.path.join(out, "corpus.json"))
              and not os.path.exists(os.path.join(base, "ro-parent", "corpus.json")),
              f"exit={proc.returncode} stderr={proc.stderr[-300:]}")
    finally:
        os.chmod(os.path.join(base, "ro-parent"), 0o755)

    plain = os.path.join(base, "not-a-repo")
    os.makedirs(plain, exist_ok=True)
    open(os.path.join(plain, "compose.yml"), "w").write("services: {}\n")
    mf2 = os.path.join(base, "local-plain.json")
    run([sys.executable, BUILD, "--local", plain, "--json", mf2])
    m2 = json.load(open(mf2))
    check("a non-git directory is admitted but warned about, not dropped",
          len(m2["repos"]) == 1 and m2["repos"][0].get("head") is None and m2["warnings"],
          f"manifest: {json.dumps(m2)[:400]}")


# ---------------------------------------------------------------------------
# 6 + 7: _walk hostile input and coverage honesty
# ---------------------------------------------------------------------------

def test_walk_symlinks(base):
    root = os.path.join(base, "walkroot")
    os.makedirs(os.path.join(root, "sub"), exist_ok=True)
    open(os.path.join(root, "sub", "real.txt"), "w").write("real\n")

    outside = os.path.join(base, "outside")
    os.makedirs(outside, exist_ok=True)
    open(os.path.join(outside, "secret.txt"), "w").write("SECRET\n")

    os.symlink(outside, os.path.join(root, "escape-dir"))
    os.symlink(os.path.join(outside, "secret.txt"), os.path.join(root, "escape-file"))

    stats = _walk.WalkStats()
    seen = [rel for _, rel in _walk.walk_files(root, stats=stats)]
    check("_walk does not descend a directory symlink pointing outside the root",
          not any("secret" in s for s in seen), f"saw: {seen}")
    check("_walk skips a file symlink resolving outside the root",
          "escape-file" not in seen, f"saw: {seen}")
    check("_walk counts the escaping symlinks it skipped",
          stats.symlinks_skipped >= 2, f"symlinks_skipped={stats.symlinks_skipped}")
    check("_walk still yields real files", "sub/real.txt" in seen, f"saw: {seen}")


def test_walk_prune_and_file_root(base):
    root = os.path.join(base, "pruneroot")
    os.makedirs(os.path.join(root, "node_modules", "x"), exist_ok=True)
    os.makedirs(os.path.join(root, "src"), exist_ok=True)
    open(os.path.join(root, "node_modules", "x", "index.js"), "w").write("//\n")
    open(os.path.join(root, "src", "app.py"), "w").write("pass\n")

    stats = _walk.WalkStats()
    seen = [rel for _, rel in _walk.walk_files(root, stats=stats)]
    check("_walk prunes node_modules by default",
          not any(s.startswith("node_modules") for s in seen), f"saw: {seen}")
    check("_walk counts what it pruned, so a report can state the blind spot",
          stats.prune_counts.get("node_modules") == 1, f"counts={stats.prune_counts}")

    stats2 = _walk.WalkStats()
    seen2 = [rel for _, rel in _walk.walk_files(root, no_prune=True, stats=stats2)]
    check("--no-prune reaches the pruned content",
          any(s.startswith("node_modules") for s in seen2), f"saw: {seen2}")

    # os.walk() on a file yields nothing - a root passed as a file would scan
    # zero bytes and report clean. That bug is in this package's history.
    f = os.path.join(root, "src", "app.py")
    stats3 = _walk.WalkStats()
    seen3 = list(_walk.walk_files(f, stats=stats3))
    check("_walk on a file root yields that file (not silently nothing)",
          len(seen3) == 1, f"saw: {seen3}")


def test_walk_unreadable(base):
    if os.geteuid() == 0:
        skip("_walk counts an unreadable directory",
             "running as root - chmod 000 does not block root, so this assertion "
             "would pass without exercising anything. Unreadable-path detection "
             "is NOT verified in this run; re-run as a non-root user.")
        return
    root = os.path.join(base, "unreadable")
    locked = os.path.join(root, "locked")
    os.makedirs(locked, exist_ok=True)
    open(os.path.join(locked, "x.txt"), "w").write("x\n")
    os.chmod(locked, 0o000)
    try:
        stats = _walk.WalkStats()
        list(_walk.walk_files(root, stats=stats))
        check("_walk counts an unreadable directory rather than skipping it",
              len(stats.unreadable) >= 1, f"unreadable={stats.unreadable}")
        check("unreadable paths make clean_coverage False", not stats.clean_coverage)
    finally:
        os.chmod(locked, 0o755)


# ---------------------------------------------------------------------------
# 8: marketplace registration
# ---------------------------------------------------------------------------

def test_driver_shell_portability(base):
    """The driver must survive bash 3.2, and must never report a scan outcome
    for a run that did not happen."""
    driver = os.path.join(SCRIPTS, "run_corpus.sh")
    src = open(driver, encoding="utf-8").read()

    # Static, because bash 3.2 cannot be installed here to reproduce it: on
    # macOS's bash 3.2, "${arr[@]}" on an EMPTY array under `set -u` aborts with
    # "unbound variable". Positional parameters are the portable substitute.
    # Match ${NAME[@]} / ${NAME[*]} specifically. An earlier version of this
    # check excluded any line containing "$@" - but the offending line held BOTH
    # a positional expansion and an array one, so the check passed against the
    # very bug it was written for. A guard that cannot fail is not a guard.
    array_expansion = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\[[@*]\]")
    array_assignment = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*=\(")
    offenders = [ln.strip() for ln in src.splitlines()
                 if not ln.strip().startswith("#")
                 and (array_expansion.search(ln) or array_assignment.search(ln))]
    check("the driver uses no bash arrays (macOS ships bash 3.2)",
          not offenders, f"array usage found: {offenders}")
    check("the driver does not use associative arrays",
          "declare -A" not in src)

    # A failure of the run itself must not be dressed up as a statement about
    # repositories. Exit 1 means "partial corpus"; it may only appear when a
    # manifest exists. --repos-json on a missing file fails deterministically
    # and offline.
    # Reproduce the ACTUAL failure faithfully. The reported bug was the driver
    # dying inside a command substitution: exit status 1, no manifest, no output
    # - which the driver then announced as "PARTIAL CORPUS", a verdict about
    # repositories for a run that never reached them. A merely-missing argument
    # exits 2 and would not have caught it, so the builder is stubbed to exit 1
    # silently, in a throwaway skill layout the driver resolves from its own path.
    stub_skill = os.path.join(base, "stub-skill")
    os.makedirs(os.path.join(stub_skill, "scripts"), exist_ok=True)
    shutil.copy(driver, os.path.join(stub_skill, "scripts", "run_corpus.sh"))
    with open(os.path.join(stub_skill, "scripts", "build_corpus.py"), "w") as f:
        f.write("import sys\nsys.exit(1)\n")     # exit 1, nothing on stdout
    stub_driver = os.path.join(stub_skill, "scripts", "run_corpus.sh")

    env = dict(os.environ, REPO_CORPUS_SKIP_SELFTEST="1")   # or it recurses into us
    proc = subprocess.run(["bash", stub_driver, "--org", "fixture"],
                          capture_output=True, text=True, env=env, timeout=120)
    out = proc.stdout + proc.stderr
    check("a builder that exits 1 without a manifest is reported as an error, not a corpus",
          proc.returncode == 2, f"exit={proc.returncode}\n{out[-400:]}")
    check("a run that produced no manifest is never called PARTIAL CORPUS",
          "PARTIAL CORPUS" not in out,
          f"claimed a corpus verdict for a run that produced none:\n{out[-400:]}")
    check("skipping the self-test says so loudly",
          "SELF-TEST SKIPPED" in out and "NOT verified" in out,
          "the only supported use of REPO_CORPUS_SKIP_SELFTEST must announce itself")


def test_marketplace_paths():
    mp = os.path.join(REPO_ROOT, ".claude-plugin", "marketplace.json")
    try:
        data = json.load(open(mp))
    except (OSError, json.JSONDecodeError) as e:
        check("marketplace.json parses", False, str(e))
        return
    missing = []
    for plugin in data.get("plugins", []):
        for rel in plugin.get("skills", []):
            if not os.path.isdir(os.path.join(REPO_ROOT, rel)):
                missing.append(rel)
    check("every skill path registered in marketplace.json exists on disk",
          not missing, f"missing: {missing}")


# ---------------------------------------------------------------------------

def main():
    global _HERMETIC_HOME
    print("repo-corpus self-test\n")

    ver = run(["git", "--version"])
    print(f"  {(ver.stdout or ver.stderr or 'git not found').strip()}"
          f" | python {sys.version.split()[0]} | uid {os.geteuid()}\n")

    with tempfile.TemporaryDirectory(prefix="repo-corpus-selftest-") as base:
        _HERMETIC_HOME = os.path.join(base, "hermetic-home")
        os.makedirs(_HERMETIC_HOME, exist_ok=True)

        # Build one fixture up front. If the environment cannot produce a git
        # repository at all, that is a setup problem, and saying so once beats
        # five downstream assertions failing in ways that describe it badly.
        try:
            make_source_repo(os.path.join(base, "preflight"))
        except FixtureError as e:
            print(f"  {RED}CANNOT BUILD TEST FIXTURES{RESET}\n")
            print(f"  {e}\n")
            print("  This is an environment problem, not a scanner failure: the")
            print("  self-test could not create a local git repository to clone.")
            print("  Nothing about the clone hardening was verified.")
            return 1

        print("Clone hardening")
        test_hooks_disabled(base)
        test_clone_argv_flags()
        print("\nFailure handling and the manifest contract")
        test_failed_clone(base)
        test_branch_coverage(base)
        test_branch_filter(base)
        test_empty_repo_recorded(base)
        test_enumeration_truncation(base)
        print("\nLocal mode")
        test_local_mode(base)
        print("\nWalking hostile input")
        test_walk_symlinks(base)
        test_walk_prune_and_file_root(base)
        test_walk_unreadable(base)
        print("\nDriver")
        test_driver_shell_portability(base)
        print("\nRegistration")
        test_marketplace_paths()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n{passed}/{total} assertions passed", end="")
    if skipped:
        print(f", {len(skipped)} SKIPPED (not passed):")
        for name, why in skipped:
            print(f"  - {name}")
    else:
        print()

    if passed != total:
        print(f"\n{RED}SELF-TEST FAILED - do not build a corpus with this code.{RESET}")
        return 1
    print(f"\n{GREEN}All assertions passed.{RESET}")
    if skipped:
        print("Note: skipped assertions were NOT verified. See above.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
