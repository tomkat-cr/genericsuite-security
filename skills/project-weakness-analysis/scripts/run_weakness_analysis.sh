#!/usr/bin/env bash
# run_weakness_analysis.sh - Verify detection works, then analyze projects.
#
# Usage:
#   ./run_weakness_analysis.sh --root ~/dev
#   ./run_weakness_analysis.sh --projects ~/a ~/b
#   ./run_weakness_analysis.sh --corpus path/corpus.json
#   ./run_weakness_analysis.sh --org acme
#   ./run_weakness_analysis.sh --db                     # optional registry mode
#   ./run_weakness_analysis.sh --phase merge            # after agents have run
#
# Exit: 0 nothing blocked at the thresholds, 1 at least one project blocked,
#       2 error (no report produced).
#
# NO BASH ARRAYS ANYWHERE IN THIS FILE. macOS ships bash 3.2, where "${a[@]}"
# on an EMPTY array under `set -u` aborts with "unbound variable" - and a crash
# inside a command substitution can look like a verdict rather than a broken
# run. repo-docker-scanner shipped exactly that bug.
#
# Deliberately no errexit here: a benign non-zero from one pipeline stage
# would abort silently under that option, which is the same failure wearing
# a different hat.
set -uo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$SKILL_DIR/scripts"
CORPUS_SKILL="$(cd "$SKILL_DIR/../repo-corpus" 2>/dev/null && pwd || true)"

# Capture the exact top-level invocation BEFORE any argument is consumed.
# --root/--org/--db all resolve into a --corpus path long before the Python
# scripts run, so their own argv would only show the internal call.
# gen_report.py redacts this before writing it anywhere.
WEAKNESS_INVOKED_CMD="./scripts/run_weakness_analysis.sh"
for _a in "$@"; do
  _q="$(printf '%s' "$_a" | sed "s/'/'\\\\''/g")"
  WEAKNESS_INVOKED_CMD="$WEAKNESS_INVOKED_CMD '$_q'"
done
export WEAKNESS_INVOKED_CMD
unset _a _q 2>/dev/null || true

command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }

usage() {
  cat >&2 <<'USAGE'
Usage: run_weakness_analysis.sh <input mode> [options]

Input modes (exactly one; --db is optional and needs a database, the others do not):
  --root PATH              discover every project under PATH
  --projects A B C         an explicit list of project directories
  --corpus PATH            an existing repo-corpus manifest
  --org NAME | --user NAME clone from GitHub via repo-corpus
  --db                     read a project registry table (Supabase/Postgres, read-only)

Options:
  --out PATH               output tree (default ./insights)
  --profile NAME|PATH      policy overlay (default generic)
  --phase collect|merge|all
  --max-depth N            discovery depth cap (default 3)
  --limit N                cap discovered projects
  --db-config PATH         table and column mapping
  --db-limit N             cap rows read
  --db-rows-json PATH      use a saved payload instead of a live database
  --split-monorepo         treat each marker-bearing subdirectory as a project
  --list-only              print what would be analyzed, then exit 0
  --fail-on SEVERITY       critical|high|medium|low|none (default high)
  --fail-on-readiness TIER production-ready|needs-work|not-ready|none (default not-ready)
  --no-siblings            skip the sibling scanners (recorded as a blind spot)
  --keep-work              preserve .work/
USAGE
}

OUT="./insights"; PROFILE="generic"; PHASE="collect"
MODE=""; ROOT=""; CORPUS=""; ORG=""; USERNAME=""; PROJECTS=""
MAX_DEPTH=""; LIMIT=""; DB_CONFIG=""; DB_LIMIT=""; DB_ROWS=""
SPLIT=""; LIST_ONLY=""; NO_SIBLINGS=""; KEEP_WORK=""
FAIL_ON=""; FAIL_ON_READINESS=""

[ $# -eq 0 ] && { usage; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --root) MODE="root"; ROOT="$2"; shift 2 ;;
    --corpus) MODE="corpus"; CORPUS="$2"; shift 2 ;;
    --org) MODE="org"; ORG="$2"; shift 2 ;;
    --user) MODE="org"; USERNAME="$2"; shift 2 ;;
    --db) MODE="db"; shift ;;
    --projects)
      MODE="projects"; shift
      while [ $# -gt 0 ]; do
        case "$1" in --*) break ;; *) PROJECTS="$PROJECTS $1"; shift ;; esac
      done ;;
    --out) OUT="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --phase) PHASE="$2"; shift 2 ;;
    --max-depth) MAX_DEPTH="$2"; shift 2 ;;
    --limit) LIMIT="$2"; shift 2 ;;
    --db-config) DB_CONFIG="$2"; shift 2 ;;
    --db-limit) DB_LIMIT="$2"; shift 2 ;;
    --db-rows-json) DB_ROWS="$2"; shift 2 ;;
    --split-monorepo) SPLIT="1"; shift ;;
    --list-only) LIST_ONLY="1"; shift ;;
    --no-siblings) NO_SIBLINGS="1"; shift ;;
    --keep-work) KEEP_WORK="1"; shift ;;
    --fail-on) FAIL_ON="$2"; shift 2 ;;
    --fail-on-readiness) FAIL_ON_READINESS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[ "$PHASE" = "all" ] && PHASE="collect"

if [ "$PHASE" = "collect" ] && [ -z "$MODE" ]; then
  echo "no input mode given - refusing to guess what to scan." >&2
  usage; exit 2
fi

WORK="$OUT/.work"
EVIDENCE="$WORK/evidence"
AGENTS="$WORK/agents"
mkdir -p "$WORK" "$EVIDENCE" "$AGENTS/out" || { echo "cannot write to $OUT" >&2; exit 2; }

# Defaulted here (not only inside the collect-phase block below) so a
# `--phase merge` invocation - a separate script run that never executes the
# collect block - has CORPUS_JSON defined under `set -u` instead of aborting
# on first reference. This matches where collect writes the manifest for
# every input mode except `--corpus` (which points at the user's own file and
# is never copied into .work/); for that mode the merge-phase lookup below
# simply finds nothing at this default path and skips gracefully, which is
# correct since --corpus/--discovery-stats are optional, best-effort inputs.
CORPUS_JSON="$WORK/corpus.json"

# The self-test is the only evidence that the detectors detect. A scanner that
# checks nothing and reports clean looks exactly like a working one.
if [ "${WEAKNESS_SKIP_SELFTEST:-0}" = "1" ]; then
  echo "### Step 1: SELF-TEST SKIPPED (WEAKNESS_SKIP_SELFTEST=1)"
  echo "    Detection is NOT verified in this run."
else
  echo "### Step 1: self-test (proves every detector still fires)"
  if ! python3 "$SKILL_DIR/tests/selftest.py"; then
    echo >&2
    echo "  SELF-TEST FAILED - not analyzing. A clean verdict from an unverified" >&2
    echo "  scanner is indistinguishable from one that checked nothing." >&2
    exit 2
  fi
fi

if [ "$PHASE" = "collect" ]; then
  echo "### Step 2: resolve input to a corpus"
  CORPUS_JSON="$WORK/corpus.json"
  # Separate from CORPUS_JSON deliberately: build_corpus.py's --out is a build
  # / clone-anchor DIRECTORY (repos get cloned under it in --org/--user mode;
  # in --local mode it is only a fallback anchor for the manifest). The
  # manifest's own path is controlled independently by --json. Passing
  # CORPUS_JSON (a *file* path) as --out would make build_corpus.py treat it
  # as a directory and write the manifest to <CORPUS_JSON>/corpus.json instead
  # - verified against the installed repo-corpus CLI (--help), not assumed
  # from the brief.
  CORPUS_BUILD_DIR="$WORK/corpus-build"
  BUILD="$CORPUS_SKILL/scripts/build_corpus.py"

  case "$MODE" in
    corpus)
      CORPUS_JSON="$CORPUS" ;;
    root)
      DEPTH_ARG=""; [ -n "$MAX_DEPTH" ] && DEPTH_ARG="--max-depth $MAX_DEPTH"
      LIMIT_ARG="";  [ -n "$LIMIT" ] && LIMIT_ARG="--limit $LIMIT"
      SPLIT_ARG="";  [ -n "$SPLIT" ] && SPLIT_ARG="--split-monorepo"
      # shellcheck disable=SC2086
      FOUND="$(python3 "$SCRIPTS/discover_projects.py" --root "$ROOT" --profile "$PROFILE" \
                 --stats-json "$WORK/discovery.json" $DEPTH_ARG $LIMIT_ARG $SPLIT_ARG)" || exit 2
      [ -n "$LIST_ONLY" ] && { printf '%s\n' "$FOUND"; exit 0; }
      [ -f "$BUILD" ] || { echo "repo-corpus not installed at $CORPUS_SKILL" >&2; exit 2; }
      # shellcheck disable=SC2086
      python3 "$BUILD" --local $FOUND --out "$CORPUS_BUILD_DIR" --json "$CORPUS_JSON" >/dev/null || true ;;
    projects)
      [ -n "$LIST_ONLY" ] && { printf '%s\n' $PROJECTS; exit 0; }
      [ -f "$BUILD" ] || { echo "repo-corpus not installed at $CORPUS_SKILL" >&2; exit 2; }
      # shellcheck disable=SC2086
      python3 "$BUILD" --local $PROJECTS --out "$CORPUS_BUILD_DIR" --json "$CORPUS_JSON" >/dev/null || true ;;
    org)
      [ -f "$BUILD" ] || { echo "repo-corpus not installed at $CORPUS_SKILL" >&2; exit 2; }
      if [ -n "$ORG" ]; then
        python3 "$BUILD" --org "$ORG" --out "$CORPUS_BUILD_DIR" --json "$CORPUS_JSON" >/dev/null || true
      else
        python3 "$BUILD" --user "$USERNAME" --out "$CORPUS_BUILD_DIR" --json "$CORPUS_JSON" >/dev/null || true
      fi ;;
    db)
      DBC_ARG=""; [ -n "$DB_CONFIG" ] && DBC_ARG="--db-config $DB_CONFIG"
      DBL_ARG=""; [ -n "$DB_LIMIT" ] && DBL_ARG="--db-limit $DB_LIMIT"
      DBR_ARG=""; [ -n "$DB_ROWS" ] && DBR_ARG="--db-rows-json $DB_ROWS"
      # shellcheck disable=SC2086
      python3 "$SCRIPTS/db_collect.py" --out "$WORK/db-projects.json" \
        --profile "$PROFILE" $DBC_ARG $DBL_ARG $DBR_ARG || exit 2
      [ -n "$LIST_ONLY" ] && { python3 -c "import json,sys;[sys.stdout.write(p['repo_url']+'\n') for p in json.load(open('$WORK/db-projects.json'))['selected']]"; exit 0; }
      [ -f "$BUILD" ] || { echo "repo-corpus not installed at $CORPUS_SKILL" >&2; exit 2; }
      python3 -c "import json;d=json.load(open('$WORK/db-projects.json'));json.dump([{'name':p['slug'],'url':p['repo_url']} for p in d['selected']],open('$WORK/repo-list.json','w'))"
      python3 "$BUILD" --repos-json "$WORK/repo-list.json" --out "$CORPUS_BUILD_DIR" --json "$CORPUS_JSON" >/dev/null || true ;;
  esac

  [ -s "$CORPUS_JSON" ] || { echo "no usable corpus was produced" >&2; exit 2; }

  echo "### Step 3: collect deterministic signals"
  SIB_ARG=""; [ -n "$NO_SIBLINGS" ] && SIB_ARG="--no-siblings"
  # shellcheck disable=SC2086
  python3 "$SCRIPTS/collect_signals.py" --corpus "$CORPUS_JSON" --out "$EVIDENCE" \
    --profile "$PROFILE" $SIB_ARG || exit 2

  # --db mode only: fold the registry's per-project metadata (name,
  # repo_source_field, and the configured metadata_columns) into the
  # evidence bundles collect_signals.py just wrote. Nothing else populates
  # db_metadata - see Task 6's attach_metadata.
  if [ "$MODE" = "db" ] && [ -s "$WORK/db-projects.json" ]; then
    python3 -c "
import json, sys
sys.path.insert(0, '$SCRIPTS')
import db_collect
d = json.load(open('$WORK/db-projects.json'))
db_collect.attach_metadata('$EVIDENCE', d['selected'])
" || exit 2
  fi

  echo "### Step 4: build the agent task manifest"
  PRIOR="$OUT/security-audit.json"
  PRIOR_ARG=""; [ -f "$PRIOR" ] && PRIOR_ARG="--prior-audit $PRIOR"
  # shellcheck disable=SC2086
  python3 "$SCRIPTS/build_tasks.py" --evidence "$EVIDENCE" --out "$AGENTS/tasks.json" \
    --profile "$PROFILE" $PRIOR_ARG || exit 2

  echo
  echo "COLLECT COMPLETE. The two AI stages are dispatched by Claude, not by this script."
  echo
  echo "  Task manifest: $AGENTS/tasks.json"
  echo "  Dispatch every task in it as a parallel subagent (see SKILL.md),"
  echo "  then finish with:"
  echo
  echo "      $0 --phase merge --out $OUT --profile $PROFILE"
  echo
  exit 0
fi

if [ "$PHASE" = "merge" ]; then
  echo "### Step 5: merge agent output and derive verdicts"
  PRIOR="$OUT/security-audit.json"
  PRIOR_ARG=""; [ -f "$PRIOR" ] && PRIOR_ARG="--prior-audit $PRIOR"
  FO_ARG="";  [ -n "$FAIL_ON" ] && FO_ARG="--fail-on $FAIL_ON"
  FR_ARG="";  [ -n "$FAIL_ON_READINESS" ] && FR_ARG="--fail-on-readiness $FAIL_ON_READINESS"
  # Both optional: corpus.json (repo-corpus's clone-failure/warning record) and
  # discovery.json (discover_projects.py's --stats-json, --root mode only) may
  # not exist - e.g. --corpus/--projects input modes never write the latter.
  # merge_insights.py degrades gracefully when either flag is omitted.
  CORPUS_ARG=""; [ -f "$CORPUS_JSON" ] && CORPUS_ARG="--corpus $CORPUS_JSON"
  DISC_ARG=""; [ -f "$WORK/discovery.json" ] && DISC_ARG="--discovery-stats $WORK/discovery.json"
  # shellcheck disable=SC2086
  python3 "$SCRIPTS/merge_insights.py" --evidence "$EVIDENCE" --agents "$AGENTS" \
    --out "$OUT" --profile "$PROFILE" $PRIOR_ARG $FO_ARG $FR_ARG $CORPUS_ARG $DISC_ARG || exit 2

  echo "### Step 6: render the report"
  DIGEST_ARG=""; [ -f "$WORK/digest.md" ] && DIGEST_ARG="--digest $WORK/digest.md"
  # shellcheck disable=SC2086
  python3 "$SCRIPTS/gen_report.py" --insights "$OUT/insights.json" --out "$OUT" \
    --profile "$PROFILE" --scan-command "$WEAKNESS_INVOKED_CMD" $DIGEST_ARG || exit 2

  BLOCKED="$(python3 -c "
import json,sys
d=json.load(open('$OUT/insights.json'))
n=sum(1 for p in d['projects'] if p.get('blocked'))
print(n)")" || exit 2
  [ -z "$KEEP_WORK" ] && echo "(.work/ kept for inspection; remove it yourself if unwanted)"

  echo
  if [ "$BLOCKED" -gt 0 ] 2>/dev/null; then
    echo "$BLOCKED project(s) blocked. See $OUT/WEAKNESS-REPORT.md"
    exit 1
  fi
  echo "No project blocked at the configured thresholds. See $OUT/WEAKNESS-REPORT.md"
  exit 0
fi

echo "unknown --phase: $PHASE (expected collect, merge, or all)" >&2
exit 2
