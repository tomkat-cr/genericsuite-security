#!/usr/bin/env bash
# run_docker_scan.sh - Verify detection works, then scan a corpus.
#
# Usage:
#   ./run_docker_scan.sh --corpus /path/to/corpus.json
#   ./run_docker_scan.sh --org tomkat-cr            # builds the corpus first
#   ./run_docker_scan.sh --local .                  # single checkout, lint mode
#
# Exit: 0 clean at the threshold, 1 findings, 2 error.
#
# NO BASH ARRAYS ANYWHERE IN THIS FILE. macOS ships bash 3.2, where "${a[@]}"
# on an EMPTY array under `set -u` aborts with "unbound variable". The sibling
# repo-corpus driver shipped that bug and then reported the crash as a scan
# verdict; the repo-corpus self-test now asserts against it statically.
set -uo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS_SKILL="$(cd "$SKILL_DIR/../repo-corpus" 2>/dev/null && pwd || true)"

command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }

if [ $# -eq 0 ]; then
  echo "Usage: $0 (--corpus CORPUS_JSON | --org ORG | --user USER | --local PATH)" >&2
  exit 2
fi

# The self-test is the only evidence that the detectors detect. A scanner that
# checks nothing and reports clean looks exactly like a working one on a clean
# corpus - which is the normal case, and therefore the dangerous one.
if [ "${DOCKER_SCAN_SKIP_SELFTEST:-0}" = "1" ]; then
  echo "### Step 1: SELF-TEST SKIPPED (DOCKER_SCAN_SKIP_SELFTEST=1)"
  echo "    Detection is NOT verified in this run."
else
  echo "### Step 1: self-test (proves every detection pass still fires)"
  if ! python3 "$SKILL_DIR/tests/selftest.py"; then
    echo >&2
    echo "  SELF-TEST FAILED - not scanning. A clean verdict from an unverified" >&2
    echo "  scanner is indistinguishable from one that checked nothing." >&2
    exit 2
  fi
fi

# Build a corpus first unless one was handed to us.
CORPUS=""
if [ "${1:-}" = "--corpus" ]; then
  CORPUS="${2:-}"
  shift 2
else
  [ -n "$CORPUS_SKILL" ] || {
    echo "ERROR: repo-corpus skill not found next to this one, and no --corpus given." >&2
    exit 2; }
  echo
  echo "### Step 2: build the corpus (repo-corpus)"
  CORPUS="$(python3 "$CORPUS_SKILL/scripts/build_corpus.py" "$@")"
  RC=$?
  if [ -z "$CORPUS" ] || [ ! -f "$CORPUS" ]; then
    echo "ERROR: no corpus manifest was produced (builder exit $RC)." >&2
    echo "  Nothing was scanned and nothing is known." >&2
    exit 2
  fi
  if [ "$RC" -eq 1 ]; then
    echo "  NOTE: PARTIAL corpus - some repos failed to clone. The scan below"
    echo "  inherits that blind spot and states it in its report."
  fi
  set --
fi

[ -f "$CORPUS" ] || { echo "ERROR: corpus not found: $CORPUS" >&2; exit 2; }

echo
echo "### Step 3: scan for mutable image references"
REPORT="$(python3 "$SKILL_DIR/scripts/scan_images.py" --corpus "$CORPUS" --sarif "$@")"
RC=$?

echo
echo "======================================================================"
if [ -z "$REPORT" ] || [ ! -f "$REPORT" ]; then
  echo "ERROR: no report was produced (scanner exit $RC)." >&2
  echo "  This is a failure of the run itself, not a finding about any" >&2
  echo "  repository. Nothing is known." >&2
  exit 2
fi

echo "Report: $REPORT"
if [ "$RC" -eq 1 ]; then
  echo "FINDINGS at or above the failure threshold - triage before acting."
  echo "  Read the 'Residual blind spots' section before reading the tables as"
  echo "  a complete picture."
  exit 1
fi
echo "No findings at or above the threshold."
echo "  This is not the same as 'no mutable images': see the report's policy"
echo "  boundary and blind-spot sections."
exit 0
