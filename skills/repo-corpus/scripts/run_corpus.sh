#!/usr/bin/env bash
# run_corpus.sh - Verify the clone hardening, then build a corpus.
#
# Usage:
#   ./run_corpus.sh --org tomkat-cr
#   ./run_corpus.sh --user someone --no-forks
#   ./run_corpus.sh --local .
#   OUT=~/corpora/tomkat ./run_corpus.sh --org tomkat-cr
#
# Every argument is passed through to build_corpus.py.
# Exit: 0 complete corpus, 1 partial corpus (some repos failed), 2 error.
set -uo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }
command -v git >/dev/null || { echo "git required" >&2; exit 2; }

if [ $# -eq 0 ]; then
  echo "Usage: $0 (--org ORG | --user USER | --local PATH...) [options]" >&2
  echo "       $0 --help   for the full option list" >&2
  exit 2
fi

# The self-test is not ceremony. repo-corpus has no findings to sanity-check,
# so the hardening properties are invisible when they hold - the self-test is
# the only signal that they still do. A corpus built by unverified hardening is
# not a corpus anyone should scan.
echo "### Step 1: self-test (proves the clone hardening still holds)"
if ! python3 "$SKILL_DIR/tests/selftest.py"; then
  echo >&2
  echo "  SELF-TEST FAILED - not building a corpus. Cloned repositories are" >&2
  echo "  hostile input, and the protections against them are not verified." >&2
  exit 2
fi

echo
echo "### Step 2: build the corpus"
OUT_ARG=()
[ -n "${OUT:-}" ] && OUT_ARG=(--out "$OUT")

MANIFEST="$(python3 "$SKILL_DIR/scripts/build_corpus.py" "${OUT_ARG[@]}" "$@")"
RC=$?

echo
echo "======================================================================"
if [ $RC -eq 2 ]; then
  echo "ERROR: no usable corpus was produced."
  exit 2
fi

echo "Manifest: $MANIFEST"
if [ $RC -eq 1 ]; then
  echo "PARTIAL CORPUS - at least one repository failed to clone."
  echo "  Every scan over this corpus inherits that blind spot and must say so."
  echo "  Failed repos are in the manifest with their error; they are never omitted."
  exit 1
fi
echo "COMPLETE CORPUS - every selected repository materialized."
exit 0
