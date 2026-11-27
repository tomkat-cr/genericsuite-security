#!/usr/bin/env bash
# run_audit.sh — self-test, then scan roots for runtime / supply-chain floors.
#
# Usage:
#   ./scripts/run_audit.sh ROOT [ROOT...]
#   ./scripts/run_audit.sh                  # defaults to repo containing this skill's monorepo guess
#
# Exit: 0 clean, 1 findings, 2 error.
#
# NO BASH ARRAYS — macOS ships bash 3.2.
set -uo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${TMPDIR:-/tmp}/runtime-sca-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT_DIR"

command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }

if [ "${RUNTIME_SCA_SKIP_SELFTEST:-0}" = "1" ]; then
  echo "### Step 1: SELF-TEST SKIPPED (RUNTIME_SCA_SKIP_SELFTEST=1)"
else
  echo "### Step 1: self-test"
  if ! python3 "$SKILL_DIR/tests/selftest.py"; then
    echo "SELF-TEST FAILED — refusing to report a clean verdict." >&2
    exit 2
  fi
fi

if [ "$#" -eq 0 ]; then
  # Prefer the genericsuite monorepo root (../../../../ from skill scripts) when present.
  GUESS="$(cd "$SKILL_DIR/../../../.." 2>/dev/null && pwd || true)"
  if [ -n "$GUESS" ] && [ -f "$GUESS/CLAUDE.md" ]; then
    set -- "$GUESS"
  else
    set -- "$SKILL_DIR/../.."
  fi
fi

echo "### Step 2: scan $*"
echo "    Reports -> $OUT_DIR"
python3 "$SKILL_DIR/scripts/scan_runtime_supply_chain.py" \
  --policy "$SKILL_DIR/policy/floors.json" \
  --json-out "$OUT_DIR/findings.json" \
  --md-out "$OUT_DIR/report.md" \
  "$@"
rc=$?
echo "Wrote $OUT_DIR/report.md and $OUT_DIR/findings.json"
exit "$rc"
