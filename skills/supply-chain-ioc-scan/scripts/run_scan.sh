#!/usr/bin/env bash
# run_scan.sh - Fetch the current compromised-package list and run both scan axes.
#
# Usage:
#   ./run_scan.sh ROOT [ROOT ...]
#   PROFILE=iocs/other-campaign.json ./run_scan.sh ~/dev
#
# Exit: 0 clean, 1 findings, 2 error.
set -uo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${PROFILE:-$SKILL_DIR/iocs/keyv-shai-hulud-2026-08.json}"
OUT="${OUT:-${TMPDIR:-/tmp}/ioc-scan-$(date +%Y%m%d-%H%M%S)}"

command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }
[ -f "$PROFILE" ] || { echo "profile not found: $PROFILE" >&2; exit 2; }

# Default scope is the whole of $HOME. Payload artifacts are machine-level -
# IDE persistence, staged runtimes and stray checkouts do not respect whichever
# project directory you had in mind - so narrowing the scope is how a scan
# misses what it was run to find. Pass roots explicitly to narrow deliberately.
if [ $# -eq 0 ]; then
  set -- "$HOME"
  echo "No roots given - scanning all of \$HOME ($HOME)."
  echo "Caches and app containers are pruned; this still takes several minutes."
  echo "Pass directories explicitly to narrow the scope."
  echo
fi

mkdir -p "$OUT"
CSV="$OUT/packages.csv"
OTHER="$OUT/packages.other-ecosystems.csv"

echo "### Step 0: refresh compromised-package lists (all vendor feeds, merged)"
if ! python3 "$SKILL_DIR/scripts/fetch_package_lists.py" \
      --profile "$PROFILE" --out "$CSV" --fallback "$SKILL_DIR/iocs/packages.csv"; then
  echo "  ERROR: could not obtain any package list. These lists grow for days" >&2
  echo "  after disclosure; scanning without one yields a falsely clean verdict." >&2
  exit 2
fi
# Keep the newest good merge as the offline fallback for future runs.
cp "$CSV" "$SKILL_DIR/iocs/packages.csv" 2>/dev/null || true

echo
echo "### Step 1: self-test (proves the scanners can detect)"
if ! python3 "$SKILL_DIR/tests/selftest.py" >"$OUT/selftest.log" 2>&1; then
  echo "  SELF-TEST FAILED - scanners are broken, verdicts are meaningless." >&2
  tail -25 "$OUT/selftest.log" >&2
  exit 2
fi
echo "  passed - detection provably works"

echo
echo "### Step 2: dependency axis"
OTHER_ARG=""
[ -f "$OTHER" ] && OTHER_ARG="--other-ecosystems $OTHER"
python3 "$SKILL_DIR/scripts/scan_dependencies.py" \
  --csv "$CSV" $OTHER_ARG --json "$OUT/dependencies.json" "$@" | tee "$OUT/dependencies.txt"
DEP=${PIPESTATUS[0]}

echo
echo "### Step 3: artifact axis"
python3 "$SKILL_DIR/scripts/scan_artifacts.py" \
  --profile "$PROFILE" --json "$OUT/artifacts.json" "$@" | tee "$OUT/artifacts.txt"
ART=${PIPESTATUS[0]}

echo
echo "======================================================================"
echo "Reports: $OUT"
UNREAD=$(python3 - "$OUT" <<'PYEOF'
import json, os, sys
o = sys.argv[1]; n = 0
for f in ("dependencies.json", "artifacts.json"):
    p = os.path.join(o, f)
    if os.path.isfile(p):
        try: n += len(json.load(open(p)).get("unreadable") or [])
        except Exception: pass
print(n)
PYEOF
)
if [ "$DEP" -eq 0 ] && [ "$ART" -eq 0 ]; then
  if [ "${UNREAD:-0}" -gt 0 ]; then
    echo "OVERALL: CLEAN over what was readable - ${UNREAD} path(s) COULD NOT BE READ."
    echo "  Unreadable is not clean. On macOS grant Full Disk Access to your terminal"
    echo "  (System Settings > Privacy & Security > Full Disk Access) and re-run."
    exit 0
  fi
  echo "OVERALL: CLEAN on both axes"; exit 0
fi
echo "OVERALL: FINDINGS (deps=$DEP artifacts=$ART) - triage before acting"
exit 1
