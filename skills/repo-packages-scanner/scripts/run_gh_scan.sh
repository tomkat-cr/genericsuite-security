#!/usr/bin/env bash
# run_gh_scan.sh - Scan a specific date range of repos for the specified keyword in the description.
# 2026-08-05 | CR
# Usage: ./run_gh_scan.sh <username> [<keyword> <date>]
# Exit: 0 clean, 1 error.

set -uo pipefail

USERNAME="${1:-}"
KEYWORD="${2:-}"
DATE="${3:-}"

if [ "$USERNAME" = "" ]; then
  echo "Usage: $0 <username> [<keyword> <date>]"
  exit 1
fi

if [ "$KEYWORD" = "" ]; then
  KEYWORD="Shai-Hulud|Here We Go Again"
fi

if [ "$DATE" = "" ]; then
  DATE="2026-08-01"
fi

DETAILED="${DETAILED:-0}"
if [ "$DETAILED" = "1" ]; then
  DETAILS_FROM_GH=', (.description // "-")'
  ADDITIONAL_HEADER=$'\tdescription'
else
  DETAILS_FROM_GH=""
  ADDITIONAL_HEADER=""
fi

echo "Scanning '$USERNAME' for '$KEYWORD' in the description or created_at between '$DATE' and today"
echo ""

# GH_PAGER= disables gh's interactive pager so results print on the terminal.
# Print every checked repo; status is MATCH when description or created_at hits the filter.
# DETAILS_FROM_GH is spliced into the jq array (empty unless DETAILED=1).
result="$(
  GH_PAGER= gh api "users/${USERNAME}/repos?per_page=100&sort=created&direction=desc" \
    -q '.[] | [
      (if ((.description // "")|test("'"${KEYWORD}"'";"i")) or (.created_at > "'"${DATE}"'")
       then "MATCH" else "ok" end),
      .created_at,
      .name'"${DETAILS_FROM_GH}"'
    ] | @tsv'
)" || {
  echo "ERROR: gh api failed" >&2
  exit 1
}

if [ -z "$result" ]; then
  echo "No repos returned for '$USERNAME'."
else
  echo "status	created_at		name${ADDITIONAL_HEADER}"
  echo "$result"
  echo ""
  checked="$(printf '%s\n' "$result" | wc -l | tr -d ' ')"
  matches="$(printf '%s\n' "$result" | grep -c '^MATCH' || true)"
  echo "Checked: $checked  Matches: $matches"
fi

echo ""
echo "Done"
echo ""