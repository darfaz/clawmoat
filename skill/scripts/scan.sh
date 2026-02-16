#!/usr/bin/env bash
# ClawMoat scan wrapper — scans text/file for threats, logs results
set -euo pipefail

LOGFILE="${CLAWMOAT_LOG:-clawmoat-scan.log}"
if [ -n "${CLAWMOAT_BIN:-}" ]; then
  CLAWMOAT="$CLAWMOAT_BIN"
elif command -v clawmoat &>/dev/null; then
  CLAWMOAT="clawmoat"
else
  SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
  CLAWMOAT="node $SCRIPT_DIR/bin/clawmoat.js"
fi
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Pass all args through to clawmoat scan
OUTPUT=$($CLAWMOAT scan "$@" 2>&1) || true

# Log
echo "[$TIMESTAMP] scan $*" >> "$LOGFILE"
echo "$OUTPUT" >> "$LOGFILE"
echo "---" >> "$LOGFILE"

# Print output
echo "$OUTPUT"

# Exit non-zero if CRITICAL or HIGH found
if echo "$OUTPUT" | grep -qiE '"severity"\s*:\s*"(critical|high)"' || \
   echo "$OUTPUT" | grep -qiE '(CRITICAL|HIGH)'; then
  echo "⚠️  CRITICAL/HIGH threat detected!" >&2
  exit 1
fi
