#!/usr/bin/env bash
# ClawMoat audit wrapper — audits session logs
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
SESSION_DIR="${1:-$HOME/.openclaw/agents/main/sessions/}"

OUTPUT=$($CLAWMOAT audit "$SESSION_DIR" 2>&1) || true

echo "[$TIMESTAMP] audit $SESSION_DIR" >> "$LOGFILE"
echo "$OUTPUT" >> "$LOGFILE"
echo "---" >> "$LOGFILE"

echo "$OUTPUT"

if echo "$OUTPUT" | grep -qiE '(CRITICAL|HIGH|FAIL)'; then
  echo "⚠️  Security issues found in audit!" >&2
  exit 1
fi
