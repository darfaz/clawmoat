#!/usr/bin/env bash
# ClawMoat test wrapper — runs detection test suite
set -euo pipefail

if [ -n "${CLAWMOAT_BIN:-}" ]; then
  CLAWMOAT="$CLAWMOAT_BIN"
elif command -v clawmoat &>/dev/null; then
  CLAWMOAT="clawmoat"
else
  SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
  CLAWMOAT="node $SCRIPT_DIR/bin/clawmoat.js"
fi
exec $CLAWMOAT test
