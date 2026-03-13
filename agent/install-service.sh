#!/usr/bin/env bash
# ClawMoat Agent — Systemd User Service Installer
# 
# Usage: ./install-service.sh [node-path] [agent-script-path]
# Or called from setup.js with those args.

set -euo pipefail

NODE_BIN="${1:-$(which node)}"
AGENT_SCRIPT="${2:-$(dirname "$0")/index.js}"
SERVICE_NAME="clawmoat-agent"
USER_SYSTEMD_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$USER_SYSTEMD_DIR/$SERVICE_NAME.service"

echo "Installing ClawMoat agent as systemd user service..."
echo "  Node:   $NODE_BIN"
echo "  Script: $AGENT_SCRIPT"

# Check prerequisites
if ! command -v systemctl &>/dev/null; then
  echo "ERROR: systemctl not found. Cannot install systemd service."
  echo "To run manually: node $AGENT_SCRIPT"
  exit 1
fi

# Create systemd user dir
mkdir -p "$USER_SYSTEMD_DIR"

# Write service file
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=ClawMoat Local Security Agent
Documentation=https://app.clawmoat.com
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$NODE_BIN $AGENT_SCRIPT
WorkingDirectory=$HOME
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=clawmoat-agent

# Environment
Environment=NODE_ENV=production
Environment=HOME=$HOME

# Resource limits (lightweight)
CPUQuota=10%
MemoryMax=128M

[Install]
WantedBy=default.target
EOF

echo "✓ Service file written: $SERVICE_FILE"

# Enable and start
if systemctl --user daemon-reload 2>/dev/null; then
  echo "✓ Systemd daemon reloaded"
  
  if systemctl --user enable "$SERVICE_NAME" 2>/dev/null; then
    echo "✓ Service enabled (auto-start on login)"
  else
    echo "  Warning: Could not enable service (WSL2 may require --user session)"
  fi

  if systemctl --user start "$SERVICE_NAME" 2>/dev/null; then
    echo "✓ Service started"
    sleep 1
    systemctl --user status "$SERVICE_NAME" --no-pager 2>/dev/null || true
  else
    echo "  Warning: Could not start service now"
    echo "  Try manually: systemctl --user start $SERVICE_NAME"
  fi
else
  echo ""
  echo "  Note: systemd --user session not active."
  echo "  In WSL2, enable systemd in /etc/wsl.conf:"
  echo "    [boot]"
  echo "    systemd=true"
  echo ""
  echo "  Then restart WSL and run: systemctl --user enable $SERVICE_NAME"
fi

echo ""
echo "Service management:"
echo "  Status:  systemctl --user status $SERVICE_NAME"
echo "  Logs:    journalctl --user -u $SERVICE_NAME -f"
echo "  Stop:    systemctl --user stop $SERVICE_NAME"
echo "  Disable: systemctl --user disable $SERVICE_NAME"
