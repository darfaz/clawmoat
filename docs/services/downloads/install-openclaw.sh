#!/bin/bash
# ============================================
#  OpenClaw Installer for Linux
#  Double-click or run: bash install-openclaw.sh
# ============================================

clear
echo ""
echo "============================================"
echo "  🛡️ OpenClaw + ClawMoat Installer"
echo "  Powered by ClawMoat"
echo ""
echo "============================================"
echo ""
echo "This will install your AI agent. It takes"
echo "about 5 minutes. Just follow the prompts."
echo ""
read -p "Press Enter to start..."

# Download and run the setup script
curl -fsSL https://raw.githubusercontent.com/darfaz/openclaw-deploy/main/setup-linux.sh -o /tmp/openclaw-setup.sh
chmod +x /tmp/openclaw-setup.sh
bash /tmp/openclaw-setup.sh

echo ""
echo "============================================"
echo "  Almost done! Two final steps:"
echo ""
echo "  1. Type: claude login"
echo "     (sign in with your Claude Max account)"
echo ""
echo "  2. Type: openclaw gateway restart"
echo ""
echo "  Then message your bot in Slack/Telegram!"
echo "============================================"
echo ""

exec bash
