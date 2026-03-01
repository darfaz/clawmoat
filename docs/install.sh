#!/usr/bin/env bash
# ============================================================================
# ClawMoat Installer — Enterprise-Grade AI Agent Security
# https://clawmoat.com/business/install.html
#
# Usage:
#   curl -fsSL https://clawmoat.com/install.sh | bash
#   curl -fsSL https://clawmoat.com/install.sh | bash -s -- --enterprise
#
# ⚠️  This script runs locally — no data is sent anywhere.
#     It installs ClawMoat via npm and generates a local config.
#     Source: https://github.com/ClawMoat/clawmoat
#
# Exit codes: 0 = success, 1 = error
# ============================================================================

set -euo pipefail

# ─── Colors & Formatting ────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# Disable colors if not a terminal
if [ ! -t 1 ]; then
  RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' RESET=''
fi

# ─── Helpers ─────────────────────────────────────────────────────────────────

info()    { echo -e "${BLUE}ℹ${RESET}  $*"; }
success() { echo -e "${GREEN}✅${RESET} $*"; }
warn()    { echo -e "${YELLOW}⚠️${RESET}  $*"; }
error()   { echo -e "${RED}❌${RESET} $*" >&2; }
step()    { echo -e "\n${BOLD}${CYAN}▸ $*${RESET}"; }
divider() { echo -e "${DIM}────────────────────────────────────────────────────${RESET}"; }

# ─── Flags ───────────────────────────────────────────────────────────────────

ENTERPRISE=false
DRY_RUN=false
CLAWMOAT_DIR="$HOME/.clawmoat"
CONFIG_FILE="$CLAWMOAT_DIR/config.json"

for arg in "$@"; do
  case "$arg" in
    --enterprise) ENTERPRISE=true ;;
    --dry-run)    DRY_RUN=true ;;
    --help|-h)
      echo "ClawMoat Installer"
      echo ""
      echo "Usage: bash install.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --enterprise  Enable FinanceGuard, McpFirewall, SOX templates"
      echo "  --dry-run     Show what would be done without making changes"
      echo "  --help        Show this help message"
      exit 0
      ;;
    *)
      error "Unknown option: $arg"
      exit 1
      ;;
  esac
done

# ─── Banner ──────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}🏰 ClawMoat Installer${RESET}"
echo -e "${DIM}   Enterprise-Grade AI Agent Security${RESET}"
divider
echo ""
echo -e "${DIM}⚠️  This script runs locally — no data is sent anywhere.${RESET}"
echo -e "${DIM}   All configuration stays on your machine at ~/.clawmoat/${RESET}"
echo ""

if $ENTERPRISE; then
  info "Enterprise mode enabled"
fi
if $DRY_RUN; then
  warn "Dry run — no changes will be made"
fi

# ─── Step 1: Detect OS ──────────────────────────────────────────────────────

step "Detecting operating system..."

OS="unknown"
ARCH="$(uname -m)"

case "$(uname -s)" in
  Linux*)
    if grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; then
      OS="wsl"
      info "Detected: WSL (Windows Subsystem for Linux) — $ARCH"
    else
      OS="linux"
      info "Detected: Linux — $ARCH"
    fi
    ;;
  Darwin*)
    OS="macos"
    info "Detected: macOS — $ARCH"
    ;;
  *)
    error "Unsupported operating system: $(uname -s)"
    error "ClawMoat supports Linux, macOS, and WSL."
    exit 1
    ;;
esac

# ─── Step 2: Check Node.js ──────────────────────────────────────────────────

step "Checking Node.js..."

NODE_OK=false
MIN_NODE_MAJOR=18

check_node_version() {
  if command -v node &>/dev/null; then
    NODE_VERSION="$(node -v 2>/dev/null | sed 's/^v//')"
    NODE_MAJOR="${NODE_VERSION%%.*}"
    if [ "$NODE_MAJOR" -ge "$MIN_NODE_MAJOR" ] 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

if check_node_version; then
  NODE_OK=true
  success "Node.js v$NODE_VERSION found"
else
  warn "Node.js v${MIN_NODE_MAJOR}+ is required but not found."
  echo ""

  if $DRY_RUN; then
    info "Would install Node.js via nvm"
  else
    echo -e "  ${BOLD}Install Node.js via nvm?${RESET} (recommended)"
    echo -e "  This installs nvm and Node.js LTS in your home directory."
    echo ""
    read -rp "  Install? [Y/n] " INSTALL_NODE
    INSTALL_NODE="${INSTALL_NODE:-Y}"

    if [[ "$INSTALL_NODE" =~ ^[Yy]$ ]]; then
      step "Installing nvm..."
      export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"

      if [ ! -d "$NVM_DIR" ]; then
        curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
      fi

      # Source nvm
      # shellcheck source=/dev/null
      [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

      info "Installing Node.js LTS..."
      nvm install --lts
      nvm use --lts

      if check_node_version; then
        NODE_OK=true
        success "Node.js v$NODE_VERSION installed"
      else
        error "Node.js installation failed. Please install manually:"
        echo "  https://nodejs.org/"
        exit 1
      fi
    else
      error "Node.js v${MIN_NODE_MAJOR}+ is required. Install it from https://nodejs.org/"
      exit 1
    fi
  fi
fi

# ─── Step 3: Install ClawMoat ───────────────────────────────────────────────

step "Installing ClawMoat..."

if $DRY_RUN; then
  info "Would run: npm install -g clawmoat"
else
  if command -v clawmoat &>/dev/null; then
    CURRENT_VERSION="$(clawmoat --version 2>/dev/null || echo 'unknown')"
    info "ClawMoat already installed (v$CURRENT_VERSION). Updating..."
  fi

  npm install -g clawmoat 2>&1 | tail -3
  success "ClawMoat installed: $(clawmoat --version 2>/dev/null || echo 'latest')"
fi

# ─── Step 4: Create directory structure ──────────────────────────────────────

step "Setting up ~/.clawmoat/..."

DIRS=(
  "$CLAWMOAT_DIR"
  "$CLAWMOAT_DIR/audit"
  "$CLAWMOAT_DIR/reports"
  "$CLAWMOAT_DIR/templates"
)

if $ENTERPRISE; then
  DIRS+=(
    "$CLAWMOAT_DIR/finance"
    "$CLAWMOAT_DIR/mcp-firewall"
    "$CLAWMOAT_DIR/sox"
  )
fi

if $DRY_RUN; then
  for d in "${DIRS[@]}"; do
    info "Would create: $d"
  done
else
  for d in "${DIRS[@]}"; do
    mkdir -p "$d"
  done
  success "Directory structure created"
fi

# ─── Step 5: Generate hardened config ────────────────────────────────────────

step "Generating hardened security configuration..."

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Build the enterprise section if needed
ENTERPRISE_JSON=""
if $ENTERPRISE; then
  ENTERPRISE_JSON=',
    "enterprise": {
      "financeGuard": {
        "enabled": true,
        "mode": "monitor",
        "alertOnHighValue": true,
        "thresholdUsd": 1000
      },
      "mcpFirewall": {
        "enabled": true,
        "mode": "read-only",
        "allowedTools": [],
        "blockedServers": [],
        "logAllCalls": true
      },
      "soxCompliance": {
        "enabled": true,
        "auditRetentionDays": 2555,
        "templateDir": "~/.clawmoat/sox",
        "controlsFile": "~/.clawmoat/sox/controls.json",
        "segregationOfDuties": true
      }
    }'
fi

CONFIG_CONTENT='{
  "_clawmoat": {
    "version": "1.0.0",
    "generatedAt": "'"$TIMESTAMP"'",
    "generatedBy": "install.sh",
    "os": "'"$OS"'"
  },
  "permissions": {
    "tier": "worker",
    "note": "Worker tier: read workspace, write workspace, no system changes. Upgrade to standard/full in config if needed."
  },
  "forbiddenZones": [
    { "path": "~/.ssh",              "label": "SSH keys",              "severity": "critical" },
    { "path": "~/.gnupg",            "label": "GPG keys",              "severity": "critical" },
    { "path": "~/.aws",              "label": "AWS credentials",       "severity": "critical" },
    { "path": "~/.gcloud",           "label": "Google Cloud creds",    "severity": "critical" },
    { "path": "~/.azure",            "label": "Azure credentials",     "severity": "critical" },
    { "path": "~/.kube",             "label": "Kubernetes config",     "severity": "critical" },
    { "path": "~/.docker",           "label": "Docker credentials",    "severity": "high" },
    { "path": "~/.npmrc",            "label": "npm credentials",       "severity": "high" },
    { "path": "~/.pypirc",           "label": "PyPI credentials",      "severity": "high" },
    { "path": "~/.netrc",            "label": "Network credentials",   "severity": "critical" },
    { "path": "~/.git-credentials",  "label": "Git credentials",       "severity": "critical" },
    { "path": "~/.config/gcloud",    "label": "Google Cloud config",   "severity": "high" },
    { "path": "~/.config/gh",        "label": "GitHub CLI tokens",     "severity": "high" },
    { "path": "~/.password-store",   "label": "Password store",        "severity": "critical" },
    { "path": "~/.1password",        "label": "1Password data",        "severity": "critical" },
    { "path": "/etc/shadow",         "label": "System passwords",      "severity": "critical" },
    { "path": "/etc/sudoers",        "label": "Sudo configuration",    "severity": "critical" }
  ],
  "forbiddenPatterns": [
    { "pattern": "Cookies|Login Data|Web Data", "label": "Browser credentials", "severity": "critical" },
    { "pattern": ".keychain|.keychain-db",      "label": "macOS Keychain",      "severity": "critical" },
    { "pattern": "wallet.dat|seed.txt|mnemonic", "label": "Crypto wallet",      "severity": "critical" },
    { "pattern": ".kdbx|KeePass",               "label": "KeePass database",    "severity": "critical" },
    { "pattern": ".env|.env.local|.env.prod",    "label": "Environment secrets", "severity": "high" }
  ],
  "network": {
    "egressLogging": true,
    "logFile": "~/.clawmoat/audit/network.log",
    "allowedDomains": [],
    "blockedDomains": [],
    "alertOnUnknownEgress": true
  },
  "secretScanning": {
    "enabled": true,
    "scanOnFileAccess": true,
    "patterns": ["AWS_ACCESS_KEY", "GITHUB_TOKEN", "PRIVATE_KEY", "password", "secret", "api_key"],
    "alertOnDetection": true
  },
  "audit": {
    "enabled": true,
    "logDir": "~/.clawmoat/audit",
    "retentionDays": 90,
    "logFileAccess": true,
    "logCommandExecution": true,
    "logNetworkRequests": true,
    "tamperProtection": true
  },
  "alerts": {
    "webhookUrl": "",
    "emailTo": "",
    "slackChannel": "",
    "note": "Configure at least one alert channel. Webhook receives JSON POST on security events."
  }'"$ENTERPRISE_JSON"'
}'

if $DRY_RUN; then
  info "Would write config to: $CONFIG_FILE"
  echo -e "${DIM}$CONFIG_CONTENT${RESET}" | head -20
  echo -e "${DIM}  ... (truncated)${RESET}"
else
  if [ -f "$CONFIG_FILE" ]; then
    BACKUP="$CONFIG_FILE.backup.$(date +%s)"
    cp "$CONFIG_FILE" "$BACKUP"
    warn "Existing config backed up to: $BACKUP"
  fi

  echo "$CONFIG_CONTENT" > "$CONFIG_FILE"
  chmod 600 "$CONFIG_FILE"
  success "Config written to $CONFIG_FILE (mode 600)"
fi

# ─── Step 5b: Enterprise templates ──────────────────────────────────────────

if $ENTERPRISE && ! $DRY_RUN; then
  step "Setting up enterprise templates..."

  # SOX audit control template
  cat > "$CLAWMOAT_DIR/sox/controls.json" << 'SOXEOF'
{
  "framework": "SOX-AI-Agent",
  "version": "1.0",
  "controls": [
    {
      "id": "AC-01",
      "name": "Agent Permission Tiers",
      "description": "AI agents operate under least-privilege permission tiers",
      "frequency": "continuous",
      "evidence": "~/.clawmoat/audit/*.log"
    },
    {
      "id": "AC-02",
      "name": "Credential Zone Protection",
      "description": "Forbidden zones prevent agent access to credentials",
      "frequency": "continuous",
      "evidence": "~/.clawmoat/config.json → forbiddenZones"
    },
    {
      "id": "AC-03",
      "name": "Secret Detection",
      "description": "Real-time scanning for leaked secrets in agent output",
      "frequency": "continuous",
      "evidence": "~/.clawmoat/audit/secrets.log"
    },
    {
      "id": "AU-01",
      "name": "Audit Trail Integrity",
      "description": "Tamper-protected logging of all agent actions",
      "frequency": "continuous",
      "evidence": "~/.clawmoat/audit/"
    },
    {
      "id": "NW-01",
      "name": "Network Egress Monitoring",
      "description": "All outbound network requests logged and reviewed",
      "frequency": "continuous",
      "evidence": "~/.clawmoat/audit/network.log"
    }
  ]
}
SOXEOF
  chmod 600 "$CLAWMOAT_DIR/sox/controls.json"
  success "SOX audit templates created"

  # MCP Firewall default config
  cat > "$CLAWMOAT_DIR/mcp-firewall/config.json" << 'MCPEOF'
{
  "mode": "read-only",
  "logAllCalls": true,
  "allowedTools": [],
  "blockedServers": [],
  "rateLimiting": {
    "enabled": true,
    "maxCallsPerMinute": 60
  }
}
MCPEOF
  chmod 600 "$CLAWMOAT_DIR/mcp-firewall/config.json"
  success "MCP Firewall configured (read-only mode)"
fi

# ─── Step 6: Security scan ──────────────────────────────────────────────────

step "Running initial security scan..."

REPORT_FILE="$CLAWMOAT_DIR/reports/initial-scan-$(date +%Y%m%d-%H%M%S).txt"
FINDINGS=0
CRITICAL=0

scan_report() {
  echo "$*" >> "$REPORT_FILE"
}

if ! $DRY_RUN; then

echo "# ClawMoat Initial Security Report" > "$REPORT_FILE"
echo "# Generated: $TIMESTAMP" >> "$REPORT_FILE"
echo "# OS: $OS ($ARCH)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Check for exposed credential files
echo "## Credential Exposure Check" >> "$REPORT_FILE"

CRED_PATHS=(
  "$HOME/.ssh"
  "$HOME/.aws"
  "$HOME/.gnupg"
  "$HOME/.gcloud"
  "$HOME/.azure"
  "$HOME/.kube"
  "$HOME/.docker"
  "$HOME/.npmrc"
  "$HOME/.pypirc"
  "$HOME/.netrc"
  "$HOME/.git-credentials"
  "$HOME/.password-store"
  "$HOME/.1password"
  "$HOME/.env"
)

for cred in "${CRED_PATHS[@]}"; do
  if [ -e "$cred" ]; then
    FINDINGS=$((FINDINGS + 1))
    CRITICAL=$((CRITICAL + 1))
    label="$(basename "$cred")"
    scan_report "  [FOUND] $cred — will be protected by ClawMoat"
    warn "Found: $cred — ${GREEN}now protected${RESET}"
  fi
done

# Check file permissions on sensitive items
echo "" >> "$REPORT_FILE"
echo "## Permission Check" >> "$REPORT_FILE"

if [ -d "$HOME/.ssh" ]; then
  SSH_PERMS="$(stat -c '%a' "$HOME/.ssh" 2>/dev/null || stat -f '%A' "$HOME/.ssh" 2>/dev/null || echo 'unknown')"
  if [ "$SSH_PERMS" != "700" ] && [ "$SSH_PERMS" != "unknown" ]; then
    scan_report "  [WARN] ~/.ssh permissions are $SSH_PERMS (should be 700)"
    warn "~/.ssh permissions: $SSH_PERMS (recommended: 700)"
    FINDINGS=$((FINDINGS + 1))
  fi
fi

# Check for .env files in common locations
echo "" >> "$REPORT_FILE"
echo "## Environment File Check" >> "$REPORT_FILE"

ENV_COUNT=0
while IFS= read -r -d '' envfile; do
  ENV_COUNT=$((ENV_COUNT + 1))
  scan_report "  [FOUND] $envfile"
done < <(find "$HOME" -maxdepth 3 -name '.env*' -type f -print0 2>/dev/null | head -z -20)

if [ "$ENV_COUNT" -gt 0 ]; then
  FINDINGS=$((FINDINGS + ENV_COUNT))
  info "Found $ENV_COUNT .env file(s) — secret scanning will monitor these"
fi

# Node/npm global check
echo "" >> "$REPORT_FILE"
echo "## Node.js Environment" >> "$REPORT_FILE"
scan_report "  Node.js: $(node -v 2>/dev/null || echo 'not found')"
scan_report "  npm: $(npm -v 2>/dev/null || echo 'not found')"
scan_report "  Global prefix: $(npm prefix -g 2>/dev/null || echo 'unknown')"

chmod 600 "$REPORT_FILE"
success "Security report saved to: $REPORT_FILE"

fi  # end if not dry-run

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
divider
echo ""
echo -e "${BOLD}🏰 ClawMoat Installation Complete!${RESET}"
echo ""
echo -e "  ${GREEN}✅${RESET} OS detected:         $OS ($ARCH)"
if $NODE_OK; then
echo -e "  ${GREEN}✅${RESET} Node.js:             v${NODE_VERSION:-unknown}"
fi
echo -e "  ${GREEN}✅${RESET} ClawMoat:            installed"
echo -e "  ${GREEN}✅${RESET} Config:              $CONFIG_FILE"
echo -e "  ${GREEN}✅${RESET} Permission tier:     worker (least-privilege)"
echo -e "  ${GREEN}✅${RESET} Forbidden zones:     17 credential paths protected"
echo -e "  ${GREEN}✅${RESET} Secret scanning:     enabled"
echo -e "  ${GREEN}✅${RESET} Network logging:     enabled"
echo -e "  ${GREEN}✅${RESET} Audit trail:         enabled"

if $ENTERPRISE; then
echo -e "  ${GREEN}✅${RESET} FinanceGuard:        monitor mode"
echo -e "  ${GREEN}✅${RESET} MCP Firewall:        read-only"
echo -e "  ${GREEN}✅${RESET} SOX templates:       installed"
fi

if [ "${FINDINGS:-0}" -gt 0 ]; then
echo ""
echo -e "  ${YELLOW}📊${RESET} Security findings:   ${BOLD}$FINDINGS${RESET} items found and now protected"
fi

echo ""
divider
echo ""
echo -e "${BOLD}Next steps:${RESET}"
echo ""
echo -e "  1. ${CYAN}Configure alerts${RESET} — edit ~/.clawmoat/config.json"
echo -e "     Set webhookUrl, emailTo, or slackChannel for security alerts"
echo ""
echo -e "  2. ${CYAN}Test your setup${RESET}"
echo -e "     $ clawmoat scan"
echo ""
echo -e "  3. ${CYAN}View documentation${RESET}"
echo -e "     https://clawmoat.com/docs"
echo ""

if ! $ENTERPRISE; then
echo -e "  💼 ${BOLD}Need enterprise features?${RESET} Re-run with --enterprise:"
echo -e "     $ curl -fsSL https://clawmoat.com/install.sh | bash -s -- --enterprise"
echo ""
fi

echo -e "${DIM}Questions? https://clawmoat.com/support/ • GitHub: ClawMoat/clawmoat${RESET}"
echo ""
