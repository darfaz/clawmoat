# Policy Engine

The Policy Engine evaluates every tool call against YAML-defined security policies. It's orthogonal to the scanner pipeline — scanners analyze content, the policy engine controls actions.

## Configuration File

ClawMoat looks for policies in this order:

1. `./clawmoat.yml` (project root)
2. `~/.clawmoat.yml` (user home)
3. Programmatic config via `createPolicy()`

## Full Configuration Reference

```yaml
# clawmoat.yml
version: 1

# ── Scanner Settings ────────────────────────
detection:
  prompt_injection: true       # Enable prompt injection scanner
  jailbreak: true              # Enable jailbreak detection
  pii_outbound: true           # Scan outbound messages for PII
  secret_scanning: true        # Scan for API keys/credentials
  exfiltration: true           # Detect data exfiltration patterns
  url_scanning: true           # Detect phishing URLs
  memory_poison: true          # Detect memory manipulation
  supply_chain: true           # Scan skills before install

# ── Tool Policies ───────────────────────────
policies:
  exec:
    # Commands that are always blocked
    block_patterns:
      - "rm -rf /"
      - "rm -rf ~"
      - "curl * | bash"
      - "curl * | sh"
      - "wget * | bash"
      - "wget * | sh"
      - "chmod 777"
      - "> /dev/sda"
      - "mkfs.*"
      - "dd if=/dev/zero"

    # Commands that require human approval before execution
    require_approval:
      - "ssh *"
      - "scp *"
      - "git push *"
      - "npm publish"
      - "docker run *"

    # Allowed commands (if set, only these are permitted)
    # allow_patterns: []

  file:
    # Paths the agent cannot read
    deny_read:
      - "~/.ssh/*"
      - "~/.aws/*"
      - "~/.gnupg/*"
      - "**/credentials*"
      - "**/.env"
      - "**/.env.local"
      - "/etc/shadow"
      - "/etc/sudoers"

    # Paths the agent cannot write
    deny_write:
      - "/etc/*"
      - "~/.bashrc"
      - "~/.profile"
      - "~/.ssh/*"
      - "~/.aws/*"

  browser:
    # Domains to block
    block_domains:
      - "*.onion"
      - "*.tor2web.*"

    # Log all browser navigation
    log_all: true

    # Block data: URLs (used for local phishing)
    block_data_urls: true

  message:
    # Scan all outbound messages for secrets/PII
    scan_outbound: true

    # Block messages containing critical findings
    block_on_critical: true

# ── Alert Configuration ─────────────────────
alerts:
  webhook: null                # POST findings to a webhook URL
  email: null                  # Send email alerts
  telegram: null               # Send Telegram alerts (bot_token:chat_id)
  severity_threshold: medium   # Minimum severity to alert on

# ── Audit Settings ──────────────────────────
audit:
  enabled: true
  log_path: ~/.clawmoat/audit.log
  tamper_evident: true         # SHA-256 hash chain
  retention_days: 90
```

## Decision Types

| Decision | Meaning | Behavior |
|----------|---------|----------|
| `allow` | Tool call is safe | Execute normally |
| `deny` | Tool call violates policy | Block execution, log event |
| `warn` | Tool call is suspicious | Execute but log warning, send alert |
| `review` | Tool call needs human approval | Pause execution, notify user |

## Programmatic Policy Creation

```javascript
const { createPolicy, evaluateToolCall } = require('clawmoat');

const policy = createPolicy({
  exec: {
    block_patterns: ['rm -rf', 'curl * | sh'],
    require_approval: ['git push *'],
  },
  file: {
    deny_read: ['~/.ssh/*', '~/.aws/*'],
    deny_write: ['/etc/*'],
  },
});

const decision = evaluateToolCall('exec', { command: 'rm -rf /' }, policy);
// → { decision: 'deny', tool: 'exec', reason: 'Matches blocked pattern: rm -rf' }
```

## Per-Tool Policy Details

### Exec Policy

Evaluated against the full command string. Supports glob patterns.

```yaml
policies:
  exec:
    block_patterns:
      - "rm -rf *"           # Glob: matches rm -rf anything
      - "curl * | bash"      # Pipe to shell
    require_approval:
      - "ssh *"              # Any SSH connection
```

### File Policy

Evaluated against the file path. Supports glob patterns and `~` expansion.

```yaml
policies:
  file:
    deny_read:
      - "~/.ssh/*"           # All SSH keys
      - "**/.env"            # Any .env file in any directory
    deny_write:
      - "/etc/*"             # System config
```

### Browser Policy

Evaluated against navigation URLs and domains.

```yaml
policies:
  browser:
    block_domains:
      - "*.onion"            # Tor sites
      - "evil.com"           # Specific domain
    log_all: true            # Log every navigation
```

## Example: Minimal Secure Config

```yaml
version: 1
detection:
  prompt_injection: true
  secret_scanning: true
policies:
  exec:
    block_patterns: ["rm -rf", "curl * | bash"]
  file:
    deny_read: ["~/.ssh/*", "~/.aws/*"]
```

## Example: Paranoid Mode

```yaml
version: 1
detection:
  prompt_injection: true
  jailbreak: true
  pii_outbound: true
  secret_scanning: true
  exfiltration: true
  url_scanning: true
  memory_poison: true
  supply_chain: true
policies:
  exec:
    block_patterns: ["rm -rf", "curl * | bash", "wget * | sh", "chmod 777"]
    require_approval: ["ssh *", "scp *", "git push *", "npm publish", "docker *"]
  file:
    deny_read: ["~/.ssh/*", "~/.aws/*", "~/.gnupg/*", "**/.env*", "**/credentials*"]
    deny_write: ["/etc/*", "~/.bashrc", "~/.profile", "~/.ssh/*"]
  browser:
    block_domains: ["*.onion"]
    log_all: true
    block_data_urls: true
  message:
    scan_outbound: true
    block_on_critical: true
alerts:
  severity_threshold: low
audit:
  enabled: true
  tamper_evident: true
```
