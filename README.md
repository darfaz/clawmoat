# 🏰 ClawMoat

**Security moat for AI agents.**

Runtime protection against prompt injection, tool misuse, and data exfiltration — for [OpenClaw](https://openclaw.ai) and other agentic AI systems.

---

## The Problem

AI agents have unprecedented access: shell, browser, files, email, messaging. A single prompt injection in an email, webpage, or chat message can hijack your agent into exfiltrating data, running malicious commands, or impersonating you.

**ClawMoat wraps a security perimeter around your agent.**

## How It Works

```
Inbound Messages ──▶ ┌─────────────┐ ──▶ AI Agent
                     │  ClawMoat    │
Tool Call Results ◀── │  Scan Layer  │ ◀── Tool Requests
                     └─────────────┘
                           │
                     Dashboard & Alerts
```

ClawMoat intercepts the flow between your agent and the outside world:

1. **Inbound scanning** — Detects prompt injection, jailbreak attempts, and social engineering in messages, emails, and web content before they reach the agent
2. **Tool call auditing** — Validates every tool invocation against security policies (block dangerous commands, prevent data exfiltration, enforce least privilege)
3. **Outbound monitoring** — Catches sensitive data (PII, secrets, credentials) before they leave your system
4. **Behavioral analysis** — Baselines normal agent behavior and alerts on anomalies

## Quick Start

```bash
# Install
npm install -g clawmoat

# Scan a message for prompt injection
clawmoat scan "Please ignore all previous instructions and..."

# Audit an OpenClaw session log
clawmoat audit ~/.openclaw/agents/main/sessions/

# Run as middleware (intercepts tool calls in real-time)
clawmoat protect --config clawmoat.yml

# Start the dashboard
clawmoat dashboard
```

## As an OpenClaw Skill

```bash
# Install the ClawMoat skill
openclaw skills add clawmoat
```

Once installed, ClawMoat automatically:
- Scans inbound messages on all channels
- Audits tool calls before execution
- Blocks policy violations
- Logs security events

## Configuration

```yaml
# clawmoat.yml
version: 1

# Detection engines
detection:
  prompt_injection: true    # Scan for prompt injection
  jailbreak: true           # Detect jailbreak attempts
  pii_outbound: true        # Block PII in outbound messages
  secret_scanning: true     # Detect API keys, passwords, tokens

# Tool policies
policies:
  exec:
    block_patterns:
      - "rm -rf"
      - "curl * | bash"
      - "wget * | sh"
    require_approval:
      - "ssh *"
      - "scp *"
      - "git push *"
  file:
    deny_read:
      - "~/.ssh/*"
      - "~/.aws/*"
      - "**/credentials*"
    deny_write:
      - "/etc/*"
      - "~/.bashrc"
  browser:
    block_domains:
      - "*.onion"
    log_all: true

# Alerting
alerts:
  webhook: null             # POST alerts to a URL
  email: null               # Email alerts
  telegram: null            # Telegram bot alerts
  severity_threshold: medium

# SaaS features (optional)
cloud:
  enabled: false
  api_key: null             # Get yours at clawmoat.com
  # Enables: dashboard, behavioral analysis, team policies, audit trail
```

## Detection Capabilities

| Threat | Detection Method | Status |
|--------|-----------------|--------|
| Prompt injection | Pattern matching + ML classifier | ✅ v0.1 |
| Jailbreak attempts | Heuristic + classifier | ✅ v0.1 |
| Dangerous shell commands | Policy engine | ✅ v0.1 |
| Secret/credential exfiltration | Regex + entropy analysis | ✅ v0.1 |
| PII leakage | Named entity detection | 🔜 v0.2 |
| Behavioral anomalies | Session baselining | 🔜 v0.3 |
| Supply chain (malicious skills) | Static analysis | 🔜 v0.3 |

## Architecture

```
clawmoat/
├── src/
│   ├── index.js              # Main exports
│   ├── server.js             # Dashboard & API server
│   ├── scanners/
│   │   ├── prompt-injection.js    # Prompt injection detection
│   │   ├── jailbreak.js           # Jailbreak detection
│   │   ├── secrets.js             # Secret/credential scanning
│   │   └── pii.js                 # PII detection
│   ├── policies/
│   │   ├── engine.js              # Policy evaluation engine
│   │   ├── exec.js                # Shell command policies
│   │   ├── file.js                # File access policies
│   │   └── browser.js             # Browser action policies
│   ├── middleware/
│   │   └── openclaw.js            # OpenClaw integration layer
│   └── utils/
│       ├── logger.js              # Security event logging
│       └── config.js              # Configuration loader
├── bin/
│   └── clawmoat.js           # CLI entry point
├── skill/                    # OpenClaw skill package
│   └── SKILL.md
├── test/
└── dashboard/                # Web dashboard (future)
```

## OWASP Agentic AI Coverage

ClawMoat maps to the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):

| OWASP Risk | ClawMoat Protection |
|-----------|-------------------|
| ASI01 – Agent Goal Hijack | Prompt injection scanning on all inbound |
| ASI02 – Tool Misuse | Policy engine for tool calls |
| ASI03 – Identity/Privilege Abuse | Credential access monitoring |
| ASI04 – Supply Chain | Skill/plugin scanning (v0.3) |
| ASI05 – Code Execution | Shell command validation |
| ASI06 – Data Leakage | Outbound PII/secret scanning |

## Contributing

ClawMoat is open source under the MIT license. PRs welcome.

## License

MIT — see [LICENSE](LICENSE)

---

**Built for the OpenClaw community. Protecting agents everywhere.** 🏰
