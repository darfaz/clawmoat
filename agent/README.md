# ClawMoat Local Agent

A Node.js daemon that monitors OpenClaw activity, scans messages through ClawMoat, and reports results to the cloud dashboard at [app.clawmoat.com](https://app.clawmoat.com).

## Quick Start

```bash
# 1. Configure (interactive setup)
node agent/setup.js

# 2. Run the daemon
node agent/index.js

# 3. Or run with verbose output
node agent/index.js --verbose
```

## What it monitors

- **`~/.openclaw/agents/main/sessions/*.jsonl`** — Real-time OpenClaw session files. Every inbound (user) and outbound (assistant) message is scanned as it's written.
- **`~/.openclaw/delivery-queue/`** — Incoming channel messages (Telegram, Discord, etc.) before they reach the agent.

## Files

| File | Purpose |
|------|---------|
| `index.js` | Main daemon — run this |
| `setup.js` | Interactive configuration wizard |
| `install-service.sh` | Install as systemd user service |
| `openclaw-hook.js` | OpenClaw integration layer (can also run standalone) |
| `~/.clawmoat/agent.json` | Config (API key, settings) |
| `~/.clawmoat/audit.log` | Local JSONL audit log of all scans |

## Config (`~/.clawmoat/agent.json`)

```json
{
  "apiKey": "cm_live_...",
  "dashboardUrl": "https://app.clawmoat.com",
  "scanInbound": true,
  "scanOutbound": true,
  "scanToolCalls": true,
  "auditLog": "~/.clawmoat/audit.log",
  "reportToCloud": true
}
```

Get your API key from: https://app.clawmoat.com/settings/api-keys

## Systemd Service (WSL2)

First enable systemd in WSL2 (`/etc/wsl.conf`):
```ini
[boot]
systemd=true
```

Then run setup:
```bash
node agent/setup.js
# Answer yes to "Install as systemd user service?"
```

Or manually:
```bash
bash agent/install-service.sh
systemctl --user status clawmoat-agent
journalctl --user -u clawmoat-agent -f
```

## Cloud API

Each scan posts to `POST /api/scan` with Bearer auth:

```json
{
  "source": "local-agent",
  "agentVersion": "1.0.0",
  "hostname": "DarLaptop",
  "meta": {
    "direction": "inbound",
    "role": "user",
    "sessionFile": "abc123",
    "timestamp": "2026-03-12T..."
  },
  "result": {
    "safe": false,
    "severity": "high",
    "action": "block",
    "findings": [...]
  }
}
```

Cloud reporting is skipped silently if `apiKey` is not set or is the placeholder value.

## Dry Run / Testing

```bash
# No cloud calls, verbose output
node agent/index.js --dry-run --verbose

# Hook standalone (same flags)
node agent/openclaw-hook.js --verbose
```

## Architecture

```
OpenClaw session files (.jsonl)
         │
         ▼
  SessionTailer (fs.watch)
         │ new lines
         ▼
  extractContent()
         │ text + role
         ▼
  ClawMoat.scanInbound/scanOutbound()
         │
    ┌────┴────┐
    │         │
CLEAN      THREAT
    │         │
  audit    audit + cloud POST
  log         │
           reportToCloud()
               │
        app.clawmoat.com
           /api/scan
```
