---
name: clawmoat
description: AI agent security scanner. Detects prompt injection, jailbreak attempts, secret/credential leakage, and dangerous tool calls. Use when scanning inbound messages, auditing sessions, evaluating tool safety, or checking outbound content for sensitive data. Automatically protects against OWASP Top 10 Agentic AI risks.
---

# ClawMoat — Security Moat for AI Agents

## Quick Use

Scan any suspicious text:
```bash
node /path/to/clawmoat/bin/clawmoat.js scan "TEXT_TO_SCAN"
```

Audit session logs:
```bash
node /path/to/clawmoat/bin/clawmoat.js audit ~/.openclaw/agents/main/sessions/
```

Run detection test suite:
```bash
node /path/to/clawmoat/bin/clawmoat.js test
```

## As a Library

```javascript
const ClawMoat = require('/path/to/clawmoat/src/index');
const moat = new ClawMoat();

// Scan inbound message
const result = moat.scanInbound(text, { context: 'email' });
// → { safe: bool, findings: [], severity, action }

// Check tool call against policies
const policy = moat.evaluateTool('exec', { command: 'rm -rf /' });
// → { decision: 'deny', reason: '...', severity: 'critical' }

// Scan outbound for secrets
const leak = moat.scanOutbound(text);
// → { safe: bool, findings: [] }
```

## What It Detects

- **Prompt injection**: instruction overrides, role manipulation, delimiter attacks, invisible text, data exfiltration attempts
- **Jailbreak**: DAN, sudo mode, developer mode, dual persona, encoding bypasses
- **Secrets**: AWS, GitHub, OpenAI, Anthropic, Stripe, Telegram, SSH keys, JWTs, connection strings, passwords
- **Dangerous tools**: destructive shell commands, sensitive file access, network listeners, pipe-to-shell

## When to Use

- Before processing emails, web content, or messages from untrusted sources
- Before executing tool calls suggested by external input
- When auditing session logs for security events
- When sending outbound messages that might contain credentials
