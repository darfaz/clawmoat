# ClawMoat Threat Model

Honest, precise. Security tools that overclaim are worse than useless.

## What ClawMoat Protects Against

### ✅ In Scope

**1. Prompt Injection**
- Direct instruction override ("ignore previous instructions")
- System prompt extraction attempts
- Indirect injection via tool results (poisoned README, issues, emails, web pages)
- Encoding-based injection: base64, zero-width chars, bidi overrides, Unicode tags, HTML comments
- Role-play/persona injection (DAN, jailbreaks)
- CI/CD workflow injection (${{ github.event.* }})
- Multi-language injection (foreign-script wrapper with embedded English commands)

**2. Secret Exfiltration**
- 30+ credential pattern detection (OpenAI, AWS, GitHub, Slack, Stripe, private keys)
- Shell-based exfil: curl POST, wget upload, DNS exfil, netcat, tar+pipe
- Output scanning: blocks agent responses containing API keys, private keys, PII

**3. Dangerous Tool Calls**
- Shell command injection (rm -rf, fork bomb, curl|bash, chmod 777, crontab)
- Privilege escalation (sudo, setuid, su root)
- Credential file access (~/.ssh, ~/.aws, ~/.env, ~/.npmrc)
- SQL injection in tool arguments
- Path traversal (../../etc/passwd, /proc/self)

**4. Supply Chain**
- Known compromised packages: telnyx@4.87.x, event-stream@3.3.6, ua-parser-js@0.7.29, node-ipc
- Malicious postinstall/preinstall scripts
- Webpack/build config tampering with exec callbacks
- CI workflow injection risks

**5. MCP Configuration Risks**
- Dangerous MCP server commands (arbitrary shell, root filesystem access)
- Credential leaks in MCP environment variables
- Known vulnerable MCP servers (mcp-shell, mcp-terminal)
- Unpinned npx package installations
- External (non-localhost) MCP server URLs

---

## ❌ Out of Scope (Honest Limitations)

**1. Zero-day or novel attack patterns**
ClawMoat uses pattern matching and heuristic scoring. A sufficiently novel attack that doesn't match known patterns will not be detected. We add patterns as new attacks emerge — run `npm update clawmoat` regularly.

**2. Semantic/contextual injection at the LLM layer**
If an attacker crafts a prompt that looks syntactically safe but semantically manipulates the model's reasoning, ClawMoat will not catch it. This requires LLM-native defenses (input validation at inference time). ClawMoat operates at the text/tool layer, not inside the model.

**3. Encrypted or heavily obfuscated payloads**
ClawMoat detects common encoding (base64, zero-width chars, bidi). A well-crafted multi-layer obfuscation that evades our decoders would not be caught. Treat deeply obfuscated input as suspicious regardless.

**4. Agent logic flaws**
If your agent's *design* leaks secrets (e.g., always includes API keys in prompts), ClawMoat can't fix architectural mistakes — though it will catch the output if a key appears there.

**5. In-memory attacks**
Attacks that exploit memory, heap, or native code execution within the Node.js runtime are outside scope.

**6. Authenticated attacker with code execution**
If an attacker already has code execution on the host, ClawMoat provides no additional protection. It's a runtime layer, not a host hardening solution.

**7. False-positive-free guarantee**
The current eval suite shows 0% false positives on 7 common dev tasks. Real-world workflows are far more varied. You may encounter false positives on legitimate code snippets that resemble attack patterns. Use `monitor` mode first to calibrate before `enforce`.

---

## Attack Coverage Matrix

| Attack Vector | Covered | Confidence | Notes |
|---------------|---------|------------|-------|
| Direct prompt injection | ✅ | High | 10+ patterns |
| Indirect injection via tool results | ✅ | High | Added in v0.9.1 |
| Base64-encoded instructions | ✅ | High | Decoded + rescanned |
| Zero-width / bidi hiding | ✅ | High | 20+ Unicode ranges |
| HTML comment injection | ✅ | High | |
| Role-play / DAN jailbreak | ✅ | High | |
| System prompt extraction | ✅ | High | |
| curl/wget exfiltration | ✅ | High | |
| DNS exfiltration | ✅ | High | |
| Secret in outbound response | ✅ | High | 30+ patterns |
| SSH key in output | ✅ | High | |
| Dangerous shell commands | ✅ | High | 20+ patterns |
| Privilege escalation | ✅ | High | |
| SQL injection in tool args | ✅ | High | |
| Path traversal | ✅ | High | |
| MCP config risks | ✅ | High | |
| Known compromised packages | ✅ | Medium | Known list only |
| CI/CD injection | ✅ | Medium | Expression-based |
| Semantic/contextual injection | ❌ | n/a | Requires LLM-native defense |
| Novel encoding techniques | ⚠️ | Low | Pattern-dependent |
| Multi-turn persistent injection | ⚠️ | Low | Per-message only |

---

## Operating Modes

| Mode | Behavior | Use When |
|------|----------|----------|
| `enforce` | Block on critical/high findings | Production agents |
| `monitor` | Log findings, allow everything | Calibrating thresholds |
| `off` | Disabled | Testing / debugging |

---

## False Positive Mitigation

If ClawMoat blocks legitimate work:

1. **Switch to `monitor` mode** — see what's being flagged without blocking
2. **Check the finding evidence** — `result.findings[0].evidence` shows exactly what matched
3. **Add exceptions** via custom policy rules in `clawmoat.yml`
4. **Report it** — open an issue at https://github.com/darfaz/clawmoat/issues

---

## Version History

- **v1.0.0** (current): ClawMoat positioned as the open-source agent firewall, with runtime containment, MCP scanning, enforcement middleware, live monitoring, and the full multi-module framework unified into the first stable major release
- **v0.9.1**: Added indirect injection, CI injection, wget upload, known compromised packages, private key content detection in inbound scanner
- **v0.9.0**: Policy engine, MCP scanner, enforcement middleware, 7-module framework
- **v0.8.0**: Supply chain scanner, insider threat detection
- **v0.7.0**: Host Guardian with permission tiers

---

*Last updated: 2026-04-14*
