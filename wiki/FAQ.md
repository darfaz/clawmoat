# FAQ

## General

### What is ClawMoat?

ClawMoat is a security layer for AI agents. It scans inputs for prompt injection, detects jailbreak attempts, prevents credential exfiltration, and enforces tool-use policies — all at runtime, with zero dependencies.

### Why do AI agents need security?

Modern AI agents have access to shell commands, file systems, browsers, email, and APIs. A prompt injection in an email or web page can hijack an agent into running malicious commands, exfiltrating secrets, or impersonating the user. ClawMoat prevents this.

### Is ClawMoat only for OpenClaw?

No. ClawMoat works as a standalone CLI tool and Node.js library. It has first-class OpenClaw integration via the skill system, but you can use it with any AI agent framework — LangChain, AutoGPT, CrewAI, or custom agents.

### Does ClawMoat require an API key or cloud service?

No. ClawMoat runs entirely locally with zero external dependencies. The Layer 1 (pattern matching) and Layer 2 (heuristic/ML) detection work offline. Layer 3 (LLM judge) optionally uses your existing LLM API for edge cases.

---

## Detection

### What types of attacks does ClawMoat detect?

- **Prompt injection** — Attempts to override agent instructions
- **Jailbreak** — DAN, developer mode, dual persona, and other LLM bypass techniques
- **Secret exfiltration** — API keys, tokens, credentials in outbound text (30+ patterns)
- **PII leakage** — Emails, SSNs, phone numbers, credit cards, addresses
- **Data exfiltration** — curl/wget uploads, DNS tunneling, paste service uploads
- **Phishing URLs** — Suspicious TLDs, shorteners, typosquatting
- **Memory poisoning** — Attempts to manipulate agent memory files
- **Supply chain** — Malicious patterns in third-party agent skills

### What is the false positive rate?

ClawMoat is tuned for high precision. Layer 1 pattern matching has near-zero false positives for critical/high severity findings. Medium/low severity findings are intentionally more sensitive and may produce some false positives — these are logged as warnings, not blocks.

### Can attackers bypass ClawMoat?

No security tool is 100% effective. ClawMoat significantly raises the bar for attacks. The 3-layer pipeline means an attacker needs to evade pattern matching, ML classification, AND the LLM judge simultaneously. Novel attacks may initially bypass Layer 1, but Layers 2-3 provide defense in depth.

### Does ClawMoat slow down my agent?

Layer 1 runs in under 1ms. Layer 2 adds ~50ms. Layer 3 (LLM judge) adds 200ms-2s but is only invoked for ~5% of inputs. For most inputs, total overhead is under 5ms.

---

## Configuration

### Where does ClawMoat look for config?

1. `./clawmoat.yml` in the current directory
2. `~/.clawmoat.yml` in your home directory
3. Programmatic config via `createPolicy()`

### What's the minimum useful config?

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

### Can I use ClawMoat without a config file?

Yes. Without a config file, ClawMoat runs all scanners with default settings. The policy engine is inactive (all tool calls allowed) — only content scanning is performed.

---

## Integration

### How do I use ClawMoat with LangChain?

```javascript
const { scan } = require('clawmoat');

// Wrap your agent's input processing
function secureInput(text) {
  const result = scan(text);
  if (!result.safe) {
    throw new Error(`Blocked: ${result.findings.map(f => f.type).join(', ')}`);
  }
  return text;
}

// Use in your LangChain chain
const chain = new LLMChain({
  llm,
  prompt,
  inputModifier: secureInput,
});
```

### How do I add ClawMoat to my CI/CD pipeline?

```bash
# In your CI script
clawmoat audit --badge
# Exit code 1 if threats found — fails the build
```

### Does ClawMoat work with TypeScript?

ClawMoat is written in JavaScript but includes JSDoc type annotations. TypeScript projects can use it directly. Full `.d.ts` type definitions are planned for v0.3.

---

## Project

### What's the license?

MIT — free forever, for any use.

### How do I contribute?

Open an [issue](https://github.com/darfaz/clawmoat/issues) or submit a PR. All contributions welcome.

### What's on the roadmap?

- **v0.2** — TypeScript rewrite, plugin API
- **v0.3** — Behavioral anomaly detection, ML classifier models
- **v0.4** — Multi-agent delegation policies, real-time dashboard
- **v1.0** — Stable API, comprehensive test suite, full OWASP coverage

### How do I report a security vulnerability?

See our [Security Policy](https://github.com/darfaz/clawmoat/blob/main/SECURITY.md). Email security@clawmoat.com for responsible disclosure.
