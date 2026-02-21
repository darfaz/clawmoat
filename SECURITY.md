# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.6.x   | ✅ Current release |
| 0.5.x   | ✅ Security fixes  |
| < 0.5   | ❌ End of life     |

## Reporting a Vulnerability

If you discover a security vulnerability in ClawMoat, **please report it responsibly**.

### How to Report

1. **Email:** Send details to **security@clawmoat.com**
2. **Subject line:** `[SECURITY] Brief description`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Time Commitments

| Stage | Timeframe |
|-------|-----------|
| **Acknowledgment** | Within 48 hours |
| **Initial assessment** | Within 7 days |
| **Fix timeline communicated** | Within 14 days |
| **Patch released** | Within 30 days (critical), 90 days (other) |
| **Public disclosure** | Coordinated with reporter |

### What NOT to Do

- Do not open a public GitHub issue for security vulnerabilities
- Do not exploit the vulnerability beyond what's needed to demonstrate it
- Do not access or modify other users' data

## 🏰 Hack Challenge

Think you can bypass ClawMoat? We want you to try.

**[hack-clawmoat](https://github.com/darfaz/hack-clawmoat)** — our official challenge repo with guided scenarios for testing ClawMoat's defenses. Bypass a scanner, escape the policy engine, or tamper with audit logs.

Valid bypasses qualify for recognition in our security program.

## Scope

**In scope:**

- **Scanner bypasses** — Attacks that evade ClawMoat's detection (prompt injection, jailbreak, secret scanning)
- **Policy engine bypasses** — Tool calls that circumvent policy rules
- **Host Guardian escapes** — Breaking out of permission tiers
- **Audit log tampering** — Ways to modify or forge audit entries
- **Insider threat detection evasion** — Bypassing behavioral analysis
- **Dependency issues** — Vulnerabilities in ClawMoat's dependencies

**Out of scope:**

- Denial of service via large inputs (expected behavior — use input size limits)
- False positives/negatives in detection (please open a regular issue)
- Vulnerabilities in upstream LLM providers

## 🏆 Recognition Program

We believe in recognizing the people who make ClawMoat more secure.

### Founding Security Advisor

The highest recognition tier. **Only available pre-v1.0** — once ClawMoat hits v1.0, this title is closed forever.

**Requirements:** Discover and responsibly disclose a critical or high-severity vulnerability.

**You get:**
- 🛡️ Permanent "Founding Security Advisor" title on our [Hall of Fame](https://clawmoat.com/hall-of-fame.html)
- 📝 Named acknowledgment in every major release's changelog
- 🔗 Profile link (GitHub, website, or social) on the Hall of Fame page
- 🤝 Direct line to the maintainers for future security discussions

### Hall of Fame

For any verified security vulnerability report.

**You get:**
- 🏆 Permanent listing on the [Hall of Fame](https://clawmoat.com/hall-of-fame.html)
- 📝 Credit in the release notes for the fixing version
- 🔗 Profile link on the Hall of Fame page

### Honorable Mention

For reports that improve security posture without being exploitable vulnerabilities — hardening suggestions, edge cases, documentation improvements.

**You get:**
- 🙏 Listed in the Honorable Mentions section of the Hall of Fame
- 📝 Credit in the relevant release notes

## Security Best Practices

When using ClawMoat:

1. Keep ClawMoat updated to the latest version
2. Enable all relevant scanners for your use case
3. Use strict policy configurations in production
4. Review audit logs regularly
5. Set up alerts for critical-severity findings

## PGP Key

For encrypted communications, use our PGP key (available on request at security@clawmoat.com).
