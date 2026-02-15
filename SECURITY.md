# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ Current release |

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

### What to Expect

- **Acknowledgment** within 48 hours
- **Assessment** within 7 days
- **Fix timeline** communicated within 14 days
- **Credit** in the release notes (unless you prefer anonymity)

### What NOT to Do

- Do not open a public GitHub issue for security vulnerabilities
- Do not exploit the vulnerability beyond what's needed to demonstrate it
- Do not access or modify other users' data

## Scope

The following are in scope:

- **Scanner bypasses** — Attacks that evade ClawMoat's detection
- **Policy engine bypasses** — Tool calls that circumvent policy rules
- **Audit log tampering** — Ways to modify or forge audit entries
- **Dependency issues** — Vulnerabilities in ClawMoat's dependencies (currently: none)

The following are out of scope:

- Denial of service via large inputs (expected behavior — use input size limits)
- False positives/negatives in detection (please open a regular issue)
- Vulnerabilities in upstream LLM providers

## Security Best Practices

When using ClawMoat:

1. Keep ClawMoat updated to the latest version
2. Enable all relevant scanners for your use case
3. Use strict policy configurations in production
4. Review audit logs regularly
5. Set up alerts for critical-severity findings

## PGP Key

For encrypted communications, use our PGP key (available on request at security@clawmoat.com).
