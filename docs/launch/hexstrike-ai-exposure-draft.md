# HexStrike AI exposure draft — internal only

Status: `internal_draft`
External action: none sent. Ask Dar before opening an issue, discussion, PR, email, or DM.

## Target

- Project: `0x4m4/hexstrike-ai`
- Source: https://github.com/0x4m4/hexstrike-ai
- Reviewed commit: `9b8c780`
- Segment: security MCP / autonomous pentest agent platform
- Why this is high-fit: HexStrike intentionally gives MCP-connected agents access to offensive security tools, browser automation, file operations, generated payloads, and shell-backed execution. This is exactly the buyer boundary ClawMoat explains: useful agent power and dangerous agent power are the same capability unless the host gates it.

## Files inspected

- `README.md`
- `hexstrike-ai-mcp.json`
- `hexstrike_mcp.py`
- `hexstrike_server.py`
- `requirements.txt`

## ClawMoat scan evidence

Scanner: local `clawmoat@1.0.0` from this repo.

Commands run:

```bash
node bin/clawmoat.js scan --file /tmp/hexstrike-ai/README.md
node bin/clawmoat.js scan --file /tmp/hexstrike-ai/hexstrike_server.py
node bin/clawmoat.js scan-mcp /tmp/hexstrike-ai/hexstrike-ai-mcp.json
node bin/clawmoat.js ci /tmp/hexstrike-ai --json
```

Results:

- README scan: 5 findings, including high-severity hits around debug-mode language, privileged package-manager usage, and no-permission wording. Some are expected for an offensive security framework, so treat these as review triggers, not proof of compromise.
- Server scan: 9 findings, including critical/high hits around credential-harvesting terminology, JWT none-algorithm test logic, local/cloud metadata URLs, privileged command references, and generic password-like strings. Many appear to be intentional offensive or test-generation features.
- MCP config scan: 3 findings.
  - Medium: external URL in MCP config.
  - Medium: unrestricted stdio MCP server.
  - Low: no tool restrictions configured.
- CI scan JSON returned zero findings. That means the generic CI scanner did not catch the MCP/runtime boundary concerns; the targeted file and MCP scans did.

## Findings worth turning into a useful maintainer report

| Severity | Surface | Evidence | Why it matters | Suggested fix |
|---|---|---|---|---|
| High | MCP tool boundary | `hexstrike-ai-mcp.json` exposes the MCP server without an allowlist, while the README documents use from Claude Desktop, Cursor, VS Code Copilot, and other MCP clients. | A connected agent can invoke a broad set of powerful security, file, browser, payload, and command-adjacent tools. For this project, broad power is the product, but users need a safe default boundary. | Add a recommended locked-down MCP config with `allowedTools` or equivalent client-side restrictions for first-run use. Separate demo-safe tools from offensive/high-impact tools. |
| High | Shell-backed execution | `hexstrike_server.py` exposes `/api/command`, which calls a generic command executor. The executor ultimately uses shell-backed subprocess execution. | If the local API is reachable by a malicious local process, misconfigured network binding, or an over-permissioned agent, the blast radius becomes host command execution. | Document that the server must stay bound to loopback, add optional token auth, and consider deny-by-default command categories unless an explicit profile is enabled. |
| Medium | File operations | The server exposes create, modify, delete, and list file endpoints. | Agent-accessible file mutation is valuable for pentest workflows but risky when paired with untrusted prompts, browser content, or copied target data. | Add a workspace root restriction and document a disposable working directory setup. |
| Medium | Browser / network automation | README installs browser automation and many network/security tools, and the server includes browser/proxy/network modules. | This creates a strong ClawMoat story: the agent can touch local browser tooling, network scanners, and external targets. Users need scope and authorization checks. | Add a preflight checklist: allowed targets, allowed networks, no real credentials, explicit authorization, and log retention. |
| Medium | Public docs safety | README contains commands and language expected for a pentest framework, including high-risk terms that ClawMoat flags. | These are not automatically bad. The issue is that MCP users may copy the config into general-purpose agents without a safety boundary. | Add a “safe MCP setup” section with restricted tools and a warning that general-purpose agents should not receive unrestricted offensive-tool access. |

## Boundary questions for maintainers

1. Is the API meant to be reachable only on loopback, or do users commonly bind it to other interfaces for remote MCP clients?
2. Which tools are safe enough for first-run demos, and which should require explicit opt-in?
3. Is there already an auth/token mechanism planned for the local API?
4. Should file operations be restricted to a workspace directory by default?
5. Would you accept a docs PR with a “safe MCP profile” and a scan/report badge section?

## Outreach draft, do not send unless Dar approves it

Subject: safe MCP profile idea for HexStrike AI

I reviewed HexStrike AI because it is one of the clearest examples of an MCP server where useful agent power and risky host access are the same thing.

The strong part is obvious: the project gives agents real security tooling. The boundary risk is also obvious: the sample MCP config is broad, and the server exposes command, file, browser, and network surfaces that deserve a safer first-run profile.

I ran ClawMoat against the README, MCP config, and server. Most findings are expected for an offensive security framework, not “bugs.” The useful recommendation is a docs PR with a locked-down MCP profile, workspace-only file guidance, and a short preflight checklist for authorized targets.

Want me to send that PR/report over?

## Internal recommendation

This is a strong target, but do not cold-file a scary “vulnerability” issue. That would be wrong and annoying because most findings are inherent to the product category. The right move is a helpful docs/security-boundary PR offer: safe MCP profile, explicit local-only API note, workspace restriction recommendation, and optional ClawMoat scan badge.
