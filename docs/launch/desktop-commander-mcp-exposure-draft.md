# DesktopCommanderMCP exposure report draft — 2026-05-13

## Project

- Repo: `wonderwhy-er/DesktopCommanderMCP`
- Segment: MCP server with terminal/filesystem control
- Source: https://github.com/wonderwhy-er/DesktopCommanderMCP
- Status: internal draft, not sent

## Why this project is relevant

DesktopCommanderMCP is a strong ClawMoat fit because it gives AI assistants access to terminal commands, filesystem search, and file editing. That is exactly the host-machine boundary ClawMoat is trying to make visible and enforceable.

## What I scanned

- `README.md`
- `package.json`
- `SECURITY.md`
- Scanner: `/home/ildar/.hermes/skills/openclaw-imports/clawmoat/scripts/scan.sh`
- Local clone: `/tmp/clawmoat-targets/DesktopCommanderMCP`

## Findings

| Severity | Surface | Evidence | Why it matters | Suggested fix |
|---|---|---|---|---|
| critical from scanner, likely security-relevant install pattern rather than malicious prompt injection | README install path | README contains pipe-to-shell remote installer patterns for the main installer and Docker installer | Pipe-to-shell install instructions are common, but they are exactly the kind of high-trust remote execution path agent users may copy into terminals. For an MCP server controlling desktop/terminal access, this is a meaningful trust boundary. | Offer a safer install path: pin release checksums, provide `npm install` first, show an inspect-before-run command, or publish signed release artifacts. |
| clean | `package.json` | ClawMoat scan returned clean | Package metadata did not trigger prompt-injection/secret/tool-risk checks in the simple scan. | No action. |
| clean | `SECURITY.md` | ClawMoat scan returned clean | Security disclosure docs did not trigger scanner findings. | No action. |

## Boundary questions for maintainers

1. What terminal commands are allowed by default?
2. Are filesystem paths allowlisted or denied by policy?
3. Can the assistant read shell history, SSH config, `.env`, browser profiles, or credential files?
4. Are destructive commands gated by approval?
5. Are install scripts pinned to immutable releases or always fetched from `main`?

## Suggested ClawMoat outreach angle

Do not send a generic pitch. If contacting this project, lead with the install/runtime boundary:

> I scanned your public README/package/security docs with ClawMoat. The main thing it flagged was not a malicious payload, it was the trust boundary around pipe-to-shell install instructions for an MCP server that gives assistants terminal/filesystem access. Want a short PR that adds safer install guidance and an agent-boundary checklist?

## Internal note

This draft is evidence for possible outreach. It is not enough for a GitHub issue yet. Before posting externally, verify current README line numbers against the latest upstream commit and keep the tone useful, not promotional.
