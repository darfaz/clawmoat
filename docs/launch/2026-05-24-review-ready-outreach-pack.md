# ClawMoat review-ready outreach pack — 2026-05-24

Status: internal approval pack. No external messages have been sent from this pass.

## Why this exists

ClawMoat already has public funnel assets. The current sales bottleneck is not more generic content. It is getting Dar to approve a small number of evidence-backed, non-spammy maintainer actions.

This pack turns the three strongest internal exposure drafts into approval-ready next steps. Each action is framed as a useful docs/security-boundary contribution, not a vulnerability accusation and not a cold product pitch.

## Public state checked today

- GitHub repo: `darfaz/clawmoat`, 40 stars, 6 forks.
- npm: `clawmoat@1.0.0`, `latest` tag points to `1.0.0`.
- npm downloads: 23 last week, 228 last month.
- GitHub release: `v1.0.0 — Open-source agent firewall`, not draft, not prerelease.
- Website: homepage, pricing, assessment, attack demo, comparison, MCP RCE aliases, and sitemap returned `200` for curl, Python urllib, and browser-like user agents.
- Static-site API note: `https://clawmoat.com/api/health` returned `404`; `https://clawmoat.com/api/create-checkout-session` returned `405` to invalid POST. Do not describe static-site checkout/API health as live until the intended Railway/API endpoint is checked separately.

## Approval request A: DesktopCommanderMCP docs-hardening PR offer

- Target: `wonderwhy-er/DesktopCommanderMCP`
- Source: https://github.com/wonderwhy-er/DesktopCommanderMCP
- Internal report: `docs/launch/desktop-commander-mcp-exposure-draft.md`
- Status: reviewed draft ready, not sent.
- Best channel: GitHub discussion or concise issue asking whether a docs PR would be welcome. Do not open a scary vulnerability issue.

### Why it fits

DesktopCommanderMCP gives assistants terminal control, filesystem search, and file editing. That is the clearest possible ClawMoat boundary: useful agent power and risky host access are the same capability.

### Evidence to re-verify before sending

- Current README still uses mutable pipe-to-shell install commands from `refs/heads/main`.
- Current docs still expose broad terminal/filesystem setup guidance without a short agent-boundary checklist.
- Line numbers in the existing internal report still match upstream.

### Recommended maintainer note

Hi, I reviewed DesktopCommanderMCP from an agent-boundary angle, not as a vulnerability report.

The useful part is obvious: it gives assistants terminal and filesystem control. That is also the part users need help containing.

The main thing ClawMoat flagged was the install/runtime trust boundary: mutable pipe-to-shell install docs from `refs/heads/main`, plus a powerful MCP server that can touch the host. I think a small docs PR could help: keep `npx` first, move shell installers under an inspect-first path, prefer release-tagged installer URLs, and add a short checklist for allowed directories, blocked commands, and secrets paths.

Would you want that PR?

### Go / no-go

Go if Dar approves a docs-hardening PR offer.

No-go if the action would be framed as “we found a vulnerability.” That is inaccurate and annoying.

## Approval request B: mcp-chrome browser-boundary SECURITY/docs PR offer

- Target: `hangwin/mcp-chrome`
- Source: https://github.com/hangwin/mcp-chrome
- Internal report: `docs/launch/mcp-chrome-exposure-draft.md`
- Status: reviewed draft ready, not sent.
- Best channel: GitHub issue/discussion asking whether a SECURITY/docs PR would be useful.

### Why it fits

mcp-chrome connects assistants to a real browser profile. That makes auth state, tabs, history, bookmarks, debugger/network features, downloads, and page scripting part of the agent trust boundary.

### Evidence to re-verify before sending

- README still positions mcp-chrome as using the user's existing Chrome environment/login state.
- Extension config still requests broad browser permissions.
- Tool docs still include browser interaction, JavaScript execution, debugger/network, and native bridge surfaces.

### Recommended maintainer note

Hi, I reviewed mcp-chrome from an agent/MCP exposure angle, not traditional CVE hunting.

The project is useful because it connects assistants to a real Chrome session. That is also the part users need help containing: browser profile, login state, tabs, history, bookmarks, debugger, network capture, downloads, and scripting APIs.

I drafted a short exposure map with docs/control suggestions: dedicated browser profile guidance, clearer permission-to-feature mapping, separate gates for JavaScript/network/debugger tools, and safer defaults around authenticated pages.

Would a concise SECURITY/docs PR be useful?

### Go / no-go

Go if Dar approves a neutral docs/security-boundary contribution.

No-go if we cannot re-verify the current extension permissions and docs before posting.

## Approval request C: HexStrike AI safe MCP profile PR offer

- Target: `0x4m4/hexstrike-ai`
- Source: https://github.com/0x4m4/hexstrike-ai
- Internal report: `docs/launch/hexstrike-ai-exposure-draft.md`
- Status: reviewed draft ready, not sent.
- Best channel: GitHub issue/discussion asking whether a safe-profile docs PR would be useful.

### Why it fits

HexStrike AI intentionally gives MCP-connected agents access to offensive security tools, browser automation, file operations, generated payloads, and command-adjacent workflows. This is a strong ClawMoat target because broad power is the product, but users still need a safe default boundary.

### Evidence to re-verify before sending

- Current sample MCP config still lacks a documented restricted first-run profile.
- Current server/API docs still need explicit local-only/auth/workspace guidance.
- Current README still targets Claude Desktop, Cursor, VS Code Copilot, and other general MCP clients.

### Recommended maintainer note

Hi, I reviewed HexStrike AI because it is one of the clearest MCP projects where useful agent power and risky host access are the same thing.

The strong part is obvious: the project gives agents real security tooling. The boundary risk is also obvious: the sample MCP config is broad, and the server exposes command, file, browser, and network surfaces that deserve a safer first-run profile.

I ran ClawMoat against the README, MCP config, and server. Most findings are expected for an offensive security framework, not bugs. The useful recommendation is a docs PR with a locked-down MCP profile, workspace-only file guidance, local-only/API-auth notes, and a short preflight checklist for authorized targets.

Would you want that PR/report?

### Go / no-go

Go if Dar approves a safe-profile docs PR offer.

No-go if we cannot keep the tone clear that this is hardening guidance, not an accusation.

## Recommended send order

1. DesktopCommanderMCP first. It has the cleanest non-controversial docs-hardening angle and the least risk of sounding like a vulnerability accusation.
2. mcp-chrome second. It is highly relevant, but the browser/auth-state surface needs careful wording.
3. HexStrike AI third. It is high-fit but sensitive because offensive-security findings are mostly intentional capabilities.

## Approval needed from Dar

Reply with one of these if you want me to execute externally in a future non-cron session:

- `Approve DesktopCommanderMCP docs PR offer`
- `Approve mcp-chrome docs PR offer`
- `Approve HexStrike safe MCP profile offer`
- `Approve all three, in send order`

Without that approval, the correct next move is more internal preparation and re-verification, not public outreach.
