# mcp-chrome exposure report draft

Date: 2026-05-14
Status: internal_draft, not sent
Project: hangwin/mcp-chrome
Source: https://github.com/hangwin/mcp-chrome
Reviewed commit: f48e71751e00bc09725c7e173423cff4f2ccd12a
Segment: Browser MCP server

## Why this target fits ClawMoat

mcp-chrome exposes a user's real Chrome browser to AI assistants through MCP. The project explicitly positions this as using the user's existing browser environment, configuration, and login state. That is a strong utility story and a strong exposure story.

This is exactly where ClawMoat's message lands: prompt filters inspect text, but an MCP browser server grants tools that can touch authenticated pages, browser history, downloads, tabs, page content, and network activity.

## Files reviewed

- README.md
- docs/TOOLS.md
- app/chrome-extension/wxt.config.ts
- packages/shared/src/tools.ts
- app/chrome-extension utility/background files surfaced by Chrome API searches

## ClawMoat scan evidence

Command set run locally from the ClawMoat repo:

```bash
node bin/clawmoat.js scan --file /tmp/clawmoat-target-mcp-chrome/README.md
node bin/clawmoat.js scan --file /tmp/clawmoat-target-mcp-chrome/app/chrome-extension/wxt.config.ts
node bin/clawmoat.js scan --file /tmp/clawmoat-target-mcp-chrome/packages/shared/src/tools.ts
```

Results:

- README.md: one HIGH finding for a localhost MCP endpoint. This is likely legitimate local MCP configuration, not malicious by itself. It still marks the endpoint as an exposed agent-control boundary.
- wxt.config.ts: clean.
- packages/shared/src/tools.ts: one HIGH finding in tool description text around execution timing/automation language. This needs manual review before treating it as a vulnerability.

## Exposure map

| Surface | Evidence | Risk | Suggested control |
|---|---|---|---|
| Existing browser session reuse | README.md lines 17-45 says the server uses the user's daily Chrome browser and preserves login state/configuration | High-value agent surface because authenticated sessions and personal browser context become reachable through MCP tools | Add a security section that plainly states what browser/session data may be reachable and recommends a dedicated browser profile for high-risk agents |
| Broad extension permissions | app/chrome-extension/wxt.config.ts lines 40-59 requests nativeMessaging, tabs, activeTab, scripting, downloads, webRequest, webNavigation, debugger, history, bookmarks, offscreen, storage, declarativeNetRequest, sidePanel, and all URLs | Very broad browser authority. This may be required for the product, but users need explicit containment guidance | Document least-privilege setup options, dedicated profile guidance, and which features require each permission |
| JavaScript execution in pages | packages/shared/src/tools.ts lines 837-865 exposes a browser JavaScript tool with debugger/runtime evaluation and scripting fallback | Agent-controlled script execution is a powerful page-context capability, especially on authenticated pages | Require explicit user approval or policy gating for JavaScript execution on sensitive domains; redact/truncate outputs by default is good, but should be part of a documented security model |
| Browser interaction tools | README.md lines 145-199 lists navigation, content extraction, network capture, clicks, form fill, keyboard, history, and bookmarks | Combined tools can read, act, and navigate across sensitive pages | Add a security checklist for sensitive domains and a denylist/allowlist recommendation |
| Network capture/debugger features | README.md lines 167-173 lists webRequest capture and debugger features; wxt.config.ts line 49 includes debugger permission | Debugger/network features can expose request metadata and potentially sensitive payload context | Gate network/debugger tools separately from basic tab listing/content reading |
| Native bridge | README.md lines 61-79 installs a global bridge and wxt.config.ts line 41 requests nativeMessaging | Native bridge extends the trust boundary from browser extension into local host process | Document native-host lifecycle, update path, and logs/storage locations; recommend verifying package origin/version |

## Not a vulnerability claim

This draft does not claim mcp-chrome is compromised or unsafe. The high-level finding is that mcp-chrome is a powerful, useful MCP server with a broad browser trust boundary. That boundary deserves explicit documentation and runtime policy guidance.

## Strongest useful outreach angle

Do not open with "we found a vulnerability." That would be sloppy and probably wrong.

Open with: "I mapped mcp-chrome's MCP/browser exposure boundary and found a few places where security docs could make the project safer for agent users. The product is powerful because it reuses the real browser session; that is also the part users need help containing."

## Draft maintainer note, not sent

Hi, I reviewed mcp-chrome from the perspective of agent/MCP exposure, not traditional CVE hunting. The project is valuable because it connects assistants to the user's real Chrome session, but that also makes the browser profile, auth state, tabs, history, bookmarks, debugger, network, and scripting APIs part of the trust boundary.

I drafted a short exposure map with specific doc/control suggestions: dedicated browser profile guidance, clearer permission-to-feature mapping, separate gates for JavaScript/network/debugger tools, and safer language around authenticated pages. No vulnerability claim, just a practical hardening note.

If useful, I can turn it into a concise SECURITY.md/docs PR.

## Next action

Ask Dar before any external issue, PR, discussion, or maintainer message. If approved, convert this into a neutral docs PR proposal rather than a security alarm.
