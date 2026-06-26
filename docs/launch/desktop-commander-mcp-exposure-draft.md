# DesktopCommanderMCP exposure report draft — 2026-05-13

## Project

- Repo: `wonderwhy-er/DesktopCommanderMCP`
- Segment: MCP server with terminal/filesystem control
- Source: https://github.com/wonderwhy-er/DesktopCommanderMCP
- Upstream commit reviewed: `9c44119` (2026-05-14 local clone)
- Status: reviewed internal draft, not sent

## Why this project is relevant

DesktopCommanderMCP is a strong ClawMoat fit because it gives AI assistants access to terminal commands, filesystem search, and file editing. That is exactly the host-machine boundary ClawMoat is trying to make visible and enforceable.

## What I scanned

- `README.md`
- `package.json`
- `SECURITY.md`
- Scanner: `node bin/clawmoat.js scan --file ...` from `/home/ildar/clawmoat`
- Local clone: `/tmp/clawmoat-targets/DesktopCommanderMCP`

## Findings

| Severity | Surface | Evidence | Why it matters | Suggested fix |
|---|---|---|---|---|
| critical from ClawMoat scanner, likely security-relevant install pattern rather than malicious prompt injection | README install path | README line 136 contains `curl -fsSL https://raw.githubusercontent.com/.../refs/heads/main/install.sh | bash`; Docker installer uses `bash <(curl -fsSL .../refs/heads/main/install-docker.sh)` at lines 217, 288, 293, and 310 | Pipe-to-shell install instructions are common, but they are exactly the kind of high-trust remote execution path agent users may copy into terminals. For an MCP server controlling desktop/terminal access, this is a meaningful trust boundary. Fetching from `refs/heads/main` also means the executed installer is mutable rather than release-pinned. | Offer a safer install path: make `npx` the primary recommendation, pin installer URLs to release tags, provide checksums/signatures, show an inspect-before-run command, or publish signed release artifacts. |
| clean | `package.json` | `node bin/clawmoat.js scan --file package.json` returned clean | Package metadata did not trigger prompt-injection/secret/tool-risk checks in the simple scan. | No action. |
| clean | `SECURITY.md` | `node bin/clawmoat.js scan --file SECURITY.md` returned clean | Security disclosure docs did not trigger scanner findings. | No action. |

## Boundary questions for maintainers

1. What terminal commands are allowed by default?
2. Are filesystem paths allowlisted or denied by policy?
3. Can the assistant read shell history, SSH config, `.env`, browser profiles, or credential files?
4. Are destructive commands gated by approval?
5. Are install scripts pinned to immutable releases or always fetched from `main`?

## Scanner evidence

```text
$ node bin/clawmoat.js scan --file /tmp/clawmoat-targets/DesktopCommanderMCP/README.md
Scanning file: /tmp/clawmoat-targets/DesktopCommanderMCP/README.md (50214 chars)

🏰 ClawMoat Scan Results

CRITICAL prompt_injection (data_exfiltration)
  Matched: "curl -fsSL https://raw.githubusercontent.com/wonderwhy-er/DesktopCommanderMCP/refs/heads/main/instal"

Total findings: 1
```

Important nuance: this is not evidence that DesktopCommanderMCP is malicious. It is evidence that ClawMoat currently treats remote script execution from public docs as a critical agent/host trust boundary. The finding should be framed as install hardening, not as an accusation.

## Suggested ClawMoat outreach angle

Do not send a generic pitch. If contacting this project, lead with the install/runtime boundary:

> I scanned your public README/package/security docs with ClawMoat. The main thing it flagged was not a malicious payload, it was the trust boundary around mutable pipe-to-shell install instructions (`refs/heads/main`) for an MCP server that gives assistants terminal/filesystem access. Want a short PR that adds safer install guidance and an agent-boundary checklist?

## Internal note

This draft is evidence for possible outreach. It is not enough for a GitHub issue yet. Before posting externally, verify current README line numbers against the latest upstream commit and keep the tone useful, not promotional.


## Draft docs PR shape

If Dar approves outreach, the lowest-friction contribution is a docs-only PR:

1. Keep `npx @wonderwhy-er/desktop-commander@latest setup` as the first install path.
2. Move pipe-to-shell installers under an “advanced / inspect first” heading.
3. Add an inspect-before-run command:

```bash
curl -fsSL https://raw.githubusercontent.com/wonderwhy-er/DesktopCommanderMCP/<release-tag>/install.sh -o install.sh
less install.sh
bash install.sh
```

4. Prefer release-tag URLs over `refs/heads/main`.
5. Add a short agent boundary checklist:
   - configure `allowedDirectories`;
   - review `blockedCommands`;
   - avoid broad home-directory access;
   - do not expose secrets, SSH config, browser profiles, or `.env` paths unless intentional.

## Go / no-go

- Go: publish as a useful docs-hardening PR, no scare language.
- No-go: do not open a GitHub issue that sounds like a vulnerability disclosure; this is hardening guidance, not confirmed exploitation.
