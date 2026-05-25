# DesktopCommanderMCP docs-hardening PR draft — 2026-05-25

Status: internal draft. No issue, PR, DM, or email has been sent.

## Target

- Repo: `wonderwhy-er/DesktopCommanderMCP`
- URL: https://github.com/wonderwhy-er/DesktopCommanderMCP
- Re-verified upstream commit: `9c44119`
- Best channel: ask maintainers whether they want a small docs PR before opening it.

## Why this is the cleanest first outreach

Desktop Commander is not a good target for a scary vulnerability report. Their `SECURITY.md` already says the built-in restrictions are guardrails for AI behavior, not hardened security boundaries, and it explicitly recommends Docker isolation for users who need stronger security.

That makes the useful angle simple: a docs-hardening contribution that helps users choose the right boundary before they connect an AI assistant to local files, terminal commands, and process control.

This is exactly ClawMoat's wedge:

> Prompt filters inspect text. ClawMoat protects the machine.

## Current evidence re-verified

- README says Desktop Commander can search, update, manage files, run terminal commands, interact with processes, and perform full filesystem operations.
- README install option 1 uses `npx @wonderwhy-er/desktop-commander@latest setup` as the recommended path.
- README install option 2 still uses a mutable raw GitHub `refs/heads/main` shell installer for macOS.
- README install option 6 recommends Docker isolation and selective folder mounting.
- `SECURITY.md` says directory restrictions and command blocking are not hardened security boundaries and recommends Docker for production/security-sensitive use.
- `server.yaml` includes an `ALLOWED_DIRECTORIES` setting and notes that an empty array allows full filesystem access.
- Local ClawMoat scan of upstream `README.md`, `SECURITY.md`, and `server.yaml` returned clean, which is good. The issue is not malicious content. The issue is users may not understand the host boundary they are granting.

## Proposed PR title

`docs: add agent boundary quickstart`

## Proposed PR summary

Add a short security-oriented quickstart that helps users choose between the fastest install path and the safer Docker/selective-mount path. This does not frame Desktop Commander as vulnerable. It makes the existing security model easier to understand before users connect broad filesystem and terminal access to an AI assistant.

## Exact change I would propose

### README.md

Add this short section after the feature list/security-hardening bullets and before `How to install`:

```md
## Agent boundary quickstart

Desktop Commander gives your AI assistant useful local power: filesystem access, terminal commands, process control, and document editing. Treat that as a host boundary decision, not just an install step.

If you are trying Desktop Commander on your own machine, the `npx` install is the fastest path. If you are connecting it to client work, production repositories, shared credentials, or sensitive documents, start with Docker and mount only the folders the assistant needs.

A safer first-run setup looks like this:

- Use Docker isolation when you need a real security boundary.
- Mount one workspace folder first, not your whole home directory.
- Keep secrets, SSH keys, browser profiles, and password stores outside mounted folders.
- Prefer project-specific MCP config over global config when possible.
- Review allowed directories and blocked commands before giving the assistant a broad task.
- Check the audit log after the first few sessions so you know what the assistant actually touched.

See [SECURITY.md](SECURITY.md) for current limitations and the Docker install section below for setup.
```

### SECURITY.md

Add this after `For users who need security`:

```md
### Safer first-run profile

For users evaluating Desktop Commander in a security-sensitive environment, start narrow and expand deliberately:

1. Use Docker installation for isolation.
2. Mount only one test workspace folder.
3. Do not mount secrets directories, SSH keys, browser profiles, password stores, or full home directories.
4. Prefer a project-specific MCP config over a global user config.
5. Keep network access disabled or tightly scoped when the task does not require it.
6. Review Desktop Commander's audit logs after setup and after the first real task.

These defaults will be too restrictive for some workflows. That is the point of a first-run profile: prove the assistant only needs a small boundary before granting a larger one.
```

## Maintainer note draft

Hi, I reviewed Desktop Commander from an agent-boundary angle, not as a vulnerability report.

The useful part is obvious: it gives assistants real filesystem, terminal, and process control. The current `SECURITY.md` already explains that the built-in restrictions are guardrails, not hardened security boundaries, and recommends Docker for users who need stronger isolation.

I think a small docs PR could help users make the right boundary choice before install: a short "agent boundary quickstart" in the README plus a safer first-run profile in `SECURITY.md`. It would point security-sensitive users toward Docker, selective folder mounts, project-specific config, and audit-log review without changing the product or making alarmist claims.

Would you want that PR?

## Why this should come before the other two outreach actions

This is the least accusatory ask and the highest chance of being welcomed. The maintainers already acknowledge the security model. We would be offering to make that model clearer for users.

## Approval gate

Requires Dar approval before any external action. Suggested approval phrase:

`Approve DesktopCommanderMCP docs PR offer`
