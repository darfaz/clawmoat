# ClawMoat launch channel strategy — 2026-05-13

## Straight take

X alone will not sell this. It is useful for founder narrative, but developer adoption will come from places where people already look for agent tooling: GitHub, HN, Reddit, npm, docs, and specific security reports for projects with real agent permissions.

The strongest safe next move is not another generic post. It is a reviewed target list plus a concrete scan/report offer.

## Channel order

1. GitHub target reports
   - Purpose: create trust with maintainers and agent-tool users.
   - Angle: "I scanned the boundary your agent exposes. Want the report?"
   - Current status: first 25 candidate repos saved in `docs/launch/2026-05-13-github-targets.csv`.
   - Approval needed before external action: yes, for every issue, PR, discussion, or maintainer message.

2. Hacker News Show HN
   - Purpose: broad developer feedback and early installs.
   - Angle: open-source firewall for agents running on real machines.
   - Asset: draft already in `docs/plans/2026-05-12-launch-assets.md`.
   - Approval needed before posting: yes.

3. Reddit technical communities
   - Purpose: sharper objections from local-agent and self-hosted users.
   - Angle: "What would you want blocked before trusting an agent with your laptop?"
   - Approval needed before posting: yes.

4. Dev.to / technical article
   - Purpose: durable search asset with attack demo.
   - Angle: poisoned README tries to exfiltrate secrets, ClawMoat blocks it.
   - Current gap: demo needs to become the primary conversion asset.
   - Approval needed before posting: yes.

5. npm/GitHub metadata
   - Purpose: conversion trust at install moment.
   - Status: npm/GitHub release/version alignment is good.
   - Safe autonomous work: keep docs, README, package metadata, badges, and examples tight.

6. Direct assessment offer
   - Purpose: turn technical interest into revenue.
   - Angle: "I’ll show you exactly what your agent can touch that it shouldn’t."
   - Approval needed before sending: yes.

## Candidate scoring rubric

Score each candidate 0-2 on each line. Prioritize 7+.

- Agent has filesystem, shell, browser, network, auth, or MCP access.
- Users are technical enough to install a CLI or accept a security docs PR.
- Repo is active and maintainer-facing discussion is available.
- ClawMoat can produce a specific finding/report, not a generic pitch.
- Outreach can be helpful without hijacking the project.

## Outreach rule

Do not post "try my tool" into repos. That will read as spam.

Only contact a project after doing one of these:

- run a ClawMoat scan against public examples/configs;
- identify a concrete dangerous permission pattern in docs;
- draft a useful security checklist PR;
- produce a short exposure report they can reject or use.

## First 5 candidates to manually review

1. `wonderwhy-er/DesktopCommanderMCP` — strongest fit: terminal control and filesystem access.
2. `hangwin/mcp-chrome` — browser access is visceral and easy to explain.
3. `google-gemini/gemini-cli` — huge local-agent audience, but needs polished evidence.
4. `ComposioHQ/composio` — agent tools/auth surface maps to ClawMoat's boundary.
5. `0x4m4/hexstrike-ai` — security MCP with command/network risk, high relevance.

## Next safe autonomous tasks

- Build a one-page exposure-report template for candidate repos.
- Run ClawMoat against the first candidate's public examples/config docs locally.
- Add a README section that points maintainers to the free scan/report offer.
