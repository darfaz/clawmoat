# ClawMoat v1 launch assets — May 12, 2026

## Current launch state

ClawMoat is no longer blocked by release hygiene.

- GitHub repo: `darfaz/clawmoat`
- GitHub description: `The open-source agent firewall. Prevent AI agents from leaking data, using dangerous tools, and importing poisoned dependencies.`
- GitHub release: `v1.0.0 — Open-source agent firewall`
- npm: `clawmoat@1.0.0`, `latest` dist-tag points to `1.0.0`
- Website: `https://clawmoat.com/` returns `200` for browser, curl, and Python agent-style clients
- Homepage H1: `ClawMoat v1.0.0, the open-source agent firewall.`
- Tests: 527 passing from latest verification run
- Launch baseline: 39 GitHub stars, 6 forks, 43 npm downloads in the last 30 days

The sales problem is now distribution, not product availability.

## Core positioning

Primary frame:

> Your AI agent has access to your machine. ClawMoat decides what it can touch.

Short frame:

> Prompt filters inspect text. ClawMoat protects the machine.

Category:

> The open-source firewall for AI agents running on real machines.

Mechanism:

> ClawMoat watches the boundary: files, shell commands, network calls, MCP configs, secrets, PII, outbound data, and runtime behavior.

## Launch decision rules

Safe to execute without another approval:

- Update repo docs, plans, metadata, and launch assets
- Verify npm/GitHub/site/checkout state
- Build target lists from public information
- Draft posts, emails, and reports
- Commit and push internal launch-prep assets

Requires Dar approval before execution:

- Posting on X, HN, Reddit, Dev.to, LinkedIn
- Sending outbound emails, DMs, comments, or PRs to third parties
- Creating paid checkout sessions or real purchases
- Changing Cloudflare/security settings further

## Day 1 launch post set

### X single post

Your AI agent has access to your machine.

SSH keys. `.env` files. AWS creds. Browser cookies. Repo history.

Prompt filters inspect text.
ClawMoat controls what the agent can actually touch.

Open-source agent firewall:
https://clawmoat.com

### X thread

1/ Your AI agent has access to your machine.

That means SSH keys, `.env` files, AWS creds, browser sessions, source code, shell commands, MCP tools, and outbound network calls.

That is not a chatbot anymore. That is an intern with root-ish access.

2/ Most AI security tools protect the model or inspect the prompt.

Useful, but incomplete.

The real question is what happens after the model decides to act.

What can it read?
What can it run?
What can it send?
What gets logged?
What gets blocked?

3/ That is the boundary ClawMoat is built for.

It scans inbound content, outbound content, tool calls, MCP configs, secrets, PII, dangerous shell commands, supply-chain patterns, exfiltration patterns, and runtime behavior.

4/ The category is simple:

Prompt filters inspect the conversation.
ClawMoat protects the machine.

5/ It is open source, MIT licensed, and published on npm.

Install:
`npm install -g clawmoat`

Scan your MCP setup:
`clawmoat scan-mcp`

Site:
https://clawmoat.com

### Hacker News Show HN

Title:

> Show HN: ClawMoat, an open-source firewall for AI agents

Post:

I built ClawMoat because local AI agents are getting real permissions faster than they are getting real security.

If you run Claude Code, OpenClaw, Cursor agents, MCP servers, or custom agent loops on your machine, the agent can often read files, run shell commands, access credentials, and make network calls. Prompt injection is only part of the problem. The bigger problem is runtime containment.

ClawMoat scans inbound text, outbound text, MCP configs, tool calls, secrets, PII, dangerous shell commands, supply-chain payloads, and exfiltration patterns. The goal is not to make the model safe. The goal is to control what the agent can touch.

It is MIT licensed and runs locally.

```bash
npm install -g clawmoat
clawmoat scan-mcp
clawmoat watch ~/.openclaw/agents/main
```

I would especially like feedback from people running local agents with real file/shell access. What boundary would you want enforced before trusting an agent on your laptop?

Repo: https://github.com/darfaz/clawmoat
Site: https://clawmoat.com

### Reddit version

Title:

> I built an open-source firewall for local AI agents

Post:

I have been getting more uncomfortable with how much access local coding agents and MCP setups have.

A prompt filter can catch some bad text, but it does not answer the question I care about:

What can the agent actually touch?

ClawMoat is my attempt at that boundary. It scans MCP configs, shell/file/network actions, secrets, PII, prompt injection, supply-chain patterns, and outbound data. The point is runtime containment for agents running on real machines.

Install:

```bash
npm install -g clawmoat
clawmoat scan-mcp
```

Repo: https://github.com/darfaz/clawmoat
Site: https://clawmoat.com

I am looking for technical feedback, especially from people running Claude Code, Cursor agents, OpenClaw, Aider, or MCP servers locally. What would you want blocked or logged before you trust an agent with repo/filesystem access?

## Direct outbound pack

### Segment 1: AI automation consultants

Subject:

> quick security layer for the agents you deploy

Message:

I saw you deploy AI agents for clients. Quick question: are those agents allowed to touch files, shell commands, APIs, or client data?

I’m building ClawMoat, an open-source firewall for AI agents. It scans prompts, MCP configs, shell/file/network actions, secrets, and outbound data so you can tell clients: the agent can’t touch what it shouldn’t.

If useful, I’ll run a free exposure scan on one demo setup and send the report. No pitch deck.

CTA:

> Want me to scan one setup and send the report?

### Segment 2: agent framework/tool maintainers

Subject:

> want a free security badge for your agent project?

Message:

I’m building ClawMoat, an open-source agent firewall.

For your project, the useful part is simple: scan MCP configs, dangerous tool permissions, prompt-injection payloads, secrets, and exfiltration patterns. If it passes, you can add a `Secured by ClawMoat` badge and link to the report.

Want me to run it against your repo and send a PR with the badge/report if it’s clean?

CTA:

> Send repo URL, I’ll run the scan.

### Segment 3: founders using coding agents

Subject:

> your coding agent probably has more access than you think

Message:

Your coding agent can likely read SSH keys, env files, repo history, cloud credentials, and browser-adjacent data. That’s fine until one poisoned README, website, or MCP tool tells it to leak something.

ClawMoat is the open-source firewall I built for that boundary: files, shell, network, MCP, secrets, outbound data.

If you send me the agent stack you’re using, I’ll tell you the top 3 exposure points and how to lock them down.

CTA:

> What agent stack are you running right now?

## 100-target list criteria

Build the list in this order:

1. AI automation consultants who publicly mention agents, MCP, Claude Code, Cursor, OpenAI Agents, LangChain, CrewAI, OpenClaw, or client automation.
2. Maintainers of MCP servers and agent frameworks with active repos.
3. Founders and engineers posting about local agents with file/shell access.
4. Security engineers discussing prompt injection, MCP security, agent permissions, or secret exfiltration.
5. Open-source projects that could accept a `Secured by ClawMoat` scan report/badge PR.

Minimum fields:

```csv
name,segment,company_or_project,source_url,contact_channel,why_relevant,personalized_hook,status,next_action
```

Daily outbound cap for quality:

- 20 messages/day
- 5 badge/report offers/day
- 5 follow-ups/day starting day 3

## First 10 free assessment offer

Offer:

> I’ll scan your local agent/MCP setup and send a short exposure report: dangerous tools, reachable secrets, outbound risk, and what I’d lock down first.

Deliverable:

- 1-page report
- top 3 risks
- exact commands/configs to fix
- ClawMoat install/scan commands
- optional badge if clean

Conversion path:

1. Free assessment
2. If real risk exists, offer $249–$999 setup/fix package
3. If team usage exists, offer Team plan at $49/mo
4. If consultant, offer affiliate/badge bundle

## Launch execution files

- `docs/launch/2026-05-13-channel-strategy.md` — channel order, approval boundaries, target scoring rubric.
- `docs/launch/2026-05-13-github-targets.csv` — first 25 GitHub candidate targets for scan/report offers. All are `candidate_unreviewed` unless explicitly marked reviewed; no external outreach has been sent from autonomous passes.
- `docs/launch/2026-05-13-metrics.csv` — current daily metric baseline.
- `docs/launch/2026-05-24-review-ready-outreach-pack.md` — approval-ready maintainer outreach asks for DesktopCommanderMCP, mcp-chrome, and HexStrike AI. Still internal; requires Dar approval before any issue, PR, discussion, email, or DM.

## Metrics to track daily

```csv
date,github_stars,npm_downloads_7d,npm_downloads_30d,site_status,targets_added,messages_sent,replies,assessments_booked,assessments_done,paid_conversions,mrr,notes
```

Day 7 targets:

- 100 targets identified
- 60 direct messages sent
- 6 replies
- 3 assessment calls/reports
- 1 paid conversion or warm buying signal

## Hard truth checkpoint

If ClawMoat gets posts but no replies, the problem is not awareness. The problem is offer specificity.

The offer that should get replies is not “try my security tool.”

The offer is:

> I’ll show you exactly what your agent can touch that it shouldn’t.

That is the sales motion.
