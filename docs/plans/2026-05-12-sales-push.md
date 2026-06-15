# ClawMoat sales push — May 12, 2026

## Straight diagnosis

ClawMoat has a real product shape now, but sales are being throttled by execution gaps, not by the idea.

The strong part: the category claim is sharp. **They protect the model. ClawMoat protects the machine.** That is a real wedge because the market is crowded with prompt filters, MCP scanners, and guardrail libraries, while ClawMoat can credibly claim host/runtime containment.

The weak part: the public product funnel is split across too many offers and some proof points are stale. The homepage sells open-source security SaaS. `/services/` sells done-for-you OpenClaw setup. `/business/` sells enterprise assessment. The npm package still shows `0.8.0` even though the repo is `1.0.0`. That inconsistency kills trust right before purchase.

## Current baseline

- GitHub: 39 stars, 6 forks.
- npm: latest published version is now `1.0.0`, matching repo `package.json`.
- npm downloads last 30 days: 43.
- Tests: 527 passing, 0 failing on the latest full verification run.
- Site: deployed and current on `clawmoat.com`; browser, curl, and Python agent-style clients return `200` after Cloudflare bot-setting fix.
- Checkout endpoint: live at `https://clawmoat-production.up.railway.app/api/checkout` for POST, health check live.
- Homepage paid CTA exists for Developer and Team plans.
- Services page has live Stripe links.

## Market read

The agent-security category has moved fast. GitHub search shows several adjacent tools with more stars:

- `luckyPipewrench/pipelock` — 583 stars, "Open-source AI agent firewall for MCP security: agent egress control, DLP, SSRF, and prompt injection defense."
- `getagentseal/agentseal` — 254 stars, security toolkit for dangerous skills, MCP configs, supply chain attacks, prompt-injection resistance.
- `snyk/agent-scan` — 2392 stars, security scanner for AI agents, MCP servers, and agent skills.
- `splx-ai/agentic-radar` — 966 stars, scanner for LLM agentic workflows.
- `cisco-ai-defense/mcp-scanner` — 923 stars, MCP server scanner.
- `protectai/llm-guard` and `NVIDIA-NeMo/Guardrails` are broader LLM guardrail/toolkit players.

This means ClawMoat cannot win by saying "we scan prompt injection". That claim is already commoditized.

ClawMoat should win by owning this exact sentence:

> Prompt filters inspect text. ClawMoat controls what the agent can do to your machine.

## Best buyer segments

### 1. Self-hosted AI agent users

People running Claude Code, OpenClaw, Cursor, Aider, MCP servers, local agents, or homegrown agent loops on real machines.

Their pain: "I want the power, but I don't trust the blast radius."

Best offer: free CLI + scanner + badge, then Developer plan for alerts, persistent logs, threat intel.

### 2. Small technical teams adopting coding agents

Founders and engineering leads with 3-25 developers. They are not ready for enterprise procurement but they do worry about credentials, repo access, and MCP sprawl.

Their pain: "My team is installing agent tools faster than security can track them."

Best offer: Team plan at $49/mo or one-time implementation/security review.

### 3. Consultants / AI automation shops

They deploy agents for clients and need a trust story. They can resell or bundle ClawMoat.

Their pain: "I need to convince the client this won't leak their data."

Best offer: affiliate/referral program + `Secured by ClawMoat` badge + white-label report.

### 4. Security-aware enterprises

This is slower sales. Useful for credibility, not first revenue unless there is a warm intro.

Their pain: "Employees are using agents with access to production credentials and no audit trail."

Best offer: Business assessment, compliance report, managed rollout.

## Funnel problems to fix first

### 1. npm release mismatch is fixed

Repo, homepage, GitHub release, and npm now all say `1.0.0`. That trust leak is closed.

Next action: keep package/release metadata in sync for every public push.

### 2. Package contents include junk

`npm pack --dry-run` currently includes `clawmoat-0.8.0.tgz`, `server/index.js.patch`, and `server/data/api-keys.json`. The public preview key is not catastrophic, but shipping key stores and patch scraps looks sloppy.

Action: exclude stale tarballs, patch scraps, and local key stores from npm.

### 3. The product has too many offers

Homepage pricing: Developer/Team SaaS. Services page: setup packages. Business page: assessment. Scanner page: free tool. That is not fatal, but the paths need to be explicit:

- Developers: install free → scan → upgrade for logs/alerts.
- Teams: scan fleet → Team plan.
- Businesses: book assessment.
- Consultants: affiliate/resell.

### 4. Proof needs to be more concrete

"40/40 eval" is useful, but buyers need one visceral demo:

- poisoned README tries to exfiltrate `.env`
- ClawMoat blocks it
- audit log shows why
- policy says what would have happened

Action: make the attack demo the primary conversion asset.

### 5. Sales CTA is mostly passive

Waiting for traffic will not work. The immediate sales motion should be direct outreach to people already showing intent: maintainers of agent repos, AI automation consultants, and founders posting about Claude Code/MCP security.

## Positioning

Primary headline:

> Your AI agent has access to your machine. ClawMoat decides what it can touch.

Secondary:

> The open-source firewall for AI agents running on real machines.

Mechanism:

> Prompt filters inspect the conversation. ClawMoat monitors the boundary: files, shell commands, network calls, MCP configs, secrets, and outbound data.

Contrast:

> Lakera, LLM Guard, and NeMo focus on model/prompt safety. Snyk and MCP scanners focus on config/static scanning. ClawMoat focuses on runtime containment for the host.

## 14-day sales push

### Day 0: Product hygiene

- npm `1.0.0` is published.
- GitHub `v1.0.0` release is live.
- Package hygiene excludes stale tarballs, patch scraps, and mutable server key state.
- Website now returns `200` for browser, curl, and Python agent-style clients.
- Next: pin attack demo GIF/video in README and homepage.
- Next: make `/scan/` the top CTA everywhere.
- Next: verify checkout with one test Stripe session if Dar approves.

### Days 1-3: Founder/dev launch

- X thread: "Your agent has root access. Does it deserve it?"
- Hacker News Show HN: ClawMoat, open-source firewall for AI agents.
- Reddit posts in `r/LocalLLaMA`, `r/ClaudeAI`, `r/cybersecurity`, `r/mcp`, `r/selfhosted`.
- Dev.to post with attack demo code.
- GitHub Discussions/community posts only where relevant, not spam.

### Days 4-7: Direct outbound

Build a list of 100 targets:

- AI automation consultants.
- Agent framework maintainers.
- MCP tool authors.
- Founders posting about Claude Code/OpenClaw/Cursor agents.
- Security engineers discussing prompt injection or MCP risk.

Send 20/day. The CTA is not "buy now". The CTA is:

> I scanned your agent/tooling surface and found a few places ClawMoat can help. Want the report?

### Days 8-14: Convert proof into revenue

- Offer free 15-minute agent exposure assessment to first 10 teams.
- Turn every assessment into a sanitized case study.
- Ask every technical adopter to add the `Secured by ClawMoat` badge.
- Ask every consultant to join affiliate program.
- Push Team plan only after a real risk finding.

## Outbound message drafts

### For AI automation consultants

Subject: quick security layer for the agents you deploy

I saw you deploy AI agents for clients. Quick question: are you giving those agents file/shell/API access, or keeping them inside a narrow sandbox?

I’m building ClawMoat, an open-source firewall for AI agents. It scans prompts, MCP configs, shell/file/network actions, and outbound data so you can tell clients, “your agent can’t touch what it shouldn’t.”

If useful, I’ll run a free exposure scan on one demo setup and send you the report. No pitch deck.

### For agent framework/tool maintainers

Subject: want a free security badge for your agent project?

I’m building ClawMoat, an open-source agent firewall.

The useful part for your project is simple: scan MCP configs, dangerous tool permissions, prompt-injection payloads, secrets, and exfiltration patterns. If it passes, you can add a `Secured by ClawMoat` badge and link to the report.

Want me to run it against your repo and send a PR with the badge/report if it’s clean?

### For founders using Claude Code / OpenClaw / Cursor agents

Subject: your coding agent probably has more access than you think

Your coding agent can likely read SSH keys, env files, browser sessions, and cloud credentials. That’s fine until one poisoned README, website, or MCP tool tells it to exfiltrate them.

ClawMoat is the open-source firewall I built for that boundary: files, shell, network, MCP, secrets, outbound data.

If you send me the agent stack you’re using, I’ll tell you the top 3 exposure points and how to lock them down.

## Public post drafts

### X short post

Your AI agent has access to your machine.

SSH keys. `.env` files. AWS creds. Browser cookies. Repo history.

Prompt filters inspect text.
ClawMoat controls what the agent can actually touch.

Open-source agent firewall.
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

It scans inbound content, outbound content, tool calls, MCP configs, secrets, PII, dangerous shell commands, supply-chain patterns, and runtime behavior.

4/ The category is simple:

Prompt filters inspect the conversation.
ClawMoat protects the machine.

5/ It’s open source, zero-dependency Node.js, MIT licensed, and the test suite is green.

Install:
`npm install -g clawmoat`

Scan:
`clawmoat scan-mcp`

Site:
https://clawmoat.com

### Hacker News Show HN draft

Title: Show HN: ClawMoat, an open-source firewall for AI agents

I built ClawMoat because local AI agents are getting real permissions faster than they’re getting real security.

If you run Claude Code, OpenClaw, Cursor agents, MCP servers, or custom agent loops on your machine, the agent can often read files, run shell commands, access credentials, and make network calls. Prompt injection is only part of the problem. The bigger problem is runtime containment.

ClawMoat scans inbound text, outbound text, MCP configs, tool calls, secrets, PII, dangerous shell commands, supply-chain payloads, and exfiltration patterns. The goal is not to make the model “safe”. The goal is to control what the agent can touch.

It’s MIT licensed, zero-dependency Node.js, and runs locally.

Install:

```bash
npm install -g clawmoat
clawmoat scan-mcp
clawmoat watch ~/.openclaw/agents/main
```

I’d especially like feedback from people running local agents with real file/shell access. What boundary would you want enforced before trusting an agent on your laptop?

Repo: https://github.com/darfaz/clawmoat
Site: https://clawmoat.com

## Revenue math

The first sales target should not be enterprise. It should be:

- 10 Developer subscribers at $15/mo = $150 MRR and validates checkout.
- 5 Team subscribers at $49/mo = $245 MRR.
- 3 setup/service sales at $249-$999 = immediate cash and case studies.
- 2 consultant affiliates = distribution leverage.

The fastest path to revenue is a hybrid: open-source product for credibility, paid setup/security reviews for cash, Team subscriptions for recurring revenue.

## My recommendation

Do not spend the next week adding features.

Spend it converting existing product into trust:

1. Publish npm v1.0.0.
2. Clean npm package contents.
3. Push one attack demo hard.
4. Run 100 targeted outbound messages.
5. Turn every response into either a report, badge PR, or paid setup call.

The hard truth: ClawMoat is currently more built than sold. That is fixable, but only if we stop treating content as the sales motion. Content supports sales. Direct outreach creates sales.
