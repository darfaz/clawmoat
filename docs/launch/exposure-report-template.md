# ClawMoat exposure report template

Use this before contacting a project. The point is to be useful, not promotional.

## Project

- Repo:
- Segment:
- Date:
- Reviewer:
- Contact channel:
- Status: draft / sent / declined / accepted

## Why this project is relevant

One paragraph. Tie the project to a concrete agent boundary: filesystem, shell, browser, network, MCP, auth, memory, secrets, outbound data, or package execution.

## What I scanned

- Files/configs:
- Commands run:
- ClawMoat version:
- Limits of scan:

## Findings

| Severity | Surface | Evidence | Why it matters | Suggested fix |
|---|---|---|---|---|
| info/low/medium/high/critical | | | | |

## Boundary questions for maintainers

1. What can the agent read by default?
2. What can it execute by default?
3. What outbound network calls are allowed?
4. Where are secrets/session tokens reachable?
5. Is there a denylist/allowlist or human approval step?

## Suggested ClawMoat next step

- Free exposure scan
- Security checklist PR
- Example policy
- Badge/report only if the project wants it

## Outreach draft

Short, specific, and evidence-backed. Do not say “try my tool.” Say what was scanned and what was found.
