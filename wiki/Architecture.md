# Architecture

ClawMoat uses a **3-layer detection pipeline** to catch threats with increasing sophistication. Each layer acts as a progressively finer filter — fast pattern matching catches the obvious attacks, ML classification catches the subtle ones, and the LLM judge handles edge cases.

## Pipeline Overview

```
                    ┌──────────────────────────────────────────┐
                    │              ClawMoat                     │
                    │                                          │
  User Input ──────▶  ┌──────────┐  ┌──────────┐  ┌────────┐ │
  Web Content        │ Layer 1  │→│ Layer 2  │→│ Layer 3│ │──▶ AI Agent
  Emails             │ Pattern  │  │ ML       │  │ LLM    │ │
                    │  │ Match    │  │ Classify │  │ Judge  │ │
                    │  └──────────┘  └──────────┘  └────────┘ │
                    │       │              │            │      │
                    │       ▼              ▼            ▼      │
                    │  ┌─────────────────────────────────────┐ │
  Tool Requests ◀───│  │         Policy Engine (YAML)        │ │◀── Tool Calls
                    │  └─────────────────────────────────────┘ │
                    │       │                                  │
                    │       ▼                                  │
                    │  ┌──────────────┐  ┌──────────────────┐ │
                    │  │ Audit Logger │  │ Alerts (webhook,  │ │
                    │  │              │  │ email, Telegram)  │ │
                    │  └──────────────┘  └──────────────────┘ │
                    └──────────────────────────────────────────┘
```

## Layer 1: Pattern Matching (< 1ms)

The first layer uses compiled regular expressions to catch known attack patterns instantly. This includes:

- **Prompt injection signatures** — "ignore previous instructions", "you are now", role manipulation phrases
- **Secret patterns** — API keys (AWS, GitHub, OpenAI, Anthropic, Stripe, etc.), private keys, JWTs
- **Jailbreak markers** — DAN mode, developer mode, dual persona attacks
- **Exfiltration commands** — `curl -d`, `wget --post`, base64 piping, DNS tunneling

**Performance:** Sub-millisecond. Runs on every input with zero overhead.

**Tradeoff:** High precision for known patterns, but misses novel/obfuscated attacks. That's what Layer 2 is for.

## Layer 2: ML Classification (< 50ms)

The second layer applies heuristic scoring and lightweight ML classifiers:

- **Instruction density scoring** — Measures how "instruction-like" text is within a data context (emails, web content). Normal data rarely contains imperative sentences with system-level vocabulary.
- **Entropy analysis** — High-entropy strings in outbound text suggest encoded secrets or exfiltration payloads.
- **Behavioral anomaly detection** — Compares current agent actions against baseline patterns (frequency, targets, timing).

**Performance:** Under 50ms. No external API calls required.

## Layer 3: LLM Judge (200-2000ms)

For ambiguous cases that pass Layers 1-2, an LLM reviews the content in context:

- Is this a legitimate instruction or an injected command?
- Does the context justify this tool call?
- Is the agent behaving consistently with its stated goal?

**Performance:** 200ms-2s depending on model. Only invoked for borderline cases (~5% of inputs).

**Privacy:** The judge prompt contains only the suspicious fragment, not your full conversation.

## Policy Engine

Orthogonal to the detection layers, the **Policy Engine** evaluates every tool call against YAML-defined security policies:

| Tool | Policy Controls |
|------|----------------|
| `exec` | Block patterns, require approval patterns, allowed commands |
| `file` | Deny read/write paths, sensitive file protection |
| `browser` | Domain blocking, URL logging |
| `message` | Outbound content scanning |

Decisions: `allow`, `deny`, `warn`, `review` (requires human approval).

See [Policy Engine](Policy-Engine) for full configuration reference.

## Audit Trail

Every scan result and policy decision is logged to a tamper-evident audit trail:

```json
{
  "timestamp": "2026-02-14T12:00:00.000Z",
  "event": "scan",
  "input_hash": "sha256:abc123...",
  "findings": [...],
  "decision": "block",
  "layer": 1,
  "latency_ms": 0.4
}
```

Audit logs can be reviewed with `clawmoat audit` or exported for compliance.

## Data Flow

1. **Inbound content** (user messages, emails, web pages) → Scanner pipeline
2. **Tool calls** (exec, file, browser) → Policy Engine
3. **Outbound content** (agent responses, emails) → PII + Secret scanning
4. **All events** → Audit Logger + Alert system
