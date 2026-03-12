# @openclaw/plugin-clawmoat

OpenClaw sanitizer plugin wrapping [ClawMoat](https://github.com/darfaz/clawmoat)'s
prompt injection detection, secret scanning, and PII detection.

## What it does

Runs ClawMoat's `scan()` function as a **pre-phase** sanitizer plugin.
Every piece of untrusted content (transcript or MCP result) passes through
ClawMoat's pattern matching and entropy analysis before reaching the
semantic sub-agent.

- Sub-millisecond execution — pure regex/entropy, no model calls, no network
- 30+ credential patterns, OWASP Agentic AI coverage
- Deterministic results (confidence always 1.0)
- Complements OpenClaw's built-in Tier 1 patterns with ClawMoat's own library

## Install

```bash
cd plugins/clawmoat-adapter
npm install
npm run build
```

This produces `dist/index.js` — a single-file CJS bundle with ClawMoat inlined.

## Configure

In your OpenClaw config:

```yaml
memory.sessions.sanitization.plugins:
  - module: "./plugins/clawmoat-adapter/dist/index.js"
    phase: "pre"
    config:
      # ClawMoat policy config (passed through to createPolicy)
      policy:
        secretPatterns: ["AWS_*", "GITHUB_TOKEN"]
        blockedCommands: ["rm -rf", "curl * | sh"]
      # Block threshold — which severity level triggers a block?
      # Default: "low" (any finding blocks)
      # Options: "low" | "medium" | "high" | "critical"
      blockThreshold: "low"
```

## Block threshold

By default, any ClawMoat finding (even `low` severity) produces a block.
This is the safest setting. If you're seeing false positives on low-severity
findings, you can raise the threshold:

| `blockThreshold` | Blocks on | Flags (but passes) |
| --- | --- | --- |
| `"low"` (default) | low, medium, high, critical | — |
| `"medium"` | medium, high, critical | low |
| `"high"` | high, critical | low, medium |
| `"critical"` | critical only | low, medium, high |

Findings below the threshold still appear in the audit trail as flags and
contribute to frequency scoring. They're not ignored — they just don't
independently trigger a block.

## How it maps to OpenClaw

| ClawMoat concept | OpenClaw mapping |
| --- | --- |
| `result.blocked` | `PluginResult.safe` (inverted) |
| `result.threats[].pattern` | `PluginResult.ruleIds` (prefixed with `clawmoat.scanner.`) |
| `result.threats[].match` | `PluginResult.flags` |
| `result.threats[].severity` | Used for block threshold decision |
| `createPolicy()` config | Passed through from plugin `config.policy` |

## Overlap with built-in Tier 1

ClawMoat's injection and credential patterns overlap with OpenClaw's
built-in Tier 1 pre-filter (INJ-*, CRED-*). This is intentional —
defense in depth. ClawMoat maintains its own pattern library which may
catch things the built-in set misses, and vice versa. Duplicate findings
are deduplicated by ruleId in the final merge.

## Development

```bash
npm run typecheck    # Type check without emitting
npm run build        # Bundle to dist/index.js
```

The build uses esbuild to produce a single CJS file with clawmoat inlined,
following the plugin spec's recommended bundling approach.
