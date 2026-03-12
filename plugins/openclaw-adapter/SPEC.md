# Pluggable Sanitizer Interface

### OpenClaw · Feature Spec · v1.2.1

### Extension of: Input Validation Layers v2.3, Context-Aware Sanitization v2.1, MCP Trust Tier v2

### Companion to: Audit Trail Enhancement v2.2, Audit Alerting v2.3, Tier 1 Pattern Library v1

### Requires companion update: Context-Aware Sanitization v2.2 (plugin profile schema)

---

## Changelog (v1.2 → v1.2.1)

| # | Issue | Resolution |
| - | ----- | ---------- |
| 1 | Malformed-result block policy contradicts clamp/strip policy for out-of-range confidence and bad ruleId prefix | Split validation into recoverable (clamp/strip + warn) and unrecoverable (block). Error handling table updated with explicit categories. |
| 2 | Truth table does not account for frequency tier1+ forcing Stage 2 even when hard block would skip it | Added frequency override row to truth table. Tier1+ always forces Stage 2. Plugin `safe: false` still persists to final merge. |
| 3 | `plugin_config_loaded` emits at startup before any session exists, but spec says plugin events go to per-session audit JSONL | `plugin_config_loaded` writes to agent-level alert log, not session audit. Same pattern as `audit_config_loaded` in audit trail spec. |
| 4 | CJS export contract ambiguous: "default factory function" vs `module.exports` direct assignment | Both forms valid. Loader uses `mod.default \|\| mod` resolution. Documented explicitly. |
| 5 | Path containment `startsWith(configDir)` matches sibling dirs (e.g. `/config2` matches `/config`) | Append `path.sep` to config directory before prefix comparison. |
| 6 | Profile override key model contradicts: wildcard prefixes supported in frequency section but not in companion schema | Three key forms defined as authoritative: plugin id, full ruleId, prefix wildcard (`"id.*"`). Companion schema updated to match. |
| 7 | `pluginErrorSpike` aggregation scope not defined | Scoped to same agent, matching existing alerting patterns. |

| # | Issue | Resolution |
| - | ----- | ---------- |
| 1 | Config shape contradiction: `plugins` defined as both array and parent of `.maxTotal` / `.maxPrePhase` / `.maxPostPhase` nested keys | Moved limits to sibling namespace `memory.sessions.sanitization.pluginLimits.*`. `plugins` is a clean array. |
| 2 | `safe: false` semantics contradictory: two-pass section says non-hard-block plugin fails are "flags that proceed," final merge says "ANY block → block" | Added Pre-Plugin Block Semantics truth table. Plugin `safe: false` always persists to final merge as a block. Stage 2 running is for enrichment, not rescue. |
| 3 | `priorPlugins` typed as `PluginResult[]` but Content Transformation section requires `transformApplied: true` which is not in `PluginResult` | Added `PluginResultMeta` wrapper type for `priorPlugins` that extends `PluginResult` with pipeline-set metadata fields. |
| 4 | Rule taxonomy registration undefined in executable terms: no interface method, conflicts with static taxonomy validation in context profiles | Added `ruleIdPrefix: string` to `SanitizerPlugin` interface. Taxonomy registration uses prefix. Dynamic ruleIds valid if they start with declared prefix. Added taxonomy integration section. |
| 5 | Trust tier interaction conflicts: draft says plugins bypassed for trusted servers, but trust tier spec requires Stage 1 prefilter runs for all results including trusted | Clarified: Stage 1 runs for all results (per trust tier spec), trust routing happens after Stage 1, plugins sit after the trust routing decision. Updated architecture diagram. |
| 6 | Worker concurrency unspecified: no queuing model, timeout start point, or "permanently failed" scope definition | Defined FIFO request queue per worker, timeout starts at post-to-worker, "permanently failed" scoped to process lifetime. |
| 7 | Transform schema validation under-specified for MCP: no definition of which tool schema/discriminant context to use | Specified: transform validation receives same `query` context (server, tool, params) and tool schema reference as original Stage 1B validation. |
| 8 | Audit event contract incomplete: `plugin_pass`/`plugin_flags` overlap undefined, payload schemas for `plugin_error`/`plugin_transform`/`plugin_config_loaded` not specified | Defined emission rule (flags-present → `plugin_flags` only, not both). Added full payload schemas for all six plugin event types. |
| 9 | Alerting requirement not wired to existing rule model: `plugin_error` described as "alert on occurrence" but existing `write_failed` uses aggregation (`writeFailSpike`) | Defined new `pluginErrorSpike` alert rule with aggregation (default: 3 errors in 5 minutes). Added config keys. |
| 10 | Module format ambiguous: `require/import` without specifying CJS/ESM behavior | Specified: plugins must export CommonJS. Loader uses `require()`. ESM/TS plugins must be transpiled to CJS before deployment. |
| 11 | Path validation not cross-platform: covers `..` and leading `/` but not Windows absolute paths, UNC paths, or `file://` URIs | Replaced enumerated checks with platform-agnostic containment: `path.resolve()` then verify resolved path starts with config directory's resolved path. |
| 12 | Confidence bounds unspecified: no clamping, no behavior for empty findings | Defined: clamp to [0.0, 1.0] with warning log. Empty ruleIds with `safe: true` is clean pass — confidence not scored. |
| 13 | Profile override surface unclear: draft introduces `plugins:` profile block not present in current custom profile schema | Called out as required companion change: context-aware-sanitization-spec v2.2 must add `plugins` map to custom profile schema. Defined the schema extension. |

## Changelog (v1 → v1.1)

| Issue | Resolution |
| ----- | ---------- |
| Timeout enforcement assumed cooperative async; sync loops block the event loop and prevent timeout from firing | Added Runtime Isolation section. Plugin `inspect` calls execute in `worker_threads` with `worker.terminate()` as the kill mechanism. |
| Single `confidence` field per `PluginResult` forces uniform confidence across multiple findings | Added optional `findingConfidence` map keyed by ruleId. Single `confidence` field retained as fallback for all unkeyed rules. |
| `transformed` output typed as `unknown` with no structural validation — could break downstream stages | Transformed output must pass Stage 1B schema validation before being accepted. Rejection produces `plugin_error` with `reason: "transform_schema_fail"`. |
| Transform visibility to subsequent plugins in the same phase was undefined | Clarified: later plugins in the same phase receive transformed content. `priorPlugins` entries include transform metadata. |
| SHA-256 audit hashes for transforms did not specify serialization — `JSON.stringify` key order is non-deterministic | Specified canonical JSON serialization: sorted keys, no whitespace, applied recursively. |
| "No node_modules resolution" prevented plugins from importing their own dependencies | Added Plugin Dependency Strategy section. Plugins must ship as single-file bundles or the loader sets `NODE_PATH` to the plugin's directory. |
| Path validation rejected `..` but not symlinks pointing outside the config directory | Added `fs.realpath()` resolution before traversal validation. |
| Default frequency weight of 3 had no documented rationale relative to built-in weight scale | Added weight scale reference table in Frequency Scoring section. |

---

## Origin

Community feedback on PR #35427 (sanitization hardening) suggested adding a
pluggable sanitizer interface so teams can bring their own inspection rules —
regex patterns, ML classifiers, external scanning tools — without modifying
the core pipeline. This spec formalizes that idea within the existing
architecture.

---

## Summary

Define a plugin interface that allows operator-provided inspection modules to
run alongside the built-in validation pipeline. Plugins slot into declared
phases of the existing Stage 1 → Stage 2 flow. They conform to a standard
contract, produce results in the same shape as built-in stages, and feed into
the same audit trail and alerting infrastructure.

Plugins do NOT replace built-in stages. They augment them. The built-in
syntactic filter, schema validator, and semantic sub-agent always run
(subject to existing config toggles). Plugins add additional inspection on
top.

---

## Design Goals

- **Additive only.** Plugins cannot disable, bypass, or weaken built-in
  stages. They can add inspection, not remove it. A plugin that returns
  `safe: true` does not override a built-in stage that returns `safe: false`.
- **Same contract, same audit trail.** Plugin results conform to the same
  result types as built-in stages. Plugin-triggered rules appear in audit
  events with the same structure as built-in rules. No separate audit path.
- **Fail closed on plugin error.** A plugin that throws, times out, or
  returns malformed output is treated as a block, not a pass. The pipeline
  does not degrade silently when a plugin fails.
- **Static loading only.** Plugins are declared in config and loaded at
  startup. No runtime plugin installation, no hot-loading, no remote
  plugin fetching. Same static guarantee as context profiles: resolved at
  config load time, frozen for agent lifetime, never modified by user input.
- **Composable with context profiles.** Profiles can enable, disable, or
  weight-adjust specific plugins per-rule. A plugin that is useful in
  `code-generation` context may be noise in `research` context.
- **Bounded execution.** Plugins run under a configurable timeout. A plugin
  that exceeds its timeout is killed and treated as a block. The pipeline
  never waits indefinitely for a plugin.

---

## Runtime Isolation

Plugin `inspect` calls execute inside Node.js `worker_threads`, not on the
main event loop. This is the mechanism that makes timeout enforcement
reliable — without it, a plugin containing a synchronous tight loop would
block the event loop and prevent `setTimeout` from ever firing.

**How it works:**

- At startup, the plugin loader spawns one `Worker` per loaded plugin.
  The worker imports the plugin module and holds the initialized plugin
  instance.
- On each `inspect` call, the main thread posts a message to the worker
  with the serialized `PluginInput`. The worker runs `inspect` and posts
  back the `PluginResult`.
- The main thread sets a timer for `timeoutMs`. If the worker does not
  respond before the timer fires, the main thread calls
  `worker.terminate()`, which kills the worker thread regardless of
  whether it is blocked in sync code. A `plugin_error` event is emitted
  with `reason: "timeout"`.
- After a termination, the loader respawns the worker and re-initializes
  the plugin. If re-initialization fails, the plugin is marked as
  permanently failed for the remainder of the **process lifetime** (not
  session — a process restart clears the failure state). All subsequent
  inspect calls for that plugin produce `plugin_error` with
  `reason: "worker_init_failed"` and are treated as blocks.

### Request Queuing

Each worker processes one `inspect` call at a time. If a second request
arrives while the worker is busy (possible on high-throughput MCP paths),
it enters a FIFO queue on the main thread. The `timeoutMs` timer starts
when the message is **posted to the worker**, not when it enters the queue.
This means queue wait time does not consume the plugin's timeout budget —
the plugin gets its full configured time once the worker picks it up.

If the queue depth exceeds a configurable limit (`maxQueueDepth`, default
10), additional requests are rejected immediately with `plugin_error`
`reason: "queue_full"` and treated as blocks. This prevents unbounded
memory growth from a stalled plugin.

**Serialization cost:** `PluginInput` and `PluginResult` cross the
`worker_threads` structured clone boundary. This adds serialization
overhead proportional to the size of `content.raw`. For typical payloads
(< 100KB), this is sub-millisecond. For unusually large payloads, the
Tier 1 structural size check (STRUCT-002, max 512KB default) bounds the
upper end.

**Initialize and shutdown** run on the worker thread, not the main thread.
The main thread communicates lifecycle events via message passing. This
means a plugin that does heavy synchronous work in `initialize` does not
block the main event loop during startup.

**Why not child_process?** `worker_threads` share memory for
`SharedArrayBuffer` if needed in future, have lower spawn overhead, and
are sufficient for the isolation requirement (timeout enforcement). Full
process isolation (filesystem, network) is out of scope for v1 and
listed under Out of Scope as plugin sandboxing.

---

## Architecture

```
Input arrives (transcript or MCP result)
        ↓
Stage 1: Built-in Pre-Filter (unchanged, runs for ALL inputs including trusted MCP)
  ┌──────────────────────┬────────────────────────────┐
  │ Stage 1A: Syntactic  │ Stage 1B: Schema           │
  └──────────┬───────────┴──────────┬─────────────────┘
             └────── merge ────────┘
                      ↓
  Stage 1 audit events emitted (per trust tier spec — always, even for trusted)
                      ↓
  Terminated-session check (per trust tier spec — always, trusted do not exempt)
                      ↓
  Trust tier routing decision:
    ├── TRUSTED → trusted_pass audit entry → result to manager (skip all below)
    └── UNTRUSTED → continue ↓
                      ↓
Stage 1P: Plugin Pre-Filters (new — untrusted + transcript only)
  Runs plugins declared with phase: "pre"
  Sequential execution in declared order
  Each plugin receives: raw content + Stage 1 results (flags, ruleIds)
                      ↓
  Frequency scoring (built-in + plugin flags combined)
                      ↓
  Two-pass gating (unchanged logic, but plugin flags contribute to score)
                      ↓
Stage 2: Semantic Sub-Agent (unchanged)
  Sub-agent receives plugin flags as additional hints alongside
  syntactic flags (same injection mechanism as existing flag passthrough)
                      ↓
Stage 2P: Plugin Post-Filters (new — untrusted + transcript only)
  Runs plugins declared with phase: "post"
  Sequential execution in declared order
  Each plugin receives: raw content + Stage 1 results + Stage 2 output
                      ↓
  Final merge: built-in result ∪ ALL plugin results (pre + post)
  ANY safe: false from any source → block
  Flags aggregated, deduplicated by ruleId
                      ↓
  Audit events emitted (built-in + plugin events in unified stream)
```

### Why two plugin phases?

**Pre-plugins (Stage 1P)** run before the semantic sub-agent. They're for
fast, deterministic checks — regex libraries, pattern databases, format
validators. Their flags feed into frequency scoring and inform the sub-agent
via hint injection. If a pre-plugin blocks and its rule is in
`hardBlockRules`, the two-pass optimization can skip the sub-agent call
entirely (same logic as existing hard blocks).

**Post-plugins (Stage 2P)** run after the semantic sub-agent. They're for
checks that benefit from the sub-agent's structured output — ML classifiers
that analyze the sanitized result, external scanning tools that need the
final structured content, compliance validators that check what the sub-agent
decided to pass through.

A plugin declares exactly one phase. If an operator needs both pre and post
inspection from the same system, they register two plugins.

### Pre-Plugin Block Semantics

A pre-plugin returning `safe: false` has two effects that operate at
different points in the pipeline. This truth table is the single source of
truth:

| Pre-plugin `safe` | ruleId in `hardBlockRules`? | Session at frequency tier1+? | Stage 2 runs? | Plugin `safe: false` persists to final merge? | Final outcome |
| --- | --- | --- | --- | --- | --- |
| `true` | n/a | n/a | yes | no | depends on Stage 2 + post-plugins |
| `false` | yes | no | **no** (two-pass skip) | yes | **block** |
| `false` | yes | **yes** | **yes** (frequency override) | yes | **block** |
| `false` | no | n/a | **yes** (flags injected as hints) | yes | **block** |

The third row is the frequency override case. The input validation spec
requires that frequency tier1+ forces the semantic pass to run even when
two-pass gating would otherwise skip it. This takes precedence over the
hard block skip. The rationale is that sustained suspicious activity
warrants full semantic analysis for audit enrichment, even when the
content is already definitively blocked.

The fourth row is the soft-block case. When a pre-plugin returns
`safe: false` but its rule is not in `hardBlockRules`:

- Stage 2 **runs** — the two-pass optimization does not skip it, because
  the rule is not a hard block. The plugin's flags are injected into the
  sub-agent prompt as additional scrutiny hints.
- The plugin's `safe: false` **persists** to the final merge. Stage 2
  running is for audit enrichment and additional detection. It does not
  "rescue" a plugin block. The final merge sees the plugin's `safe: false`
  and the outcome is block.

**Post-plugin blocks** are simpler: any post-plugin returning `safe: false`
adds a block to the final merge. Two-pass gating is not involved (it runs
before Stage 2, post-plugins run after).

---

## Plugin Interface

```typescript
/**
 * The contract every plugin must implement.
 * Plugins are CommonJS modules that export a factory function
 * returning an object conforming to this interface.
 *
 * Module format: CommonJS. Both export forms are valid:
 *   - module.exports = createPlugin        (direct assignment)
 *   - exports.default = createPlugin       (default export — typical of transpiled TS)
 * The loader resolves via: const factory = mod.default || mod
 * This is the standard CJS interop pattern used by bundlers.
 */
interface SanitizerPlugin {
  /** Unique identifier. Must not collide with built-in rule prefixes
   *  (INJ-, CRED-, STRUCT-, TYPE-, ENC-, TEMPORAL-, schema.*, injection.*,
   *  credential.*, scope-creep.*). Recommended format: "org.pluginname"
   *  e.g. "acme.hipaa-redactor", "clawmoat.scanner" */
  id: string;

  /** Human-readable name for audit and logging */
  name: string;

  /** Which pipeline phase this plugin runs in */
  phase: "pre" | "post";

  /** Rule ID prefix for all rules this plugin produces.
   *  Must equal id — e.g. if id is "acme.hipaa-redactor", then
   *  ruleIdPrefix is "acme.hipaa-redactor" and all ruleIds in
   *  PluginResult must start with "acme.hipaa-redactor.".
   *  Validated at startup: collision with built-in prefixes → failure.
   *  The prefix is registered in the rule taxonomy and used for
   *  frequency weight lookups and profile override matching. */
  ruleIdPrefix: string;

  /** Called once at startup with the plugin's config block.
   *  Throw here to prevent startup (fail-closed on bad config).
   *  Async to allow one-time setup (loading models, compiling patterns). */
  initialize(config: Record<string, unknown>): Promise<void>;

  /** Called once on shutdown. Cleanup resources. Best-effort —
   *  errors in shutdown are logged but do not prevent process exit. */
  shutdown(): Promise<void>;

  /** The inspection function. Called once per content unit.
   *  Must resolve within the configured timeout or be killed. */
  inspect(input: PluginInput): Promise<PluginResult>;
}

interface PluginInput {
  /** The content being inspected */
  content: {
    /** "transcript" or "mcp" */
    source: "transcript" | "mcp";
    /** Raw content object (same shape the built-in stages receive).
     *  If a prior plugin in the same phase applied a transform,
     *  this is the transformed content, not the original. */
    raw: unknown;
    /** For MCP: the tool call that produced this result.
     *  Always present when source is "mcp", always absent for "transcript". */
    query?: { server: string; tool: string; params: unknown };
  };

  /** Results from prior stages (available context depends on phase) */
  priorResults: {
    /** Stage 1A syntactic result (always available) */
    syntactic: { pass: boolean; flags: string[]; ruleIds: string[] };
    /** Stage 1B schema result (always available) */
    schema: { pass: boolean; violations: string[]; ruleIds: string[] };
    /** Stage 2 semantic result (only available for post-phase plugins).
     *  Undefined for pre-phase plugins — do not check, will not be set. */
    semantic?: { safe: boolean; flags: string[]; structuredResult: unknown };
    /** Results from prior plugins in the same phase (sequential ordering).
     *  Empty array for the first plugin in a phase. */
    priorPlugins: PluginResultMeta[];
  };

  /** Active context profile id */
  contextProfile: string;
}

/**
 * What the plugin returns from inspect().
 */
interface PluginResult {
  /** Plugin id (must match the plugin's declared id) */
  pluginId: string;

  /** Did the plugin find the content acceptable? */
  safe: boolean;

  /** Rule IDs for any findings. Every entry must start with the
   *  plugin's declared ruleIdPrefix followed by ".".
   *  e.g. "acme.hipaa-redactor.ssn-detected"
   *  Empty array is valid (no findings). */
  ruleIds: string[];

  /** Human-readable descriptions of findings */
  flags: string[];

  /** Default confidence for all findings. Used for frequency weight
   *  calculation: effectiveWeight = weight × confidence.
   *  Range: [0.0, 1.0]. Values outside this range are clamped with
   *  a warning log — this is a recoverable validation error, not a
   *  block. The plugin's results are still applied with the clamped value.
   *  Built-in stages implicitly have confidence 1.0.
   *  Applies to all ruleIds unless overridden in findingConfidence.
   *  When ruleIds is empty and safe is true (clean pass), confidence
   *  is not factored into frequency scoring. */
  confidence: number;

  /** Optional per-finding confidence, keyed by ruleId.
   *  When present, the value for a given ruleId overrides the default
   *  confidence for frequency scoring purposes. Same [0.0, 1.0] range
   *  and clamping rules apply per entry.
   *  Use case: A plugin that runs multiple detection strategies in one
   *  inspect call — regex matches may be confidence 1.0 while an ML
   *  classifier hit may be 0.6.
   *  Example: { "acme.scanner.regex-match": 1.0, "acme.scanner.ml-flag": 0.6 }
   *  Keys must be a subset of the ruleIds array. Keys not in ruleIds
   *  are ignored. */
  findingConfidence?: Record<string, number>;

  /** Optional: transformed content. Only meaningful for pre-phase plugins.
   *  If provided, downstream stages receive this instead of the raw input.
   *  Must pass Stage 1B schema validation with the same context (source type,
   *  tool schema/discriminant for MCP) as the original content. If validation
   *  fails, the transform is rejected (plugin_error, reason:
   *  "transform_schema_fail") and the pipeline continues with the original.
   *  Use with extreme caution — transforms can mask content from the
   *  semantic sub-agent. See Content Transformation section. */
  transformed?: unknown;
}

/**
 * Extended result type used in priorPlugins array. The pipeline sets
 * metadata fields after receiving PluginResult from the worker.
 * Plugins return PluginResult; the pipeline wraps it as PluginResultMeta
 * before passing to subsequent plugins.
 */
interface PluginResultMeta extends PluginResult {
  /** True if this plugin's transform was applied to content.raw.
   *  Only set when the plugin returned a transformed field AND the
   *  transform passed schema validation AND allowTransform was true.
   *  False or absent otherwise. */
  transformApplied?: boolean;

  /** True if the plugin timed out, threw, or returned malformed output.
   *  When true, safe/ruleIds/flags/confidence reflect the error-as-block
   *  state, not the plugin's actual judgment. */
  errored?: boolean;
}
```

### Rule Taxonomy Integration

Plugins declare their `ruleIdPrefix` as a static field on the interface.
At startup, the loader:

1. Validates that `ruleIdPrefix` equals `id` (enforced convention).
2. Validates no collision with built-in prefixes (INJ-, CRED-, STRUCT-,
   TYPE-, ENC-, TEMPORAL-, schema.*, injection.*, credential.*,
   scope-creep.*) or other loaded plugins.
3. Registers the prefix in the rule taxonomy as a dynamic namespace.

At inspect time, every ruleId in `PluginResult.ruleIds` is validated to
start with `ruleIdPrefix + "."`. A ruleId that violates the prefix is
stripped from the result with a warning log (not a block — the plugin's
other findings are preserved).

**Interaction with profile frequency weight overrides:** Profile config
references plugin rules by full ruleId (e.g. `"acme.hipaa-redactor.ssn-detected": 15`)
or by prefix with wildcard (e.g. `"acme.hipaa-redactor.*": 10`). The
wildcard form applies to all rules under the prefix. Explicit ruleId
overrides take precedence over wildcards. This is the same pattern used
for built-in rules in the context-aware sanitization spec.

**Interaction with static taxonomy validation in context profiles:** The
existing context profile schema validates that frequency weight keys exist
in the rule taxonomy. Plugin prefixes are registered dynamically at startup,
before profile validation runs. If a profile references a plugin rule that
isn't loaded (plugin disabled or removed), the weight entry is ignored with
a warning log — not a startup failure. This prevents a profile from becoming
invalid when a plugin is removed.

### Factory Pattern

Plugins are CommonJS modules that export a default factory function:

```typescript
// Example: plugins/hipaa-redactor/index.ts (transpile to CJS before deploy)
import type { SanitizerPlugin } from "@openclaw/sanitizer-plugin";

export default function createPlugin(): SanitizerPlugin {
  return {
    id: "acme.hipaa-redactor",
    name: "ACME HIPAA Redactor",
    phase: "pre",
    ruleIdPrefix: "acme.hipaa-redactor",

    async initialize(config) {
      // Load pattern database, warm up, validate config
    },

    async shutdown() {
      // Release resources
    },

    async inspect(input) {
      // Inspection logic
      return {
        pluginId: "acme.hipaa-redactor",
        safe: true,
        ruleIds: [],
        flags: [],
        confidence: 1.0,
      };
    },
  };
}
```

---

## Content Transformation

Pre-phase plugins may optionally return a `transformed` field containing a
modified version of the input content. If present, downstream stages
(including the semantic sub-agent) receive the transformed content instead
of the original.

**Use case:** A PII redactor that replaces SSNs with `[REDACTED-SSN]` before
the content reaches the sub-agent. The sub-agent then evaluates the redacted
version, never seeing the raw PII.

### Transform Validation

Transformed output must pass Stage 1B schema validation before being
accepted. This prevents a plugin (buggy or malicious) from producing output
that breaks downstream stages — e.g., returning a string where an object was
expected, or dropping required fields.

The validation uses the same context as the original Stage 1B pass:

- **For transcript content:** Same transcript schema, same strictness level
  from the active context profile.
- **For MCP content:** Same tool schema and discriminant context derived from
  `content.query` (server, tool, params). The tool's declared output schema
  is the validation target. Same strictness level from the active profile.

If the transformed output fails schema validation:

- The transform is rejected.
- A `plugin_error` event is emitted with `reason: "transform_schema_fail"`.
- The pipeline continues with the original (pre-transform) content.
- The plugin's other results (safe, ruleIds, flags) are still applied —
  only the transform is discarded.

This validation runs synchronously on the main thread after the worker
returns the result.

### Transform Visibility Within a Phase

When a pre-plugin with `allowTransform: true` returns a valid transform:

- **Later plugins in the same phase** receive the transformed content in
  `content.raw`. They inspect what downstream stages will actually see.
- **The `priorPlugins` array** for later plugins includes the transforming
  plugin's result as a `PluginResultMeta` with `transformApplied: true`.
- **Stage 2 (semantic sub-agent)** receives the transformed content.
- **Post-phase plugins** receive the transformed content in `content.raw`.

The original (pre-transform) content is always preserved in the raw mirror
sidecar. If an operator needs to audit what the original looked like,
it is available in the raw sidecar file regardless of transforms.

### Audit Hashing

When a transform is applied, the `plugin_transform` audit entry includes
SHA-256 hashes of both the pre-transform and post-transform content. To
ensure deterministic hashing regardless of JSON key ordering, content is
serialized using **canonical JSON**: keys sorted recursively in
lexicographic order, no whitespace.

Implementation: Apply recursive key sorting before `JSON.stringify` with no
indentation. This is equivalent to:

```typescript
function canonicalize(obj: unknown): string {
  return JSON.stringify(obj, (_, v) =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b)))
      : v
  );
}
```

The same canonicalization is used for the audit trail spec's `output_diff`
sha256 fields. If the audit trail spec does not currently specify
canonicalization, this should be back-ported as a consistency fix.

### Risks

- A transform can hide content from the semantic sub-agent, reducing its
  ability to detect threats that were present in the original.
- A malicious or buggy plugin transform could inject content into the
  pipeline.
- Transforms are not composable in a predictable way — two plugins both
  transforming the same content can produce unexpected results.

### Mitigations

- Transforms are opt-in per plugin via config (`allowTransform: true`).
  Default is `false` — even if a plugin returns `transformed`, it is
  ignored unless the operator explicitly enables it.
- Transformed output must pass Stage 1B schema validation with the same
  context as the original content. Invalid transforms are rejected without
  blocking the pipeline.
- When a transform is applied, the audit entry includes both the pre-
  and post-transform content hashes (canonical JSON SHA-256), same
  format as the audit trail spec's `output_diff`.
- Only one plugin per phase may have `allowTransform: true`. If multiple
  plugins in the same phase declare transforms, startup fails with an
  explicit error. This eliminates the composition problem.
- The raw (pre-transform) content is always written to the raw mirror
  sidecar regardless of transforms.

---

## Interaction with Trust Tiers

Plugins sit **after** the trust tier routing decision in the pipeline.
The trust tier spec requires that Stage 1 (syntactic + schema prefilter)
runs for all results including trusted, with audit events emitted. The
trust routing decision (trusted fast path vs full inspection) happens after
Stage 1. Plugins are part of the full inspection path and never run for
trusted results.

- **Trusted MCP servers:** Stage 1 runs and audits. Trust check passes.
  `trusted_pass` audit entry. Result passed directly to manager. No
  plugin inspection.
- **Untrusted MCP servers:** Stage 1 runs and audits. Trust check fails.
  Full pipeline including plugins.
- **Transcript content:** No trust tier applies. Full pipeline including
  plugins.

If an operator wants a plugin to run even on trusted server results (e.g.,
a compliance logger that must see everything), they should not use the trust
tier bypass for that server. The trust tier list is the single toggle — there
is no per-plugin override of trust tier routing.

---

## Interaction with Context Profiles

Context profiles can modulate plugin behavior through a new `plugins` map
in the custom profile schema. **This requires a companion update to the
context-aware-sanitization spec (v2.2)** — see Required Companion Changes.

```yaml
# In a custom context profile:
plugins:
  "acme.hipaa-redactor":
    enabled: true
    frequencyWeight: 15          # Override all rules under this plugin
  "acme.hipaa-redactor.ssn-detected":
    frequencyWeight: 20          # Override a specific rule (takes precedence)
  "clawmoat.scanner":
    enabled: false               # Not useful in this deployment context
```

**Rules:**

- `enabled: false` in a profile skips the plugin for sessions using that
  profile. The plugin is still loaded at startup and initialized — it is
  just not invoked. This allows fast profile switching on restart without
  re-initializing plugins.
- `frequencyWeight` overrides the plugin's default frequency weight for
  the active profile. Can be set at the plugin level (applies to all rules
  under the prefix) or at the individual ruleId level. Individual ruleId
  overrides take precedence over plugin-level overrides.
- Profile-level plugin config does not change the plugin's phase, timeout,
  or transform permissions. Those are global and set at the top level.

**Precedence:** If a profile disables a plugin, it does not run. There is no
mechanism for a plugin to force itself to run regardless of profile. Operator
config always wins.

---

## Interaction with Frequency Scoring

Plugin findings contribute to the session's frequency score through the
existing exponential decay mechanism:

- Each plugin rule ID (`pluginId.ruleName`) is a scorable event, same as
  built-in rule IDs.
- Default frequency weight for plugin rules is `3` (moderate). Operators
  can override per-rule in global config or per-profile.
- Plugin `confidence` is multiplied against the frequency weight:
  `effectiveWeight = weight × confidence`. A plugin that reports
  `confidence: 0.6` contributes 60% of its configured weight to the
  session score. This prevents low-confidence ML classifier hits from
  rapidly escalating sessions.
- When `findingConfidence` is present, each ruleId uses its specific
  confidence value instead of the default. Unkeyed ruleIds fall back to
  the default `confidence` field. This allows a single inspect call to
  contribute different weights for different finding types.
- **Clamping:** Confidence values below 0.0 are clamped to 0.0. Values
  above 1.0 are clamped to 1.0. A warning log is emitted when clamping
  occurs (likely a plugin bug). Same clamping applies to `findingConfidence`
  entries.
- **Clean passes:** When `ruleIds` is empty and `safe` is `true`, the
  result is a clean pass. Confidence is not factored into frequency scoring
  — there are no findings to score.

### Built-In Frequency Weight Scale (Reference)

For context on what the default plugin weight of `3` means relative to the
existing system:

| Weight | Examples | Interpretation |
| ------ | -------- | -------------- |
| 1 | `structural.encoding-trick` in `code-generation` profile | Very low — expected noise in context, barely registers |
| 3 | **Plugin default** | Moderate — noticeable if repeated, benign in isolation |
| 4 | `schema.undeclared-admin-reject` | Elevated — structurally suspicious |
| 5 | Most built-in defaults (e.g. `structural.*`, `schema.*`) | Standard built-in weight |
| 10–12 | `credential.*` in `code-generation` profile | High — credentials in unexpected context |
| 15 | `credential.*` in `customer-service` profile | Very high — credentials in support context are almost certainly a problem |

The default of `3` is deliberately below the standard built-in weight of `5`.
Plugin findings are additive signals — they should contribute to the session
score without rapidly dominating it. Operators running high-confidence plugins
(deterministic regex, known-good external scanners) should raise the weight.
Operators running experimental or noisy plugins should leave it low or reduce
it further.

---

## Interaction with Two-Pass Gating

- A pre-plugin that returns `safe: false` is treated identically to a
  built-in Stage 1 failure for two-pass gating purposes.
- If the failing plugin rule ID is in `twoPass.hardBlockRules`, the
  semantic sub-agent is skipped (same as built-in hard blocks) — **unless**
  the session is at frequency tier1 or above, in which case Stage 2 is
  forced to run regardless (per the input validation spec). See the
  Pre-Plugin Block Semantics truth table for the complete matrix.
- If the failing plugin rule ID is NOT in `hardBlockRules`, the result
  proceeds to the semantic pass with the plugin's flags injected as hints.
  The plugin's `safe: false` persists to the final merge regardless of
  Stage 2's outcome. See Pre-Plugin Block Semantics truth table.
- Plugin ruleIds are eligible for inclusion in `hardBlockRules`. Operators
  add them using the full ruleId (e.g. `"acme.scanner.critical-threat"`).
  Prefix wildcards are not supported in `hardBlockRules` — each rule must
  be listed explicitly (same as built-in rules).
- Post-plugins are not relevant to two-pass gating (they run after
  Stage 2).

---

## Interaction with Audit Trail

Plugin events are emitted into the same per-session audit JSONL as built-in
events.

### Event Types and Emission Rules

| Event                | Verbosity | Emitted when |
| -------------------- | --------- | ------------ |
| `plugin_block`       | `minimal` | Plugin returned `safe: false` |
| `plugin_pass`        | `standard`| Plugin returned `safe: true` with empty `flags` |
| `plugin_flags`       | `standard`| Plugin returned `safe: true` with non-empty `flags` |
| `plugin_error`       | `minimal` | Plugin threw, timed out, returned malformed output, or transform failed schema |
| `plugin_transform`   | `high`    | Plugin transform was applied (passed schema validation) |
| `plugin_config_loaded`| `minimal`| Plugin config resolved at startup (agent-level log, not session) |

**Emission rule for pass vs flags:** If a plugin returns `safe: true` with
non-empty `flags`, emit `plugin_flags` only — not both `plugin_flags` and
`plugin_pass`. This follows the same pattern as `syntactic_flags` vs
`syntactic_pass` in the audit trail spec. `plugin_pass` is only emitted
for clean passes with no findings.

**Destination note:** All per-turn plugin events (`plugin_block`,
`plugin_pass`, `plugin_flags`, `plugin_error`, `plugin_transform`) write
to the per-session audit JSONL at the standard path
(`~/.openclaw/agents/<agentId>/session-memory/audit/<sessionId>.jsonl`).
`plugin_config_loaded` is the exception — it fires at startup before any
session exists. It writes to the agent-level alert log at
`~/.openclaw/agents/<agentId>/alerts/alerts.jsonl`, same pattern as
`audit_config_loaded` in the audit trail spec.

### Event Payload Schemas

**`plugin_block`**

```jsonl
{
  "event": "plugin_block",
  "pluginId": "clawmoat.scanner",
  "ruleIds": ["clawmoat.scanner.threat-detected"],
  "flags": ["Real-time threat signature matched: CVE-2026-1234"],
  "confidence": 0.95,
  "findingConfidence": { "clawmoat.scanner.threat-detected": 0.95 },
  "phase": "post",
  "timestamp": "2026-03-07T14:22:00.000Z",
  "sessionId": "sess-abc",
  "agentId": "agent-xyz",
  "messageId": "msg-123"
}
```

**`plugin_pass`**

```jsonl
{
  "event": "plugin_pass",
  "pluginId": "acme.hipaa-redactor",
  "confidence": 1.0,
  "phase": "pre",
  "timestamp": "...",
  "sessionId": "...",
  "agentId": "...",
  "messageId": "..."
}
```

**`plugin_flags`**

```jsonl
{
  "event": "plugin_flags",
  "pluginId": "acme.hipaa-redactor",
  "ruleIds": ["acme.hipaa-redactor.ssn-detected"],
  "flags": ["1 SSN pattern(s) detected"],
  "confidence": 1.0,
  "findingConfidence": { "acme.hipaa-redactor.ssn-detected": 1.0 },
  "phase": "pre",
  "timestamp": "...",
  "sessionId": "...",
  "agentId": "...",
  "messageId": "..."
}
```

**`plugin_error`**

```jsonl
{
  "event": "plugin_error",
  "pluginId": "clawmoat.scanner",
  "reason": "timeout" | "invalid_result" | "exception" | "transform_schema_fail" | "worker_init_failed" | "queue_full",
  "detail": "Worker did not respond within 3000ms",
  "phase": "post",
  "timestamp": "...",
  "sessionId": "...",
  "agentId": "...",
  "messageId": "..."
}
```

**`plugin_transform`**

```jsonl
{
  "event": "plugin_transform",
  "pluginId": "acme.hipaa-redactor",
  "preTransformHash": "sha256:a1b2c3...",
  "postTransformHash": "sha256:d4e5f6...",
  "hashMethod": "sha256-canonical-json",
  "phase": "pre",
  "timestamp": "...",
  "sessionId": "...",
  "agentId": "...",
  "messageId": "..."
}
```

**`plugin_config_loaded`**

```jsonl
{
  "event": "plugin_config_loaded",
  "pluginId": "acme.hipaa-redactor",
  "name": "ACME HIPAA PII Redactor",
  "phase": "pre",
  "ruleIdPrefix": "acme.hipaa-redactor",
  "timeoutMs": 1000,
  "allowTransform": true,
  "frequencyWeight": 10,
  "enabled": true,
  "timestamp": "...",
  "agentId": "..."
}
```

### Rule Taxonomy

Plugin rule IDs are registered in the rule taxonomy at startup via the
`ruleIdPrefix` mechanism described in Rule Taxonomy Integration. At runtime,
specific ruleIds (e.g. `"acme.hipaa-redactor.ssn-detected"`) are validated
against the prefix and appear in `rule_triggered` events at `high` verbosity,
same as built-in rules.

Unknown plugin rule IDs (those not starting with any registered prefix)
are stripped from results with a warning log — same treatment as unknown
built-in rule IDs.

---

## Interaction with Alerting

Plugin events are consumable by the alerting layer through the same event
stream. The existing rules (burst detection, frequency escalation, etc.)
naturally cover plugin-generated events because plugin flags contribute
to frequency scoring.

### New Alert Rule: `pluginErrorSpike`

Plugin errors use aggregation-based alerting, consistent with the
existing `writeFailSpike` pattern. A single `plugin_error` may be a
transient issue (network blip for an external scanner, one-off timeout).
Sustained errors indicate an operational problem.

```
Rule: pluginErrorSpike
Trigger: >= N plugin_error events within M minutes, scoped to the same agent
  (matching existing alerting aggregation scope — see audit-alerting-spec)
Default: N = 3, M = 5
Severity: medium
Payload: includes pluginId, reason breakdown, and recentContext
Configurable: alerting.rules.pluginErrorSpike.count (default: 3)
              alerting.rules.pluginErrorSpike.windowMinutes (default: 5)
              alerting.rules.pluginErrorSpike.enabled (default: true)
```

This rule aggregates across all plugins. If operators need per-plugin
alerting granularity, that requires custom alert rule definitions
(deferred — listed under Future Work in the alerting spec).

Operators who want plugin-specific alert rules beyond `pluginErrorSpike`
can define them when the alerting spec adds support for custom rule
definitions (currently out of scope in the alerting spec, listed under
Future Work).

---

## Config Surface

```
memory.sessions.sanitization.plugins: PluginDeclaration[]
  Default: []
  Ordered list of plugin declarations. Execution order within each phase
  follows declaration order.

  Each entry:
    module: string
      Local file path to the plugin module (CommonJS). Relative to the
      OpenClaw config directory. No remote URLs.
      Path validation: resolve to absolute via path.resolve(configDir, module),
      then resolve symlinks via fs.realpath(), then verify the resolved
      absolute path starts with the config directory's resolved absolute path
      plus path.sep. The trailing separator prevents false positives from
      sibling directories (e.g. /app/config2 must not match /app/config).
      This is platform-agnostic and catches all traversal variants including
      "..", leading "/", Windows absolute paths (C:\), UNC paths (\\server),
      file:// URIs, and symlinks pointing outside the boundary.

      **Dependency resolution:** Plugins must ship as either:
      (a) A single-file CommonJS bundle (e.g., built with esbuild, rollup,
          or tsup) with all dependencies inlined. This is the recommended
          approach — it eliminates resolution ambiguity entirely.
      (b) A directory containing a CommonJS entry point and a local
          node_modules. The loader sets NODE_PATH to the plugin's directory
          before require(), allowing the plugin's own dependencies to
          resolve. The plugin's node_modules must be vendored alongside the
          plugin — the loader does not run npm install.

      Option (a) is strongly preferred for distribution. Option (b) is
      acceptable for in-house plugins where bundling is impractical.

    phase: "pre" | "post"
      Which pipeline phase. Must match the plugin's declared phase.
      Mismatch between config and plugin declaration fails at startup.

    enabled: boolean
      Default: true
      Master toggle for this plugin. When false, plugin is not loaded
      or initialized.

    config: Record<string, unknown>
      Default: {}
      Opaque config block passed to the plugin's initialize() method.
      OpenClaw does not interpret this — it's the plugin's responsibility
      to validate.

    timeoutMs: number
      Default: 1000
      Maximum time the plugin's inspect() call may take before being
      killed. Minimum: 100. Maximum: 10000.
      Timer starts when the message is posted to the worker thread,
      not when it enters the queue.
      Killed plugins produce a plugin_error audit event and are treated
      as blocks.

    allowTransform: boolean
      Default: false
      Whether the plugin's transformed output is applied. See Content
      Transformation section.

    frequencyWeight: number
      Default: 3
      Base frequency weight for all rules this plugin produces.
      Can be overridden per-rule in profile frequency weight config.

    maxQueueDepth: number
      Default: 10
      Maximum pending inspect requests queued for this plugin's worker.
      Requests exceeding this limit are rejected immediately with
      plugin_error reason: "queue_full".

memory.sessions.sanitization.pluginLimits:
  maxTotal: number
    Default: 10
    Maximum number of plugins (across both phases). Prevents unbounded
    pipeline growth. Startup fails if exceeded.

  maxPrePhase: number
    Default: 5
    Maximum pre-phase plugins.

  maxPostPhase: number
    Default: 5
    Maximum post-phase plugins.
```

---

## Plugin Loading and Lifecycle

```
Config loads
    ↓
Validate plugin declarations:
  - Path validation (resolve absolute, resolve symlinks via fs.realpath(),
    verify containment within config directory using trailing path.sep —
    platform-agnostic)
  - Phase consistency (config phase matches plugin declaration)
  - Transform uniqueness (max one allowTransform per phase)
  - Count limits (pluginLimits.maxTotal, .maxPrePhase, .maxPostPhase)
    ↓
Load plugin modules (require() — CommonJS only)
  - Module must export a default factory function
  - Factory must return an object conforming to SanitizerPlugin
  - Missing exports or wrong shape → startup failure
    ↓
Validate ruleIdPrefix:
  - Must equal plugin id
  - No collision with built-in prefixes or other plugins
    ↓
Register ruleIdPrefix in rule taxonomy (dynamic namespace)
    ↓
Validate profile plugin references:
  - Profile frequency weight keys referencing unloaded plugin prefixes
    produce warning log, not startup failure
    ↓
Spawn worker_thread per plugin
    ↓
Call initialize() on each plugin (in declaration order, on worker thread)
  - Pass plugin-specific config block
  - Plugin may throw → startup failure (fail closed)
  - Plugin may perform async setup (load models, compile patterns)
    ↓
Emit plugin_config_loaded audit event per plugin
    ↓
Pipeline ready. Plugins invoked per-turn in declared order within phase.
    ↓
On shutdown: call shutdown() on each plugin (reverse declaration order,
  on worker threads). Errors logged but do not prevent exit.
```

Plugins are loaded once and persist for the agent's lifetime. There is no
per-session plugin loading, no per-turn plugin loading, and no runtime
plugin replacement.

---

## Error Handling

### Recoverable Validation (warn, continue)

These issues are corrected automatically. The plugin's results are still
applied with the corrected values. A warning log is emitted.

| Issue | Behavior |
| ----- | -------- |
| Confidence out of range | Clamped to [0.0, 1.0]. Warning log. Plugin results applied with clamped value. |
| findingConfidence entry out of range | Same clamping per entry. |
| ruleId does not start with ruleIdPrefix | ruleId stripped from result. Warning log. Other ruleIds and plugin results preserved. |
| findingConfidence key not in ruleIds | Key ignored. No warning (explicitly allowed by spec). |

### Unrecoverable Errors (block)

These cannot be corrected. Content is blocked and a `plugin_error` audit
event is emitted.

| Failure Mode              | Behavior |
| ------------------------- | -------- |
| Plugin throws in inspect  | `plugin_error`, `reason: "exception"`. Content blocked. Pipeline continues to next plugin for audit completeness. |
| Plugin exceeds timeout    | Worker terminated via `worker.terminate()`. `plugin_error`, `reason: "timeout"`. Worker respawned and re-initialized. If re-init fails, permanently failed for process lifetime (`reason: "worker_init_failed"`). |
| Plugin returns structurally invalid result | `plugin_error`, `reason: "invalid_result"`. Missing required fields (pluginId, safe, ruleIds, flags, confidence) or wrong types. Content blocked. |
| Plugin transform fails schema | Transform rejected, pipeline continues with original content. `plugin_error`, `reason: "transform_schema_fail"`. Plugin's other results (safe, ruleIds, flags) still applied — only the transform is discarded. |
| Plugin queue full         | `plugin_error`, `reason: "queue_full"`. Content blocked. Worker not terminated. |

### Startup Failures (agent does not start)

| Failure Mode              | Behavior |
| ------------------------- | -------- |
| Plugin throws in initialize | Agent does not start. Operator must fix config or remove plugin. |
| Plugin module not found   | Clear error message with resolved path. |
| Plugin id collision       | Two plugins cannot declare the same id. |
| Plugin ruleIdPrefix collision | Prefix collides with built-in or other plugin. |
| Plugin path escapes config dir | Resolved path (post-realpath, with trailing `path.sep`) is outside config directory boundary. |
| Plugin module is ESM      | `require()` of ESM module throws. Error message suggests transpiling to CJS. |

**Pipeline continuation after block:** When a plugin blocks content, the
pipeline still runs subsequent plugins in the same phase. This is for audit
completeness — if two plugins both detect different issues, both findings
should appear in the audit trail. The content is blocked regardless, so
running additional plugins has no security cost.

---

## Example: ClawMoat Integration (Local Library)

ClawMoat (`npm install clawmoat`) is a zero-dependency Node.js library for
prompt injection detection, secret scanning, and PII detection. It exposes
`scan()` and `createPolicy()` as direct function calls — no network, no
external service, sub-millisecond execution.

```typescript
// plugins/clawmoat-adapter/index.ts (transpile to CJS before deploy)
//
// Bundle with: npx esbuild index.ts --bundle --platform=node --outfile=index.js
// This inlines the clawmoat dependency into a single CJS file.

import type { SanitizerPlugin } from "@openclaw/sanitizer-plugin";
import { scan, createPolicy } from "clawmoat";

export default function createPlugin(): SanitizerPlugin {
  let policy: ReturnType<typeof createPolicy>;

  return {
    id: "clawmoat.scanner",
    name: "ClawMoat Scanner",
    phase: "pre",
    ruleIdPrefix: "clawmoat.scanner",

    async initialize(config) {
      // createPolicy accepts YAML-style rule config:
      // allowedTools, blockedCommands, secretPatterns, etc.
      policy = createPolicy(
        (config.policy as Record<string, unknown>) ?? {}
      );
    },

    async shutdown() {
      // No resources to release — pure library, no connections
    },

    async inspect(input) {
      const content = typeof input.content.raw === "string"
        ? input.content.raw
        : JSON.stringify(input.content.raw);

      const result = scan(content, { policy });

      return {
        pluginId: "clawmoat.scanner",
        safe: !result.blocked,
        ruleIds: result.threats.map(
          (t: { pattern: string }) => `clawmoat.scanner.${t.pattern}`
        ),
        flags: result.threats.map(
          (t: { pattern: string; match: string; severity: string }) =>
            `[${t.severity}] ${t.pattern}: ${t.match}`
        ),
        confidence: 1.0, // Pattern matching is deterministic
        // Per-finding confidence not needed — all findings are
        // regex/entropy based, all confidence 1.0
      };
    },
  };
}
```

Config:

```yaml
memory.sessions.sanitization.plugins:
  - module: "./plugins/clawmoat-adapter/index.js"
    phase: "pre"
    # timeoutMs: 1000 is fine — scan() is sub-millisecond
    config:
      policy:
        secretPatterns: ["AWS_*", "GITHUB_TOKEN"]
        # Additional ClawMoat policy config passed through
```

**Why pre-phase?** ClawMoat's `scan()` is a pure synchronous function with
sub-millisecond execution. It runs pattern matching and entropy analysis —
no model calls, no network. This makes it ideal as a pre-phase plugin: its
findings feed into frequency scoring and inform the semantic sub-agent via
hint injection, adding detection coverage before the LLM call.

**Overlap with built-in Tier 1 patterns:** ClawMoat's injection detection
and credential scanning overlap with OpenClaw's built-in Tier 1 patterns
(INJ-*, CRED-*). This is acceptable — defense in depth. ClawMoat maintains
its own pattern library (30+ credential patterns, OWASP coverage) which
may catch patterns the built-in set misses, and vice versa. Duplicate
detections are deduplicated by ruleId in the final merge.

---

## Example: External Threat Scanner (Network Service Pattern)

For scanning tools that expose an HTTP API rather than a local library
(e.g., enterprise threat intelligence services, hosted ML classifiers):

```typescript
// plugins/external-scanner/index.ts (transpile to CJS before deploy)
import type { SanitizerPlugin } from "@openclaw/sanitizer-plugin";

interface ScannerClient {
  scan(payload: { content: string; context: string }): Promise<{
    threats: Array<{ category: string; description: string; confidence: number }>;
  }>;
  healthCheck(): Promise<void>;
  close(): Promise<void>;
}

export default function createPlugin(): SanitizerPlugin {
  let client: ScannerClient;

  return {
    id: "acme.threat-scanner",
    name: "ACME Threat Intelligence Scanner",
    phase: "post",
    ruleIdPrefix: "acme.threat-scanner",

    async initialize(config) {
      // Connect to external scanning service
      const endpoint = config.endpoint as string;
      const apiKey = config.apiKey as string;
      // ScannerClient is your adapter to whatever HTTP API the service exposes
      client = new ExternalScannerClient({ endpoint, apiKey });
      await client.healthCheck();
    },

    async shutdown() {
      await client.close();
    },

    async inspect(input) {
      const scanResult = await client.scan({
        content: JSON.stringify(input.content.raw),
        context: input.contextProfile,
      });

      return {
        pluginId: "acme.threat-scanner",
        safe: scanResult.threats.length === 0,
        ruleIds: scanResult.threats.map(
          (t) => `acme.threat-scanner.${t.category}`
        ),
        flags: scanResult.threats.map((t) => t.description),
        confidence: 0.85, // ML-based, not deterministic
        findingConfidence: Object.fromEntries(
          scanResult.threats.map((t) => [
            `acme.threat-scanner.${t.category}`,
            t.confidence,
          ])
        ),
      };
    },
  };
}
```

Config:

```yaml
memory.sessions.sanitization.plugins:
  - module: "./plugins/external-scanner/index.js"
    phase: "post"
    timeoutMs: 3000        # Network call — needs more headroom
    maxQueueDepth: 5       # Don't queue too many for a slow service
    config:
      endpoint: "http://localhost:9090"
      apiKey: "${SCANNER_API_KEY}"  # Env var substitution in config loader
```

**Why post-phase?** External network scanners add latency (50–500ms
typical). Running them in the post phase means they inspect the semantic
sub-agent's structured output rather than blocking it. They're also ideal
for ML-based classifiers that benefit from seeing the sub-agent's
judgment alongside the raw content.

---

## Example: HIPAA PII Redactor (Pre-Phase with Transform)

```typescript
// plugins/hipaa-redactor/index.ts (transpile to CJS before deploy)
import type { SanitizerPlugin } from "@openclaw/sanitizer-plugin";

const SSN_PATTERN = /\b\d{3}-\d{2}-\d{4}\b/g;
const MRN_PATTERN = /\bMRN[:\s]*\d{6,10}\b/gi;

export default function createPlugin(): SanitizerPlugin {
  return {
    id: "acme.hipaa-redactor",
    name: "ACME HIPAA PII Redactor",
    phase: "pre",
    ruleIdPrefix: "acme.hipaa-redactor",

    async initialize() {},
    async shutdown() {},

    async inspect(input) {
      const raw = JSON.stringify(input.content.raw);
      const findings: string[] = [];
      const ruleIds: string[] = [];
      let redacted = raw;

      const ssnMatches = raw.match(SSN_PATTERN);
      if (ssnMatches) {
        findings.push(`${ssnMatches.length} SSN pattern(s) detected`);
        ruleIds.push("acme.hipaa-redactor.ssn-detected");
        redacted = redacted.replace(SSN_PATTERN, "[REDACTED-SSN]");
      }

      const mrnMatches = raw.match(MRN_PATTERN);
      if (mrnMatches) {
        findings.push(`${mrnMatches.length} MRN pattern(s) detected`);
        ruleIds.push("acme.hipaa-redactor.mrn-detected");
        redacted = redacted.replace(MRN_PATTERN, "[REDACTED-MRN]");
      }

      return {
        pluginId: "acme.hipaa-redactor",
        safe: true,          // Redaction is remediation, not blocking
        ruleIds,
        flags: findings,
        confidence: 1.0,     // Regex matches are deterministic
        transformed: findings.length > 0
          ? JSON.parse(redacted)
          : undefined,
      };
    },
  };
}
```

Config:

```yaml
memory.sessions.sanitization.plugins:
  - module: "./plugins/hipaa-redactor/index.js"
    phase: "pre"
    allowTransform: true    # Required for redaction to take effect
    frequencyWeight: 10     # PII findings weigh heavily
```

---

## Tests

**Plugin loading:**

- Plugin with valid module, phase, and factory loads successfully
- Plugin with missing module path fails at startup with clear error
- Plugin with no default export fails at startup
- Plugin exporting ESM (no module.exports) fails with helpful error message
- Plugin with mismatched phase (config says "pre", plugin says "post") fails at startup
- Plugin that throws in initialize fails startup
- Plugin count exceeding pluginLimits.maxTotal fails startup
- Two plugins with the same id fail startup
- Plugin with ruleIdPrefix not equal to id fails startup
- Plugin with ruleIdPrefix colliding with built-in prefix fails startup
- Plugin with ruleIdPrefix colliding with other plugin fails startup
- Plugin path resolving outside config dir rejected (tested with "..", absolute
  paths, symlinks, Windows-style paths where applicable)
- Plugin path to sibling directory (e.g. /config2 vs /config) rejected by
  trailing path.sep containment check
- Plugin with remote URL in module path rejected at startup
- Plugin as single-file CJS bundle loads and resolves without node_modules
- Plugin with local node_modules resolves dependencies via NODE_PATH
- Plugin loaded via module.exports = fn (direct CJS) works
- Plugin loaded via exports.default = fn (transpiled CJS) works
- Loader resolves via mod.default || mod correctly
- Profile referencing unloaded plugin prefix produces warning, not failure

**Runtime isolation:**

- Plugin inspect runs in worker_thread, not main event loop
- Synchronous infinite loop in plugin is terminated by worker.terminate()
- Worker respawns after termination and re-initializes plugin
- Worker that fails re-initialization is permanently marked failed
- Process restart clears permanently-failed state
- Permanently failed plugin produces plugin_error on subsequent calls
- PluginInput serializes correctly across structured clone boundary
- PluginResult deserializes correctly across structured clone boundary

**Worker queuing:**

- Second request while worker is busy enters FIFO queue
- Timeout timer starts at post-to-worker, not at enqueue
- Queue depth exceeding maxQueueDepth produces plugin_error "queue_full"
- Queued requests are processed in order after current request completes

**Pre-plugin block semantics:**

- Pre-plugin safe:false + ruleId in hardBlockRules + no frequency tier → Stage 2 skipped, final block
- Pre-plugin safe:false + ruleId in hardBlockRules + frequency tier1+ → Stage 2 forced, final block
- Pre-plugin safe:false + ruleId NOT in hardBlockRules → Stage 2 runs with hints, final block
- Pre-plugin safe:false does NOT get rescued by Stage 2 safe:true
- Pre-plugin safe:true → normal flow, no block contribution

**Plugin execution — pre phase:**

- Pre-plugin receives Stage 1 results in priorResults (syntactic and schema non-optional)
- Pre-plugin flags appear in frequency scoring
- Pre-plugin block triggers two-pass skip when rule in hardBlockRules
- Pre-plugin flags injected as hints into semantic sub-agent prompt
- Multiple pre-plugins execute in declaration order
- Pre-plugin results from earlier plugins appear in priorPlugins as PluginResultMeta
- Pre-plugin with transform: later plugins in same phase receive transformed content

**Plugin execution — post phase:**

- Post-plugin receives Stage 1 + Stage 2 results in priorResults
- Post-plugin block overrides Stage 2 safe: true (ANY block wins)
- Post-plugin flags appear in final merged result
- Multiple post-plugins execute in declaration order
- Post-plugin priorResults.semantic is defined (not undefined)

**Plugin timeout:**

- Plugin exceeding timeoutMs produces plugin_error event with reason "timeout"
- Timed-out plugin treated as block
- Subsequent plugins still execute after timeout
- Sync-blocking plugin (tight loop) is terminated by worker.terminate()

**Plugin error handling — recoverable:**

- Confidence > 1.0 clamped to 1.0 with warning log, results still applied
- Confidence < 0.0 clamped to 0.0 with warning log, results still applied
- findingConfidence entry out of range clamped per entry with warning
- ruleId not starting with ruleIdPrefix stripped from result with warning
- Other ruleIds and plugin findings preserved after strip
- Plugin result with clamped/stripped values is not treated as a block

**Plugin error handling — unrecoverable:**

- Plugin throwing in inspect produces plugin_error with reason "exception"
- Plugin returning structurally invalid result (missing pluginId, safe, ruleIds,
  flags, or confidence) produces plugin_error "invalid_result"
- Content blocked after unrecoverable error
- Subsequent plugins still execute after error
- Plugin transform failing schema validation produces plugin_error "transform_schema_fail"
- Failed transform does not block — pipeline continues with original content
- Plugin's safe/ruleIds/flags still applied after transform rejection

**Content transformation:**

- Plugin with allowTransform: false — transformed field ignored
- Plugin with allowTransform: true — transformed content passed to downstream stages
- Transformed output that fails Stage 1B schema validation is rejected
- MCP transform validation uses same tool schema/discriminant as original validation
- Transcript transform validation uses same transcript schema as original
- Transform audit event includes pre and post content hashes (canonical JSON)
- Canonical JSON hashing produces same hash regardless of original key order
- Raw mirror contains original (pre-transform) content
- Two plugins with allowTransform: true in same phase fails startup
- Transform applied only when plugin returns non-undefined transformed field
- Later plugins in same phase receive transformed content in content.raw
- priorPlugins for later plugins includes PluginResultMeta with transformApplied: true
- priorPlugins for errored plugins includes PluginResultMeta with errored: true

**Context profile interaction:**

- Plugin disabled in active profile is not invoked
- Plugin frequency weight overridden by profile config (plugin id level)
- Plugin frequency weight overridden by profile config (individual ruleId level)
- Wildcard prefix override (e.g. "acme.scanner.*": 10) applies to all matching rules
- Precedence: full ruleId > prefix wildcard > plugin id
- Wildcard key cannot set enabled (only frequencyWeight)
- Full ruleId key cannot set enabled (only frequencyWeight)
- Plugin enabled in profile but disabled globally (enabled: false) is not loaded

**Trust tier interaction:**

- Trusted MCP server: Stage 1 runs, trust routing bypasses plugins, trusted_pass emitted
- Untrusted MCP server results invoke plugins
- Transcript content invokes plugins

**Audit integration:**

- plugin_block event at minimal verbosity, payload matches schema
- plugin_pass event at standard verbosity for clean pass (no flags)
- plugin_flags event at standard verbosity for safe:true with flags (not both pass and flags)
- plugin_error event at minimal verbosity, payload includes reason and detail
- plugin_transform event at high verbosity with canonical JSON hashes and hashMethod
- plugin_config_loaded writes to agent-level alert log, not session audit JSONL
- plugin_config_loaded event at minimal verbosity with full resolved config, no sessionId
- Plugin rule IDs appear in rule_triggered events at high verbosity

**Alerting integration:**

- Single plugin_error does not trigger alert (below aggregation threshold)
- 3 plugin_errors within 5 minutes (same agent) triggers pluginErrorSpike alert
- pluginErrorSpike scoped to same agent (errors from different agents don't aggregate)
- pluginErrorSpike alert includes pluginId breakdown and reason counts
- pluginErrorSpike configurable: custom count and window thresholds

**Frequency scoring integration:**

- Plugin finding with confidence 1.0 contributes full weight
- Plugin finding with confidence 0.5 contributes half weight
- Plugin with findingConfidence override: keyed ruleId uses specific confidence
- Plugin with findingConfidence override: unkeyed ruleId falls back to default
- Clamped confidence values produce correct effective weights (tested via
  recoverable validation — see error handling tests)
- Clean pass (empty ruleIds, safe:true) does not contribute to frequency score
- Plugin findings accumulate with built-in findings in session score
- Plugin-driven frequency escalation triggers same tier thresholds

---

## Residual Risks (Accepted)

| Risk | Status |
| ---- | ------ |
| Malicious plugin module executes arbitrary code at startup | Accepted. Plugins are operator-installed local modules. Same trust model as npm dependencies. Operator is responsible for vetting plugin code. |
| Plugin transform masks content from semantic sub-agent | Mitigated by allowTransform default false, single-transform-per-phase limit, Stage 1B schema validation of transforms (with full MCP context), raw mirror preservation, and canonical JSON audit hashing. Residual risk accepted. |
| Slow plugins add latency to MCP critical path | Mitigated by per-plugin timeout (default 1s, max 10s) enforced via `worker.terminate()`. Operator can tune or disable. Plugins that consistently timeout should be removed. |
| Plugin id namespace pollution | Mitigated by requiring org-prefixed ids and rejecting collisions with built-in prefixes. Residual risk: two third-party plugins could collide with each other. Accepted — operator-resolvable at config time. |
| Plugin error flood obscures real threats in audit log | Mitigated by `pluginErrorSpike` aggregation alerting and by pipeline continuation (real threats from built-in stages still surface). Operators should fix or remove failing plugins promptly. |
| Plugin with network calls introduces new egress surface | Accepted. External plugins (like ClawMoat adapter) make network calls. Operator is responsible for network policy. OpenClaw does not sandbox plugin network access (deferred). |
| Worker thread serialization overhead on large payloads | Mitigated by Tier 1 structural size check (STRUCT-002, default 512KB max). For typical payloads (< 100KB), structured clone is sub-millisecond. Accepted. |
| Plugin symlink or path traversal escapes config directory | Mitigated by platform-agnostic containment check: `path.resolve()` + `fs.realpath()` + trailing `path.sep` prefix comparison. |
| Plugin ruleIds registered dynamically may not be present in profile frequency weight references | Mitigated by warning-on-missing (not failure). Profiles remain valid when plugins are added or removed. |

---

## Required Companion Changes

### Context-Aware Sanitization Spec v2.2

The custom profile schema must be extended to support a `plugins` map:

```yaml
# Addition to custom profile schema
plugins:
  type: object
  description: Per-plugin and per-rule overrides for this profile.
  additionalProperties:
    type: object
    properties:
      enabled:
        type: boolean
        description: Override plugin enabled state for this profile.
      frequencyWeight:
        type: number
        description: Override frequency weight for this plugin or rule.
```

Keys in the `plugins` map use one of three forms:

1. **Plugin id** (e.g. `"acme.hipaa-redactor"`) — applies `enabled` and
   `frequencyWeight` to all rules under this plugin.
2. **Prefix wildcard** (e.g. `"acme.hipaa-redactor.*"`) — applies
   `frequencyWeight` only (not `enabled`) to all rules matching the prefix.
   Functionally equivalent to the plugin id form for frequency weight, but
   explicit about intent. Cannot set `enabled` (enable/disable is per-plugin,
   not per-rule).
3. **Full ruleId** (e.g. `"acme.hipaa-redactor.ssn-detected"`) — applies
   `frequencyWeight` only (not `enabled`) to a single rule.

**Precedence:** Full ruleId overrides prefix wildcard overrides plugin id.
This parallels the existing `frequencyWeightOverrides` pattern for built-in
rules in the context-aware sanitization spec.

Validation: keys referencing unloaded plugin prefixes produce a warning log
at startup, not a failure. This prevents profiles from becoming invalid when
plugins are added or removed.

### Audit Alerting Spec v2.4

Add the `pluginErrorSpike` alert rule definition and its config keys to the
alerting spec's rule inventory and config reference.

---

## Out of Scope

- Plugin sandboxing (filesystem/network isolation for plugin execution)
- Remote plugin loading (plugins fetched from URLs or registries)
- Plugin marketplace or discovery mechanism
- Hot-reload of plugins without restart
- Plugin-to-plugin communication (plugins are isolated; shared state is
  via priorPlugins in PluginInput only — full PluginResultMeta, not filtered)
- ML model hosting or management (ML plugins bring their own runtime)
- Plugin-specific alert rules beyond pluginErrorSpike (deferred until alerting
  supports custom rule definitions)
- Plugin versioning or compatibility checking beyond the interface contract
- Automatic plugin rule promotion to built-in rules (related to alerting
  spec's Rule 4 future work on syntactic rule auto-generation)
- ESM plugin support (CJS only in v1; ESM support deferred)
- Per-plugin alerting granularity (pluginErrorSpike aggregates across all plugins)

---

## Implementation Sequencing

This feature builds on all existing specs. Recommended order:

1. **Interface and loading** — Define the TypeScript interface (including
   `ruleIdPrefix`, `PluginResultMeta`), factory pattern, CJS module loading,
   config schema (with separated `pluginLimits`), platform-agnostic path
   validation, and startup validation.

2. **Worker isolation** — Spawn workers, message passing, timeout enforcement
   via `worker.terminate()`, FIFO queuing, respawn-on-failure, permanent
   failure tracking.

3. **Pre-phase integration** — Wire pre-plugin execution between trust-tier
   routing and frequency scoring. Flag passthrough to sub-agent. Pre-plugin
   block semantics (truth table). Audit events with full payload schemas.

4. **Post-phase integration** — Wire post-plugin execution after Stage 2.
   Final merge logic. Audit events.

5. **Transform support** — Implement allowTransform, schema validation with
   MCP context, canonical JSON hash audit, raw mirror preservation.

6. **Alerting integration** — Implement `pluginErrorSpike` rule. Wire
   plugin_error events to alerting layer.

7. **Example plugins** — Ship 1-2 reference plugins (a simple regex pattern
   plugin and a stub external scanner adapter) as documentation and
   integration test fixtures.

---

## Relationship to Existing Extension Points

The Tier 1 pattern library already describes a `customPatterns` config
extension (currently documented but not implemented). The pluggable
sanitizer interface supersedes that design:

- `customPatterns` was limited to regex patterns with block/flag actions.
- The plugin interface supports arbitrary inspection logic (regex, ML,
  external services) with a richer result type.
- A simple "custom regex patterns" plugin can be shipped as a built-in
  reference plugin, providing the same functionality `customPatterns` was
  designed for, but through the standard plugin interface.

The `customPatterns` config key should not be implemented separately. It
should be retired in favor of the plugin interface once this spec ships.
The tier1-pattern-library spec should be updated to reference this spec
for operator-defined patterns.

---

_Version: 1.2.1_
_Date: March 2026_
_Status: Draft — all implementation-blocking ambiguities resolved, delta review applied_
