# Pluggable Sanitizer Interface — Phase 1: Interface & Loading

## CC Instruction Set

Implement Phase 1 of the pluggable sanitizer interface for the OpenClaw
session memory sanitization system. This phase defines the TypeScript
interfaces, config schema, module loading, and startup validation. No
pipeline wiring yet — that's Phase 2+.

**Reference spec:** `pluggable-sanitizer-interface-spec-v1_2_1.md`

Do not change any existing sanitization behavior. No pipeline integration,
no audit events, no frequency scoring changes. This phase only adds the
foundational types and the loader that validates and initializes plugins
at startup.

---

## Branch

Create a new branch from the tip of `feature/sanitization-hardening`
(or `main` if that PR has merged):

```
feature/pluggable-sanitizer-interface
```

---

## Step 1 — TypeScript Interfaces

Create `src/memory/session-sanitization/plugin-interface.ts`.

Define and export these interfaces exactly as specified:

### `SanitizerPlugin`

```typescript
export interface SanitizerPlugin {
  id: string;
  name: string;
  phase: "pre" | "post";
  ruleIdPrefix: string;
  initialize(config: Record<string, unknown>): Promise<void>;
  shutdown(): Promise<void>;
  inspect(input: PluginInput): Promise<PluginResult>;
}
```

### `PluginInput`

```typescript
export interface PluginInput {
  content: {
    source: "transcript" | "mcp";
    raw: unknown;
    query?: { server: string; tool: string; params: unknown };
  };
  priorResults: {
    syntactic: { pass: boolean; flags: string[]; ruleIds: string[] };
    schema: { pass: boolean; violations: string[]; ruleIds: string[] };
    semantic?: { safe: boolean; flags: string[]; structuredResult: unknown };
    priorPlugins: PluginResultMeta[];
  };
  contextProfile: string;
}
```

### `PluginResult`

```typescript
export interface PluginResult {
  pluginId: string;
  safe: boolean;
  ruleIds: string[];
  flags: string[];
  confidence: number;
  findingConfidence?: Record<string, number>;
  transformed?: unknown;
}
```

### `PluginResultMeta`

```typescript
export interface PluginResultMeta extends PluginResult {
  transformApplied?: boolean;
  errored?: boolean;
}
```

### `PluginDeclaration` (config shape)

```typescript
export interface PluginDeclaration {
  module: string;
  phase: "pre" | "post";
  enabled?: boolean;         // default: true
  config?: Record<string, unknown>;  // default: {}
  timeoutMs?: number;        // default: 1000, min: 100, max: 10000
  allowTransform?: boolean;  // default: false
  frequencyWeight?: number;  // default: 3
  maxQueueDepth?: number;    // default: 10
}

export interface PluginLimits {
  maxTotal?: number;       // default: 10
  maxPrePhase?: number;    // default: 5
  maxPostPhase?: number;   // default: 5
}
```

**Checkpoint:** `pnpm tsgo` passes. No runtime behavior changed.

---

## Step 2 — Config Schema

Extend the sanitization config namespace to accept plugin declarations.
Find where `memory.sessions.sanitization` config is defined (likely in
`src/memory/session-sanitization/config.ts` or a shared config module).

Add two new fields:

```typescript
plugins?: PluginDeclaration[];   // default: []
pluginLimits?: PluginLimits;     // default: { maxTotal: 10, maxPrePhase: 5, maxPostPhase: 5 }
```

These are **sibling** keys — `plugins` is an array, `pluginLimits` is
a separate object. They must NOT be nested under the same key.

Provide defaults so the system behaves identically when no plugins are
configured (empty array, nothing loads, nothing changes).

**Checkpoint:** `pnpm tsgo` passes. Existing config loading still works.
No plugins configured = no behavior change.

---

## Step 3 — Built-In Prefix Registry

Create `src/memory/session-sanitization/plugin-rule-prefixes.ts`.

Export a constant set of built-in rule prefixes that plugins must not
collide with:

```typescript
export const BUILTIN_RULE_PREFIXES: ReadonlySet<string> = new Set([
  "INJ-",
  "CRED-",
  "STRUCT-",
  "TYPE-",
  "ENC-",
  "TEMPORAL-",
  "schema.",
  "injection.",
  "credential.",
  "scope-creep.",
]);
```

Export a validation function:

```typescript
export function collidesWithBuiltin(prefix: string): boolean {
  for (const builtin of BUILTIN_RULE_PREFIXES) {
    if (prefix.startsWith(builtin) || builtin.startsWith(prefix)) {
      return true;
    }
  }
  return false;
}
```

**Checkpoint:** Unit test for `collidesWithBuiltin`:
- `"INJ-custom"` → true
- `"schema.extra"` → true
- `"clawmoat.scanner"` → false
- `"acme.hipaa"` → false

---

## Step 4 — Path Validation

Create `src/memory/session-sanitization/plugin-path-validation.ts`.

Export a function that validates a plugin module path against the config
directory. The function must be **platform-agnostic** — works on both
Windows and POSIX:

```typescript
import * as path from "path";
import * as fs from "fs";

export function validatePluginPath(
  modulePath: string,
  configDir: string
): { valid: true; resolvedPath: string } | { valid: false; reason: string } {
  // 1. Resolve to absolute
  const absolute = path.resolve(configDir, modulePath);

  // 2. Resolve symlinks
  let realPath: string;
  try {
    realPath = fs.realpathSync(absolute);
  } catch (err) {
    return { valid: false, reason: `Module not found: ${absolute}` };
  }

  // 3. Containment check — resolved path must start with configDir + separator
  const configDirReal = fs.realpathSync(configDir);
  const boundary = configDirReal + path.sep;
  if (!realPath.startsWith(boundary) && realPath !== configDirReal) {
    return {
      valid: false,
      reason: `Module path escapes config directory: ${realPath} is outside ${configDirReal}`,
    };
  }

  return { valid: true, resolvedPath: realPath };
}
```

**Checkpoint:** Unit tests:
- Relative path within config dir → valid
- Path with `..` escaping → invalid
- Absolute path outside config dir → invalid
- Non-existent path → invalid with "not found"
- (If testable on the platform) symlink pointing outside → invalid

---

## Step 5 — Plugin Loader

Create `src/memory/session-sanitization/plugin-loader.ts`.

This is the core of Phase 1. The loader validates config, loads modules,
validates the plugin interface, and calls `initialize()`. It does NOT
spawn worker threads yet — that's Phase 2. For now, plugins load in-process.

```typescript
export interface LoadedPlugin {
  declaration: PluginDeclaration;
  instance: SanitizerPlugin;
  resolvedPath: string;
}

export async function loadPlugins(
  declarations: PluginDeclaration[],
  limits: Required<PluginLimits>,
  configDir: string
): Promise<LoadedPlugin[]> {
  // Implementation steps below
}
```

### Validation order (fail-fast at startup):

1. **Filter disabled plugins.** Skip entries with `enabled: false` entirely
   — do not load, do not validate path, do not count against limits.

2. **Count limits.** Count enabled plugins per phase and total.
   If any limit exceeded → throw with clear message naming the limit and
   the count.

3. **Transform uniqueness.** Per phase, at most one plugin may have
   `allowTransform: true`. If violated → throw naming both plugins.

4. **Path validation.** For each enabled plugin, call `validatePluginPath`.
   If invalid → throw with the reason.

5. **Module loading.** `require()` the resolved path. Apply CJS interop:
   `const factory = mod.default || mod`. If result is not a function →
   throw with "Module does not export a factory function".

6. **Factory call.** `const instance = factory()`. Validate the returned
   object has all required `SanitizerPlugin` fields (id, name, phase,
   ruleIdPrefix, initialize, shutdown, inspect) with correct types.
   If invalid → throw naming the missing/wrong field.

7. **Phase consistency.** `declaration.phase` must equal `instance.phase`.
   If mismatched → throw naming both values.

8. **ruleIdPrefix validation.**
   - `instance.ruleIdPrefix` must equal `instance.id`.
   - Must not collide with built-in prefixes (use `collidesWithBuiltin`).
   - Must not collide with any previously loaded plugin's prefix.
   If violated → throw naming the collision.

9. **Initialize.** Call `await instance.initialize(declaration.config ?? {})`.
   If it throws → let the error propagate (startup failure, fail closed).

10. **Return.** Collect all `LoadedPlugin` entries.

### Shutdown helper:

```typescript
export async function shutdownPlugins(
  plugins: LoadedPlugin[]
): Promise<void> {
  // Reverse order. Best-effort — log errors but don't throw.
  for (const plugin of [...plugins].reverse()) {
    try {
      await plugin.instance.shutdown();
    } catch (err) {
      log.warn(`Plugin ${plugin.instance.id} shutdown error`, err);
    }
  }
}
```

**Checkpoint:** `pnpm tsgo` passes. Write unit tests for the full loader:

---

## Step 6 — Loader Tests

Create `src/memory/session-sanitization/plugin-loader.test.ts`.

Write tests using Vitest. You will need to create small fixture plugins
as test helpers — either inline mock factories or tiny CJS files in a
test fixtures directory.

**Tests to write:**

Loading:
- Empty declarations array → returns empty array, no errors
- Single valid plugin → loads, initializes, returns LoadedPlugin
- Plugin with `enabled: false` → not loaded, not counted
- Plugin loaded via `module.exports = fn` form → works
- Plugin loaded via `exports.default = fn` form → works

Limit enforcement:
- Exceeding `maxTotal` → startup error naming the limit
- Exceeding `maxPrePhase` → startup error
- Exceeding `maxPostPhase` → startup error
- Disabled plugins do not count against limits

Validation:
- Phase mismatch (config: "pre", plugin: "post") → startup error
- ruleIdPrefix not equal to id → startup error
- ruleIdPrefix colliding with built-in prefix → startup error
- Two plugins with same id → startup error
- Two plugins with same ruleIdPrefix → startup error
- Module not found → startup error with path
- Module exports non-function → startup error
- Factory returns object missing required fields → startup error

Transform:
- Two plugins in same phase with `allowTransform: true` → startup error
- Two plugins in different phases with `allowTransform: true` → OK

Path validation:
- Module path escaping config dir → startup error
- Valid relative path → resolves and loads

Initialize:
- Plugin that throws in initialize → propagates as startup error
- Plugin initialize receives the config block from declaration

Shutdown:
- Shutdown calls plugins in reverse order
- Shutdown logs errors but does not throw

---

## Step 7 — Wire Loader Into Startup

Find where the sanitization subsystem initializes at agent startup. This
is likely in the same path where the sanitization config is loaded and
the sub-agent is prepared.

Add a call to `loadPlugins()` after config is resolved and validated.
Store the resulting `LoadedPlugin[]` in the sanitization state so it's
accessible to the pipeline (Phase 2+).

If no plugins are configured (empty array), the loader returns immediately
with an empty array. Zero overhead, zero behavior change.

Add a corresponding `shutdownPlugins()` call on the agent shutdown path.

**Do NOT wire plugins into the inspection pipeline yet.** The loaded plugins
sit in state, initialized and ready, but not invoked on any content. That
wiring is Phase 2 (worker isolation) and Phase 3 (pre-phase integration).

**Checkpoint:** Full test suite passes:
- `pnpm vitest run src/memory/session-sanitization/plugin-loader.test.ts`
- `pnpm vitest run src/memory/session-sanitization/plugin-path-validation.test.ts`
- `pnpm vitest run src/memory/session-sanitization/plugin-rule-prefixes.test.ts`
- `pnpm tsgo`
- `pnpm test` (full suite — confirm no regressions)
- `pnpm format`

---

## Commit

Single commit on `feature/pluggable-sanitizer-interface`.

```
feat: add pluggable sanitizer interface types, config schema, and plugin loader

Phase 1 of pluggable-sanitizer-interface-spec-v1.2.1.
Defines SanitizerPlugin/PluginInput/PluginResult/PluginResultMeta interfaces,
config schema (plugins array + pluginLimits), platform-agnostic path validation,
built-in prefix collision checking, and startup plugin loading with full
validation chain. Plugins load and initialize but are not wired into the
inspection pipeline (Phase 2+).
```

---

## What this does NOT include (deferred to later phases)

- Worker thread isolation (Phase 2)
- Pipeline integration — pre-phase or post-phase execution (Phase 3–4)
- Content transformation support (Phase 5)
- Audit events (plugin_config_loaded, etc.) (Phase 3–4)
- Alerting integration (pluginErrorSpike) (Phase 6)
- Frequency scoring integration (Phase 3)
- Context profile plugin overrides (Phase 3)
- Trust tier routing awareness (Phase 3)

---

## Self-Review Checklist (run before committing)

- [ ] All new files are under `src/memory/session-sanitization/`
- [ ] Interfaces match the spec exactly (field names, types, optionality)
- [ ] Config defaults mean zero behavior change when no plugins configured
- [ ] Path validation uses `path.resolve` + `fs.realpathSync` + trailing `path.sep`
- [ ] CJS interop uses `mod.default || mod`
- [ ] Loader fails fast with clear error messages at each validation step
- [ ] Shutdown is reverse-order and best-effort
- [ ] No pipeline changes — loaded plugins sit in state, uninvoked
- [ ] All tests pass, including full `pnpm test`
- [ ] `pnpm tsgo` clean
- [ ] `pnpm format` clean
