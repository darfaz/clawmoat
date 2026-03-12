/**
 * OpenClaw Sanitizer Plugin — ClawMoat Adapter
 *
 * Wraps ClawMoat's scan() and createPolicy() as an OpenClaw sanitizer plugin.
 * ClawMoat is a zero-dependency Node.js library for prompt injection detection,
 * secret scanning, and PII detection. Sub-millisecond, deterministic,
 * no network calls.
 *
 * Install: npm install clawmoat
 * Bundle:  npx esbuild src/index.ts --bundle --platform=node --outfile=dist/index.js
 *
 * @see https://github.com/darfaz/clawmoat
 * @see https://clawmoat.com
 */

import type { SanitizerPlugin, PluginInput, PluginResult } from "@openclaw/sanitizer-plugin";
import { scan, createPolicy } from "clawmoat";

// ClawMoat's scan result shape (from their README + npm examples)
interface ClawMoatThreat {
  pattern: string;    // e.g. "prompt-injection/indirect-instruction", "credential-leak/aws-access-key"
  match: string;      // the matched content
  severity: string;   // "critical" | "high" | "medium" | "low"
}

interface ClawMoatScanResult {
  blocked: boolean;
  threats: ClawMoatThreat[];
}

// Config shape passed through from OpenClaw plugin config block
interface ClawMoatPluginConfig {
  policy?: {
    allowedTools?: string[];
    blockedCommands?: string[];
    secretPatterns?: (string | RegExp)[];
    maxActionsPerMinute?: number;
  };
  // Map ClawMoat severity levels to safe/block decision.
  // By default, any threat = block. Operators can set this to "critical"
  // to only block on critical findings, letting lower severities pass as flags.
  blockThreshold?: "low" | "medium" | "high" | "critical";
}

const SEVERITY_RANK: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Determine whether a threat meets the block threshold.
 * If threshold is "high", only "high" and "critical" threats trigger a block.
 */
function meetsThreshold(
  threatSeverity: string,
  threshold: string
): boolean {
  const threatRank = SEVERITY_RANK[threatSeverity] ?? 0;
  const thresholdRank = SEVERITY_RANK[threshold] ?? 1;
  return threatRank >= thresholdRank;
}

/**
 * Normalize ClawMoat's pattern string into a valid ruleId suffix.
 * ClawMoat uses patterns like "prompt-injection/indirect-instruction"
 * which contain slashes. We convert to dots for ruleId compatibility.
 */
function normalizePattern(pattern: string): string {
  return pattern.replace(/\//g, ".").replace(/[^a-zA-Z0-9.\-_]/g, "-");
}

export default function createPlugin(): SanitizerPlugin {
  let policy: ReturnType<typeof createPolicy>;
  let blockThreshold: string;

  return {
    id: "clawmoat.scanner",
    name: "ClawMoat Scanner",
    phase: "pre",
    ruleIdPrefix: "clawmoat.scanner",

    async initialize(config: Record<string, unknown>) {
      const typed = config as unknown as ClawMoatPluginConfig;

      // Create ClawMoat policy from operator config
      policy = createPolicy(typed.policy ?? {});

      // Block threshold — default is "low" (any threat blocks)
      blockThreshold = typed.blockThreshold ?? "low";

      if (!SEVERITY_RANK[blockThreshold]) {
        throw new Error(
          `clawmoat-adapter: invalid blockThreshold "${blockThreshold}". ` +
          `Must be one of: low, medium, high, critical`
        );
      }
    },

    async shutdown() {
      // Nothing to release — ClawMoat is a pure library with no connections
    },

    async inspect(input: PluginInput): Promise<PluginResult> {
      // Serialize content for ClawMoat's text-based scanner
      const content =
        typeof input.content.raw === "string"
          ? input.content.raw
          : JSON.stringify(input.content.raw);

      // ClawMoat scan — synchronous, sub-millisecond
      const result: ClawMoatScanResult = scan(content, { policy });

      // Separate threats into blocking (meets threshold) and flagging (below threshold)
      const blockingThreats = result.threats.filter((t) =>
        meetsThreshold(t.severity, blockThreshold)
      );
      const allThreats = result.threats;

      // Build ruleIds from all threats (blocking or not — all go into audit)
      const ruleIds = allThreats.map(
        (t) => `clawmoat.scanner.${normalizePattern(t.pattern)}`
      );

      // Build human-readable flags
      const flags = allThreats.map(
        (t) => `[${t.severity}] ${t.pattern}: ${t.match}`
      );

      return {
        pluginId: "clawmoat.scanner",
        safe: blockingThreats.length === 0,
        ruleIds,
        flags,
        confidence: 1.0, // All ClawMoat detections are deterministic pattern/entropy matches
      };
    },
  };
}
