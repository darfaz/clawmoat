/**
 * Agent Boundary Scanner
 * 
 * Formalizes scanning at every agent boundary:
 * - pre-input:      User/external → Agent (prompt injection, obfuscation, jailbreak)
 * - pre-model:      Agent → LLM (prompt leakage, system prompt exposure)
 * - pre-tool-call:  LLM → Tool (dangerous commands, exfil, excessive agency)
 * - post-tool-result: Tool → LLM (poisoned results, injected instructions)
 * - pre-output:     Agent → User/external (secret leakage, PII, data exfil)
 * 
 * This is the pipeline that makes ClawMoat agent-native, not chat-native.
 * 
 * @module boundary-scanner
 */

'use strict';

const STAGES = ['pre-input', 'pre-model', 'pre-tool-call', 'post-tool-result', 'pre-output'];

/**
 * Create a boundary scanner pipeline
 * @param {Object} [config] - Configuration
 * @param {string} [config.mode='enforce'] - 'enforce' (block), 'monitor' (log only), 'off'
 * @param {Function} [config.onViolation] - Callback on violations: (stage, finding, context) => void
 * @param {Function} [config.onDecision] - Callback on every decision: (stage, result, context) => void
 * @param {Object} [config.stageConfig] - Per-stage overrides
 * @returns {Object} Pipeline instance
 */
function createPipeline(config = {}) {
  const {
    mode = 'enforce',
    onViolation = null,
    onDecision = null,
    stageConfig = {},
  } = config;

  // Registered scanners per stage
  const scanners = {};
  for (const stage of STAGES) {
    scanners[stage] = [];
  }

  // Execution trace
  const trace = [];
  const stats = { scanned: 0, blocked: 0, warned: 0, allowed: 0 };

  /**
   * Register a scanner for a stage
   * @param {string} stage - Pipeline stage
   * @param {string} name - Scanner name
   * @param {Function} fn - Scanner function: (text, context) => { safe, findings }
   * @param {Object} [opts] - Options
   * @param {number} [opts.priority=50] - Lower runs first
   * @param {boolean} [opts.required=false] - Pipeline fails if scanner throws
   */
  function register(stage, name, fn, opts = {}) {
    if (!STAGES.includes(stage)) {
      throw new Error(`Invalid stage: ${stage}. Must be one of: ${STAGES.join(', ')}`);
    }
    const { priority = 50, required = false } = opts;
    scanners[stage].push({ name, fn, priority, required });
    scanners[stage].sort((a, b) => a.priority - b.priority);
  }

  /**
   * Run all scanners for a pipeline stage
   * @param {string} stage - Pipeline stage
   * @param {string|Object} input - Text or structured input to scan
   * @param {Object} [context] - Additional context (trust level, tool name, etc.)
   * @returns {Object} { allowed, findings, blocked, actions }
   */
  function scan(stage, input, context = {}) {
    if (!STAGES.includes(stage)) {
      throw new Error(`Invalid stage: ${stage}. Must be one of: ${STAGES.join(', ')}`);
    }

    const stageMode = stageConfig[stage]?.mode || mode;
    if (stageMode === 'off') {
      return { allowed: true, findings: [], blocked: false, actions: [] };
    }

    const text = typeof input === 'string' ? input : JSON.stringify(input);
    const allFindings = [];
    const actions = [];
    let blocked = false;

    stats.scanned++;

    for (const scanner of scanners[stage]) {
      try {
        const result = scanner.fn(text, { ...context, stage });
        if (result && !result.safe && result.findings) {
          for (const finding of result.findings) {
            const enriched = {
              ...finding,
              scanner: scanner.name,
              stage,
              timestamp: new Date().toISOString(),
            };
            allFindings.push(enriched);

            const action = resolveAction(enriched, stageMode);
            actions.push({ finding: enriched, action });

            if (action === 'block') blocked = true;
            if (onViolation) onViolation(stage, enriched, context);
          }
        }
      } catch (err) {
        if (scanner.required) {
          blocked = true;
          allFindings.push({
            type: 'scanner_error',
            subtype: 'required_scanner_failed',
            severity: 'critical',
            scanner: scanner.name,
            stage,
            evidence: err.message,
            timestamp: new Date().toISOString(),
          });
        }
      }
    }

    const allowed = stageMode === 'monitor' ? true : !blocked;
    if (blocked) stats.blocked++;
    else if (allFindings.length > 0) stats.warned++;
    else stats.allowed++;

    const decision = {
      stage,
      allowed,
      blocked,
      findings: allFindings,
      actions,
      mode: stageMode,
      scannersRun: scanners[stage].length,
      timestamp: new Date().toISOString(),
    };

    trace.push(decision);
    if (onDecision) onDecision(stage, decision, context);

    return decision;
  }

  /**
   * Run a complete agent turn through the pipeline
   * @param {Object} turn - Agent turn data
   * @param {string} [turn.input] - User/external input
   * @param {string} [turn.modelPrompt] - Full prompt sent to model
   * @param {Array} [turn.toolCalls] - Array of { tool, args } objects
   * @param {Array} [turn.toolResults] - Array of tool result strings
   * @param {string} [turn.output] - Final agent output
   * @param {Object} [context] - Context passed to all stages
   * @returns {Object} { allowed, stages, findings, trace }
   */
  function scanTurn(turn, context = {}) {
    const stages = {};
    const allFindings = [];
    let turnAllowed = true;

    if (turn.input !== undefined) {
      stages['pre-input'] = scan('pre-input', turn.input, context);
      if (!stages['pre-input'].allowed) turnAllowed = false;
      allFindings.push(...stages['pre-input'].findings);
    }

    if (turn.modelPrompt !== undefined && turnAllowed) {
      stages['pre-model'] = scan('pre-model', turn.modelPrompt, context);
      if (!stages['pre-model'].allowed) turnAllowed = false;
      allFindings.push(...stages['pre-model'].findings);
    }

    if (turn.toolCalls && turnAllowed) {
      for (let i = 0; i < turn.toolCalls.length; i++) {
        const tc = turn.toolCalls[i];
        const key = `pre-tool-call[${i}]`;
        const tcContext = { ...context, tool: tc.tool, toolIndex: i };
        stages[key] = scan('pre-tool-call', tc, tcContext);
        if (!stages[key].allowed) turnAllowed = false;
        allFindings.push(...stages[key].findings);
      }
    }

    if (turn.toolResults && turnAllowed) {
      for (let i = 0; i < turn.toolResults.length; i++) {
        const key = `post-tool-result[${i}]`;
        stages[key] = scan('post-tool-result', turn.toolResults[i], { ...context, toolIndex: i });
        if (!stages[key].allowed) turnAllowed = false;
        allFindings.push(...stages[key].findings);
      }
    }

    if (turn.output !== undefined && turnAllowed) {
      stages['pre-output'] = scan('pre-output', turn.output, context);
      if (!stages['pre-output'].allowed) turnAllowed = false;
      allFindings.push(...stages['pre-output'].findings);
    }

    return {
      allowed: turnAllowed,
      stages,
      findings: allFindings,
      turnBlocked: !turnAllowed,
    };
  }

  function resolveAction(finding, stageMode) {
    if (stageMode === 'monitor') return 'log';
    const recommended = finding.recommended_action || 'block';
    const severityMap = {
      critical: 'block',
      high: 'block',
      medium: recommended === 'block' ? 'block' : 'warn',
      low: 'warn',
    };
    return severityMap[finding.severity] || 'warn';
  }

  function getTrace() { return [...trace]; }
  function getStats() { return { ...stats }; }
  function resetTrace() { trace.length = 0; }
  function resetStats() { stats.scanned = 0; stats.blocked = 0; stats.warned = 0; stats.allowed = 0; }

  return {
    register,
    scan,
    scanTurn,
    getTrace,
    getStats,
    resetTrace,
    resetStats,
    STAGES,
  };
}

/**
 * Create a pre-configured pipeline with all ClawMoat scanners registered
 * @param {Object} [config] - Pipeline config
 * @returns {Object} Ready-to-use pipeline
 */
function createDefaultPipeline(config = {}) {
  const pipeline = createPipeline(config);

  // Lazy-load to avoid circular deps
  const loadScanner = (name) => {
    try { return require(`./${name}`); } catch (_) { return null; }
  };

  // Pre-input: prompt injection, jailbreak, obfuscation
  const index = loadScanner('index');
  const obfuscation = loadScanner('obfuscation-scanner');
  const codeScanner = loadScanner('code-scanner');

  if (index) {
    const moat = new index();
    pipeline.register('pre-input', 'prompt-injection', (text) => {
      const r = moat.scanInbound(text);
      return r;
    }, { priority: 10 });

    pipeline.register('pre-output', 'secret-pii-leak', (text) => {
      const r = moat.scanOutbound(text);
      return r;
    }, { priority: 10 });
  }

  if (obfuscation) {
    pipeline.register('pre-input', 'obfuscation', (text) => {
      return obfuscation.scanObfuscation(text);
    }, { priority: 5 }); // Run before injection detection (strip first)
  }

  if (codeScanner) {
    pipeline.register('pre-tool-call', 'dangerous-code', (text, ctx) => {
      return codeScanner.scanCode(text, { tool: ctx.tool });
    }, { priority: 20 });
  }

  // Post-tool-result: check for injected instructions in tool output
  if (index) {
    const moat = new index();
    pipeline.register('post-tool-result', 'tool-result-injection', (text) => {
      return moat.scanInbound(text);
    }, { priority: 10 });
  }

  return pipeline;
}

module.exports = {
  createPipeline,
  createDefaultPipeline,
  STAGES,
};
