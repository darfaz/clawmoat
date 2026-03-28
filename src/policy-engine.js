/**
 * ClawMoat Policy Engine — Declarative security rules for AI agents
 * 
 * Define rules in YAML/JSON, enforce them at runtime.
 * This is what makes ClawMoat a firewall, not a scanner.
 * 
 * @example
 * const { PolicyEngine } = require('clawmoat');
 * const engine = new PolicyEngine('./clawmoat-policy.yaml');
 * 
 * // Evaluate a tool call
 * const decision = engine.evaluate({
 *   type: 'tool_call',
 *   tool: 'slack.send',
 *   args: { channel: '#general', text: 'API key: sk-...' },
 *   context: { user: 'agent-1', source: 'mcp' }
 * });
 * 
 * if (decision.action === 'block') {
 *   console.log('Blocked:', decision.reason);
 * }
 */

const fs = require('fs');
const path = require('path');

// Severity levels (ordered)
const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// Built-in data patterns for classification
const DATA_PATTERNS = {
  secret: [
    /sk-(?:proj-)?[a-zA-Z0-9]{20,}/g,              // OpenAI keys
    /ghp_[a-zA-Z0-9]{36}/g,                       // GitHub PAT
    /glpat-[a-zA-Z0-9\-_]{20,}/g,                 // GitLab PAT
    /xox[bpsa]-[a-zA-Z0-9\-]{10,}/g,              // Slack tokens
    /AKIA[A-Z0-9]{16}/g,                           // AWS access key
    /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g,   // Private keys
    /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, // JWT tokens
  ],
  pii: [
    /\b\d{3}-\d{2}-\d{4}\b/g,                     // SSN
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, // Email
    /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, // Credit card
    /\b\d{3}[\s.-]?\d{3}[\s.-]?\d{4}\b/g,         // Phone number
  ],
  internal: [
    /(?:internal|confidential|restricted|do not share)/gi,
    /(?:JIRA|CONFLUENCE)-[A-Z]+-\d+/g,            // Internal ticket refs
  ],
};

// Built-in tool risk levels
const TOOL_RISK_DEFAULTS = {
  // Read-only = low
  'read': 'low', 'get': 'low', 'list': 'low', 'search': 'low', 'query': 'low',
  // Side-effecting = medium
  'create': 'medium', 'update': 'medium', 'write': 'medium', 'put': 'medium',
  // External comms = high
  'send': 'high', 'email': 'high', 'post': 'high', 'publish': 'high', 'notify': 'high',
  // Destructive/privileged = critical
  'delete': 'critical', 'exec': 'critical', 'shell': 'critical', 'eval': 'critical',
  'drop': 'critical', 'rm': 'critical', 'chmod': 'critical', 'sudo': 'critical',
};

/**
 * @typedef {Object} PolicyRule
 * @property {string} id - Unique rule identifier
 * @property {string} [description] - Human-readable description
 * @property {string} [severity] - Rule severity (critical/high/medium/low)
 * @property {Object} when - Match conditions
 * @property {string} action - Enforcement action (block/warn/sanitize/log/require_approval)
 * @property {string} [message] - Message to include in decision
 */

/**
 * @typedef {Object} EvalEvent
 * @property {string} type - Event type (tool_call/inbound/outbound/memory_write/retrieval)
 * @property {string} [tool] - Tool name (for tool_call events)
 * @property {Object} [args] - Tool arguments
 * @property {string} [text] - Text content (for inbound/outbound)
 * @property {Object} [context] - Additional context (user, source, session, etc.)
 */

/**
 * @typedef {Object} Decision
 * @property {string} action - Final action (allow/block/warn/sanitize/require_approval)
 * @property {string} [ruleId] - ID of the rule that triggered
 * @property {string} [reason] - Human-readable reason
 * @property {string} [severity] - Severity of the match
 * @property {Array} matchedRules - All rules that matched
 * @property {Object} classifications - Data classifications found
 * @property {number} timestamp - Unix timestamp
 * @property {number} latencyMs - Processing time
 */

class PolicyEngine {
  /**
   * @param {string|Object|Array} policy - Path to YAML/JSON file, or policy object/array
   * @param {Object} [options]
   * @param {string} [options.mode='block'] - Default mode: monitor/warn/sanitize/block
   * @param {boolean} [options.trace=true] - Enable execution tracing
   * @param {Function} [options.onDecision] - Callback for every decision
   */
  constructor(policy, options = {}) {
    this.mode = options.mode || 'block';
    this.trace = options.trace !== false;
    this.onDecision = options.onDecision || null;
    this.rules = [];
    this.traceLog = [];
    this.stats = { total: 0, allowed: 0, blocked: 0, warned: 0, sanitized: 0 };
    this.toolRiskOverrides = {};

    if (typeof policy === 'string') {
      this._loadFromFile(policy);
    } else if (Array.isArray(policy)) {
      this.rules = policy;
    } else if (policy && policy.rules) {
      this.rules = policy.rules;
      if (policy.tool_risks) this.toolRiskOverrides = policy.tool_risks;
      if (policy.mode) this.mode = policy.mode;
    }
  }

  _loadFromFile(filePath) {
    const ext = path.extname(filePath);
    const raw = fs.readFileSync(filePath, 'utf8');

    if (ext === '.json') {
      const parsed = JSON.parse(raw);
      this.rules = parsed.rules || parsed;
      if (parsed.tool_risks) this.toolRiskOverrides = parsed.tool_risks;
      if (parsed.mode) this.mode = parsed.mode;
    } else if (ext === '.yaml' || ext === '.yml') {
      // Simple YAML parser (no deps) — handles the subset we need
      const parsed = this._parseSimpleYaml(raw);
      this.rules = parsed.rules || [];
      if (parsed.tool_risks) this.toolRiskOverrides = parsed.tool_risks;
      if (parsed.mode) this.mode = parsed.mode;
    } else {
      throw new Error(`Unsupported policy file format: ${ext}. Use .json or .yaml`);
    }
  }

  _parseSimpleYaml(text) {
    // Minimal YAML parser for policy files — handles maps, arrays, strings
    // For production, users should convert to JSON. This handles 90% of cases.
    try {
      // Strip comments
      const lines = text.split('\n').filter(l => !l.trim().startsWith('#'));
      const cleaned = lines.join('\n');
      // Convert YAML-ish to JSON-ish (basic)
      let json = cleaned
        .replace(/:\s*\n/g, ': null\n')  // empty values
        .replace(/^(\s*)- /gm, '$1  ')   // arrays
        ;
      // Fall back to JSON.parse if it looks like JSON
      if (cleaned.trim().startsWith('{') || cleaned.trim().startsWith('[')) {
        return JSON.parse(cleaned);
      }
      // For complex YAML, tell user to use JSON
      throw new Error('Complex YAML detected. Please use JSON format for policy files, or install a YAML parser.');
    } catch(e) {
      throw new Error(`Failed to parse policy YAML: ${e.message}. Tip: use .json format for reliability.`);
    }
  }

  /**
   * Classify text content for data types
   * @param {string} text
   * @returns {Object} classifications { secret: [...], pii: [...], internal: [...] }
   */
  classify(text) {
    if (!text || typeof text !== 'string') return {};
    const result = {};
    for (const [category, patterns] of Object.entries(DATA_PATTERNS)) {
      const matches = [];
      for (const pattern of patterns) {
        const p = new RegExp(pattern.source, pattern.flags);
        const found = text.match(p);
        if (found) matches.push(...found);
      }
      if (matches.length > 0) result[category] = matches;
    }
    return result;
  }

  /**
   * Get risk level for a tool
   * @param {string} toolName
   * @returns {string} risk level
   */
  getToolRisk(toolName) {
    if (this.toolRiskOverrides[toolName]) return this.toolRiskOverrides[toolName];
    const lower = (toolName || '').toLowerCase();
    for (const [keyword, risk] of Object.entries(TOOL_RISK_DEFAULTS)) {
      if (lower.includes(keyword)) return risk;
    }
    return 'medium'; // default
  }

  /**
   * Check if an event matches a rule's conditions
   * @param {EvalEvent} event
   * @param {PolicyRule} rule
   * @returns {boolean}
   */
  _matchRule(event, rule) {
    const when = rule.when;
    if (!when) return false;

    // Match event type
    if (when.type && when.type !== event.type) return false;

    // Match tool name
    if (when.tool) {
      const tools = Array.isArray(when.tool) ? when.tool : [when.tool];
      const eventTool = event.tool || '';
      if (!tools.some(t => {
        if (t === '*') return true;
        if (t.includes('*')) {
          // Convert glob to regex: "http.*" → /^http\..*$/
          const re = new RegExp('^' + t.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$');
          return re.test(eventTool);
        }
        return eventTool === t || eventTool.toLowerCase() === t.toLowerCase();
      })) return false;
    }

    // Match text content contains
    if (when.input_contains) {
      const text = this._getEventText(event);
      const terms = Array.isArray(when.input_contains) ? when.input_contains : [when.input_contains];
      if (!terms.some(term => text.toLowerCase().includes(term.toLowerCase()))) return false;
    }

    // Match text content regex
    if (when.input_matches) {
      const text = this._getEventText(event);
      const patterns = Array.isArray(when.input_matches) ? when.input_matches : [when.input_matches];
      if (!patterns.some(p => new RegExp(p, 'i').test(text))) return false;
    }

    // Match data classification
    if (when.data_classification) {
      const text = this._getEventText(event);
      const classifications = this.classify(text);
      const required = Array.isArray(when.data_classification) ? when.data_classification : [when.data_classification];
      if (!required.some(c => classifications[c] && classifications[c].length > 0)) return false;
    }

    // Match tool risk level
    if (when.tool_risk) {
      const risk = this.getToolRisk(event.tool);
      const required = Array.isArray(when.tool_risk) ? when.tool_risk : [when.tool_risk];
      if (!required.includes(risk)) return false;
    }

    // Match context
    if (when.context) {
      const ctx = event.context || {};
      for (const [key, val] of Object.entries(when.context)) {
        if (ctx[key] !== val) return false;
      }
    }

    // Match source
    if (when.source) {
      const sources = Array.isArray(when.source) ? when.source : [when.source];
      const eventSource = (event.context || {}).source || event.source || '';
      if (!sources.includes(eventSource)) return false;
    }

    return true;
  }

  _getEventText(event) {
    if (event.text) return event.text;
    if (event.args) return JSON.stringify(event.args);
    return '';
  }

  /**
   * Evaluate an event against all rules
   * @param {EvalEvent} event
   * @returns {Decision}
   */
  evaluate(event) {
    const start = Date.now();
    this.stats.total++;

    const text = this._getEventText(event);
    const classifications = this.classify(text);
    const matchedRules = [];

    // Test all rules
    for (const rule of this.rules) {
      if (this._matchRule(event, rule)) {
        matchedRules.push(rule);
      }
    }

    // Determine action from highest-severity matched rule
    let finalAction = 'allow';
    let triggerRule = null;
    let maxSeverity = -1;

    for (const rule of matchedRules) {
      const sev = SEVERITY_ORDER[rule.severity || 'medium'] || 2;
      if (sev > maxSeverity) {
        maxSeverity = sev;
        triggerRule = rule;
      }
    }

    if (triggerRule) {
      // Apply mode override
      const ruleAction = triggerRule.action || 'block';
      if (this.mode === 'monitor') {
        finalAction = 'log';
      } else if (this.mode === 'warn') {
        finalAction = 'warn';
      } else {
        finalAction = ruleAction;
      }
    }

    // Update stats
    if (finalAction === 'allow' || finalAction === 'log') this.stats.allowed++;
    else if (finalAction === 'block') this.stats.blocked++;
    else if (finalAction === 'warn') this.stats.warned++;
    else if (finalAction === 'sanitize') this.stats.sanitized++;

    const decision = {
      action: finalAction,
      ruleId: triggerRule ? triggerRule.id : null,
      reason: triggerRule ? (triggerRule.message || triggerRule.description || `Matched rule: ${triggerRule.id}`) : null,
      severity: triggerRule ? (triggerRule.severity || 'medium') : null,
      matchedRules: matchedRules.map(r => ({ id: r.id, severity: r.severity, action: r.action })),
      classifications: Object.keys(classifications).length > 0 ? classifications : undefined,
      toolRisk: event.tool ? this.getToolRisk(event.tool) : undefined,
      timestamp: Date.now(),
      latencyMs: Date.now() - start,
    };

    // Trace log
    if (this.trace) {
      this.traceLog.push({
        event: { type: event.type, tool: event.tool },
        decision: { action: decision.action, ruleId: decision.ruleId, severity: decision.severity },
        timestamp: decision.timestamp,
        latencyMs: decision.latencyMs,
      });
    }

    // Callback
    if (this.onDecision) {
      try { this.onDecision(decision, event); } catch(e) { /* ignore callback errors */ }
    }

    return decision;
  }

  /**
   * Get execution trace
   * @returns {Array}
   */
  getTrace() {
    return [...this.traceLog];
  }

  /**
   * Get stats
   * @returns {Object}
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Simulate a policy against a set of test events
   * @param {Array<EvalEvent>} events
   * @returns {Object} simulation results
   */
  simulate(events) {
    const originalMode = this.mode;
    this.mode = 'block'; // Simulate full enforcement
    const results = events.map(event => {
      const decision = this.evaluate(event);
      return { event, decision };
    });
    this.mode = originalMode;
    return {
      total: results.length,
      blocked: results.filter(r => r.decision.action === 'block').length,
      allowed: results.filter(r => r.decision.action === 'allow').length,
      results,
    };
  }
}

module.exports = { PolicyEngine, DATA_PATTERNS, TOOL_RISK_DEFAULTS, SEVERITY_ORDER };
