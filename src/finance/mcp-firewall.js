/**
 * MCP Tool Firewall — Intercepts MCP tool calls to financial services
 * 
 * Sits between the AI agent and MCP servers (QuickBooks, Xero, Stripe, etc.)
 * to enforce security policies on financial tool usage.
 * 
 * Key insight: Companies won't trust AI agents to WRITE to financial systems yet.
 * The real risk is READ-SIDE LEAKAGE — agent pulls sensitive financial data
 * via MCP, then leaks it through prompt injection or exfiltration.
 * 
 * Features:
 * - Read-only mode enforcement (block all write/create/update/delete operations)
 * - Field-level redaction on MCP tool responses (SSN, account numbers, etc.)
 * - Tool allowlisting (only approved MCP tools can be called)
 * - Call rate limiting per tool
 * - Full audit trail of every MCP tool invocation
 * - Sensitive field masking in responses before they reach the agent
 * 
 * @module clawmoat/finance/mcp-firewall
 * @example
 * const { McpFirewall } = require('clawmoat/finance/mcp-firewall');
 * const firewall = new McpFirewall({
 *   mode: 'read-only',
 *   redactFields: ['ssn', 'tax_id', 'bank_account', 'routing_number'],
 *   allowedTools: ['get_invoices', 'get_profit_loss', 'get_balance_sheet'],
 *   onBlock: (event) => console.log('Blocked:', event),
 * });
 * 
 * // Wrap MCP tool call
 * const result = firewall.intercept({
 *   tool: 'create_invoice',
 *   args: { amount: 5000, customer: 'Acme Corp' },
 *   server: 'quickbooks-mcp',
 * });
 * // result.blocked = true (write operation in read-only mode)
 */

const crypto = require('crypto');

// ─── Write Operation Patterns ───────────────────────────────────

/** Tool name patterns that indicate write operations */
const WRITE_PATTERNS = [
  /^create[_-]/i,
  /^add[_-]/i,
  /^update[_-]/i,
  /^edit[_-]/i,
  /^modify[_-]/i,
  /^delete[_-]/i,
  /^remove[_-]/i,
  /^send[_-]/i,
  /^post[_-]/i,
  /^submit[_-]/i,
  /^approve[_-]/i,
  /^void[_-]/i,
  /^cancel[_-]/i,
  /^refund[_-]/i,
  /^transfer[_-]/i,
  /^pay[_-]/i,
  /^charge[_-]/i,
  /^issue[_-]/i,
  /^record[_-]/i,
  /^close[_-]/i,
  /^batch[_-]/i,
  /^import[_-]/i,
  /^set[_-]/i,
  /^assign[_-]/i,
  /^link[_-]/i,
  /^unlink[_-]/i,
  /^archive[_-]/i,
  /^restore[_-]/i,
  /^merge[_-]/i,
];

/** Known financial MCP server identifiers */
const KNOWN_FINANCIAL_SERVERS = [
  { pattern: /quickbooks/i, label: 'QuickBooks', category: 'accounting' },
  { pattern: /xero/i, label: 'Xero', category: 'accounting' },
  { pattern: /freshbooks/i, label: 'FreshBooks', category: 'accounting' },
  { pattern: /stripe/i, label: 'Stripe', category: 'payment' },
  { pattern: /plaid/i, label: 'Plaid', category: 'banking' },
  { pattern: /square/i, label: 'Square', category: 'payment' },
  { pattern: /paypal/i, label: 'PayPal', category: 'payment' },
  { pattern: /braintree/i, label: 'Braintree', category: 'payment' },
  { pattern: /coinbase/i, label: 'Coinbase', category: 'crypto' },
  { pattern: /mercury/i, label: 'Mercury', category: 'banking' },
  { pattern: /wise/i, label: 'Wise', category: 'transfer' },
  { pattern: /wave/i, label: 'Wave', category: 'accounting' },
  { pattern: /gusto/i, label: 'Gusto', category: 'payroll' },
  { pattern: /rippling/i, label: 'Rippling', category: 'payroll' },
  { pattern: /bill\.com/i, label: 'Bill.com', category: 'payment' },
];

/** Sensitive field patterns to redact in MCP responses */
const DEFAULT_SENSITIVE_FIELDS = [
  // Identity
  { pattern: /ssn|social_security|social_sec/i, label: 'SSN', replacement: '***-**-****' },
  { pattern: /tax_id|^tin$|^ein$|employer_id/i, label: 'Tax ID', replacement: '**-*******' },
  { pattern: /^sin$|social_insurance/i, label: 'SIN', replacement: '***-***-***' },
  
  // Banking
  { pattern: /account_num|acct_num|bank_account|account_number/i, label: 'Account Number', replacement: '****XXXX' },
  { pattern: /routing|aba_num|routing_number/i, label: 'Routing Number', replacement: '*********' },
  { pattern: /iban/i, label: 'IBAN', replacement: '****XXXX' },
  { pattern: /swift|bic/i, label: 'SWIFT/BIC', replacement: '****XXXX' },
  
  // Payment
  { pattern: /card_num|credit_card|cc_num|card_number/i, label: 'Card Number', replacement: '****-****-****-XXXX' },
  { pattern: /cvv|cvc|security_code/i, label: 'CVV', replacement: '***' },
  { pattern: /^pin$|^pin_code$/i, label: 'PIN', replacement: '****' },
  
  // Auth
  { pattern: /api_key|secret_key|access_token|refresh_token/i, label: 'API Key', replacement: '[REDACTED]' },
  { pattern: /password|passwd/i, label: 'Password', replacement: '[REDACTED]' },
  { pattern: /oauth_token|bearer/i, label: 'OAuth Token', replacement: '[REDACTED]' },
  
  // Personal
  { pattern: /date_of_birth|dob|birth_date/i, label: 'DOB', replacement: '****-**-**' },
  { pattern: /driver_license|dl_number/i, label: 'Driver License', replacement: '[REDACTED]' },
  { pattern: /passport_num/i, label: 'Passport', replacement: '[REDACTED]' },
];

// ─── McpFirewall Class ──────────────────────────────────────────

class McpFirewall {
  /**
   * @param {Object} options
   * @param {string} [options.mode='read-only'] - 'read-only' | 'read-write' | 'audit-only'
   * @param {string[]} [options.allowedTools] - Allowlist of tool names (null = all allowed)
   * @param {string[]} [options.blockedTools] - Explicit blocklist of tool names
   * @param {Object[]} [options.redactFields] - Additional sensitive field patterns
   * @param {boolean} [options.redactResponses=true] - Auto-redact sensitive fields in responses
   * @param {number} [options.rateLimit=60] - Max calls per tool per minute
   * @param {Function} [options.onBlock] - Called when a tool call is blocked
   * @param {Function} [options.onRedact] - Called when fields are redacted
   * @param {Function} [options.onCall] - Called on every tool call (audit)
   */
  constructor(options = {}) {
    this.mode = options.mode || 'read-only';
    this.allowedTools = options.allowedTools ? new Set(options.allowedTools.map(t => t.toLowerCase())) : null;
    this.blockedTools = new Set((options.blockedTools || []).map(t => t.toLowerCase()));
    this.redactResponses = options.redactResponses !== false;
    this.rateLimit = options.rateLimit ?? 60;
    this.onBlock = options.onBlock || null;
    this.onRedact = options.onRedact || null;
    this.onCall = options.onCall || null;

    // Merge custom sensitive fields
    this.sensitiveFields = [...DEFAULT_SENSITIVE_FIELDS];
    if (options.redactFields) {
      for (const f of options.redactFields) {
        if (typeof f === 'string') {
          this.sensitiveFields.push({
            pattern: new RegExp(`^${f}$`, 'i'),
            label: f,
            replacement: '[REDACTED]',
          });
        } else {
          this.sensitiveFields.push(f);
        }
      }
    }

    // State
    this.auditLog = [];
    this.callCounts = new Map(); // tool -> [{timestamp}]
    this.stats = { total: 0, allowed: 0, blocked: 0, redacted: 0 };
  }

  // ─── Core: Intercept a Tool Call ──────────────────────────────

  /**
   * Intercept and evaluate an MCP tool call before execution.
   * @param {Object} call
   * @param {string} call.tool - Tool name (e.g., 'get_invoices', 'create_invoice')
   * @param {Object} [call.args] - Tool arguments
   * @param {string} [call.server] - MCP server identifier
   * @param {string} [call.initiator] - What triggered the call
   * @returns {Object} { allowed, blocked, reason, callId, serverInfo }
   */
  intercept(call) {
    const callId = crypto.randomBytes(6).toString('hex');
    const toolLower = (call.tool || '').toLowerCase();
    const now = Date.now();

    this.stats.total++;

    const result = {
      callId,
      tool: call.tool,
      server: call.server || 'unknown',
      allowed: false,
      blocked: false,
      reason: '',
      serverInfo: this._identifyServer(call.server),
    };

    const auditEntry = {
      callId,
      timestamp: now,
      tool: call.tool,
      server: call.server,
      args: this._sanitizeArgs(call.args),
      initiator: call.initiator || 'agent',
      decision: 'pending',
      reason: '',
    };

    // 1. Check explicit blocklist
    if (this.blockedTools.has(toolLower)) {
      result.blocked = true;
      result.reason = `Tool "${call.tool}" is explicitly blocked`;
      auditEntry.decision = 'blocked';
      auditEntry.reason = result.reason;
      this.stats.blocked++;
      this._emitBlock(result, call);
      this.auditLog.push(auditEntry);
      if (this.onCall) this.onCall(auditEntry);
      return result;
    }

    // 2. Check allowlist
    if (this.allowedTools && !this.allowedTools.has(toolLower)) {
      result.blocked = true;
      result.reason = `Tool "${call.tool}" is not in allowlist`;
      auditEntry.decision = 'blocked';
      auditEntry.reason = result.reason;
      this.stats.blocked++;
      this._emitBlock(result, call);
      this.auditLog.push(auditEntry);
      if (this.onCall) this.onCall(auditEntry);
      return result;
    }

    // 3. Check read-only mode
    if (this.mode === 'read-only') {
      const isWrite = WRITE_PATTERNS.some(p => p.test(call.tool));
      if (isWrite) {
        result.blocked = true;
        result.reason = `Write operation "${call.tool}" blocked in read-only mode`;
        auditEntry.decision = 'blocked';
        auditEntry.reason = result.reason;
        this.stats.blocked++;
        this._emitBlock(result, call);
        this.auditLog.push(auditEntry);
        if (this.onCall) this.onCall(auditEntry);
        return result;
      }
    }

    // 4. Rate limiting
    if (this.rateLimit > 0) {
      const key = toolLower;
      const calls = this.callCounts.get(key) || [];
      const recent = calls.filter(t => t > now - 60000);
      if (recent.length >= this.rateLimit) {
        result.blocked = true;
        result.reason = `Rate limit exceeded for "${call.tool}" (${recent.length}/${this.rateLimit} per minute)`;
        auditEntry.decision = 'rate_limited';
        auditEntry.reason = result.reason;
        this.stats.blocked++;
        this._emitBlock(result, call);
        this.auditLog.push(auditEntry);
        if (this.onCall) this.onCall(auditEntry);
        return result;
      }
      recent.push(now);
      this.callCounts.set(key, recent);
    }

    // 5. Allowed
    result.allowed = true;
    result.reason = this.mode === 'audit-only' ? 'Audit-only mode (all calls allowed)' : 'Passed all checks';
    auditEntry.decision = 'allowed';
    auditEntry.reason = result.reason;
    this.stats.allowed++;

    this.auditLog.push(auditEntry);
    if (this.onCall) this.onCall(auditEntry);

    return result;
  }

  // ─── Redact Response ──────────────────────────────────────────

  /**
   * Redact sensitive fields from an MCP tool response before it reaches the agent.
   * Works recursively on nested objects/arrays.
   * @param {*} response - The MCP tool response (object, array, or primitive)
   * @param {Object} [options]
   * @param {string} [options.callId] - Link to the intercept call
   * @returns {Object} { redacted, fieldCount, fields }
   */
  redactResponse(response, options = {}) {
    if (!this.redactResponses) {
      return { redacted: response, fieldCount: 0, fields: [] };
    }

    const redactedFields = [];
    const redacted = this._deepRedact(response, redactedFields, '');

    if (redactedFields.length > 0) {
      this.stats.redacted += redactedFields.length;
      if (this.onRedact) {
        this.onRedact({
          callId: options.callId,
          fieldCount: redactedFields.length,
          fields: redactedFields,
        });
      }
      this.auditLog.push({
        timestamp: Date.now(),
        action: 'redact_response',
        callId: options.callId,
        fieldCount: redactedFields.length,
        fields: redactedFields.map(f => f.path + ' → ' + f.label),
      });
    }

    return {
      redacted,
      fieldCount: redactedFields.length,
      fields: redactedFields,
    };
  }

  /** @private Recursively redact sensitive fields */
  _deepRedact(obj, findings, path) {
    if (obj === null || obj === undefined) return obj;
    if (typeof obj !== 'object') return obj;

    if (Array.isArray(obj)) {
      return obj.map((item, i) => this._deepRedact(item, findings, `${path}[${i}]`));
    }

    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      const fieldPath = path ? `${path}.${key}` : key;
      const match = this.sensitiveFields.find(f => f.pattern.test(key));

      if (match && value !== null && value !== undefined) {
        findings.push({ path: fieldPath, label: match.label, original_type: typeof value });
        result[key] = match.replacement;
      } else if (typeof value === 'object') {
        result[key] = this._deepRedact(value, findings, fieldPath);
      } else {
        result[key] = value;
      }
    }
    return result;
  }

  // ─── Convenience: Intercept + Redact ──────────────────────────

  /**
   * Full pipeline: intercept call, if allowed execute callback, redact response.
   * @param {Object} call - Same as intercept()
   * @param {Function} executor - async fn(call) that executes the actual MCP call
   * @returns {Object} { allowed, blocked, response, redaction, callId }
   */
  async guard(call, executor) {
    const decision = this.intercept(call);
    if (decision.blocked) {
      return { ...decision, response: null, redaction: null };
    }

    const rawResponse = await executor(call);
    const redaction = this.redactResponse(rawResponse, { callId: decision.callId });

    return {
      ...decision,
      response: redaction.redacted,
      redaction: {
        fieldCount: redaction.fieldCount,
        fields: redaction.fields,
      },
    };
  }

  // ─── Tool Discovery ───────────────────────────────────────────

  /**
   * Analyze a list of MCP tools and classify them as read/write/dangerous.
   * Useful for auto-configuring allowlists.
   * @param {string[]} tools - Array of tool names from MCP server
   * @returns {Object} { read, write, unknown, recommended_allowlist }
   */
  classifyTools(tools) {
    const read = [];
    const write = [];
    const unknown = [];

    for (const tool of tools) {
      const isWrite = WRITE_PATTERNS.some(p => p.test(tool));
      const isRead = /^(get|list|query|search|find|fetch|read|show|describe|count|check|verify|report|export|download)/i.test(tool);

      if (isWrite) {
        write.push(tool);
      } else if (isRead) {
        read.push(tool);
      } else {
        unknown.push(tool);
      }
    }

    return {
      read,
      write,
      unknown,
      recommended_allowlist: read,
      summary: `${read.length} read, ${write.length} write, ${unknown.length} unknown of ${tools.length} total`,
    };
  }

  // ─── Reports ──────────────────────────────────────────────────

  /** Get audit summary */
  getAuditSummary() {
    return {
      mode: this.mode,
      ...this.stats,
      recentCalls: this.auditLog.slice(-20),
      topTools: this._getTopTools(),
    };
  }

  /** Get all blocked calls */
  getBlockedCalls() {
    return this.auditLog.filter(e => e.decision === 'blocked' || e.decision === 'rate_limited');
  }

  /** Reset state */
  reset() {
    this.auditLog = [];
    this.callCounts.clear();
    this.stats = { total: 0, allowed: 0, blocked: 0, redacted: 0 };
  }

  // ─── Private helpers ──────────────────────────────────────────

  _identifyServer(server) {
    if (!server) return null;
    const match = KNOWN_FINANCIAL_SERVERS.find(s => s.pattern.test(server));
    return match ? { label: match.label, category: match.category } : null;
  }

  _sanitizeArgs(args) {
    if (!args || typeof args !== 'object') return args;
    const sanitized = {};
    for (const [k, v] of Object.entries(args)) {
      const isSensitive = this.sensitiveFields.some(f => f.pattern.test(k));
      sanitized[k] = isSensitive ? '[REDACTED]' : v;
    }
    return sanitized;
  }

  _emitBlock(result, call) {
    if (this.onBlock) {
      this.onBlock({
        callId: result.callId,
        tool: call.tool,
        server: call.server,
        reason: result.reason,
        timestamp: Date.now(),
      });
    }
  }

  _getTopTools() {
    const counts = {};
    for (const entry of this.auditLog) {
      if (entry.tool) counts[entry.tool] = (counts[entry.tool] || 0) + 1;
    }
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([tool, count]) => ({ tool, count }));
  }
}

module.exports = {
  McpFirewall,
  WRITE_PATTERNS,
  KNOWN_FINANCIAL_SERVERS,
  DEFAULT_SENSITIVE_FIELDS,
};
