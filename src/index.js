/**
 * ClawMoat — Security moat for AI agents
 * 
 * Main API: scan messages, audit tool calls, check for secrets.
 */

const { scanPromptInjection } = require('./scanners/prompt-injection');
const { scanJailbreak } = require('./scanners/jailbreak');
const { scanSecrets } = require('./scanners/secrets');
const { evaluateToolCall } = require('./policies/engine');
const { SecurityLogger } = require('./utils/logger');
const { loadConfig } = require('./utils/config');

class ClawMoat {
  constructor(opts = {}) {
    this.config = opts.config || loadConfig(opts.configPath);
    this.logger = new SecurityLogger({
      logFile: opts.logFile,
      quiet: opts.quiet,
      minSeverity: this.config.alerts?.severity_threshold,
      webhook: this.config.alerts?.webhook,
      onEvent: opts.onEvent,
    });
    this.stats = { scanned: 0, blocked: 0, warnings: 0 };
  }

  /**
   * Scan inbound text (messages, emails, web content, tool output)
   * Returns { safe, findings[], severity, action }
   */
  scanInbound(text, opts = {}) {
    this.stats.scanned++;
    const results = { findings: [], safe: true, severity: null, action: 'allow' };

    // Prompt injection scan
    if (this.config.detection?.prompt_injection !== false) {
      const pi = scanPromptInjection(text, opts);
      if (!pi.clean) {
        results.findings.push(...pi.findings);
        results.safe = false;
      }
    }

    // Jailbreak scan
    if (this.config.detection?.jailbreak !== false) {
      const jb = scanJailbreak(text);
      if (!jb.clean) {
        results.findings.push(...jb.findings);
        results.safe = false;
      }
    }

    // Determine action
    if (!results.safe) {
      const maxSev = this._maxSeverity(results.findings);
      results.severity = maxSev;
      results.action = maxSev === 'critical' ? 'block' : maxSev === 'high' ? 'warn' : 'log';

      if (results.action === 'block') this.stats.blocked++;
      if (results.action === 'warn') this.stats.warnings++;

      this.logger.log({
        type: 'inbound_threat',
        severity: maxSev,
        message: `${results.findings.length} threat(s) detected in ${opts.context || 'message'}`,
        details: {
          findings: results.findings.map(f => ({ type: f.type, subtype: f.subtype, severity: f.severity })),
          source: opts.context,
          textPreview: text.substring(0, 100),
        },
      });
    }

    return results;
  }

  /**
   * Scan outbound text for secrets/PII leakage
   */
  scanOutbound(text, opts = {}) {
    this.stats.scanned++;
    const results = { findings: [], safe: true, severity: null, action: 'allow' };

    // Secret scanning
    if (this.config.detection?.secret_scanning !== false) {
      const secrets = scanSecrets(text, { direction: 'outbound', ...opts });
      if (!secrets.clean) {
        results.findings.push(...secrets.findings);
        results.safe = false;
      }
    }

    if (!results.safe) {
      const maxSev = this._maxSeverity(results.findings);
      results.severity = maxSev;
      results.action = maxSev === 'critical' ? 'block' : 'warn';

      this.stats.blocked++;
      this.logger.log({
        type: 'outbound_leak',
        severity: maxSev,
        message: `Secret/credential detected in outbound ${opts.context || 'message'}`,
        details: {
          findings: results.findings.map(f => ({ type: f.type, subtype: f.subtype, severity: f.severity, matched: f.matched })),
        },
      });
    }

    return results;
  }

  /**
   * Evaluate a tool call against policies
   */
  evaluateTool(tool, args) {
    const result = evaluateToolCall(tool, args, this.config.policies || {});

    if (result.decision !== 'allow') {
      const severity = result.severity || 'medium';
      if (result.decision === 'deny') this.stats.blocked++;
      if (result.decision === 'warn') this.stats.warnings++;

      this.logger.log({
        type: 'tool_policy',
        severity,
        message: `Tool ${tool}: ${result.decision} — ${result.reason}`,
        details: { tool, decision: result.decision, ...result },
      });
    }

    return result;
  }

  /**
   * Full scan: check text as both inbound threat AND outbound leak
   */
  scan(text, opts = {}) {
    const inbound = this.scanInbound(text, opts);
    const outbound = this.scanOutbound(text, opts);

    return {
      safe: inbound.safe && outbound.safe,
      inbound,
      outbound,
      findings: [...inbound.findings, ...outbound.findings],
    };
  }

  /**
   * Get security event log
   */
  getEvents(filter) {
    return this.logger.getEvents(filter);
  }

  /**
   * Get summary stats
   */
  getSummary() {
    return {
      ...this.stats,
      events: this.logger.summary(),
    };
  }

  _maxSeverity(findings) {
    const rank = { low: 0, medium: 1, high: 2, critical: 3 };
    return findings.reduce(
      (max, f) => (rank[f.severity] || 0) > (rank[max] || 0) ? f.severity : max,
      'low'
    );
  }
}

module.exports = ClawMoat;
module.exports.ClawMoat = ClawMoat;
module.exports.scanPromptInjection = scanPromptInjection;
module.exports.scanJailbreak = scanJailbreak;
module.exports.scanSecrets = scanSecrets;
module.exports.evaluateToolCall = evaluateToolCall;
