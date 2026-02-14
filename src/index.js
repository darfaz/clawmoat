/**
 * ClawMoat — Security moat for AI agents
 * 
 * Main API: scan messages, audit tool calls, check for secrets.
 */

const { scanPromptInjection } = require('./scanners/prompt-injection');
const { scanJailbreak } = require('./scanners/jailbreak');
const { scanSecrets } = require('./scanners/secrets');
const { scanPII } = require('./scanners/pii');
const { scanUrls } = require('./scanners/urls');
const { scanMemoryPoison } = require('./scanners/memory-poison');
const { scanExfiltration } = require('./scanners/exfiltration');
const { scanSkill, scanSkillContent } = require('./scanners/supply-chain');
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

    // URL scan
    if (this.config.detection?.url_scanning !== false) {
      const urls = scanUrls(text, opts);
      if (!urls.clean) {
        results.findings.push(...urls.findings);
        results.safe = false;
      }
    }

    // Memory poisoning scan
    if (this.config.detection?.memory_poison !== false) {
      const mp = scanMemoryPoison(text, opts);
      if (!mp.clean) {
        results.findings.push(...mp.findings);
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

    // PII scanning
    if (this.config.detection?.pii !== false) {
      const pii = scanPII(text, opts);
      if (!pii.clean) {
        results.findings.push(...pii.findings);
        results.safe = false;
      }
    }

    // Exfiltration scanning
    if (this.config.detection?.exfiltration !== false) {
      const exfil = scanExfiltration(text, opts);
      if (!exfil.clean) {
        results.findings.push(...exfil.findings);
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

  /**
   * Scan a skill for supply chain threats
   */
  scanSkill(skillPath) {
    const result = scanSkill(skillPath);

    if (!result.clean) {
      const maxSev = this._maxSeverity(result.findings);
      this.logger.log({
        type: 'supply_chain_threat',
        severity: maxSev,
        message: `${result.findings.length} issue(s) in skill: ${skillPath}`,
        details: { findings: result.findings },
      });
    }

    return result;
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
module.exports.scanPII = scanPII;
module.exports.scanUrls = scanUrls;
module.exports.scanMemoryPoison = scanMemoryPoison;
module.exports.scanExfiltration = scanExfiltration;
module.exports.scanSkill = scanSkill;
module.exports.scanSkillContent = scanSkillContent;
module.exports.evaluateToolCall = evaluateToolCall;
