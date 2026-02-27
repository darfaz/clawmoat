/**
 * ClawMoat — Security moat for AI agents
 * 
 * Runtime protection against prompt injection, jailbreaks, tool misuse,
 * secret/PII leakage, data exfiltration, memory poisoning, and supply chain attacks.
 * 
 * @module clawmoat
 * @example
 * const ClawMoat = require('clawmoat');
 * const moat = new ClawMoat();
 * 
 * // Scan inbound message for injection/jailbreak threats
 * const result = moat.scanInbound(userMessage);
 * if (!result.safe) console.log('Threat detected:', result.findings);
 * 
 * // Scan outbound text for secret/PII leaks
 * const out = moat.scanOutbound(responseText);
 * 
 * // Evaluate a tool call against security policies
 * const policy = moat.evaluateTool('exec', { command: 'rm -rf /' });
 * if (policy.decision === 'deny') console.log('Blocked:', policy.reason);
 */

const { scanPromptInjection } = require('./scanners/prompt-injection');
const { scanJailbreak } = require('./scanners/jailbreak');
const { scanSecrets } = require('./scanners/secrets');
const { scanPII } = require('./scanners/pii');
const { scanUrls } = require('./scanners/urls');
const { scanMemoryPoison } = require('./scanners/memory-poison');
const { scanExfiltration } = require('./scanners/exfiltration');
const { scanExcessiveAgency } = require('./scanners/excessive-agency');
const { scanSkill, scanSkillContent } = require('./scanners/supply-chain');
const { evaluateToolCall } = require('./policies/engine');
const { HostGuardian, TIERS } = require('./guardian');
const { SecurityLogger } = require('./utils/logger');
const { loadConfig } = require('./utils/config');

/**
 * @typedef {Object} ScanFinding
 * @property {string} type - Finding category (e.g. 'prompt_injection', 'secret_detected', 'pii_detected')
 * @property {string} subtype - Specific detection pattern name
 * @property {string} severity - 'low' | 'medium' | 'high' | 'critical'
 * @property {string} [matched] - The matched text (may be redacted for secrets)
 * @property {number} [position] - Character position in the scanned text
 */

/**
 * @typedef {Object} ScanResult
 * @property {boolean} safe - true if no threats found
 * @property {ScanFinding[]} findings - Array of detected issues
 * @property {string|null} severity - Maximum severity across findings
 * @property {string} action - 'allow' | 'log' | 'warn' | 'block'
 */

/**
 * @typedef {Object} ToolDecision
 * @property {string} decision - 'allow' | 'deny' | 'warn' | 'review'
 * @property {string} tool - Tool name evaluated
 * @property {string} [reason] - Human-readable explanation
 * @property {string} [severity] - Severity of the policy violation
 */

/**
 * Main ClawMoat security scanner class.
 * Instantiate with optional config to scan text and evaluate tool calls.
 */
class ClawMoat {
  /**
   * Create a ClawMoat instance.
   * @param {Object} [opts] - Options
   * @param {Object} [opts.config] - Configuration object (overrides file-based config)
   * @param {string} [opts.configPath] - Path to clawmoat.yml config file
   * @param {string} [opts.logFile] - Path to write security event logs
   * @param {boolean} [opts.quiet] - Suppress console output
   * @param {Function} [opts.onEvent] - Callback for each security event
   */
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

    // Initialize Host Guardian if configured
    if (this.config.guardian) {
      this.guardian = new HostGuardian({
        mode: this.config.guardian.mode || 'standard',
        workspace: this.config.guardian.workspace,
        safeZones: this.config.guardian.safe_zones,
        forbiddenZones: this.config.guardian.forbidden_zones,
        logFile: opts.logFile,
        quiet: opts.quiet,
        onViolation: opts.onViolation,
      });
    }
  }

  /**
   * Create and return a Host Guardian instance for laptop-hosted agent security.
   * Can be used standalone without full ClawMoat config.
   * @param {Object} opts - Guardian options (mode, workspace, safeZones, etc.)
   * @returns {HostGuardian}
   */
  static createGuardian(opts = {}) {
    return new HostGuardian(opts);
  }

  /**
   * Scan inbound text for prompt injection, jailbreaks, suspicious URLs, and memory poisoning.
   * @param {string} text - Text to scan (message, email, web content, tool output)
   * @param {Object} [opts] - Options
   * @param {string} [opts.context] - Source context ('message' | 'email' | 'web' | 'tool_output')
   * @returns {ScanResult} Scan result with findings and recommended action
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

    // Excessive agency scan
    if (this.config.detection?.excessive_agency !== false) {
      const ea = scanExcessiveAgency(text, opts);
      if (!ea.clean) {
        results.findings.push(...ea.findings);
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
   * Scan outbound text for secrets, PII, and data exfiltration attempts.
   * @param {string} text - Outbound text to scan
   * @param {Object} [opts] - Options
   * @param {string} [opts.context] - Source context for logging
   * @returns {ScanResult} Scan result with findings and recommended action
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
   * Evaluate a tool call against security policies.
   * @param {string} tool - Tool name (e.g. 'exec', 'read', 'write', 'browser')
   * @param {Object} args - Tool arguments to evaluate
   * @returns {ToolDecision} Policy decision with explanation
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
   * Full bidirectional scan: check text as both inbound threat AND outbound leak.
   * @param {string} text - Text to scan
   * @param {Object} [opts] - Options passed to both scanInbound and scanOutbound
   * @returns {{ safe: boolean, inbound: ScanResult, outbound: ScanResult, findings: ScanFinding[] }}
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
   * Scan a skill directory or file for supply chain threats (malicious code patterns).
   * @param {string} skillPath - Path to skill directory or file
   * @returns {{ clean: boolean, findings: ScanFinding[], severity: string|null }}
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
module.exports.scanExcessiveAgency = scanExcessiveAgency;
module.exports.scanSkill = scanSkill;
module.exports.scanSkillContent = scanSkillContent;
module.exports.evaluateToolCall = evaluateToolCall;
module.exports.HostGuardian = HostGuardian;
module.exports.TIERS = TIERS;
module.exports.GatewayMonitor = require('./guardian/gateway-monitor').GatewayMonitor;
