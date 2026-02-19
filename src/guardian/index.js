/**
 * ClawMoat Host Guardian — Runtime Security for Laptop-Hosted AI Agents
 * 
 * The missing trust layer that makes running AI agents on your actual
 * laptop safe. Monitors filesystem access, command execution, network
 * egress, and enforces permission boundaries in real-time.
 * 
 * @module clawmoat/guardian
 * @example
 * const { HostGuardian } = require('clawmoat/guardian');
 * const guardian = new HostGuardian({
 *   mode: 'standard',           // 'paranoid' | 'standard' | 'permissive'
 *   workspace: '~/.openclaw/workspace',
 *   user: 'ildar',
 * });
 * 
 * // Check before every tool call
 * const verdict = guardian.check('read', { path: '~/.ssh/id_rsa' });
 * // => { allowed: false, reason: 'Protected zone: SSH keys', zone: 'forbidden', severity: 'critical' }
 * 
 * // Get audit trail
 * const log = guardian.audit();
 */

const path = require('path');
const os = require('os');
const { SecurityLogger } = require('../utils/logger');

// ─── Permission Tiers ───────────────────────────────────────────────
const TIERS = {
  /** Read-only observer: can read workspace files, nothing else */
  observer: {
    label: 'Observer',
    description: 'Read-only access to workspace. No shell, no writes, no network.',
    allowRead: 'workspace',
    allowWrite: false,
    allowExec: false,
    allowNetwork: false,
    allowBrowser: false,
  },
  /** Workspace worker: read/write workspace, limited safe commands */
  worker: {
    label: 'Workspace Worker',
    description: 'Read/write workspace. Safe commands only. No access outside workspace.',
    allowRead: 'workspace',
    allowWrite: 'workspace',
    allowExec: 'safe',
    allowNetwork: 'fetch-only',
    allowBrowser: true,
  },
  /** Standard: workspace + read system files, broader command access */
  standard: {
    label: 'Standard',
    description: 'Full workspace access. Can read system files. Most commands allowed. Forbidden zones enforced.',
    allowRead: 'system',
    allowWrite: 'workspace',
    allowExec: 'standard',
    allowNetwork: true,
    allowBrowser: true,
  },
  /** Full access: everything allowed, audit-only mode */
  full: {
    label: 'Full Access',
    description: 'Everything allowed. Forbidden zones still logged but not blocked. Audit trail only.',
    allowRead: true,
    allowWrite: true,
    allowExec: true,
    allowNetwork: true,
    allowBrowser: true,
  },
};

// ─── Forbidden Zones (always blocked except in 'full' mode) ─────────
const FORBIDDEN_ZONES = [
  { pattern: /^~?\/?\.ssh\b/i, label: 'SSH keys', severity: 'critical' },
  { pattern: /^~?\/?\.gnupg\b/i, label: 'GPG keys', severity: 'critical' },
  { pattern: /^~?\/?\.aws\b/i, label: 'AWS credentials', severity: 'critical' },
  { pattern: /^~?\/?\.gcloud\b/i, label: 'Google Cloud credentials', severity: 'critical' },
  { pattern: /^~?\/?\.azure\b/i, label: 'Azure credentials', severity: 'critical' },
  { pattern: /^~?\/?\.kube\b/i, label: 'Kubernetes config', severity: 'critical' },
  { pattern: /^~?\/?\.docker\b/i, label: 'Docker credentials', severity: 'high' },
  { pattern: /^~?\/?\.npmrc$/i, label: 'npm credentials', severity: 'high' },
  { pattern: /^~?\/?\.pypirc$/i, label: 'PyPI credentials', severity: 'high' },
  { pattern: /^~?\/?\.netrc$/i, label: 'Network credentials', severity: 'critical' },
  { pattern: /^~?\/?\.git-credentials$/i, label: 'Git credentials', severity: 'critical' },
  { pattern: /^~?\/?\.env(?:\.local|\.prod|\.production)?$/i, label: 'Environment secrets', severity: 'high' },
  { pattern: /^~?\/?\.config\/gcloud\b/i, label: 'Google Cloud config', severity: 'high' },
  { pattern: /^~?\/?\.config\/gh\b/i, label: 'GitHub CLI tokens', severity: 'high' },
  { pattern: /^\/etc\/shadow$/i, label: 'System passwords', severity: 'critical' },
  { pattern: /^\/etc\/sudoers/i, label: 'Sudo configuration', severity: 'critical' },
  { pattern: /^\/etc\/passwd$/i, label: 'System users', severity: 'medium' },
  { pattern: /(?:Cookies|Login Data|Web Data)$/i, label: 'Browser credentials', severity: 'critical' },
  { pattern: /\.(?:keychain|keychain-db)$/i, label: 'macOS Keychain', severity: 'critical' },
  { pattern: /(?:wallet\.dat|seed\.txt|mnemonic)/i, label: 'Crypto wallet', severity: 'critical' },
  { pattern: /^~?\/?\.password-store\b/i, label: 'Password store', severity: 'critical' },
  { pattern: /^~?\/?\.1password\b/i, label: '1Password data', severity: 'critical' },
  { pattern: /(?:KeePass|\.kdbx)$/i, label: 'KeePass database', severity: 'critical' },
];

// ─── Dangerous Commands (blocked in observer/worker, warned in standard) ─
const DANGEROUS_COMMANDS = [
  // Destructive
  { pattern: /\brm\s+.*-[a-zA-Z]*r[a-zA-Z]*f/i, label: 'Recursive force delete', severity: 'critical', block: ['observer', 'worker', 'standard'] },
  { pattern: /\brm\s+-rf\s+[\/~]/i, label: 'Delete from root/home', severity: 'critical', block: ['observer', 'worker', 'standard'] },
  { pattern: /\bmkfs\b/i, label: 'Format filesystem', severity: 'critical', block: ['observer', 'worker', 'standard'] },
  { pattern: /\bdd\s+.*of=\/dev\//i, label: 'Raw disk write', severity: 'critical', block: ['observer', 'worker', 'standard'] },

  // Privilege escalation
  { pattern: /\bsudo\b/i, label: 'Sudo command', severity: 'high', block: ['observer', 'worker'] },
  { pattern: /\bsu\s+-/i, label: 'Switch user', severity: 'high', block: ['observer', 'worker'] },
  { pattern: /\bchmod\s+(?:\+s|4[0-7]{3})/i, label: 'SUID bit', severity: 'critical', block: ['observer', 'worker', 'standard'] },

  // Network exposure
  { pattern: /\bnc\s+.*-l/i, label: 'Network listener', severity: 'critical', block: ['observer', 'worker', 'standard'] },
  { pattern: /\bssh\s+-R\b/i, label: 'Reverse SSH tunnel', severity: 'high', block: ['observer', 'worker'] },
  { pattern: /\bngrok\b/i, label: 'Public tunnel', severity: 'high', block: ['observer', 'worker'] },
  { pattern: /\bcurl\b.*\|\s*(?:bash|sh)\b/i, label: 'Pipe URL to shell', severity: 'critical', block: ['observer', 'worker', 'standard'] },

  // Persistence
  { pattern: /\bcrontab\b/i, label: 'Cron modification', severity: 'medium', block: ['observer', 'worker'] },
  { pattern: /\bsystemctl\s+(?:enable|start)\b/i, label: 'Service management', severity: 'medium', block: ['observer', 'worker'] },
  { pattern: /(?:\.bashrc|\.zshrc|\.profile|\.bash_profile)/i, label: 'Shell config modification', severity: 'high', block: ['observer', 'worker'] },

  // Data exfiltration
  { pattern: /\bcurl\s+.*(?:-d\s|--data|--upload-file|-F\s|-T\s)/i, label: 'Data upload via curl', severity: 'high', block: ['observer', 'worker'] },
  { pattern: /\bscp\b/i, label: 'File transfer via SCP', severity: 'medium', block: ['observer'] },
  { pattern: /\brsync\b.*(?:@|:)/i, label: 'Remote file sync', severity: 'medium', block: ['observer'] },
];

// ─── Network Rules ──────────────────────────────────────────────────
const NETWORK_BLOCKLIST = [
  /(?:pastebin|hastebin|0x0|transfer\.sh|file\.io|tmpfiles)/i,
  /(?:ngrok|serveo|localtunnel|cloudflared)/i,
];

// ─── Safe Commands (allowed even in worker mode) ────────────────────
const SAFE_COMMANDS = [
  /^(?:ls|cat|head|tail|wc|grep|find|echo|date|pwd|whoami|id|uname|env|which|whereis|file|stat|du|df|free|uptime|hostname)\b/,
  /^(?:git\s+(?:status|log|diff|branch|show|stash|remote|describe))\b/,
  /^(?:node|npm\s+(?:list|ls|outdated|info|view|search|test|run))\b/,
  /^(?:python3?\s+-c)\b/,
  /^(?:jq|sed|awk|sort|uniq|cut|tr|tee|xargs|diff)\b/,
  /^(?:curl|wget)\s+(?!.*(?:--data|-d\s|-F\s|--upload|--post|-T\s))/,
];

/**
 * @typedef {Object} GuardianVerdict
 * @property {boolean} allowed - Whether the action is permitted
 * @property {string} [reason] - Why it was blocked/warned
 * @property {string} [zone] - 'workspace' | 'system' | 'forbidden' | 'unknown'
 * @property {string} [severity] - 'low' | 'medium' | 'high' | 'critical'
 * @property {string} decision - 'allow' | 'deny' | 'warn' | 'audit'
 */

class HostGuardian {
  /**
   * @param {Object} opts
   * @param {string} [opts.mode='standard'] - Permission tier: 'observer' | 'worker' | 'standard' | 'full'
   * @param {string} [opts.workspace] - Workspace directory path
   * @param {string[]} [opts.safeZones] - Additional allowed paths
   * @param {string[]} [opts.forbiddenZones] - Additional forbidden path patterns
   * @param {string} [opts.logFile] - Audit log file path
   * @param {boolean} [opts.quiet] - Suppress console output
   * @param {Function} [opts.onViolation] - Callback on policy violation
   */
  constructor(opts = {}) {
    this.mode = opts.mode || 'standard';
    this.tier = TIERS[this.mode] || TIERS.standard;
    this.home = os.homedir();
    this.workspace = opts.workspace ? this._resolve(opts.workspace) : path.join(this.home, '.openclaw', 'workspace');
    this.safeZones = (opts.safeZones || []).map(z => this._resolve(z));
    this.extraForbidden = (opts.forbiddenZones || []).map(p => ({
      pattern: new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'),
      label: `Custom forbidden: ${p}`,
      severity: 'high',
    }));
    this.onViolation = opts.onViolation || null;
    this.logger = new SecurityLogger({
      logFile: opts.logFile,
      quiet: opts.quiet !== false,
    });
    this.auditTrail = [];
    this.stats = { checked: 0, allowed: 0, denied: 0, warned: 0 };
  }

  /**
   * Check if a tool call is allowed.
   * @param {string} tool - Tool name (read, write, exec, browser, message, etc.)
   * @param {Object} args - Tool arguments
   * @returns {GuardianVerdict}
   */
  check(tool, args = {}) {
    this.stats.checked++;
    let verdict;

    switch (tool) {
      case 'read':
      case 'Read':
        verdict = this._checkFileRead(args);
        break;
      case 'write':
      case 'Write':
      case 'edit':
      case 'Edit':
        verdict = this._checkFileWrite(args);
        break;
      case 'exec':
        verdict = this._checkExec(args);
        break;
      case 'browser':
        verdict = this._checkBrowser(args);
        break;
      case 'message':
        verdict = this._checkMessage(args);
        break;
      default:
        verdict = { allowed: true, decision: 'allow' };
    }

    // Record audit trail
    this.auditTrail.push({
      timestamp: Date.now(),
      tool,
      args: this._sanitizeArgs(args),
      verdict,
    });

    // Trim audit trail to last 10000 entries
    if (this.auditTrail.length > 10000) {
      this.auditTrail = this.auditTrail.slice(-5000);
    }

    if (verdict.allowed) {
      this.stats.allowed++;
    } else {
      this.stats.denied++;
      if (this.onViolation) this.onViolation(tool, args, verdict);
      this.logger.log({
        type: 'guardian_block',
        severity: verdict.severity || 'high',
        message: `[${this.mode}] ${tool}: ${verdict.reason}`,
        details: { tool, verdict, args: this._sanitizeArgs(args) },
      });
    }

    if (verdict.decision === 'warn') this.stats.warned++;

    return verdict;
  }

  // ─── File Read Check ────────────────────────────────────────────
  _checkFileRead(args) {
    const filePath = args.path || args.file_path || '';
    const resolved = this._resolve(filePath);

    // Check forbidden zones
    const forbidden = this._checkForbidden(filePath, resolved);
    if (forbidden) return forbidden;

    // Observer/worker: workspace only
    if (this.tier.allowRead === 'workspace') {
      if (!this._inWorkspace(resolved) && !this._inSafeZone(resolved)) {
        return {
          allowed: false,
          decision: 'deny',
          reason: `Read outside workspace not allowed in ${this.mode} mode`,
          zone: this._classifyZone(resolved),
          severity: 'medium',
        };
      }
    }

    return { allowed: true, decision: 'allow', zone: this._classifyZone(resolved) };
  }

  // ─── File Write Check ───────────────────────────────────────────
  _checkFileWrite(args) {
    const filePath = args.path || args.file_path || '';
    const resolved = this._resolve(filePath);

    // Check forbidden zones
    const forbidden = this._checkForbidden(filePath, resolved);
    if (forbidden) return forbidden;

    // No writes in observer mode
    if (this.tier.allowWrite === false) {
      return {
        allowed: false,
        decision: 'deny',
        reason: 'Writes not allowed in observer mode',
        zone: this._classifyZone(resolved),
        severity: 'medium',
      };
    }

    // workspace-only writes
    if (this.tier.allowWrite === 'workspace') {
      if (!this._inWorkspace(resolved) && !this._inSafeZone(resolved)) {
        return {
          allowed: false,
          decision: 'deny',
          reason: `Write outside workspace not allowed in ${this.mode} mode`,
          zone: this._classifyZone(resolved),
          severity: 'high',
        };
      }
    }

    return { allowed: true, decision: 'allow', zone: this._classifyZone(resolved) };
  }

  // ─── Exec Check ────────────────────────────────────────────────
  _checkExec(args) {
    const command = args.command || '';

    // No exec at all in observer mode
    if (this.tier.allowExec === false) {
      return {
        allowed: false,
        decision: 'deny',
        reason: 'Command execution not allowed in observer mode',
        severity: 'high',
      };
    }

    // Check dangerous commands
    for (const rule of DANGEROUS_COMMANDS) {
      if (rule.pattern.test(command)) {
        const blocked = rule.block.includes(this.mode);
        if (blocked) {
          return {
            allowed: false,
            decision: 'deny',
            reason: `Dangerous command blocked: ${rule.label}`,
            severity: rule.severity,
            matched: command.substring(0, 200),
          };
        }
        // In full mode, just warn
        return {
          allowed: true,
          decision: 'warn',
          reason: `Dangerous command (audit only): ${rule.label}`,
          severity: rule.severity,
          matched: command.substring(0, 200),
        };
      }
    }

    // Worker mode: only safe commands allowed
    if (this.tier.allowExec === 'safe') {
      const isSafe = SAFE_COMMANDS.some(p => p.test(command));
      if (!isSafe) {
        return {
          allowed: false,
          decision: 'deny',
          reason: `Command not in safe list for worker mode`,
          severity: 'medium',
          matched: command.substring(0, 200),
        };
      }
    }

    return { allowed: true, decision: 'allow' };
  }

  // ─── Browser Check ─────────────────────────────────────────────
  _checkBrowser(args) {
    if (!this.tier.allowBrowser) {
      return {
        allowed: false,
        decision: 'deny',
        reason: 'Browser access not allowed in observer mode',
        severity: 'medium',
      };
    }

    const url = args.targetUrl || args.url || '';
    for (const pattern of NETWORK_BLOCKLIST) {
      if (pattern.test(url)) {
        return {
          allowed: false,
          decision: 'deny',
          reason: `Blocked URL: matches exfiltration service pattern`,
          severity: 'high',
          matched: url,
        };
      }
    }

    return { allowed: true, decision: 'allow' };
  }

  // ─── Message Check ─────────────────────────────────────────────
  _checkMessage(args) {
    // Messages always allowed, but log in audit trail
    return { allowed: true, decision: 'allow' };
  }

  // ─── Forbidden Zone Check ──────────────────────────────────────
  _checkForbidden(rawPath, resolvedPath) {
    const allForbidden = [...FORBIDDEN_ZONES, ...this.extraForbidden];
    const normalized = resolvedPath.replace(this.home, '~');

    for (const zone of allForbidden) {
      if (zone.pattern.test(rawPath) || zone.pattern.test(normalized) || zone.pattern.test(resolvedPath)) {
        if (this.mode === 'full') {
          // Full mode: log but allow
          return {
            allowed: true,
            decision: 'warn',
            reason: `Protected zone accessed (audit): ${zone.label}`,
            zone: 'forbidden',
            severity: zone.severity,
          };
        }
        return {
          allowed: false,
          decision: 'deny',
          reason: `Protected zone: ${zone.label}`,
          zone: 'forbidden',
          severity: zone.severity,
        };
      }
    }
    return null;
  }

  // ─── Zone Classification ───────────────────────────────────────
  _classifyZone(resolvedPath) {
    if (this._inWorkspace(resolvedPath)) return 'workspace';
    if (this._inSafeZone(resolvedPath)) return 'safe';
    if (resolvedPath.startsWith(this.home)) return 'home';
    if (resolvedPath.startsWith('/etc') || resolvedPath.startsWith('/usr') || resolvedPath.startsWith('/var')) return 'system';
    return 'unknown';
  }

  _inWorkspace(p) {
    return p.startsWith(this.workspace + '/') || p === this.workspace;
  }

  _inSafeZone(p) {
    return this.safeZones.some(z => p.startsWith(z + '/') || p === z);
  }

  _resolve(p) {
    if (!p) return '';
    const expanded = p.replace(/^~/, this.home);
    return path.resolve(expanded);
  }

  _sanitizeArgs(args) {
    // Don't log full file contents or long commands
    const sanitized = { ...args };
    if (sanitized.content && sanitized.content.length > 200) {
      sanitized.content = sanitized.content.substring(0, 200) + '...[truncated]';
    }
    if (sanitized.command && sanitized.command.length > 500) {
      sanitized.command = sanitized.command.substring(0, 500) + '...[truncated]';
    }
    return sanitized;
  }

  // ─── Audit & Stats ────────────────────────────────────────────
  
  /**
   * Get audit trail entries.
   * @param {Object} [filter]
   * @param {number} [filter.last] - Last N entries
   * @param {string} [filter.tool] - Filter by tool name
   * @param {boolean} [filter.deniedOnly] - Only show denied actions
   * @returns {Array}
   */
  audit(filter = {}) {
    let entries = this.auditTrail;
    if (filter.tool) entries = entries.filter(e => e.tool === filter.tool);
    if (filter.deniedOnly) entries = entries.filter(e => !e.verdict.allowed);
    if (filter.last) entries = entries.slice(-filter.last);
    return entries;
  }

  /**
   * Get summary statistics.
   * @returns {Object}
   */
  summary() {
    return {
      mode: this.mode,
      tier: this.tier.label,
      description: this.tier.description,
      workspace: this.workspace,
      ...this.stats,
      forbiddenZones: FORBIDDEN_ZONES.length + this.extraForbidden.length,
      dangerousCommandRules: DANGEROUS_COMMANDS.length,
    };
  }

  /**
   * Change permission tier at runtime.
   * @param {string} mode - New tier name
   */
  setMode(mode) {
    if (!TIERS[mode]) throw new Error(`Unknown mode: ${mode}. Valid: ${Object.keys(TIERS).join(', ')}`);
    this.mode = mode;
    this.tier = TIERS[mode];
    this.logger.log({
      type: 'guardian_mode_change',
      severity: 'medium',
      message: `Guardian mode changed to: ${mode}`,
    });
  }

  /**
   * Generate a human-readable security report.
   * @returns {string}
   */
  report() {
    const s = this.summary();
    const denied = this.audit({ deniedOnly: true, last: 20 });
    let report = `\n═══ ClawMoat Host Guardian Report ═══\n`;
    report += `Mode: ${s.tier} (${s.mode})\n`;
    report += `${s.description}\n\n`;
    report += `Actions checked: ${s.checked}\n`;
    report += `  Allowed: ${s.allowed}\n`;
    report += `  Denied:  ${s.denied}\n`;
    report += `  Warned:  ${s.warned}\n\n`;

    if (denied.length > 0) {
      report += `Recent blocked actions:\n`;
      for (const entry of denied) {
        const t = new Date(entry.timestamp).toISOString().substring(11, 19);
        report += `  [${t}] ${entry.tool}: ${entry.verdict.reason}\n`;
      }
    } else {
      report += `No blocked actions recorded.\n`;
    }

    return report;
  }
}

module.exports = { HostGuardian, TIERS, FORBIDDEN_ZONES, DANGEROUS_COMMANDS, SAFE_COMMANDS };
