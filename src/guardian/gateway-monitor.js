/**
 * ClawMoat Gateway Monitor
 * 
 * Detects and mitigates the Oasis Security WebSocket hijack attack
 * (CVE-2026-XXXXX) where any website can silently take full control
 * of an OpenClaw agent via localhost WebSocket brute-force.
 * 
 * Attack chain:
 * 1. Malicious website opens WebSocket to localhost:18789
 * 2. Brute-forces gateway password (rate limiter exempts localhost)
 * 3. Auto-registers as trusted device (no user prompt for localhost)
 * 4. Full agent takeover: messages, files, shell commands
 * 
 * This module monitors for:
 * - Rapid authentication attempts (brute-force detection)
 * - Unexpected device pairings
 * - WebSocket connections from browser origins
 * - Gateway configuration weaknesses
 * 
 * @module clawmoat/guardian/gateway-monitor
 * @see https://www.oasis.security/blog/openclaw-vulnerability
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

// ─── Constants ──────────────────────────────────────────────────────

/** Default OpenClaw gateway port */
const DEFAULT_GATEWAY_PORT = 18789;

/** Maximum auth attempts before triggering alert */
const BRUTE_FORCE_THRESHOLD = 10;

/** Time window for brute-force detection (ms) */
const BRUTE_FORCE_WINDOW_MS = 60_000;

/** Maximum new device pairings before alert */
const PAIRING_THRESHOLD = 3;

/** Time window for pairing flood detection (ms) */
const PAIRING_WINDOW_MS = 300_000;

/** Known browser WebSocket origins that indicate cross-origin attack */
const SUSPICIOUS_ORIGINS = [
  /^https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
];

/** Gateway config paths to check */
const GATEWAY_CONFIG_PATHS = [
  path.join(os.homedir(), '.openclaw', 'gateway.json'),
  path.join(os.homedir(), '.openclaw', 'config.json5'),
  path.join(os.homedir(), '.config', 'openclaw', 'gateway.json'),
];

// ─── Gateway Monitor ────────────────────────────────────────────────

class GatewayMonitor {
  /**
   * @param {Object} options
   * @param {number} [options.port=18789] - Gateway port to monitor
   * @param {number} [options.bruteForceThreshold=10] - Auth attempts before alert
   * @param {number} [options.bruteForceWindowMs=60000] - Time window for detection
   * @param {number} [options.pairingThreshold=3] - Max pairings before alert
   * @param {Function} [options.onAlert] - Callback for security alerts
   * @param {string} [options.logPath] - Path to write audit log
   */
  constructor(options = {}) {
    this.port = options.port || DEFAULT_GATEWAY_PORT;
    this.bruteForceThreshold = options.bruteForceThreshold || BRUTE_FORCE_THRESHOLD;
    this.bruteForceWindowMs = options.bruteForceWindowMs || BRUTE_FORCE_WINDOW_MS;
    this.pairingThreshold = options.pairingThreshold || PAIRING_THRESHOLD;
    this.pairingWindowMs = options.pairingWindowMs || PAIRING_WINDOW_MS;
    this.onAlert = options.onAlert || null;
    this.logPath = options.logPath || null;

    // State tracking
    this.authAttempts = [];       // { timestamp, source, success }
    this.devicePairings = [];     // { timestamp, deviceId, source, autoApproved }
    this.wsConnections = [];      // { timestamp, origin, source }
    this.alerts = [];             // { timestamp, type, severity, message, details }
    this.knownDevices = new Set();
    this.configIssues = [];
  }

  // ─── Authentication Monitoring ──────────────────────────────────

  /**
   * Record an authentication attempt and check for brute-force patterns.
   * @param {Object} attempt
   * @param {string} attempt.source - Source IP/identifier
   * @param {boolean} attempt.success - Whether auth succeeded
   * @param {string} [attempt.origin] - WebSocket origin header
   * @param {number} [attempt.timestamp] - Unix ms (defaults to now)
   * @returns {Object} Analysis result
   */
  recordAuthAttempt(attempt) {
    const record = {
      timestamp: attempt.timestamp || Date.now(),
      source: attempt.source || 'unknown',
      success: !!attempt.success,
      origin: attempt.origin || null,
    };

    this.authAttempts.push(record);
    this._pruneOldEntries(this.authAttempts, this.bruteForceWindowMs);

    const analysis = this._analyzeAuthPatterns(record);
    
    if (this.logPath) {
      this._appendLog({ type: 'auth_attempt', ...record, analysis });
    }

    return analysis;
  }

  /**
   * Analyze authentication patterns for brute-force indicators.
   * @private
   */
  _analyzeAuthPatterns(latestAttempt) {
    const now = latestAttempt.timestamp;
    const windowStart = now - this.bruteForceWindowMs;
    const recentAttempts = this.authAttempts.filter(a => a.timestamp >= windowStart);
    
    const result = {
      totalAttempts: recentAttempts.length,
      failedAttempts: recentAttempts.filter(a => !a.success).length,
      uniqueSources: new Set(recentAttempts.map(a => a.source)).size,
      isBruteForce: false,
      isSuspiciousOrigin: false,
      alerts: [],
    };

    // Check for brute-force
    if (result.failedAttempts >= this.bruteForceThreshold) {
      result.isBruteForce = true;
      const alert = {
        timestamp: now,
        type: 'brute_force_detected',
        severity: 'critical',
        message: `Brute-force attack detected: ${result.failedAttempts} failed auth attempts in ${this.bruteForceWindowMs / 1000}s`,
        details: {
          failedAttempts: result.failedAttempts,
          windowMs: this.bruteForceWindowMs,
          sources: [...new Set(recentAttempts.filter(a => !a.success).map(a => a.source))],
          recommendation: 'Change gateway password immediately. Use 32+ character password. Consider binding to non-localhost IP.',
          reference: 'https://www.oasis.security/blog/openclaw-vulnerability',
        },
      };
      this._emitAlert(alert);
      result.alerts.push(alert);
    }

    // Check for suspicious origin
    if (latestAttempt.origin) {
      const isSuspicious = SUSPICIOUS_ORIGINS.some(re => re.test(latestAttempt.origin));
      if (isSuspicious) {
        result.isSuspiciousOrigin = true;
        const alert = {
          timestamp: now,
          type: 'suspicious_websocket_origin',
          severity: 'critical',
          message: `WebSocket connection from suspicious origin: ${latestAttempt.origin}`,
          details: {
            origin: latestAttempt.origin,
            source: latestAttempt.source,
            recommendation: 'This may be a cross-origin WebSocket hijack attempt. Verify no unauthorized browser tabs are connecting to your gateway.',
            reference: 'https://www.oasis.security/blog/openclaw-vulnerability',
          },
        };
        this._emitAlert(alert);
        result.alerts.push(alert);
      }
    }

    // Check for rapid successful auth (may indicate stolen credentials)
    const successfulAttempts = recentAttempts.filter(a => a.success);
    const uniqueSuccessSources = new Set(successfulAttempts.map(a => a.source));
    if (uniqueSuccessSources.size > 2) {
      const alert = {
        timestamp: now,
        type: 'multiple_auth_sources',
        severity: 'warning',
        message: `Authenticated from ${uniqueSuccessSources.size} different sources in ${this.bruteForceWindowMs / 1000}s`,
        details: {
          sources: [...uniqueSuccessSources],
          recommendation: 'Verify all authentication sources are legitimate. Rotate gateway password if any are unknown.',
        },
      };
      this._emitAlert(alert);
      result.alerts.push(alert);
    }

    return result;
  }

  // ─── Device Pairing Monitoring ──────────────────────────────────

  /**
   * Record a device pairing event and check for suspicious patterns.
   * @param {Object} pairing
   * @param {string} pairing.deviceId - Device identifier
   * @param {string} [pairing.source] - Source IP
   * @param {boolean} [pairing.autoApproved] - Whether auto-approved
   * @param {string} [pairing.deviceName] - Human-readable device name
   * @param {number} [pairing.timestamp] - Unix ms
   * @returns {Object} Analysis result
   */
  recordDevicePairing(pairing) {
    const record = {
      timestamp: pairing.timestamp || Date.now(),
      deviceId: pairing.deviceId,
      source: pairing.source || 'unknown',
      autoApproved: !!pairing.autoApproved,
      deviceName: pairing.deviceName || null,
    };

    this.devicePairings.push(record);
    this._pruneOldEntries(this.devicePairings, this.pairingWindowMs);

    const isNew = !this.knownDevices.has(record.deviceId);
    if (isNew) {
      this.knownDevices.add(record.deviceId);
    }

    const analysis = this._analyzePairingPatterns(record, isNew);

    if (this.logPath) {
      this._appendLog({ type: 'device_pairing', ...record, isNew, analysis });
    }

    return analysis;
  }

  /**
   * Analyze device pairing patterns.
   * @private
   */
  _analyzePairingPatterns(latestPairing, isNew) {
    const now = latestPairing.timestamp;
    const windowStart = now - this.pairingWindowMs;
    const recentPairings = this.devicePairings.filter(p => p.timestamp >= windowStart);

    const result = {
      isNew,
      totalRecentPairings: recentPairings.length,
      autoApprovedCount: recentPairings.filter(p => p.autoApproved).length,
      isPairingFlood: false,
      isAutoApproveRisk: false,
      alerts: [],
    };

    // Check for pairing flood
    if (recentPairings.length >= this.pairingThreshold) {
      result.isPairingFlood = true;
      const alert = {
        timestamp: now,
        type: 'pairing_flood',
        severity: 'high',
        message: `${recentPairings.length} device pairings in ${this.pairingWindowMs / 1000}s (threshold: ${this.pairingThreshold})`,
        details: {
          devices: recentPairings.map(p => ({ id: p.deviceId, source: p.source, autoApproved: p.autoApproved })),
          recommendation: 'Review all paired devices. Revoke unknown devices. Disable auto-approve for localhost.',
        },
      };
      this._emitAlert(alert);
      result.alerts.push(alert);
    }

    // Check for auto-approved pairing from localhost (the Oasis attack)
    if (latestPairing.autoApproved && isNew) {
      result.isAutoApproveRisk = true;
      const severity = latestPairing.source === 'localhost' || latestPairing.source === '127.0.0.1' ? 'critical' : 'warning';
      const alert = {
        timestamp: now,
        type: 'auto_approved_pairing',
        severity,
        message: `New device "${latestPairing.deviceName || latestPairing.deviceId}" auto-approved from ${latestPairing.source}`,
        details: {
          deviceId: latestPairing.deviceId,
          deviceName: latestPairing.deviceName,
          source: latestPairing.source,
          recommendation: severity === 'critical'
            ? 'CRITICAL: Localhost auto-approve is the exact vector used in the Oasis WebSocket hijack. Disable auto-approve immediately.'
            : 'Verify this device pairing was intentional.',
          reference: 'https://www.oasis.security/blog/openclaw-vulnerability',
        },
      };
      this._emitAlert(alert);
      result.alerts.push(alert);
    }

    return result;
  }

  // ─── Gateway Configuration Audit ────────────────────────────────

  /**
   * Audit the gateway configuration for security weaknesses.
   * Checks for the specific vulnerabilities exploited in the Oasis attack.
   * @returns {Object} Audit results
   */
  auditGatewayConfig() {
    const issues = [];
    let configFound = false;
    let config = null;

    // Find and parse gateway config
    for (const configPath of GATEWAY_CONFIG_PATHS) {
      try {
        const raw = fs.readFileSync(configPath, 'utf8');
        // Handle JSON5 (strip comments)
        const cleaned = raw.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
        config = JSON.parse(cleaned);
        configFound = true;
        break;
      } catch {
        // Try next path
      }
    }

    if (!configFound) {
      issues.push({
        severity: 'info',
        issue: 'gateway_config_not_found',
        message: 'Could not find gateway configuration file. Using defaults.',
        recommendation: 'Ensure gateway is configured with strong authentication.',
      });
    }

    // Check 1: Password strength
    if (config) {
      const token = config.auth?.token || config.gatewayToken || config.token;
      if (token) {
        if (token.length < 20) {
          issues.push({
            severity: 'critical',
            issue: 'weak_gateway_password',
            message: `Gateway password is only ${token.length} characters. Oasis attack brute-forces at hundreds of attempts/second.`,
            recommendation: 'Use a 32+ character random password. Run: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
            reference: 'https://www.oasis.security/blog/openclaw-vulnerability',
          });
        } else if (token.length < 32) {
          issues.push({
            severity: 'warning',
            issue: 'short_gateway_password',
            message: `Gateway password is ${token.length} characters. Consider using 32+ for brute-force resistance.`,
            recommendation: 'Use a longer random password for maximum security.',
          });
        }
      } else {
        issues.push({
          severity: 'critical',
          issue: 'no_gateway_password',
          message: 'No gateway authentication configured. Anyone on localhost can connect.',
          recommendation: 'Set a strong gateway token immediately.',
        });
      }
    }

    // Check 2: Binding address
    if (config) {
      const host = config.host || config.gateway?.host || config.bind;
      if (!host || host === '0.0.0.0') {
        issues.push({
          severity: 'critical',
          issue: 'gateway_bound_all_interfaces',
          message: 'Gateway is bound to all interfaces (0.0.0.0). Accessible from any network.',
          recommendation: 'Bind to localhost (127.0.0.1) or a Tailscale/VPN IP only.',
        });
      } else if (host === '127.0.0.1' || host === 'localhost') {
        issues.push({
          severity: 'warning',
          issue: 'gateway_bound_localhost',
          message: 'Gateway bound to localhost. Still vulnerable to Oasis WebSocket attack from browser.',
          recommendation: 'Consider binding to a Tailscale IP to prevent browser-based WebSocket attacks.',
          reference: 'https://www.oasis.security/blog/openclaw-vulnerability',
        });
      }
    }

    // Check 3: Auto-approve settings
    if (config) {
      const autoApprove = config.autoApprove ?? config.gateway?.autoApprove ?? config.pairApproval?.auto;
      if (autoApprove === true || autoApprove === 'localhost') {
        issues.push({
          severity: 'critical',
          issue: 'auto_approve_enabled',
          message: 'Device auto-approve is enabled. This is the exact vector exploited in the Oasis attack.',
          recommendation: 'Disable auto-approve. Require manual confirmation for all device pairings.',
          reference: 'https://www.oasis.security/blog/openclaw-vulnerability',
        });
      }
    }

    // Check 4: Rate limiting
    if (config) {
      const rateLimit = config.rateLimit || config.gateway?.rateLimit;
      if (!rateLimit) {
        issues.push({
          severity: 'high',
          issue: 'no_rate_limiting',
          message: 'No rate limiting configured. Gateway can be brute-forced at hundreds of attempts/second.',
          recommendation: 'Enable rate limiting, including for localhost connections.',
        });
      } else if (rateLimit.excludeLocalhost || rateLimit.trustLocalhost) {
        issues.push({
          severity: 'critical',
          issue: 'localhost_rate_limit_exempt',
          message: 'Localhost is exempt from rate limiting. This is the exact configuration exploited in the Oasis attack.',
          recommendation: 'Remove localhost exemption from rate limiting.',
          reference: 'https://www.oasis.security/blog/openclaw-vulnerability',
        });
      }
    }

    // Check 5: Gateway port
    if (config) {
      const port = config.port || config.gateway?.port || DEFAULT_GATEWAY_PORT;
      if (port === DEFAULT_GATEWAY_PORT) {
        issues.push({
          severity: 'low',
          issue: 'default_gateway_port',
          message: `Using default gateway port ${DEFAULT_GATEWAY_PORT}. Easily discoverable.`,
          recommendation: 'Consider using a non-default port to reduce attack surface.',
        });
      }
    }

    this.configIssues = issues;

    const result = {
      configFound,
      issues,
      criticalCount: issues.filter(i => i.severity === 'critical').length,
      highCount: issues.filter(i => i.severity === 'high').length,
      warningCount: issues.filter(i => i.severity === 'warning').length,
      score: this._calculateSecurityScore(issues),
      oasisVulnerable: issues.some(i => i.reference?.includes('oasis')),
    };

    if (result.criticalCount > 0) {
      const alert = {
        timestamp: Date.now(),
        type: 'gateway_audit_critical',
        severity: 'critical',
        message: `Gateway audit found ${result.criticalCount} critical issues`,
        details: {
          issues: issues.filter(i => i.severity === 'critical'),
          score: result.score,
          oasisVulnerable: result.oasisVulnerable,
        },
      };
      this._emitAlert(alert);
    }

    if (this.logPath) {
      this._appendLog({ type: 'gateway_audit', ...result });
    }

    return result;
  }

  /**
   * Calculate a security score (0-100) based on config issues.
   * @private
   */
  _calculateSecurityScore(issues) {
    let score = 100;
    for (const issue of issues) {
      switch (issue.severity) {
        case 'critical': score -= 25; break;
        case 'high': score -= 15; break;
        case 'warning': score -= 10; break;
        case 'low': score -= 5; break;
      }
    }
    return Math.max(0, score);
  }

  // ─── Recommendations ────────────────────────────────────────────

  /**
   * Generate a strong gateway token.
   * @returns {string} 64-character hex token
   */
  static generateStrongToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Get hardened gateway configuration recommendations.
   * @returns {Object} Recommended config
   */
  static getHardenedConfig() {
    return {
      gateway: {
        host: '127.0.0.1',  // Or Tailscale IP for remote access
        port: 18700 + Math.floor(Math.random() * 89),  // Random non-default port
        token: GatewayMonitor.generateStrongToken(),
        rateLimit: {
          windowMs: 60_000,
          maxAttempts: 5,
          excludeLocalhost: false,  // CRITICAL: do NOT exclude localhost
        },
        autoApprove: false,  // CRITICAL: require manual device approval
        pairApproval: {
          auto: false,
          requireConfirmation: true,
          notifyOnPairing: true,
        },
      },
      _comment: 'Generated by ClawMoat gateway-monitor. See: https://www.oasis.security/blog/openclaw-vulnerability',
    };
  }

  // ─── Utility Methods ────────────────────────────────────────────

  /**
   * Get all alerts, optionally filtered by severity.
   * @param {string} [minSeverity] - Minimum severity: 'low' | 'warning' | 'high' | 'critical'
   * @returns {Array} Alerts
   */
  getAlerts(minSeverity) {
    if (!minSeverity) return [...this.alerts];
    const levels = { low: 0, warning: 1, high: 2, critical: 3 };
    const min = levels[minSeverity] || 0;
    return this.alerts.filter(a => (levels[a.severity] || 0) >= min);
  }

  /**
   * Get a summary report.
   * @returns {Object} Summary
   */
  getSummary() {
    return {
      authAttempts: this.authAttempts.length,
      failedAuth: this.authAttempts.filter(a => !a.success).length,
      devicePairings: this.devicePairings.length,
      knownDevices: this.knownDevices.size,
      alerts: this.alerts.length,
      criticalAlerts: this.alerts.filter(a => a.severity === 'critical').length,
      configIssues: this.configIssues.length,
    };
  }

  /**
   * Reset all state (for testing).
   */
  reset() {
    this.authAttempts = [];
    this.devicePairings = [];
    this.wsConnections = [];
    this.alerts = [];
    this.knownDevices.clear();
    this.configIssues = [];
  }

  /** @private */
  _emitAlert(alert) {
    this.alerts.push(alert);
    if (this.onAlert) {
      this.onAlert(alert);
    }
  }

  /** @private */
  _pruneOldEntries(arr, maxAgeMs) {
    const cutoff = Date.now() - maxAgeMs;
    while (arr.length > 0 && arr[0].timestamp < cutoff) {
      arr.shift();
    }
  }

  /** @private */
  _appendLog(entry) {
    if (!this.logPath) return;
    try {
      const line = JSON.stringify({ ...entry, _ts: new Date().toISOString() }) + '\n';
      fs.appendFileSync(this.logPath, line);
    } catch {
      // Silently fail — don't let logging break monitoring
    }
  }
}

module.exports = { GatewayMonitor, DEFAULT_GATEWAY_PORT, BRUTE_FORCE_THRESHOLD };
