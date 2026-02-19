/**
 * ClawMoat Alert Delivery System
 * 
 * Unified alerting with console, file, and webhook delivery.
 * Rate-limited to avoid alert storms.
 * 
 * @module clawmoat/guardian/alerts
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

const SEVERITY_RANK = { info: 0, warning: 1, critical: 2 };

class AlertManager {
  /**
   * @param {Object} opts
   * @param {string[]} [opts.channels] - ['console', 'file', 'webhook']
   * @param {string} [opts.logFile] - Path for file channel (default: audit.log)
   * @param {string} [opts.webhookUrl] - URL for webhook channel
   * @param {number} [opts.rateLimitMs] - Min ms between duplicate alerts (default: 300000 = 5 min)
   * @param {boolean} [opts.quiet] - Suppress console output
   */
  constructor(opts = {}) {
    this.channels = opts.channels || ['console'];
    this.logFile = opts.logFile || 'audit.log';
    this.webhookUrl = opts.webhookUrl || null;
    this.rateLimitMs = opts.rateLimitMs ?? 300000;
    this.quiet = opts.quiet || false;
    this._recentAlerts = new Map(); // key -> timestamp
    this._alertCount = 0;
  }

  /**
   * Send an alert through configured channels.
   * @param {Object} alert
   * @param {string} alert.severity - 'info' | 'warning' | 'critical'
   * @param {string} alert.type - Alert category
   * @param {string} alert.message - Human-readable message
   * @param {Object} [alert.details] - Additional data
   * @returns {{ delivered: boolean, rateLimited: boolean }}
   */
  send(alert) {
    const key = `${alert.type}:${alert.message}`;
    const now = Date.now();
    const lastSent = this._recentAlerts.get(key);

    if (lastSent && (now - lastSent) < this.rateLimitMs) {
      return { delivered: false, rateLimited: true };
    }

    this._recentAlerts.set(key, now);
    this._alertCount++;

    // Prune old entries periodically
    if (this._recentAlerts.size > 1000) {
      for (const [k, ts] of this._recentAlerts) {
        if (now - ts > this.rateLimitMs) this._recentAlerts.delete(k);
      }
    }

    const entry = {
      timestamp: new Date().toISOString(),
      severity: alert.severity || 'info',
      type: alert.type || 'unknown',
      message: alert.message || '',
      details: alert.details || null,
    };

    for (const channel of this.channels) {
      switch (channel) {
        case 'console':
          this._deliverConsole(entry);
          break;
        case 'file':
          this._deliverFile(entry);
          break;
        case 'webhook':
          this._deliverWebhook(entry);
          break;
      }
    }

    return { delivered: true, rateLimited: false };
  }

  _deliverConsole(entry) {
    if (this.quiet) return;
    const colors = { info: '\x1b[36m', warning: '\x1b[33m', critical: '\x1b[31m' };
    const icons = { info: 'ℹ️', warning: '⚠️', critical: '🚨' };
    const c = colors[entry.severity] || '';
    const icon = icons[entry.severity] || '•';
    console.error(
      `${icon} ${c}[${entry.severity.toUpperCase()}]\x1b[0m ${entry.type}: ${entry.message}`
    );
  }

  _deliverFile(entry) {
    try {
      const dir = path.dirname(this.logFile);
      if (dir !== '.' && !fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.appendFileSync(this.logFile, JSON.stringify(entry) + '\n');
    } catch {}
  }

  _deliverWebhook(entry) {
    if (!this.webhookUrl) return;
    try {
      const url = new URL(this.webhookUrl);
      const transport = url.protocol === 'https:' ? https : http;
      const body = JSON.stringify(entry);
      const req = transport.request({
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      });
      req.on('error', () => {});
      req.write(body);
      req.end();
    } catch {}
  }

  /** Get total alerts sent. */
  get count() {
    return this._alertCount;
  }

  /** Clear rate limit cache. */
  clearRateLimit() {
    this._recentAlerts.clear();
  }
}

module.exports = { AlertManager, SEVERITY_RANK };
