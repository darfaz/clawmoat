/**
 * ClawMoat Security Event Logger
 */

const fs = require('fs');
const path = require('path');

const SEVERITY = { low: 0, medium: 1, high: 2, critical: 3 };
const COLORS = {
  low: '\x1b[36m',       // cyan
  medium: '\x1b[33m',    // yellow
  high: '\x1b[31m',      // red
  critical: '\x1b[35m',  // magenta
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
};

class SecurityLogger {
  constructor(opts = {}) {
    this.events = [];
    this.logFile = opts.logFile || null;
    this.quiet = opts.quiet || false;
    this.minSeverity = SEVERITY[opts.minSeverity || 'low'] || 0;
    this.webhook = opts.webhook || null;
    this.onEvent = opts.onEvent || null;
  }

  log(event) {
    const entry = {
      timestamp: new Date().toISOString(),
      id: `cm_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      ...event,
    };

    this.events.push(entry);

    // Console output
    if (!this.quiet && SEVERITY[event.severity] >= this.minSeverity) {
      const sev = event.severity.toUpperCase().padEnd(8);
      const color = COLORS[event.severity] || '';
      console.error(
        `${COLORS.dim}[ClawMoat]${COLORS.reset} ${color}${sev}${COLORS.reset} ${COLORS.bold}${event.type}${COLORS.reset}: ${event.message}` +
        (event.details ? ` ${COLORS.dim}(${JSON.stringify(event.details)})${COLORS.reset}` : '')
      );
    }

    // File logging
    if (this.logFile) {
      try {
        const dir = path.dirname(this.logFile);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.appendFileSync(this.logFile, JSON.stringify(entry) + '\n');
      } catch {}
    }

    // Webhook
    if (this.webhook && SEVERITY[event.severity] >= SEVERITY.medium) {
      this._sendWebhook(entry).catch(() => {});
    }

    // Callback
    if (this.onEvent) {
      try { this.onEvent(entry); } catch {}
    }

    return entry;
  }

  async _sendWebhook(entry) {
    try {
      await fetch(this.webhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(entry),
      });
    } catch {}
  }

  getEvents(filter = {}) {
    let events = this.events;
    if (filter.severity) {
      const min = SEVERITY[filter.severity] || 0;
      events = events.filter(e => SEVERITY[e.severity] >= min);
    }
    if (filter.type) {
      events = events.filter(e => e.type === filter.type);
    }
    if (filter.since) {
      events = events.filter(e => new Date(e.timestamp) >= new Date(filter.since));
    }
    if (filter.limit) {
      events = events.slice(-filter.limit);
    }
    return events;
  }

  summary() {
    const counts = { low: 0, medium: 0, high: 0, critical: 0 };
    const types = {};
    for (const e of this.events) {
      counts[e.severity] = (counts[e.severity] || 0) + 1;
      types[e.type] = (types[e.type] || 0) + 1;
    }
    return { total: this.events.length, bySeverity: counts, byType: types };
  }
}

module.exports = { SecurityLogger, SEVERITY };
