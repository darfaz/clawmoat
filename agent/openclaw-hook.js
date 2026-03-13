#!/usr/bin/env node
/**
 * ClawMoat OpenClaw Hook Monitor
 * 
 * Watches ~/.openclaw/ for real-time session activity:
 * - Tails session JSONL files for inbound/outbound messages
 * - Scans each message through ClawMoat
 * - Logs threats to audit log and optionally reports to cloud
 * - Can be run standalone or imported by index.js
 * 
 * Usage: node agent/openclaw-hook.js [--verbose] [--dry-run]
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

// ─── Paths ────────────────────────────────────────────────────────────────────

const OPENCLAW_DIR = path.join(os.homedir(), '.openclaw');
const SESSIONS_DIR = path.join(OPENCLAW_DIR, 'agents', 'main', 'sessions');
const DELIVERY_QUEUE_DIR = path.join(OPENCLAW_DIR, 'delivery-queue');
const HOOKS_DIR = path.join(OPENCLAW_DIR, 'hooks');
const LOGS_DIR = path.join(OPENCLAW_DIR, 'logs');

const args = process.argv.slice(2);
const VERBOSE = args.includes('--verbose') || args.includes('-v');
const DRY_RUN = args.includes('--dry-run');

// ─── Logger ───────────────────────────────────────────────────────────────────

function ts() { return new Date().toISOString(); }
function log(msg, ...rest) {
  if (VERBOSE) console.log(`${ts()} [hook]`, msg, ...rest);
}
function warn(msg, ...rest) {
  console.warn(`${ts()} [hook] WARN`, msg, ...rest);
}
function threat(msg, ...rest) {
  console.log(`${ts()} [hook] 🚨 THREAT`, msg, ...rest);
}

// ─── ClawMoat Scanner ─────────────────────────────────────────────────────────

function loadScanner() {
  try {
    const ClawMoat = require(path.join(os.homedir(), 'clawmoat', 'src', 'index.js'));
    const moat = new ClawMoat({ quiet: true });
    log('Scanner loaded from ~/clawmoat');
    return moat;
  } catch (e) {
    try {
      const { ClawMoat } = require('clawmoat');
      const moat = new ClawMoat({ quiet: true });
      log('Scanner loaded from npm');
      return moat;
    } catch (e2) {
      throw new Error(`Cannot load ClawMoat: ${e.message}`);
    }
  }
}

// ─── Content Extractor ────────────────────────────────────────────────────────

/**
 * Extract scannable text from an OpenClaw session entry.
 * Returns null if nothing to scan.
 */
function extractContent(entry) {
  if (!entry || typeof entry !== 'object') return null;

  // Standard message event
  if (entry.type === 'message' && entry.message) {
    const msg = entry.message;
    const role = msg.role;
    const texts = [];

    if (Array.isArray(msg.content)) {
      for (const block of msg.content) {
        if (block.type === 'text' && block.text) {
          texts.push(block.text);
        }
        // Tool use input (scanToolCalls)
        if (block.type === 'tool_use' && block.input) {
          const inputStr = typeof block.input === 'string'
            ? block.input
            : JSON.stringify(block.input);
          texts.push(`[tool:${block.name}] ${inputStr}`);
        }
        // Tool result
        if (block.type === 'tool_result') {
          const content = Array.isArray(block.content)
            ? block.content.filter(c => c.type === 'text').map(c => c.text).join('\n')
            : block.content;
          if (content) texts.push(`[tool_result] ${content}`);
        }
      }
    } else if (typeof msg.content === 'string') {
      texts.push(msg.content);
    }

    if (texts.length === 0) return null;

    return {
      text: texts.join('\n'),
      role,
      direction: role === 'user' ? 'inbound' : 'outbound',
      type: 'message',
    };
  }

  // Delivery queue item (inbound from Telegram/Discord)
  if (entry.type === 'delivery' || entry.channel) {
    const text = entry.text || entry.message || entry.content;
    if (!text) return null;
    return {
      text: String(text),
      role: 'user',
      direction: 'inbound',
      type: 'delivery',
      channel: entry.channel,
    };
  }

  return null;
}

// ─── Threat Handler ───────────────────────────────────────────────────────────

/**
 * Handle a detected threat.
 * @param {Object} result - ClawMoat scan result
 * @param {Object} content - Extracted content
 * @param {Object} context - File/session context
 * @param {Function} [onThreat] - Optional callback for blocking/alerting
 */
async function handleThreat(result, content, context, onThreat) {
  const findings = result.findings
    .map(f => `${f.type}(${f.severity}): ${f.subtype || ''}${f.matched ? ` — "${f.matched}"` : ''}`)
    .join('; ');

  threat(`[${context.sessionId}] ${content.direction} [${content.role}]`);
  threat(`  Severity: ${result.severity} | Action: ${result.action}`);
  threat(`  Findings: ${findings}`);
  threat(`  Text: "${content.text.slice(0, 120).replace(/\n/g, ' ')}"`);

  if (onThreat) {
    await onThreat({ result, content, context });
  }
}

// ─── Session File Tailer ──────────────────────────────────────────────────────

class SessionTailer {
  constructor(sessionsDir, scanner, handlers = {}) {
    this.dir = sessionsDir;
    this.scanner = scanner;
    this.handlers = handlers;
    this.files = new Map(); // path → { position, watcher }
    this.dirWatcher = null;
    this.stats = { processed: 0, threats: 0, errors: 0 };
  }

  start() {
    if (!fs.existsSync(this.dir)) {
      warn(`Sessions dir not found: ${this.dir}`);
      // Watch for directory creation
      this._watchForDir();
      return;
    }
    this._init();
  }

  _watchForDir() {
    const grandparent = path.join(this.dir, '..', '..');
    if (!fs.existsSync(grandparent)) return;
    const w = fs.watch(grandparent, { recursive: true }, (event, filename) => {
      if (filename && filename.includes('sessions') && fs.existsSync(this.dir)) {
        w.close();
        this._init();
      }
    });
  }

  _init() {
    log(`Watching sessions dir: ${this.dir}`);

    // Watch existing session files (start at EOF — don't replay history)
    try {
      const files = fs.readdirSync(this.dir).filter(f => f.endsWith('.jsonl'));
      for (const f of files) {
        this._addFile(path.join(this.dir, f), /* startAtEnd */ true);
      }
      log(`Watching ${files.length} existing session file(s)`);
    } catch (e) {
      warn(`Cannot read sessions dir: ${e.message}`);
    }

    // Watch for new session files
    this.dirWatcher = fs.watch(this.dir, (event, filename) => {
      if (!filename?.endsWith('.jsonl')) return;
      const fp = path.join(this.dir, filename);
      if (!this.files.has(fp) && fs.existsSync(fp)) {
        log(`New session: ${filename}`);
        this._addFile(fp, /* startAtEnd */ false);
      }
    });
  }

  _addFile(filepath, startAtEnd = true) {
    if (this.files.has(filepath)) return;

    let position = 0;
    if (startAtEnd) {
      try { position = fs.statSync(filepath).size; } catch {}
    }

    const state = { position, partial: '' };
    this.files.set(filepath, state);

    const w = fs.watch(filepath, (event) => {
      if (event === 'change') this._drain(filepath, state);
    });
    w.on('error', () => this.files.delete(filepath));
    state.watcher = w;

    log(`Tailing: ${path.basename(filepath)} (offset ${position})`);
  }

  _drain(filepath, state) {
    let fd;
    try {
      fd = fs.openSync(filepath, 'r');
      const stat = fs.fstatSync(fd);
      if (stat.size <= state.position) return;

      const toRead = Math.min(stat.size - state.position, 131072); // 128KB max per read
      const buf = Buffer.alloc(toRead);
      const n = fs.readSync(fd, buf, 0, toRead, state.position);
      state.position += n;

      const chunk = state.partial + buf.slice(0, n).toString('utf8');
      const lines = chunk.split('\n');
      state.partial = lines.pop();

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const entry = JSON.parse(trimmed);
          this._processEntry(entry, filepath);
        } catch {}
      }
    } catch (e) {
      warn(`Read error ${path.basename(filepath)}: ${e.message}`);
    } finally {
      if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    }
  }

  async _processEntry(entry, filepath) {
    const content = extractContent(entry);
    if (!content) return;

    const sessionId = path.basename(filepath, '.jsonl').slice(0, 8);
    const context = { sessionId, filepath, entryId: entry.id, timestamp: entry.timestamp };

    this.stats.processed++;

    let result;
    try {
      if (content.direction === 'inbound') {
        result = this.scanner.scanInbound(content.text);
      } else {
        result = this.scanner.scanOutbound(content.text);
      }
    } catch (e) {
      this.stats.errors++;
      warn(`Scan error: ${e.message}`);
      return;
    }

    if (VERBOSE && result.safe) {
      log(`CLEAN [${sessionId}] ${content.direction} "${content.text.slice(0, 60).replace(/\n/g, ' ')}"`);
    }

    if (!result.safe) {
      this.stats.threats++;
      await handleThreat(result, content, context, this.handlers.onThreat);
    }

    // Always emit for audit logging
    if (this.handlers.onScan) {
      this.handlers.onScan({ result, content, context });
    }
  }

  stop() {
    if (this.dirWatcher) this.dirWatcher.close();
    for (const [, state] of this.files) {
      if (state.watcher) state.watcher.close();
    }
    this.files.clear();
  }

  getStats() { return { ...this.stats }; }
}

// ─── Delivery Queue Watcher ───────────────────────────────────────────────────
// Watch the delivery queue for incoming channel messages (Telegram, Discord, etc.)

class DeliveryWatcher {
  constructor(queueDir, scanner, handlers = {}) {
    this.dir = queueDir;
    this.scanner = scanner;
    this.handlers = handlers;
    this.watcher = null;
    this.stats = { processed: 0, threats: 0 };
  }

  start() {
    if (!fs.existsSync(this.dir)) {
      log(`Delivery queue dir not found: ${this.dir} (skipping)`);
      return;
    }
    log(`Watching delivery queue: ${this.dir}`);
    this.watcher = fs.watch(this.dir, { recursive: false }, async (event, filename) => {
      if (!filename || !filename.endsWith('.json')) return;
      const fp = path.join(this.dir, filename);
      if (!fs.existsSync(fp)) return;
      await this._processFile(fp);
    });
  }

  async _processFile(filepath) {
    let data;
    try {
      data = JSON.parse(fs.readFileSync(filepath, 'utf8'));
    } catch { return; }

    const text = data.text || data.message || data.content;
    if (!text) return;

    this.stats.processed++;

    let result;
    try {
      result = this.scanner.scanInbound(String(text));
    } catch (e) {
      warn(`Delivery scan error: ${e.message}`);
      return;
    }

    if (!result.safe) {
      this.stats.threats++;
      const content = { text: String(text), role: 'user', direction: 'inbound', type: 'delivery', channel: data.channel };
      const context = { sessionId: 'delivery', filepath };
      await handleThreat(result, content, context, this.handlers.onThreat);
    }

    if (this.handlers.onScan) {
      this.handlers.onScan({ result, content: { text, direction: 'inbound' }, context: { filepath } });
    }
  }

  stop() {
    if (this.watcher) this.watcher.close();
  }
}

// ─── Standalone Mode ──────────────────────────────────────────────────────────

if (require.main === module) {
  const CONFIG_PATH = path.join(os.homedir(), '.clawmoat', 'agent.json');
  let config = {};
  try {
    config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    console.log('No config found — running with defaults (no cloud reporting)');
  }

  const AUDIT_PATH = (config.auditLog || '~/.clawmoat/audit.log').replace(/^~/, os.homedir());
  fs.mkdirSync(path.dirname(AUDIT_PATH), { recursive: true });
  const auditStream = fs.createWriteStream(AUDIT_PATH, { flags: 'a' });

  let scanner;
  try {
    scanner = loadScanner();
  } catch (e) {
    console.error('FATAL:', e.message);
    process.exit(1);
  }

  const handlers = {
    onScan: ({ result, content, context }) => {
      const entry = {
        ts: new Date().toISOString(),
        sessionId: context.sessionId,
        direction: content.direction,
        role: content.role,
        safe: result.safe,
        severity: result.severity,
        action: result.action,
        findings: result.findings?.length || 0,
        textPreview: content.text.slice(0, 200),
      };
      auditStream.write(JSON.stringify(entry) + '\n');
    },
    onThreat: async ({ result, content, context }) => {
      // Cloud reporting if configured
      if (config.reportToCloud && config.apiKey && config.apiKey !== 'cm_live_...') {
        const { reportToCloud } = require('./index.js');
        // Use the main agent's reporting if available, else fire-and-forget
      }
    },
  };

  const tailer = new SessionTailer(SESSIONS_DIR, scanner, handlers);
  const deliveryWatcher = new DeliveryWatcher(DELIVERY_QUEUE_DIR, scanner, handlers);

  tailer.start();
  deliveryWatcher.start();

  console.log(`${ts()} [hook] ClawMoat OpenClaw Hook running`);
  console.log(`${ts()} [hook] Monitoring: ${SESSIONS_DIR}`);
  console.log(`${ts()} [hook] Audit log: ${AUDIT_PATH}`);
  if (VERBOSE) console.log(`${ts()} [hook] Verbose mode on`);
  if (DRY_RUN) console.log(`${ts()} [hook] Dry-run mode (no cloud reporting)`);

  process.on('SIGINT', () => {
    console.log(`\n${ts()} [hook] Shutting down...`);
    const s = tailer.getStats();
    console.log(`${ts()} [hook] Stats: processed=${s.processed} threats=${s.threats} errors=${s.errors}`);
    tailer.stop();
    deliveryWatcher.stop();
    auditStream.end();
    process.exit(0);
  });

  // Periodic stats
  setInterval(() => {
    const s = tailer.getStats();
    if (s.processed > 0 || VERBOSE) {
      console.log(`${ts()} [hook] Stats: processed=${s.processed} threats=${s.threats} errors=${s.errors}`);
    }
  }, 30 * 60 * 1000);
}

// ─── Exports (for use by index.js) ───────────────────────────────────────────

module.exports = { SessionTailer, DeliveryWatcher, extractContent, loadScanner };
