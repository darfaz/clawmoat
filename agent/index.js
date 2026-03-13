#!/usr/bin/env node
/**
 * ClawMoat Local Agent — Main Daemon
 * 
 * Monitors OpenClaw session activity, scans messages through ClawMoat,
 * reports results to the cloud dashboard, and maintains a local audit log.
 * 
 * Usage: node agent/index.js [--config <path>] [--dry-run] [--verbose]
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const http = require('http');
const readline = require('readline');
const { EventEmitter } = require('events');

// ─── Config ───────────────────────────────────────────────────────────────────

const DEFAULT_CONFIG_PATH = path.join(os.homedir(), '.clawmoat', 'agent.json');
const OPENCLAW_SESSIONS_DIR = path.join(os.homedir(), '.openclaw', 'agents', 'main', 'sessions');

const args = process.argv.slice(2);
const DRY_RUN = args.includes('--dry-run');
const VERBOSE = args.includes('--verbose') || args.includes('-v');
const configPath = (() => {
  const i = args.indexOf('--config');
  return i >= 0 ? args[i + 1] : DEFAULT_CONFIG_PATH;
})();

function loadConfig() {
  try {
    const raw = fs.readFileSync(configPath, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    if (e.code === 'ENOENT') {
      console.error(`[clawmoat-agent] Config not found at ${configPath}`);
      console.error(`[clawmoat-agent] Run: node agent/setup.js`);
      process.exit(1);
    }
    console.error(`[clawmoat-agent] Failed to parse config: ${e.message}`);
    process.exit(1);
  }
}

let config = loadConfig();

function resolveAuditLog() {
  const raw = config.auditLog || '~/.clawmoat/audit.log';
  return raw.replace(/^~/, os.homedir());
}

// ─── ClawMoat Scanner ─────────────────────────────────────────────────────────

let moat;
try {
  const ClawMoat = require(path.join(os.homedir(), 'clawmoat', 'src', 'index.js'));
  moat = new ClawMoat({ quiet: true });
  log('ClawMoat scanner loaded from ~/clawmoat');
} catch (e) {
  try {
    const { ClawMoat } = require('clawmoat');
    moat = new ClawMoat({ quiet: true });
    log('ClawMoat scanner loaded from npm');
  } catch (e2) {
    console.error('[clawmoat-agent] Cannot load ClawMoat:', e.message);
    process.exit(1);
  }
}

// ─── Logging ──────────────────────────────────────────────────────────────────

function log(...args) {
  if (VERBOSE || args[0]?.includes('ERROR') || args[0]?.includes('THREAT')) {
    console.log(new Date().toISOString(), '[clawmoat-agent]', ...args);
  }
}

function logAlways(...args) {
  console.log(new Date().toISOString(), '[clawmoat-agent]', ...args);
}

// ─── Audit Log ────────────────────────────────────────────────────────────────

let auditStream;

function initAuditLog() {
  const auditPath = resolveAuditLog();
  fs.mkdirSync(path.dirname(auditPath), { recursive: true });
  auditStream = fs.createWriteStream(auditPath, { flags: 'a' });
  log(`Audit log: ${auditPath}`);
}

function writeAudit(entry) {
  const line = JSON.stringify({ ...entry, agentVersion: '1.0.0', ts: new Date().toISOString() });
  if (auditStream) auditStream.write(line + '\n');
}

// ─── Cloud Reporting ──────────────────────────────────────────────────────────

const RETRY_DELAYS = [1000, 5000, 15000, 60000]; // ms

async function reportToCloud(scanResult, meta) {
  if (!config.reportToCloud || DRY_RUN) {
    if (DRY_RUN) log('[DRY-RUN] Would report to cloud:', JSON.stringify(scanResult).slice(0, 100));
    return;
  }
  if (!config.apiKey || config.apiKey === 'cm_live_...') {
    log('No valid API key — skipping cloud report');
    return;
  }

  const dashboardUrl = config.dashboardUrl || 'https://app.clawmoat.com';
  const payload = JSON.stringify({
    source: 'local-agent',
    agentVersion: '1.0.0',
    hostname: os.hostname(),
    meta,
    result: scanResult,
  });

  for (let attempt = 0; attempt <= RETRY_DELAYS.length; attempt++) {
    try {
      await httpPost(`${dashboardUrl}/api/scan`, payload, {
        'Authorization': `Bearer ${config.apiKey}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      });
      log('Reported to cloud dashboard');
      return;
    } catch (e) {
      if (attempt < RETRY_DELAYS.length) {
        const delay = RETRY_DELAYS[attempt];
        log(`Cloud report failed (attempt ${attempt + 1}): ${e.message} — retrying in ${delay}ms`);
        await sleep(delay);
      } else {
        log(`ERROR: Cloud report failed after all retries: ${e.message}`);
      }
    }
  }
}

function httpPost(url, body, headers) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;
    const req = lib.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers,
      timeout: 10000,
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(data);
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
    req.write(body);
    req.end();
  });
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ─── Scan Engine ──────────────────────────────────────────────────────────────

async function scanAndReport(text, meta) {
  if (!text || typeof text !== 'string' || text.trim().length === 0) return;

  let result;
  try {
    if (meta.direction === 'inbound' && config.scanInbound !== false) {
      result = moat.scanInbound(text);
    } else if (meta.direction === 'outbound' && config.scanOutbound !== false) {
      result = moat.scanOutbound(text);
    } else {
      return;
    }
  } catch (e) {
    log(`ERROR: Scan failed: ${e.message}`);
    return;
  }

  const entry = { meta, result, text: text.slice(0, 500) };
  writeAudit(entry);

  if (!result.safe || VERBOSE) {
    const label = result.safe ? 'CLEAN' : `THREAT[${result.severity}]`;
    const findings = result.findings?.length
      ? ` — ${result.findings.map(f => `${f.type}:${f.subtype}`).join(', ')}`
      : '';
    logAlways(`${label} ${meta.direction} [${meta.role}] ${findings} | "${text.slice(0, 80).replace(/\n/g, ' ')}"`);
  }

  if (!result.safe) {
    await reportToCloud(result, meta);
  }
}

// ─── Session File Watcher ─────────────────────────────────────────────────────

class SessionWatcher extends EventEmitter {
  constructor(sessionsDir) {
    super();
    this.sessionsDir = sessionsDir;
    this.watched = new Map(); // file → { fd, position, watcher }
    this.dirWatcher = null;
  }

  start() {
    if (!fs.existsSync(this.sessionsDir)) {
      log(`WARNING: Sessions dir not found: ${this.sessionsDir} — watching parent`);
      // Watch parent for when sessions dir appears
      const parent = path.dirname(this.sessionsDir);
      if (fs.existsSync(parent)) {
        fs.watch(parent, (event, filename) => {
          if (filename === 'sessions' && fs.existsSync(this.sessionsDir)) {
            this._watchDir();
          }
        });
      }
      return;
    }
    this._watchDir();
  }

  _watchDir() {
    log(`Watching sessions: ${this.sessionsDir}`);

    // Watch existing files
    try {
      const files = fs.readdirSync(this.sessionsDir).filter(f => f.endsWith('.jsonl'));
      for (const file of files) {
        this._startWatchingFile(path.join(this.sessionsDir, file));
      }
    } catch (e) {
      log(`ERROR reading sessions dir: ${e.message}`);
    }

    // Watch for new files
    this.dirWatcher = fs.watch(this.sessionsDir, (event, filename) => {
      if (!filename?.endsWith('.jsonl')) return;
      const fullPath = path.join(this.sessionsDir, filename);
      if (!this.watched.has(fullPath) && fs.existsSync(fullPath)) {
        log(`New session file: ${filename}`);
        this._startWatchingFile(fullPath);
      }
    });
  }

  _startWatchingFile(filePath) {
    if (this.watched.has(filePath)) return;

    let position;
    try {
      const stat = fs.statSync(filePath);
      // For existing files, start at end (don't re-scan history)
      position = stat.size;
    } catch (e) {
      position = 0;
    }

    const state = { position, pending: '' };
    this.watched.set(filePath, state);

    const watcher = fs.watch(filePath, (event) => {
      if (event === 'change') {
        this._readNewLines(filePath, state);
      }
    });

    watcher.on('error', () => {
      this.watched.delete(filePath);
    });

    state.watcher = watcher;
    log(`Watching file: ${path.basename(filePath)} (from byte ${position})`);
  }

  _readNewLines(filePath, state) {
    let fd;
    try {
      fd = fs.openSync(filePath, 'r');
      const stat = fs.fstatSync(fd);
      if (stat.size <= state.position) return;

      const chunkSize = Math.min(stat.size - state.position, 65536);
      const buf = Buffer.alloc(chunkSize);
      const bytesRead = fs.readSync(fd, buf, 0, chunkSize, state.position);
      state.position += bytesRead;

      const text = state.pending + buf.slice(0, bytesRead).toString('utf8');
      const lines = text.split('\n');
      state.pending = lines.pop(); // last partial line

      for (const line of lines) {
        if (line.trim()) {
          try {
            const entry = JSON.parse(line);
            this.emit('entry', entry, filePath);
          } catch (e) {
            // partial JSON, skip
          }
        }
      }
    } catch (e) {
      log(`ERROR reading ${path.basename(filePath)}: ${e.message}`);
    } finally {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch {}
      }
    }
  }

  stop() {
    if (this.dirWatcher) this.dirWatcher.close();
    for (const [, state] of this.watched) {
      if (state.watcher) state.watcher.close();
    }
    this.watched.clear();
  }
}

// ─── Message Parser ───────────────────────────────────────────────────────────

function parseEntry(entry, filePath) {
  // Only process message events
  if (entry.type !== 'message' || !entry.message) return null;

  const msg = entry.message;
  const role = msg.role; // 'user' | 'assistant'
  const timestamp = entry.timestamp || msg.timestamp;

  // Extract text content
  const texts = [];
  if (Array.isArray(msg.content)) {
    for (const block of msg.content) {
      if (block.type === 'text' && block.text) {
        texts.push(block.text);
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
    sessionFile: path.basename(filePath, '.jsonl'),
    messageId: entry.id,
    timestamp,
  };
}

// ─── Workspace Watcher (fallback) ─────────────────────────────────────────────
// If no sessions, also watch workspace for changes as a secondary signal

class WorkspaceWatcher extends EventEmitter {
  constructor(workspaceDir) {
    super();
    this.dir = workspaceDir;
    this.watcher = null;
  }

  start() {
    if (!fs.existsSync(this.dir)) return;
    log(`Watching workspace: ${this.dir}`);
    // Shallow watch — just detect activity, don't scan file contents
    this.watcher = fs.watch(this.dir, { recursive: false }, (event, filename) => {
      if (filename && !filename.startsWith('.')) {
        this.emit('activity', { event, filename });
      }
    });
  }

  stop() {
    if (this.watcher) this.watcher.close();
  }
}

// ─── Heartbeat / Stats ────────────────────────────────────────────────────────

let stats = { scanned: 0, threats: 0, errors: 0, startedAt: new Date().toISOString() };

setInterval(() => {
  logAlways(`[heartbeat] scanned=${stats.scanned} threats=${stats.threats} errors=${stats.errors} uptime=${Math.floor((Date.now() - new Date(stats.startedAt)) / 1000)}s`);
}, 60 * 60 * 1000); // every hour

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  logAlways('ClawMoat Local Agent starting...');
  logAlways(`Config: ${configPath}`);
  logAlways(`Dry-run: ${DRY_RUN} | Verbose: ${VERBOSE}`);
  logAlways(`Scan inbound: ${config.scanInbound !== false} | outbound: ${config.scanOutbound !== false}`);
  logAlways(`Cloud reporting: ${config.reportToCloud && config.apiKey && config.apiKey !== 'cm_live_...' ? 'enabled' : 'disabled (no valid API key)'}`);

  initAuditLog();

  // Watch OpenClaw sessions
  const watcher = new SessionWatcher(OPENCLAW_SESSIONS_DIR);

  watcher.on('entry', async (entry, filePath) => {
    const parsed = parseEntry(entry, filePath);
    if (!parsed) return;

    stats.scanned++;
    try {
      await scanAndReport(parsed.text, {
        direction: parsed.direction,
        role: parsed.role,
        sessionFile: parsed.sessionFile,
        messageId: parsed.messageId,
        timestamp: parsed.timestamp,
      });
      if (moat.stats?.blocked > (stats.threats || 0)) {
        stats.threats = moat.stats.blocked;
      }
    } catch (e) {
      stats.errors++;
      log(`ERROR: ${e.message}`);
    }
  });

  watcher.start();

  // Also watch for hooks directory for future hook integration
  const hooksDir = path.join(os.homedir(), '.openclaw', 'hooks');
  if (fs.existsSync(hooksDir)) {
    log(`OpenClaw hooks dir found at ${hooksDir}`);
  }

  logAlways('Agent running. Press Ctrl+C to stop.');
  logAlways(`Monitoring: ${OPENCLAW_SESSIONS_DIR}`);

  // Graceful shutdown
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  function shutdown() {
    logAlways('Shutting down...');
    watcher.stop();
    if (auditStream) auditStream.end();
    logAlways(`Final stats: scanned=${stats.scanned} threats=${stats.threats} errors=${stats.errors}`);
    process.exit(0);
  }
}

main().catch(e => {
  console.error('[clawmoat-agent] FATAL:', e);
  process.exit(1);
});
