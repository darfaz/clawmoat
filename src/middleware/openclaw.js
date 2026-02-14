/**
 * ClawMoat — OpenClaw Integration Middleware
 * 
 * Hooks into OpenClaw's session transcript files to provide
 * real-time monitoring and alerting.
 * 
 * Usage:
 *   const { watchSessions } = require('clawmoat/src/middleware/openclaw');
 *   watchSessions({ agentDir: '~/.openclaw/agents/main' });
 */

const fs = require('fs');
const path = require('path');
const ClawMoat = require('../index');

/**
 * Watch OpenClaw session files for security events
 */
function watchSessions(opts = {}) {
  const agentDir = expandHome(opts.agentDir || '~/.openclaw/agents/main');
  const sessionsDir = path.join(agentDir, 'sessions');
  const moat = new ClawMoat(opts);

  if (!fs.existsSync(sessionsDir)) {
    console.error(`[ClawMoat] Sessions directory not found: ${sessionsDir}`);
    return null;
  }

  console.log(`[ClawMoat] 🏰 Watching sessions in ${sessionsDir}`);

  // Track file sizes to only read new content
  const filePositions = {};

  const watcher = fs.watch(sessionsDir, (eventType, filename) => {
    if (!filename || !filename.endsWith('.jsonl')) return;

    const filePath = path.join(sessionsDir, filename);
    
    try {
      const stat = fs.statSync(filePath);
      const lastPos = filePositions[filename] || 0;

      if (stat.size <= lastPos) return;

      // Read only new content
      const fd = fs.openSync(filePath, 'r');
      const buffer = Buffer.alloc(stat.size - lastPos);
      fs.readSync(fd, buffer, 0, buffer.length, lastPos);
      fs.closeSync(fd);

      filePositions[filename] = stat.size;

      const newContent = buffer.toString('utf8');
      const lines = newContent.split('\n').filter(Boolean);

      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          processEntry(moat, entry, filename);
        } catch {}
      }
    } catch {}
  });

  return {
    moat,
    watcher,
    stop: () => watcher.close(),
    getEvents: (filter) => moat.getEvents(filter),
    getSummary: () => moat.getSummary(),
  };
}

function processEntry(moat, entry, sessionFile) {
  // Scan user messages (inbound)
  if (entry.role === 'user') {
    const text = extractText(entry);
    if (text) {
      const result = moat.scanInbound(text, { context: 'message', session: sessionFile });
      if (!result.safe && result.action === 'block') {
        console.error(`[ClawMoat] 🚨 BLOCKED threat in ${sessionFile}: ${result.findings[0]?.subtype}`);
      }
    }
  }

  // Audit tool calls (from assistant)
  if (entry.role === 'assistant' && Array.isArray(entry.content)) {
    for (const part of entry.content) {
      if (part.type === 'toolCall') {
        const result = moat.evaluateTool(part.name, part.arguments || {});
        if (result.decision === 'deny') {
          console.error(`[ClawMoat] 🚨 BLOCKED tool call: ${part.name} — ${result.reason}`);
        }
      }
    }
  }

  // Scan tool results for injected content
  if (entry.role === 'tool') {
    const text = extractText(entry);
    if (text) {
      moat.scanInbound(text, { context: 'tool_output', session: sessionFile });
    }
  }

  // Check outbound messages for secrets
  if (entry.role === 'assistant') {
    const text = extractText(entry);
    if (text) {
      const result = moat.scanOutbound(text, { context: 'assistant_reply', session: sessionFile });
      if (!result.safe) {
        console.error(`[ClawMoat] 🚨 SECRET in outbound message: ${result.findings[0]?.subtype}`);
      }
    }
  }
}

function extractText(entry) {
  if (typeof entry.content === 'string') return entry.content;
  if (Array.isArray(entry.content)) {
    return entry.content
      .filter(c => c.type === 'text')
      .map(c => c.text)
      .join('\n');
  }
  return null;
}

function expandHome(p) {
  return p.replace(/^~/, process.env.HOME || '/home/user');
}

module.exports = { watchSessions };
