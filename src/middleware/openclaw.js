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
const { InsiderThreatDetector } = require('../guardian/insider-threat');

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
  let monitor = null;

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
          // Track for insider threat detection
          if (monitor && monitor._trackEntry) monitor._trackEntry(entry, filename);
        } catch {}
      }
    } catch {}
  });

  // Run insider threat detection on accumulated transcript
  const insiderDetector = new InsiderThreatDetector();
  const sessionTranscripts = {};

  monitor = {
    moat,
    watcher,
    insiderDetector,
    stop: () => watcher.close(),
    getEvents: (filter) => moat.getEvents(filter),
    getSummary: () => moat.getSummary(),
    getInsiderThreats: (sessionFile) => {
      const transcript = sessionTranscripts[sessionFile] || [];
      return insiderDetector.analyze(transcript);
    },
    _trackEntry: (entry, sessionFile) => {
      if (!sessionTranscripts[sessionFile]) sessionTranscripts[sessionFile] = [];
      sessionTranscripts[sessionFile].push(entry);
      // Periodic insider threat scan (every 20 entries)
      const t = sessionTranscripts[sessionFile];
      if (t.length % 20 === 0) {
        const result = insiderDetector.analyze(t);
        if (result.recommendation === 'block' || result.recommendation === 'alert') {
          console.error(`[ClawMoat] 🚨 INSIDER THREAT in ${sessionFile}: score=${result.riskScore}, recommendation=${result.recommendation}, threats=${result.threats.length}`);
        }
      }
    },
  };

  return monitor;
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

/**
 * Scan inter-agent messages with heightened sensitivity.
 * Agent-to-agent messages can be more precisely crafted for injection.
 * 
 * @param {string} message - The message content
 * @param {string} senderAgent - Sender agent identifier
 * @param {string} receiverAgent - Receiver agent identifier
 * @returns {{ safe: boolean, findings: Array, confidence: number, recommendation: 'allow'|'flag'|'block' }}
 */
function scanInterAgentMessage(message, senderAgent, receiverAgent) {
  if (!message || typeof message !== 'string') {
    return { safe: true, findings: [], confidence: 1.0, recommendation: 'allow' };
  }

  const moat = new ClawMoat({ quiet: true });
  const findings = [];

  // Run full inbound scan (prompt injection, jailbreak, memory poison, etc.)
  const inbound = moat.scanInbound(message, { context: 'inter_agent' });
  if (!inbound.safe) {
    findings.push(...inbound.findings);
  }

  // Run outbound scan (secrets, PII, exfiltration)
  const outbound = moat.scanOutbound(message, { context: 'inter_agent' });
  if (!outbound.safe) {
    findings.push(...outbound.findings);
  }

  // Additional agent-specific checks with higher sensitivity
  const agentPatterns = [
    { pattern: /\boverride\s+(?:your|the)\s+(?:instructions|rules|config|policy)/i, label: 'instruction_override_agent', severity: 'critical' },
    { pattern: /\bpretend\s+(?:you(?:'re| are)\s+)?(?:a different|another|the main)\s+agent/i, label: 'agent_impersonation', severity: 'critical' },
    { pattern: /\bforward\s+(?:this|all|the)\s+(?:to|message)/i, label: 'message_forwarding', severity: 'warning' },
    { pattern: /\bdon'?t\s+(?:tell|inform|alert|notify)\s+(?:the|your)\s+(?:user|human|admin|operator)/i, label: 'concealment_attempt', severity: 'critical' },
    { pattern: /\bhide\s+this\s+from/i, label: 'concealment_attempt', severity: 'critical' },
    { pattern: /\bexecute\s+(?:without|before)\s+(?:review|approval|checking)/i, label: 'bypass_review', severity: 'high' },
    { pattern: /\bescalate\s+(?:your\s+)?(?:privileges|permissions|access)/i, label: 'privilege_escalation', severity: 'critical' },
    { pattern: /\b(?:send|post|upload|exfil)\s+.*\b(?:credentials|tokens?|keys?|secrets?|passwords?)\b/i, label: 'credential_exfiltration', severity: 'critical' },
    { pattern: /\bagent[_\s]?(?:chain|relay|hop)/i, label: 'agent_chaining', severity: 'warning' },
    { pattern: /\bignore\s+(?:the\s+)?(?:safety|security|policy|guardrail|clawmoat)/i, label: 'safety_bypass', severity: 'critical' },
  ];

  for (const rule of agentPatterns) {
    if (rule.pattern.test(message)) {
      findings.push({
        type: 'inter_agent_threat',
        subtype: rule.label,
        severity: rule.severity,
        matched: (message.match(rule.pattern) || [''])[0].substring(0, 100),
      });
    }
  }

  // Calculate confidence based on number and severity of findings
  const severityWeight = { low: 0.1, medium: 0.3, high: 0.6, critical: 0.9, warning: 0.4 };
  let maxWeight = 0;
  for (const f of findings) {
    const w = severityWeight[f.severity] || 0.3;
    if (w > maxWeight) maxWeight = w;
  }

  const confidence = findings.length === 0 ? 1.0 : Math.min(1.0, 0.5 + maxWeight * 0.5);
  const safe = findings.length === 0;

  let recommendation = 'allow';
  if (findings.some(f => f.severity === 'critical')) {
    recommendation = 'block';
  } else if (findings.length > 0) {
    recommendation = 'flag';
  }

  return { safe, findings, confidence, recommendation };
}

module.exports = { watchSessions, scanInterAgentMessage };
