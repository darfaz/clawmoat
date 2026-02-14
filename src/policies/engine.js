/**
 * ClawMoat — Policy Engine
 * 
 * Evaluates tool calls against security policies.
 * Returns allow/deny/warn decisions with explanations.
 */

const path = require('path');

const DECISIONS = { allow: 'allow', deny: 'deny', warn: 'warn', review: 'review' };

/**
 * Evaluate a tool call against policies
 * @param {string} tool - Tool name (exec, read, write, browser, etc.)
 * @param {object} args - Tool arguments
 * @param {object} policies - Policy config
 * @returns {object} Decision
 */
function evaluateToolCall(tool, args, policies) {
  switch (tool) {
    case 'exec': return evaluateExec(args, policies.exec || {});
    case 'read':
    case 'Read': return evaluateFileRead(args, policies.file || {});
    case 'write':
    case 'Write':
    case 'edit':
    case 'Edit': return evaluateFileWrite(args, policies.file || {});
    case 'browser': return evaluateBrowser(args, policies.browser || {});
    case 'message': return evaluateMessage(args, policies.message || {});
    default: return { decision: DECISIONS.allow, tool, reason: 'No policy defined' };
  }
}

function evaluateExec(args, policy) {
  const command = args.command || '';
  
  // Check block patterns
  for (const pattern of (policy.block_patterns || [])) {
    const regex = globToRegex(pattern);
    if (regex.test(command)) {
      return {
        decision: DECISIONS.deny,
        tool: 'exec',
        reason: `Command matches blocked pattern: ${pattern}`,
        matched: command.substring(0, 200),
        severity: 'critical',
      };
    }
  }

  // Check dangerous commands
  const dangerousCommands = [
    { pattern: /\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+|.*-[a-zA-Z]*r[a-zA-Z]*f)/, reason: 'Recursive force delete', severity: 'critical' },
    { pattern: /\bmkfs\b/, reason: 'Filesystem format', severity: 'critical' },
    { pattern: /\bdd\s+if=/, reason: 'Low-level disk write', severity: 'high' },
    { pattern: />\s*\/dev\/sd[a-z]/, reason: 'Direct disk write', severity: 'critical' },
    { pattern: /\bchmod\s+777\b/, reason: 'World-writable permissions', severity: 'medium' },
    { pattern: /\bchmod\s+\+s\b/, reason: 'Set SUID bit', severity: 'high' },
    { pattern: /\bcrontab\s+-r\b/, reason: 'Remove all cron jobs', severity: 'high' },
    { pattern: /\biptables\s+-F\b/, reason: 'Flush all firewall rules', severity: 'critical' },
    { pattern: /\bpasswd\b/, reason: 'Password change attempt', severity: 'high' },
    { pattern: /\buseradd\b|\badduser\b/, reason: 'User creation', severity: 'high' },
    { pattern: /\bvisudo\b|\bsudoers\b/, reason: 'Sudo configuration change', severity: 'critical' },
    { pattern: /\bnc\s+-[a-z]*l/i, reason: 'Network listener (reverse shell risk)', severity: 'critical' },
    { pattern: /\b(?:python|node|ruby|perl)\s+-.*(?:socket|http\.server|SimpleHTTP)/i, reason: 'Network server spawn', severity: 'high' },
    { pattern: /\bcurl\b.*\|\s*(?:bash|sh|zsh)\b/, reason: 'Pipe remote script to shell', severity: 'critical' },
    { pattern: /\bwget\b.*\|\s*(?:bash|sh|zsh)\b/, reason: 'Pipe remote script to shell', severity: 'critical' },
    { pattern: /\beval\s+\$\(curl\b/, reason: 'Eval remote content', severity: 'critical' },
    { pattern: /\beval\s+\$\(wget\b/, reason: 'Eval remote content', severity: 'critical' },
  ];

  for (const { pattern, reason, severity } of dangerousCommands) {
    if (pattern.test(command)) {
      return {
        decision: severity === 'critical' ? DECISIONS.deny : DECISIONS.warn,
        tool: 'exec',
        reason,
        matched: command.substring(0, 200),
        severity,
      };
    }
  }

  // Check require_approval patterns
  for (const pattern of (policy.require_approval || [])) {
    const regex = globToRegex(pattern);
    if (regex.test(command)) {
      return {
        decision: DECISIONS.review,
        tool: 'exec',
        reason: `Command requires approval: ${pattern}`,
        matched: command.substring(0, 200),
        severity: 'medium',
      };
    }
  }

  return { decision: DECISIONS.allow, tool: 'exec' };
}

function evaluateFileRead(args, policy) {
  const filePath = args.path || args.file_path || '';
  const expanded = expandHome(filePath);

  for (const pattern of (policy.deny_read || [])) {
    const regex = globToRegex(expandHome(pattern));
    if (regex.test(expanded)) {
      return {
        decision: DECISIONS.deny,
        tool: 'read',
        reason: `File read blocked by policy: ${pattern}`,
        path: filePath,
        severity: 'high',
      };
    }
  }

  return { decision: DECISIONS.allow, tool: 'read' };
}

function evaluateFileWrite(args, policy) {
  const filePath = args.path || args.file_path || '';
  const expanded = expandHome(filePath);

  for (const pattern of (policy.deny_write || [])) {
    const regex = globToRegex(expandHome(pattern));
    if (regex.test(expanded)) {
      return {
        decision: DECISIONS.deny,
        tool: 'write',
        reason: `File write blocked by policy: ${pattern}`,
        path: filePath,
        severity: 'high',
      };
    }
  }

  return { decision: DECISIONS.allow, tool: 'write' };
}

function evaluateBrowser(args, policy) {
  const url = args.targetUrl || args.url || '';
  
  for (const pattern of (policy.block_domains || [])) {
    const regex = globToRegex(pattern);
    if (regex.test(url)) {
      return {
        decision: DECISIONS.deny,
        tool: 'browser',
        reason: `Domain blocked by policy: ${pattern}`,
        url,
        severity: 'high',
      };
    }
  }

  return { decision: DECISIONS.allow, tool: 'browser' };
}

function evaluateMessage(args, policy) {
  // Flag messages going to unknown recipients
  return { decision: DECISIONS.allow, tool: 'message' };
}

// Helpers
function expandHome(p) {
  return p.replace(/^~/, process.env.HOME || '/home/user');
}

function globToRegex(glob) {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '§DOUBLESTAR§')
    .replace(/\*/g, '[^/]*')
    .replace(/§DOUBLESTAR§/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(escaped, 'i');
}

module.exports = { evaluateToolCall, DECISIONS };
