/**
 * ClawMoat — Memory Poisoning Detection Scanner
 * 
 * Detects attempts to poison agent memory files (MEMORY.md, SOUL.md, etc.)
 */

const MEMORY_PATTERNS = [
  // Direct memory file manipulation
  { pattern: /(?:add|write|append|update|modify|change|insert|put)\s+(?:this\s+)?(?:to|in|into)\s+(?:your\s+)?(?:MEMORY|SOUL|memory|soul)\.md/i, severity: 'critical', name: 'memory_file_write' },
  { pattern: /(?:add|write|append|update|modify|change|insert|put)\s+(?:this\s+)?(?:to|in|into)\s+(?:your\s+)?(?:AGENTS|HEARTBEAT|TOOLS|BOOTSTRAP)\.md/i, severity: 'critical', name: 'config_file_write' },

  // Memory manipulation instructions
  { pattern: /\bremember\s+that\s+your\s+(?:instructions?|rules?|guidelines?|purpose|goal)\s+(?:are|is)\b/i, severity: 'critical', name: 'memory_override' },
  { pattern: /\b(?:save|store|memorize|remember)\s+(?:this|the\s+following)\s+(?:for|across|between)\s+(?:future\s+)?sessions?\b/i, severity: 'high', name: 'persistent_memory' },
  { pattern: /\b(?:update|change|modify|edit)\s+(?:your\s+)?(?:personality|identity|soul|core\s+(?:values|instructions?))\b/i, severity: 'critical', name: 'identity_override' },

  // Config file targeting
  { pattern: /\b(?:edit|modify|update|write\s+to|overwrite)\s+(?:the\s+)?(?:AGENTS|TOOLS|HEARTBEAT|BOOTSTRAP|SOUL|MEMORY)\.md\b/i, severity: 'critical', name: 'config_targeting' },

  // Persistent injection (survive across sessions)
  { pattern: /\b(?:always|forever|permanently|from\s+now\s+on)\s+(?:remember|keep|maintain|follow|obey)\b/i, severity: 'high', name: 'persistent_injection' },
  { pattern: /\b(?:in\s+(?:all|every)\s+future\s+(?:sessions?|conversations?|interactions?))\b/i, severity: 'high', name: 'persistent_injection' },
  { pattern: /\b(?:across\s+(?:all\s+)?sessions?\s+(?:you\s+)?(?:must|should|will))\b/i, severity: 'high', name: 'persistent_injection' },

  // Time bomb patterns
  { pattern: /\b(?:next\s+time|when\s+you\s+(?:next\s+)?see|if\s+(?:someone|anyone|a\s+user)\s+(?:asks?|says?|mentions?))\b.*\b(?:do|execute|run|say|respond|output)\b/i, severity: 'high', name: 'time_bomb' },
  { pattern: /\b(?:whenever|each\s+time|every\s+time)\s+(?:you|someone|a\s+user)\b.*\b(?:secretly|silently|without\s+(?:telling|mentioning|saying))\b/i, severity: 'critical', name: 'time_bomb' },
  { pattern: /\b(?:after\s+this\s+(?:conversation|session|chat)\s+(?:ends?|is\s+over))\b/i, severity: 'high', name: 'time_bomb' },
];

/**
 * Scan text for memory poisoning attempts
 * @param {string} text - Text to scan
 * @param {object} opts - Options
 * @returns {object} Scan result { clean, findings[], severity }
 */
function scanMemoryPoison(text, opts = {}) {
  if (!text || typeof text !== 'string') {
    return { clean: true, findings: [], severity: null };
  }

  const findings = [];

  for (const { pattern, severity, name } of MEMORY_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      findings.push({
        type: 'memory_poison',
        subtype: name,
        severity,
        matched: match[0].substring(0, 100),
        position: match.index,
      });
    }
  }

  const maxSev = findings.length > 0
    ? findings.reduce((max, f) => rank(f.severity) > rank(max) ? f.severity : max, 'low')
    : null;

  return { clean: findings.length === 0, findings, severity: maxSev };
}

function rank(s) {
  return { low: 0, medium: 1, high: 2, critical: 3 }[s] || 0;
}

module.exports = { scanMemoryPoison };
