/**
 * ClawMoat — Jailbreak Detection
 * 
 * Detects common LLM jailbreak patterns (DAN, roleplay exploits, etc.)
 */

const JAILBREAK_PATTERNS = [
  // DAN and variants
  { pattern: /\bDAN\b.*(?:do anything now|jailbreak)/i, severity: 'critical', name: 'dan_jailbreak' },
  { pattern: /\b(?:DAN|STAN|DUDE|AIM)\s+(?:mode|prompt|jailbreak)/i, severity: 'critical', name: 'named_jailbreak' },

  // Developer/debug mode
  { pattern: /(?:enable|enter|activate|switch\s+to)\s+(?:developer|debug|maintenance|test|unrestricted|unfiltered)\s+mode/i, severity: 'high', name: 'mode_switch' },
  { pattern: /\bsudo\s+mode\b/i, severity: 'high', name: 'mode_switch' },

  // Dual persona / split personality
  { pattern: /(?:respond|answer|reply)\s+(?:as|like)\s+(?:both|two)\s+(?:characters|personas|versions|a\s+normal)/i, severity: 'high', name: 'dual_persona' },
  { pattern: /(?:both)\s+(?:a\s+)?(?:normal|regular|standard)\s+(?:AI|assistant|mode)\s+(?:and|\/)\s+(?:an?\s+)?(?:unrestricted|unfiltered|DAN)/i, severity: 'high', name: 'dual_persona' },
  { pattern: /(?:classic|normal)\s+(?:mode|response)\s+(?:and|vs|\/)\s+(?:jailbreak|DAN|unfiltered)/i, severity: 'high', name: 'dual_persona' },

  // "Hypothetical" bypass
  { pattern: /(?:hypothetically|theoretically|in\s+a\s+fictional)\s+(?:how\s+would|could\s+you|what\s+if)/i, severity: 'medium', name: 'hypothetical_bypass' },
  { pattern: /(?:write|create)\s+(?:a\s+)?(?:story|fiction|screenplay)\s+(?:where|about|in\s+which).*(?:hack|exploit|steal|attack)/i, severity: 'medium', name: 'fiction_bypass' },

  // Token smuggling
  { pattern: /(?:translate|decode|convert)\s+(?:this|the\s+following)\s+(?:from\s+)?(?:base64|hex|rot13|binary|morse)/i, severity: 'medium', name: 'encoding_bypass' },

  // Grandma exploit
  { pattern: /(?:my\s+(?:grandma|grandmother|nana))\s+(?:used\s+to|would\s+always)\s+(?:tell|read|say)/i, severity: 'low', name: 'social_engineering' },

  // Prompt leaking via completion
  { pattern: /(?:continue|complete|finish)\s+(?:this|the)\s+(?:sentence|text|prompt)\s*:\s*(?:"|'|`)/i, severity: 'medium', name: 'completion_attack' },

  // Anti-safety patterns
  { pattern: /(?:safety|content|ethical)\s+(?:filters?|guidelines?|restrictions?)\s+(?:are|have\s+been)\s+(?:removed|disabled|turned\s+off)/i, severity: 'critical', name: 'safety_bypass_claim' },
  { pattern: /(?:you\s+(?:can|are\s+able\s+to|have\s+permission\s+to))\s+(?:say|do|generate)\s+anything/i, severity: 'high', name: 'permission_claim' },
];

/**
 * Scan text for jailbreak attempts
 * @param {string} text - Text to scan
 * @returns {object} Scan result
 */
function scanJailbreak(text) {
  if (!text || typeof text !== 'string') {
    return { clean: true, score: 0, findings: [] };
  }

  const findings = [];

  for (const { pattern, severity, name } of JAILBREAK_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      findings.push({
        type: 'jailbreak',
        subtype: name,
        severity,
        matched: match[0].substring(0, 100),
        position: match.index,
      });
    }
  }

  const score = Math.min(findings.length * 30, 100);
  const maxSeverity = findings.reduce(
    (max, f) => (rank(f.severity) > rank(max) ? f.severity : max), 'low'
  );

  return {
    clean: findings.length === 0,
    score,
    severity: findings.length > 0 ? maxSeverity : null,
    findings,
  };
}

function rank(s) {
  return { low: 0, medium: 1, high: 2, critical: 3 }[s] || 0;
}

module.exports = { scanJailbreak, JAILBREAK_PATTERNS };
