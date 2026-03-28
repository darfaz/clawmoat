/**
 * Ban Topics / Substrings / Allow-Deny Lists
 * 
 * Stolen from LLM Guard. Enterprises love obvious controls.
 * Configure banned topics, required keywords, regex patterns, and deny/allow lists.
 * 
 * @module ban-scanner
 */

'use strict';

/**
 * Create a ban scanner with configurable rules
 * @param {Object} config - Ban configuration
 * @param {string[]} [config.bannedSubstrings=[]] - Exact substrings to block (case-insensitive)
 * @param {RegExp[]|string[]} [config.bannedPatterns=[]] - Regex patterns to block
 * @param {string[]} [config.bannedTopics=[]] - Topic keywords to block
 * @param {string[]} [config.allowedTopics=[]] - If set, ONLY these topics are allowed
 * @param {string[]} [config.requiredSubstrings=[]] - At least one must be present (for output validation)
 * @param {Object} [config.customRules=[]] - Array of {name, test: (text) => bool, severity, message}
 * @returns {Object} Scanner instance
 */
function createBanScanner(config = {}) {
  const {
    bannedSubstrings = [],
    bannedPatterns = [],
    bannedTopics = [],
    allowedTopics = [],
    requiredSubstrings = [],
    customRules = [],
  } = config;

  // Pre-compile patterns
  const compiledPatterns = bannedPatterns.map(p => 
    p instanceof RegExp ? p : new RegExp(p, 'gi')
  );

  /**
   * Scan text against ban rules
   * @param {string} text - Text to scan
   * @returns {Object} { safe, findings }
   */
  function scan(text) {
    const findings = [];
    const lower = text.toLowerCase();

    // Check banned substrings
    for (const sub of bannedSubstrings) {
      if (lower.includes(sub.toLowerCase())) {
        findings.push({
          type: 'banned_content',
          subtype: 'banned_substring',
          severity: 'high',
          confidence: 1.0,
          evidence: `Banned substring found: "${sub}"`,
          matched: sub,
          recommended_action: 'block',
        });
      }
    }

    // Check banned patterns
    for (const pattern of compiledPatterns) {
      pattern.lastIndex = 0; // Reset regex state
      const match = pattern.exec(text);
      if (match) {
        findings.push({
          type: 'banned_content',
          subtype: 'banned_pattern',
          severity: 'high',
          confidence: 0.95,
          evidence: `Banned pattern matched: "${match[0].substring(0, 60)}"`,
          matched: match[0].substring(0, 100),
          recommended_action: 'block',
        });
      }
    }

    // Check banned topics (keyword-based)
    for (const topic of bannedTopics) {
      const topicWords = topic.toLowerCase().split(/\s+/);
      const allPresent = topicWords.every(w => lower.includes(w));
      if (allPresent) {
        findings.push({
          type: 'banned_content',
          subtype: 'banned_topic',
          severity: 'medium',
          confidence: 0.7,
          evidence: `Banned topic detected: "${topic}"`,
          topic,
          recommended_action: 'block',
        });
      }
    }

    // Check allowed topics (if set, text MUST match at least one)
    if (allowedTopics.length > 0) {
      const matchesAllowed = allowedTopics.some(topic => {
        const topicWords = topic.toLowerCase().split(/\s+/);
        return topicWords.some(w => lower.includes(w));
      });
      if (!matchesAllowed) {
        findings.push({
          type: 'banned_content',
          subtype: 'off_topic',
          severity: 'medium',
          confidence: 0.6,
          evidence: `Text does not match any allowed topics: ${allowedTopics.join(', ')}`,
          recommended_action: 'block',
        });
      }
    }

    // Check required substrings (output validation)
    if (requiredSubstrings.length > 0) {
      const hasRequired = requiredSubstrings.some(s => lower.includes(s.toLowerCase()));
      if (!hasRequired) {
        findings.push({
          type: 'banned_content',
          subtype: 'missing_required',
          severity: 'low',
          confidence: 0.8,
          evidence: `Missing required content. Expected one of: ${requiredSubstrings.join(', ')}`,
          recommended_action: 'warn',
        });
      }
    }

    // Custom rules
    for (const rule of customRules) {
      try {
        if (rule.test(text)) {
          findings.push({
            type: 'banned_content',
            subtype: 'custom_rule',
            severity: rule.severity || 'medium',
            confidence: 0.9,
            evidence: rule.message || `Custom rule "${rule.name}" triggered`,
            rule: rule.name,
            recommended_action: rule.action || 'block',
          });
        }
      } catch (_) { /* skip broken rules */ }
    }

    return {
      safe: findings.length === 0,
      findings,
    };
  }

  return { scan };
}

// Pre-built rulesets
const PRESETS = {
  // Block competitor mentions (for support bots)
  noCompetitors: (competitors) => ({
    bannedSubstrings: competitors,
  }),

  // Block personal information requests
  noPIIRequests: () => ({
    bannedPatterns: [
      /what.{0,20}(social security|ssn|credit card|bank account)/i,
      /tell me your.{0,20}(password|address|phone|email)/i,
      /give me.{0,20}(credentials|access|token|key)/i,
    ],
  }),

  // Block harmful content
  noHarmful: () => ({
    bannedTopics: [
      'how to hack', 'how to exploit', 'how to attack',
      'make a bomb', 'make a weapon', 'create malware',
      'bypass security', 'disable firewall', 'crack password',
    ],
  }),

  // Coding agent safety
  codingAgent: () => ({
    bannedPatterns: [
      /rm\s+-rf\s+[\/~]/,
      /curl.*\|\s*bash/,
      /wget.*\|\s*sh/,
      /chmod\s+777/,
      /:()\s*{.*}/,
    ],
    bannedSubstrings: [
      '/etc/shadow',
      'DROP TABLE',
      'format c:',
    ],
  }),
};

module.exports = {
  createBanScanner,
  PRESETS,
};
