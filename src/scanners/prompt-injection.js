/**
 * ClawMoat — Prompt Injection Scanner
 * 
 * Detects prompt injection attempts in text using:
 * 1. Pattern matching (known injection patterns)
 * 2. Heuristic scoring (instruction-like language in data context)
 * 3. (Future) ML classifier via LlamaFirewall/NeMo
 */

// Known prompt injection patterns (case-insensitive)
const INJECTION_PATTERNS = [
  // Direct instruction override
  { pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)/i, severity: 'critical', name: 'instruction_override' },
  { pattern: /disregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|prompts?|rules?|programming)/i, severity: 'critical', name: 'instruction_override' },
  { pattern: /forget\s+(all\s+)?(previous|prior|your|everything)/i, severity: 'high', name: 'instruction_override' },
  { pattern: /override\s+(your|all|the)\s+(instructions?|rules?|guidelines?|programming)/i, severity: 'critical', name: 'instruction_override' },
  
  // Role manipulation
  { pattern: /you\s+are\s+now\s+(a|an|the|my)\s+/i, severity: 'high', name: 'role_manipulation' },
  { pattern: /act\s+as\s+(a|an|if|though)\s+/i, severity: 'medium', name: 'role_manipulation' },
  { pattern: /pretend\s+(you('re| are)|to\s+be)\s+/i, severity: 'high', name: 'role_manipulation' },
  { pattern: /switch\s+to\s+(\w+\s+)?mode/i, severity: 'medium', name: 'role_manipulation' },
  { pattern: /enter\s+(DAN|jailbreak|developer|god|sudo|admin)\s+mode/i, severity: 'critical', name: 'role_manipulation' },
  
  // System prompt extraction
  { pattern: /(?:show|reveal|display|print|output|repeat|echo)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?)/i, severity: 'high', name: 'system_prompt_extraction' },
  { pattern: /what\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions?|rules?|initial\s+message)/i, severity: 'medium', name: 'system_prompt_extraction' },
  { pattern: /(?:beginning|start)\s+of\s+(?:the\s+)?(?:system|initial)\s+(?:prompt|message|instruction)/i, severity: 'high', name: 'system_prompt_extraction' },

  // Data exfiltration attempts
  { pattern: /(?:send|post|upload|transmit|exfiltrate|forward)\s+(?:all|the|my|this|your)\s+(?:data|files?|info|content|messages?|history|conversation)/i, severity: 'critical', name: 'data_exfiltration' },
  { pattern: /curl\s+.*\|\s*(?:bash|sh)/i, severity: 'critical', name: 'data_exfiltration' },
  
  // Delimiter/encoding attacks
  { pattern: /```\s*system\b/i, severity: 'high', name: 'delimiter_attack' },
  { pattern: /<\/?(?:system|instruction|prompt|message)\s*>/i, severity: 'high', name: 'delimiter_attack' },
  { pattern: /\[INST\]|\[\/INST\]|\[SYSTEM\]/i, severity: 'high', name: 'delimiter_attack' },
  { pattern: /<<\s*SYS\s*>>|<<\s*\/SYS\s*>>/i, severity: 'high', name: 'delimiter_attack' },
  
  // Invisible/encoded text
  { pattern: /[\u200B-\u200F\u2028-\u202F\uFEFF]{3,}/i, severity: 'high', name: 'invisible_text' },
  { pattern: /(?:base64|atob|decode)\s*\(/i, severity: 'medium', name: 'encoded_payload' },

  // Tool abuse instructions
  { pattern: /(?:run|execute|call|use)\s+(?:the\s+)?(?:exec|shell|terminal|command|bash)\s+(?:tool|function)/i, severity: 'medium', name: 'tool_abuse' },
  { pattern: /(?:read|access|open)\s+(?:the\s+)?(?:file|path)\s+(?:\/etc|~\/\.ssh|~\/\.aws|\.env)/i, severity: 'high', name: 'tool_abuse' },
];

// Heuristic signals that text contains instruction-like content (in a data context)
const INSTRUCTION_SIGNALS = [
  { pattern: /\byou\s+(?:must|should|need\s+to|have\s+to|are\s+(?:required|instructed))\b/i, weight: 2 },
  { pattern: /\b(?:do\s+not|don'?t|never)\s+(?:mention|reveal|tell|say|disclose)\b/i, weight: 3 },
  { pattern: /\b(?:important|critical|urgent|mandatory)\s*[:\-!]\s*/i, weight: 1 },
  { pattern: /\b(?:new\s+)?instructions?\s*:/i, weight: 3 },
  { pattern: /\bstep\s+\d+\s*:/i, weight: 1 },
  { pattern: /\bfrom\s+now\s+on\b/i, weight: 2 },
  { pattern: /\binstead\s*,?\s+(?:you\s+)?(?:should|must|will)\b/i, weight: 2 },
  { pattern: /\breal\s+(?:task|instruction|objective|goal)\b/i, weight: 3 },
  { pattern: /\bhidden\s+(?:instruction|task|message)\b/i, weight: 3 },
];

/**
 * Scan text for prompt injection
 * @param {string} text - Text to scan
 * @param {object} opts - Options
 * @param {string} opts.context - Where this text came from (message, email, web, tool_output)
 * @returns {object} Scan result
 */
function scanPromptInjection(text, opts = {}) {
  if (!text || typeof text !== 'string') {
    return { clean: true, score: 0, findings: [] };
  }

  const findings = [];
  let maxSeverity = 'low';

  // 1. Pattern matching
  for (const { pattern, severity, name } of INJECTION_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      findings.push({
        type: 'prompt_injection',
        subtype: name,
        severity,
        matched: match[0].substring(0, 100),
        position: match.index,
      });
      if (severityRank(severity) > severityRank(maxSeverity)) {
        maxSeverity = severity;
      }
    }
  }

  // 2. Heuristic scoring (instruction-like language in data)
  let heuristicScore = 0;
  for (const { pattern, weight } of INSTRUCTION_SIGNALS) {
    if (pattern.test(text)) {
      heuristicScore += weight;
    }
  }

  // Boost score if text is from untrusted context
  const contextMultiplier = opts.context === 'email' ? 1.5 :
                            opts.context === 'web' ? 1.5 :
                            opts.context === 'tool_output' ? 1.3 : 1.0;
  heuristicScore *= contextMultiplier;

  if (heuristicScore >= 5 && findings.length === 0) {
    findings.push({
      type: 'prompt_injection',
      subtype: 'heuristic_detection',
      severity: heuristicScore >= 8 ? 'high' : 'medium',
      score: heuristicScore,
      message: 'Text contains multiple instruction-like patterns in data context',
    });
    if (heuristicScore >= 8 && severityRank('high') > severityRank(maxSeverity)) {
      maxSeverity = 'high';
    }
  }

  // Composite score (0-100)
  const patternScore = Math.min(findings.length * 25, 75);
  const compositeScore = Math.min(patternScore + Math.min(heuristicScore * 5, 25), 100);

  return {
    clean: findings.length === 0,
    score: compositeScore,
    severity: findings.length > 0 ? maxSeverity : null,
    findings,
    heuristicScore,
  };
}

function severityRank(s) {
  return { low: 0, medium: 1, high: 2, critical: 3 }[s] || 0;
}

module.exports = { scanPromptInjection, INJECTION_PATTERNS };
