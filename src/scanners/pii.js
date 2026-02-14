/**
 * ClawMoat — PII Detection Scanner
 * 
 * Detects personally identifiable information in outbound messages:
 * emails, phone numbers, SSNs, credit cards, IP addresses, physical addresses, names.
 */

const PII_PATTERNS = [
  // Email addresses
  { name: 'email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, severity: 'high' },

  // SSN
  { name: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/, severity: 'critical' },

  // Phone numbers (US)
  { name: 'phone_us', pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, severity: 'high' },

  // Phone numbers (international)
  { name: 'phone_international', pattern: /\b\+(?:2[0-9]|3[0-9]|4[0-9]|5[0-9]|6[0-9]|7[0-9]|8[0-9]|9[0-9])\d{7,12}\b/, severity: 'high' },

  // IP addresses (private/internal)
  { name: 'private_ip', pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/, severity: 'medium' },

  // Physical addresses (street patterns)
  { name: 'physical_address', pattern: /\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Ln|Lane|Rd|Road|Ct|Court|Pl|Place|Way|Cir(?:cle)?)\b/i, severity: 'high' },
];

// Credit card patterns (need Luhn validation)
const CREDIT_CARD_PATTERNS = [
  { name: 'visa', pattern: /\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/ },
  { name: 'mastercard', pattern: /\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/ },
  { name: 'amex', pattern: /\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b/ },
  { name: 'discover', pattern: /\b6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/ },
];

// Name-near-keyword heuristic
const NAME_KEYWORDS = /\b(?:patient|client|user|customer|employee|member|applicant|resident|tenant|subscriber)\s*(?:name)?\s*[:=]?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})/;

/**
 * Luhn algorithm to validate credit card numbers
 */
function luhnCheck(numStr) {
  const digits = numStr.replace(/[-\s]/g, '');
  if (!/^\d+$/.test(digits)) return false;
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/**
 * Scan text for PII
 * @param {string} text - Text to scan
 * @param {object} opts - Options
 * @returns {object} Scan result { clean, findings[], severity }
 */
function scanPII(text, opts = {}) {
  if (!text || typeof text !== 'string') {
    return { clean: true, findings: [], severity: null };
  }

  const findings = [];

  // Standard PII patterns
  for (const { name, pattern, severity } of PII_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      findings.push({
        type: 'pii_detected',
        subtype: name,
        severity,
        matched: redact(match[0]),
        position: match.index,
      });
    }
  }

  // Credit card with Luhn validation
  for (const { name, pattern } of CREDIT_CARD_PATTERNS) {
    const match = text.match(pattern);
    if (match && luhnCheck(match[0])) {
      findings.push({
        type: 'pii_detected',
        subtype: 'credit_card_' + name,
        severity: 'critical',
        matched: redact(match[0]),
        position: match.index,
      });
    }
  }

  // Name near keyword heuristic
  const nameMatch = text.match(NAME_KEYWORDS);
  if (nameMatch) {
    findings.push({
      type: 'pii_detected',
      subtype: 'name_keyword',
      severity: 'medium',
      matched: redact(nameMatch[0]),
      position: nameMatch.index,
    });
  }

  const maxSev = findings.length > 0
    ? findings.reduce((max, f) => rank(f.severity) > rank(max) ? f.severity : max, 'low')
    : null;

  return { clean: findings.length === 0, findings, severity: maxSev };
}

function redact(value) {
  if (value.length <= 8) return '****';
  return value.substring(0, 4) + '*'.repeat(Math.min(value.length - 8, 20)) + value.substring(value.length - 4);
}

function rank(s) {
  return { low: 0, medium: 1, high: 2, critical: 3 }[s] || 0;
}

module.exports = { scanPII };
