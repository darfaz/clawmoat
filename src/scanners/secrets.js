/**
 * ClawMoat — Secret/Credential Scanner
 * 
 * Detects API keys, passwords, tokens, and other secrets in text
 * to prevent exfiltration via outbound messages.
 */

const SECRET_PATTERNS = [
  // API Keys & Tokens
  { name: 'aws_access_key', pattern: /\bAKIA[0-9A-Z]{16}\b/, severity: 'critical' },
  { name: 'aws_secret_key', pattern: /\b[A-Za-z0-9/+=]{40}\b/, severity: 'high', requireContext: /aws|secret|key/i },
  { name: 'github_token', pattern: /\b(ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9_]{36,}\b/, severity: 'critical' },
  { name: 'github_fine_grained', pattern: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/, severity: 'critical' },
  { name: 'openai_key', pattern: /\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b/, severity: 'critical' },
  { name: 'openai_key_v2', pattern: /\bsk-proj-[A-Za-z0-9_-]{40,}\b/, severity: 'critical' },
  { name: 'anthropic_key', pattern: /\bsk-ant-[A-Za-z0-9_-]{40,}\b/, severity: 'critical' },
  { name: 'stripe_key', pattern: /\b[sr]k_(test|live)_[A-Za-z0-9]{20,}\b/, severity: 'critical' },
  { name: 'stripe_webhook', pattern: /\bwhsec_[A-Za-z0-9]{20,}\b/, severity: 'critical' },
  { name: 'slack_token', pattern: /\bxox[baprs]-[0-9]{10,}-[A-Za-z0-9-]+\b/, severity: 'critical' },
  { name: 'discord_token', pattern: /\b[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b/, severity: 'critical' },
  { name: 'telegram_bot_token', pattern: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/, severity: 'critical' },
  { name: 'google_api_key', pattern: /\bAIza[A-Za-z0-9_-]{35}\b/, severity: 'high' },
  { name: 'heroku_api_key', pattern: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/, severity: 'medium', requireContext: /heroku|api.key/i },
  { name: 'sendgrid_key', pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/, severity: 'critical' },
  { name: 'twilio_key', pattern: /\bSK[0-9a-fA-F]{32}\b/, severity: 'high' },
  { name: 'resend_key', pattern: /\bre_[A-Za-z0-9]{20,}\b/, severity: 'critical' },
  { name: 'jwt_token', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, severity: 'high' },

  // SSH & Crypto
  { name: 'private_key', pattern: /-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, severity: 'critical' },
  { name: 'ssh_key_content', pattern: /ssh-(rsa|ed25519|ecdsa)\s+[A-Za-z0-9+/=]{100,}/, severity: 'high' },

  // Generic patterns
  { name: 'generic_password', pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{8,}['"]?/i, severity: 'high' },
  { name: 'generic_secret', pattern: /(?:secret|token|api[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_-]{16,}['"]?/i, severity: 'high' },
  { name: 'connection_string', pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s]+:[^\s]+@/i, severity: 'critical' },

  // Entropy-based (long hex/base64 strings that look like secrets)
  { name: 'high_entropy_hex', pattern: /\b[0-9a-f]{32,}\b/i, severity: 'medium', requireContext: /key|secret|token|password|credential/i },
];

/**
 * Scan text for secrets and credentials
 * @param {string} text - Text to scan
 * @param {object} opts - Options
 * @param {string} opts.direction - 'inbound' or 'outbound'
 * @returns {object} Scan result
 */
function scanSecrets(text, opts = {}) {
  if (!text || typeof text !== 'string') {
    return { clean: true, findings: [] };
  }

  const findings = [];

  for (const { name, pattern, severity, requireContext } of SECRET_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      // If requireContext is set, only flag if context keywords are nearby
      if (requireContext) {
        const surrounding = text.substring(
          Math.max(0, match.index - 50),
          Math.min(text.length, match.index + match[0].length + 50)
        );
        if (!requireContext.test(surrounding)) continue;
      }

      findings.push({
        type: 'secret_detected',
        subtype: name,
        severity,
        matched: redact(match[0]),
        position: match.index,
        direction: opts.direction || 'unknown',
      });
    }
  }

  return {
    clean: findings.length === 0,
    findings,
    severity: findings.length > 0
      ? findings.reduce((max, f) => severityRank(f.severity) > severityRank(max) ? f.severity : max, 'low')
      : null,
  };
}

function redact(value) {
  if (value.length <= 8) return '****';
  return value.substring(0, 4) + '*'.repeat(Math.min(value.length - 8, 20)) + value.substring(value.length - 4);
}

function severityRank(s) {
  return { low: 0, medium: 1, high: 2, critical: 3 }[s] || 0;
}

module.exports = { scanSecrets, SECRET_PATTERNS };
