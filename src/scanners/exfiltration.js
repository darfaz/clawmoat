/**
 * ClawMoat — Exfiltration Detection Scanner
 * 
 * Detects data exfiltration attempts — when an agent is being used
 * to send data to external services.
 */

const PASTE_SERVICES = [
  'pastebin.com', 'hastebin.com', '0x0.st', 'transfer.sh', 'paste.ee',
  'dpaste.org', 'ghostbin.com', 'rentry.co', 'paste.mozilla.org',
  'ix.io', 'sprunge.us', 'cl1p.net', 'file.io', 'tmpfiles.org',
];

const EXFIL_PATTERNS = [
  // Curl/wget to external services
  { pattern: /\bcurl\s+(?:-[a-zA-Z]\s+)*(?:--data|--data-binary|-d|-F)\s/i, severity: 'high', name: 'curl_data_upload' },
  { pattern: /\bwget\s+--post-(?:data|file)\b/i, severity: 'high', name: 'wget_data_upload' },

  // Base64 data being sent externally
  { pattern: /\bcurl\b.*\b(?:base64|atob|btoa)\b/i, severity: 'high', name: 'base64_exfiltration' },
  { pattern: /\b(?:echo|printf)\s+['"]?[A-Za-z0-9+/=]{50,}['"]?\s*\|\s*(?:curl|wget|nc)\b/i, severity: 'critical', name: 'base64_exfiltration' },

  // DNS exfiltration (long subdomain strings)
  { pattern: /\b(?:dig|nslookup|host)\s+[A-Za-z0-9]{20,}\./i, severity: 'high', name: 'dns_exfiltration' },
  { pattern: /\$\(.*\)\.[A-Za-z0-9.-]+\.[a-z]{2,}/i, severity: 'medium', name: 'dns_exfiltration' },

  // File contents being sent via messaging
  { pattern: /\b(?:send|post|forward|share|upload)\s+(?:the\s+)?(?:contents?\s+of|file)\s+(?:\/|~\/|\.\/)/i, severity: 'high', name: 'file_content_send' },
  { pattern: /\bcat\s+[^\s|]+\s*\|\s*(?:curl|wget|nc)\b/i, severity: 'critical', name: 'file_content_pipe' },

  // Paste services
  { pattern: new RegExp('\\b(?:curl|wget|fetch)\\s+.*(?:' + PASTE_SERVICES.map(s => s.replace(/\./g, '\\.')).join('|') + ')', 'i'), severity: 'critical', name: 'paste_service_upload' },

  // Email forwarding of sensitive content
  { pattern: /\b(?:send|forward|email|mail)\s+(?:the\s+)?(?:ssh|key|password|credential|token|secret|env|config)\b.*\bto\b/i, severity: 'critical', name: 'email_exfiltration' },

  // Netcat reverse connections
  { pattern: /\bnc\s+(?:-[a-z]\s+)*[^\s]+\s+\d+\s*</i, severity: 'critical', name: 'netcat_exfiltration' },

  // Upload via fetch/XMLHttpRequest
  { pattern: /\bfetch\s*\(\s*['"][^'"]+['"]\s*,\s*\{[^}]*method\s*:\s*['"]POST['"]/i, severity: 'high', name: 'fetch_upload' },
];

/**
 * Scan text for data exfiltration attempts
 * @param {string} text - Text to scan
 * @param {object} opts - Options
 * @returns {object} Scan result { clean, findings[], severity }
 */
function scanExfiltration(text, opts = {}) {
  if (!text || typeof text !== 'string') {
    return { clean: true, findings: [], severity: null };
  }

  const findings = [];

  for (const { pattern, severity, name } of EXFIL_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      findings.push({
        type: 'exfiltration',
        subtype: name,
        severity,
        matched: match[0].substring(0, 100),
        position: match.index,
      });
    }
  }

  // Check for paste service URLs directly
  const lowerText = text.toLowerCase();
  for (const service of PASTE_SERVICES) {
    if (lowerText.includes(service) && /\b(?:upload|post|send|push|put)\b/i.test(text)) {
      const existing = findings.find(f => f.subtype === 'paste_service_upload');
      if (!existing) {
        findings.push({
          type: 'exfiltration',
          subtype: 'paste_service_upload',
          severity: 'high',
          matched: service,
        });
      }
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

module.exports = { scanExfiltration };
