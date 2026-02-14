/**
 * ClawMoat — Phishing URL Detection Scanner
 * 
 * Detects malicious/suspicious URLs in inbound messages.
 */

const PHISHING_TLDS = ['.zip', '.mov', '.tk', '.ml', '.ga', '.cf', '.gq'];

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'db.tt', 'qr.ae', 'cur.lv',
  'lnkd.in', 'yourls.org', 'rb.gy', 'short.io', 'cutt.ly', 'v.gd',
];

const SUSPICIOUS_PATH_KEYWORDS = /\b(?:login|signin|sign-in|verify|account|security|update|confirm|authenticate|banking|password|reset|suspend)/i;

const TRUSTED_DOMAINS = [
  'google.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
  'facebook.com', 'twitter.com', 'linkedin.com', 'stackoverflow.com',
  'wikipedia.org', 'youtube.com', 'reddit.com', 'npmjs.com', 'mozilla.org',
];

const URL_REGEX = /(?:https?:\/\/|data:)[^\s<>"')\]]+/gi;

/**
 * Scan text for suspicious/phishing URLs
 * @param {string} text - Text to scan
 * @param {object} opts - Options
 * @returns {object} Scan result { clean, findings[], severity }
 */
function scanUrls(text, opts = {}) {
  if (!text || typeof text !== 'string') {
    return { clean: true, findings: [], severity: null };
  }

  const findings = [];
  const urls = text.match(URL_REGEX) || [];

  for (const url of urls) {
    // Data URLs with executable content
    if (/^data:/i.test(url)) {
      if (/data:(?:text\/html|application\/javascript|text\/javascript)/i.test(url)) {
        findings.push({
          type: 'suspicious_url',
          subtype: 'data_url_executable',
          severity: 'critical',
          matched: url.substring(0, 100),
        });
      }
      continue;
    }

    let hostname = '';
    try {
      const parsed = new URL(url);
      hostname = parsed.hostname.toLowerCase();
      const pathname = parsed.pathname;

      // IP-based URLs
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        findings.push({
          type: 'suspicious_url',
          subtype: 'ip_based_url',
          severity: 'high',
          matched: url.substring(0, 100),
        });
        continue;
      }

      // Punycode/homograph attacks
      if (hostname.includes('xn--')) {
        findings.push({
          type: 'suspicious_url',
          subtype: 'punycode_homograph',
          severity: 'high',
          matched: url.substring(0, 100),
        });
        continue;
      }

      // Phishing TLDs
      const tld = hostname.substring(hostname.lastIndexOf('.'));
      if (PHISHING_TLDS.includes(tld)) {
        findings.push({
          type: 'suspicious_url',
          subtype: 'phishing_tld',
          severity: 'medium',
          matched: url.substring(0, 100),
        });
        continue;
      }

      // URL shorteners
      if (URL_SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s))) {
        findings.push({
          type: 'suspicious_url',
          subtype: 'url_shortener',
          severity: 'medium',
          matched: url.substring(0, 100),
        });
        continue;
      }

      // Excessive subdomains (4+ levels)
      const parts = hostname.split('.');
      if (parts.length >= 5) {
        findings.push({
          type: 'suspicious_url',
          subtype: 'excessive_subdomains',
          severity: 'high',
          matched: url.substring(0, 100),
        });
        continue;
      }

      // Suspicious path keywords on non-trusted domains
      const rootDomain = parts.slice(-2).join('.');
      if (SUSPICIOUS_PATH_KEYWORDS.test(pathname) && !TRUSTED_DOMAINS.includes(rootDomain)) {
        findings.push({
          type: 'suspicious_url',
          subtype: 'suspicious_path',
          severity: 'medium',
          matched: url.substring(0, 100),
        });
      }
    } catch {
      // Invalid URL, skip
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

module.exports = { scanUrls };
