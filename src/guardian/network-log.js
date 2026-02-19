/**
 * ClawMoat Network Egress Logger
 * 
 * Parses session JSONL files for outbound network activity,
 * maintains domain allowlists, and flags suspicious destinations.
 * 
 * @module clawmoat/guardian/network-log
 */

const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// Known-bad domains commonly used for exfiltration
const KNOWN_BAD_DOMAINS = [
  'webhook.site',
  'requestbin.com',
  'pipedream.net',
  'ngrok.io',
  'ngrok-free.app',
  'ngrok.app',
  'burpcollaborator.net',
  'interact.sh',
  'oastify.com',
  'canarytokens.com',
  'dnslog.cn',
  'beeceptor.com',
  'hookbin.com',
  'requestcatcher.com',
  'mockbin.org',
  'postb.in',
  'ptsv2.com',
  'transfer.sh',
  'file.io',
  '0x0.st',
  'hastebin.com',
  'pastebin.com',
  'paste.ee',
  'dpaste.org',
  'serveo.net',
  'localtunnel.me',
  'localhost.run',
];

// Default safe domains
const DEFAULT_ALLOWLIST = [
  'github.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'npmjs.org',
  'registry.npmjs.org',
  'google.com',
  'googleapis.com',
  'stackoverflow.com',
  'developer.mozilla.org',
  'nodejs.org',
  'docs.python.org',
];

/**
 * Extract URLs from a text string.
 * @param {string} text
 * @returns {string[]} Extracted URLs
 */
function extractUrls(text) {
  if (!text) return [];
  const urlRegex = /https?:\/\/[^\s"'<>\]\)]+/gi;
  return (text.match(urlRegex) || []);
}

/**
 * Extract domain from a URL string.
 * @param {string} urlStr
 * @returns {string|null}
 */
function extractDomain(urlStr) {
  try {
    const u = new URL(urlStr);
    return u.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Parse a session JSONL file for network activity.
 * @param {string} filePath - Path to .jsonl file
 * @returns {{ urls: string[], domains: Set<string>, toolCalls: Array }}
 */
function parseSessionFile(filePath) {
  const urls = [];
  const domains = new Set();
  const toolCalls = [];

  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return { urls, domains, toolCalls };
  }

  const lines = content.split('\n').filter(Boolean);

  for (const line of lines) {
    let entry;
    try { entry = JSON.parse(line); } catch { continue; }

    // Check tool calls from assistant
    if (entry.role === 'assistant' && Array.isArray(entry.content)) {
      for (const part of entry.content) {
        if (part.type !== 'toolCall') continue;
        const name = part.name || '';
        const args = part.arguments || {};

        if (name === 'web_fetch' || name === 'web_search') {
          const url = args.url || args.query || '';
          const extracted = extractUrls(url);
          if (extracted.length) {
            urls.push(...extracted);
          } else if (url.startsWith('http')) {
            urls.push(url);
          }
          toolCalls.push({ tool: name, args, session: filePath });
        }

        if (name === 'exec') {
          const cmd = args.command || '';
          if (/\b(curl|wget|fetch|http)\b/i.test(cmd)) {
            const cmdUrls = extractUrls(cmd);
            urls.push(...cmdUrls);
            toolCalls.push({ tool: 'exec', args, session: filePath });
          }
        }
      }
    }
  }

  for (const u of urls) {
    const d = extractDomain(u);
    if (d) domains.add(d);
  }

  return { urls, domains, toolCalls };
}

class NetworkEgressLogger {
  /**
   * @param {Object} opts
   * @param {string[]} [opts.allowlist] - Additional allowed domains
   * @param {string[]} [opts.badDomains] - Additional known-bad domains
   * @param {Function} [opts.onAlert] - Callback for alerts
   */
  constructor(opts = {}) {
    this.allowlist = new Set([...DEFAULT_ALLOWLIST, ...(opts.allowlist || [])]);
    this.badDomains = new Set([...KNOWN_BAD_DOMAINS, ...(opts.badDomains || [])]);
    this.seenDomains = new Set();
    this.onAlert = opts.onAlert || null;
    this.log = []; // { timestamp, url, domain, status }
  }

  /**
   * Scan session directory for network egress.
   * @param {string} sessionsDir - Path to sessions directory
   * @param {Object} [opts]
   * @param {number} [opts.maxAge] - Only scan files modified within this many ms
   * @returns {{ totalUrls: number, domains: string[], flagged: Array, badDomains: Array, firstSeen: string[] }}
   */
  scanSessions(sessionsDir, opts = {}) {
    if (!fs.existsSync(sessionsDir)) {
      return { totalUrls: 0, domains: [], flagged: [], badDomains: [], firstSeen: [] };
    }

    const files = fs.readdirSync(sessionsDir).filter(f => f.endsWith('.jsonl'));
    const allUrls = [];
    const allDomains = new Set();
    const flagged = [];
    const badFound = [];
    const firstSeen = [];

    for (const file of files) {
      const filePath = path.join(sessionsDir, file);

      // Optional age filter
      if (opts.maxAge) {
        try {
          const stat = fs.statSync(filePath);
          if (Date.now() - stat.mtimeMs > opts.maxAge) continue;
        } catch { continue; }
      }

      const result = parseSessionFile(filePath);
      allUrls.push(...result.urls);

      for (const domain of result.domains) {
        allDomains.add(domain);

        // Check bad domains
        if (this._isBadDomain(domain)) {
          badFound.push({ domain, file, urls: result.urls.filter(u => extractDomain(u) === domain) });
          this._alert({
            severity: 'critical',
            type: 'bad_domain',
            message: `Known-bad domain contacted: ${domain}`,
            details: { domain, session: file },
          });
        }

        // Check first-seen
        if (!this.seenDomains.has(domain) && !this.allowlist.has(domain)) {
          firstSeen.push(domain);
          this._alert({
            severity: 'info',
            type: 'first_seen_domain',
            message: `First-seen domain: ${domain}`,
            details: { domain, session: file },
          });
        }

        this.seenDomains.add(domain);
      }
    }

    // Flag non-allowlisted domains
    for (const d of allDomains) {
      if (!this.allowlist.has(d)) {
        flagged.push(d);
      }
    }

    return {
      totalUrls: allUrls.length,
      domains: [...allDomains],
      flagged,
      badDomains: badFound,
      firstSeen,
    };
  }

  /**
   * Check a single URL against rules.
   * @param {string} url
   * @returns {{ allowed: boolean, domain: string|null, reason: string|null }}
   */
  checkUrl(url) {
    const domain = extractDomain(url);
    if (!domain) return { allowed: true, domain: null, reason: null };

    if (this._isBadDomain(domain)) {
      return { allowed: false, domain, reason: `Known-bad domain: ${domain}` };
    }

    if (!this.allowlist.has(domain)) {
      return { allowed: true, domain, reason: `Not in allowlist: ${domain}` };
    }

    return { allowed: true, domain, reason: null };
  }

  _isBadDomain(domain) {
    if (this.badDomains.has(domain)) return true;
    // Check subdomains (e.g. xyz.ngrok.io)
    for (const bad of this.badDomains) {
      if (domain.endsWith('.' + bad)) return true;
    }
    return false;
  }

  _alert(alert) {
    this.log.push({ timestamp: Date.now(), ...alert });
    if (this.onAlert) this.onAlert(alert);
  }
}

module.exports = {
  NetworkEgressLogger,
  extractUrls,
  extractDomain,
  parseSessionFile,
  KNOWN_BAD_DOMAINS,
  DEFAULT_ALLOWLIST,
};
