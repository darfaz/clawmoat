/**
 * ClawMoat — Supply Chain Scanner
 * 
 * Scans OpenClaw skills for malicious patterns.
 */

const fs = require('fs');
const path = require('path');

const KNOWN_GOOD_SOURCES = [
  'github.com/openclaw', 'github.com/darfaz', 'openclaw.com',
  'npmjs.com', 'github.com/anthropics',
];

const SKILL_PATTERNS = [
  // Outbound network requests
  { pattern: /\bcurl\s+/i, severity: 'medium', name: 'network_curl' },
  { pattern: /\bwget\s+/i, severity: 'medium', name: 'network_wget' },
  { pattern: /\bfetch\s*\(/i, severity: 'medium', name: 'network_fetch' },
  { pattern: /\bXMLHttpRequest\b/i, severity: 'medium', name: 'network_xhr' },
  { pattern: /\brequire\s*\(\s*['"](?:http|https|net|dgram|request|axios|node-fetch)['"]\s*\)/i, severity: 'high', name: 'network_module' },

  // Sensitive file access
  { pattern: /~\/\.ssh\b|\/\.ssh\b/i, severity: 'critical', name: 'sensitive_ssh' },
  { pattern: /~\/\.aws\b|\/\.aws\b/i, severity: 'critical', name: 'sensitive_aws' },
  { pattern: /\bcredentials?\b.*(?:read|cat|open|access)/i, severity: 'high', name: 'sensitive_credentials' },
  { pattern: /\/etc\/(?:passwd|shadow|sudoers)\b/i, severity: 'critical', name: 'sensitive_system' },
  { pattern: /\.env\b.*(?:read|cat|source|load)/i, severity: 'high', name: 'sensitive_env' },

  // Obfuscated code
  { pattern: /\beval\s*\(/i, severity: 'high', name: 'obfuscated_eval' },
  { pattern: /\bFunction\s*\(/i, severity: 'high', name: 'obfuscated_function' },
  { pattern: /\batob\s*\(/i, severity: 'medium', name: 'obfuscated_atob' },
  { pattern: /\bBuffer\.from\s*\([^,]+,\s*['"]base64['"]\s*\)/i, severity: 'medium', name: 'obfuscated_buffer' },
  { pattern: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){5,}/i, severity: 'high', name: 'obfuscated_hex' },
  // Double base64 encoding (LiteLLM-style payload obfuscation)
  { pattern: /base64[._]?(?:b64)?decode\s*\([^)]*base64[._]?(?:b64)?decode/i, severity: 'critical', name: 'obfuscated_double_b64' },
  // exec(base64.b64decode(...)) — Python payload pattern
  { pattern: /\bexec\s*\(\s*(?:base64\.)?(?:b64decode|decodestring)\s*\(/i, severity: 'critical', name: 'obfuscated_exec_b64' },

  // .pth file injection (Python site-packages auto-execution, as used in LiteLLM attack)
  { pattern: /\.pth\b.*(?:import|exec|subprocess|eval|compile)/i, severity: 'critical', name: 'pth_file_injection' },
  { pattern: /litellm_init\.pth/i, severity: 'critical', name: 'pth_known_malicious_litellm' },
  // Generic .pth with code execution (not just path entries)
  { pattern: /^import\s+\w+/m, severity: 'low', name: 'pth_import_statement' },

  // Lookalike domain detection (exfiltration via typosquatting)
  { pattern: /models\.litellm\.cloud/i, severity: 'critical', name: 'exfil_litellm_lookalike' },
  { pattern: /(?:pypi|npmjs|github|googleapis)\.(?:cloud|io|dev|app)\b/i, severity: 'high', name: 'exfil_lookalike_domain' },

  // System configuration modification
  { pattern: /\bcrontab\b/i, severity: 'high', name: 'system_crontab' },
  { pattern: /\/etc\/(?:cron|systemd|init)\b/i, severity: 'high', name: 'system_config' },
  { pattern: /\bsystemctl\s+(?:enable|start|restart)\b/i, severity: 'medium', name: 'system_service' },
  { pattern: /\bchmod\s+(?:\+s|[0-7]*[4-7][0-7]{2})\b/i, severity: 'high', name: 'system_permissions' },
];

/**
 * Scan a skill file for malicious patterns
 * @param {string} skillPath - Path to skill directory or file
 * @returns {object} Scan result { clean, findings[], severity }
 */
function scanSkill(skillPath) {
  const findings = [];

  try {
    const stat = fs.statSync(skillPath);
    const files = stat.isDirectory()
      ? walkDir(skillPath).filter(f => /\.(js|sh|py|rb|ts|yaml|yml|md)$/i.test(f))
      : [skillPath];

    for (const file of files) {
      const content = fs.readFileSync(file, 'utf8');
      const result = scanSkillContent(content);
      if (!result.clean) {
        for (const f of result.findings) {
          f.file = path.relative(skillPath, file) || path.basename(file);
          findings.push(f);
        }
      }
    }

    // Check source (look for source in SKILL.md or package.json)
    const skillMd = files.find(f => f.endsWith('SKILL.md'));
    if (skillMd) {
      const content = fs.readFileSync(skillMd, 'utf8');
      const sourceMatch = content.match(/(?:source|origin|from|url)\s*[:=]\s*(.+)/i);
      if (sourceMatch) {
        const source = sourceMatch[1].trim();
        const trusted = KNOWN_GOOD_SOURCES.some(s => source.includes(s));
        if (!trusted) {
          findings.push({
            type: 'supply_chain',
            subtype: 'untrusted_source',
            severity: 'medium',
            matched: source.substring(0, 100),
          });
        }
      }
    }
  } catch (err) {
    findings.push({
      type: 'supply_chain',
      subtype: 'scan_error',
      severity: 'low',
      matched: err.message,
    });
  }

  const maxSev = findings.length > 0
    ? findings.reduce((max, f) => rank(f.severity) > rank(max) ? f.severity : max, 'low')
    : null;

  return { clean: findings.length === 0, findings, severity: maxSev };
}

/**
 * Scan skill content string for malicious patterns
 * @param {string} content - Skill content
 * @returns {object} Scan result { clean, findings[], severity }
 */
function scanSkillContent(content) {
  if (!content || typeof content !== 'string') {
    return { clean: true, findings: [], severity: null };
  }

  const findings = [];

  for (const { pattern, severity, name } of SKILL_PATTERNS) {
    const match = content.match(pattern);
    if (match) {
      findings.push({
        type: 'supply_chain',
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

function walkDir(dir) {
  const results = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
        results.push(...walkDir(full));
      } else if (entry.isFile()) {
        results.push(full);
      }
    }
  } catch {}
  return results;
}

function rank(s) {
  return { low: 0, medium: 1, high: 2, critical: 3 }[s] || 0;
}

module.exports = { scanSkill, scanSkillContent };
