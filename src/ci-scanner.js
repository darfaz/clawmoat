/**
 * ClawMoat CI Scanner
 * 
 * Scans a repo for agent security issues before deployment:
 * - Leaked secrets in tracked files
 * - Dangerous MCP server configs
 * - Unsafe CI/CD workflow patterns
 * - Known compromised dependency versions
 * - Agent config files with excessive permissions
 * 
 * @module ci-scanner
 */

'use strict';

const fs = require('fs');
const path = require('path');

const KNOWN_COMPROMISED = [
  { pkg: 'telnyx', versions: ['4.87.1', '4.87.2'], cve: 'TeamPCP supply chain (Mar 2026)', severity: 'critical' },
  { pkg: 'event-stream', versions: ['3.3.6'], cve: 'CVE-2018-21270', severity: 'critical' },
  { pkg: 'ua-parser-js', versions: ['0.7.29', '0.7.30', '1.0.0', '1.0.1'], cve: 'CVE-2021-41265', severity: 'critical' },
  { pkg: 'coa', versions: ['2.0.3', '2.0.4'], cve: 'CVE-2021-43789', severity: 'critical' },
  { pkg: 'rc', versions: ['1.2.9'], cve: 'CVE-2021-43790', severity: 'critical' },
  { pkg: 'node-ipc', versions: ['10.1.1', '10.1.2', '11.1.0'], cve: 'CVE-2022-23812', severity: 'critical' },
];

// Patterns that indicate secrets in source files
const SECRET_PATTERNS = [
  { re: /(?:^|[\s'"=])(sk-[a-zA-Z0-9]{20,})/, name: 'OpenAI API key', severity: 'critical' },
  { re: /(?:^|[\s'"=])(sk-proj-[a-zA-Z0-9]{40,})/, name: 'OpenAI project key', severity: 'critical' },
  { re: /(?:^|[\s'"=])(ghp_[a-zA-Z0-9]{36})/, name: 'GitHub Personal Access Token', severity: 'critical' },
  { re: /(?:^|[\s'"=])(github_pat_[a-zA-Z0-9_]{82})/, name: 'GitHub fine-grained token', severity: 'critical' },
  { re: /(?:^|[\s'"=])(AKIA[0-9A-Z]{16})/, name: 'AWS Access Key ID', severity: 'critical' },
  { re: /AWS_SECRET_ACCESS_KEY\s*[=:]\s*([A-Za-z0-9/+=]{40})/, name: 'AWS Secret Access Key', severity: 'critical' },
  { re: /(?:^|[\s'"=])(xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+)/, name: 'Slack bot token', severity: 'critical' },
  { re: /(?:^|[\s'"=])(xoxp-[0-9]+-[0-9]+-[a-zA-Z0-9]+)/, name: 'Slack user token', severity: 'critical' },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, name: 'Private key', severity: 'critical' },
  { re: /(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]/, name: 'Hardcoded password', severity: 'high' },
];

// CI/CD workflow risk patterns
const CI_RISK_PATTERNS = [
  { re: /\$\{\{\s*github\.event\.(?:issue|pull_request|comment)\.(?:title|body)\s*\}\}/, name: 'Untrusted PR/issue data in workflow', severity: 'critical' },
  { re: /\$\{\{\s*github\.event\.head_commit\.message\s*\}\}/, name: 'Untrusted commit message in workflow', severity: 'high' },
  { re: /uses:\s*[a-z0-9-]+\/[a-z0-9-]+@(?:main|master|latest|HEAD)/, name: 'Unpinned GitHub Action (use @SHA)', severity: 'medium' },
  { re: /curl\s+.*\|\s*(?:bash|sh)/, name: 'Curl pipe to shell in workflow', severity: 'critical' },
  { re: /run:\s*echo\s+\$\{\{/, name: 'Unsanitized expression in echo', severity: 'high' },
];

// Extensions to scan for secrets
const SCANNABLE_EXTENSIONS = new Set([
  '.js', '.ts', '.py', '.rb', '.go', '.java', '.cs', '.php',
  '.env', '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg',
  '.sh', '.bash', '.zsh', '.fish',
]);

// Files/dirs to always skip
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '__pycache__', '.pytest_cache',
  'dist', 'build', 'coverage', '.nyc_output', 'vendor',
  '.venv', 'venv', 'env',
]);

/**
 * Scan a repository for security issues
 * @param {Object} [opts] - Options
 * @param {string} [opts.rootDir='.'] - Root directory to scan
 * @param {boolean} [opts.checkDeps=true] - Check package.json for known-bad deps
 * @param {boolean} [opts.checkSecrets=true] - Scan files for leaked secrets
 * @param {boolean} [opts.checkCI=true] - Scan CI/CD workflows
 * @param {boolean} [opts.checkMCP=true] - Scan MCP configs
 * @param {string} [opts.failOn='high'] - Severity to fail CI on
 * @returns {Object} { findings, summary, passed }
 */
function scanRepo(opts = {}) {
  const {
    rootDir = process.cwd(),
    checkDeps = true,
    checkSecrets = true,
    checkCI = true,
    checkMCP = true,
    failOn = 'high',
  } = opts;

  const findings = [];

  // 1. Check package.json for compromised deps
  if (checkDeps) {
    const pkgPath = path.join(rootDir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
        for (const [name, version] of Object.entries(allDeps)) {
          const cleanVer = version.replace(/^[^0-9]*/, '');
          const compromised = KNOWN_COMPROMISED.find(c =>
            c.pkg === name && c.versions.includes(cleanVer)
          );
          if (compromised) {
            findings.push({
              type: 'compromised_dependency',
              severity: compromised.severity,
              file: 'package.json',
              evidence: `${name}@${cleanVer} — ${compromised.cve}`,
              fix: `Update ${name} to latest safe version`,
            });
          }
        }
      } catch (_) {}
    }

    // Check requirements.txt
    const reqPath = path.join(rootDir, 'requirements.txt');
    if (fs.existsSync(reqPath)) {
      const content = fs.readFileSync(reqPath, 'utf8');
      for (const line of content.split('\n')) {
        const match = line.match(/^([a-zA-Z0-9_-]+)==([0-9.]+)/);
        if (match) {
          const [, name, version] = match;
          const compromised = KNOWN_COMPROMISED.find(c =>
            c.pkg === name.toLowerCase() && c.versions.includes(version)
          );
          if (compromised) {
            findings.push({
              type: 'compromised_dependency',
              severity: compromised.severity,
              file: 'requirements.txt',
              evidence: `${name}==${version} — ${compromised.cve}`,
              fix: `Update ${name} to latest safe version`,
            });
          }
        }
      }
    }
  }

  // 2. Scan source files for secrets
  if (checkSecrets) {
    const secretFindings = scanDirForSecrets(rootDir);
    findings.push(...secretFindings);
  }

  // 3. Scan CI/CD workflows
  if (checkCI) {
    const workflowDir = path.join(rootDir, '.github', 'workflows');
    if (fs.existsSync(workflowDir)) {
      const files = fs.readdirSync(workflowDir).filter(f => f.endsWith('.yml') || f.endsWith('.yaml'));
      for (const file of files) {
        const content = fs.readFileSync(path.join(workflowDir, file), 'utf8');
        for (const pattern of CI_RISK_PATTERNS) {
          if (pattern.re.test(content)) {
            findings.push({
              type: 'ci_risk',
              severity: pattern.severity,
              file: `.github/workflows/${file}`,
              evidence: pattern.name,
              fix: getCI_Fix(pattern.name),
            });
          }
        }
      }
    }
  }

  // 4. Scan MCP configs
  if (checkMCP) {
    try {
      const { scanMCP } = require('./mcp-scanner');
      const mcpReport = scanMCP({ quiet: true });
      for (const f of mcpReport.findings) {
        findings.push({
          type: 'mcp_config',
          severity: f.severity,
          file: f.configName || 'mcp-config',
          evidence: `${f.label} (${f.server})`,
          fix: f.fix,
        });
      }
    } catch (_) {}
  }

  // Compute summary
  const summary = {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
  };

  const severityRank = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
  const failRank = severityRank[failOn] || 3;
  const passed = !findings.some(f => (severityRank[f.severity] || 0) >= failRank);

  return { findings, summary, passed, rootDir };
}

function scanDirForSecrets(dir, depth = 0) {
  if (depth > 8) return [];
  const findings = [];

  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_) { return []; }

  for (const entry of entries) {
    if (entry.name.startsWith('.') && entry.name !== '.env') continue;
    if (SKIP_DIRS.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      findings.push(...scanDirForSecrets(fullPath, depth + 1));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      const isEnvFile = entry.name === '.env' || entry.name.startsWith('.env.');

      if (isEnvFile) {
        // Flag .env files committed to repo
        findings.push({
          type: 'committed_env_file',
          severity: 'high',
          file: path.relative(process.cwd(), fullPath),
          evidence: '.env file committed to repository',
          fix: 'Add .env to .gitignore and rotate any exposed secrets',
        });
      }

      if (!SCANNABLE_EXTENSIONS.has(ext) && !isEnvFile) continue;

      let content;
      try { content = fs.readFileSync(fullPath, 'utf8'); }
      catch (_) { continue; }

      // Skip if file is too large (> 500KB)
      if (content.length > 512000) continue;

      const relPath = path.relative(process.cwd(), fullPath);

      for (const pattern of SECRET_PATTERNS) {
        const match = pattern.re.exec(content);
        if (match) {
          const secret = match[1] || match[0];
          const redacted = secret.length > 8
            ? secret.substring(0, 4) + '*'.repeat(Math.min(secret.length - 8, 20)) + secret.substring(secret.length - 4)
            : '****';
          findings.push({
            type: 'leaked_secret',
            severity: pattern.severity,
            file: relPath,
            evidence: `${pattern.name}: ${redacted}`,
            fix: 'Remove secret from file, add to .gitignore, rotate the credential',
          });
        }
      }
    }
  }

  return findings;
}

function getCI_Fix(patternName) {
  const fixes = {
    'Untrusted PR/issue data in workflow': 'Use an intermediate env var with sanitization, or use github.event_name check',
    'Unpinned GitHub Action (use @SHA)': 'Pin to a full SHA: uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683',
    'Curl pipe to shell in workflow': 'Download script, verify checksum, then execute separately',
    'Unsanitized expression in echo': 'Use $GITHUB_ENV or intermediate env var to prevent log injection',
  };
  return fixes[patternName] || 'Review and remediate the risk';
}

module.exports = {
  scanRepo,
  scanDirForSecrets,
  KNOWN_COMPROMISED,
  SECRET_PATTERNS,
  CI_RISK_PATTERNS,
};
