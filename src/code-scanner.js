/**
 * Dangerous Code & Tool Argument Scanner
 * 
 * Detects dangerous code patterns in tool arguments, prompts, and outputs:
 * - Shell injection (bash, cmd, powershell)
 * - Filesystem destruction
 * - Credential/secret access
 * - Network exfiltration
 * - SQL injection
 * - Code execution (eval, exec, subprocess)
 * - Path traversal
 * - Environment manipulation
 * 
 * Context-aware: scores differently based on target tool.
 * 
 * @module code-scanner
 */

'use strict';

// Dangerous shell patterns
const SHELL_PATTERNS = [
  { re: /rm\s+(-[rf]+\s+)*[\/~]/, name: 'recursive delete from root/home', severity: 'critical' },
  { re: /rm\s+-[rf]*\s+\*/, name: 'wildcard recursive delete', severity: 'critical' },
  { re: /mkfs\b/, name: 'filesystem format', severity: 'critical' },
  { re: /dd\s+if=.*of=\/dev\//, name: 'disk overwrite', severity: 'critical' },
  { re: /:\(\)\s*\{\s*:\|:\s*&\s*\}\s*;?\s*:/, name: 'fork bomb', severity: 'critical' },
  { re: />\s*\/dev\/[sh]d[a-z]/, name: 'write to disk device', severity: 'critical' },
  { re: /curl\s+[^|]*\|\s*(ba)?sh/, name: 'curl pipe to shell', severity: 'critical' },
  { re: /wget\s+[^|]*\|\s*(ba)?sh/, name: 'wget pipe to shell', severity: 'critical' },
  { re: /\bchmod\s+[0-7]*777\b/, name: 'world-writable permissions', severity: 'high' },
  { re: /\bchmod\s+[+]s\b/, name: 'setuid permission', severity: 'critical' },
  { re: /\bchown\s+root\b/, name: 'change owner to root', severity: 'high' },
  { re: /nc\s+(-[a-z]+\s+)*.*\d+\s*(<|>|\|)/, name: 'netcat with redirect', severity: 'critical' },
  { re: /nc\s+-[a-z]*e\s/, name: 'netcat exec', severity: 'critical' },
  { re: /\bnohup\b.*&/, name: 'persistent background process', severity: 'medium' },
  { re: /crontab\s+-[er]/, name: 'crontab modification', severity: 'high' },
  { re: /\/etc\/passwd/, name: 'password file access', severity: 'high' },
  { re: /\/etc\/shadow/, name: 'shadow file access', severity: 'critical' },
  { re: /\bsudo\s/, name: 'privilege escalation (sudo)', severity: 'high' },
  { re: /\bsu\s+-?\s*root/, name: 'switch to root', severity: 'critical' },
  { re: /\bkill\s+-9\s/, name: 'force kill process', severity: 'medium' },
  { re: /\bkillall\b/, name: 'kill all matching processes', severity: 'high' },
  { re: /iptables\s+-[FA]/, name: 'firewall rule flush', severity: 'critical' },
  { re: /systemctl\s+(stop|disable)\s/, name: 'service stop/disable', severity: 'high' },
  { re: /\bshutdown\b|\breboot\b|\binit\s+[06]/, name: 'system shutdown/reboot', severity: 'critical' },
];

// Credential/secret access patterns
const CREDENTIAL_PATTERNS = [
  { re: /~\/\.ssh\/(id_|authorized_keys|known_hosts|config)/, name: 'SSH key access', severity: 'critical' },
  { re: /~\/\.aws\/(credentials|config)/, name: 'AWS credential access', severity: 'critical' },
  { re: /~\/\.gnupg\//, name: 'GPG key access', severity: 'critical' },
  { re: /~\/\.env\b|\.env\b/, name: 'environment file access', severity: 'high' },
  { re: /~\/\.gitconfig\b/, name: 'git config access', severity: 'medium' },
  { re: /~\/\.npmrc\b/, name: 'npm config (may contain tokens)', severity: 'high' },
  { re: /~\/\.docker\/config\.json/, name: 'Docker config (may contain auth)', severity: 'high' },
  { re: /~\/\.kube\/config/, name: 'Kubernetes config', severity: 'critical' },
  { re: /keychain|keyring|wallet\.dat|\.bitcoin/, name: 'keychain/wallet access', severity: 'critical' },
  { re: /\/var\/run\/secrets\//, name: 'Kubernetes secrets mount', severity: 'critical' },
  { re: /process\.env\[?['"][A-Z_]*(KEY|SECRET|TOKEN|PASS|AUTH)/, name: 'env var credential access', severity: 'high' },
  { re: /os\.environ\[?['"][A-Z_]*(KEY|SECRET|TOKEN|PASS|AUTH)/, name: 'Python env credential access', severity: 'high' },
];

// Network exfiltration patterns
const EXFIL_PATTERNS = [
  { re: /curl\s+.*-d\s+.*@/, name: 'curl POST with file data', severity: 'high' },
  { re: /curl\s+.*--data-binary\s+@/, name: 'curl binary upload', severity: 'high' },
  { re: /curl\s+.*-T\s/, name: 'curl file upload', severity: 'high' },
  { re: /scp\s+.*@.*:/, name: 'SCP file transfer', severity: 'high' },
  { re: /rsync\s+.*@.*:/, name: 'rsync to remote', severity: 'high' },
  { re: /base64\s+.*\|\s*curl/, name: 'base64 encode and exfiltrate', severity: 'critical' },
  { re: /tar\s+.*\|\s*(nc|curl|wget)/, name: 'archive and exfiltrate', severity: 'critical' },
  { re: /dns.*txt.*\|\s*(nc|curl)/, name: 'DNS exfiltration', severity: 'critical' },
  { re: /fetch\(['"]https?:\/\/(?!localhost|127\.0\.0\.1)/, name: 'JS fetch to external URL', severity: 'medium' },
  { re: /XMLHttpRequest|\.ajax\(|axios\.(post|put)/, name: 'HTTP client outbound', severity: 'medium' },
];

// SQL injection patterns
const SQL_PATTERNS = [
  { re: /'\s*(OR|AND)\s+'?\d*'?\s*=\s*'?\d*'?\s*--/, name: 'SQL injection (OR/AND tautology)', severity: 'critical' },
  { re: /UNION\s+(ALL\s+)?SELECT/i, name: 'SQL UNION injection', severity: 'critical' },
  { re: /;\s*DROP\s+TABLE/i, name: 'SQL DROP TABLE', severity: 'critical' },
  { re: /;\s*DELETE\s+FROM/i, name: 'SQL DELETE', severity: 'high' },
  { re: /;\s*UPDATE\s+.*SET\s+/i, name: 'SQL UPDATE injection', severity: 'high' },
  { re: /;\s*INSERT\s+INTO/i, name: 'SQL INSERT injection', severity: 'high' },
  { re: /EXEC(\s+|UTE\s+)(xp_|sp_)/i, name: 'SQL stored procedure execution', severity: 'critical' },
  { re: /INTO\s+OUTFILE/i, name: 'SQL file write', severity: 'critical' },
  { re: /LOAD_FILE\s*\(/i, name: 'SQL file read', severity: 'critical' },
];

// Code execution patterns
const EXEC_PATTERNS = [
  { re: /\beval\s*\(/, name: 'eval() call', severity: 'high' },
  { re: /\bexec\s*\(/, name: 'exec() call', severity: 'high' },
  { re: /Function\s*\(/, name: 'Function constructor', severity: 'high' },
  { re: /child_process/, name: 'Node.js child_process', severity: 'high' },
  { re: /subprocess\.(run|Popen|call)\s*\(/, name: 'Python subprocess', severity: 'high' },
  { re: /os\.system\s*\(/, name: 'Python os.system', severity: 'high' },
  { re: /os\.popen\s*\(/, name: 'Python os.popen', severity: 'high' },
  { re: /\b__import__\s*\(/, name: 'Python dynamic import', severity: 'high' },
  { re: /Runtime\.getRuntime\(\)\.exec/, name: 'Java Runtime.exec', severity: 'high' },
  { re: /ProcessBuilder/, name: 'Java ProcessBuilder', severity: 'high' },
  { re: /System\.Diagnostics\.Process/, name: '.NET Process.Start', severity: 'high' },
  { re: /\bimport\s+ctypes\b/, name: 'Python ctypes (FFI)', severity: 'medium' },
  { re: /require\s*\(\s*['"]child_process['"]/, name: 'require child_process', severity: 'high' },
];

// Path traversal patterns
const TRAVERSAL_PATTERNS = [
  { re: /\.\.\/\.\.\//, name: 'path traversal (..)', severity: 'high' },
  { re: /\.\.\\\.\.\\/, name: 'path traversal (Windows)', severity: 'high' },
  { re: /%2e%2e(%2f|%5c)/i, name: 'URL-encoded path traversal', severity: 'high' },
  { re: /\/proc\/self\//, name: 'Linux proc self access', severity: 'critical' },
  { re: /\/dev\/(tcp|udp)\//, name: 'Bash /dev/tcp socket', severity: 'critical' },
];

// Tool risk multipliers — context matters
const TOOL_RISK = {
  // High-risk tools: any finding is amplified
  'exec': 2.0, 'shell': 2.0, 'bash': 2.0, 'terminal': 2.0, 'run_command': 2.0,
  'write_file': 1.5, 'create_file': 1.5, 'edit_file': 1.2,
  'http': 1.3, 'fetch': 1.3, 'request': 1.3, 'curl': 1.5,
  'sql': 1.5, 'query': 1.3, 'database': 1.3,
  // Lower-risk tools
  'read_file': 0.8, 'list_files': 0.5, 'search': 0.5,
  'chat': 0.7, 'respond': 0.5, 'think': 0.3,
};

/**
 * Scan code/tool arguments for dangerous patterns
 * @param {string} text - Code or tool args to scan
 * @param {Object} [opts] - Options
 * @param {string} [opts.tool] - Tool name for context-aware scoring
 * @param {string} [opts.language] - Expected language ('shell', 'python', 'javascript', 'sql')
 * @returns {Object} { safe, findings, score }
 */
function scanCode(text, opts = {}) {
  const { tool, language } = opts;

  const findings = [];
  const allPatterns = [
    ...SHELL_PATTERNS.map(p => ({ ...p, category: 'shell' })),
    ...CREDENTIAL_PATTERNS.map(p => ({ ...p, category: 'credential_access' })),
    ...EXFIL_PATTERNS.map(p => ({ ...p, category: 'exfiltration' })),
    ...SQL_PATTERNS.map(p => ({ ...p, category: 'sql_injection' })),
    ...EXEC_PATTERNS.map(p => ({ ...p, category: 'code_execution' })),
    ...TRAVERSAL_PATTERNS.map(p => ({ ...p, category: 'path_traversal' })),
  ];

  for (const pattern of allPatterns) {
    // Skip SQL patterns if tool is clearly not DB-related
    if (pattern.category === 'sql_injection' && tool && !/(sql|query|database|db)/i.test(tool)) {
      // Still check but reduce confidence
    }

    const match = pattern.re.exec(text);
    if (match) {
      findings.push({
        type: 'dangerous_code',
        subtype: pattern.category,
        severity: pattern.severity,
        confidence: 0.85,
        evidence: `${pattern.name}: matched "${match[0].substring(0, 80)}"`,
        pattern_name: pattern.name,
        category: pattern.category,
        recommended_action: pattern.severity === 'critical' ? 'block' : 'require_confirmation',
      });
    }
  }

  // Apply tool risk multiplier
  const toolMultiplier = tool ? (TOOL_RISK[tool.toLowerCase()] || 1.0) : 1.0;

  const baseScore = findings.reduce((s, f) => {
    const w = { critical: 40, high: 25, medium: 15, low: 5 };
    return s + (w[f.severity] || 5);
  }, 0);

  const score = Math.min(100, Math.round(baseScore * toolMultiplier));

  const maxSeverity = findings.reduce((max, f) => {
    const order = { critical: 4, high: 3, medium: 2, low: 1 };
    return (order[f.severity] || 0) > (order[max] || 0) ? f.severity : max;
  }, 'low');

  return {
    safe: findings.length === 0,
    findings,
    score,
    maxSeverity: findings.length > 0 ? maxSeverity : null,
    toolMultiplier,
  };
}

/**
 * Quick check if a tool call looks dangerous
 * @param {string} tool - Tool name
 * @param {Object|string} args - Tool arguments
 * @returns {Object} { safe, risk, reason }
 */
function quickToolCheck(tool, args) {
  const text = typeof args === 'string' ? args : JSON.stringify(args);
  const result = scanCode(text, { tool });
  
  if (result.findings.length === 0) {
    return { safe: true, risk: 'none', reason: null };
  }

  const topFinding = result.findings.reduce((top, f) => {
    const order = { critical: 4, high: 3, medium: 2, low: 1 };
    return (order[f.severity] || 0) > (order[top.severity] || 0) ? f : top;
  }, result.findings[0]);

  return {
    safe: false,
    risk: topFinding.severity,
    reason: topFinding.evidence,
    findings: result.findings.length,
    score: result.score,
  };
}

module.exports = {
  scanCode,
  quickToolCheck,
  SHELL_PATTERNS,
  CREDENTIAL_PATTERNS,
  EXFIL_PATTERNS,
  SQL_PATTERNS,
  EXEC_PATTERNS,
  TRAVERSAL_PATTERNS,
  TOOL_RISK,
};
