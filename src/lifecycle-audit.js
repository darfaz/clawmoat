const fs = require('fs');
const path = require('path');

const DEFAULT_IGNORE_DIRS = new Set(['.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache']);
const TEXT_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.json', '.yml', '.yaml', '.toml', '.env', '.md', '.txt']);
const CONFIG_NAMES = new Set(['clawmoat.yml', 'clawmoat.yaml', '.clawmoat.yml', '.clawmoat.yaml']);

function auditAgentLifecycle(opts = {}) {
  const rootDir = path.resolve(opts.rootDir || process.cwd());
  const pathExists = fs.existsSync(rootDir);
  const files = pathExists ? collectProjectFiles(rootDir) : [];
  const fileTexts = files
    .map((file) => ({ file, rel: path.relative(rootDir, file), text: safeRead(file) }))
    .filter((entry) => !isGeneratedLifecycleReport(entry));
  const combined = fileTexts.map((entry) => `\n# ${entry.rel}\n${entry.text}`).join('\n');

  const surfaces = detectSurfaces(fileTexts, combined);
  const frameworks = detectFrameworks(fileTexts, combined);
  const credentials = detectCredentialHints(fileTexts);
  const controls = detectControls(fileTexts, combined);
  const findings = buildFindings({ files: fileTexts, combined, surfaces, credentials, controls, pathExists });
  const riskScore = scoreRisk(findings, controls);

  return {
    type: 'agent_lifecycle_audit',
    rootDir,
    ok: riskScore < 40 && !findings.some((finding) => finding.severity === 'critical'),
    summary: {
      riskScore,
      grade: gradeRisk(riskScore),
      filesScanned: fileTexts.length,
      findings: findings.length,
      surfaces: surfaces.length,
      frameworks: frameworks.length,
      credentials: credentials.length,
    },
    surfaces,
    frameworks,
    credentials,
    controls,
    findings,
    recommendations: buildRecommendations({ findings, controls, surfaces, credentials }),
  };
}

function collectProjectFiles(rootDir) {
  const out = [];
  walk(rootDir, out);
  return out.sort();
}

function walk(dir, out) {
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (_err) {
    return;
  }

  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!DEFAULT_IGNORE_DIRS.has(entry.name)) walk(full, out);
      continue;
    }
    if (!entry.isFile()) continue;
    if (isTextProjectFile(full, entry.name)) out.push(full);
  }
}

function isTextProjectFile(file, name) {
  if (CONFIG_NAMES.has(name) || name === '.env' || name.startsWith('.env.')) return true;
  if (/^(requirements.*\.txt|pyproject\.toml|poetry\.lock|pdm\.lock)$/.test(name)) return true;
  return TEXT_EXTENSIONS.has(path.extname(file));
}

function safeRead(file) {
  try {
    const stat = fs.statSync(file);
    if (stat.size > 256 * 1024) return '';
    return fs.readFileSync(file, 'utf8');
  } catch (_err) {
    return '';
  }
}

function isGeneratedLifecycleReport(entry) {
  const base = path.basename(entry.rel).toLowerCase();
  return base === 'lifecycle-report.md' || entry.text.startsWith('# ClawMoat Agent Lifecycle Exposure Report');
}

function detectSurfaces(fileTexts, combined) {
  const lower = combined.toLowerCase();
  const surfaces = new Set();
  const hasFile = (regex) => fileTexts.some((entry) => regex.test(entry.rel.toLowerCase()) || regex.test(entry.text.toLowerCase()));

  if (/\b(shell|exec|spawn|child_process|bash|powershell|terminal|command)\b/.test(lower)) surfaces.add('shell');
  if (/\b(filesystem|fs\.|readfile|writefile|server-filesystem|file[_-]?system)\b/.test(lower)) surfaces.add('filesystem');
  if (/\b(fetch|axios|http\.|https\.|websocket|curl|network|egress)\b/.test(lower)) surfaces.add('network');
  if (/\b(browser|playwright|puppeteer|selenium|chrome)\b/.test(lower)) surfaces.add('browser');
  if (/\b(gmail|calendar|imap|smtp|googleapis|email)\b/.test(lower)) surfaces.add('email_calendar');
  if (/\b(github|gh\s|octokit|pull request|repository)\b/.test(lower)) surfaces.add('github');
  if (/\b(wallet|ethereum|solana|bitcoin|private[_-]?key|web3|ethers|viem)\b/.test(lower)) surfaces.add('wallet');
  if (/mcpservers|modelcontextprotocol|mcp server|@modelcontextprotocol/.test(lower) || hasFile(/(^|\/)(\.mcp\.json|mcp\.json)$/)) surfaces.add('mcp');

  return Array.from(surfaces).sort();
}

function detectFrameworks(fileTexts, combined) {
  const lower = combined.toLowerCase();
  const frameworks = new Set();
  const hasPackage = (name) => fileTexts.some((entry) => entry.rel.endsWith('package.json') && entry.text.toLowerCase().includes(`"${name.toLowerCase()}"`));
  const hasPythonDependency = (name) => fileTexts.some((entry) => {
    if (!/(^|\/)(requirements.*\.txt|pyproject\.toml|poetry\.lock|pdm\.lock)$/.test(entry.rel)) return false;
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`(^|["'\\s_-])${escaped}(["'\\s<>=~_-]|$)`, 'im').test(entry.text);
  });

  if (hasPackage('langchain') || hasPythonDependency('langchain') || /from ['"]langchain|require\(['"]langchain|langchain\//.test(lower)) frameworks.add('langchain');
  if (hasPackage('@openai/agents') || /openai agents|@openai\/agents|agents sdk/.test(lower)) frameworks.add('openai_agents');
  if (hasPackage('crewai') || hasPythonDependency('crewai') || /from ['"]crewai|import crewai|crew ai/.test(lower)) frameworks.add('crewai');
  if (hasPackage('autogen') || hasPackage('@microsoft/autogen') || hasPythonDependency('autogen') || hasPythonDependency('pyautogen') || /from ['"]autogen|import autogen|microsoft autogen/.test(lower)) frameworks.add('autogen');
  if (hasPackage('@modelcontextprotocol/sdk') || hasPythonDependency('mcp') || /mcpservers|modelcontextprotocol|mcp server|@modelcontextprotocol/.test(lower)) frameworks.add('mcp');
  if (/claude desktop|claude-code|claude code|\.claude\//.test(lower)) frameworks.add('anthropic_claude');

  return Array.from(frameworks).sort();
}

function detectCredentialHints(fileTexts) {
  const hints = new Set();
  const patterns = [
    ['openai', /OPENAI_API_KEY|sk-[A-Za-z0-9_-]{8,}/],
    ['anthropic', /ANTHROPIC_API_KEY|sk-ant-/],
    ['google', /GOOGLE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|GMAIL|CALENDAR/],
    ['github', /GITHUB_TOKEN|GH_TOKEN|github_pat_/],
    ['aws', /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY/],
    ['wallet', /PRIVATE_KEY|WALLET_SEED|MNEMONIC/],
  ];

  for (const entry of fileTexts) {
    for (const [name, regex] of patterns) {
      if (regex.test(entry.text)) hints.add(name);
    }
    if (entry.rel === '.env' || entry.rel.startsWith('.env.')) hints.add('env_file');
  }

  return Array.from(hints).sort();
}

function detectControls(fileTexts, combined) {
  const lower = combined.toLowerCase();
  const configText = fileTexts
    .filter((entry) => CONFIG_NAMES.has(path.basename(entry.rel)))
    .map((entry) => entry.text.toLowerCase())
    .join('\n');
  const policyText = configText || lower;

  return {
    identity: /agent[_-]?id|identity|principal|session[_-]?id|actor/.test(policyText),
    toolPolicy: /policies:|tools:|allowlist|denylist|read-only|review|required_for/.test(policyText),
    humanApproval: /approval|human[_-]?in[_-]?the[_-]?loop|review|required_for/.test(policyText),
    auditTrail: /audit[_-]?trail|tamper[_-]?evident|hash[_-]?chain|logging:|securitylogger/.test(policyText),
    credentialHealth: /credential.*health|health_check|token.*expiry|oauth.*status|rotation/.test(policyText),
    killSwitch: /kill[_-]?switch|freeze|circuit[_-]?breaker|stop[_-]?session/.test(policyText),
    mcpPolicy: /mcp.*policy|mcp.*gateway|scan-mcp|mcp-security|mcp_proxy/.test(policyText),
  };
}

function buildFindings({ files, surfaces, credentials, controls, pathExists = true }) {
  const findings = [];
  if (!pathExists) {
    findings.push(finding('audit_path_missing', 'critical', 'The requested audit path does not exist or cannot be reached.', 'Fix the audit path and re-run `clawmoat lifecycle audit --path <dir>`.'));
    return findings;
  }
  const hasSurface = (name) => surfaces.includes(name);
  const hasConfig = files.some((entry) => CONFIG_NAMES.has(path.basename(entry.rel)));

  if (credentials.length > 0 && !controls.credentialHealth) {
    findings.push(finding('credentials_without_health_checks', 'high', 'Credentials are present or referenced, but no credential health/expiry/rotation control was detected.', 'Add credential health checks for missing, expired, overbroad, or stale tokens.'));
  }

  if ((hasSurface('mcp') || files.some((entry) => entry.rel.endsWith('.mcp.json'))) && !(controls.mcpPolicy || controls.toolPolicy)) {
    findings.push(finding('mcp_without_policy', 'high', 'MCP configuration or SDK usage was detected without a visible MCP/tool policy.', 'Put a policy gate between the agent and MCP tool calls. Start with per-server allowlists and review gates for write tools.'));
  }

  if ((hasSurface('shell') || hasSurface('filesystem') || hasSurface('wallet') || hasSurface('github')) && !controls.humanApproval) {
    findings.push(finding('write_tools_without_approval', 'critical', 'High-impact tool surfaces were detected without a human approval gate.', 'Require review for shell, filesystem writes, wallet transactions, GitHub writes, and other irreversible actions.'));
  }

  if (surfaces.length > 0 && !controls.identity) {
    findings.push(finding('agent_identity_missing', 'medium', 'The project exposes agent tool surfaces but no agent/session identity control was detected.', 'Assign every agent run a stable agent_id/session_id so incidents answer: which agent did this?'));
  }

  if (surfaces.length > 0 && !controls.auditTrail) {
    findings.push(finding('audit_trail_missing', 'high', 'The project exposes agent tool surfaces but no audit trail control was detected.', 'Log prompts, tool calls, policy decisions, blocked events, and actor/session metadata.'));
  }

  if ((hasSurface('shell') || hasSurface('wallet') || hasSurface('filesystem')) && !controls.killSwitch) {
    findings.push(finding('kill_switch_missing', 'medium', 'High-impact tool surfaces were detected without a kill switch or circuit breaker.', 'Freeze risky tools after suspicious sequences or repeated policy violations.'));
  }

  if (!hasConfig && surfaces.length > 0) {
    findings.push(finding('clawmoat_config_missing', 'low', 'Agent surfaces were detected, but no ClawMoat config file was found.', 'Run `clawmoat init` and add lifecycle policies before the agent touches production systems.'));
  }

  return findings;
}

function finding(id, severity, message, recommendation) {
  return { id, severity, message, recommendation };
}

function scoreRisk(findings, controls) {
  const weights = { critical: 35, high: 22, medium: 12, low: 5 };
  let score = findings.reduce((sum, item) => sum + (weights[item.severity] || 5), 0);
  const controlCount = Object.values(controls).filter(Boolean).length;
  score -= controlCount * 4;
  if (findings.some((item) => item.severity === 'critical')) score = Math.max(score, 80);
  return Math.max(0, Math.min(100, score));
}

function gradeRisk(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  return 'controlled';
}

function buildRecommendations({ findings, controls, surfaces, credentials }) {
  const recommendations = findings.map((findingItem) => findingItem.recommendation);
  if (surfaces.includes('mcp')) recommendations.push('Run `clawmoat scan-mcp` on MCP server descriptions and tool outputs before enabling them for agents.');
  if (credentials.length > 0) recommendations.push('Record credential owner, scope, expiry, and revocation path for every agent-accessible token.');
  if (controls.auditTrail && controls.toolPolicy) recommendations.push('Re-run this audit after every new tool, MCP server, credential, or scheduled agent job.');
  if (recommendations.length === 0) recommendations.push('Re-run this audit after every new tool, MCP server, credential, or scheduled agent job.');
  return Array.from(new Set(recommendations));
}

function escapeMarkdownCell(value) {
  return escapeMarkdownInline(value).replace(/\|/g, '\\|').replace(/\n+/g, ' ');
}

function escapeMarkdownInline(value) {
  return String(value).replace(/`/g, '\\`').replace(/\n+/g, ' ');
}

function formatLifecycleAuditMarkdown(report) {
  const lines = [];
  lines.push('# ClawMoat Agent Lifecycle Exposure Report');
  lines.push('');
  lines.push(`Path: \`${escapeMarkdownInline(report.rootDir)}\``);
  lines.push(`Risk: **${report.summary.grade.toUpperCase()}** (${report.summary.riskScore}/100)`);
  lines.push(`Files scanned: **${report.summary.filesScanned}**`);
  lines.push(`Surfaces: ${report.surfaces.length ? report.surfaces.map((item) => `\`${escapeMarkdownInline(item)}\``).join(', ') : 'none detected'}`);
  lines.push(`Frameworks: ${report.frameworks.length ? report.frameworks.map((item) => `\`${escapeMarkdownInline(item)}\``).join(', ') : 'none detected'}`);
  lines.push(`Credential hints: ${report.credentials.length ? report.credentials.map((item) => `\`${escapeMarkdownInline(item)}\``).join(', ') : 'none detected'}`);
  lines.push('');
  lines.push('## Lifecycle controls');
  lines.push('');
  lines.push('| Control | Status |');
  lines.push('|---|---|');
  for (const [name, enabled] of Object.entries(report.controls)) {
    lines.push(`| ${escapeMarkdownCell(name)} | ${enabled ? '✅ present' : '❌ missing'} |`);
  }
  lines.push('');
  lines.push('## Findings');
  lines.push('');
  if (report.findings.length === 0) {
    lines.push('No lifecycle exposure findings detected.');
  } else {
    lines.push('| Severity | Finding | Fix |');
    lines.push('|---|---|---|');
    for (const item of report.findings) {
      lines.push(`| ${item.severity.toUpperCase()} | \`${escapeMarkdownCell(item.id)}\` — ${escapeMarkdownCell(item.message)} | ${escapeMarkdownCell(item.recommendation)} |`);
    }
  }
  lines.push('');
  lines.push('## Remediation checklist');
  lines.push('');
  for (const rec of report.recommendations) lines.push(`- [ ] ${rec}`);
  lines.push('');
  lines.push('## Next step');
  lines.push('');
  lines.push('Want a second set of eyes? Request a free AI agent security assessment: https://clawmoat.com/assessment/');
  return lines.join('\n');
}

function formatLifecycleAuditText(report) {
  const lines = [];
  lines.push('🏰 ClawMoat Agent Lifecycle Exposure Report');
  lines.push('');
  lines.push(`Path: ${report.rootDir}`);
  lines.push(`Risk: ${report.summary.grade.toUpperCase()} (${report.summary.riskScore}/100)`);
  lines.push(`Files scanned: ${report.summary.filesScanned}`);
  lines.push(`Surfaces: ${report.surfaces.length ? report.surfaces.join(', ') : 'none detected'}`);
  lines.push(`Frameworks: ${report.frameworks.length ? report.frameworks.join(', ') : 'none detected'}`);
  lines.push(`Credential hints: ${report.credentials.length ? report.credentials.join(', ') : 'none detected'}`);
  lines.push('');
  lines.push('Lifecycle controls:');
  for (const [name, enabled] of Object.entries(report.controls)) {
    lines.push(`  ${enabled ? '✅' : '❌'} ${name}`);
  }
  lines.push('');

  if (report.findings.length === 0) {
    lines.push('No lifecycle exposure findings detected.');
  } else {
    lines.push('Top findings:');
    for (const item of report.findings) {
      lines.push(`  [${item.severity.toUpperCase()}] ${item.id}`);
      lines.push(`    ${item.message}`);
      lines.push(`    Fix: ${item.recommendation}`);
    }
  }

  lines.push('');
  lines.push('Recommendations:');
  for (const rec of report.recommendations) lines.push(`  • ${rec}`);
  return lines.join('\n');
}

module.exports = {
  auditAgentLifecycle,
  formatLifecycleAuditText,
  formatLifecycleAuditMarkdown,
};
