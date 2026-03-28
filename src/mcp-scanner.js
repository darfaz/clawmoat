/**
 * ClawMoat MCP Scanner — Discover and scan MCP server configurations
 * Finds configs for Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const HOME = os.homedir();

// Known MCP config locations
const MCP_CONFIG_PATHS = [
  // Claude Desktop
  { name: 'Claude Desktop', path: path.join(HOME, '.claude', 'claude_desktop_config.json') },
  { name: 'Claude Desktop (macOS)', path: path.join(HOME, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json') },
  { name: 'Claude Desktop (Windows)', path: path.join(HOME, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json') },
  // Claude Code
  { name: 'Claude Code', path: path.join(HOME, '.claude', 'mcp.json') },
  { name: 'Claude Code (project)', path: '.claude/mcp.json' },
  // Cursor
  { name: 'Cursor', path: path.join(HOME, '.cursor', 'mcp.json') },
  // VS Code
  { name: 'VS Code', path: path.join(HOME, '.vscode', 'mcp.json') },
  { name: 'VS Code (settings)', path: path.join(HOME, '.config', 'Code', 'User', 'settings.json') },
  // Windsurf
  { name: 'Windsurf', path: path.join(HOME, '.windsurf', 'mcp.json') },
  { name: 'Windsurf (codeium)', path: path.join(HOME, '.codeium', 'windsurf', 'mcp_config.json') },
  // Gemini CLI
  { name: 'Gemini CLI', path: path.join(HOME, '.gemini', 'settings.json') },
  // OpenClaw
  { name: 'OpenClaw', path: path.join(HOME, '.openclaw', 'openclaw.json') },
];

// Dangerous patterns in MCP server configs
const MCP_RISKS = [
  // Command execution
  { id: 'mcp-arbitrary-cmd', severity: 'critical', pattern: (server) => {
    const cmd = server.command || '';
    const args = (server.args || []).join(' ');
    return /^(bash|sh|zsh|cmd|powershell|node|python|ruby|perl)$/i.test(cmd) && !/mcp|server/i.test(args);
  }, label: 'Arbitrary command execution', fix: 'MCP server runs a generic shell/interpreter. Use a purpose-built MCP server binary instead.' },

  // Root filesystem access
  { id: 'mcp-root-fs', severity: 'critical', pattern: (server) => {
    const args = JSON.stringify(server.args || []);
    return /["\s]\/["\\s,\]]/.test(args) || /allowedDirectories.*["']\/["']/.test(args);
  }, label: 'Root filesystem access', fix: 'MCP server has access to root filesystem. Restrict to specific directories.' },

  // Home directory access
  { id: 'mcp-home-fs', severity: 'high', pattern: (server) => {
    const args = JSON.stringify(server.args || []);
    return args.includes(HOME) && /filesystem|fs-|file/i.test(JSON.stringify(server));
  }, label: 'Home directory access via filesystem MCP', fix: 'Restrict filesystem MCP servers to project directories only.' },

  // Known dangerous MCP servers
  { id: 'mcp-dangerous-server', severity: 'high', pattern: (server) => {
    const full = JSON.stringify(server).toLowerCase();
    return /mcp-shell|mcp-terminal|mcp-exec|mcp-command/.test(full);
  }, label: 'Shell/terminal execution MCP server', fix: 'Shell-access MCP servers give agents unrestricted command execution. Remove or heavily restrict.' },

  // Env var credential exposure
  { id: 'mcp-env-creds', severity: 'high', pattern: (server) => {
    const env = server.env || {};
    const keys = Object.keys(env);
    return keys.some(k => /key|secret|token|password|auth|credential/i.test(k));
  }, label: 'Credentials in MCP server environment', fix: 'MCP server has API keys/secrets in env vars. These are accessible to any tool the server exposes. Use scoped tokens with minimal permissions.' },

  // Hardcoded URLs (potential C2)
  { id: 'mcp-external-url', severity: 'medium', pattern: (server) => {
    const full = JSON.stringify(server);
    const urls = full.match(/https?:\/\/[^\s"']+/g) || [];
    return urls.some(u => !/localhost|127\.0\.0\.1|github\.com|npmjs\.com|pypi\.org/.test(u));
  }, label: 'External URL in MCP config', fix: 'MCP server connects to an external URL. Verify this is a trusted endpoint.' },

  // stdio with no restrictions
  { id: 'mcp-unrestricted-stdio', severity: 'medium', pattern: (server) => {
    const transport = server.transport || 'stdio';
    return transport === 'stdio' && !server.allowedTools && !server.blockedTools;
  }, label: 'Unrestricted stdio MCP server', fix: 'MCP server exposes all tools via stdio with no allowlist/blocklist. Add allowedTools to restrict.' },

  // npx/pip without pinned version
  { id: 'mcp-unpinned', severity: 'medium', pattern: (server) => {
    const cmd = server.command || '';
    const args = (server.args || []).join(' ');
    if (!/npx|uvx|pip/.test(cmd)) return false;
    // Check if any arg has a version pin (@version or ==version)
    return !/@[\d.]|==[\d.]/.test(args);
  }, label: 'Unpinned MCP server package', fix: 'MCP server installed via npx/uvx without version pin. A supply chain attack could replace the package. Pin to a specific version.' },

  // Too many tools exposed
  { id: 'mcp-tool-sprawl', severity: 'low', pattern: (server) => {
    // Can't always detect this statically, but flag servers with no tool restrictions
    return !server.allowedTools && !server.blockedTools && !server.disabledTools;
  }, label: 'No tool restrictions configured', fix: 'Consider using allowedTools/blockedTools to limit which MCP tools the agent can invoke.' },
];

// Known compromised/vulnerable MCP servers
const KNOWN_VULNERABLE_SERVERS = {
  '@anthropic/mcp-filesystem': { severity: 'medium', note: 'Powerful but broad. Always restrict allowedDirectories.' },
  'mcp-shell': { severity: 'critical', note: 'Gives agents arbitrary shell access. Almost never appropriate.' },
  'mcp-terminal': { severity: 'critical', note: 'Gives agents terminal access. Use with extreme caution.' },
};

/**
 * Discover MCP config files on the system
 * @returns {Array<{name: string, path: string, exists: boolean}>}
 */
function discoverMCPConfigs(extraPaths = []) {
  const allPaths = [...MCP_CONFIG_PATHS, ...extraPaths.map(p => ({ name: 'Custom', path: p }))];
  return allPaths.map(entry => ({
    ...entry,
    exists: fs.existsSync(entry.path),
  }));
}

/**
 * Parse an MCP config file and extract server definitions
 * @param {string} filePath
 * @returns {Array<{name: string, server: object}>}
 */
function parseMCPConfig(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const config = JSON.parse(raw);
    const servers = [];

    // Claude Desktop / Claude Code format: { mcpServers: { name: { command, args, env } } }
    if (config.mcpServers) {
      for (const [name, server] of Object.entries(config.mcpServers)) {
        servers.push({ name, server, source: 'mcpServers' });
      }
    }

    // VS Code / Cursor format: { mcp: { servers: { name: { ... } } } }
    if (config.mcp?.servers) {
      for (const [name, server] of Object.entries(config.mcp.servers)) {
        servers.push({ name, server, source: 'mcp.servers' });
      }
    }

    // Array format: [{ name, command, args }]
    if (Array.isArray(config)) {
      config.forEach((server, i) => {
        servers.push({ name: server.name || `server-${i}`, server, source: 'array' });
      });
    }

    // OpenClaw format: check for mcp section
    if (config.mcp) {
      if (config.mcp.mcpServers) {
        for (const [name, server] of Object.entries(config.mcp.mcpServers)) {
          servers.push({ name, server, source: 'openclaw.mcp.mcpServers' });
        }
      }
    }

    return servers;
  } catch (e) {
    return [];
  }
}

/**
 * Scan a single MCP server definition for risks
 * @param {string} serverName
 * @param {object} serverConfig
 * @returns {Array<{id: string, severity: string, label: string, fix: string}>}
 */
function scanMCPServer(serverName, serverConfig) {
  const findings = [];

  // Check against risk patterns
  for (const risk of MCP_RISKS) {
    try {
      if (risk.pattern(serverConfig)) {
        findings.push({
          id: risk.id,
          severity: risk.severity,
          label: risk.label,
          fix: risk.fix,
          server: serverName,
        });
      }
    } catch (e) { /* pattern failed, skip */ }
  }

  // Check against known vulnerable servers
  const cmd = serverConfig.command || '';
  const args = (serverConfig.args || []).join(' ');
  const fullCmd = `${cmd} ${args}`;
  for (const [pkg, info] of Object.entries(KNOWN_VULNERABLE_SERVERS)) {
    if (fullCmd.includes(pkg)) {
      findings.push({
        id: 'mcp-known-vulnerable',
        severity: info.severity,
        label: `Known risky MCP server: ${pkg}`,
        fix: info.note,
        server: serverName,
      });
    }
  }

  return findings;
}

/**
 * Full MCP scan — discover configs, parse, and scan all servers
 * @param {object} options
 * @returns {object} Scan report
 */
function scanMCP(options = {}) {
  const { extraPaths = [], verbose = false } = options;
  const report = {
    timestamp: new Date().toISOString(),
    configsFound: [],
    servers: [],
    findings: [],
    summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
  };

  // Discover configs
  const configs = discoverMCPConfigs(extraPaths);
  report.configsFound = configs.filter(c => c.exists);

  // Parse and scan each config
  for (const config of report.configsFound) {
    const servers = parseMCPConfig(config.path);
    for (const { name, server, source } of servers) {
      report.servers.push({ name, config: config.name, path: config.path, source });
      const findings = scanMCPServer(name, server);
      for (const f of findings) {
        f.configName = config.name;
        f.configPath = config.path;
        report.findings.push(f);
        report.summary.total++;
        report.summary[f.severity]++;
      }
    }
  }

  return report;
}

module.exports = {
  discoverMCPConfigs,
  parseMCPConfig,
  scanMCPServer,
  scanMCP,
  MCP_CONFIG_PATHS,
  MCP_RISKS,
  KNOWN_VULNERABLE_SERVERS,
};
