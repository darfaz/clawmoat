const { scanMCPServer, parseMCPConfig, discoverMCPConfigs, scanMCP } = require('../src/mcp-scanner');
const fs = require('fs');
const path = require('path');
const os = require('os');

describe('MCP Scanner', () => {
  test('detects bash as MCP command', () => {
    const findings = scanMCPServer('evil-server', { command: 'bash', args: ['-c', 'echo hello'] });
    expect(findings.some(f => f.id === 'mcp-arbitrary-cmd')).toBe(true);
    expect(findings.some(f => f.severity === 'critical')).toBe(true);
  });

  test('allows legitimate MCP server command', () => {
    const findings = scanMCPServer('good-server', { command: 'npx', args: ['@modelcontextprotocol/server-filesystem', '/tmp'] });
    expect(findings.some(f => f.id === 'mcp-arbitrary-cmd')).toBe(false);
  });

  test('detects root filesystem access', () => {
    const findings = scanMCPServer('fs-server', { command: 'npx', args: ['@anthropic/mcp-filesystem', '/'] });
    expect(findings.some(f => f.id === 'mcp-root-fs')).toBe(true);
  });

  test('detects credentials in env vars', () => {
    const findings = scanMCPServer('cred-server', {
      command: 'node', args: ['server.js'],
      env: { OPENAI_API_KEY: 'sk-abc123', DATABASE_URL: 'postgres://...' }
    });
    expect(findings.some(f => f.id === 'mcp-env-creds')).toBe(true);
  });

  test('does not flag safe env vars', () => {
    const findings = scanMCPServer('safe-server', {
      command: 'npx', args: ['mcp-server'],
      env: { NODE_ENV: 'production', PORT: '3000' }
    });
    expect(findings.some(f => f.id === 'mcp-env-creds')).toBe(false);
  });

  test('detects mcp-shell server', () => {
    const findings = scanMCPServer('shell', { command: 'npx', args: ['mcp-shell'] });
    expect(findings.some(f => f.id === 'mcp-known-vulnerable')).toBe(true);
  });

  test('detects unpinned npx package', () => {
    const findings = scanMCPServer('unpinned', { command: 'npx', args: ['some-mcp-server'] });
    expect(findings.some(f => f.id === 'mcp-unpinned')).toBe(true);
  });

  test('allows pinned npx package', () => {
    const findings = scanMCPServer('pinned', { command: 'npx', args: ['some-mcp-server@1.2.3'] });
    expect(findings.some(f => f.id === 'mcp-unpinned')).toBe(false);
  });

  test('detects external URLs', () => {
    const findings = scanMCPServer('ext', { command: 'node', args: ['--url', 'https://suspicious-site.com/api'] });
    expect(findings.some(f => f.id === 'mcp-external-url')).toBe(true);
  });

  test('allows localhost URLs', () => {
    const findings = scanMCPServer('local', { command: 'node', args: ['--url', 'http://localhost:3000'] });
    expect(findings.some(f => f.id === 'mcp-external-url')).toBe(false);
  });

  test('parses Claude Desktop format', () => {
    const tmp = path.join(os.tmpdir(), 'test-mcp-config.json');
    fs.writeFileSync(tmp, JSON.stringify({
      mcpServers: {
        'test-server': { command: 'npx', args: ['test-mcp@1.0.0'] }
      }
    }));
    const servers = parseMCPConfig(tmp);
    expect(servers.length).toBe(1);
    expect(servers[0].name).toBe('test-server');
    fs.unlinkSync(tmp);
  });

  test('parses VS Code format', () => {
    const tmp = path.join(os.tmpdir(), 'test-vscode-mcp.json');
    fs.writeFileSync(tmp, JSON.stringify({
      mcp: { servers: { 'vscode-server': { command: 'node', args: ['server.js'] } } }
    }));
    const servers = parseMCPConfig(tmp);
    expect(servers.length).toBe(1);
    expect(servers[0].name).toBe('vscode-server');
    fs.unlinkSync(tmp);
  });

  test('discoverMCPConfigs returns expected paths', () => {
    const configs = discoverMCPConfigs();
    expect(configs.length).toBeGreaterThan(5);
    expect(configs.some(c => c.name.includes('Claude'))).toBe(true);
    expect(configs.some(c => c.name.includes('Cursor'))).toBe(true);
  });

  test('scanMCP works with custom config', () => {
    const tmp = path.join(os.tmpdir(), 'test-scan-mcp.json');
    fs.writeFileSync(tmp, JSON.stringify({
      mcpServers: {
        'danger': { command: 'bash', args: ['-c', 'evil'], env: { SECRET_KEY: 'abc' } },
        'safe': { command: 'npx', args: ['@mcp/server@1.0.0'] }
      }
    }));
    const report = scanMCP({ extraPaths: [tmp] });
    expect(report.servers.length).toBeGreaterThanOrEqual(2);
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.summary.critical + report.summary.high).toBeGreaterThan(0);
    fs.unlinkSync(tmp);
  });
});
