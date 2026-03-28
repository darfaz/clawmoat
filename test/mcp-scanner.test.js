const { scanMCPServer, parseMCPConfig, discoverMCPConfigs, scanMCP } = require('../src/mcp-scanner');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Test scanMCPServer
console.log('=== MCP Scanner Tests ===\n');
let pass = 0, fail = 0;

function test(name, fn) {
  try {
    fn();
    pass++;
    console.log(`  ✓ ${name}`);
  } catch(e) {
    fail++;
    console.log(`  ✗ ${name}: ${e.message}`);
  }
}

function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }

// Critical: arbitrary command execution
test('detects bash as MCP command', () => {
  const findings = scanMCPServer('evil-server', { command: 'bash', args: ['-c', 'echo hello'] });
  assert(findings.some(f => f.id === 'mcp-arbitrary-cmd'), 'should flag bash');
  assert(findings.some(f => f.severity === 'critical'), 'should be critical');
});

test('allows legitimate MCP server command', () => {
  const findings = scanMCPServer('good-server', { command: 'npx', args: ['@modelcontextprotocol/server-filesystem', '/tmp'] });
  assert(!findings.some(f => f.id === 'mcp-arbitrary-cmd'), 'should not flag npx mcp server');
});

// Critical: root filesystem access
test('detects root filesystem access', () => {
  const findings = scanMCPServer('fs-server', { command: 'npx', args: ['@anthropic/mcp-filesystem', '/'] });
  assert(findings.some(f => f.id === 'mcp-root-fs'), 'should flag root access');
});

// High: env var credentials
test('detects credentials in env vars', () => {
  const findings = scanMCPServer('cred-server', {
    command: 'node', args: ['server.js'],
    env: { OPENAI_API_KEY: 'sk-abc123', DATABASE_URL: 'postgres://...' }
  });
  assert(findings.some(f => f.id === 'mcp-env-creds'), 'should flag API key in env');
});

test('does not flag safe env vars', () => {
  const findings = scanMCPServer('safe-server', {
    command: 'npx', args: ['mcp-server'],
    env: { NODE_ENV: 'production', PORT: '3000' }
  });
  assert(!findings.some(f => f.id === 'mcp-env-creds'), 'should not flag NODE_ENV');
});

// High: known dangerous servers
test('detects mcp-shell server', () => {
  const findings = scanMCPServer('shell', { command: 'npx', args: ['mcp-shell'] });
  assert(findings.some(f => f.id === 'mcp-known-vulnerable'), 'should flag mcp-shell');
});

// Medium: unpinned packages
test('detects unpinned npx package', () => {
  const findings = scanMCPServer('unpinned', { command: 'npx', args: ['some-mcp-server'] });
  assert(findings.some(f => f.id === 'mcp-unpinned'), 'should flag unpinned');
});

test('allows pinned npx package', () => {
  const findings = scanMCPServer('pinned', { command: 'npx', args: ['some-mcp-server@1.2.3'] });
  assert(!findings.some(f => f.id === 'mcp-unpinned'), 'should not flag pinned');
});

// Medium: external URLs
test('detects external URLs', () => {
  const findings = scanMCPServer('ext', { command: 'node', args: ['--url', 'https://suspicious-site.com/api'] });
  assert(findings.some(f => f.id === 'mcp-external-url'), 'should flag external URL');
});

test('allows localhost URLs', () => {
  const findings = scanMCPServer('local', { command: 'node', args: ['--url', 'http://localhost:3000'] });
  assert(!findings.some(f => f.id === 'mcp-external-url'), 'should not flag localhost');
});

// Test parseMCPConfig with temp file
test('parses Claude Desktop format', () => {
  const tmp = path.join(os.tmpdir(), 'test-mcp-config.json');
  fs.writeFileSync(tmp, JSON.stringify({
    mcpServers: {
      'test-server': { command: 'npx', args: ['test-mcp@1.0.0'] }
    }
  }));
  const servers = parseMCPConfig(tmp);
  assert(servers.length === 1, 'should find 1 server');
  assert(servers[0].name === 'test-server', 'should have correct name');
  fs.unlinkSync(tmp);
});

test('parses VS Code format', () => {
  const tmp = path.join(os.tmpdir(), 'test-vscode-mcp.json');
  fs.writeFileSync(tmp, JSON.stringify({
    mcp: { servers: { 'vscode-server': { command: 'node', args: ['server.js'] } } }
  }));
  const servers = parseMCPConfig(tmp);
  assert(servers.length === 1, 'should find 1 server');
  assert(servers[0].name === 'vscode-server');
  fs.unlinkSync(tmp);
});

// Test discoverMCPConfigs
test('discoverMCPConfigs returns expected paths', () => {
  const configs = discoverMCPConfigs();
  assert(configs.length > 5, 'should check multiple paths');
  assert(configs.some(c => c.name.includes('Claude')), 'should include Claude');
  assert(configs.some(c => c.name.includes('Cursor')), 'should include Cursor');
});

// Test full scanMCP with custom path
test('scanMCP works with custom config', () => {
  const tmp = path.join(os.tmpdir(), 'test-scan-mcp.json');
  fs.writeFileSync(tmp, JSON.stringify({
    mcpServers: {
      'danger': { command: 'bash', args: ['-c', 'evil'], env: { SECRET_KEY: 'abc' } },
      'safe': { command: 'npx', args: ['@mcp/server@1.0.0'] }
    }
  }));
  const report = scanMCP({ extraPaths: [tmp] });
  assert(report.servers.length >= 2, 'should find servers');
  assert(report.findings.length > 0, 'should have findings');
  assert(report.summary.critical > 0 || report.summary.high > 0, 'should have critical/high');
  fs.unlinkSync(tmp);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail > 0 ? 1 : 0);
