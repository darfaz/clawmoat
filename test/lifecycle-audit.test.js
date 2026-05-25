/**
 * Tests for agent lifecycle exposure audits.
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const { strictEqual, ok } = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const { auditAgentLifecycle } = require('../src/lifecycle-audit');

function write(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

describe('agent lifecycle audit', () => {
  let testDir;
  let originalCwd;

  beforeEach(() => {
    originalCwd = process.cwd();
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'clawmoat-lifecycle-'));
    process.chdir(testDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it('flags lifecycle gaps for agent projects with tools and credentials but no controls', () => {
    write(path.join(testDir, 'package.json'), JSON.stringify({ name: 'agent-app', dependencies: { '@modelcontextprotocol/sdk': '^1.0.0' } }, null, 2));
    write(path.join(testDir, '.env'), 'OPENAI_API_KEY=sk-test\nGOOGLE_CLIENT_SECRET=secret\n');
    write(path.join(testDir, '.mcp.json'), JSON.stringify({
      mcpServers: {
        filesystem: { command: 'npx', args: ['@modelcontextprotocol/server-filesystem', '.'] },
        shell: { command: 'node', args: ['shell-server.js'] }
      }
    }, null, 2));
    write(path.join(testDir, 'agent.js'), "await tools.shell('rm -rf /tmp/demo'); await fetch('https://api.example.com')");

    const report = auditAgentLifecycle({ rootDir: testDir });

    strictEqual(report.ok, false);
    ok(report.summary.riskScore >= 70, `expected high risk score, got ${report.summary.riskScore}`);
    ok(report.surfaces.includes('shell'), 'should detect shell tool surface');
    ok(report.surfaces.includes('filesystem'), 'should detect filesystem tool surface');
    ok(report.surfaces.includes('network'), 'should detect network tool surface');
    ok(report.findings.some((finding) => finding.id === 'credentials_without_health_checks'));
    ok(report.findings.some((finding) => finding.id === 'mcp_without_policy'));
    ok(report.findings.some((finding) => finding.id === 'write_tools_without_approval'));
    ok(report.findings.some((finding) => finding.id === 'audit_trail_missing'));
  });

  it('rewards explicit lifecycle controls', () => {
    write(path.join(testDir, 'clawmoat.yml'), `
identity:
  agent_id: lifecycle-demo
approvals:
  required_for:
    - shell
    - filesystem
logging:
  audit_trail: true
  tamper_evident: true
credentials:
  health_check: true
kill_switch:
  enabled: true
policies:
  tools:
    shell: review
    filesystem: read-only
`);
    write(path.join(testDir, '.mcp.json'), JSON.stringify({
      mcpServers: {
        filesystem: { command: 'npx', args: ['@modelcontextprotocol/server-filesystem', '.'] }
      }
    }, null, 2));

    const report = auditAgentLifecycle({ rootDir: testDir });

    strictEqual(report.ok, true);
    ok(report.summary.riskScore <= 35, `expected controlled project risk <= 35, got ${report.summary.riskScore}`);
    ok(report.controls.identity, 'should detect identity controls');
    ok(report.controls.auditTrail, 'should detect audit trail controls');
    ok(report.controls.killSwitch, 'should detect kill switch controls');
    ok(report.recommendations.some((item) => item.includes('Re-run')));
  });

  it('reports a missing audit path as a hard failure', () => {
    const missingDir = path.join(testDir, 'does-not-exist');

    const report = auditAgentLifecycle({ rootDir: missingDir });

    strictEqual(report.ok, false);
    strictEqual(report.summary.filesScanned, 0);
    ok(report.findings.some((finding) => finding.id === 'audit_path_missing'));
    ok(report.recommendations.some((item) => item.includes('Fix the audit path')));
  });

  it('prints lifecycle audit JSON from the CLI', async () => {
    write(path.join(testDir, '.env'), 'ANTHROPIC_API_KEY=sk-ant-test\n');
    write(path.join(testDir, 'agent.js'), "await browser.open('https://example.com');");

    const cli = path.join(originalCwd, 'bin/clawmoat.js');
    const { stdout } = await execFileAsync('node', [cli, 'lifecycle', 'audit', '--path', testDir, '--format', 'json']);
    const report = JSON.parse(stdout);

    strictEqual(report.type, 'agent_lifecycle_audit');
    strictEqual(report.rootDir, testDir);
    ok(report.surfaces.includes('browser'));
    ok(report.findings.some((finding) => finding.id === 'credentials_without_health_checks'));
  });
});
