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

const { auditAgentLifecycle, formatLifecycleAuditMarkdown } = require('../src/lifecycle-audit');

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

  it('detects common agent frameworks for better buyer-facing reports', () => {
    write(path.join(testDir, 'package.json'), JSON.stringify({
      name: 'agent-app',
      dependencies: {
        langchain: '^0.3.0',
        '@openai/agents': '^0.1.0',
        '@modelcontextprotocol/sdk': '^1.0.0'
      }
    }, null, 2));
    write(path.join(testDir, 'agent.js'), "import { AgentExecutor } from 'langchain/agents'; await fetch('https://api.example.com');");

    const report = auditAgentLifecycle({ rootDir: testDir });

    ok(report.frameworks.includes('langchain'), 'should detect LangChain');
    ok(report.frameworks.includes('openai_agents'), 'should detect OpenAI Agents');
    ok(report.frameworks.includes('mcp'), 'should detect MCP SDK/config usage');
    strictEqual(report.summary.frameworks, 3);
  });

  it('detects Python agent framework manifests without treating provider keys as frameworks', () => {
    write(path.join(testDir, 'requirements.txt'), 'langchain==0.3.1\ncrewai>=0.80\npyautogen~=0.2\n');
    write(path.join(testDir, '.env'), 'ANTHROPIC_API_KEY=sk-ant-test\n');

    const report = auditAgentLifecycle({ rootDir: testDir });

    ok(report.frameworks.includes('langchain'), 'should detect Python LangChain dependency');
    ok(report.frameworks.includes('crewai'), 'should detect Python CrewAI dependency');
    ok(report.frameworks.includes('autogen'), 'should detect Python AutoGen dependency');
    strictEqual(report.frameworks.includes('anthropic_claude'), false, 'provider credential alone is not a Claude framework');
  });

  it('ignores generated lifecycle reports so reruns are not self-poisoned', () => {
    write(path.join(testDir, 'agent.js'), "await tools.shell('git push origin main');");
    const first = auditAgentLifecycle({ rootDir: testDir });
    write(path.join(testDir, 'lifecycle-report.md'), formatLifecycleAuditMarkdown(first));

    const second = auditAgentLifecycle({ rootDir: testDir });

    strictEqual(second.controls.humanApproval, false);
    strictEqual(second.controls.auditTrail, false);
    strictEqual(second.ok, false);
    ok(second.findings.some((finding) => finding.id === 'write_tools_without_approval'));
  });

  it('formats a shareable markdown lifecycle report with checklist and CTA', () => {
    write(path.join(testDir, '.env'), 'ANTHROPIC_API_KEY=sk-ant-test\n');
    write(path.join(testDir, 'agent.js'), "await browser.open('https://example.com');");

    const report = auditAgentLifecycle({ rootDir: testDir });
    const markdown = formatLifecycleAuditMarkdown(report);

    ok(markdown.startsWith('# ClawMoat Agent Lifecycle Exposure Report'));
    ok(markdown.includes('| Control | Status |'));
    ok(markdown.includes('## Remediation checklist'));
    ok(markdown.includes('https://clawmoat.com/assessment/'));

    const escaped = formatLifecycleAuditMarkdown({ ...report, rootDir: path.join(testDir, 'odd`path') });
    ok(escaped.includes('odd\\`path'));
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

  it('writes markdown lifecycle audit reports to an output file from the CLI', async () => {
    write(path.join(testDir, 'package.json'), JSON.stringify({ name: 'agent-app', dependencies: { langchain: '^0.3.0' } }, null, 2));
    write(path.join(testDir, 'agent.js'), "await tools.shell('git push origin main');");
    const outFile = path.join(testDir, 'lifecycle-report.md');

    const cli = path.join(originalCwd, 'bin/clawmoat.js');
    const { stdout } = await execFileAsync('node', [cli, 'lifecycle', 'audit', '--path', testDir, '--format', 'markdown', '--output', outFile]);
    const markdown = fs.readFileSync(outFile, 'utf8');

    ok(stdout.includes('Wrote lifecycle audit report'));
    ok(markdown.includes('# ClawMoat Agent Lifecycle Exposure Report'));
    ok(markdown.includes('langchain'));
    ok(markdown.includes('write_tools_without_approval'));
  });
});
