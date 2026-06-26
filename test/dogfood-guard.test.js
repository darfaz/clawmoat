/**
 * Tests for ClawMoat dogfooding itself around Leo/Hermes agent work.
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const { strictEqual, ok } = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const { createAgentGuardReport, formatAgentGuardReportText } = require('../src/dogfood-guard');

function write(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

describe('dogfood agent guard', () => {
  let testDir;
  let originalCwd;

  beforeEach(() => {
    originalCwd = process.cwd();
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'clawmoat-dogfood-'));
    process.chdir(testDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it('creates a Leo guard report from a Hermes workspace audit', () => {
    write(path.join(testDir, 'clawmoat.yml'), `
identity:
  agent_id: leo
approvals:
  required_for:
    - shell
    - send_message
logging:
  audit_trail: true
credentials:
  health_check: true
kill_switch:
  enabled: true
policies:
  tools:
    shell: review
    filesystem: read-only
    send_message: review
`);
    write(path.join(testDir, 'AGENTS.md'), 'Hermes agent uses terminal tools, filesystem reads, browser tools, and Telegram send_message.');
    write(path.join(testDir, '.mcp.json'), JSON.stringify({
      mcpServers: {
        filesystem: { command: 'npx', args: ['@modelcontextprotocol/server-filesystem', '.'] }
      }
    }, null, 2));

    const report = createAgentGuardReport({ agent: 'leo', rootDir: testDir, sessionsProtected: 1, toolCallsChecked: 4 });

    strictEqual(report.type, 'clawmoat_agent_guard_report');
    strictEqual(report.agent, 'leo');
    strictEqual(report.mode, 'dogfood');
    strictEqual(report.receipt.metrics.sessionsProtected, 1);
    strictEqual(report.receipt.metrics.toolCallsChecked, 4);
    ok(report.guardrails.some((item) => item.includes('Scan inbound')));
    ok(report.guardrails.some((item) => item.includes('Scan outbound')));
    ok(report.proof.claim.includes('ClawMoat is protecting leo'));
  });

  it('formats a public dogfood proof without pretending protection is perfect', () => {
    write(path.join(testDir, 'agent.js'), "await tools.shell('git push origin main'); await fetch('https://example.com');");

    const report = createAgentGuardReport({ agent: 'leo', rootDir: testDir });
    const text = formatAgentGuardReportText(report);

    ok(text.includes('ClawMoat Agent Guard'));
    ok(text.includes('Agent: leo'));
    ok(text.includes('Seatbelt on'));
    ok(text.includes('Dogfood status'));
    ok(text.includes('not a guarantee'));
    ok(text.includes('Next best fix'));
  });

  it('prints and writes a Leo dogfood report from the CLI', async () => {
    write(path.join(testDir, 'agent.js'), "await browser.open('https://example.com');");
    const outFile = path.join(testDir, 'leo-guard.json');
    const cli = path.join(originalCwd, 'bin/clawmoat.js');

    const { stdout } = await execFileAsync('node', [cli, 'dogfood', 'leo', '--path', testDir, '--format', 'json', '--output', outFile]);
    const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));

    ok(stdout.includes('Wrote agent guard report'));
    strictEqual(report.type, 'clawmoat_agent_guard_report');
    strictEqual(report.agent, 'leo');
    strictEqual(report.rootDir, testDir);
  });
});
