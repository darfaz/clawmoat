/**
 * Tests for ClawMoat safety receipts, the buyer-facing "fresh smell" loop.
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
const { createSafetyReceipt, formatSafetyReceiptText } = require('../src/safety-receipt');

function write(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

describe('safety receipt', () => {
  let testDir;
  let originalCwd;

  beforeEach(() => {
    originalCwd = process.cwd();
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'clawmoat-receipt-'));
    process.chdir(testDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it('turns lifecycle audit output into a positive daily value receipt', () => {
    write(path.join(testDir, 'clawmoat.yml'), `
identity:
  agent_id: receipt-demo
approvals:
  required_for:
    - shell
logging:
  audit_trail: true
credentials:
  health_check: true
kill_switch:
  enabled: true
policies:
  tools:
    shell: review
`);
    write(path.join(testDir, '.mcp.json'), JSON.stringify({
      mcpServers: {
        filesystem: { command: 'npx', args: ['@modelcontextprotocol/server-filesystem', '.'] }
      }
    }, null, 2));
    write(path.join(testDir, 'agent.js'), "await tools.shell('npm test'); await fetch('https://api.example.com');");

    const audit = auditAgentLifecycle({ rootDir: testDir });
    const receipt = createSafetyReceipt(audit, {
      sessionsProtected: 4,
      toolCallsChecked: 18,
      riskyActionsBlocked: 1,
      secretsExposed: 0,
    });

    strictEqual(receipt.tagline, 'Seatbelt on. Your agent workspace is clean.');
    strictEqual(receipt.score, 100 - audit.summary.riskScore);
    strictEqual(receipt.metrics.sessionsProtected, 4);
    strictEqual(receipt.metrics.toolCallsChecked, 18);
    strictEqual(receipt.metrics.riskyActionsBlocked, 1);
    strictEqual(receipt.metrics.secretsExposed, 0);
    ok(receipt.wins.some((win) => win.includes('MCP')));
    ok(receipt.wins.some((win) => win.includes('audit trail')));
    ok(receipt.nearMisses.some((miss) => miss.includes('1 risky action')));
  });

  it('formats a receipt that gives the user satisfaction and one next fix', () => {
    write(path.join(testDir, '.env'), 'ANTHROPIC_API_KEY=sk-ant-test\n');
    write(path.join(testDir, '.mcp.json'), JSON.stringify({
      mcpServers: {
        shell: { command: 'node', args: ['shell-server.js'] }
      }
    }, null, 2));
    write(path.join(testDir, 'agent.js'), "await tools.shell('git push origin main');");

    const receipt = createSafetyReceipt(auditAgentLifecycle({ rootDir: testDir }), {
      sessionsProtected: 2,
      toolCallsChecked: 9,
      riskyActionsBlocked: 0,
      secretsExposed: 0,
    });
    const text = formatSafetyReceiptText(receipt);

    ok(text.includes('Seatbelt on'));
    ok(text.includes('Fresh workspace score'));
    ok(text.includes('2 agent sessions protected'));
    ok(text.includes('9 tool calls checked'));
    ok(text.includes('0 secrets exposed'));
    ok(text.includes('Next best fix'));
  });

  it('prints a safety receipt from the CLI', async () => {
    write(path.join(testDir, '.env'), 'OPENAI_API_KEY=sk-test\n');
    write(path.join(testDir, 'agent.js'), "await browser.open('https://example.com');");

    const cli = path.join(originalCwd, 'bin/clawmoat.js');
    const { stdout } = await execFileAsync('node', [cli, 'receipt', '--path', testDir, '--sessions', '3', '--tool-calls', '12', '--blocked', '1']);

    ok(stdout.includes('Seatbelt on'));
    ok(stdout.includes('3 agent sessions protected'));
    ok(stdout.includes('12 tool calls checked'));
    ok(stdout.includes('1 risky action blocked'));
  });
});
