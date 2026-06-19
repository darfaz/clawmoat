/**
 * Tests for recurring receipt history, weekly summaries, and audit evidence exports.
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const { strictEqual, ok } = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const {
  saveReceipt,
  loadReceiptHistory,
  createWeeklySummary,
  formatWeeklySummaryText,
  exportAuditEvidence,
} = require('../src/receipt-history');

function receipt(overrides = {}) {
  return {
    type: 'clawmoat_safety_receipt',
    generatedAt: overrides.generatedAt || '2026-06-10T12:00:00.000Z',
    path: overrides.path || '/repo',
    score: overrides.score ?? 91,
    grade: overrides.grade || 'fresh',
    tagline: overrides.tagline || 'Seatbelt on. Your agent workspace is clean.',
    metrics: {
      sessionsProtected: overrides.sessionsProtected ?? 1,
      toolCallsChecked: overrides.toolCallsChecked ?? 4,
      mcpServersReviewed: overrides.mcpServersReviewed ?? 1,
      riskyActionsBlocked: overrides.riskyActionsBlocked ?? 0,
      secretsExposed: overrides.secretsExposed ?? 0,
    },
    wins: overrides.wins || ['No exposed secrets reported in this receipt.'],
    nearMisses: overrides.nearMisses || ['No near-miss detected in this receipt.'],
    nextBestFix: overrides.nextBestFix || 'Keep scanning before adding new tools.',
  };
}

describe('receipt history and recurring proof', () => {
  let testDir;
  let originalCwd;
  let historyFile;

  beforeEach(() => {
    originalCwd = process.cwd();
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'clawmoat-history-'));
    process.chdir(testDir);
    historyFile = path.join(testDir, 'receipts.jsonl');
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it('saves receipts as append-only JSONL history and reloads newest first', () => {
    const first = saveReceipt(receipt({ generatedAt: '2026-06-10T12:00:00.000Z', score: 87 }), { historyFile });
    const second = saveReceipt(receipt({ generatedAt: '2026-06-11T12:00:00.000Z', score: 94 }), { historyFile });

    strictEqual(first.historyFile, historyFile);
    strictEqual(second.saved, true);
    const entries = loadReceiptHistory({ historyFile });

    strictEqual(entries.length, 2);
    strictEqual(entries[0].score, 94);
    strictEqual(entries[1].score, 87);
  });

  it('creates a weekly summary that turns saved receipts into recurring value evidence', () => {
    const receipts = [
      receipt({ generatedAt: '2026-06-10T12:00:00.000Z', score: 80, sessionsProtected: 2, toolCallsChecked: 8, riskyActionsBlocked: 0 }),
      receipt({ generatedAt: '2026-06-11T12:00:00.000Z', score: 90, sessionsProtected: 3, toolCallsChecked: 11, riskyActionsBlocked: 1 }),
      receipt({ generatedAt: '2026-06-12T12:00:00.000Z', score: 96, sessionsProtected: 1, toolCallsChecked: 5, riskyActionsBlocked: 2 }),
    ];

    const summary = createWeeklySummary(receipts, { now: '2026-06-17T00:00:00.000Z' });
    const text = formatWeeklySummaryText(summary);

    strictEqual(summary.type, 'clawmoat_weekly_safety_summary');
    strictEqual(summary.receipts, 3);
    strictEqual(summary.metrics.sessionsProtected, 6);
    strictEqual(summary.metrics.toolCallsChecked, 24);
    strictEqual(summary.metrics.riskyActionsBlocked, 3);
    strictEqual(summary.score.start, 80);
    strictEqual(summary.score.end, 96);
    strictEqual(summary.score.delta, 16);
    ok(text.includes('Weekly ClawMoat safety summary'));
    ok(text.includes('6 agent sessions protected'));
    ok(text.includes('3 risky actions blocked'));
    ok(text.includes('80 → 96'));
  });

  it('exports an audit evidence pack from saved receipts', () => {
    saveReceipt(receipt({ generatedAt: '2026-06-10T12:00:00.000Z', score: 88 }), { historyFile });
    saveReceipt(receipt({ generatedAt: '2026-06-11T12:00:00.000Z', score: 93, riskyActionsBlocked: 1 }), { historyFile });
    const outputFile = path.join(testDir, 'evidence.json');

    const result = exportAuditEvidence({ historyFile, outputFile, team: 'demo-team' });
    const exported = JSON.parse(fs.readFileSync(outputFile, 'utf8'));

    strictEqual(result.outputFile, outputFile);
    strictEqual(exported.type, 'clawmoat_audit_evidence_pack');
    strictEqual(exported.team, 'demo-team');
    strictEqual(exported.summary.receipts, 2);
    strictEqual(exported.summary.metrics.riskyActionsBlocked, 1);
    ok(Array.isArray(exported.receipts));
  });

  it('saves a receipt and prints weekly summary from the CLI', async () => {
    fs.writeFileSync(path.join(testDir, 'agent.js'), "await tools.shell('npm test');");
    const cli = path.join(originalCwd, 'bin/clawmoat.js');

    const saved = await execFileAsync('node', [cli, 'receipt', '--path', testDir, '--save', '--history-file', historyFile, '--sessions', '2', '--tool-calls', '7']);
    ok(saved.stdout.includes('Saved safety receipt'));

    const weekly = await execFileAsync('node', [cli, 'receipts', 'weekly', '--history-file', historyFile]);
    ok(weekly.stdout.includes('Weekly ClawMoat safety summary'));
    ok(weekly.stdout.includes('2 agent sessions protected'));
  });
});
