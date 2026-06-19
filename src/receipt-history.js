const fs = require('fs');
const os = require('os');
const path = require('path');

function defaultReceiptHistoryPath() {
  const home = process.env.CLAWMOAT_HOME || path.join(os.homedir(), '.clawmoat');
  return path.join(home, 'receipts.jsonl');
}

function saveReceipt(receipt, opts = {}) {
  const historyFile = path.resolve(opts.historyFile || defaultReceiptHistoryPath());
  fs.mkdirSync(path.dirname(historyFile), { recursive: true });
  const entry = normalizeReceipt(receipt);
  fs.appendFileSync(historyFile, `${JSON.stringify(entry)}\n`);
  return { saved: true, historyFile, receipt: entry };
}

function normalizeReceipt(receipt) {
  return {
    ...receipt,
    generatedAt: receipt.generatedAt || new Date().toISOString(),
    metrics: {
      sessionsProtected: numberOrZero(receipt.metrics?.sessionsProtected),
      toolCallsChecked: numberOrZero(receipt.metrics?.toolCallsChecked),
      mcpServersReviewed: numberOrZero(receipt.metrics?.mcpServersReviewed),
      riskyActionsBlocked: numberOrZero(receipt.metrics?.riskyActionsBlocked),
      secretsExposed: numberOrZero(receipt.metrics?.secretsExposed),
    },
  };
}

function numberOrZero(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

function loadReceiptHistory(opts = {}) {
  const historyFile = path.resolve(opts.historyFile || defaultReceiptHistoryPath());
  if (!fs.existsSync(historyFile)) return [];
  const entries = fs.readFileSync(historyFile, 'utf8')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      try { return JSON.parse(line); } catch (_err) { return null; }
    })
    .filter((entry) => entry && entry.type === 'clawmoat_safety_receipt');
  return entries.sort((a, b) => new Date(b.generatedAt).getTime() - new Date(a.generatedAt).getTime());
}

function createWeeklySummary(receipts, opts = {}) {
  const now = new Date(opts.now || new Date().toISOString());
  const since = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const weeklyReceipts = receipts
    .filter((item) => {
      const ts = new Date(item.generatedAt).getTime();
      return Number.isFinite(ts) && ts >= since.getTime() && ts <= now.getTime();
    })
    .sort((a, b) => new Date(a.generatedAt).getTime() - new Date(b.generatedAt).getTime());

  const metrics = weeklyReceipts.reduce((acc, item) => {
    acc.sessionsProtected += numberOrZero(item.metrics?.sessionsProtected);
    acc.toolCallsChecked += numberOrZero(item.metrics?.toolCallsChecked);
    acc.mcpServersReviewed += numberOrZero(item.metrics?.mcpServersReviewed);
    acc.riskyActionsBlocked += numberOrZero(item.metrics?.riskyActionsBlocked);
    acc.secretsExposed += numberOrZero(item.metrics?.secretsExposed);
    return acc;
  }, {
    sessionsProtected: 0,
    toolCallsChecked: 0,
    mcpServersReviewed: 0,
    riskyActionsBlocked: 0,
    secretsExposed: 0,
  });

  const scores = weeklyReceipts.map((item) => Number(item.score)).filter(Number.isFinite);
  const start = scores.length ? scores[0] : null;
  const end = scores.length ? scores[scores.length - 1] : null;
  const average = scores.length ? Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length) : null;

  return {
    type: 'clawmoat_weekly_safety_summary',
    generatedAt: opts.generatedAt || new Date().toISOString(),
    window: { since: since.toISOString(), until: now.toISOString() },
    receipts: weeklyReceipts.length,
    score: {
      start,
      end,
      average,
      delta: start === null || end === null ? null : end - start,
    },
    metrics,
    topNextFix: pickTopNextFix(weeklyReceipts),
    streak: buildStreak(weeklyReceipts),
  };
}

function pickTopNextFix(receipts) {
  const fixes = receipts.map((item) => item.nextBestFix).filter(Boolean);
  return fixes[fixes.length - 1] || 'Run `clawmoat receipt --save` after each agent session to build a safety history.';
}

function buildStreak(receipts) {
  const cleanDays = new Set();
  for (const item of receipts) {
    if (numberOrZero(item.metrics?.secretsExposed) === 0) cleanDays.add(String(item.generatedAt).slice(0, 10));
  }
  return { cleanSecretDays: cleanDays.size };
}

function formatWeeklySummaryText(summary) {
  const lines = [];
  lines.push('🧾 Weekly ClawMoat safety summary');
  lines.push('');
  lines.push(`Receipts saved: ${summary.receipts}`);
  if (summary.score.start !== null) {
    lines.push(`Fresh workspace score: ${summary.score.start} → ${summary.score.end} (${summary.score.delta >= 0 ? '+' : ''}${summary.score.delta})`);
    lines.push(`Average score: ${summary.score.average}/100`);
  } else {
    lines.push('Fresh workspace score: no saved receipts yet');
  }
  lines.push('');
  lines.push('This week ClawMoat protected:');
  lines.push(`  ✓ ${summary.metrics.sessionsProtected} agent session${summary.metrics.sessionsProtected === 1 ? '' : 's'} protected`);
  lines.push(`  ✓ ${summary.metrics.toolCallsChecked} tool call${summary.metrics.toolCallsChecked === 1 ? '' : 's'} checked`);
  lines.push(`  ✓ ${summary.metrics.mcpServersReviewed} MCP surface${summary.metrics.mcpServersReviewed === 1 ? '' : 's'} reviewed`);
  lines.push(`  ✓ ${summary.metrics.riskyActionsBlocked} risky action${summary.metrics.riskyActionsBlocked === 1 ? '' : 's'} blocked`);
  lines.push(`  ✓ ${summary.metrics.secretsExposed} secret${summary.metrics.secretsExposed === 1 ? '' : 's'} exposed`);
  lines.push('');
  lines.push(`Clean-secret streak: ${summary.streak.cleanSecretDays} day${summary.streak.cleanSecretDays === 1 ? '' : 's'} with no exposed secrets in saved receipts`);
  lines.push(`Next best fix: ${summary.topNextFix}`);
  return lines.join('\n');
}

function exportAuditEvidence(opts = {}) {
  const historyFile = path.resolve(opts.historyFile || defaultReceiptHistoryPath());
  const outputFile = path.resolve(opts.outputFile || path.join(path.dirname(historyFile), 'audit-evidence.json'));
  const receipts = loadReceiptHistory({ historyFile });
  const latestReceiptAt = receipts.length ? receipts[0].generatedAt : undefined;
  const summary = createWeeklySummary(receipts, { ...opts, now: opts.now || latestReceiptAt });
  const evidence = {
    type: 'clawmoat_audit_evidence_pack',
    generatedAt: opts.generatedAt || new Date().toISOString(),
    team: opts.team || null,
    source: { historyFile },
    summary,
    receipts,
    note: 'Generated from local ClawMoat safety receipts. This is evidence of recurring checks, not a security guarantee.',
  };
  fs.mkdirSync(path.dirname(outputFile), { recursive: true });
  fs.writeFileSync(outputFile, JSON.stringify(evidence, null, 2));
  return { outputFile, evidence };
}

module.exports = {
  defaultReceiptHistoryPath,
  saveReceipt,
  loadReceiptHistory,
  createWeeklySummary,
  formatWeeklySummaryText,
  exportAuditEvidence,
};
