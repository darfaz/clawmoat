const DEFAULT_TAGLINE = 'Seatbelt on. Your agent workspace is clean.';

function createSafetyReceipt(auditReport, opts = {}) {
  const riskScore = auditReport?.summary?.riskScore || 0;
  const score = Math.max(0, Math.min(100, 100 - riskScore));
  const metrics = {
    sessionsProtected: numberOrZero(opts.sessionsProtected),
    toolCallsChecked: numberOrZero(opts.toolCallsChecked),
    mcpServersReviewed: numberOrZero(opts.mcpServersReviewed ?? countMcpSurfaces(auditReport)),
    riskyActionsBlocked: numberOrZero(opts.riskyActionsBlocked),
    secretsExposed: numberOrZero(opts.secretsExposed),
  };

  return {
    type: 'clawmoat_safety_receipt',
    tagline: taglineForScore(score),
    score,
    grade: gradeScore(score),
    generatedAt: opts.generatedAt || new Date().toISOString(),
    path: auditReport?.rootDir || process.cwd(),
    metrics,
    wins: buildWins(auditReport, metrics),
    nearMisses: buildNearMisses(auditReport, metrics),
    nextBestFix: buildNextBestFix(auditReport),
  };
}

function numberOrZero(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

function countMcpSurfaces(auditReport) {
  return auditReport?.surfaces?.includes('mcp') || auditReport?.frameworks?.includes('mcp') ? 1 : 0;
}

function taglineForScore(score) {
  if (score >= 80) return DEFAULT_TAGLINE;
  if (score >= 60) return 'Seatbelt on, with fixes needed. Your agent workspace is partly clean.';
  return 'Seatbelt on, but this workspace is risky. Fix the exposed agent paths before you trust it.';
}

function gradeScore(score) {
  if (score >= 90) return 'fresh';
  if (score >= 80) return 'clean';
  if (score >= 60) return 'needs_attention';
  return 'risky';
}

function buildWins(auditReport, metrics) {
  const wins = [];
  const controls = auditReport?.controls || {};
  if (controls.toolPolicy) wins.push('Tool policy detected, risky agent actions have a defined gate.');
  if (controls.humanApproval) wins.push('Human approval detected for high-impact agent actions.');
  if (controls.auditTrail) wins.push('Agent audit trail detected, you have a receipt for what happened.');
  if (controls.credentialHealth) wins.push('Credential health control detected, secret risk is easier to manage.');
  if (controls.killSwitch) wins.push('Kill switch detected, runaway agent behavior has a stop path.');
  if (controls.mcpPolicy || auditReport?.surfaces?.includes('mcp')) wins.push('MCP surface reviewed before trusting connected tools.');
  if (metrics.secretsExposed === 0) wins.push('No exposed secrets reported in this receipt.');
  if (wins.length === 0) wins.push('Workspace inspected. ClawMoat produced a concrete next fix instead of vague security advice.');
  return Array.from(new Set(wins));
}

function buildNearMisses(auditReport, metrics) {
  const misses = [];
  if (metrics.riskyActionsBlocked > 0) {
    misses.push(`${metrics.riskyActionsBlocked} risky action${metrics.riskyActionsBlocked === 1 ? '' : 's'} blocked before it became an incident.`);
  }
  if (metrics.secretsExposed > 0) {
    misses.push(`${metrics.secretsExposed} secret exposure${metrics.secretsExposed === 1 ? '' : 's'} detected. Rotate affected credentials.`);
  }
  const criticalFindings = (auditReport?.findings || []).filter((finding) => finding.severity === 'critical');
  if (criticalFindings.length > 0) {
    misses.push(`${criticalFindings.length} critical agent exposure${criticalFindings.length === 1 ? '' : 's'} found before rollout.`);
  }
  if (misses.length === 0) misses.push('No near-miss detected in this receipt. Keep scanning before adding new tools or MCP servers.');
  return misses;
}

function buildNextBestFix(auditReport) {
  const firstCritical = (auditReport?.findings || []).find((finding) => finding.severity === 'critical');
  if (firstCritical) return firstCritical.recommendation;
  const firstFinding = (auditReport?.findings || [])[0];
  if (firstFinding) return firstFinding.recommendation;
  const firstRecommendation = (auditReport?.recommendations || [])[0];
  return firstRecommendation || 'Re-run this receipt after every new tool, MCP server, credential, or scheduled agent job.';
}

function formatSafetyReceiptText(receipt) {
  const lines = [];
  lines.push(`🟢 ${receipt.tagline}`);
  lines.push('');
  lines.push(`Fresh workspace score: ${receipt.score}/100 (${receipt.grade})`);
  lines.push(`Path: ${receipt.path}`);
  lines.push('');
  lines.push('Today ClawMoat protected:');
  lines.push(`  ✓ ${receipt.metrics.sessionsProtected} agent session${receipt.metrics.sessionsProtected === 1 ? '' : 's'} protected`);
  lines.push(`  ✓ ${receipt.metrics.toolCallsChecked} tool call${receipt.metrics.toolCallsChecked === 1 ? '' : 's'} checked`);
  lines.push(`  ✓ ${receipt.metrics.mcpServersReviewed} MCP surface${receipt.metrics.mcpServersReviewed === 1 ? '' : 's'} reviewed`);
  lines.push(`  ✓ ${receipt.metrics.riskyActionsBlocked} risky action${receipt.metrics.riskyActionsBlocked === 1 ? '' : 's'} blocked`);
  lines.push(`  ✓ ${receipt.metrics.secretsExposed} secret${receipt.metrics.secretsExposed === 1 ? '' : 's'} exposed`);
  lines.push('');
  lines.push('Why this mattered:');
  for (const win of receipt.wins.slice(0, 5)) lines.push(`  • ${win}`);
  lines.push('');
  lines.push('Near-miss log:');
  for (const nearMiss of receipt.nearMisses.slice(0, 3)) lines.push(`  • ${nearMiss}`);
  lines.push('');
  lines.push(`Next best fix: ${receipt.nextBestFix}`);
  return lines.join('\n');
}

module.exports = {
  createSafetyReceipt,
  formatSafetyReceiptText,
};
