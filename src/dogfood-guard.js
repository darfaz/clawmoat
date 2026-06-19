const path = require('path');
const { auditAgentLifecycle } = require('./lifecycle-audit');
const { createSafetyReceipt, formatSafetyReceiptText } = require('./safety-receipt');

function createAgentGuardReport(opts = {}) {
  const agent = opts.agent || 'leo';
  const rootDir = path.resolve(opts.rootDir || process.cwd());
  const audit = auditAgentLifecycle({ rootDir });
  const receipt = createSafetyReceipt(audit, {
    sessionsProtected: opts.sessionsProtected ?? 1,
    toolCallsChecked: opts.toolCallsChecked ?? 0,
    riskyActionsBlocked: opts.riskyActionsBlocked ?? 0,
    secretsExposed: opts.secretsExposed ?? 0,
  });

  return {
    type: 'clawmoat_agent_guard_report',
    mode: 'dogfood',
    agent,
    rootDir,
    generatedAt: opts.generatedAt || new Date().toISOString(),
    dogfoodStatus: dogfoodStatusFor(receipt.score, audit),
    audit,
    receipt,
    guardrails: buildGuardrails(agent),
    proof: buildProof(agent, receipt),
    limitations: [
      'This is a local guard report, not a guarantee that the agent cannot make a mistake.',
      'It does not replace user approval for irreversible external actions.',
      'It is strongest when run before and after agent sessions and before trusting new MCP servers.',
    ],
  };
}

function dogfoodStatusFor(score, audit) {
  if (!audit.ok || score < 60) return 'active_guard_with_fixes_needed';
  if (score < 90) return 'active_guard_needs_attention';
  return 'active_guard_clean';
}

function buildGuardrails(agent) {
  return [
    `Scan inbound external documents before ${agent} summarizes or acts on them.`,
    `Scan outbound messages before ${agent} sends code, configs, logs, or project details externally.`,
    `Generate a safety receipt after meaningful ${agent} work sessions.`,
    `Review risky shell, filesystem, network, browser, GitHub, and messaging tool surfaces.`,
    'Re-run the guard before adding new MCP servers, credentials, scheduled jobs, or agent tools.',
  ];
}

function buildProof(agent, receipt) {
  return {
    claim: `ClawMoat is protecting ${agent} with a local guard report and safety receipt.`,
    receiptType: receipt.type,
    score: receipt.score,
    grade: receipt.grade,
    tagline: receipt.tagline,
  };
}

function formatAgentGuardReportText(report) {
  const lines = [];
  lines.push('🏰 ClawMoat Agent Guard');
  lines.push('');
  lines.push(`Agent: ${report.agent}`);
  lines.push(`Mode: ${report.mode}`);
  lines.push(`Path: ${report.rootDir}`);
  lines.push(`Dogfood status: ${report.dogfoodStatus}`);
  lines.push('');
  lines.push(formatSafetyReceiptText(report.receipt));
  lines.push('');
  lines.push('Guardrails now expected:');
  for (const guardrail of report.guardrails) lines.push(`  • ${guardrail}`);
  lines.push('');
  lines.push('Limitations:');
  for (const limitation of report.limitations) lines.push(`  • ${limitation}`);
  lines.push('');
  lines.push(`Proof claim: ${report.proof.claim}`);
  lines.push(`Next best fix: ${report.receipt.nextBestFix}`);
  return lines.join('\n');
}

module.exports = {
  createAgentGuardReport,
  formatAgentGuardReportText,
};
