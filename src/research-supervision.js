const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

function defaultResearchLedgerPath() {
  const home = process.env.CLAWMOAT_HOME || path.join(os.homedir(), '.clawmoat');
  return path.join(home, 'research-supervision.jsonl');
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function hashLedgerEntry(entry) {
  const copy = { ...entry };
  delete copy.entryHash;
  return sha256(stableStringify(copy));
}

function safeDate(value) {
  const parsed = new Date(value || new Date().toISOString());
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : new Date().toISOString();
}

function summarizeRequiredApprovals(report) {
  const approvals = ['supervisor'];
  if ((report.summary?.critical || 0) > 0 || report.summary?.disposition === 'compliance_hold') approvals.push('compliance');
  return approvals;
}

function createResearchReviewPacket(preflightReport, opts = {}) {
  const report = preflightReport || {};
  const generatedAt = safeDate(opts.generatedAt || report.generatedAt);
  const baseId = [
    report.receipt?.artifactHash || 'draft',
    report.receipt?.modelHash || 'model',
    generatedAt,
    opts.submittedBy || report.analyst || 'analyst',
  ].join('|');
  const summary = {
    totalFindings: report.summary?.totalFindings || 0,
    critical: report.summary?.critical || 0,
    high: report.summary?.high || 0,
    medium: report.summary?.medium || 0,
    low: report.summary?.low || 0,
    disposition: report.summary?.disposition || 'unknown',
  };
  return {
    type: 'clawmoat_research_review_packet',
    packetId: opts.packetId || `research-${sha256(baseId).slice(0, 16)}`,
    generatedAt,
    status: opts.status || 'pending_supervisor_review',
    workflow: report.workflow || 'equity research preflight',
    analyst: report.analyst || opts.submittedBy || 'unspecified',
    submittedBy: opts.submittedBy || report.analyst || 'unspecified',
    coverageGroup: opts.coverageGroup || null,
    clientDistribution: opts.clientDistribution || 'not-specified',
    modelProvider: report.modelProvider || 'unspecified',
    policyPack: report.policyPack || report.receipt?.policyPack || 'research-preflight-default-v1',
    summary,
    artifacts: {
      draftHash: report.receipt?.artifactHash || null,
      modelHash: report.receipt?.modelHash || null,
      restrictedListHash: report.receipt?.restrictedListHash || null,
      sourceHashes: report.receipt?.sourceHashes || {},
    },
    controls: report.receipt?.controls || [],
    controlMatrix: report.receipt?.controlMatrix || [],
    retentionClass: report.receipt?.retention?.retentionClass || 'research-supervision-audit-packet',
    requiredApprovals: opts.requiredApprovals || summarizeRequiredApprovals(report),
    findingTypes: Array.from(new Set((report.findings || []).map((finding) => finding.type))).sort(),
  };
}

function parseLedgerFile(ledgerFile) {
  if (!fs.existsSync(ledgerFile)) return [];
  return fs.readFileSync(ledgerFile, 'utf8')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function loadResearchLedger(opts = {}) {
  const ledgerFile = path.resolve(opts.ledgerFile || defaultResearchLedgerPath());
  const entries = parseLedgerFile(ledgerFile);
  return {
    type: 'clawmoat_research_supervision_ledger',
    ledgerFile,
    entries,
    verification: verifyResearchLedger(entries),
  };
}

function appendResearchLedgerEntry(entry, opts = {}) {
  const ledgerFile = path.resolve(opts.ledgerFile || defaultResearchLedgerPath());
  fs.mkdirSync(path.dirname(ledgerFile), { recursive: true });
  const existing = parseLedgerFile(ledgerFile);
  const previous = existing[existing.length - 1] || null;
  const normalized = {
    ...entry,
    generatedAt: safeDate(entry.generatedAt),
    sequence: existing.length + 1,
    previousHash: previous ? previous.entryHash : null,
  };
  normalized.entryHash = hashLedgerEntry(normalized);
  fs.appendFileSync(ledgerFile, `${JSON.stringify(normalized)}\n`);
  return { saved: true, ledgerFile, entry: normalized };
}

function latestPacketFor(entries, packetId) {
  return entries.filter((entry) => entry.packetId === packetId && entry.type === 'clawmoat_research_review_packet').pop() || null;
}

function approveResearchPacket(packetId, opts = {}) {
  const ledgerFile = path.resolve(opts.ledgerFile || defaultResearchLedgerPath());
  const entries = parseLedgerFile(ledgerFile);
  const currentVerification = verifyResearchLedger(entries);
  if (!currentVerification.valid) throw new Error('Cannot approve research packet because the supervision ledger is invalid');
  const packet = latestPacketFor(entries, packetId);
  if (!packet) throw new Error(`Research review packet not found: ${packetId}`);
  const reviewer = opts.reviewer || 'unspecified';
  if (String(reviewer).trim().toLowerCase() === String(packet.analyst || packet.submittedBy).trim().toLowerCase()) {
    throw new Error('Analyst cannot approve their own research');
  }
  const decision = opts.decision || 'approve';
  const approval = {
    type: 'clawmoat_research_approval',
    packetId,
    generatedAt: safeDate(opts.generatedAt),
    reviewer,
    role: opts.role || 'supervisor',
    decision,
    rationale: opts.rationale || '',
    conditions: opts.conditions || [],
    analyst: packet.analyst,
    policyPack: packet.policyPack,
    sourcePacketHash: packet.entryHash,
    status: decision === 'reject' || decision === 'deny' ? 'rejected' : 'approved_with_supervision',
  };
  return appendResearchLedgerEntry(approval, { ledgerFile });
}

function verifyResearchLedger(entries = []) {
  const failures = [];
  let previousHash = null;
  entries.forEach((entry, index) => {
    const expectedSequence = index + 1;
    if (entry.sequence !== expectedSequence) failures.push({ index, sequence: entry.sequence, reason: 'sequence_mismatch' });
    if ((entry.previousHash || null) !== previousHash) failures.push({ index, sequence: entry.sequence, reason: 'previous_hash_mismatch' });
    const expectedHash = hashLedgerEntry(entry);
    if (entry.entryHash !== expectedHash) failures.push({ index, sequence: entry.sequence, reason: 'entry_hash_mismatch' });
    previousHash = entry.entryHash || null;
  });
  return {
    valid: failures.length === 0,
    entries: entries.length,
    headHash: entries.length ? entries[entries.length - 1].entryHash : null,
    failures,
  };
}

function formatResearchLedgerText(ledger) {
  const lines = [];
  lines.push('ClawMoat Research Supervision Ledger');
  lines.push(`Ledger: ${ledger.ledgerFile}`);
  lines.push(`Entries: ${ledger.verification.entries}`);
  lines.push(`Verification: ${ledger.verification.valid ? 'valid' : 'INVALID'}`);
  if (ledger.verification.headHash) lines.push(`Head hash: ${ledger.verification.headHash}`);
  if (!ledger.verification.valid) {
    lines.push('Failures:');
    for (const failure of ledger.verification.failures) lines.push(`- entry ${failure.sequence || failure.index + 1}: ${failure.reason}`);
  }
  return lines.join('\n');
}

module.exports = {
  defaultResearchLedgerPath,
  createResearchReviewPacket,
  appendResearchLedgerEntry,
  approveResearchPacket,
  loadResearchLedger,
  verifyResearchLedger,
  formatResearchLedgerText,
  hashLedgerEntry,
};
