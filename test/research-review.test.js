'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  ResearchReviewGuard,
  scanResearchDraft,
  CONTROL_MATRIX,
  buildArchiveManifest,
  buildSupervisorAttestationPacket,
  buildSupervisionQueue,
} = require('../src/finance/research-review');
const ClawMoat = require('../src');

test('blocks draft that appears to use MNPI and missing release controls', () => {
  const draft = `
    Upgrade ACME to Buy, PT $58.
    We know from a wall-crossed conversation that unannounced earnings will beat consensus.
    Source: internal channel notes.
  `;

  const result = scanResearchDraft(draft);

  assert.equal(result.action, 'block');
  assert.equal(result.severity, 'critical');
  assert.ok(result.findings.some(f => f.subtype === 'possible_mnpi'));
  assert.ok(result.findings.some(f => f.subtype === 'unsupported_price_target'));
  assert.ok(result.findings.some(f => f.subtype === 'missing_reg_ac_certification'));
  assert.match(result.evidence.draftHash, /^[a-f0-9]{64}$/);
});

test('allows sourced draft with rating, supported target, and certification', () => {
  const draft = `
    Rating: Outperform. Price target $42, based on 14x FY27 EPS and peer P/E multiples.
    Sources: company 10-K, Q1 10-Q, earnings transcript, and FactSet consensus.
    Analyst certification: I certify that the views expressed accurately reflect my personal views and
    that my compensation was not related to the specific recommendation.
  `;

  const result = scanResearchDraft(draft);

  assert.equal(result.safe, true);
  assert.equal(result.action, 'allow');
  assert.deepEqual(result.findings, []);
  assert.equal(result.evidence.checks.hasRegAC, true);
});

test('ResearchReviewGuard records exportable pre-publication evidence', () => {
  const guard = new ResearchReviewGuard();

  const blocked = guard.reviewDraft('Sell XYZ. Confidential deal under NDA will collapse.', {
    ticker: 'XYZ',
    analyst: 'analyst-17',
    model: 'equity-research-agent',
  });
  const attestation = guard.recordDisposition(blocked.reviewId, {
    decision: 'rejected',
    supervisor: 'supervisor-3',
    rationale: 'Draft includes client-confidential deal information and cannot be published.',
    attestedAt: '2026-06-20T12:00:00.000Z',
  });
  const evidence = guard.exportEvidence({ attestation: { generatedAt: '2026-06-20T12:05:00.000Z' } });

  assert.equal(blocked.action, 'block');
  assert.equal(attestation.decision, 'rejected');
  assert.match(attestation.digest, /^[a-f0-9]{64}$/);
  assert.equal(evidence.summary.totalReviews, 1);
  assert.equal(evidence.summary.blocked, 1);
  assert.equal(evidence.supervisorAttestationPacket.summary.attested, 1);
  assert.equal(evidence.supervisorAttestationPacket.summary.rejected, 1);
  assert.equal(evidence.supervisionQueue.summary.pending, 0);
  assert.match(evidence.supervisionQueue.queueDigest, /^[a-f0-9]{64}$/);
  assert.match(evidence.supervisorAttestationPacket.packetDigest, /^[a-f0-9]{64}$/);
  assert.ok(evidence.controlMatrix.some(control => control.id === 'MNPI-01'));
  assert.ok(evidence.controlMatrix.some(control => control.id === 'SUP-01'));
  assert.ok(evidence.archiveManifest);
  assert.equal(evidence.archiveManifest.format, 'equity_research_retention_archive_manifest');
  assert.equal(evidence.archiveManifest.summary.totalEntries, 1);
  assert.equal(evidence.archiveManifest.entries[0].disposition, 'rejected');
  assert.match(evidence.archiveManifest.entries[0].dispositionDigest, /^[a-f0-9]{64}$/);
  assert.match(evidence.archiveManifest.entries[0].recordDigest, /^[a-f0-9]{64}$/);
  assert.match(evidence.archiveManifest.entries[0].chainDigest, /^[a-f0-9]{64}$/);
  assert.ok(CONTROL_MATRIX.some(control => control.id === 'REGAC-01'));
});

test('buildArchiveManifest creates deterministic digest chain for retention exports', () => {
  const reviews = [
    {
      reviewId: 'review-1',
      timestamp: 1781820000000,
      metadata: { ticker: 'ACME', analyst: 'analyst-17' },
      action: 'block',
      severity: 'critical',
      findings: [{ subtype: 'possible_mnpi', severity: 'critical', control: 'MNPI-01' }],
      evidence: { draftHash: 'a'.repeat(64) },
    },
    {
      reviewId: 'review-2',
      timestamp: 1781820060000,
      metadata: { ticker: 'BETA', analyst: 'analyst-22' },
      action: 'allow',
      severity: null,
      findings: [],
      evidence: { draftHash: 'b'.repeat(64) },
    },
  ];

  const manifest = buildArchiveManifest(reviews, {
    generatedAt: '2026-06-19T12:00:00.000Z',
    firmId: 'demo-bank',
    retentionYears: 6,
  });

  assert.equal(manifest.firmId, 'demo-bank');
  assert.equal(manifest.retentionPolicy.archiveMode, 'export_manifest_for_worm_or_sec_17a4_store');
  assert.equal(manifest.summary.blocked, 1);
  assert.equal(manifest.entries[0].previousDigest, null);
  assert.equal(manifest.entries[1].previousDigest, manifest.entries[0].chainDigest);
  assert.match(manifest.archiveDigest, /^[a-f0-9]{64}$/);
});

test('buildSupervisorAttestationPacket separates attested and pending supervisory decisions', () => {
  const reviews = [
    {
      reviewId: 'review-1',
      timestamp: 1781820000000,
      metadata: { ticker: 'ACME', analyst: 'analyst-17' },
      action: 'review',
      severity: 'high',
      findings: [{ subtype: 'unsupported_price_target', severity: 'high', control: 'PT-01', action: 'review' }],
      evidence: { draftHash: 'a'.repeat(64) },
      disposition: {
        format: 'equity_research_supervisor_disposition_attestation',
        reviewId: 'review-1',
        draftHash: 'a'.repeat(64),
        decision: 'approved_with_changes',
        supervisor: 'supervisor-3',
        rationale: 'Valuation table was added before publication.',
        attestedAt: '2026-06-20T12:00:00.000Z',
        requiredForRelease: true,
        controlIds: ['SUP-01', 'PT-01'],
        findingSummary: [{ subtype: 'unsupported_price_target', severity: 'high', control: 'PT-01', action: 'review' }],
        digest: 'c'.repeat(64),
      },
    },
    {
      reviewId: 'review-2',
      timestamp: 1781820060000,
      metadata: { ticker: 'BETA', analyst: 'analyst-22' },
      action: 'block',
      severity: 'critical',
      findings: [{ subtype: 'possible_mnpi', severity: 'critical', control: 'MNPI-01', action: 'block' }],
      evidence: { draftHash: 'b'.repeat(64) },
    },
  ];

  const packet = buildSupervisorAttestationPacket(reviews, {
    generatedAt: '2026-06-20T12:10:00.000Z',
  });

  assert.equal(packet.format, 'equity_research_supervisor_attestation_packet');
  assert.equal(packet.summary.attested, 1);
  assert.equal(packet.summary.pending, 1);
  assert.equal(packet.pending[0].reviewId, 'review-2');
  assert.deepEqual(packet.pending[0].requiredControls, ['SUP-01', 'MNPI-01']);
  assert.match(packet.packetDigest, /^[a-f0-9]{64}$/);
});

test('buildSupervisionQueue prioritizes overdue critical reviews for escalation', () => {
  const reviews = [
    {
      reviewId: 'review-critical',
      timestamp: Date.parse('2026-06-20T08:00:00.000Z'),
      metadata: { ticker: 'ACME', analyst: 'analyst-17', model: 'equity-research-agent' },
      action: 'block',
      severity: 'critical',
      findings: [{ subtype: 'possible_mnpi', severity: 'critical', control: 'MNPI-01', action: 'block' }],
      evidence: { draftHash: 'a'.repeat(64) },
    },
    {
      reviewId: 'review-high',
      timestamp: Date.parse('2026-06-20T11:00:00.000Z'),
      metadata: { ticker: 'BETA', analyst: 'analyst-22', model: 'equity-research-agent' },
      action: 'review',
      severity: 'high',
      findings: [{ subtype: 'unsupported_price_target', severity: 'high', control: 'PT-01', action: 'review' }],
      evidence: { draftHash: 'b'.repeat(64) },
    },
    {
      reviewId: 'review-approved',
      timestamp: Date.parse('2026-06-20T09:00:00.000Z'),
      metadata: { ticker: 'CALM', analyst: 'analyst-31' },
      action: 'review',
      severity: 'high',
      findings: [{ subtype: 'missing_reg_ac_certification', severity: 'high', control: 'REGAC-01', action: 'review' }],
      evidence: { draftHash: 'c'.repeat(64) },
      disposition: { decision: 'approved_with_changes', digest: 'd'.repeat(64) },
    },
  ];

  const queue = buildSupervisionQueue(reviews, {
    generatedAt: '2026-06-20T13:30:00.000Z',
    now: '2026-06-20T13:30:00.000Z',
  });

  assert.equal(queue.format, 'equity_research_supervision_queue');
  assert.equal(queue.summary.pending, 2);
  assert.equal(queue.summary.breached, 1);
  assert.equal(queue.summary.critical, 1);
  assert.equal(queue.queue[0].reviewId, 'review-critical');
  assert.equal(queue.queue[0].status, 'breached');
  assert.equal(queue.queue[0].dueAt, '2026-06-20T12:00:00.000Z');
  assert.equal(queue.queue[0].ageHours, 5.5);
  assert.equal(queue.queue[0].dueInHours, -1.5);
  assert.equal(queue.queue[0].recommendedAction, 'escalate_to_compliance_before_release');
  assert.deepEqual(queue.queue[0].requiredControls, ['SUP-01', 'SUP-02', 'MNPI-01']);
  assert.equal(queue.queue[1].status, 'due_within_24h');
  assert.match(queue.queueDigest, /^[a-f0-9]{64}$/);
});

test('top-level package exports ResearchReviewGuard', () => {
  assert.equal(typeof ClawMoat.ResearchReviewGuard, 'function');
  assert.equal(typeof ClawMoat.scanResearchDraft, 'function');
  assert.equal(typeof ClawMoat.buildResearchArchiveManifest, 'function');
  assert.equal(typeof ClawMoat.buildResearchSupervisorAttestationPacket, 'function');
  assert.equal(typeof ClawMoat.buildResearchSupervisionQueue, 'function');
  assert.equal(typeof ClawMoat.createResearchDispositionAttestation, 'function');
});
