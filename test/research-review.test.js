'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { ResearchReviewGuard, scanResearchDraft, CONTROL_MATRIX, buildArchiveManifest } = require('../src/finance/research-review');
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
  const evidence = guard.exportEvidence();

  assert.equal(blocked.action, 'block');
  assert.equal(evidence.summary.totalReviews, 1);
  assert.equal(evidence.summary.blocked, 1);
  assert.ok(evidence.controlMatrix.some(control => control.id === 'MNPI-01'));
  assert.ok(evidence.archiveManifest);
  assert.equal(evidence.archiveManifest.format, 'equity_research_retention_archive_manifest');
  assert.equal(evidence.archiveManifest.summary.totalEntries, 1);
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

test('top-level package exports ResearchReviewGuard', () => {
  assert.equal(typeof ClawMoat.ResearchReviewGuard, 'function');
  assert.equal(typeof ClawMoat.scanResearchDraft, 'function');
  assert.equal(typeof ClawMoat.buildResearchArchiveManifest, 'function');
});
