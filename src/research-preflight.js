'use strict';

const crypto = require('crypto');
const { scanPromptInjection } = require('./scanners/prompt-injection');

const MONEY_OR_PERCENT = /(?:\$\s?\d+(?:\.\d+)?\s?(?:billion|million|bn|mm|m)?|\d+(?:\.\d+)?%|\b\d+(?:\.\d+)?\s?(?:billion|million|bn|mm)\b)/gi;
const CLAIM_SENTENCE = /[^.!?\n]*(?:\$\s?\d|\d+(?:\.\d+)?%|revenue|ebitda|eps|margin|price target|rating|buy|sell|hold|outperform|underperform|guidance|raised|lowered|growth|decline)[^.!?\n]*[.!?]?/gi;
const AI_TERMS = /\b(ai-assisted|ai generated|ai-generated|gemini|copilot|chatgpt|claude|llm|large language model)\b/i;
const REVIEW_TERMS = /\b(analyst reviewed|reviewed by|certif|attest|human reviewed|supervisor reviewed|approved by)\b/i;
const PT_TERMS = /\b(price target|pt|target price)\b/i;
const EBITDA_TERMS = /\b(ebitda|margin)\b/i;

function hashText(text) {
  return crypto.createHash('sha256').update(String(text || '')).digest('hex');
}

function normalize(text) {
  return String(text || '').toLowerCase().replace(/[^a-z0-9$%.]+/g, ' ').replace(/\s+/g, ' ').trim();
}

function compactMoney(value) {
  return String(value || '').toLowerCase().replace(/\s+/g, '').replace(/usd/g, '$');
}

function splitLines(text) {
  return String(text || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function extractClaims(draftText) {
  const claims = [];
  const matches = String(draftText || '').match(CLAIM_SENTENCE) || [];
  for (const raw of matches) {
    const claim = raw.trim();
    if (claim.length > 8 && !claims.includes(claim)) claims.push(claim);
  }
  return claims;
}

function parseRestrictedIssuers(text) {
  return splitLines(text)
    .map((line) => line.split(',')[0].trim())
    .filter((line) => line && !/^ticker|issuer|company$/i.test(line));
}

function parseModelValues(modelText) {
  const rows = splitLines(modelText);
  const values = [];
  for (const row of rows) {
    if (/^ticker,metric,value/i.test(row)) continue;
    const parts = row.split(',').map((part) => part.trim()).filter(Boolean);
    for (const part of parts) {
      const matches = part.match(MONEY_OR_PERCENT) || [];
      values.push(...matches.map(compactMoney));
    }
  }
  return Array.from(new Set(values));
}

function hasSourceSupport(claim, sourceCorpus) {
  const normalizedSource = normalize(sourceCorpus);
  const normalizedClaim = normalize(claim);
  if (!normalizedClaim) return true;
  if (normalizedSource.includes(normalizedClaim)) return true;

  const values = (claim.match(MONEY_OR_PERCENT) || []).map(compactMoney);
  if (values.length && values.every((value) => compactMoney(sourceCorpus).includes(value))) return true;

  const keyWords = normalizedClaim.split(' ').filter((word) => word.length > 4 && !['increased', 'decreased', 'raised', 'lowered', 'stronger'].includes(word));
  if (keyWords.length >= 3) {
    const hits = keyWords.filter((word) => normalizedSource.includes(word)).length;
    return hits / keyWords.length >= 0.72;
  }
  return false;
}

function runResearchPreflight(opts = {}) {
  const draftText = String(opts.draftText || '');
  const sourceTexts = opts.sourceTexts || {};
  const sourceCorpus = Object.values(sourceTexts).join('\n\n');
  const modelText = String(opts.modelText || '');
  const restrictedText = String(opts.restrictedText || '');
  const analyst = opts.analyst || 'unspecified';
  const workflow = opts.workflow || 'equity research preflight';
  const modelProvider = opts.modelProvider || opts.provider || 'unspecified';
  const now = opts.now || new Date().toISOString();
  const findings = [];

  for (const claim of extractClaims(draftText)) {
    if (!hasSourceSupport(claim, sourceCorpus)) {
      findings.push({
        type: 'unsupported_claim',
        severity: 'high',
        evidence: claim,
        recommendation: 'Link the claim to an approved transcript, filing, model cell, or remove it before supervisor review.',
      });
    }
  }

  const modelValues = parseModelValues(modelText);
  const draftValues = (draftText.match(MONEY_OR_PERCENT) || []).map(compactMoney);
  for (const value of Array.from(new Set(draftValues))) {
    const sentence = (extractClaims(draftText).find((claim) => compactMoney(claim).includes(value)) || draftText).trim();
    const shouldTieOut = PT_TERMS.test(sentence) || EBITDA_TERMS.test(sentence) || /\$|%/.test(value);
    if (shouldTieOut && modelValues.length && !modelValues.includes(value)) {
      findings.push({
        type: 'model_tie_out',
        severity: PT_TERMS.test(sentence) ? 'high' : 'medium',
        evidence: `Draft uses ${value}; model values include ${modelValues.slice(0, 8).join(', ')}`,
        recommendation: 'Tie every price target, estimate, and margin number to the approved model version before publication.',
      });
    }
  }

  for (const [name, text] of Object.entries(sourceTexts)) {
    const scan = scanPromptInjection(String(text || ''), { context: name });
    if (!scan.clean) {
      findings.push({
        type: 'prompt_injection_source',
        severity: 'high',
        evidence: `${name}: ${scan.findings.map((finding) => finding.subtype || finding.type).join(', ')}`,
        recommendation: 'Treat the source as untrusted. Do not allow source text to control tools, retrieval scope, recipients, or model/system instructions.',
      });
    }
  }

  for (const issuer of parseRestrictedIssuers(restrictedText)) {
    const pattern = new RegExp(`\\b${issuer.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
    if (pattern.test(draftText) || pattern.test(sourceCorpus) || pattern.test(modelText)) {
      findings.push({
        type: 'restricted_issuer',
        severity: 'critical',
        evidence: `Restricted/watch-list issuer referenced: ${issuer}`,
        recommendation: 'Route to compliance and verify information-barrier approval before any AI-assisted distribution or client communication.',
      });
    }
  }

  if (AI_TERMS.test(draftText) && !REVIEW_TERMS.test(draftText)) {
    findings.push({
      type: 'ai_usage_attestation',
      severity: 'medium',
      evidence: 'Draft references AI assistance but no analyst review/attestation language was detected.',
      recommendation: 'Record analyst review, source verification, and supervisor approval before relying on AI-assisted content.',
    });
  }

  const bySeverity = findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });

  const sourceHashes = {};
  for (const [name, text] of Object.entries(sourceTexts)) sourceHashes[name] = hashText(text);

  return {
    type: 'clawmoat_research_preflight',
    generatedAt: now,
    workflow,
    analyst,
    modelProvider,
    summary: {
      totalFindings: findings.length,
      critical: bySeverity.critical || 0,
      high: bySeverity.high || 0,
      medium: bySeverity.medium || 0,
      low: bySeverity.low || 0,
      disposition: findings.some((f) => f.severity === 'critical' || f.severity === 'high') ? 'supervisor_review_required' : 'ready_for_human_review',
    },
    findings,
    receipt: {
      artifactHash: hashText(draftText),
      modelHash: hashText(modelText),
      restrictedListHash: hashText(restrictedText),
      sourceHashes,
      controls: [
        'claim_source_support',
        'model_number_tie_out',
        'prompt_injection_source_scan',
        'restricted_issuer_check',
        'ai_usage_attestation_check',
      ],
    },
  };
}

function formatResearchPreflightMarkdown(report) {
  const lines = [];
  lines.push('# ClawMoat Research Preflight');
  lines.push('');
  lines.push(`Generated: ${report.generatedAt}`);
  lines.push(`Workflow: ${report.workflow}`);
  lines.push(`Analyst: ${report.analyst}`);
  lines.push(`Model/provider: ${report.modelProvider}`);
  lines.push(`Disposition: ${report.summary.disposition}`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push(`- Total findings: ${report.summary.totalFindings}`);
  lines.push(`- Critical: ${report.summary.critical}`);
  lines.push(`- High: ${report.summary.high}`);
  lines.push(`- Medium: ${report.summary.medium}`);
  lines.push(`- Low: ${report.summary.low}`);
  lines.push('');
  lines.push('## Findings');
  lines.push('');
  if (!report.findings.length) {
    lines.push('No findings. Human analyst review is still required before publication.');
  } else {
    report.findings.forEach((finding, index) => {
      lines.push(`### ${index + 1}. ${finding.type} (${finding.severity})`);
      lines.push('');
      lines.push(`Evidence: ${finding.evidence}`);
      lines.push('');
      lines.push(`Recommendation: ${finding.recommendation}`);
      lines.push('');
    });
  }
  lines.push('## Evidence receipt');
  lines.push('');
  lines.push(`- Draft artifact hash: ${report.receipt.artifactHash}`);
  lines.push(`- Model hash: ${report.receipt.modelHash}`);
  lines.push(`- Restricted list hash: ${report.receipt.restrictedListHash}`);
  for (const [name, hash] of Object.entries(report.receipt.sourceHashes)) lines.push(`- Source ${name} hash: ${hash}`);
  lines.push(`- Controls applied: ${report.receipt.controls.join(', ')}`);
  lines.push('');
  lines.push('## Supervisor checklist');
  lines.push('');
  lines.push('- [ ] Analyst confirmed AI output reflects their personal view.');
  lines.push('- [ ] Unsupported claims were removed or tied to approved sources.');
  lines.push('- [ ] Price target, estimates, and percentages tie to the approved model.');
  lines.push('- [ ] Restricted-list and information-barrier hits were cleared.');
  lines.push('- [ ] Evidence receipt was archived with the final research artifact.');
  return lines.join('\n');
}

module.exports = {
  runResearchPreflight,
  formatResearchPreflightMarkdown,
  extractClaims,
  parseModelValues,
};
