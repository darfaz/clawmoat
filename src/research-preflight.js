'use strict';

const crypto = require('crypto');
const { scanPromptInjection } = require('./scanners/prompt-injection');

const MONEY_OR_PERCENT = /(?:\$\s?\d+(?:\.\d+)?\s?(?:billion|million|bn|mm|m)?|\d+(?:\.\d+)?%|\b\d+(?:\.\d+)?\s?(?:billion|million|bn|mm)\b)/gi;
const MONEY_OR_PERCENT_TEST = /(?:\$\s?\d+(?:\.\d+)?\s?(?:billion|million|bn|mm|m)?|\d+(?:\.\d+)?%|\b\d+(?:\.\d+)?\s?(?:billion|million|bn|mm)\b)/i;
const CLAIM_SENTENCE = /[^.!?\n]*(?:\$\s?\d|\d+(?:\.\d+)?%|revenue|ebitda|eps|margin|price target|rating|buy|sell|hold|outperform|underperform|guidance|raised|lowered|growth|decline)[^.!?\n]*[.!?]?/gi;
const AI_TERMS = /\b(ai-assisted|ai generated|ai-generated|gemini|copilot|chatgpt|claude|llm|large language model)\b/i;
const REVIEW_TERMS = /\b(analyst reviewed|reviewed by|certif|attest|human reviewed|supervisor reviewed|approved by)\b/i;
const PT_TERMS = /\b(price target|pt|target price)\b/i;
const EBITDA_TERMS = /\b(ebitda|margin)\b/i;
const BANK_POLICY_PACK = 'investment-banking-research-v1';
const CITATION_TERMS = /\[(?:S|source):[^\]]+\]|\bsource\s*:/i;
const MNPI_TERMS = /\b(privately told|private conversation|not public|non[-\s]?public|mnpi|confidential|before public release|unannounced|undisclosed|selective disclosure|wall[-\s]?crossed)\b/i;
const REQUIRED_RESEARCH_DISCLOSURES = [
  { key: 'valuation methodology', pattern: /\b(valuation methodology|methodology|valuation basis|derived from|dcf|sum[-\s]?of[-\s]?the[-\s]?parts|multiple)\b/i },
  { key: 'risk factors', pattern: /\b(risk factors?|key risks?|investment risks?|downside risks?)\b/i },
  { key: 'analyst certification', pattern: /\b(analyst certification|certify|certifies|analyst reviewed|personal view|personal views)\b/i },
];

const CONTROL_MATRIX = [
  { id: 'FINRA-3110-GENAI', name: 'Reasonably designed supervision for GenAI use', source: 'FINRA Regulatory Notice 24-09 / Rule 3110' },
  { id: 'FINRA-2210-COMMS', name: 'Communications content standards apply to AI-generated output', source: 'FINRA Regulatory Notice 24-09 / Rule 2210' },
  { id: 'IB-RESEARCH-CITATIONS', name: 'Material claims require source citations', source: 'ClawMoat investment-banking research policy' },
  { id: 'IB-RESEARCH-MNPI', name: 'Potential MNPI and selective-disclosure hold', source: 'ClawMoat investment-banking research policy' },
  { id: 'IB-RESEARCH-DISCLOSURES', name: 'Research disclosure and analyst-certification checks', source: 'ClawMoat investment-banking research policy' },
];

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

function isBankPolicy(policyPack) {
  return policyPack === BANK_POLICY_PACK || policyPack === 'bank' || policyPack === 'investment-banking';
}

function hasCitation(claim) {
  return CITATION_TERMS.test(claim);
}

function materialClaimNeedsCitation(claim) {
  return MONEY_OR_PERCENT_TEST.test(claim) || PT_TERMS.test(claim) || /\b(rating|buy|sell|hold|outperform|underperform|guidance|consensus|revenue|eps|ebitda)\b/i.test(claim);
}

function extractMnpiEvidence(text) {
  const findings = [];
  for (const line of splitLines(text)) {
    if (MNPI_TERMS.test(line)) findings.push(line);
  }
  return findings;
}

function summarizeRetention(draftText, modelText, restrictedText, sourceTexts) {
  const sourceHashes = {};
  for (const [name, text] of Object.entries(sourceTexts)) sourceHashes[name] = hashText(text);
  return {
    artifactHashes: {
      draft: hashText(draftText),
      model: hashText(modelText),
      restrictedList: hashText(restrictedText),
      sources: sourceHashes,
    },
    retentionClass: 'research-supervision-audit-packet',
    note: 'Archive with the final research artifact, approval workflow, and firm books-and-records system.',
  };
}

function dispositionFor(findings) {
  if (findings.some((f) => f.type === 'potential_mnpi' || f.type === 'restricted_issuer')) return 'compliance_hold';
  if (findings.some((f) => f.severity === 'critical' || f.severity === 'high')) return 'supervisor_review_required';
  return 'ready_for_human_review';
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
  const policyPack = opts.policyPack || (opts.bankGrade ? BANK_POLICY_PACK : 'research-preflight-default-v1');
  const bankPolicyEnabled = isBankPolicy(policyPack);
  const now = opts.now || new Date().toISOString();
  const findings = [];
  const claims = extractClaims(draftText);

  for (const claim of claims) {
    if (bankPolicyEnabled && materialClaimNeedsCitation(claim) && !hasCitation(claim)) {
      findings.push({
        type: 'missing_claim_citation',
        severity: PT_TERMS.test(claim) || /\b(rating|buy|sell|hold|outperform|underperform)\b/i.test(claim) ? 'high' : 'medium',
        evidence: claim,
        recommendation: 'Add an explicit source citation such as [S:transcript] or [S:model] for every material claim before supervisor review.',
        control: 'IB-RESEARCH-CITATIONS',
      });
    }
    if (!hasSourceSupport(claim, sourceCorpus)) {
      findings.push({
        type: 'unsupported_claim',
        severity: 'high',
        evidence: claim,
        recommendation: 'Link the claim to an approved transcript, filing, model cell, or remove it before supervisor review.',
        control: 'FINRA-2210-COMMS',
      });
    }
  }

  const modelValues = parseModelValues(modelText);
  const draftValues = (draftText.match(MONEY_OR_PERCENT) || []).map(compactMoney);
  for (const value of Array.from(new Set(draftValues))) {
    const sentence = (claims.find((claim) => compactMoney(claim).includes(value)) || draftText).trim();
    const shouldTieOut = PT_TERMS.test(sentence) || EBITDA_TERMS.test(sentence) || /\$|%/.test(value);
    if (shouldTieOut && modelValues.length && !modelValues.includes(value)) {
      findings.push({
        type: 'model_tie_out',
        severity: PT_TERMS.test(sentence) ? 'high' : 'medium',
        evidence: `Draft uses ${value}; model values include ${modelValues.slice(0, 8).join(', ')}`,
        recommendation: 'Tie every price target, estimate, and margin number to the approved model version before publication.',
        control: 'IB-RESEARCH-CITATIONS',
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
        control: 'FINRA-3110-GENAI',
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
        control: 'IB-RESEARCH-MNPI',
      });
    }
  }

  if (AI_TERMS.test(draftText) && !REVIEW_TERMS.test(draftText)) {
    findings.push({
      type: 'ai_usage_attestation',
      severity: 'medium',
      evidence: 'Draft references AI assistance but no analyst review/attestation language was detected.',
      recommendation: 'Record analyst review, source verification, and supervisor approval before relying on AI-assisted content.',
      control: 'FINRA-3110-GENAI',
    });
  }

  if (bankPolicyEnabled) {
    const mnpiEvidence = [draftText, sourceCorpus, modelText].flatMap(extractMnpiEvidence);
    for (const evidence of Array.from(new Set(mnpiEvidence)).slice(0, 5)) {
      findings.push({
        type: 'potential_mnpi',
        severity: 'critical',
        evidence,
        recommendation: 'Stop distribution. Route to compliance, confirm public-source provenance, and document wall-crossing / information-barrier clearance before any AI-assisted use.',
        control: 'IB-RESEARCH-MNPI',
      });
    }

    for (const disclosure of REQUIRED_RESEARCH_DISCLOSURES) {
      if (!disclosure.pattern.test(draftText)) {
        findings.push({
          type: 'missing_research_disclosure',
          severity: disclosure.key === 'analyst certification' ? 'high' : 'medium',
          evidence: `Missing ${disclosure.key}`,
          recommendation: 'Add required research disclosure language before publication or archive the compliance rationale for omission.',
          control: 'IB-RESEARCH-DISCLOSURES',
        });
      }
    }
  }

  const bySeverity = findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });

  const sourceHashes = {};
  for (const [name, text] of Object.entries(sourceTexts)) sourceHashes[name] = hashText(text);
  const controls = [
    'claim_source_support',
    'model_number_tie_out',
    'prompt_injection_source_scan',
    'restricted_issuer_check',
    'ai_usage_attestation_check',
  ];
  if (bankPolicyEnabled) controls.push('claim_citation_required', 'mnpi_selective_disclosure_hold', 'research_disclosure_check', 'audit_retention_packet');
  const retention = summarizeRetention(draftText, modelText, restrictedText, sourceTexts);

  return {
    type: 'clawmoat_research_preflight',
    generatedAt: now,
    workflow,
    analyst,
    modelProvider,
    policyPack,
    summary: {
      totalFindings: findings.length,
      critical: bySeverity.critical || 0,
      high: bySeverity.high || 0,
      medium: bySeverity.medium || 0,
      low: bySeverity.low || 0,
      disposition: dispositionFor(findings),
    },
    findings,
    receipt: {
      artifactHash: retention.artifactHashes.draft,
      modelHash: retention.artifactHashes.model,
      restrictedListHash: retention.artifactHashes.restrictedList,
      sourceHashes,
      policyPack,
      controls,
      controlMatrix: bankPolicyEnabled ? CONTROL_MATRIX : CONTROL_MATRIX.slice(0, 2),
      retention,
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
  if (report.policyPack) lines.push(`Policy pack: ${report.policyPack}`);
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
  if (report.receipt.retention) {
    lines.push(`- Retention class: ${report.receipt.retention.retentionClass}`);
    lines.push(`- Retention note: ${report.receipt.retention.note}`);
  }
  lines.push('');
  lines.push('## Control matrix');
  lines.push('');
  for (const control of report.receipt.controlMatrix || []) {
    lines.push(`- ${control.id}: ${control.name} (${control.source})`);
  }
  lines.push('');
  lines.push('## Supervisor checklist');
  lines.push('');
  lines.push('- [ ] Analyst confirmed AI output reflects their personal view.');
  lines.push('- [ ] Unsupported claims were removed or tied to approved sources.');
  lines.push('- [ ] Price target, estimates, and percentages tie to the approved model.');
  if ((report.receipt.controls || []).includes('claim_citation_required')) lines.push('- [ ] Every material claim has an explicit source citation.');
  if ((report.receipt.controls || []).includes('mnpi_selective_disclosure_hold')) lines.push('- [ ] Potential MNPI, restricted-list, and information-barrier hits were cleared by compliance.');
  if ((report.receipt.controls || []).includes('research_disclosure_check')) lines.push('- [ ] Required research disclosures, risk factors, valuation methodology, and analyst certification were added or documented as not applicable.');
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
