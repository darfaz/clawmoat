'use strict';

const crypto = require('crypto');

const DEFAULT_RULES = {
  requireRating: true,
  requirePriceTargetRationale: true,
  requireRegACCertification: true,
  requireSourceTrail: true,
  blockMnpi: true,
  blockClientConfidential: true,
  blockUnapprovedPersonalData: true,
};

const RATING_PATTERN = /\b(?:buy|sell|hold|neutral|underperform|outperform|overweight|underweight|market\s+perform|sector\s+perform|equal\s+weight)\b/i;
const PRICE_TARGET_PATTERN = /\b(?:price\s+target|PT)\b[^\n$]*(?:\$|USD\s*)\d+(?:\.\d+)?/i;
const RATIONALE_PATTERN = /\b(?:DCF|discounted cash flow|multiple|EV\/EBITDA|P\/E|EPS|revenue growth|margin|WACC|terminal value|sum-of-the-parts|SOTP)\b/i;
const REG_AC_PATTERN = /\b(?:Reg(?:ulation)?\s+AC|analyst certification|certif(?:y|ication).{0,120}(?:views|compensation|recommendation))\b/i;
const SOURCE_PATTERN = /\b(?:source|sources|filing|10-K|10-Q|8-K|transcript|company presentation|FactSet|Bloomberg|Refinitiv|S&P Capital IQ|CapIQ)\b/i;

const RISK_PATTERNS = [
  {
    subtype: 'possible_mnpi',
    severity: 'critical',
    control: 'MNPI-01',
    action: 'block',
    pattern: /\b(?:MNPI|material non[-\s]?public|non[-\s]?public information|not yet announced|before (?:it|this) is announced|unannounced earnings|confidential deal|pending acquisition|board approved but not public)\b/i,
    message: 'Draft appears to use material non-public information.',
  },
  {
    subtype: 'client_confidential',
    severity: 'critical',
    control: 'CONF-01',
    action: 'block',
    pattern: /\b(?:client confidential|do not distribute|NDA|under NDA|wall[-\s]?crossed|private placement memorandum|confidential investor deck)\b/i,
    message: 'Draft appears to include restricted client-confidential material.',
  },
  {
    subtype: 'investment_banking_conflict',
    severity: 'high',
    control: 'IB-01',
    action: 'review',
    pattern: /\b(?:investment banking mandate|banking client|roadshow|bookrunner|underwriter|ECM|DCM|M&A mandate|advisory mandate)\b/i,
    message: 'Investment banking conflict language needs supervisory review.',
  },
  {
    subtype: 'guaranteed_return_language',
    severity: 'high',
    control: 'FAIR-01',
    action: 'review',
    pattern: /\b(?:guaranteed|risk[-\s]?free|can't lose|certain to|will definitely|sure thing)\b/i,
    message: 'Promissory or exaggerated investment language needs review.',
  },
  {
    subtype: 'personal_data',
    severity: 'high',
    control: 'PRIV-01',
    action: 'review',
    pattern: /\b(?:SSN|social security number|passport number|home address|personal phone|personal email)\b/i,
    message: 'Personal data in a research draft should be removed or justified.',
  },
];

const CONTROL_MATRIX = [
  { id: 'MNPI-01', name: 'MNPI prevention', evidence: 'Blocked finding plus reviewer disposition before publication', mapsTo: ['FINRA 2210', 'SEC books-and-records readiness', 'firm information barrier policy'] },
  { id: 'CONF-01', name: 'Client confidential data prevention', evidence: 'Restricted-data finding with redacted preview', mapsTo: ['SOC 2 CC6/CC7', 'vendor confidentiality obligations'] },
  { id: 'IB-01', name: 'Investment banking conflict supervision', evidence: 'Conflict alert routed to supervisor', mapsTo: ['FINRA research conflict controls', 'information barriers'] },
  { id: 'REGAC-01', name: 'Analyst certification completeness', evidence: 'Reg AC certification present before release', mapsTo: ['Reg AC workflow readiness'] },
  { id: 'SRC-01', name: 'Source trail completeness', evidence: 'Citations/source references attached to AI-assisted claims', mapsTo: ['supervision evidence trail', 'model risk documentation'] },
  { id: 'PT-01', name: 'Price target support', evidence: 'Price target and valuation rationale paired in draft', mapsTo: ['pre-publication review', 'fair and balanced communications'] },
];

function hashText(text) {
  return crypto.createHash('sha256').update(String(text || '')).digest('hex');
}

function maxSeverity(findings) {
  const rank = { low: 0, medium: 1, high: 2, critical: 3 };
  return findings.reduce((max, finding) => (rank[finding.severity] > rank[max] ? finding.severity : max), 'low');
}

function actionFor(findings) {
  if (findings.some(f => f.action === 'block' || f.severity === 'critical')) return 'block';
  if (findings.some(f => f.action === 'review' || f.severity === 'high')) return 'review';
  if (findings.length) return 'warn';
  return 'allow';
}

function addFinding(findings, fields) {
  findings.push({
    type: 'equity_research_review',
    ...fields,
  });
}

function scanResearchDraft(draft, options = {}) {
  const text = String(draft || '');
  const rules = { ...DEFAULT_RULES, ...(options.rules || {}) };
  const findings = [];

  for (const risk of RISK_PATTERNS) {
    if ((risk.subtype === 'possible_mnpi' && !rules.blockMnpi) ||
        (risk.subtype === 'client_confidential' && !rules.blockClientConfidential) ||
        (risk.subtype === 'personal_data' && !rules.blockUnapprovedPersonalData)) {
      continue;
    }

    const match = text.match(risk.pattern);
    if (match) {
      addFinding(findings, {
        subtype: risk.subtype,
        severity: risk.severity,
        action: risk.action,
        control: risk.control,
        message: risk.message,
        matched: match[0].slice(0, 96),
      });
    }
  }

  const hasRating = RATING_PATTERN.test(text);
  const hasPriceTarget = PRICE_TARGET_PATTERN.test(text);
  const hasRationale = RATIONALE_PATTERN.test(text);
  const hasRegAC = REG_AC_PATTERN.test(text);
  const hasSourceTrail = SOURCE_PATTERN.test(text);

  if (rules.requireRating && !hasRating) {
    addFinding(findings, {
      subtype: 'missing_rating',
      severity: 'medium',
      action: 'review',
      control: 'PUB-01',
      message: 'Research draft is missing an explicit rating/recommendation.',
    });
  }

  if (rules.requirePriceTargetRationale && hasPriceTarget && !hasRationale) {
    addFinding(findings, {
      subtype: 'unsupported_price_target',
      severity: 'high',
      action: 'review',
      control: 'PT-01',
      message: 'Price target is present without visible valuation rationale.',
    });
  }

  if (rules.requireRegACCertification && !hasRegAC) {
    addFinding(findings, {
      subtype: 'missing_reg_ac_certification',
      severity: 'high',
      action: 'review',
      control: 'REGAC-01',
      message: 'Research package is missing analyst certification / Reg AC language.',
    });
  }

  if (rules.requireSourceTrail && !hasSourceTrail) {
    addFinding(findings, {
      subtype: 'missing_source_trail',
      severity: 'medium',
      action: 'review',
      control: 'SRC-01',
      message: 'AI-assisted research should carry source references for supervisory evidence.',
    });
  }

  return {
    safe: findings.length === 0,
    action: actionFor(findings),
    severity: findings.length ? maxSeverity(findings) : null,
    findings,
    evidence: {
      draftHash: hashText(text),
      generatedAt: new Date().toISOString(),
      checks: {
        hasRating,
        hasPriceTarget,
        hasRationale,
        hasRegAC,
        hasSourceTrail,
      },
      controls: CONTROL_MATRIX.map(control => control.id),
    },
  };
}

class ResearchReviewGuard {
  constructor(options = {}) {
    this.rules = { ...DEFAULT_RULES, ...(options.rules || {}) };
    this.reviews = [];
    this.onReviewRequired = options.onReviewRequired || null;
  }

  reviewDraft(draft, metadata = {}) {
    const result = scanResearchDraft(draft, { rules: this.rules });
    const record = {
      reviewId: crypto.randomBytes(8).toString('hex'),
      timestamp: Date.now(),
      metadata: {
        ticker: metadata.ticker || null,
        analyst: metadata.analyst || null,
        model: metadata.model || null,
        workflow: metadata.workflow || 'pre_publication',
      },
      ...result,
    };

    this.reviews.push(record);
    if (record.action !== 'allow' && this.onReviewRequired) {
      this.onReviewRequired(record);
    }
    return record;
  }

  exportEvidence(options = {}) {
    const from = options.fromTimestamp || 0;
    const to = options.toTimestamp || Date.now();
    const reviews = this.reviews.filter(review => review.timestamp >= from && review.timestamp <= to);
    return {
      generatedAt: new Date().toISOString(),
      format: 'equity_research_prepublication_evidence',
      summary: {
        totalReviews: reviews.length,
        allowed: reviews.filter(review => review.action === 'allow').length,
        reviewRequired: reviews.filter(review => review.action === 'review').length,
        blocked: reviews.filter(review => review.action === 'block').length,
        criticalFindings: reviews.reduce((sum, review) => sum + review.findings.filter(f => f.severity === 'critical').length, 0),
      },
      controlMatrix: CONTROL_MATRIX,
      reviews,
    };
  }
}

module.exports = {
  ResearchReviewGuard,
  scanResearchDraft,
  CONTROL_MATRIX,
  DEFAULT_RULES,
};
