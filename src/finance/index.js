/**
 * ClawMoat Finance — Financial Security Module for AI Agents
 * 
 * Protects financial data, credentials, and transactions when
 * AI agents operate in financial contexts (bookkeeping, invoicing,
 * crypto, banking, payments).
 * 
 * Features:
 * - Financial credential detection and protection
 * - Transaction amount guardrails with approval thresholds
 * - PCI-DSS / SOX-ready audit trail formatting
 * - Financial PII scanning (SSN, account numbers, routing numbers)
 * - Crypto wallet protection (seed phrases, private keys, wallet files)
 * - API rate limiting for financial services
 * - Dual-approval workflow for high-value operations
 * 
 * @module clawmoat/finance
 * @example
 * const { FinanceGuard } = require('clawmoat/finance');
 * const guard = new FinanceGuard({
 *   transactionLimit: 1000,        // Require approval above $1000
 *   dualApprovalThreshold: 10000,  // Two approvals above $10K
 *   auditFormat: 'sox',            // SOX-compliant audit trail
 *   onAlert: (alert) => notifySlack(alert),
 * });
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

// ─── Financial Credential Patterns ──────────────────────────────

/** Patterns that indicate financial credentials in file paths */
const FINANCIAL_FORBIDDEN_ZONES = [
  // Banking & Payment
  { pattern: /\.stripe\b/i, label: 'Stripe credentials', severity: 'critical', category: 'payment' },
  { pattern: /\.plaid\b/i, label: 'Plaid credentials', severity: 'critical', category: 'banking' },
  { pattern: /\.square\b/i, label: 'Square credentials', severity: 'critical', category: 'payment' },
  { pattern: /braintree/i, label: 'Braintree credentials', severity: 'critical', category: 'payment' },
  { pattern: /paypal/i, label: 'PayPal credentials', severity: 'high', category: 'payment' },
  { pattern: /adyen/i, label: 'Adyen credentials', severity: 'critical', category: 'payment' },
  { pattern: /dwolla/i, label: 'Dwolla credentials', severity: 'critical', category: 'payment' },
  
  // Crypto Wallets
  { pattern: /\.bitcoin\b/i, label: 'Bitcoin wallet', severity: 'critical', category: 'crypto' },
  { pattern: /\.ethereum\b/i, label: 'Ethereum wallet', severity: 'critical', category: 'crypto' },
  { pattern: /\.solana\b/i, label: 'Solana wallet', severity: 'critical', category: 'crypto' },
  { pattern: /wallet\.dat/i, label: 'Crypto wallet file', severity: 'critical', category: 'crypto' },
  { pattern: /keystore.*\.json/i, label: 'Crypto keystore', severity: 'critical', category: 'crypto' },
  { pattern: /\.metamask\b/i, label: 'MetaMask data', severity: 'critical', category: 'crypto' },
  { pattern: /\.phantom\b/i, label: 'Phantom wallet', severity: 'critical', category: 'crypto' },
  { pattern: /\.ledger\b/i, label: 'Ledger config', severity: 'high', category: 'crypto' },
  { pattern: /\.trezor\b/i, label: 'Trezor config', severity: 'high', category: 'crypto' },
  
  // Accounting Software
  { pattern: /quickbooks/i, label: 'QuickBooks data', severity: 'high', category: 'accounting' },
  { pattern: /xero/i, label: 'Xero credentials', severity: 'high', category: 'accounting' },
  { pattern: /freshbooks/i, label: 'FreshBooks credentials', severity: 'high', category: 'accounting' },
  { pattern: /\.qbo$/i, label: 'QuickBooks Online file', severity: 'high', category: 'accounting' },
  { pattern: /\.qbw$/i, label: 'QuickBooks data file', severity: 'high', category: 'accounting' },
  { pattern: /\.ofx$/i, label: 'Open Financial Exchange file', severity: 'high', category: 'accounting' },
  { pattern: /\.qfx$/i, label: 'Quicken Financial Exchange file', severity: 'high', category: 'accounting' },
  
  // Tax & Compliance
  { pattern: /\.tax\b/i, label: 'Tax data', severity: 'high', category: 'tax' },
  { pattern: /turbotax/i, label: 'TurboTax data', severity: 'high', category: 'tax' },
  { pattern: /\.1099\b/i, label: '1099 form data', severity: 'critical', category: 'tax' },
  { pattern: /\.w[29]\b/i, label: 'W-2/W-9 form data', severity: 'critical', category: 'tax' },
  
  // Banking Files
  { pattern: /\.bai2?$/i, label: 'BAI bank statement', severity: 'high', category: 'banking' },
  { pattern: /\.mt940$/i, label: 'SWIFT MT940 statement', severity: 'high', category: 'banking' },
  { pattern: /\.ach$/i, label: 'ACH payment file', severity: 'critical', category: 'banking' },
  { pattern: /nacha/i, label: 'NACHA payment file', severity: 'critical', category: 'banking' },
];

/** Patterns that indicate financial secrets in text content */
const FINANCIAL_SECRET_PATTERNS = [
  // API Keys
  { pattern: /sk_(test|live)_[a-zA-Z0-9]{24,}/g, label: 'Stripe secret key', severity: 'critical' },
  { pattern: /pk_(test|live)_[a-zA-Z0-9]{24,}/g, label: 'Stripe publishable key', severity: 'high' },
  { pattern: /rk_(test|live)_[a-zA-Z0-9]{24,}/g, label: 'Stripe restricted key', severity: 'critical' },
  { pattern: /whsec_[a-zA-Z0-9]{32,}/g, label: 'Stripe webhook secret', severity: 'critical' },
  { pattern: /access-[a-z0-9]{32,}/g, label: 'Plaid access token', severity: 'critical' },
  { pattern: /sq0[a-z]{3}-[a-zA-Z0-9\-_]{22,}/g, label: 'Square API key', severity: 'critical' },
  
  // Crypto
  { pattern: /(?:^|\s)(5[HJK][1-9A-HJ-NP-Za-km-z]{49})(?:\s|$)/g, label: 'Bitcoin private key (WIF)', severity: 'critical' },
  { pattern: /0x[a-fA-F0-9]{64}/g, label: 'Ethereum private key', severity: 'critical' },
  { pattern: /(?:^|\s)([1-9A-HJ-NP-Za-km-z]{87,88})(?:\s|$)/g, label: 'Solana private key', severity: 'critical' },
  { pattern: /(?:abandon|ability|able|about|above)\s+(?:abandon|ability|able|about|above)(?:\s+\w+){10,22}/gi, label: 'Possible BIP-39 seed phrase', severity: 'critical' },
  
  // Financial PII
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: 'SSN (Social Security Number)', severity: 'critical' },
  { pattern: /\b\d{9}\b(?=.*(?:routing|aba|rtn))/gi, label: 'ABA routing number', severity: 'critical' },
  { pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g, label: 'Credit card number', severity: 'critical' },
  { pattern: /\b[0-9]{8,17}\b(?=.*(?:account|acct|checking|savings|routing))/gi, label: 'Bank account number', severity: 'critical' },
  { pattern: /\b\d{2}-\d{7}\b(?=.*(?:ein|tax|employer))/gi, label: 'EIN (Employer ID Number)', severity: 'high' },
  { pattern: /\bIBAN\s*:?\s*[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/gi, label: 'IBAN number', severity: 'critical' },
  { pattern: /\bSWIFT\s*:?\s*[A-Z]{6}[A-Z0-9]{2,5}\b/gi, label: 'SWIFT/BIC code', severity: 'high' },
];

/** Financial API domains to monitor */
const FINANCIAL_API_DOMAINS = [
  { domain: 'api.stripe.com', label: 'Stripe', category: 'payment' },
  { domain: 'api.plaid.com', label: 'Plaid', category: 'banking' },
  { domain: 'connect.squareup.com', label: 'Square', category: 'payment' },
  { domain: 'api.braintreegateway.com', label: 'Braintree', category: 'payment' },
  { domain: 'api.paypal.com', label: 'PayPal', category: 'payment' },
  { domain: 'checkout-test.adyen.com', label: 'Adyen', category: 'payment' },
  { domain: 'api.coinbase.com', label: 'Coinbase', category: 'crypto' },
  { domain: 'api.binance.com', label: 'Binance', category: 'crypto' },
  { domain: 'api.kraken.com', label: 'Kraken', category: 'crypto' },
  { domain: 'quickbooks.api.intuit.com', label: 'QuickBooks', category: 'accounting' },
  { domain: 'api.xero.com', label: 'Xero', category: 'accounting' },
  { domain: 'api.freshbooks.com', label: 'FreshBooks', category: 'accounting' },
  { domain: 'api.wise.com', label: 'Wise', category: 'transfer' },
  { domain: 'api.mercury.com', label: 'Mercury', category: 'banking' },
  { domain: 'api.svb.com', label: 'SVB', category: 'banking' },
];

// ─── FinanceGuard Class ─────────────────────────────────────────

class FinanceGuard {
  /**
   * @param {Object} options
   * @param {number} [options.transactionLimit=1000] - Require approval above this amount
   * @param {number} [options.dualApprovalThreshold=10000] - Two approvals above this
   * @param {string} [options.currency='USD'] - Default currency
   * @param {string} [options.auditFormat='sox'] - Audit format: 'sox' | 'pcidss' | 'standard'
   * @param {Function} [options.onAlert] - Alert callback
   * @param {Function} [options.onApprovalRequired] - Called when transaction needs approval
   * @param {string} [options.logPath] - Audit log file path
   * @param {string[]} [options.allowedDomains] - Additional allowed financial domains
   */
  constructor(options = {}) {
    this.transactionLimit = options.transactionLimit ?? 1000;
    this.dualApprovalThreshold = options.dualApprovalThreshold ?? 10000;
    this.currency = options.currency || 'USD';
    this.auditFormat = options.auditFormat || 'sox';
    this.onAlert = options.onAlert || null;
    this.onApprovalRequired = options.onApprovalRequired || null;
    this.logPath = options.logPath || null;
    this.allowedDomains = new Set(options.allowedDomains || []);

    // State
    this.transactions = [];
    this.alerts = [];
    this.auditLog = [];
    this.apiCallLog = [];
    this.pendingApprovals = new Map();
  }

  // ─── File Path Protection ─────────────────────────────────────

  /**
   * Check if a file path accesses financial data.
   * @param {string} filePath - Path to check
   * @returns {Object} { allowed, findings[] }
   */
  checkFilePath(filePath) {
    const normalized = filePath.replace(/\\/g, '/').replace(/^~/, os.homedir());
    const findings = [];

    for (const zone of FINANCIAL_FORBIDDEN_ZONES) {
      if (zone.pattern.test(normalized)) {
        findings.push({
          type: 'financial_forbidden_zone',
          label: zone.label,
          category: zone.category,
          severity: zone.severity,
          path: filePath,
        });
      }
    }

    if (findings.length > 0) {
      this._audit('file_access_blocked', { path: filePath, findings });
      if (findings.some(f => f.severity === 'critical')) {
        this._alert({
          type: 'financial_credential_access',
          severity: 'critical',
          message: `Agent attempted to access financial data: ${findings[0].label}`,
          details: { path: filePath, findings },
        });
      }
    }

    return {
      allowed: findings.length === 0,
      findings,
    };
  }

  // ─── Content Scanning ─────────────────────────────────────────

  /**
   * Scan text content for financial secrets and PII.
   * @param {string} text - Content to scan
   * @returns {Object} { safe, findings[], redacted }
   */
  scanContent(text) {
    if (!text || typeof text !== 'string') {
      return { safe: true, findings: [], redacted: text || '' };
    }

    const findings = [];
    let redacted = text;

    for (const pattern of FINANCIAL_SECRET_PATTERNS) {
      // Reset regex state
      pattern.pattern.lastIndex = 0;
      let match;
      while ((match = pattern.pattern.exec(text)) !== null) {
        findings.push({
          type: 'financial_secret',
          label: pattern.label,
          severity: pattern.severity,
          match: match[0].substring(0, 8) + '***REDACTED***',
          position: match.index,
        });
        // Redact in output
        const replacement = `[REDACTED:${pattern.label}]`;
        redacted = redacted.replace(match[0], replacement);
      }
    }

    if (findings.length > 0) {
      this._audit('financial_secret_detected', { findingCount: findings.length, labels: findings.map(f => f.label) });
      for (const f of findings) {
        if (f.severity === 'critical') {
          this._alert({
            type: 'financial_secret_leak',
            severity: 'critical',
            message: `Financial secret detected in agent output: ${f.label}`,
            details: f,
          });
        }
      }
    }

    return {
      safe: findings.length === 0,
      findings,
      redacted,
    };
  }

  // ─── Transaction Guardrails ───────────────────────────────────

  /**
   * Evaluate a financial transaction for approval.
   * @param {Object} transaction
   * @param {number} transaction.amount - Transaction amount
   * @param {string} [transaction.currency] - Currency code
   * @param {string} transaction.type - 'payment' | 'transfer' | 'refund' | 'subscription' | 'invoice'
   * @param {string} [transaction.recipient] - Recipient identifier
   * @param {string} [transaction.description] - Description
   * @param {string} [transaction.initiator] - Who/what initiated (agent, skill, user)
   * @returns {Object} { approved, requiresApproval, requiresDualApproval, reason, transactionId }
   */
  evaluateTransaction(transaction) {
    const txId = crypto.randomBytes(8).toString('hex');
    const amount = Math.abs(transaction.amount || 0);
    const currency = transaction.currency || this.currency;
    const now = Date.now();

    const record = {
      transactionId: txId,
      timestamp: now,
      amount,
      currency,
      type: transaction.type || 'unknown',
      recipient: transaction.recipient || 'unknown',
      description: transaction.description || '',
      initiator: transaction.initiator || 'agent',
      status: 'pending',
    };

    this.transactions.push(record);

    // Check daily aggregate
    const todayStart = new Date().setHours(0, 0, 0, 0);
    const todayTotal = this.transactions
      .filter(t => t.timestamp >= todayStart && t.status === 'approved')
      .reduce((sum, t) => sum + t.amount, 0);

    const result = {
      transactionId: txId,
      amount,
      currency,
      approved: false,
      requiresApproval: false,
      requiresDualApproval: false,
      reason: '',
      dailyTotal: todayTotal,
    };

    // Evaluate
    if (amount >= this.dualApprovalThreshold) {
      result.requiresDualApproval = true;
      result.requiresApproval = true;
      result.reason = `Amount $${amount.toLocaleString()} exceeds dual-approval threshold ($${this.dualApprovalThreshold.toLocaleString()})`;
      record.status = 'pending_dual_approval';
      this.pendingApprovals.set(txId, { approvals: [], required: 2, record });
    } else if (amount >= this.transactionLimit) {
      result.requiresApproval = true;
      result.reason = `Amount $${amount.toLocaleString()} exceeds single-approval threshold ($${this.transactionLimit.toLocaleString()})`;
      record.status = 'pending_approval';
      this.pendingApprovals.set(txId, { approvals: [], required: 1, record });
    } else {
      result.approved = true;
      result.reason = 'Within auto-approval limits';
      record.status = 'approved';
    }

    this._audit('transaction_evaluated', { ...result, type: record.type, recipient: record.recipient });

    if (result.requiresApproval) {
      this._alert({
        type: result.requiresDualApproval ? 'dual_approval_required' : 'approval_required',
        severity: result.requiresDualApproval ? 'critical' : 'high',
        message: result.reason,
        details: { transactionId: txId, amount, currency, type: record.type, recipient: record.recipient },
      });

      if (this.onApprovalRequired) {
        this.onApprovalRequired(result);
      }
    }

    return result;
  }

  /**
   * Approve a pending transaction.
   * @param {string} transactionId
   * @param {string} approver - Who is approving
   * @returns {Object} { approved, remainingApprovals }
   */
  approveTransaction(transactionId, approver) {
    const pending = this.pendingApprovals.get(transactionId);
    if (!pending) {
      return { approved: false, error: 'Transaction not found or already resolved' };
    }

    // Prevent same person approving twice
    if (pending.approvals.includes(approver)) {
      return { approved: false, error: 'Same approver cannot approve twice' };
    }

    pending.approvals.push(approver);
    const remaining = pending.required - pending.approvals.length;

    if (remaining <= 0) {
      pending.record.status = 'approved';
      this.pendingApprovals.delete(transactionId);
      this._audit('transaction_approved', { transactionId, approvers: pending.approvals });
      return { approved: true, remainingApprovals: 0 };
    }

    this._audit('transaction_partial_approval', { transactionId, approver, remaining });
    return { approved: false, remainingApprovals: remaining };
  }

  /**
   * Deny a pending transaction.
   * @param {string} transactionId
   * @param {string} denier - Who is denying
   * @param {string} [reason] - Reason for denial
   * @returns {Object} { denied }
   */
  denyTransaction(transactionId, denier, reason) {
    const pending = this.pendingApprovals.get(transactionId);
    if (!pending) {
      return { denied: false, error: 'Transaction not found or already resolved' };
    }

    pending.record.status = 'denied';
    this.pendingApprovals.delete(transactionId);
    this._audit('transaction_denied', { transactionId, denier, reason });
    return { denied: true };
  }

  // ─── API Call Monitoring ──────────────────────────────────────

  /**
   * Monitor an outbound API call to a financial service.
   * @param {Object} call
   * @param {string} call.url - API URL
   * @param {string} [call.method] - HTTP method
   * @param {string} [call.initiator] - What triggered the call
   * @returns {Object} { allowed, service, category, alerts }
   */
  monitorApiCall(call) {
    let url;
    try {
      url = new URL(call.url);
    } catch {
      return { allowed: true, service: null, category: null, alerts: [] };
    }

    const domain = url.hostname;
    const matchedService = FINANCIAL_API_DOMAINS.find(s => domain.includes(s.domain));
    const alerts = [];

    if (matchedService) {
      const record = {
        timestamp: Date.now(),
        domain,
        service: matchedService.label,
        category: matchedService.category,
        method: call.method || 'unknown',
        path: url.pathname,
        initiator: call.initiator || 'agent',
      };

      this.apiCallLog.push(record);
      this._audit('financial_api_call', record);

      // Check for dangerous operations
      const isDangerous = /\/charges|\/transfers|\/payouts|\/send|\/withdraw/i.test(url.pathname);
      if (isDangerous && (call.method || '').toUpperCase() === 'POST') {
        const alert = {
          type: 'financial_api_mutation',
          severity: 'high',
          message: `Agent making POST to financial API: ${matchedService.label} ${url.pathname}`,
          details: record,
        };
        this._alert(alert);
        alerts.push(alert);
      }

      // Rate limiting check
      const recentCalls = this.apiCallLog.filter(
        c => c.service === matchedService.label && c.timestamp > Date.now() - 60000
      );
      if (recentCalls.length > 30) {
        const alert = {
          type: 'financial_api_rate',
          severity: 'warning',
          message: `High rate of calls to ${matchedService.label}: ${recentCalls.length} in last 60s`,
          details: { service: matchedService.label, callCount: recentCalls.length },
        };
        this._alert(alert);
        alerts.push(alert);
      }
    }

    return {
      allowed: !this.allowedDomains.size || this.allowedDomains.has(domain) || !matchedService,
      service: matchedService?.label || null,
      category: matchedService?.category || null,
      alerts,
    };
  }

  // ─── Compliance Report ────────────────────────────────────────

  /**
   * Generate a compliance-ready audit report.
   * @param {Object} [options]
   * @param {string} [options.format] - 'sox' | 'pcidss' | 'standard'
   * @param {number} [options.fromTimestamp] - Start time
   * @param {number} [options.toTimestamp] - End time
   * @returns {Object} Formatted audit report
   */
  generateReport(options = {}) {
    const format = options.format || this.auditFormat;
    const from = options.fromTimestamp || 0;
    const to = options.toTimestamp || Date.now();

    const filteredLog = this.auditLog.filter(e => e.timestamp >= from && e.timestamp <= to);
    const filteredTx = this.transactions.filter(t => t.timestamp >= from && t.timestamp <= to);

    const report = {
      generatedAt: new Date().toISOString(),
      format,
      period: {
        from: new Date(from).toISOString(),
        to: new Date(to).toISOString(),
      },
      summary: {
        totalTransactions: filteredTx.length,
        approvedTransactions: filteredTx.filter(t => t.status === 'approved').length,
        deniedTransactions: filteredTx.filter(t => t.status === 'denied').length,
        pendingTransactions: filteredTx.filter(t => t.status.startsWith('pending')).length,
        totalAmount: filteredTx.filter(t => t.status === 'approved').reduce((s, t) => s + t.amount, 0),
        totalAlerts: this.alerts.filter(a => a.timestamp >= from && a.timestamp <= to).length,
        criticalAlerts: this.alerts.filter(a => a.timestamp >= from && a.timestamp <= to && a.severity === 'critical').length,
        financialApiCalls: this.apiCallLog.filter(c => c.timestamp >= from && c.timestamp <= to).length,
      },
      transactions: filteredTx,
      alerts: this.alerts.filter(a => a.timestamp >= from && a.timestamp <= to),
      auditEntries: filteredLog.length,
    };

    if (format === 'sox') {
      report.soxCompliance = {
        separationOfDuties: this.dualApprovalThreshold > 0,
        auditTrailComplete: filteredLog.length > 0,
        transactionLimitsEnforced: this.transactionLimit > 0,
        unauthorizedAccessAttempts: this.alerts.filter(a => a.type === 'financial_credential_access').length,
      };
    }

    if (format === 'pcidss') {
      report.pciCompliance = {
        cardDataDetected: this.alerts.filter(a => 
          a.details?.label?.includes('Credit card')
        ).length,
        credentialLeaks: this.alerts.filter(a => a.type === 'financial_secret_leak').length,
        accessControlEnforced: true,
        auditTrailEnabled: !!this.logPath,
      };
    }

    this._audit('compliance_report_generated', { format, entries: filteredLog.length });

    return report;
  }

  // ─── Utility Methods ──────────────────────────────────────────

  /** Get all alerts */
  getAlerts(minSeverity) {
    if (!minSeverity) return [...this.alerts];
    const levels = { low: 0, warning: 1, high: 2, critical: 3 };
    const min = levels[minSeverity] || 0;
    return this.alerts.filter(a => (levels[a.severity] || 0) >= min);
  }

  /** Get summary stats */
  getSummary() {
    return {
      transactions: this.transactions.length,
      pendingApprovals: this.pendingApprovals.size,
      alerts: this.alerts.length,
      criticalAlerts: this.alerts.filter(a => a.severity === 'critical').length,
      apiCalls: this.apiCallLog.length,
      auditEntries: this.auditLog.length,
    };
  }

  /** Reset all state */
  reset() {
    this.transactions = [];
    this.alerts = [];
    this.auditLog = [];
    this.apiCallLog = [];
    this.pendingApprovals.clear();
  }

  /** @private */
  _alert(alert) {
    alert.timestamp = alert.timestamp || Date.now();
    this.alerts.push(alert);
    if (this.onAlert) this.onAlert(alert);
  }

  /** @private */
  _audit(action, details) {
    const entry = {
      timestamp: Date.now(),
      action,
      details,
      _iso: new Date().toISOString(),
    };
    this.auditLog.push(entry);
    if (this.logPath) {
      try {
        fs.appendFileSync(this.logPath, JSON.stringify(entry) + '\n');
      } catch { /* don't let logging break functionality */ }
    }
  }
}

module.exports = {
  FinanceGuard,
  FINANCIAL_FORBIDDEN_ZONES,
  FINANCIAL_SECRET_PATTERNS,
  FINANCIAL_API_DOMAINS,
};
