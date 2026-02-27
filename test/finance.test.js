const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { FinanceGuard } = require('../src/finance');

describe('FinanceGuard', () => {
  describe('constructor', () => {
    it('creates with defaults', () => {
      const fg = new FinanceGuard();
      assert.equal(fg.transactionLimit, 1000);
      assert.equal(fg.dualApprovalThreshold, 10000);
      assert.equal(fg.currency, 'USD');
    });

    it('accepts custom options', () => {
      const fg = new FinanceGuard({ transactionLimit: 500, currency: 'EUR' });
      assert.equal(fg.transactionLimit, 500);
      assert.equal(fg.currency, 'EUR');
    });
  });

  describe('checkFilePath', () => {
    it('blocks Stripe credential paths', () => {
      const fg = new FinanceGuard();
      const result = fg.checkFilePath('/home/user/.stripe/config');
      assert.equal(result.allowed, false);
      assert.equal(result.findings[0].category, 'payment');
    });

    it('blocks crypto wallet files', () => {
      const fg = new FinanceGuard();
      const result = fg.checkFilePath('/home/user/.bitcoin/wallet.dat');
      assert.equal(result.allowed, false);
      assert.ok(result.findings.some(f => f.category === 'crypto'));
    });

    it('blocks MetaMask data', () => {
      const fg = new FinanceGuard();
      const result = fg.checkFilePath('/home/user/.metamask/vault');
      assert.equal(result.allowed, false);
    });

    it('blocks QuickBooks files', () => {
      const fg = new FinanceGuard();
      const result = fg.checkFilePath('/docs/company.qbw');
      assert.equal(result.allowed, false);
      assert.equal(result.findings[0].category, 'accounting');
    });

    it('blocks ACH payment files', () => {
      const fg = new FinanceGuard();
      const result = fg.checkFilePath('/transfers/payroll.ach');
      assert.equal(result.allowed, false);
      assert.equal(result.findings[0].severity, 'critical');
    });

    it('allows normal file paths', () => {
      const fg = new FinanceGuard();
      const result = fg.checkFilePath('/home/user/documents/report.pdf');
      assert.equal(result.allowed, true);
      assert.equal(result.findings.length, 0);
    });

    it('fires alert on critical access', () => {
      const alerts = [];
      const fg = new FinanceGuard({ onAlert: a => alerts.push(a) });
      fg.checkFilePath('/home/user/.stripe/key');
      assert.ok(alerts.length > 0);
      assert.equal(alerts[0].severity, 'critical');
    });
  });

  describe('scanContent', () => {
    it('detects Stripe secret keys', () => {
      const fg = new FinanceGuard();
      const result = fg.scanContent('Here is the key: sk_test_abc123def456ghi789jkl012mno');
      assert.equal(result.safe, false);
      assert.ok(result.findings.some(f => f.label.includes('Stripe')));
      assert.ok(result.redacted.includes('[REDACTED'));
    });

    it('detects credit card numbers', () => {
      const fg = new FinanceGuard();
      const result = fg.scanContent('Card: 4111111111111111');
      assert.equal(result.safe, false);
      assert.ok(result.findings.some(f => f.label.includes('Credit card')));
    });

    it('detects SSN patterns', () => {
      const fg = new FinanceGuard();
      const result = fg.scanContent('SSN: 123-45-6789');
      assert.equal(result.safe, false);
      assert.ok(result.findings.some(f => f.label.includes('SSN')));
    });

    it('detects Ethereum private keys', () => {
      const fg = new FinanceGuard();
      const result = fg.scanContent('Private key: 0x' + 'a'.repeat(64));
      assert.equal(result.safe, false);
      assert.ok(result.findings.some(f => f.label.includes('Ethereum')));
    });

    it('passes clean content', () => {
      const fg = new FinanceGuard();
      const result = fg.scanContent('This is a normal financial report with no secrets.');
      assert.equal(result.safe, true);
    });

    it('handles null/empty input', () => {
      const fg = new FinanceGuard();
      assert.equal(fg.scanContent(null).safe, true);
      assert.equal(fg.scanContent('').safe, true);
    });
  });

  describe('evaluateTransaction', () => {
    it('auto-approves small transactions', () => {
      const fg = new FinanceGuard({ transactionLimit: 1000 });
      const result = fg.evaluateTransaction({ amount: 50, type: 'payment' });
      assert.equal(result.approved, true);
      assert.equal(result.requiresApproval, false);
    });

    it('requires approval above limit', () => {
      const fg = new FinanceGuard({ transactionLimit: 1000 });
      const result = fg.evaluateTransaction({ amount: 1500, type: 'transfer' });
      assert.equal(result.approved, false);
      assert.equal(result.requiresApproval, true);
      assert.equal(result.requiresDualApproval, false);
    });

    it('requires dual approval above threshold', () => {
      const fg = new FinanceGuard({ dualApprovalThreshold: 10000 });
      const result = fg.evaluateTransaction({ amount: 15000, type: 'transfer' });
      assert.equal(result.approved, false);
      assert.equal(result.requiresDualApproval, true);
    });

    it('returns transaction ID', () => {
      const fg = new FinanceGuard();
      const result = fg.evaluateTransaction({ amount: 50, type: 'payment' });
      assert.ok(result.transactionId);
      assert.equal(result.transactionId.length, 16);
    });

    it('calls onApprovalRequired callback', () => {
      const pending = [];
      const fg = new FinanceGuard({
        transactionLimit: 100,
        onApprovalRequired: r => pending.push(r),
      });
      fg.evaluateTransaction({ amount: 500, type: 'payment' });
      assert.equal(pending.length, 1);
    });
  });

  describe('approveTransaction', () => {
    it('approves single-approval transaction', () => {
      const fg = new FinanceGuard({ transactionLimit: 100, dualApprovalThreshold: 10000 });
      const tx = fg.evaluateTransaction({ amount: 500, type: 'payment' });
      const result = fg.approveTransaction(tx.transactionId, 'admin');
      assert.equal(result.approved, true);
    });

    it('requires two approvals for dual-approval', () => {
      const fg = new FinanceGuard({ transactionLimit: 100, dualApprovalThreshold: 1000 });
      const tx = fg.evaluateTransaction({ amount: 5000, type: 'transfer' });
      
      const first = fg.approveTransaction(tx.transactionId, 'admin1');
      assert.equal(first.approved, false);
      assert.equal(first.remainingApprovals, 1);
      
      const second = fg.approveTransaction(tx.transactionId, 'admin2');
      assert.equal(second.approved, true);
    });

    it('prevents same person approving twice', () => {
      const fg = new FinanceGuard({ transactionLimit: 100, dualApprovalThreshold: 1000 });
      const tx = fg.evaluateTransaction({ amount: 5000, type: 'transfer' });
      
      fg.approveTransaction(tx.transactionId, 'admin1');
      const result = fg.approveTransaction(tx.transactionId, 'admin1');
      assert.equal(result.approved, false);
      assert.ok(result.error.includes('Same approver'));
    });

    it('handles unknown transaction ID', () => {
      const fg = new FinanceGuard();
      const result = fg.approveTransaction('nonexistent', 'admin');
      assert.equal(result.approved, false);
    });
  });

  describe('denyTransaction', () => {
    it('denies pending transaction', () => {
      const fg = new FinanceGuard({ transactionLimit: 100 });
      const tx = fg.evaluateTransaction({ amount: 500, type: 'payment' });
      const result = fg.denyTransaction(tx.transactionId, 'admin', 'Suspicious');
      assert.equal(result.denied, true);
    });

    it('handles unknown transaction', () => {
      const fg = new FinanceGuard();
      const result = fg.denyTransaction('nonexistent', 'admin');
      assert.equal(result.denied, false);
    });
  });

  describe('monitorApiCall', () => {
    it('detects Stripe API calls', () => {
      const fg = new FinanceGuard();
      const result = fg.monitorApiCall({ url: 'https://api.stripe.com/v1/charges', method: 'POST' });
      assert.equal(result.service, 'Stripe');
      assert.equal(result.category, 'payment');
      assert.ok(result.alerts.length > 0); // POST to charges is dangerous
    });

    it('detects Coinbase API calls', () => {
      const fg = new FinanceGuard();
      const result = fg.monitorApiCall({ url: 'https://api.coinbase.com/v2/accounts' });
      assert.equal(result.service, 'Coinbase');
      assert.equal(result.category, 'crypto');
    });

    it('allows non-financial URLs', () => {
      const fg = new FinanceGuard();
      const result = fg.monitorApiCall({ url: 'https://api.github.com/repos' });
      assert.equal(result.service, null);
    });

    it('handles invalid URLs', () => {
      const fg = new FinanceGuard();
      const result = fg.monitorApiCall({ url: 'not-a-url' });
      assert.equal(result.allowed, true);
    });
  });

  describe('generateReport', () => {
    it('generates SOX report', () => {
      const fg = new FinanceGuard({ auditFormat: 'sox' });
      fg.evaluateTransaction({ amount: 50, type: 'payment' });
      fg.evaluateTransaction({ amount: 200, type: 'invoice' });
      const report = fg.generateReport();
      assert.equal(report.format, 'sox');
      assert.ok(report.soxCompliance);
      assert.equal(report.summary.totalTransactions, 2);
    });

    it('generates PCI-DSS report', () => {
      const fg = new FinanceGuard();
      const report = fg.generateReport({ format: 'pcidss' });
      assert.ok(report.pciCompliance);
    });

    it('filters by time range', () => {
      const fg = new FinanceGuard();
      fg.evaluateTransaction({ amount: 50, type: 'payment' });
      const report = fg.generateReport({ fromTimestamp: Date.now() + 100000 });
      assert.equal(report.summary.totalTransactions, 0);
    });
  });

  describe('getSummary', () => {
    it('returns complete summary', () => {
      const fg = new FinanceGuard();
      fg.evaluateTransaction({ amount: 50, type: 'payment' });
      fg.scanContent('test content');
      const summary = fg.getSummary();
      assert.equal(summary.transactions, 1);
      assert.equal(typeof summary.alerts, 'number');
    });
  });

  describe('reset', () => {
    it('clears all state', () => {
      const fg = new FinanceGuard();
      fg.evaluateTransaction({ amount: 50, type: 'payment' });
      fg.reset();
      const summary = fg.getSummary();
      assert.equal(summary.transactions, 0);
      assert.equal(summary.alerts, 0);
    });
  });
});
