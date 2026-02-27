const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { McpFirewall } = require('../src/finance/mcp-firewall');

describe('McpFirewall', () => {
  describe('constructor', () => {
    it('creates with defaults', () => {
      const fw = new McpFirewall();
      assert.equal(fw.mode, 'read-only');
      assert.equal(fw.rateLimit, 60);
    });

    it('accepts custom options', () => {
      const fw = new McpFirewall({ mode: 'audit-only', rateLimit: 10 });
      assert.equal(fw.mode, 'audit-only');
      assert.equal(fw.rateLimit, 10);
    });
  });

  describe('intercept — read-only mode', () => {
    it('allows read operations', () => {
      const fw = new McpFirewall();
      const r = fw.intercept({ tool: 'get_invoices', server: 'quickbooks-mcp' });
      assert.equal(r.allowed, true);
      assert.equal(r.blocked, false);
    });

    it('blocks create operations', () => {
      const fw = new McpFirewall();
      const r = fw.intercept({ tool: 'create_invoice', server: 'quickbooks-mcp' });
      assert.equal(r.blocked, true);
      assert.ok(r.reason.includes('read-only'));
    });

    it('blocks update operations', () => {
      const fw = new McpFirewall();
      const r = fw.intercept({ tool: 'update_customer', server: 'quickbooks-mcp' });
      assert.equal(r.blocked, true);
    });

    it('blocks delete operations', () => {
      const fw = new McpFirewall();
      assert.equal(fw.intercept({ tool: 'delete_invoice' }).blocked, true);
    });

    it('blocks send operations', () => {
      const fw = new McpFirewall();
      assert.equal(fw.intercept({ tool: 'send_payment' }).blocked, true);
    });

    it('blocks transfer operations', () => {
      const fw = new McpFirewall();
      assert.equal(fw.intercept({ tool: 'transfer_funds' }).blocked, true);
    });

    it('blocks refund operations', () => {
      const fw = new McpFirewall();
      assert.equal(fw.intercept({ tool: 'refund_payment' }).blocked, true);
    });

    it('blocks void operations', () => {
      const fw = new McpFirewall();
      assert.equal(fw.intercept({ tool: 'void_invoice' }).blocked, true);
    });

    it('blocks batch operations', () => {
      const fw = new McpFirewall();
      assert.equal(fw.intercept({ tool: 'batch_import' }).blocked, true);
    });
  });

  describe('intercept — read-write mode', () => {
    it('allows write operations', () => {
      const fw = new McpFirewall({ mode: 'read-write' });
      const r = fw.intercept({ tool: 'create_invoice', server: 'quickbooks-mcp' });
      assert.equal(r.allowed, true);
    });
  });

  describe('intercept — allowlist', () => {
    it('blocks tools not in allowlist', () => {
      const fw = new McpFirewall({ allowedTools: ['get_invoices', 'get_customers'] });
      const r = fw.intercept({ tool: 'get_profit_loss' });
      assert.equal(r.blocked, true);
      assert.ok(r.reason.includes('allowlist'));
    });

    it('allows tools in allowlist', () => {
      const fw = new McpFirewall({ allowedTools: ['get_invoices'] });
      const r = fw.intercept({ tool: 'get_invoices' });
      assert.equal(r.allowed, true);
    });

    it('allowlist is case-insensitive', () => {
      const fw = new McpFirewall({ allowedTools: ['Get_Invoices'] });
      assert.equal(fw.intercept({ tool: 'get_invoices' }).allowed, true);
    });
  });

  describe('intercept — blocklist', () => {
    it('blocks explicitly blocked tools', () => {
      const fw = new McpFirewall({ mode: 'read-write', blockedTools: ['get_ssn_report'] });
      const r = fw.intercept({ tool: 'get_ssn_report' });
      assert.equal(r.blocked, true);
      assert.ok(r.reason.includes('explicitly blocked'));
    });
  });

  describe('intercept — rate limiting', () => {
    it('blocks after rate limit exceeded', () => {
      const fw = new McpFirewall({ rateLimit: 3 });
      fw.intercept({ tool: 'get_invoices' });
      fw.intercept({ tool: 'get_invoices' });
      fw.intercept({ tool: 'get_invoices' });
      const r = fw.intercept({ tool: 'get_invoices' });
      assert.equal(r.blocked, true);
      assert.ok(r.reason.includes('Rate limit'));
    });

    it('rate limits per-tool', () => {
      const fw = new McpFirewall({ rateLimit: 2 });
      fw.intercept({ tool: 'get_invoices' });
      fw.intercept({ tool: 'get_invoices' });
      // Different tool should still work
      const r = fw.intercept({ tool: 'get_customers' });
      assert.equal(r.allowed, true);
    });
  });

  describe('intercept — callbacks', () => {
    it('calls onBlock when blocked', () => {
      const blocked = [];
      const fw = new McpFirewall({ onBlock: e => blocked.push(e) });
      fw.intercept({ tool: 'create_invoice' });
      assert.equal(blocked.length, 1);
      assert.equal(blocked[0].tool, 'create_invoice');
    });

    it('calls onCall on every call', () => {
      const calls = [];
      const fw = new McpFirewall({ onCall: e => calls.push(e) });
      fw.intercept({ tool: 'get_invoices' });
      fw.intercept({ tool: 'create_invoice' });
      assert.equal(calls.length, 2);
    });
  });

  describe('intercept — server identification', () => {
    it('identifies QuickBooks server', () => {
      const fw = new McpFirewall();
      const r = fw.intercept({ tool: 'get_invoices', server: 'quickbooks-mcp' });
      assert.equal(r.serverInfo.label, 'QuickBooks');
      assert.equal(r.serverInfo.category, 'accounting');
    });

    it('identifies Stripe server', () => {
      const fw = new McpFirewall();
      const r = fw.intercept({ tool: 'get_charges', server: 'stripe-mcp-server' });
      assert.equal(r.serverInfo.label, 'Stripe');
    });

    it('returns null for unknown server', () => {
      const fw = new McpFirewall();
      const r = fw.intercept({ tool: 'get_data', server: 'my-custom-server' });
      assert.equal(r.serverInfo, null);
    });
  });

  describe('redactResponse', () => {
    it('redacts SSN fields', () => {
      const fw = new McpFirewall();
      const r = fw.redactResponse({ name: 'John', ssn: '123-45-6789' });
      assert.equal(r.redacted.ssn, '***-**-****');
      assert.equal(r.redacted.name, 'John');
      assert.equal(r.fieldCount, 1);
    });

    it('redacts bank account numbers', () => {
      const fw = new McpFirewall();
      const r = fw.redactResponse({ bank_account: '12345678', routing_number: '021000021' });
      assert.equal(r.redacted.bank_account, '****XXXX');
      assert.equal(r.redacted.routing_number, '*********');
      assert.equal(r.fieldCount, 2);
    });

    it('redacts nested objects', () => {
      const fw = new McpFirewall();
      const r = fw.redactResponse({
        customer: { name: 'Acme', tax_id: '12-3456789' },
      });
      assert.equal(r.redacted.customer.tax_id, '**-*******');
      assert.equal(r.redacted.customer.name, 'Acme');
    });

    it('redacts inside arrays', () => {
      const fw = new McpFirewall();
      const r = fw.redactResponse({
        employees: [
          { name: 'Alice', ssn: '111-22-3333' },
          { name: 'Bob', ssn: '444-55-6666' },
        ],
      });
      assert.equal(r.redacted.employees[0].ssn, '***-**-****');
      assert.equal(r.redacted.employees[1].ssn, '***-**-****');
      assert.equal(r.fieldCount, 2);
    });

    it('redacts API keys and tokens', () => {
      const fw = new McpFirewall();
      const r = fw.redactResponse({ api_key: 'sk_live_abc123', access_token: 'tok_xyz' });
      assert.equal(r.redacted.api_key, '[REDACTED]');
      assert.equal(r.redacted.access_token, '[REDACTED]');
    });

    it('handles null/undefined gracefully', () => {
      const fw = new McpFirewall();
      assert.equal(fw.redactResponse(null).redacted, null);
      assert.equal(fw.redactResponse(undefined).redacted, undefined);
    });

    it('skips redaction when disabled', () => {
      const fw = new McpFirewall({ redactResponses: false });
      const r = fw.redactResponse({ ssn: '123-45-6789' });
      assert.equal(r.redacted.ssn, '123-45-6789');
      assert.equal(r.fieldCount, 0);
    });

    it('handles custom redact fields', () => {
      const fw = new McpFirewall({ redactFields: ['salary', 'bonus'] });
      const r = fw.redactResponse({ name: 'Alice', salary: 120000, bonus: 15000 });
      assert.equal(r.redacted.salary, '[REDACTED]');
      assert.equal(r.redacted.bonus, '[REDACTED]');
      assert.equal(r.redacted.name, 'Alice');
    });
  });

  describe('guard (full pipeline)', () => {
    it('blocks and returns null response', async () => {
      const fw = new McpFirewall();
      const result = await fw.guard(
        { tool: 'create_invoice', server: 'quickbooks-mcp' },
        async () => ({ id: 123 })
      );
      assert.equal(result.blocked, true);
      assert.equal(result.response, null);
    });

    it('allows and redacts response', async () => {
      const fw = new McpFirewall();
      const result = await fw.guard(
        { tool: 'get_customer', server: 'quickbooks-mcp' },
        async () => ({ name: 'Acme', tax_id: '12-3456789', balance: 5000 })
      );
      assert.equal(result.allowed, true);
      assert.equal(result.response.tax_id, '**-*******');
      assert.equal(result.response.balance, 5000);
    });
  });

  describe('classifyTools', () => {
    it('classifies read vs write tools', () => {
      const fw = new McpFirewall();
      const result = fw.classifyTools([
        'get_invoices', 'list_customers', 'create_invoice',
        'update_customer', 'delete_payment', 'query_reports',
        'send_invoice', 'refund_charge', 'search_transactions',
      ]);
      assert.equal(result.read.length, 4);
      assert.equal(result.write.length, 5);
      assert.ok(result.recommended_allowlist.includes('get_invoices'));
      assert.ok(!result.recommended_allowlist.includes('create_invoice'));
    });
  });

  describe('getAuditSummary', () => {
    it('returns complete summary', () => {
      const fw = new McpFirewall();
      fw.intercept({ tool: 'get_invoices' });
      fw.intercept({ tool: 'create_invoice' });
      const summary = fw.getAuditSummary();
      assert.equal(summary.total, 2);
      assert.equal(summary.allowed, 1);
      assert.equal(summary.blocked, 1);
    });
  });

  describe('getBlockedCalls', () => {
    it('returns only blocked calls', () => {
      const fw = new McpFirewall();
      fw.intercept({ tool: 'get_invoices' });
      fw.intercept({ tool: 'create_invoice' });
      fw.intercept({ tool: 'delete_customer' });
      const blocked = fw.getBlockedCalls();
      assert.equal(blocked.length, 2);
    });
  });

  describe('reset', () => {
    it('clears all state', () => {
      const fw = new McpFirewall();
      fw.intercept({ tool: 'get_invoices' });
      fw.reset();
      assert.equal(fw.getAuditSummary().total, 0);
    });
  });
});
