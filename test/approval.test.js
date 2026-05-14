/**
 * Tests for Interactive Approval Workflow
 */


const assert = require('node:assert');
const { describe, test } = require('node:test');
const fs = require('fs');
const path = require('path');
const { 
  ApprovalWorkflow, 
  ConsoleChannel, 
  WebhookChannel, 
  CallbackChannel 
} = require('../src/approval');

describe('ApprovalWorkflow', () => {
  test('should auto-deny after timeout by default', async (t) => {
    const workflow = new ApprovalWorkflow({
      defaultTimeout: 100,
      channels: [] // No channels means no approval possible
    });

    const start = Date.now();
    const result = await workflow.requestApproval({
      action: 'test_action',
      agent: 'test-agent',
      reason: 'Testing timeout behavior'
    });

    const elapsed = Date.now() - start;
    
    assert.ok(elapsed >= 100, 'Should wait for timeout');
    assert.ok(elapsed < 200, 'Should not wait much longer than timeout');
    assert.strictEqual(result.approved, false);
    assert.strictEqual(result.source, 'timeout');
    assert.ok(result.requestId);
    assert.ok(result.timestamp);
  });

  test('should auto-approve after timeout when configured', async (t) => {
    const workflow = new ApprovalWorkflow({
      defaultTimeout: 100,
      defaultAction: 'approve',
      channels: []
    });

    const result = await workflow.requestApproval({
      action: 'test_action',
      agent: 'test-agent',
      reason: 'Testing auto-approve'
    });
    
    assert.strictEqual(result.approved, true);
    assert.strictEqual(result.source, 'timeout');
  });

  test('should use custom timeout from request', async (t) => {
    const workflow = new ApprovalWorkflow({
      defaultTimeout: 1000,
      channels: []
    });

    const start = Date.now();
    const result = await workflow.requestApproval({
      action: 'test_action',
      agent: 'test-agent', 
      reason: 'Testing custom timeout',
      timeout: 150
    });

    const elapsed = Date.now() - start;
    assert.ok(elapsed >= 125, 'Should use custom timeout');
    assert.ok(elapsed < 300, 'Should not wait much longer than custom timeout');
  });
});

describe('CallbackChannel', () => {
  test('should use provided notify and check functions', async (t) => {
    let notifiedRequest = null;
    const responses = new Map();

    const channel = new CallbackChannel({
      notifyFn: async (request) => {
        notifiedRequest = request;
      },
      checkResponseFn: async (requestId) => {
        return responses.get(requestId) || null;
      }
    });

    // Test notification
    const request = {
      requestId: 'test-123',
      action: 'test_action',
      agent: 'test-agent',
      reason: 'Test reason',
      expiresAt: Date.now() + 5000
    };

    await channel.notify(request);
    assert.deepStrictEqual(notifiedRequest, request);

    // Test no response initially
    const noResponse = await channel.checkResponse('test-123');
    assert.strictEqual(noResponse, null);

    // Test with response
    responses.set('test-123', { approved: true, reason: 'Looks good' });
    const response = await channel.checkResponse('test-123');
    assert.deepStrictEqual(response, { approved: true, reason: 'Looks good' });
  });

  test('should require notifyFn and checkResponseFn', async (t) => {
    assert.throws(() => {
      new CallbackChannel({});
    }, /requires notifyFn function/);

    assert.throws(() => {
      new CallbackChannel({
        notifyFn: () => {}
      });
    }, /requires checkResponseFn function/);
  });
});

describe('ConsoleChannel', () => {
  test('should track pending requests', async (t) => {
    const channel = new ConsoleChannel();
    
    const request = {
      requestId: 'test-456',
      action: 'test_action',
      agent: 'test-agent',
      reason: 'Test reason',
      expiresAt: Date.now() + 5000
    };

    await channel.notify(request);
    assert.ok(channel.pendingRequests.has('test-456'));

    const pending = channel.pendingRequests.get('test-456');
    assert.strictEqual(pending.active, true);
    assert.strictEqual(pending.response, null);

    await channel.cleanup('test-456');
  });

  test('should cleanup pending requests', async (t) => {
    const channel = new ConsoleChannel();
    
    channel.pendingRequests.set('test-cleanup', { active: true, response: null });
    assert.ok(channel.pendingRequests.has('test-cleanup'));

    await channel.cleanup('test-cleanup');
    assert.ok(!channel.pendingRequests.has('test-cleanup'));
  });
});

describe('WebhookChannel', () => {
  test('should require webhookUrl', async (t) => {
    assert.throws(() => {
      new WebhookChannel({});
    }, /requires webhookUrl option/);
  });

  test('should create channel with valid URL', async (t) => {
    const channel = new WebhookChannel({
      webhookUrl: 'http://localhost:8080/webhook'
    });
    
    assert.strictEqual(channel.webhookUrl, 'http://localhost:8080/webhook');
    assert.strictEqual(channel.responseUrl, undefined);
    assert.strictEqual(channel.secret, undefined);
  });

  test('should handle notify without actual HTTP call', async (t) => {
    // We can't easily test actual HTTP calls in unit tests without setting up servers
    // So we just verify the channel is created correctly
    const channel = new WebhookChannel({
      webhookUrl: 'http://localhost:8080/webhook',
      responseUrl: 'http://localhost:8080/responses',
      secret: 'test-secret'
    });
    
    assert.strictEqual(channel.webhookUrl, 'http://localhost:8080/webhook');
    assert.strictEqual(channel.responseUrl, 'http://localhost:8080/responses');
    assert.strictEqual(channel.secret, 'test-secret');
  });
});

describe('ApprovalWorkflow with CallbackChannel integration', () => {
  test('should approve action when user responds positively', async (t) => {
    const responses = new Map();
    
    const channel = new CallbackChannel({
      notifyFn: async (request) => {
        // Simulate user approval after small delay
        setTimeout(() => {
          responses.set(request.requestId, { 
            approved: true, 
            reason: 'User approved via callback' 
          });
        }, 50);
      },
      checkResponseFn: async (requestId) => {
        return responses.get(requestId) || null;
      }
    });

    const workflow = new ApprovalWorkflow({
      defaultTimeout: 1000,
      channels: [channel]
    });

    const result = await workflow.requestApproval({
      action: 'delete_temp_files',
      agent: 'cleanup-bot',
      reason: 'Removing old temporary files'
    });

    assert.strictEqual(result.approved, true);
    assert.strictEqual(result.source, 'user');
    assert.strictEqual(result.reason, 'User approved via callback');
  });

  test('should deny action when user responds negatively', async (t) => {
    const responses = new Map();
    
    const channel = new CallbackChannel({
      notifyFn: async (request) => {
        setTimeout(() => {
          responses.set(request.requestId, { 
            approved: false, 
            reason: 'Too risky' 
          });
        }, 50);
      },
      checkResponseFn: async (requestId) => {
        return responses.get(requestId) || null;
      }
    });

    const workflow = new ApprovalWorkflow({
      defaultTimeout: 1000,
      channels: [channel]
    });

    const result = await workflow.requestApproval({
      action: 'system_restart',
      agent: 'maintenance-bot',
      reason: 'Apply security updates'
    });

    assert.strictEqual(result.approved, false);
    assert.strictEqual(result.source, 'user');
    assert.strictEqual(result.reason, 'Too risky');
  });

  test('should use first responding channel when multiple channels configured', async (t) => {
    const responses1 = new Map();
    const responses2 = new Map();
    
    const channel1 = new CallbackChannel({
      notifyFn: async (request) => {
        // Slow response
        setTimeout(() => {
          responses1.set(request.requestId, { approved: false });
        }, 200);
      },
      checkResponseFn: async (requestId) => responses1.get(requestId) || null
    });

    const channel2 = new CallbackChannel({
      notifyFn: async (request) => {
        // Fast response
        setTimeout(() => {
          responses2.set(request.requestId, { approved: true, reason: 'Quick approval' });
        }, 50);
      },
      checkResponseFn: async (requestId) => responses2.get(requestId) || null
    });

    const workflow = new ApprovalWorkflow({
      defaultTimeout: 1000,
      channels: [channel1, channel2]
    });

    const result = await workflow.requestApproval({
      action: 'backup_database',
      agent: 'backup-bot',
      reason: 'Daily backup routine'
    });

    // Should get the fast response from channel2
    assert.strictEqual(result.approved, true);
    assert.strictEqual(result.source, 'user');
    assert.strictEqual(result.reason, 'Quick approval');
  });
});

describe('ApprovalWorkflow audit logging', () => {
  test('should log to audit file when configured', async (t) => {
    const tmpDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'clawmoat-test-'));
    const auditPath = path.join(tmpDir, 'audit.log');
    
    const workflow = new ApprovalWorkflow({
      defaultTimeout: 100,
      auditLog: auditPath,
      channels: []
    });

    const result = await workflow.requestApproval({
      action: 'test_audit',
      agent: 'test-agent',
      reason: 'Testing audit logging'
    });

    // Check audit file exists and has content
    assert.ok(fs.existsSync(auditPath));
    const logContent = fs.readFileSync(auditPath, 'utf8');
    const lines = logContent.trim().split('\n').filter(l => l);
    
    assert.strictEqual(lines.length, 2); // request + timeout
    
    const requestEntry = JSON.parse(lines[0]);
    assert.strictEqual(requestEntry.type, 'approval_request');
    assert.strictEqual(requestEntry.action, 'test_audit');
    assert.strictEqual(requestEntry.agent, 'test-agent');
    
    const timeoutEntry = JSON.parse(lines[1]);
    assert.strictEqual(timeoutEntry.type, 'approval_timeout');
    assert.strictEqual(timeoutEntry.approved, false);

    // Cleanup
    fs.rmSync(tmpDir, { recursive: true });
  });

  test('should retrieve audit log entries with filtering', async (t) => {
    const tmpDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'clawmoat-test-'));
    const auditPath = path.join(tmpDir, 'audit.log');
    
    const workflow = new ApprovalWorkflow({
      defaultTimeout: 100,
      auditLog: auditPath,
      channels: []
    });

    // Generate some audit entries
    await workflow.requestApproval({
      action: 'action1',
      agent: 'agent1',
      reason: 'test'
    });

    await workflow.requestApproval({
      action: 'action2', 
      agent: 'agent2',
      reason: 'test'
    });

    // Test filtering
    const allEntries = await workflow.getAuditLog();
    assert.ok(allEntries.length >= 4); // 2 requests + 2 timeouts

    const agent1Entries = await workflow.getAuditLog({ agent: 'agent1' });
    assert.strictEqual(agent1Entries.length, 1);
    assert.strictEqual(agent1Entries[0].agent, 'agent1');

    const requestEntries = await workflow.getAuditLog({ type: 'approval_request' });
    assert.strictEqual(requestEntries.length, 2);

    // Cleanup
    fs.rmSync(tmpDir, { recursive: true });
  });
});