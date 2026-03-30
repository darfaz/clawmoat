/**
 * Tests for AgentMesh Governance Integration
 */


const assert = require('node:assert');
const { describe, test } = require('node:test');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { 
  AgentMeshBridge,
  OWASP_AGENTIC_MAPPING,
  DEFAULT_POLICIES,
  GOVERNANCE_ACTIONS
} = require('../src/integrations/agentmesh');

describe('AgentMeshBridge', () => {
  test('should create bridge with default policies', async (t) => {
    const bridge = new AgentMeshBridge();
    
    assert.ok(bridge);
    assert.ok(Object.keys(bridge.policies).length > 0);
    
    // Should have default policies
    assert.ok(bridge.policies['prompt_injection']);
    assert.strictEqual(bridge.policies['prompt_injection'].action, 'block');
    assert.strictEqual(bridge.policies['prompt_injection'].severity, 'high');
  });

  test('should create bridge with custom policies', async (t) => {
    const customPolicies = {
      'custom_threat': {
        action: 'alert',
        severity: 'medium',
        notify: true
      }
    };
    
    const bridge = new AgentMeshBridge({ policies: customPolicies });
    
    assert.ok(bridge.policies['custom_threat']);
    assert.strictEqual(bridge.policies['custom_threat'].action, 'alert');
    
    // Should still have default policies
    assert.ok(bridge.policies['prompt_injection']);
  });

  test('should enforce allow policy for no findings', async (t) => {
    const bridge = new AgentMeshBridge();
    
    const decision = await bridge.enforcePolicy({
      action: 'send_message',
      agent: 'test-agent',
      findings: []
    });
    
    assert.strictEqual(decision.decision, 'allow');
    assert.strictEqual(decision.reason, 'No threats detected');
    assert.strictEqual(decision.triggeredRules.length, 0);
    assert.strictEqual(decision.owaspCategory, null);
  });

  test('should enforce block policy for high-risk threats', async (t) => {
    const bridge = new AgentMeshBridge();
    
    const findings = [
      {
        type: 'prompt_injection',
        severity: 'high',
        message: 'Injection detected'
      }
    ];
    
    const decision = await bridge.enforcePolicy({
      action: 'send_message',
      agent: 'test-agent',
      findings
    });
    
    assert.strictEqual(decision.decision, 'block');
    assert.ok(decision.reason.includes('policy violation'));
    assert.ok(decision.triggeredRules.includes('prompt_injection'));
    assert.strictEqual(decision.owaspCategory, 'LLM01');
    assert.strictEqual(decision.actions.block, true);
    assert.strictEqual(decision.actions.notify, true);
  });

  test('should map findings to OWASP categories', async (t) => {
    const bridge = new AgentMeshBridge();
    
    const testCases = [
      { type: 'jailbreak', expected: 'LLM01' },
      { type: 'secret_detected', expected: 'LLM02' },
      { type: 'memory_poison', expected: 'LLM03' },
      { type: 'excessive_agency', expected: 'LLM08' }
    ];
    
    for (const testCase of testCases) {
      const decision = await bridge.enforcePolicy({
        action: 'test',
        agent: 'test-agent',
        findings: [{ type: testCase.type, severity: 'medium' }]
      });
      
      assert.strictEqual(decision.owaspCategory, testCase.expected);
    }
  });

  test('should handle multiple findings with different severities', async (t) => {
    const bridge = new AgentMeshBridge();
    
    const findings = [
      { type: 'steganographic_pattern', severity: 'low' },
      { type: 'secret_detected', severity: 'critical' }
    ];
    
    const decision = await bridge.enforcePolicy({
      action: 'send_message',
      agent: 'test-agent',
      findings
    });
    
    // Should block due to critical secret detection
    assert.strictEqual(decision.decision, 'block');
    assert.strictEqual(decision.triggeredRules.length, 2);
    assert.ok(decision.reason.includes('critical severity'));
    assert.strictEqual(decision.actions.redact, true);
  });

  test('should respect strict mode for unknown threats', async (t) => {
    const bridge = new AgentMeshBridge({ strict: true });
    
    const findings = [
      { type: 'unknown_threat_type', severity: 'medium' }
    ];
    
    const decision = await bridge.enforcePolicy({
      action: 'test',
      agent: 'test-agent',
      findings
    });
    
    assert.strictEqual(decision.decision, 'alert');
    assert.ok(decision.triggeredRules.includes('unknown_threat:unknown_threat_type'));
    assert.strictEqual(decision.actions.alert, true);
  });

  test('should track statistics correctly', async (t) => {
    const bridge = new AgentMeshBridge();
    
    // Test allow
    await bridge.enforcePolicy({
      action: 'test',
      agent: 'test-agent',
      findings: []
    });
    
    // Test block
    await bridge.enforcePolicy({
      action: 'test',
      agent: 'test-agent',
      findings: [{ type: 'prompt_injection', severity: 'high' }]
    });
    
    // Test alert
    await bridge.enforcePolicy({
      action: 'test',
      agent: 'test-agent',
      findings: [{ type: 'memory_poison', severity: 'medium' }]
    });
    
    const stats = bridge.getStats();
    assert.strictEqual(stats.decisions, 3);
    assert.strictEqual(stats.allowed, 1);
    assert.strictEqual(stats.blocked, 1);
    assert.strictEqual(stats.alerted, 1);
  });
});

describe('Policy Management', () => {
  test('should add and remove policies', async (t) => {
    const bridge = new AgentMeshBridge();
    
    // Add custom policy
    bridge.setPolicy('new_threat', {
      action: 'quarantine',
      severity: 'high',
      notify: true
    });
    
    assert.ok(bridge.policies['new_threat']);
    assert.strictEqual(bridge.policies['new_threat'].action, 'quarantine');
    
    // Remove policy
    bridge.removePolicy('new_threat');
    assert.strictEqual(bridge.policies['new_threat'], undefined);
  });

  test('should get current policies', async (t) => {
    const bridge = new AgentMeshBridge();
    
    const policies = bridge.getPolicies();
    assert.ok(typeof policies === 'object');
    assert.ok(Object.keys(policies).length > 0);
    
    // Should be a copy, not reference
    policies['test'] = 'value';
    assert.strictEqual(bridge.policies['test'], undefined);
  });

  test('should map OWASP categories', async (t) => {
    const bridge = new AgentMeshBridge();
    
    assert.strictEqual(bridge.getOwaspCategory('prompt_injection'), 'LLM01');
    assert.strictEqual(bridge.getOwaspCategory('secret_detected'), 'LLM02');
    assert.strictEqual(bridge.getOwaspCategory('nonexistent'), null);
  });
});

describe('Policy File Loading', () => {
  test('should load JSON policy file', async (t) => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentmesh-test-'));
    const policyFile = path.join(tmpDir, 'policies.json');
    
    const policies = {
      'test_threat': {
        action: 'block',
        severity: 'critical',
        notify: true
      }
    };
    
    fs.writeFileSync(policyFile, JSON.stringify(policies, null, 2));
    
    const bridge = new AgentMeshBridge({ policyFile });
    
    assert.ok(bridge.policies['test_threat']);
    assert.strictEqual(bridge.policies['test_threat'].action, 'block');
    
    // Cleanup
    fs.rmSync(tmpDir, { recursive: true });
  });

  test('should load YAML policy file', async (t) => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentmesh-test-'));
    const policyFile = path.join(tmpDir, 'policies.yml');
    
    const yamlContent = `
test_threat:
  action: alert
  severity: medium
  notify: true
  log: true

another_threat:
  action: log
  severity: low
  notify: false
`;
    
    fs.writeFileSync(policyFile, yamlContent);
    
    const bridge = new AgentMeshBridge({ policyFile });
    
    assert.ok(bridge.policies['test_threat']);
    assert.strictEqual(bridge.policies['test_threat'].action, 'alert');
    assert.strictEqual(bridge.policies['test_threat'].notify, true);
    
    assert.ok(bridge.policies['another_threat']);
    assert.strictEqual(bridge.policies['another_threat'].action, 'log');
    assert.strictEqual(bridge.policies['another_threat'].notify, false);
    
    // Cleanup
    fs.rmSync(tmpDir, { recursive: true });
  });

  test('should handle missing policy file gracefully', async (t) => {
    assert.throws(() => {
      new AgentMeshBridge({ policyFile: '/nonexistent/path.json' });
    }, /Policy file not found/);
  });

  test('should handle malformed policy file gracefully', async (t) => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentmesh-test-'));
    const policyFile = path.join(tmpDir, 'invalid.json');
    
    fs.writeFileSync(policyFile, '{invalid json}');
    
    assert.throws(() => {
      new AgentMeshBridge({ policyFile });
    }, /Failed to load policies/);
    
    // Cleanup
    fs.rmSync(tmpDir, { recursive: true });
  });
});

describe('Governance Logging', () => {
  test('should log policy decisions when configured', async (t) => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentmesh-test-'));
    const logFile = path.join(tmpDir, 'governance.log');
    
    const bridge = new AgentMeshBridge({ logFile });
    
    await bridge.enforcePolicy({
      action: 'send_message',
      agent: 'test-agent',
      findings: [{ type: 'prompt_injection', severity: 'high' }]
    });
    
    // Check log file exists and has content
    assert.ok(fs.existsSync(logFile));
    
    const logContent = fs.readFileSync(logFile, 'utf8');
    assert.ok(logContent.includes('test-agent'));
    assert.ok(logContent.includes('send_message'));
    assert.ok(logContent.includes('block'));
    
    // Cleanup
    fs.rmSync(tmpDir, { recursive: true });
  });

  test('should read and filter decision logs', async (t) => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentmesh-test-'));
    const logFile = path.join(tmpDir, 'governance.log');
    
    const bridge = new AgentMeshBridge({ logFile });
    
    // Generate some log entries
    await bridge.enforcePolicy({
      action: 'send_message',
      agent: 'agent1',
      findings: [{ type: 'prompt_injection' }]
    });
    
    await bridge.enforcePolicy({
      action: 'execute_tool',
      agent: 'agent2',
      findings: []
    });
    
    // Read logs
    const allLogs = bridge.getDecisionLog();
    assert.strictEqual(allLogs.length, 2);
    
    // Filter by agent
    const agent1Logs = bridge.getDecisionLog({ agent: 'agent1' });
    assert.strictEqual(agent1Logs.length, 1);
    assert.strictEqual(agent1Logs[0].agent, 'agent1');
    
    // Filter by decision
    const blockLogs = bridge.getDecisionLog({ decision: 'block' });
    assert.strictEqual(blockLogs.length, 1);
    
    // Cleanup
    fs.rmSync(tmpDir, { recursive: true });
  });

  test('should handle missing log file gracefully', async (t) => {
    const bridge = new AgentMeshBridge();
    
    const logs = bridge.getDecisionLog();
    assert.strictEqual(logs.length, 0);
  });
});

describe('Policy Decision Callback', () => {
  test('should execute callback on policy decisions', async (t) => {
    let callbackExecuted = false;
    let callbackContext = null;
    let callbackDecision = null;
    
    const onDecision = async (context, decision) => {
      callbackExecuted = true;
      callbackContext = context;
      callbackDecision = decision;
    };
    
    const bridge = new AgentMeshBridge({ onDecision });
    
    const context = {
      action: 'test_action',
      agent: 'test-agent',
      findings: [{ type: 'prompt_injection', severity: 'high' }]
    };
    
    const decision = await bridge.enforcePolicy(context);
    
    assert.strictEqual(callbackExecuted, true);
    assert.deepStrictEqual(callbackContext, context);
    assert.strictEqual(callbackDecision.decision, 'block');
  });

  test('should handle callback errors gracefully', async (t) => {
    const onDecision = async () => {
      throw new Error('Callback error');
    };
    
    const bridge = new AgentMeshBridge({ onDecision });
    
    // Should not throw even if callback fails
    const decision = await bridge.enforcePolicy({
      action: 'test',
      agent: 'test-agent',
      findings: []
    });
    
    assert.strictEqual(decision.decision, 'allow');
  });
});

describe('Complex Policy Scenarios', () => {
  test('should handle mixed threat levels correctly', async (t) => {
    const bridge = new AgentMeshBridge();
    
    const findings = [
      { type: 'steganographic_pattern', severity: 'low' },    // log action
      { type: 'memory_poison', severity: 'medium' },         // alert action
      { type: 'prompt_injection', severity: 'high' }         // block action
    ];
    
    const decision = await bridge.enforcePolicy({
      action: 'complex_operation',
      agent: 'test-agent',
      findings
    });
    
    // Highest severity action should win (block)
    assert.strictEqual(decision.decision, 'block');
    assert.strictEqual(decision.triggeredRules.length, 3);
    assert.strictEqual(decision.actions.block, true);
    assert.strictEqual(decision.actions.alert, true);
    assert.strictEqual(decision.actions.log, true);
    assert.strictEqual(decision.actions.notify, true);
  });

  test('should generate meaningful reasons', async (t) => {
    const bridge = new AgentMeshBridge();
    
    const findings = [
      { type: 'jailbreak', severity: 'high' },
      { type: 'secret_detected', severity: 'critical' }
    ];
    
    const decision = await bridge.enforcePolicy({
      action: 'send_response',
      agent: 'test-agent',
      findings
    });
    
    assert.ok(decision.reason.includes('2 policy violation(s) detected'));
    assert.ok(decision.reason.includes('jailbreak, secret_detected'));
    assert.ok(decision.reason.includes('critical severity'));
    assert.ok(decision.reason.includes('OWASP LLM01'));
  });

  test('should handle empty and undefined contexts gracefully', async (t) => {
    const bridge = new AgentMeshBridge();
    
    const decision1 = await bridge.enforcePolicy({
      action: 'test',
      agent: 'test-agent'
      // No findings property
    });
    
    assert.strictEqual(decision1.decision, 'allow');
    
    const decision2 = await bridge.enforcePolicy({
      action: 'test',
      agent: 'test-agent',
      findings: undefined
    });
    
    assert.strictEqual(decision2.decision, 'allow');
  });
});

describe('Constants and Exports', () => {
  test('should export OWASP mapping constants', async (t) => {
    assert.ok(typeof OWASP_AGENTIC_MAPPING === 'object');
    assert.strictEqual(OWASP_AGENTIC_MAPPING['prompt_injection'], 'LLM01');
    assert.strictEqual(OWASP_AGENTIC_MAPPING['secret_detected'], 'LLM02');
  });

  test('should export default policies', async (t) => {
    assert.ok(typeof DEFAULT_POLICIES === 'object');
    assert.ok(DEFAULT_POLICIES['prompt_injection']);
    assert.strictEqual(DEFAULT_POLICIES['prompt_injection'].action, 'block');
  });

  test('should export governance actions', async (t) => {
    assert.ok(typeof GOVERNANCE_ACTIONS === 'object');
    assert.strictEqual(GOVERNANCE_ACTIONS.ALLOW, 'allow');
    assert.strictEqual(GOVERNANCE_ACTIONS.BLOCK, 'block');
  });
});