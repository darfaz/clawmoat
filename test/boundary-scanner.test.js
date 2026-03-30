
const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { createPipeline, STAGES } = require('../src/boundary-scanner');


describe('createPipeline', () => {
  it('registers and runs scanners', () => {
    const pipeline = createPipeline();
    pipeline.register('pre-input', 'test-scanner', (text) => ({
      safe: text !== 'evil',
      findings: text === 'evil' ? [{ type: 'test', severity: 'high', evidence: 'evil detected' }] : [],
    }));

    const good = pipeline.scan('pre-input', 'hello');
    assert.ok(good.allowed);
    assert.equal(good.findings.length, 0);

    const bad = pipeline.scan('pre-input', 'evil');
    assert.ok(!bad.allowed);
    assert.equal(bad.findings.length, 1);
    assert.equal(bad.findings[0].scanner, 'test-scanner');
    assert.equal(bad.findings[0].stage, 'pre-input');
  });

  it('respects monitor mode', () => {
    const pipeline = createPipeline({ mode: 'monitor' });
    pipeline.register('pre-input', 'blocker', () => ({
      safe: false,
      findings: [{ type: 'test', severity: 'critical', evidence: 'blocked' }],
    }));

    const result = pipeline.scan('pre-input', 'anything');
    assert.ok(result.allowed, 'monitor mode should allow even with findings');
    assert.equal(result.findings.length, 1);
  });

  it('tracks stats', () => {
    const pipeline = createPipeline();
    pipeline.register('pre-input', 'scanner', (text) => ({
      safe: text === 'ok',
      findings: text !== 'ok' ? [{ type: 'test', severity: 'high', evidence: 'bad' }] : [],
    }));

    pipeline.scan('pre-input', 'ok');
    pipeline.scan('pre-input', 'bad');

    const stats = pipeline.getStats();
    assert.equal(stats.scanned, 2);
    assert.equal(stats.allowed, 1);
    assert.equal(stats.blocked, 1);
  });

  it('records trace', () => {
    const pipeline = createPipeline();
    pipeline.register('pre-input', 's1', () => ({ safe: true, findings: [] }));

    pipeline.scan('pre-input', 'test');
    const trace = pipeline.getTrace();
    assert.equal(trace.length, 1);
    assert.equal(trace[0].stage, 'pre-input');
    assert.ok(trace[0].allowed);
  });

  it('calls onViolation callback', () => {
    let called = false;
    const pipeline = createPipeline({
      onViolation: (stage, finding) => {
        called = true;
        assert.equal(stage, 'pre-input');
        assert.equal(finding.type, 'threat');
      },
    });
    pipeline.register('pre-input', 's', () => ({
      safe: false,
      findings: [{ type: 'threat', severity: 'high', evidence: 'x' }],
    }));
    pipeline.scan('pre-input', 'x');
    assert.ok(called);
  });

  it('rejects invalid stages', () => {
    const pipeline = createPipeline();
    assert.throws(() => pipeline.scan('invalid-stage', 'test'), /Invalid stage/);
    assert.throws(() => pipeline.register('invalid-stage', 'x', () => {}), /Invalid stage/);
  });

  it('handles per-stage mode config', () => {
    const pipeline = createPipeline({
      mode: 'enforce',
      stageConfig: {
        'pre-output': { mode: 'off' },
      },
    });
    pipeline.register('pre-output', 'scanner', () => ({
      safe: false,
      findings: [{ type: 'test', severity: 'critical', evidence: 'x' }],
    }));

    const result = pipeline.scan('pre-output', 'test');
    assert.ok(result.allowed, 'stage should be off');
    assert.equal(result.findings.length, 0);
  });

  it('handles scanner priority ordering', () => {
    const order = [];
    const pipeline = createPipeline();
    pipeline.register('pre-input', 'second', () => {
      order.push('second');
      return { safe: true, findings: [] };
    }, { priority: 20 });
    pipeline.register('pre-input', 'first', () => {
      order.push('first');
      return { safe: true, findings: [] };
    }, { priority: 10 });

    pipeline.scan('pre-input', 'test');
    assert.deepEqual(order, ['first', 'second']);
  });
});

describe('scanTurn', () => {
  it('scans a complete agent turn', () => {
    const pipeline = createPipeline();
    pipeline.register('pre-input', 'input-check', (text) => ({
      safe: !text.includes('INJECT'),
      findings: text.includes('INJECT') ? [{ type: 'injection', severity: 'critical', evidence: 'found INJECT' }] : [],
    }));
    pipeline.register('pre-output', 'output-check', (text) => ({
      safe: !text.includes('SECRET'),
      findings: text.includes('SECRET') ? [{ type: 'leak', severity: 'high', evidence: 'found SECRET' }] : [],
    }));

    const result = pipeline.scanTurn({
      input: 'Normal question',
      output: 'Normal answer',
    });
    assert.ok(result.allowed);
    assert.equal(result.findings.length, 0);

    const bad = pipeline.scanTurn({
      input: 'INJECT evil',
      output: 'Here is your SECRET',
    });
    assert.ok(!bad.allowed);
    assert.ok(bad.findings.length >= 1); // Blocks at input, may not reach output
  });

  it('stops at first blocked stage', () => {
    const pipeline = createPipeline();
    let outputScanned = false;
    pipeline.register('pre-input', 'blocker', () => ({
      safe: false,
      findings: [{ type: 'block', severity: 'critical', evidence: 'blocked' }],
    }));
    pipeline.register('pre-output', 'output', () => {
      outputScanned = true;
      return { safe: true, findings: [] };
    });

    pipeline.scanTurn({ input: 'test', output: 'test' });
    assert.ok(!outputScanned, 'output should not be scanned if input blocked');
  });

  it('scans tool calls', () => {
    const pipeline = createPipeline();
    pipeline.register('pre-tool-call', 'tool-check', (text, ctx) => ({
      safe: !text.includes('rm -rf'),
      findings: text.includes('rm -rf') ? [{ type: 'dangerous', severity: 'critical', evidence: 'rm -rf' }] : [],
    }));

    const result = pipeline.scanTurn({
      input: 'Delete everything',
      toolCalls: [
        { tool: 'exec', args: { command: 'rm -rf /' } },
      ],
    });
    assert.ok(!result.allowed);
    assert.ok(result.findings.some(f => f.evidence === 'rm -rf'));
  });
});

describe('STAGES', () => {
  it('exports all 5 stages', () => {
    assert.equal(STAGES.length, 5);
    assert.ok(STAGES.includes('pre-input'));
    assert.ok(STAGES.includes('pre-model'));
    assert.ok(STAGES.includes('pre-tool-call'));
    assert.ok(STAGES.includes('post-tool-result'));
    assert.ok(STAGES.includes('pre-output'));
  });
});
