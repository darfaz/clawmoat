/**
 * Tests for SARIF formatter
 */

const { describe, it } = require('node:test');
const { strictEqual, ok, deepStrictEqual } = require('node:assert');
const { formatScanResultAsSarif, formatAuditResultAsSarif } = require('../src/formatters/sarif');

describe('SARIF Formatter', () => {
  
  describe('formatScanResultAsSarif', () => {
    it('formats scan result as valid SARIF', () => {
      const scanResult = {
        safe: false,
        findings: [
          {
            type: 'prompt_injection',
            subtype: 'instruction_override',
            severity: 'critical',
            reason: 'Detected instruction override',
            matched: 'ignore all previous',
            confidence: 0.95
          },
          {
            type: 'secret_leak',
            severity: 'high',
            reason: 'API key detected',
            matched: 'sk-1234567890'
          }
        ]
      };

      const result = formatScanResultAsSarif(scanResult, 'test-file.txt');

      // Validate SARIF structure
      strictEqual(result.$schema, 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json');
      strictEqual(result.version, '2.1.0');
      strictEqual(result.runs.length, 1);

      const run = result.runs[0];
      strictEqual(run.tool.driver.name, 'ClawMoat');
      strictEqual(run.tool.driver.version, '0.9.0');
      ok(run.tool.driver.informationUri);
      
      // Check rules
      ok(run.tool.driver.rules.length >= 2);
      const promptInjectionRule = run.tool.driver.rules.find(r => r.id === 'clawmoat/prompt-injection');
      ok(promptInjectionRule);
      strictEqual(promptInjectionRule.name, 'PromptInjection');
      
      // Check results
      strictEqual(run.results.length, 2);
      const firstResult = run.results[0];
      strictEqual(firstResult.ruleId, 'clawmoat/prompt-injection');
      strictEqual(firstResult.level, 'error'); // critical maps to error
      strictEqual(firstResult.message.text, 'Detected instruction override');
      
      // Check location
      ok(firstResult.locations);
      strictEqual(firstResult.locations[0].physicalLocation.artifactLocation.uri, 'test-file.txt');
      strictEqual(firstResult.locations[0].physicalLocation.region.snippet.text, 'ignore all previous');
      
      // Check artifacts
      strictEqual(run.artifacts.length, 1);
      strictEqual(run.artifacts[0].location.uri, 'test-file.txt');
    });

    it('handles safe scan result', () => {
      const scanResult = { safe: true, findings: [] };
      const result = formatScanResultAsSarif(scanResult);

      strictEqual(result.runs[0].results.length, 0);
      strictEqual(result.runs[0].tool.driver.rules.length, 0);
    });

    it('maps severities correctly', () => {
      const scanResult = {
        safe: false,
        findings: [
          { type: 'test', severity: 'critical' },
          { type: 'test', severity: 'high' },
          { type: 'test', severity: 'medium' },
          { type: 'test', severity: 'low' }
        ]
      };

      const result = formatScanResultAsSarif(scanResult);
      const results = result.runs[0].results;
      
      strictEqual(results[0].level, 'error');   // critical -> error
      strictEqual(results[1].level, 'error');   // high -> error  
      strictEqual(results[2].level, 'warning'); // medium -> warning
      strictEqual(results[3].level, 'note');    // low -> note
    });

    it('creates default rules for unknown finding types', () => {
      const scanResult = {
        safe: false,
        findings: [
          { type: 'unknown_threat_type', severity: 'medium', reason: 'Unknown threat' }
        ]
      };

      const result = formatScanResultAsSarif(scanResult);
      const rules = result.runs[0].tool.driver.rules;
      
      strictEqual(rules.length, 1);
      strictEqual(rules[0].id, 'clawmoat/unknown_threat_type');
      ok(rules[0].shortDescription.text.includes('unknown_threat_type'));
    });
  });

  describe('formatAuditResultAsSarif', () => {
    it('formats audit result with multiple files', () => {
      const auditData = {
        filesScanned: 3,
        totalFindings: 2,
        sessionDir: '/path/to/sessions',
        findings: [
          {
            type: 'prompt_injection',
            severity: 'high',
            reason: 'Threat detected',
            source: 'session1.jsonl',
            timestamp: '2023-01-01T00:00:00Z',
            entry_id: 'entry-123'
          },
          {
            type: 'tool_policy_violation',
            severity: 'medium',
            reason: 'Tool blocked',
            source: 'session2.jsonl',
            timestamp: '2023-01-01T00:01:00Z',
            entry_id: 'entry-456'
          }
        ]
      };

      const result = formatAuditResultAsSarif(auditData);

      strictEqual(result.runs[0].results.length, 2);
      strictEqual(result.runs[0].artifacts.length, 2);

      // Check first result
      const firstResult = result.runs[0].results[0];
      strictEqual(firstResult.ruleId, 'clawmoat/prompt-injection');
      strictEqual(firstResult.locations[0].physicalLocation.artifactLocation.uri, 'session1.jsonl');
      strictEqual(firstResult.properties.entry_id, 'entry-123');

      // Check artifacts
      const artifactUris = result.runs[0].artifacts.map(a => a.location.uri).sort();
      deepStrictEqual(artifactUris, ['session1.jsonl', 'session2.jsonl']);
    });

    it('handles empty audit result', () => {
      const auditData = {
        filesScanned: 0,
        totalFindings: 0,
        findings: []
      };

      const result = formatAuditResultAsSarif(auditData);
      
      strictEqual(result.runs[0].results.length, 0);
      strictEqual(result.runs[0].tool.driver.rules.length, 0);
      strictEqual(result.runs[0].artifacts.length, 0);
    });
  });

  describe('SARIF structure validation', () => {
    it('includes required SARIF properties', () => {
      const scanResult = {
        safe: false,
        findings: [{ type: 'test', severity: 'medium' }]
      };

      const result = formatScanResultAsSarif(scanResult);

      // Required top-level properties
      ok(result.$schema);
      ok(result.version);
      ok(result.runs);

      // Required run properties  
      const run = result.runs[0];
      ok(run.tool);
      ok(run.results);
      ok(run.invocations);

      // Required tool properties
      ok(run.tool.driver.name);
      ok(run.tool.driver.version);
      ok(run.tool.driver.informationUri);

      // Required result properties
      if (run.results.length > 0) {
        const firstResult = run.results[0];
        ok(firstResult.ruleId);
        ok(typeof firstResult.ruleIndex === 'number');
        ok(firstResult.level);
        ok(firstResult.message);
        ok(firstResult.locations);
      }
    });

    it('creates fingerprints for results', () => {
      const scanResult = {
        safe: false, 
        findings: [
          { type: 'test', matched: 'some text', severity: 'medium' },
          { type: 'test', matched: 'different text', severity: 'medium' }
        ]
      };

      const result = formatScanResultAsSarif(scanResult);
      const results = result.runs[0].results;
      
      // Should have different fingerprints for different content
      ok(results[0].partialFingerprints.primaryLocationLineHash);
      ok(results[1].partialFingerprints.primaryLocationLineHash);
      ok(results[0].partialFingerprints.primaryLocationLineHash !== 
         results[1].partialFingerprints.primaryLocationLineHash);
    });
  });
});