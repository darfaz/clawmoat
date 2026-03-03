/**
 * Tests for JSON formatter
 */

const { describe, it } = require('node:test');
const { strictEqual, ok, deepStrictEqual } = require('node:assert');
const { formatReport, formatScanResult, formatAuditResult } = require('../src/formatters/json');

describe('JSON Formatter', () => {
  
  describe('formatReport', () => {
    it('formats report data correctly', () => {
      const reportData = {
        recentFiles: 5,
        totalEntries: 100,
        toolCalls: 25,
        threats: 3,
        toolUsage: { 'exec': 10, 'read': 8 },
        netResult: {
          totalUrls: 15,
          domains: ['example.com', 'test.org'],
          flagged: ['suspicious.com'],
          badDomains: [{ domain: 'evil.com', file: 'session1.jsonl' }]
        },
        insiderThreats: 1,
        insiderHighScore: 75,
        findings: [
          { type: 'prompt_injection', severity: 'high', reason: 'Test finding' }
        ]
      };

      const result = formatReport(reportData);

      strictEqual(result.version, '0.9.0');
      strictEqual(result.period, '24h');
      ok(result.timestamp);
      ok(result.period_start);
      ok(result.period_end);

      strictEqual(result.summary.sessions_active, 5);
      strictEqual(result.summary.total_entries, 100);
      strictEqual(result.summary.tool_calls, 25);
      strictEqual(result.summary.threats_detected, 3);
      strictEqual(result.summary.insider_threats, 1);
      strictEqual(result.summary.highest_insider_risk_score, 75);

      deepStrictEqual(result.tool_usage, { 'exec': 10, 'read': 8 });

      strictEqual(result.network_egress.total_urls, 15);
      strictEqual(result.network_egress.unique_domains, 2);
      deepStrictEqual(result.network_egress.flagged_domains, ['suspicious.com']);
      strictEqual(result.network_egress.bad_domains.length, 1);

      strictEqual(result.findings.length, 1);
    });

    it('handles missing data gracefully', () => {
      const result = formatReport({});

      strictEqual(result.summary.sessions_active, 0);
      strictEqual(result.summary.total_entries, 0);
      strictEqual(result.summary.tool_calls, 0);
      deepStrictEqual(result.tool_usage, {});
      strictEqual(result.findings.length, 0);
    });
  });

  describe('formatScanResult', () => {
    it('formats scan result correctly', () => {
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
            reason: 'API key detected'
          }
        ],
        context: 'user_input'
      };

      const result = formatScanResult(scanResult);

      strictEqual(result.version, '0.9.0');
      strictEqual(result.safe, false);
      strictEqual(result.total_findings, 2);
      strictEqual(result.scan_context, 'user_input');
      ok(result.timestamp);

      const finding1 = result.findings[0];
      strictEqual(finding1.type, 'prompt_injection');
      strictEqual(finding1.subtype, 'instruction_override');
      strictEqual(finding1.severity, 'critical');
      strictEqual(finding1.message, 'Detected instruction override');
      strictEqual(finding1.matched_text, 'ignore all previous');
      strictEqual(finding1.confidence, 0.95);

      const finding2 = result.findings[1];
      strictEqual(finding2.type, 'secret_leak');
      strictEqual(finding2.subtype, null);
      strictEqual(finding2.severity, 'high');
      strictEqual(finding2.confidence, 1.0); // default
    });

    it('handles safe scan result', () => {
      const scanResult = { safe: true, findings: [] };
      const result = formatScanResult(scanResult);

      strictEqual(result.safe, true);
      strictEqual(result.total_findings, 0);
      strictEqual(result.findings.length, 0);
    });
  });

  describe('formatAuditResult', () => {
    it('formats audit result correctly', () => {
      const auditData = {
        filesScanned: 10,
        totalFindings: 3,
        sessionDir: '/path/to/sessions',
        findingsByFile: { 'session1.jsonl': 2, 'session2.jsonl': 1 },
        findings: [
          { type: 'threat', severity: 'medium', message: 'Test finding' }
        ]
      };

      const result = formatAuditResult(auditData);

      strictEqual(result.version, '0.9.0');
      strictEqual(result.summary.files_scanned, 10);
      strictEqual(result.summary.total_findings, 3);
      strictEqual(result.summary.sessions_directory, '/path/to/sessions');
      strictEqual(result.scan_context, 'session_audit');
      ok(result.timestamp);

      deepStrictEqual(result.findings_by_file, { 'session1.jsonl': 2, 'session2.jsonl': 1 });
      strictEqual(result.findings.length, 1);
    });
  });
});