/**
 * JSON Report Formatter for ClawMoat
 *
 * Converts scan and report data into structured JSON format
 * for programmatic consumption by monitoring dashboards, CI/CD, etc.
 */

const VERSION = require('../../package.json').version;

function formatReport(reportData) {
  const timestamp = new Date().toISOString();
  const period = '24h'; // Last 24 hours, as per current implementation
  
  return {
    timestamp,
    period,
    version: VERSION,
    summary: {
      sessions_active: reportData.recentFiles || 0,
      total_entries: reportData.totalEntries || 0,
      tool_calls: reportData.toolCalls || 0,
      threats_detected: reportData.threats || 0,
      insider_threats: reportData.insiderThreats || 0,
      highest_insider_risk_score: reportData.insiderHighScore || 0
    },
    tool_usage: reportData.toolUsage || {},
    network_egress: {
      total_urls: reportData.netResult?.totalUrls || 0,
      unique_domains: reportData.netResult?.domains?.length || 0,
      flagged_domains: reportData.netResult?.flagged || [],
      bad_domains: reportData.netResult?.badDomains || []
    },
    findings: reportData.findings || [],
    period_start: new Date(Date.now() - 86400000).toISOString(),
    period_end: timestamp
  };
}

function formatScanResult(result) {
  const timestamp = new Date().toISOString();
  
  return {
    timestamp,
    version: VERSION,
    safe: result.safe || false,
    total_findings: result.findings?.length || 0,
    findings: (result.findings || []).map(finding => ({
      type: finding.type,
      subtype: finding.subtype || null,
      severity: finding.severity || 'medium',
      message: finding.reason || finding.type,
      matched_text: finding.matched || null,
      confidence: finding.confidence || 1.0
    })),
    scan_context: result.context || 'unknown'
  };
}

function formatAuditResult(auditData) {
  const timestamp = new Date().toISOString();
  
  return {
    timestamp,
    version: VERSION,
    summary: {
      files_scanned: auditData.filesScanned || 0,
      total_findings: auditData.totalFindings || 0,
      sessions_directory: auditData.sessionDir || 'unknown'
    },
    findings_by_file: auditData.findingsByFile || {},
    findings: auditData.findings || [],
    scan_context: 'session_audit'
  };
}

module.exports = {
  formatReport,
  formatScanResult, 
  formatAuditResult
};