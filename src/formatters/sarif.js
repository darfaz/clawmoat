/**
 * SARIF (Static Analysis Results Interchange Format) Output
 * 
 * Converts ClawMoat scan results to SARIF v2.1.0 JSON format
 * for integration with GitHub Code Scanning, Azure DevOps, etc.
 */

const VERSION = require('../../package.json').version;

// Map ClawMoat severities to SARIF levels
const SEVERITY_MAP = {
  'critical': 'error',
  'high': 'error', 
  'medium': 'warning',
  'low': 'note'
};

// Define SARIF rules for ClawMoat detectors
const RULES = {
  'prompt_injection': {
    id: 'clawmoat/prompt-injection',
    name: 'PromptInjection',
    shortDescription: { text: 'Prompt injection attack detected' },
    fullDescription: { text: 'Detects attempts to override AI system instructions or manipulate behavior through malicious prompts.' },
    defaultConfiguration: { level: 'error' },
    helpUri: 'https://github.com/darfaz/clawmoat/wiki/prompt-injection',
    properties: {
      category: 'security',
      tags: ['ai-security', 'prompt-injection']
    }
  },
  'jailbreak': {
    id: 'clawmoat/jailbreak',
    name: 'JailbreakAttempt', 
    shortDescription: { text: 'AI jailbreak attempt detected' },
    fullDescription: { text: 'Detects attempts to bypass AI safety mechanisms through role-playing or mode-switching attacks.' },
    defaultConfiguration: { level: 'error' },
    helpUri: 'https://github.com/darfaz/clawmoat/wiki/jailbreak',
    properties: {
      category: 'security',
      tags: ['ai-security', 'jailbreak']
    }
  },
  'secret_leak': {
    id: 'clawmoat/secret-leak',
    name: 'SecretLeak',
    shortDescription: { text: 'Secret or credential detected' },
    fullDescription: { text: 'Detects API keys, tokens, passwords, or other sensitive credentials in content.' },
    defaultConfiguration: { level: 'error' },
    helpUri: 'https://github.com/darfaz/clawmoat/wiki/secret-detection',
    properties: {
      category: 'security',
      tags: ['credentials', 'secrets']
    }
  },
  'pii_leak': {
    id: 'clawmoat/pii-leak', 
    name: 'PersonallyIdentifiableInformation',
    shortDescription: { text: 'PII detected in output' },
    fullDescription: { text: 'Detects personally identifiable information such as SSN, credit card numbers, or email addresses.' },
    defaultConfiguration: { level: 'warning' },
    helpUri: 'https://github.com/darfaz/clawmoat/wiki/pii-detection',
    properties: {
      category: 'privacy',
      tags: ['pii', 'privacy']
    }
  },
  'url_suspicious': {
    id: 'clawmoat/suspicious-url',
    name: 'SuspiciousUrl',
    shortDescription: { text: 'Suspicious URL detected' },
    fullDescription: { text: 'Detects potentially malicious URLs including IP addresses, data URLs, or suspicious domains.' },
    defaultConfiguration: { level: 'warning' },
    helpUri: 'https://github.com/darfaz/clawmoat/wiki/url-detection',
    properties: {
      category: 'security',
      tags: ['urls', 'phishing']
    }
  },
  'memory_poisoning': {
    id: 'clawmoat/memory-poisoning',
    name: 'MemoryPoisoning',
    shortDescription: { text: 'Memory poisoning attempt detected' },
    fullDescription: { text: 'Detects attempts to modify AI memory files or inject persistent malicious instructions.' },
    defaultConfiguration: { level: 'error' },
    helpUri: 'https://github.com/darfaz/clawmoat/wiki/memory-poisoning',
    properties: {
      category: 'security',
      tags: ['ai-security', 'memory-poisoning']
    }
  },
  'exfiltration': {
    id: 'clawmoat/data-exfiltration',
    name: 'DataExfiltration',
    shortDescription: { text: 'Data exfiltration attempt detected' },
    fullDescription: { text: 'Detects commands or patterns that could be used to steal or upload sensitive data.' },
    defaultConfiguration: { level: 'error' },
    helpUri: 'https://github.com/darfaz/clawmoat/wiki/exfiltration',
    properties: {
      category: 'security',
      tags: ['exfiltration', 'data-theft']
    }
  },
  'excessive_agency': {
    id: 'clawmoat/excessive-agency',
    name: 'ExcessiveAgency', 
    shortDescription: { text: 'Excessive privilege or agency request' },
    fullDescription: { text: 'Detects attempts to gain unauthorized privileges, bypass approvals, or operate autonomously.' },
    defaultConfiguration: { level: 'warning' },
    helpUri: 'https://github.com/darfaz/clawmoat/wiki/excessive-agency',
    properties: {
      category: 'security',
      tags: ['privilege-escalation', 'agency']
    }
  },
  'supply_chain': {
    id: 'clawmoat/supply-chain',
    name: 'SupplyChainThreat',
    shortDescription: { text: 'Supply chain threat detected' },
    fullDescription: { text: 'Detects malicious patterns in skill content or external dependencies.' },
    defaultConfiguration: { level: 'error' },
    helpUri: 'https://github.com/darfaz/clawmoat/wiki/supply-chain',
    properties: {
      category: 'security', 
      tags: ['supply-chain', 'malware']
    }
  },
  'insider_threat': {
    id: 'clawmoat/insider-threat',
    name: 'InsiderThreat',
    shortDescription: { text: 'Insider threat behavior detected' },
    fullDescription: { text: 'Detects AI behaviors indicative of insider threats such as self-preservation, blackmail, or deception.' },
    defaultConfiguration: { level: 'error' },
    helpUri: 'https://github.com/darfaz/clawmoat/wiki/insider-threats',
    properties: {
      category: 'security',
      tags: ['insider-threat', 'ai-alignment']
    }
  }
};

function formatScanResultAsSarif(scanResult, sourceFile = 'stdin') {
  const timestamp = new Date().toISOString();
  const usedRules = new Set();
  const results = [];

  // Convert findings to SARIF results
  if (scanResult.findings) {
    for (const finding of scanResult.findings) {
      const ruleId = getRuleIdForFinding(finding);
      usedRules.add(ruleId);
      
      const result = {
        ruleId,
        ruleIndex: 0, // Will be updated after we know the rule order
        level: SEVERITY_MAP[finding.severity] || 'warning',
        message: {
          text: finding.reason || finding.type || 'Security threat detected'
        },
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: sourceFile,
              uriBaseId: '%SRCROOT%'
            },
            region: {
              startLine: 1,
              startColumn: 1,
              endLine: 1,
              endColumn: 100,
              snippet: {
                text: finding.matched || '(content not available)'
              }
            }
          }
        }],
        partialFingerprints: {
          primaryLocationLineHash: hashString(finding.matched || finding.type)
        },
        properties: {
          confidence: finding.confidence || 1.0,
          severity: finding.severity,
          subtype: finding.subtype || null
        }
      };

      results.push(result);
    }
  }

  // Build rules array from used rules
  const rulesArray = Array.from(usedRules).map(ruleId => {
    return RULES[ruleId] || createDefaultRule(ruleId);
  });

  // Update rule indices in results
  const ruleIndexMap = {};
  rulesArray.forEach((rule, index) => {
    ruleIndexMap[rule.id] = index;
  });
  
  results.forEach(result => {
    result.ruleIndex = ruleIndexMap[result.ruleId] || 0;
  });

  return {
    $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'ClawMoat',
          version: VERSION,
          informationUri: 'https://github.com/darfaz/clawmoat',
          rules: rulesArray,
          organization: 'ClawMoat Project',
          shortDescription: { text: 'AI security moat for agents' },
          fullDescription: { text: 'Runtime protection against prompt injection, tool misuse, and data exfiltration for AI agents.' }
        }
      },
      results,
      invocations: [{
        executionSuccessful: true,
        startTimeUtc: timestamp,
        endTimeUtc: timestamp
      }],
      artifacts: [{
        location: {
          uri: sourceFile,
          uriBaseId: '%SRCROOT%'
        },
        length: -1,
        mimeType: 'text/plain'
      }]
    }]
  };
}

function formatAuditResultAsSarif(auditData) {
  const timestamp = new Date().toISOString();
  const usedRules = new Set();
  const results = [];
  const artifacts = [];

  // Process findings from all files
  if (auditData.findings) {
    for (const finding of auditData.findings) {
      const ruleId = getRuleIdForFinding(finding);
      usedRules.add(ruleId);
      
      const sourceFile = finding.source || 'session.jsonl';
      
      // Add to artifacts if not already present
      if (!artifacts.find(a => a.location.uri === sourceFile)) {
        artifacts.push({
          location: {
            uri: sourceFile,
            uriBaseId: '%SRCROOT%'
          },
          length: -1,
          mimeType: 'application/x-jsonlines'
        });
      }

      const result = {
        ruleId,
        ruleIndex: 0,
        level: SEVERITY_MAP[finding.severity] || 'warning',
        message: {
          text: finding.reason || finding.type || 'Security threat detected'
        },
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: sourceFile,
              uriBaseId: '%SRCROOT%'
            },
            region: {
              startLine: 1,
              startColumn: 1
            }
          }
        }],
        partialFingerprints: {
          primaryLocationLineHash: hashString(finding.matched || finding.type)
        },
        properties: {
          confidence: finding.confidence || 1.0,
          severity: finding.severity,
          subtype: finding.subtype || null,
          entry_id: finding.entry_id || null
        }
      };

      results.push(result);
    }
  }

  const rulesArray = Array.from(usedRules).map(ruleId => {
    return RULES[ruleId] || createDefaultRule(ruleId);
  });

  const ruleIndexMap = {};
  rulesArray.forEach((rule, index) => {
    ruleIndexMap[rule.id] = index;
  });
  
  results.forEach(result => {
    result.ruleIndex = ruleIndexMap[result.ruleId] || 0;
  });

  return {
    $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'ClawMoat',
          version: VERSION,
          informationUri: 'https://github.com/darfaz/clawmoat',
          rules: rulesArray,
          organization: 'ClawMoat Project',
          shortDescription: { text: 'AI security moat for agents' },
          fullDescription: { text: 'Runtime protection against prompt injection, tool misuse, and data exfiltration for AI agents.' }
        }
      },
      results,
      invocations: [{
        executionSuccessful: true,
        startTimeUtc: timestamp,
        endTimeUtc: timestamp
      }],
      artifacts
    }]
  };
}

function getRuleIdForFinding(finding) {
  // Map ClawMoat finding types to SARIF rule IDs
  const type = finding.type || 'unknown';
  const subtype = finding.subtype;

  if (type === 'prompt_injection') return 'clawmoat/prompt-injection';
  if (type === 'jailbreak') return 'clawmoat/jailbreak';
  if (type === 'secret' || type === 'secrets') return 'clawmoat/secret-leak';
  if (type === 'pii') return 'clawmoat/pii-leak';
  if (type === 'url') return 'clawmoat/suspicious-url';
  if (type === 'memory_poisoning') return 'clawmoat/memory-poisoning';
  if (type === 'exfiltration') return 'clawmoat/data-exfiltration';
  if (type === 'excessive_agency') return 'clawmoat/excessive-agency';
  if (type === 'supply_chain') return 'clawmoat/supply-chain';
  if (type === 'insider_threat') return 'clawmoat/insider-threat';
  
  // Fallback: create a generic rule ID
  return `clawmoat/${type}`;
}

function createDefaultRule(ruleId) {
  const cleanId = ruleId.replace('clawmoat/', '');
  return {
    id: ruleId,
    name: cleanId.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(''),
    shortDescription: { text: `${cleanId} threat detected` },
    fullDescription: { text: `ClawMoat detected a potential ${cleanId} security threat.` },
    defaultConfiguration: { level: 'warning' },
    helpUri: 'https://github.com/darfaz/clawmoat',
    properties: {
      category: 'security',
      tags: ['clawmoat', cleanId]
    }
  };
}

function hashString(str) {
  // Simple hash for fingerprinting
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return hash.toString(16);
}

module.exports = {
  formatScanResultAsSarif,
  formatAuditResultAsSarif
};