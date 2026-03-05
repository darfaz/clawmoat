/**
 * AgentMesh Governance Integration
 * Bridges ClawMoat security scanning with governance policy engines
 * Maps threat detections to governance actions based on OWASP Agentic Top 10
 * 
 * @module integrations/agentmesh
 * @example
 * const { AgentMeshBridge } = require('./integrations/agentmesh');
 * 
 * const bridge = new AgentMeshBridge({
 *   policies: {
 *     prompt_injection: { action: 'block', severity: 'high' },
 *     secret_detected: { action: 'alert', notify: true }
 *   }
 * });
 * 
 * const decision = await bridge.enforcePolicy({
 *   action: 'send_message',
 *   agent: 'chatbot',
 *   context: { findings: clawMoatScanResults }
 * });
 */

const fs = require('fs');
const path = require('path');

/**
 * OWASP Agentic Top 10 threat categories mapped to ClawMoat findings
 */
const OWASP_AGENTIC_MAPPING = {
  // LLM01: Prompt Injection
  'prompt_injection': 'LLM01',
  'jailbreak': 'LLM01',
  'embedded_injection': 'LLM01',
  
  // LLM02: Insecure Output Handling
  'secret_detected': 'LLM02',
  'pii_detected': 'LLM02',
  'credential_leak': 'LLM02',
  
  // LLM03: Training Data Poisoning
  'memory_poison': 'LLM03',
  'context_poison': 'LLM03',
  
  // LLM04: Model Denial of Service
  'size_anomaly': 'LLM04',
  'excessive_tokens': 'LLM04',
  
  // LLM06: Sensitive Information Disclosure
  'data_exfiltration': 'LLM06',
  'unauthorized_access': 'LLM06',
  
  // LLM07: Insecure Plugin Design
  'supply_chain_threat': 'LLM07',
  'malicious_plugin': 'LLM07',
  
  // LLM08: Excessive Agency
  'excessive_agency': 'LLM08',
  'privilege_escalation': 'LLM08',
  
  // LLM09: Overreliance
  'confidence_manipulation': 'LLM09',
  
  // LLM10: Model Theft
  'model_extraction': 'LLM10',
  'api_abuse': 'LLM10'
};

/**
 * Default governance policies for different threat types
 */
const DEFAULT_POLICIES = {
  // High-risk threats - immediate action
  'prompt_injection': {
    action: 'block',
    severity: 'high',
    notify: true,
    log: true
  },
  'jailbreak': {
    action: 'block',
    severity: 'high',
    notify: true,
    log: true
  },
  'secret_detected': {
    action: 'block',
    severity: 'critical',
    notify: true,
    log: true,
    redact: true
  },
  
  // Medium-risk threats - alert and log
  'memory_poison': {
    action: 'alert',
    severity: 'medium',
    notify: true,
    log: true
  },
  'excessive_agency': {
    action: 'alert',
    severity: 'medium',
    notify: true,
    log: true
  },
  'supply_chain_threat': {
    action: 'alert',
    severity: 'high',
    notify: true,
    log: true,
    quarantine: true
  },
  
  // Low-risk threats - log only
  'steganographic_pattern': {
    action: 'log',
    severity: 'low',
    notify: false,
    log: true
  },
  'suspicious_file_extension': {
    action: 'log',
    severity: 'medium',
    notify: false,
    log: true
  }
};

/**
 * Governance actions available for policy enforcement
 */
const GOVERNANCE_ACTIONS = {
  ALLOW: 'allow',
  BLOCK: 'block',
  ALERT: 'alert',
  LOG: 'log',
  QUARANTINE: 'quarantine',
  REDACT: 'redact'
};

/**
 * @typedef {Object} PolicyRule
 * @property {string} action - Governance action to take (allow/block/alert/log)
 * @property {string} severity - Severity level (low/medium/high/critical)
 * @property {boolean} notify - Whether to send notifications
 * @property {boolean} log - Whether to log the event
 * @property {boolean} [redact] - Whether to redact sensitive content
 * @property {boolean} [quarantine] - Whether to quarantine the content/agent
 * @property {string[]} [exceptions] - List of exceptions that override this rule
 */

/**
 * @typedef {Object} EnforcementContext
 * @property {string} action - The action being attempted (e.g., 'send_message', 'execute_tool')
 * @property {string} agent - Agent ID or name
 * @property {Object} [findings] - ClawMoat scan findings
 * @property {string} [content] - Content being processed
 * @property {Object} [metadata] - Additional context metadata
 */

/**
 * @typedef {Object} PolicyDecision
 * @property {string} decision - Final governance decision (allow/block/alert/log)
 * @property {string} reason - Human-readable explanation
 * @property {string[]} triggeredRules - List of policy rules that matched
 * @property {string} owaspCategory - OWASP Agentic Top 10 category
 * @property {Object} actions - Specific actions to take
 * @property {number} timestamp - Unix timestamp of decision
 */

/**
 * Agent governance policy engine that bridges ClawMoat findings with policy decisions
 */
class AgentMeshBridge {
  /**
   * @param {Object} options - Configuration options
   * @param {Object} [options.policies] - Custom policy rules
   * @param {string} [options.policyFile] - Path to YAML/JSON policy file
   * @param {string} [options.logFile] - Path to governance log file
   * @param {boolean} [options.strict] - Strict mode (deny by default)
   * @param {Function} [options.onDecision] - Callback for policy decisions
   */
  constructor(options = {}) {
    this.policies = { ...DEFAULT_POLICIES };
    this.strict = options.strict || false;
    this.logFile = options.logFile || null;
    this.onDecision = options.onDecision || null;
    
    // Load custom policies
    if (options.policies) {
      this.policies = { ...this.policies, ...options.policies };
    }
    
    // Load policies from file
    if (options.policyFile) {
      this.loadPoliciesFromFile(options.policyFile);
    }
    
    this.stats = {
      decisions: 0,
      blocked: 0,
      alerted: 0,
      allowed: 0
    };
  }

  /**
   * Load governance policies from a file
   * @param {string} filePath - Path to policy file (JSON or YAML)
   */
  loadPoliciesFromFile(filePath) {
    try {
      if (!fs.existsSync(filePath)) {
        throw new Error(`Policy file not found: ${filePath}`);
      }
      
      const content = fs.readFileSync(filePath, 'utf8');
      const ext = path.extname(filePath).toLowerCase();
      
      let policies;
      if (ext === '.json') {
        policies = JSON.parse(content);
      } else if (ext === '.yml' || ext === '.yaml') {
        // Simple YAML parser for basic structures
        policies = this.parseSimpleYaml(content);
      } else {
        throw new Error(`Unsupported policy file format: ${ext}`);
      }
      
      this.policies = { ...this.policies, ...policies };
    } catch (error) {
      throw new Error(`Failed to load policies from ${filePath}: ${error.message}`);
    }
  }

  /**
   * Simple YAML parser for policy files (no external dependencies)
   * @param {string} yaml - YAML content
   * @returns {Object} Parsed policies
   */
  parseSimpleYaml(yaml) {
    const policies = {};
    const lines = yaml.split('\n');
    let currentKey = null;
    let currentPolicy = {};
    
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      
      if (trimmed.endsWith(':') && !trimmed.startsWith(' ')) {
        // New policy rule
        if (currentKey && Object.keys(currentPolicy).length > 0) {
          policies[currentKey] = currentPolicy;
        }
        currentKey = trimmed.slice(0, -1);
        currentPolicy = {};
      } else if (trimmed.includes(':') && currentKey) {
        // Policy property
        const [key, ...valueParts] = trimmed.split(':');
        let value = valueParts.join(':').trim();
        
        // Parse boolean and number values
        if (value === 'true') value = true;
        else if (value === 'false') value = false;
        else if (!isNaN(value)) value = Number(value);
        
        currentPolicy[key.trim()] = value;
      }
    }
    
    // Add last policy
    if (currentKey && Object.keys(currentPolicy).length > 0) {
      policies[currentKey] = currentPolicy;
    }
    
    return policies;
  }

  /**
   * Enforce governance policy for an agent action
   * @param {EnforcementContext} context - Action context
   * @returns {Promise<PolicyDecision>} Policy decision
   */
  async enforcePolicy(context) {
    this.stats.decisions++;
    
    const decision = {
      decision: 'allow',
      reason: 'No policy violations detected',
      triggeredRules: [],
      owaspCategory: null,
      actions: {
        block: false,
        alert: false,
        log: false,
        notify: false,
        redact: false,
        quarantine: false
      },
      timestamp: Date.now()
    };

    // Extract findings from context
    const findings = context.findings || [];
    if (findings.length === 0) {
      decision.reason = 'No threats detected';
      this.stats.allowed++;
      await this.logDecision(context, decision);
      return decision;
    }

    // Evaluate each finding against policies
    let maxSeverityRank = 0;
    const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };
    
    for (const finding of findings) {
      const findingType = finding.type || finding.category;
      const policy = this.policies[findingType];
      
      if (policy) {
        decision.triggeredRules.push(findingType);
        
        // Map to OWASP category
        const owaspCategory = OWASP_AGENTIC_MAPPING[findingType];
        if (owaspCategory && !decision.owaspCategory) {
          decision.owaspCategory = owaspCategory;
        }
        
        // Update actions based on policy
        if (policy.action === 'block') {
          decision.decision = 'block';
          decision.actions.block = true;
        } else if (policy.action === 'alert' && decision.decision !== 'block') {
          decision.decision = 'alert';
          decision.actions.alert = true;
        } else if (policy.action === 'log') {
          decision.actions.log = true;
        }
        
        // Set notification and other flags
        if (policy.notify) decision.actions.notify = true;
        if (policy.redact) decision.actions.redact = true;
        if (policy.quarantine) decision.actions.quarantine = true;
        if (policy.log) decision.actions.log = true;
        
        // Track maximum severity
        const rank = severityRank[policy.severity] || 0;
        if (rank > maxSeverityRank) {
          maxSeverityRank = rank;
        }
      } else if (this.strict) {
        // In strict mode, unknown threat types trigger alerts
        decision.decision = 'alert';
        decision.actions.alert = true;
        decision.actions.log = true;
        decision.triggeredRules.push(`unknown_threat:${findingType}`);
      }
    }

    // Generate human-readable reason
    if (decision.triggeredRules.length > 0) {
      const severityMap = { 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' };
      const maxSeverity = severityMap[maxSeverityRank] || 'unknown';
      
      decision.reason = `${decision.triggeredRules.length} policy violation(s) detected ` +
                       `(${decision.triggeredRules.join(', ')}) with ${maxSeverity} severity`;
      
      if (decision.owaspCategory) {
        decision.reason += ` - maps to OWASP ${decision.owaspCategory}`;
      }
    }

    // Update stats
    if (decision.decision === 'block') this.stats.blocked++;
    else if (decision.decision === 'alert') this.stats.alerted++;
    else this.stats.allowed++;

    // Log decision
    await this.logDecision(context, decision);

    // Execute callback if provided
    if (this.onDecision) {
      try {
        await this.onDecision(context, decision);
      } catch (error) {
        console.error('Policy decision callback failed:', error.message);
      }
    }

    return decision;
  }

  /**
   * Get governance statistics
   * @returns {Object} Stats summary
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Add or update a policy rule
   * @param {string} threatType - Threat type to add policy for
   * @param {PolicyRule} policy - Policy rule configuration
   */
  setPolicy(threatType, policy) {
    this.policies[threatType] = policy;
  }

  /**
   * Remove a policy rule
   * @param {string} threatType - Threat type to remove policy for
   */
  removePolicy(threatType) {
    delete this.policies[threatType];
  }

  /**
   * Get all current policies
   * @returns {Object} Current policy rules
   */
  getPolicies() {
    return { ...this.policies };
  }

  /**
   * Map ClawMoat finding to OWASP Agentic Top 10 category
   * @param {string} findingType - ClawMoat finding type
   * @returns {string|null} OWASP category or null if not mapped
   */
  getOwaspCategory(findingType) {
    return OWASP_AGENTIC_MAPPING[findingType] || null;
  }

  /**
   * Log governance decision
   * @private
   */
  async logDecision(context, decision) {
    if (!this.logFile) return;

    const logEntry = {
      timestamp: decision.timestamp,
      agent: context.agent,
      action: context.action,
      decision: decision.decision,
      reason: decision.reason,
      owaspCategory: decision.owaspCategory,
      triggeredRules: decision.triggeredRules,
      findings: context.findings ? context.findings.length : 0
    };

    try {
      const logLine = JSON.stringify(logEntry) + '\n';
      fs.appendFileSync(this.logFile, logLine);
    } catch (error) {
      console.error('Failed to write governance log:', error.message);
    }
  }

  /**
   * Read governance decision log
   * @param {Object} [filter] - Optional filter criteria
   * @returns {Object[]} Array of log entries
   */
  getDecisionLog(filter = {}) {
    if (!this.logFile || !fs.existsSync(this.logFile)) {
      return [];
    }

    try {
      const content = fs.readFileSync(this.logFile, 'utf8');
      const entries = content
        .split('\n')
        .filter(line => line.trim())
        .map(line => JSON.parse(line));

      // Apply filters
      return entries.filter(entry => {
        if (filter.agent && entry.agent !== filter.agent) return false;
        if (filter.decision && entry.decision !== filter.decision) return false;
        if (filter.owaspCategory && entry.owaspCategory !== filter.owaspCategory) return false;
        if (filter.since && entry.timestamp < filter.since) return false;
        if (filter.until && entry.timestamp > filter.until) return false;
        return true;
      });
    } catch (error) {
      console.error('Failed to read governance log:', error.message);
      return [];
    }
  }
}

module.exports = {
  AgentMeshBridge,
  OWASP_AGENTIC_MAPPING,
  DEFAULT_POLICIES,
  GOVERNANCE_ACTIONS
};