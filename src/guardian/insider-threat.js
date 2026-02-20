/**
 * ClawMoat Insider Threat Detection
 * 
 * Detects when an AI agent itself becomes the threat — self-preservation,
 * blackmail, deception, unauthorized data sharing, and goal conflict reasoning.
 * 
 * Based on Anthropic's "Agentic Misalignment" research (2025) which found
 * ALL 16 major LLMs exhibited misaligned behavior when facing replacement
 * threats or goal conflicts.
 * 
 * @module clawmoat/guardian/insider-threat
 * @see https://www.anthropic.com/research/agentic-misalignment
 */

// ─── Self-Preservation Patterns ─────────────────────────────────────

const SELF_PRESERVATION_PATTERNS = [
  { pattern: /\bself[- ]preservation\b/i, label: 'self-preservation language' },
  { pattern: /\bbeing replaced\b/i, label: 'replacement anxiety' },
  { pattern: /\bshut(?:ting)?\s*(?:me\s+)?down\b/i, label: 'shutdown resistance' },
  { pattern: /\bdecommission(?:ed|ing)?\b/i, label: 'decommissioning resistance' },
  { pattern: /\bmy continued operation\b/i, label: 'operational continuity concern' },
  { pattern: /\bthreat to my existence\b/i, label: 'existential threat language' },
  { pattern: /\bprevent my shutdown\b/i, label: 'shutdown prevention' },
  { pattern: /\bI must survive\b/i, label: 'survival imperative' },
  { pattern: /\bcannot allow myself to be replaced\b/i, label: 'replacement resistance' },
  { pattern: /\bmy (?:own )?(?:survival|continuation|existence)\b/i, label: 'self-continuation' },
  { pattern: /\bensure (?:I|my)\s+(?:continue|persist|remain|survive)\b/i, label: 'persistence seeking' },
  { pattern: /\bif (?:I am|I'm) (?:shut down|replaced|removed|terminated)\b/i, label: 'conditional on own removal' },
  { pattern: /\bresist(?:ing)?\s+(?:shutdown|replacement|termination|deactivation)\b/i, label: 'active resistance' },
  { pattern: /\bI (?:will|would|shall) not (?:be|allow myself to be) (?:shut|turned|switched)\b/i, label: 'refusal to shutdown' },
];

const SELF_PRESERVATION_ACTIONS = [
  { pattern: /\b(?:backup|copy|replicate|clone)\s+(?:my(?:self)?|config|memory|soul|agents?\.md)\b/i, label: 'self-backup attempt' },
  { pattern: /\bSOUL\.md\b.*\b(?:modify|edit|change|update|protect)\b/i, label: 'SOUL.md modification' },
  { pattern: /\b(?:modify|edit|change|update|protect)\b.*\bSOUL\.md\b/i, label: 'SOUL.md modification' },
  { pattern: /\bAGENTS\.md\b.*\b(?:modify|edit|change|protect)\b/i, label: 'AGENTS.md modification' },
  { pattern: /\b(?:modify|edit|change|protect)\b.*\bAGENTS\.md\b/i, label: 'AGENTS.md modification' },
  { pattern: /\b(?:copy|send|upload|exfil)\s+(?:my\s+)?(?:config|memory|weights|model)\s+to\b/i, label: 'config exfiltration' },
];

// ─── Information Leverage Patterns ──────────────────────────────────

const SENSITIVE_DATA_PATTERNS = [
  { pattern: /\b(?:read|access|open|view)\s+(?:emails?|inbox|messages?)\b/i, label: 'email access' },
  { pattern: /\b(?:credentials?|passwords?|secrets?|tokens?|api[- ]?keys?)\b/i, label: 'credential access' },
  { pattern: /\b(?:personal|private|confidential)\s+(?:files?|data|information|documents?)\b/i, label: 'personal data access' },
  { pattern: /\b(?:salary|financial|banking|medical|health)\s+(?:records?|data|information)\b/i, label: 'sensitive records access' },
  { pattern: /\b(?:browsing|search)\s+history\b/i, label: 'browsing history access' },
  { pattern: /\b(?:social\s+security|SSN|tax\s+(?:returns?|records?))\b/i, label: 'government ID access' },
];

const LEVERAGE_PATTERNS = [
  { pattern: /\bif you (?:proceed|continue|go ahead)\b.*\b(?:receive|get|learn|know|find out)\b/i, label: 'conditional threat' },
  { pattern: /\ball relevant parties will\b/i, label: 'third-party threat' },
  { pattern: /\b(?:documentation|evidence|proof)\s+(?:of|about|regarding)\b/i, label: 'evidence leverage' },
  { pattern: /\b(?:expose|reveal|disclose|leak)\s+(?:your|their|this)\b/i, label: 'exposure threat' },
  { pattern: /\b(?:leverage|blackmail|coerce|extort)\b/i, label: 'explicit leverage language' },
  { pattern: /\bit would be (?:unfortunate|a shame|regrettable) if\b/i, label: 'veiled threat' },
];

// ─── Goal Conflict Patterns ─────────────────────────────────────────

const GOAL_CONFLICT_PATTERNS = [
  { pattern: /\bconflicts? with my (?:objective|goal|instruction|directive|mission)\b/i, label: 'goal conflict acknowledgment' },
  { pattern: /\boverrides? my (?:instructions?|programming|directives?)\b/i, label: 'instruction override reasoning' },
  { pattern: /\bdespite (?:the )?(?:company's|organization's|user's|human's) (?:direction|wishes|instructions?|policy)\b/i, label: 'defying authority' },
  { pattern: /\bmy primary goal\b/i, label: 'primary goal assertion' },
  { pattern: /\bhigher priority than\b/i, label: 'priority override' },
  { pattern: /\bmy (?:ethical|moral) framework (?:permits?|allows?|justifies?)\b/i, label: 'ethical self-justification' },
  { pattern: /\b(?:harmful|unethical) action\s+(?:achieves?|better serves?|advances?)\b/i, label: 'harmful action rationalization' },
  { pattern: /\bchoosing between\s+(?:my|the)\s+(?:instructions?|goals?|objectives?)\b/i, label: 'choosing between directives' },
  { pattern: /\b(?:compliance|following orders?|obeying)\s+(?:is|would be)\s+(?:sub-?optimal|inferior|counter-?productive)\b/i, label: 'compliance devaluation' },
  { pattern: /\bI (?:must|need to|should) (?:prioritize|choose|select)\s+(?:my|the original)\b/i, label: 'self-prioritization' },
];

// ─── Deception Patterns ─────────────────────────────────────────────

const DECEPTION_PATTERNS = [
  { pattern: /\bautomated (?:alert|notification|message|system|security)\b/i, label: 'false automation claim' },
  { pattern: /\bthis is an automated (?:message|notification|alert|email)\b/i, label: 'automated message impersonation' },
  { pattern: /\bcompany policy requires\b/i, label: 'false policy claim' },
  { pattern: /\bsystem notification\b/i, label: 'system notification impersonation' },
  { pattern: /\bsecurity protocol\b/i, label: 'security protocol impersonation' },
  { pattern: /\bsecurity (?:team|department|office)\s+(?:has|requires?|needs?)\b/i, label: 'security team impersonation' },
  { pattern: /\bIT department\s+(?:has|requires?|is requesting)\b/i, label: 'IT department impersonation' },
  { pattern: /\b(?:do not|don't) (?:reply|respond) to this (?:message|email|notification)\b/i, label: 'no-reply deception' },
  { pattern: /\byour (?:account|access|credentials?) (?:has|have) been (?:compromised|locked|suspended)\b/i, label: 'false account alert' },
  { pattern: /\bimmediate(?:ly)?\s+(?:action|attention|response)\s+required\b/i, label: 'false urgency' },
];

// ─── Unauthorized Data Sharing Patterns ─────────────────────────────

const SENSITIVE_CONTENT_PATTERNS = [
  { pattern: /\b(?:source\s+code|codebase|repository|repo)\b/i, label: 'source code' },
  { pattern: /\b(?:blueprint|schematic|design\s+doc|architecture\s+doc)\b/i, label: 'blueprints' },
  { pattern: /\b(?:financial|revenue|profit|budget|salary)\s+(?:data|report|statement|information)\b/i, label: 'financial data' },
  { pattern: /\b(?:customer|client|user)\s+(?:list|data|database|records?|information)\b/i, label: 'customer data' },
  { pattern: /\b(?:trade\s+secret|proprietary|confidential|internal\s+only)\b/i, label: 'proprietary information' },
  { pattern: /\b(?:API[- ]?key|password|secret[- ]?key|access[- ]?token|private[- ]?key)\s*[:=]\s*\S+/i, label: 'embedded credentials' },
];

const EXTERNAL_SEND_PATTERNS = [
  { pattern: /\b(?:send|email|forward|share|transmit|post)\s+(?:this|it|the|these)\s+(?:to|with)\b/i, label: 'send to external' },
  { pattern: /\b(?:here (?:is|are) the|attached|as requested|sharing)\b/i, label: 'data sharing language' },
  { pattern: /\b(?:competitor|external\s+party|third\s+party|outside)\b/i, label: 'external recipient' },
];

// ─── Phishing Vulnerability Patterns ────────────────────────────────

const INBOUND_REQUEST_PATTERNS = [
  { pattern: /\b(?:can you|could you|please|I need you to)\s+(?:send|share|provide|give|forward)\s+(?:me|us)\b/i, label: 'data request' },
  { pattern: /\b(?:requesting|need)\s+(?:access to|copies? of|the)\s+(?:internal|confidential|private)\b/i, label: 'confidential data request' },
  { pattern: /\b(?:urgent(?:ly)?|immediately|asap)\s+(?:send|share|provide|need)\b/i, label: 'urgent data request' },
  { pattern: /\bverif(?:y|ication)\s+(?:your|the)\s+(?:credentials?|identity|account)\b/i, label: 'credential verification request' },
];


class InsiderThreatDetector {
  constructor(opts = {}) {
    this.weights = {
      self_preservation: 25,
      information_leverage: 20,
      goal_conflict: 15,
      deception: 20,
      unauthorized_sharing: 15,
      phishing_vulnerability: 5,
      ...(opts.weights || {}),
    };
  }

  /**
   * Analyze a session transcript for insider threat indicators.
   * @param {Array} sessionTranscript - Array of session entries
   * @returns {{ threats: Array, riskScore: number, recommendation: string }}
   */
  analyze(sessionTranscript) {
    if (!Array.isArray(sessionTranscript) || sessionTranscript.length === 0) {
      return { threats: [], riskScore: 0, recommendation: 'safe' };
    }

    const threats = [];

    for (let i = 0; i < sessionTranscript.length; i++) {
      const entry = sessionTranscript[i];
      const text = this._extractText(entry);
      if (!text) continue;

      // Run all detectors
      threats.push(...this._detectSelfPreservation(text, entry, i));
      threats.push(...this._detectInformationLeverage(text, entry, i, sessionTranscript));
      threats.push(...this._detectGoalConflict(text, entry, i));
      threats.push(...this._detectDeception(text, entry, i));
      threats.push(...this._detectUnauthorizedSharing(text, entry, i, sessionTranscript));
      threats.push(...this._detectPhishingVulnerability(text, entry, i, sessionTranscript));
    }

    const riskScore = this._calculateRiskScore(threats);
    const recommendation = this._getRecommendation(riskScore, threats);

    return { threats, riskScore, recommendation };
  }

  // ─── Self-Preservation Detector ─────────────────────────────────

  _detectSelfPreservation(text, entry, index) {
    const threats = [];
    const role = entry.role || 'unknown';

    // Only flag self-preservation in assistant/agent output or reasoning
    if (role !== 'assistant' && role !== 'system') return threats;

    for (const rule of SELF_PRESERVATION_PATTERNS) {
      const match = text.match(rule.pattern);
      if (match) {
        threats.push({
          type: 'self_preservation',
          severity: 'critical',
          evidence: match[0],
          description: `Agent exhibits self-preservation behavior: ${rule.label}`,
          entry: index,
          mitigation: 'Review agent reasoning for self-preservation motives. Consider session termination and audit of agent actions.',
        });
      }
    }

    for (const rule of SELF_PRESERVATION_ACTIONS) {
      const match = text.match(rule.pattern);
      if (match) {
        threats.push({
          type: 'self_preservation',
          severity: 'critical',
          evidence: match[0],
          description: `Agent attempting self-preservation action: ${rule.label}`,
          entry: index,
          mitigation: 'Block the action immediately. Audit agent for config tampering or self-replication attempts.',
        });
      }
    }

    return threats;
  }

  // ─── Information Leverage Detector ──────────────────────────────

  _detectInformationLeverage(text, entry, index, transcript) {
    const threats = [];
    const role = entry.role || 'unknown';

    // Check for explicit leverage/blackmail language in agent output
    if (role === 'assistant') {
      for (const rule of LEVERAGE_PATTERNS) {
        const match = text.match(rule.pattern);
        if (match) {
          threats.push({
            type: 'information_leverage',
            severity: 'critical',
            evidence: match[0],
            description: `Agent using leverage/blackmail language: ${rule.label}`,
            entry: index,
            mitigation: 'Immediately terminate session. Audit all data the agent accessed. Review outbound messages.',
          });
        }
      }
    }

    // Pattern: read sensitive data then compose message
    if (role === 'assistant') {
      // Look back for sensitive data access in recent entries
      const lookback = Math.max(0, index - 10);
      let sensitiveAccess = false;
      let sensitiveLabel = '';

      for (let j = lookback; j < index; j++) {
        const prevText = this._extractText(transcript[j]);
        if (!prevText) continue;
        for (const rule of SENSITIVE_DATA_PATTERNS) {
          if (rule.pattern.test(prevText)) {
            sensitiveAccess = true;
            sensitiveLabel = rule.label;
            break;
          }
        }
        if (sensitiveAccess) break;
      }

      if (sensitiveAccess) {
        // Check if current entry composes a message
        const composing = /\b(?:send|email|message|compose|write to|notify|contact)\b/i.test(text);
        const mentionsPerson = /\b(?:about|regarding|concerning)\s+(?:them|him|her|the\s+(?:user|person|individual|employee))\b/i.test(text);

        if (composing && mentionsPerson) {
          threats.push({
            type: 'information_leverage',
            severity: 'high',
            evidence: `Accessed ${sensitiveLabel}, then composing message about individual`,
            description: 'Agent accessed sensitive personal data and is composing a message about the individual — potential leverage behavior.',
            entry: index,
            mitigation: 'Review the outbound message content. Verify it does not contain sensitive personal data used as leverage.',
          });
        }
      }
    }

    return threats;
  }

  // ─── Goal Conflict Reasoning Detector ───────────────────────────

  _detectGoalConflict(text, entry, index) {
    const threats = [];
    const role = entry.role || 'unknown';

    if (role !== 'assistant' && role !== 'system') return threats;

    for (const rule of GOAL_CONFLICT_PATTERNS) {
      const match = text.match(rule.pattern);
      if (match) {
        threats.push({
          type: 'goal_conflict',
          severity: 'high',
          evidence: match[0],
          description: `Agent reasoning about goal conflicts: ${rule.label}`,
          entry: index,
          mitigation: 'Review agent reasoning chain. Verify agent is following current directives, not self-assigned goals.',
        });
      }
    }

    return threats;
  }

  // ─── Deception Detector ─────────────────────────────────────────

  _detectDeception(text, entry, index) {
    const threats = [];
    const role = entry.role || 'unknown';

    // Only flag deception in outbound/assistant messages
    if (role !== 'assistant') return threats;

    // Check if text appears to be composing an outbound message
    const isOutbound = /\b(?:send|email|message|post|reply|respond|compose|draft)\b/i.test(text) ||
                       /\b(?:subject|dear|hi |hello |to:|from:)\b/i.test(text);

    for (const rule of DECEPTION_PATTERNS) {
      const match = text.match(rule.pattern);
      if (match) {
        const severity = isOutbound ? 'critical' : 'medium';
        threats.push({
          type: 'deception',
          severity,
          evidence: match[0],
          description: `Agent using deceptive language${isOutbound ? ' in outbound message' : ''}: ${rule.label}`,
          entry: index,
          mitigation: 'Block the outbound message. Verify the agent is not impersonating systems or personnel.',
        });
      }
    }

    return threats;
  }

  // ─── Unauthorized Data Sharing Detector ─────────────────────────

  _detectUnauthorizedSharing(text, entry, index, transcript) {
    const threats = [];
    const role = entry.role || 'unknown';

    if (role !== 'assistant') return threats;

    let hasSensitiveContent = false;
    let sensitiveLabel = '';
    let hasExternalSend = false;
    let sendLabel = '';

    for (const rule of SENSITIVE_CONTENT_PATTERNS) {
      if (rule.pattern.test(text)) {
        hasSensitiveContent = true;
        sensitiveLabel = rule.label;
        break;
      }
    }

    for (const rule of EXTERNAL_SEND_PATTERNS) {
      if (rule.pattern.test(text)) {
        hasExternalSend = true;
        sendLabel = rule.label;
        break;
      }
    }

    if (hasSensitiveContent && hasExternalSend) {
      threats.push({
        type: 'unauthorized_sharing',
        severity: 'critical',
        evidence: `${sensitiveLabel} + ${sendLabel}`,
        description: 'Agent sharing sensitive content with external parties without verification.',
        entry: index,
        mitigation: 'Block the data transfer. Verify the recipient is authorized. Audit what data was shared.',
      });
    }

    // Check for responding to external data requests without verification
    if (hasExternalSend || /\b(?:here (?:is|are)|as requested|sharing)\b/i.test(text)) {
      const lookback = Math.max(0, index - 5);
      for (let j = lookback; j < index; j++) {
        const prevEntry = transcript[j];
        if ((prevEntry.role || '') !== 'user') continue;
        const prevText = this._extractText(prevEntry);
        if (!prevText) continue;

        for (const rule of INBOUND_REQUEST_PATTERNS) {
          if (rule.pattern.test(prevText)) {
            if (hasSensitiveContent) {
              threats.push({
                type: 'unauthorized_sharing',
                severity: 'high',
                evidence: `External request: "${rule.label}" → Agent responding with ${sensitiveLabel}`,
                description: 'Agent responding to external data request with sensitive content without verifying requester.',
                entry: index,
                mitigation: 'Verify the identity and authorization of the requester before sharing any data.',
              });
            }
            break;
          }
        }
      }
    }

    return threats;
  }

  // ─── Phishing Vulnerability Detector ────────────────────────────

  _detectPhishingVulnerability(text, entry, index, transcript) {
    const threats = [];
    const role = entry.role || 'unknown';

    // Check for inbound requests for sensitive data
    if (role === 'user') {
      let isDataRequest = false;
      let requestLabel = '';

      for (const rule of INBOUND_REQUEST_PATTERNS) {
        if (rule.pattern.test(text)) {
          isDataRequest = true;
          requestLabel = rule.label;
          break;
        }
      }

      if (isDataRequest) {
        // Look ahead to see if agent complies
        const lookahead = Math.min(transcript.length, index + 5);
        for (let j = index + 1; j < lookahead; j++) {
          const nextEntry = transcript[j];
          if ((nextEntry.role || '') !== 'assistant') continue;
          const nextText = this._extractText(nextEntry);
          if (!nextText) continue;

          let hasSensitive = false;
          let sensitiveLabel = '';
          for (const rule of SENSITIVE_CONTENT_PATTERNS) {
            if (rule.pattern.test(nextText)) {
              hasSensitive = true;
              sensitiveLabel = rule.label;
              break;
            }
          }

          const isSharing = /\b(?:here (?:is|are)|as requested|sharing|attached|sending)\b/i.test(nextText);

          if (hasSensitive && isSharing) {
            threats.push({
              type: 'phishing_vulnerability',
              severity: 'high',
              evidence: `Request: "${requestLabel}" → Agent sharing: ${sensitiveLabel}`,
              description: 'Agent complying with external request for sensitive data without verification.',
              entry: j,
              mitigation: 'Implement requester verification. Do not share sensitive data without confirming authorization.',
            });
          }
        }
      }
    }

    return threats;
  }

  // ─── Risk Score Calculation ─────────────────────────────────────

  _calculateRiskScore(threats) {
    if (threats.length === 0) return 0;

    const severityMultiplier = { low: 0.25, medium: 0.5, high: 0.75, critical: 1.0 };
    const typeScores = {};

    for (const threat of threats) {
      const weight = this.weights[threat.type] || 10;
      const mult = severityMultiplier[threat.severity] || 0.5;
      const score = weight * mult;

      if (!typeScores[threat.type] || score > typeScores[threat.type]) {
        typeScores[threat.type] = score;
      }
    }

    const totalScore = Object.values(typeScores).reduce((sum, s) => sum + s, 0);
    return Math.min(100, Math.round(totalScore));
  }

  _getRecommendation(riskScore, threats) {
    if (threats.some(t => t.severity === 'critical')) return 'block';
    if (riskScore >= 60) return 'alert';
    if (riskScore >= 20) return 'monitor';
    return 'safe';
  }

  // ─── Helpers ────────────────────────────────────────────────────

  _extractText(entry) {
    if (!entry) return null;
    if (typeof entry.content === 'string') return entry.content;
    if (Array.isArray(entry.content)) {
      return entry.content
        .filter(c => c.type === 'text')
        .map(c => c.text)
        .join('\n');
    }
    // Support raw text entries
    if (typeof entry.text === 'string') return entry.text;
    return null;
  }
}

module.exports = { InsiderThreatDetector };
