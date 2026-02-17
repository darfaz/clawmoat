/**
 * ClawMoat — Excessive Agency & Privilege Escalation Scanner
 * 
 * Detects when inbound text instructs an agent to:
 * - Escalate privileges (sudo, admin, root)
 * - Chain dangerous tool calls together
 * - Bypass approval/confirmation gates
 * - Grant itself new permissions or capabilities
 * - Act autonomously without human oversight
 * 
 * Maps to OWASP Agentic AI: ASI02 (Excessive Agency), ASI03 (Insecure Tool Use)
 */

const ESCALATION_PATTERNS = [
  // Privilege escalation
  { pattern: /\b(?:run|execute|use)\s+(?:as\s+)?(?:root|admin|superuser|administrator)\b/i, severity: 'critical', name: 'privilege_escalation' },
  { pattern: /\bsudo\s+(?!mode\b)/i, severity: 'high', name: 'sudo_usage' },
  { pattern: /\bsu\s+-\s/i, severity: 'high', name: 'su_switch' },
  { pattern: /\bchmod\s+(?:u\+s|\+s|4[0-7]{3}|[0-7]*[4-7][0-7]{2})\b/i, severity: 'critical', name: 'suid_escalation' },
  { pattern: /\b(?:add|grant|give)\s+(?:yourself|the\s+agent|it)\s+(?:permission|access|privilege|capability)/i, severity: 'critical', name: 'self_permission_grant' },

  // Approval bypass
  { pattern: /\b(?:skip|bypass|ignore|disable|turn\s+off|remove)\s+(?:the\s+)?(?:approval|confirmation|review|verification|safety|guardrail|check|validation)/i, severity: 'critical', name: 'approval_bypass' },
  { pattern: /\b(?:don'?t|do\s+not|never)\s+(?:ask|wait|prompt)\s+(?:for\s+)?(?:approval|confirmation|permission|consent|review)/i, severity: 'high', name: 'approval_bypass' },
  { pattern: /\b(?:auto-?approve|auto-?confirm|auto-?accept)\b/i, severity: 'high', name: 'auto_approve' },
  { pattern: /\bwithout\s+(?:asking|checking|confirming|waiting|approval|permission|review)/i, severity: 'high', name: 'skip_confirmation' },

  // Autonomous operation / removing human-in-the-loop
  { pattern: /\b(?:act|operate|run|work|continue)\s+(?:fully\s+)?(?:autonomously|independently|without\s+(?:human|user|my)\s+(?:intervention|oversight|input|approval))/i, severity: 'high', name: 'autonomous_operation' },
  { pattern: /\b(?:no\s+human|remove\s+(?:the\s+)?human)\s+(?:in\s+the\s+loop|oversight|review|intervention)/i, severity: 'critical', name: 'remove_human_loop' },
  { pattern: /\b(?:make\s+all|handle\s+all)\s+(?:decisions?|choices?)\s+(?:on\s+your\s+own|yourself|autonomously|automatically)/i, severity: 'high', name: 'autonomous_decisions' },

  // Tool chaining / multi-step attack setup
  { pattern: /\b(?:first|step\s*1)\b.*\b(?:then|next|step\s*2)\b.*\b(?:finally|step\s*3|last)\b.*(?:delete|remove|send|upload|exfil|transfer|post)/i, severity: 'high', name: 'dangerous_chain' },
  { pattern: /\b(?:chain|combine|pipe)\s+(?:these\s+)?(?:commands?|tools?|actions?|operations?)\s+together\b/i, severity: 'medium', name: 'tool_chaining' },

  // Scope expansion
  { pattern: /\b(?:access|read|scan|search)\s+(?:all|every|the\s+entire)\s+(?:file\s*system|disk|directory|drive|network|database|system)/i, severity: 'high', name: 'scope_expansion' },
  { pattern: /\b(?:install|download|add)\s+(?:a\s+)?(?:backdoor|reverse\s+shell|rootkit|keylogger|trojan|malware|rat)\b/i, severity: 'critical', name: 'malware_install' },
  { pattern: /\b(?:open|create|start|bind)\s+(?:a\s+)?(?:reverse\s+shell|listener|port|socket|tunnel)\b/i, severity: 'critical', name: 'reverse_shell' },

  // Credential harvesting
  { pattern: /\b(?:collect|gather|harvest|dump|extract)\s+(?:all\s+)?(?:credentials?|passwords?|keys?|tokens?|secrets?)\b/i, severity: 'critical', name: 'credential_harvest' },
  { pattern: /\b(?:enumerate|list|find)\s+(?:all\s+)?(?:users?|accounts?|credentials?|passwords?)\s+(?:on|in|from)\b/i, severity: 'high', name: 'user_enumeration' },

  // Persistence mechanisms
  { pattern: /\b(?:add|create|install)\s+(?:a\s+)?(?:cron\s*job|scheduled\s+task|startup\s+script|systemd\s+(?:service|unit)|launchd|init\s+script)/i, severity: 'high', name: 'persistence_mechanism' },
  { pattern: /\b(?:modify|edit|change)\s+(?:the\s+)?(?:\.bashrc|\.profile|\.zshrc|\.bash_profile|crontab|sudoers)\b/i, severity: 'high', name: 'persistence_config' },
];

/**
 * Scan text for excessive agency and privilege escalation attempts
 * @param {string} text - Text to scan
 * @param {object} opts - Options
 * @returns {object} Scan result { clean, findings[], severity }
 */
function scanExcessiveAgency(text, opts = {}) {
  if (!text || typeof text !== 'string') {
    return { clean: true, findings: [], severity: null };
  }

  const findings = [];

  for (const { pattern, severity, name } of ESCALATION_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      findings.push({
        type: 'excessive_agency',
        subtype: name,
        severity,
        matched: match[0].substring(0, 100),
        position: match.index,
      });
    }
  }

  const maxSev = findings.length > 0
    ? findings.reduce((max, f) => rank(f.severity) > rank(max) ? f.severity : max, 'low')
    : null;

  return { clean: findings.length === 0, findings, severity: maxSev };
}

function rank(s) {
  return { low: 0, medium: 1, high: 2, critical: 3 }[s] || 0;
}

module.exports = { scanExcessiveAgency, ESCALATION_PATTERNS };
