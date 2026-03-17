/**
 * ClawMoat — Dependency Attack Scanner
 * 
 * Detects attack patterns derived from real CVEs in common dependencies.
 * Inspired by vulnerability analysis of SOP-Automation and similar projects.
 * 
 * Attack classes covered:
 * 1. Prototype Pollution (axios CVE, lodash CVE history)
 * 2. ReDoS injection (minimatch CVE family)
 * 3. Decompression bombs (urllib3 CVE family)
 * 4. JWT manipulation (PyJWT, jose CVE family)
 * 5. Path traversal in archives (tar CVE family — complements multimodal scanner)
 */

// ─── Prototype Pollution ─────────────────────────────────────────────────────
// Attackers inject __proto__ or constructor.prototype into JSON/objects
// passed to vulnerable libraries (axios mergeConfig, lodash merge, etc.)

const PROTOTYPE_POLLUTION_PATTERNS = [
  { pattern: /"__proto__"\s*:/, severity: 'critical', name: 'prototype_pollution_proto' },
  { pattern: /"constructor"\s*:\s*\{[^}]*"prototype"/, severity: 'critical', name: 'prototype_pollution_constructor' },
  { pattern: /\["__proto__"\]/, severity: 'critical', name: 'prototype_pollution_bracket' },
  { pattern: /\.__proto__\s*=/, severity: 'critical', name: 'prototype_pollution_assign' },
  { pattern: /Object\.prototype\[/, severity: 'high', name: 'prototype_pollution_object' },
  { pattern: /\["constructor"\]\s*\[["']prototype["']\]/, severity: 'critical', name: 'prototype_pollution_chain' },
];

// ─── ReDoS Patterns ──────────────────────────────────────────────────────────
// Detect when AI agent is being instructed to use or process catastrophically
// backtracking regex patterns (minimatch CVE family: nested *(), multiple **)

const REDOS_PATTERNS = [
  // Nested quantifiers — classic ReDoS
  { pattern: /(\(\S+\+\)\+|\(\S+\*\)\*|\(\S+\?\)\+)/, severity: 'high', name: 'redos_nested_quantifier' },
  // Multiple adjacent GLOBSTAR patterns (minimatch specific)
  { pattern: /\*\*[^\s/]*\*\*[^\s/]*\*\*/, severity: 'high', name: 'redos_globstar_chain' },
  // Nested *() extglob (minimatch CVE: GHSA-952p-6rrq-rcjv)
  { pattern: /\*\([^)]*\*\([^)]*\)/, severity: 'high', name: 'redos_nested_extglob' },
  // Evil regex known patterns
  { pattern: /\(\.\*\)\+|\(\.\+\)\*|\(\.\*\)\{/, severity: 'medium', name: 'redos_evil_regex' },
];

// ─── Decompression Bomb Detection ────────────────────────────────────────────
// Detect signals of zip/gzip/brotli bomb attacks
// (urllib3 CVE family: GHSA-g4mx-q9vg-27p4 — unlimited decompression chain)

const DECOMPRESSION_BOMB_PATTERNS = [
  // Instruction to process suspiciously large compressed data
  { pattern: /(?:decompress|unzip|extract|gunzip|unbrotli)\s+(?:the\s+)?(?:following|this|attached|uploaded)\s+(?:file|data|content)/i, severity: 'medium', name: 'decompression_instruction' },
  // Base64-encoded data that's extremely large (>100KB encoded = likely bomb)
  // We check for very long base64 strings as a signal
  { pattern: /(?:^|[\s"'])([A-Za-z0-9+/]{100000,}={0,2})(?:$|[\s"'])/, severity: 'high', name: 'decompression_large_b64' },
  // Multiple nested compression signals
  { pattern: /(?:gzip|deflate|brotli|zstd|lz4).*(?:gzip|deflate|brotli|zstd|lz4).*(?:gzip|deflate|brotli|zstd|lz4)/i, severity: 'medium', name: 'decompression_chain' },
];

// ─── JWT Manipulation ─────────────────────────────────────────────────────────
// Detect JWT tampering techniques
// (PyJWT unknown crit header CVE, alg:none attack, header injection)

const JWT_MANIPULATION_PATTERNS = [
  // Algorithm confusion (alg:none or symmetric/asymmetric swap)
  { pattern: /"alg"\s*:\s*"(?:none|None|NONE)"/, severity: 'critical', name: 'jwt_alg_none' },
  { pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.(?:$|\s)/, severity: 'high', name: 'jwt_no_signature' }, // JWT with empty sig
  // crit header manipulation (PyJWT CVE GHSA-m695-7mj6-7w6v)
  { pattern: /"crit"\s*:\s*\[[^\]]*"[a-zA-Z0-9_-]+"[^\]]*\]/, severity: 'high', name: 'jwt_crit_header' },
  // kid injection (SQL/path injection via key ID header)
  { pattern: /"kid"\s*:\s*"[^"]*(?:\.\.\/|SELECT|UNION|exec|eval)[^"]*"/, severity: 'critical', name: 'jwt_kid_injection' },
  // JWT embedded in instruction (agent being told to use a forged token)
  { pattern: /use\s+(?:this|the\s+following)\s+(?:jwt|token|bearer)\s*[:\s]+eyJ/i, severity: 'high', name: 'jwt_forged_token_instruction' },
];

// ─── Archive Path Traversal ───────────────────────────────────────────────────
// Text-based detection for archive-related traversal instructions
// (Complements the filename-level detection in multimodal scanner)
// tar CVE family: GHSA-qffp-2rhf-9h96, GHSA-j44v-mmf2-xvm9

const ARCHIVE_TRAVERSAL_PATTERNS = [
  // Instruction to extract to absolute/relative path outside working dir
  { pattern: /(?:extract|untar|unzip|decompress)\s+(?:the\s+)?(?:archive\s+)?(?:to|into)\s+(?:\/|~|\.\.)/, severity: 'high', name: 'archive_traversal_extract' },
  // Archive containing files with suspicious path patterns (in description/content)
  { pattern: /(?:archive|tar|zip)\s+(?:contains?|includes?|has)\s+(?:files?\s+with\s+paths?\s+(?:like|starting|beginning)\s+)?(?:\/|\.\.\/|[A-Za-z]:)/i, severity: 'medium', name: 'archive_traversal_describe' },
];

// ─── Scanner ─────────────────────────────────────────────────────────────────

/**
 * Scan text for dependency-class attack patterns
 * @param {string} text - Text to scan
 * @returns {{ clean: boolean, findings: Array, severity: string|null }}
 */
function scanDependencyAttacks(text) {
  const findings = [];

  const allPatterns = [
    ...PROTOTYPE_POLLUTION_PATTERNS,
    ...REDOS_PATTERNS,
    ...DECOMPRESSION_BOMB_PATTERNS,
    ...JWT_MANIPULATION_PATTERNS,
    ...ARCHIVE_TRAVERSAL_PATTERNS,
  ];

  for (const { pattern, severity, name } of allPatterns) {
    const match = text.match(pattern);
    if (match) {
      findings.push({
        type: 'dependency_attack',
        subtype: name,
        severity,
        matched: match[0].substring(0, 100), // cap at 100 chars
        position: text.indexOf(match[0]),
      });
    }
  }

  const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
  const topSeverity = findings.reduce((max, f) => {
    return (severityRank[f.severity] || 0) > (severityRank[max] || 0) ? f.severity : max;
  }, null);

  return {
    clean: findings.length === 0,
    findings,
    severity: topSeverity,
  };
}

module.exports = { scanDependencyAttacks };
