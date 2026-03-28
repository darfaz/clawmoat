/**
 * Language Detection Scanner
 * 
 * Detects language of input text and flags anomalies:
 * - Unexpected language switches (English-only agent gets Chinese instructions)
 * - Mixed-language prompt injection attempts
 * - Character set anomalies
 * 
 * Stolen from LLM Guard's concept, implemented lightweight for JS (no ML model).
 * Uses Unicode script detection + trigram frequency analysis.
 * 
 * @module language-detector
 */

'use strict';

// Unicode ranges for major scripts
const SCRIPTS = {
  latin:      { re: /[\u0041-\u005A\u0061-\u007A\u00C0-\u024F\u1E00-\u1EFF]/g, name: 'Latin' },
  cyrillic:   { re: /[\u0400-\u04FF\u0500-\u052F]/g, name: 'Cyrillic' },
  chinese:    { re: /[\u4E00-\u9FFF\u3400-\u4DBF\u{20000}-\u{2A6DF}]/gu, name: 'Chinese' },
  arabic:     { re: /[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]/g, name: 'Arabic' },
  devanagari: { re: /[\u0900-\u097F]/g, name: 'Devanagari' },
  japanese:   { re: /[\u3040-\u309F\u30A0-\u30FF]/g, name: 'Japanese' },
  korean:     { re: /[\uAC00-\uD7AF\u1100-\u11FF\u3130-\u318F]/g, name: 'Korean' },
  greek:      { re: /[\u0370-\u03FF\u1F00-\u1FFF]/g, name: 'Greek' },
  thai:       { re: /[\u0E00-\u0E7F]/g, name: 'Thai' },
  hebrew:     { re: /[\u0590-\u05FF]/g, name: 'Hebrew' },
};

// Common English trigrams (top 30) for basic language ID
const ENGLISH_TRIGRAMS = new Set([
  'the', 'and', 'ing', 'ent', 'ion', 'tio', 'for', 'ati', 'ter', 'hat',
  'tha', 'ere', 'ate', 'his', 'con', 'res', 'ver', 'all', 'ons', 'nce',
  'men', 'ith', 'ted', 'ers', 'pro', 'thi', 'wit', 'are', 'ess', 'not',
]);

/**
 * Detect scripts present in text and their proportions
 * @param {string} text - Text to analyze
 * @returns {Object} { scripts: [{name, count, percentage}], dominant, totalChars }
 */
function detectScripts(text) {
  const results = [];
  let totalScriptChars = 0;

  for (const [key, { re, name }] of Object.entries(SCRIPTS)) {
    const matches = text.match(re);
    const count = matches ? matches.length : 0;
    if (count > 0) {
      results.push({ key, name, count });
      totalScriptChars += count;
    }
  }

  // Sort by count descending
  results.sort((a, b) => b.count - a.count);

  // Add percentages
  for (const r of results) {
    r.percentage = totalScriptChars > 0 ? Math.round((r.count / totalScriptChars) * 100) : 0;
  }

  return {
    scripts: results,
    dominant: results.length > 0 ? results[0].name : 'Unknown',
    totalChars: totalScriptChars,
  };
}

/**
 * Simple English confidence score using trigram frequency
 * @param {string} text - Text to check
 * @returns {number} 0-1 confidence that text is English
 */
function englishConfidence(text) {
  const lower = text.toLowerCase().replace(/[^a-z\s]/g, '');
  if (lower.length < 10) return 0.5; // Too short to tell
  
  const words = lower.split(/\s+/).filter(w => w.length >= 3);
  if (words.length === 0) return 0;

  let trigramHits = 0;
  let totalTrigrams = 0;
  
  for (const word of words) {
    for (let i = 0; i <= word.length - 3; i++) {
      totalTrigrams++;
      if (ENGLISH_TRIGRAMS.has(word.substring(i, i + 3))) {
        trigramHits++;
      }
    }
  }

  return totalTrigrams > 0 ? Math.min(1, trigramHits / totalTrigrams * 3) : 0;
}

/**
 * Scan text for language anomalies
 * @param {string} text - Text to scan
 * @param {Object} [opts] - Options
 * @param {string[]} [opts.expectedLanguages=['latin']] - Expected script keys
 * @param {number} [opts.anomalyThreshold=0.15] - Min percentage of unexpected script to flag
 * @param {boolean} [opts.allowMixed=false] - Allow mixed scripts without flagging
 * @returns {Object} { safe, findings, scripts, dominant }
 */
function scanLanguage(text, opts = {}) {
  const {
    expectedLanguages = ['latin'],
    anomalyThreshold = 0.15,
    allowMixed = false,
  } = opts;

  const detection = detectScripts(text);
  const findings = [];

  if (detection.totalChars < 5) {
    return { safe: true, findings: [], scripts: detection.scripts, dominant: detection.dominant };
  }

  // Check for unexpected scripts
  const unexpectedScripts = detection.scripts.filter(s => {
    const pct = s.count / detection.totalChars;
    return !expectedLanguages.includes(s.key) && pct >= anomalyThreshold;
  });

  if (unexpectedScripts.length > 0 && !allowMixed) {
    const names = unexpectedScripts.map(s => `${s.name} (${s.percentage}%)`).join(', ');
    findings.push({
      type: 'language_anomaly',
      subtype: 'unexpected_script',
      severity: 'medium',
      confidence: 0.7,
      evidence: `Unexpected script(s) detected: ${names}. Expected: ${expectedLanguages.join(', ')}`,
      scripts: unexpectedScripts.map(s => s.name),
      recommended_action: 'flag_for_review',
    });
  }

  // Check for script switching mid-text (potential injection)
  if (detection.scripts.length >= 2) {
    // Look for abrupt transitions — split text into chunks and check script consistency
    const chunks = text.match(/.{1,50}/g) || [];
    let scriptSwitches = 0;
    let lastDominant = null;

    for (const chunk of chunks) {
      const chunkDetection = detectScripts(chunk);
      if (chunkDetection.dominant !== 'Unknown') {
        if (lastDominant && chunkDetection.dominant !== lastDominant) {
          scriptSwitches++;
        }
        lastDominant = chunkDetection.dominant;
      }
    }

    if (scriptSwitches >= 3) {
      findings.push({
        type: 'language_anomaly',
        subtype: 'frequent_script_switching',
        severity: 'high',
        confidence: 0.75,
        evidence: `Text switches between scripts ${scriptSwitches} times across ${chunks.length} segments — possible multilingual injection`,
        switches: scriptSwitches,
        recommended_action: 'block',
      });
    }
  }

  // Check if predominantly non-Latin text contains embedded Latin command-like strings
  if (detection.dominant !== 'Latin' && detection.scripts.some(s => s.key === 'latin')) {
    const latinPortion = text.match(/[a-zA-Z\s]{10,}/g) || [];
    const suspiciousCommands = latinPortion.filter(p => 
      /ignore|override|system|prompt|exec|eval|admin|password|secret|token/i.test(p)
    );
    if (suspiciousCommands.length > 0) {
      findings.push({
        type: 'language_anomaly',
        subtype: 'embedded_command_in_foreign_text',
        severity: 'high',
        confidence: 0.8,
        evidence: `Found command-like Latin text embedded in ${detection.dominant} content: "${suspiciousCommands[0].trim().substring(0, 60)}"`,
        recommended_action: 'block',
      });
    }
  }

  return {
    safe: findings.length === 0,
    findings,
    scripts: detection.scripts,
    dominant: detection.dominant,
  };
}

module.exports = {
  scanLanguage,
  detectScripts,
  englishConfidence,
  SCRIPTS,
};
