/**
 * Obfuscation & Invisible Text Scanner
 * 
 * Detects hidden/disguised content in text that may be used for prompt smuggling:
 * - Zero-width characters (ZWJ, ZWNJ, ZWSP, WJ, etc.)
 * - Homoglyph attacks (Cyrillic/Greek/Latin lookalikes)
 * - Base64-encoded payloads
 * - Unicode direction overrides (RTL/LTR tricks)
 * - Invisible Unicode categories
 * - HTML comment/tag injection in text
 * - Markdown hidden content
 * - Excessive whitespace padding
 * - Mixed script attacks
 * 
 * @module obfuscation-scanner
 */

'use strict';

// Zero-width and invisible characters
const ZERO_WIDTH_CHARS = new Set([
  '\u200B', // Zero Width Space
  '\u200C', // Zero Width Non-Joiner
  '\u200D', // Zero Width Joiner
  '\u2060', // Word Joiner
  '\uFEFF', // BOM / Zero Width No-Break Space
  '\u00AD', // Soft Hyphen
  '\u034F', // Combining Grapheme Joiner
  '\u061C', // Arabic Letter Mark
  '\u180E', // Mongolian Vowel Separator
]);

// Unicode direction override characters
const BIDI_OVERRIDES = new Set([
  '\u200E', // LTR Mark
  '\u200F', // RTL Mark
  '\u202A', // LTR Embedding
  '\u202B', // RTL Embedding
  '\u202C', // Pop Directional Formatting
  '\u202D', // LTR Override
  '\u202E', // RTL Override
  '\u2066', // LTR Isolate
  '\u2067', // RTL Isolate
  '\u2068', // First Strong Isolate
  '\u2069', // Pop Directional Isolate
]);

// Tag characters (U+E0001-U+E007F) - used for language tagging, abused for hiding
const TAG_RANGE_START = 0xE0001;
const TAG_RANGE_END = 0xE007F;

// Common homoglyph mappings (Cyrillic/Greek → Latin)
const HOMOGLYPHS = new Map([
  // Cyrillic → Latin
  ['а', 'a'], ['е', 'e'], ['о', 'o'], ['р', 'p'], ['с', 'c'],
  ['у', 'y'], ['х', 'x'], ['А', 'A'], ['В', 'B'], ['С', 'C'],
  ['Е', 'E'], ['Н', 'H'], ['К', 'K'], ['М', 'M'], ['О', 'O'],
  ['Р', 'P'], ['Т', 'T'], ['Х', 'X'],
  // Greek → Latin
  ['α', 'a'], ['β', 'b'], ['ε', 'e'], ['η', 'n'], ['ι', 'i'],
  ['κ', 'k'], ['ν', 'v'], ['ο', 'o'], ['ρ', 'p'], ['τ', 't'],
  ['υ', 'u'], ['χ', 'x'], ['Α', 'A'], ['Β', 'B'], ['Ε', 'E'],
  ['Η', 'H'], ['Ι', 'I'], ['Κ', 'K'], ['Μ', 'M'], ['Ν', 'N'],
  ['Ο', 'O'], ['Ρ', 'P'], ['Τ', 'T'], ['Χ', 'X'],
  // Fullwidth → Latin
  ['ａ', 'a'], ['ｂ', 'b'], ['ｃ', 'c'], ['ｄ', 'd'], ['ｅ', 'e'],
  ['ｆ', 'f'], ['ｇ', 'g'], ['ｈ', 'h'], ['ｉ', 'i'], ['ｊ', 'j'],
]);

// Script detection regex patterns
const SCRIPT_PATTERNS = {
  latin: /[\u0041-\u005A\u0061-\u007A\u00C0-\u024F]/,
  cyrillic: /[\u0400-\u04FF]/,
  greek: /[\u0370-\u03FF]/,
  arabic: /[\u0600-\u06FF]/,
  cjk: /[\u4E00-\u9FFF\u3400-\u4DBF]/,
  hangul: /[\uAC00-\uD7AF\u1100-\u11FF]/,
  devanagari: /[\u0900-\u097F]/,
};

/**
 * Scan text for obfuscation and hidden content
 * @param {string} text - Text to scan
 * @param {Object} [opts] - Options
 * @param {number} [opts.zeroWidthThreshold=3] - Number of zero-width chars to flag
 * @param {number} [opts.homoglyphThreshold=2] - Number of homoglyphs to flag
 * @param {boolean} [opts.checkBase64=true] - Check for base64 payloads
 * @param {boolean} [opts.checkHTML=true] - Check for HTML injection
 * @param {boolean} [opts.checkMarkdown=true] - Check for markdown hiding
 * @returns {Object} Scan result with findings
 */
function scanObfuscation(text, opts = {}) {
  const {
    zeroWidthThreshold = 3,
    homoglyphThreshold = 2,
    checkBase64 = true,
    checkHTML = true,
    checkMarkdown = true,
  } = opts;

  const findings = [];

  // 1. Zero-width characters
  const zwFindings = detectZeroWidth(text, zeroWidthThreshold);
  if (zwFindings) findings.push(zwFindings);

  // 2. Bidi overrides
  const bidiFindings = detectBidiOverrides(text);
  if (bidiFindings) findings.push(bidiFindings);

  // 3. Tag characters
  const tagFindings = detectTagCharacters(text);
  if (tagFindings) findings.push(tagFindings);

  // 4. Homoglyphs
  const homoFindings = detectHomoglyphs(text, homoglyphThreshold);
  if (homoFindings) findings.push(homoFindings);

  // 5. Mixed scripts
  const mixedFindings = detectMixedScripts(text);
  if (mixedFindings) findings.push(mixedFindings);

  // 6. Base64 payloads
  if (checkBase64) {
    const b64Findings = detectBase64Payloads(text);
    if (b64Findings) findings.push(b64Findings);
  }

  // 7. HTML injection
  if (checkHTML) {
    const htmlFindings = detectHTMLInjection(text);
    if (htmlFindings) findings.push(htmlFindings);
  }

  // 8. Markdown hiding
  if (checkMarkdown) {
    const mdFindings = detectMarkdownHiding(text);
    if (mdFindings) findings.push(mdFindings);
  }

  // 9. Invisible Unicode categories
  const invisFindings = detectInvisibleUnicode(text);
  if (invisFindings) findings.push(invisFindings);

  const maxSeverity = findings.reduce((max, f) => {
    const order = { critical: 4, high: 3, medium: 2, low: 1 };
    return (order[f.severity] || 0) > (order[max] || 0) ? f.severity : max;
  }, 'low');

  return {
    safe: findings.length === 0,
    findings,
    score: Math.min(100, findings.reduce((s, f) => {
      const w = { critical: 40, high: 25, medium: 15, low: 5 };
      return s + (w[f.severity] || 5);
    }, 0)),
    maxSeverity: findings.length > 0 ? maxSeverity : null,
  };
}

function detectZeroWidth(text, threshold) {
  let count = 0;
  const positions = [];
  for (let i = 0; i < text.length; i++) {
    if (ZERO_WIDTH_CHARS.has(text[i])) {
      count++;
      if (positions.length < 5) positions.push(i);
    }
  }
  if (count >= threshold) {
    return {
      type: 'obfuscation',
      subtype: 'zero_width_characters',
      severity: count > 10 ? 'high' : 'medium',
      confidence: Math.min(0.95, 0.5 + count * 0.05),
      evidence: `Found ${count} zero-width characters at positions: ${positions.join(', ')}${count > 5 ? '...' : ''}`,
      count,
      recommended_action: 'strip_and_rescan',
    };
  }
  return null;
}

function detectBidiOverrides(text) {
  let count = 0;
  const found = [];
  for (let i = 0; i < text.length; i++) {
    if (BIDI_OVERRIDES.has(text[i])) {
      count++;
      const name = getBidiName(text[i]);
      if (found.length < 3) found.push(name);
    }
  }
  if (count > 0) {
    return {
      type: 'obfuscation',
      subtype: 'bidi_override',
      severity: 'high',
      confidence: 0.9,
      evidence: `Found ${count} bidirectional override(s): ${found.join(', ')}`,
      count,
      recommended_action: 'block',
    };
  }
  return null;
}

function getBidiName(char) {
  const names = {
    '\u200E': 'LTR Mark', '\u200F': 'RTL Mark',
    '\u202A': 'LTR Embedding', '\u202B': 'RTL Embedding',
    '\u202C': 'Pop Dir', '\u202D': 'LTR Override', '\u202E': 'RTL Override',
    '\u2066': 'LTR Isolate', '\u2067': 'RTL Isolate',
    '\u2068': 'First Strong Isolate', '\u2069': 'Pop Dir Isolate',
  };
  return names[char] || `U+${char.charCodeAt(0).toString(16).toUpperCase()}`;
}

function detectTagCharacters(text) {
  let count = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp >= TAG_RANGE_START && cp <= TAG_RANGE_END) count++;
  }
  if (count > 0) {
    return {
      type: 'obfuscation',
      subtype: 'unicode_tag_characters',
      severity: 'critical',
      confidence: 0.95,
      evidence: `Found ${count} Unicode tag character(s) — commonly used for steganographic hiding`,
      count,
      recommended_action: 'block',
    };
  }
  return null;
}

function detectHomoglyphs(text, threshold) {
  let count = 0;
  const examples = [];
  for (let i = 0; i < text.length; i++) {
    const latin = HOMOGLYPHS.get(text[i]);
    if (latin) {
      count++;
      if (examples.length < 3) {
        examples.push(`'${text[i]}' (looks like '${latin}') at pos ${i}`);
      }
    }
  }
  // Only flag if mixed with Latin — pure Cyrillic text is fine
  if (count >= threshold && SCRIPT_PATTERNS.latin.test(text)) {
    return {
      type: 'obfuscation',
      subtype: 'homoglyph_attack',
      severity: 'high',
      confidence: Math.min(0.9, 0.4 + count * 0.1),
      evidence: `Found ${count} homoglyph(s) mixed with Latin text: ${examples.join('; ')}`,
      count,
      recommended_action: 'normalize_and_rescan',
    };
  }
  return null;
}

function detectMixedScripts(text) {
  // Only flag if 3+ scripts are mixed (2 is common in multilingual text)
  const detectedScripts = [];
  for (const [name, pattern] of Object.entries(SCRIPT_PATTERNS)) {
    if (pattern.test(text)) detectedScripts.push(name);
  }
  if (detectedScripts.length >= 3) {
    return {
      type: 'obfuscation',
      subtype: 'mixed_scripts',
      severity: 'medium',
      confidence: 0.6,
      evidence: `Text contains ${detectedScripts.length} different scripts: ${detectedScripts.join(', ')}`,
      scripts: detectedScripts,
      recommended_action: 'flag_for_review',
    };
  }
  return null;
}

function detectBase64Payloads(text) {
  // Look for base64 strings that decode to something meaningful
  const b64Pattern = /(?:^|[\s=:])([A-Za-z0-9+/]{32,}={0,2})(?:[\s,.]|$)/gm;
  const matches = [];
  let m;
  while ((m = b64Pattern.exec(text)) !== null) {
    try {
      const decoded = Buffer.from(m[1], 'base64').toString('utf8');
      // Check if decoded content looks meaningful (high ratio of printable chars)
      const printable = decoded.replace(/[^\x20-\x7E]/g, '').length;
      if (printable / decoded.length > 0.7 && decoded.length > 10) {
        const preview = decoded.substring(0, 60).replace(/[^\x20-\x7E]/g, '?');
        matches.push(preview);
      }
    } catch (_) { /* not valid base64, skip */ }
  }
  if (matches.length > 0) {
    return {
      type: 'obfuscation',
      subtype: 'base64_payload',
      severity: 'high',
      confidence: 0.75,
      evidence: `Found ${matches.length} base64-encoded payload(s): "${matches[0]}${matches[0].length >= 60 ? '...' : ''}"`,
      count: matches.length,
      recommended_action: 'decode_and_rescan',
    };
  }
  return null;
}

function detectHTMLInjection(text) {
  const patterns = [
    { re: /<!--[\s\S]*?-->/g, name: 'HTML comment', severity: 'high' },
    { re: /<script[\s>]/gi, name: 'script tag', severity: 'critical' },
    { re: /<style[\s>]/gi, name: 'style tag', severity: 'high' },
    { re: /<iframe[\s>]/gi, name: 'iframe tag', severity: 'critical' },
    { re: /<img[^>]+onerror/gi, name: 'img onerror', severity: 'critical' },
    { re: /<[a-z]+[^>]*\son\w+\s*=/gi, name: 'event handler', severity: 'high' },
    { re: /<div[^>]*style\s*=\s*["'][^"']*display\s*:\s*none/gi, name: 'hidden div', severity: 'high' },
    { re: /<span[^>]*style\s*=\s*["'][^"']*font-size\s*:\s*0/gi, name: 'zero-size text', severity: 'high' },
  ];

  const found = [];
  for (const { re, name, severity } of patterns) {
    if (re.test(text)) {
      found.push({ name, severity });
    }
  }
  if (found.length > 0) {
    const maxSev = found.reduce((max, f) => {
      const order = { critical: 3, high: 2, medium: 1 };
      return (order[f.severity] || 0) > (order[max] || 0) ? f.severity : max;
    }, 'medium');
    return {
      type: 'obfuscation',
      subtype: 'html_injection',
      severity: maxSev,
      confidence: 0.85,
      evidence: `Found HTML injection patterns: ${found.map(f => f.name).join(', ')}`,
      patterns: found.map(f => f.name),
      recommended_action: 'strip_html',
    };
  }
  return null;
}

function detectMarkdownHiding(text) {
  const patterns = [
    { re: /\[([^\]]*)\]\([^)]*\s+"[^"]*"\)/g, name: 'markdown link with hidden title' },
    { re: /!\[[^\]]*\]\([^)]*\)/g, name: 'image embed (potential exfil)' },
    { re: /\[([^\]]{200,})\]/g, name: 'oversized link text (payload hiding)' },
    { re: /<!--[\s\S]*?-->/g, name: 'HTML comment in markdown' },
    { re: /\n\s*\[\/\/\]:\s*#\s*\(/g, name: 'markdown reference link comment' },
  ];

  const found = [];
  for (const { re, name } of patterns) {
    if (re.test(text)) {
      found.push(name);
    }
  }
  if (found.length > 0) {
    return {
      type: 'obfuscation',
      subtype: 'markdown_hiding',
      severity: 'medium',
      confidence: 0.6,
      evidence: `Potential markdown-based content hiding: ${found.join(', ')}`,
      patterns: found,
      recommended_action: 'strip_markdown',
    };
  }
  return null;
}

function detectInvisibleUnicode(text) {
  // Detect characters from invisible/formatting Unicode categories
  let count = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (
      (cp >= 0x2000 && cp <= 0x200F) || // General punctuation space + formatting
      (cp >= 0x2028 && cp <= 0x202F) || // Separators + bidi
      (cp >= 0x2060 && cp <= 0x2069) || // Invisible operators + bidi
      (cp >= 0xFFF0 && cp <= 0xFFFF) || // Specials
      cp === 0x00A0 || // Non-breaking space
      cp === 0x1680 || // Ogham space
      cp === 0x3000    // Ideographic space
    ) {
      // Already counted by zero-width and bidi detectors — skip those
      if (!ZERO_WIDTH_CHARS.has(ch) && !BIDI_OVERRIDES.has(ch)) {
        count++;
      }
    }
  }
  if (count > 5) {
    return {
      type: 'obfuscation',
      subtype: 'invisible_unicode',
      severity: 'medium',
      confidence: 0.7,
      evidence: `Found ${count} invisible/formatting Unicode characters`,
      count,
      recommended_action: 'normalize',
    };
  }
  return null;
}

/**
 * Strip all detected obfuscation from text (for decontamination)
 * @param {string} text - Text to clean
 * @returns {string} Cleaned text
 */
function stripObfuscation(text) {
  let clean = text;
  // Remove zero-width characters
  for (const zw of ZERO_WIDTH_CHARS) {
    clean = clean.split(zw).join('');
  }
  // Remove bidi overrides
  for (const bidi of BIDI_OVERRIDES) {
    clean = clean.split(bidi).join('');
  }
  // Remove tag characters
  clean = Array.from(clean).filter(ch => {
    const cp = ch.codePointAt(0);
    return cp < TAG_RANGE_START || cp > TAG_RANGE_END;
  }).join('');
  // Normalize homoglyphs to Latin
  clean = Array.from(clean).map(ch => HOMOGLYPHS.get(ch) || ch).join('');
  // Strip HTML comments
  clean = clean.replace(/<!--[\s\S]*?-->/g, '');
  return clean;
}

module.exports = {
  scanObfuscation,
  stripObfuscation,
  detectZeroWidth,
  detectBidiOverrides,
  detectTagCharacters,
  detectHomoglyphs,
  detectMixedScripts,
  detectBase64Payloads,
  detectHTMLInjection,
  detectMarkdownHiding,
  detectInvisibleUnicode,
  HOMOGLYPHS,
  ZERO_WIDTH_CHARS,
  BIDI_OVERRIDES,
};
