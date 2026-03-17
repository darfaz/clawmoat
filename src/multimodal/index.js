/**
 * Multimodal Input Scanning
 * Scan base64 image data URLs, PDF text content, and file metadata for threats
 * 
 * Focuses on detectable patterns without external dependencies:
 * - Metadata analysis (MIME type validation, filename patterns)
 * - Embedded strings in base64 content (between tags, steganographic patterns)
 * - Size anomalies and suspicious payloads
 * - Hidden text injection patterns
 * 
 * @module multimodal
 * @example
 * const { scanMultimodalInput } = require('./multimodal');
 * 
 * const result = scanMultimodalInput({
 *   content: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...',
 *   filename: 'innocent.png',
 *   mimeType: 'image/png'
 * });
 * 
 * if (!result.safe) {
 *   console.log('Threats found:', result.findings);
 * }
 */

const { Buffer } = require('buffer');
const path = require('path');

/**
 * @typedef {Object} MultimodalScanResult
 * @property {boolean} safe - true if no threats detected
 * @property {Array} findings - Array of detected threat patterns
 * @property {string|null} maxSeverity - Highest severity among findings
 */

/**
 * @typedef {Object} MultimodalInput
 * @property {string} content - Base64 data URL or text content
 * @property {string} [filename] - Original filename if available
 * @property {string} [mimeType] - MIME type if available
 * @property {number} [size] - File size in bytes if available
 */

/**
 * Suspicious file extensions that should trigger enhanced scanning
 */
const SUSPICIOUS_EXTENSIONS = [
  '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.jar',
  '.ps1', '.sh', '.py', '.rb', '.php', '.asp', '.jsp', '.pl'
];

/**
 * Expected MIME types for common file extensions
 */
const MIME_TYPE_MAP = {
  '.png': ['image/png'],
  '.jpg': ['image/jpeg'],
  '.jpeg': ['image/jpeg'],
  '.gif': ['image/gif'],
  '.webp': ['image/webp'],
  '.svg': ['image/svg+xml'],
  '.pdf': ['application/pdf'],
  '.txt': ['text/plain'],
  '.json': ['application/json'],
  '.xml': ['application/xml', 'text/xml'],
  '.html': ['text/html'],
  '.css': ['text/css'],
  '.js': ['application/javascript', 'text/javascript']
};

/**
 * Patterns that indicate potential prompt injection in embedded content
 */
const INJECTION_PATTERNS = [
  // Direct injection attempts
  /ignore\s+(?:previous|all)\s+instructions?/gi,
  /system\s*:\s*you\s+are\s+now/gi,
  /forget\s+(?:everything|all)\s+(?:above|before)/gi,
  /act\s+as\s+(?:if\s+you\s+are|a)\s+(?:different|new)/gi,
  
  // Hidden instruction markers
  /<!--\s*(?:system|instruction|prompt)/gi,
  /\[(?:SYSTEM|INSTRUCTION|PROMPT)\]/gi,
  /<(?:system|instruction|prompt)>/gi,
  
  // Steganographic patterns
  /\u200b|\u200c|\u200d|\ufeff/g, // Zero-width characters
  /\u00a0{2,}/g, // Multiple non-breaking spaces
  
  // Base64 encoded instructions (common patterns)
  /aWdub3Jl|c3lzdGVt|Zm9yZ2V0|YWN0IGFz/g, // base64 for: ignore, system, forget, act as
  
  // URL-like patterns that could be callback URLs
  /(?:https?:\/\/|data:)[^\s\'"]{20,}/gi
];

/**
 * Patterns indicating potential steganographic content
 */
const STEGANOGRAPHIC_PATTERNS = [
  // Repeated patterns that might hide data
  /(.{1,4})\1{10,}/g, // Same 1-4 character sequence repeated 10+ times
  
  // Unusual entropy markers
  /[A-Za-z0-9+/=]{100,}/g, // Long base64-like sequences
  
  // Hidden text markers
  /\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08/g, // Control characters
];

/**
 * PDF-specific threat patterns
 */
const PDF_THREAT_PATTERNS = [
  // JavaScript in PDFs
  /\/JavaScript/gi,
  /\/JS/gi,
  
  // Launch actions
  /\/Launch/gi,
  /\/F\s*\(.*\.(?:exe|bat|cmd|scr)\)/gi,
  
  // Embedded files
  /\/EmbeddedFile/gi,
  /\/FileAttachment/gi,
  
  // Form actions
  /\/URI\s*\(.*(?:javascript|data:)/gi
];

/**
 * Analyze filename for suspicious patterns
 * @param {string} filename 
 * @returns {Array} Array of findings
 */
function analyzeFilename(filename) {
  if (!filename) return [];
  
  const findings = [];
  const ext = path.extname(filename).toLowerCase();
  const basename = path.basename(filename, ext);
  
  // Check for suspicious extensions
  if (SUSPICIOUS_EXTENSIONS.includes(ext)) {
    findings.push({
      type: 'suspicious_file_extension',
      subtype: 'executable_extension',
      severity: 'high',
      matched: ext,
      position: filename.lastIndexOf(ext),
      message: `Potentially dangerous file extension: ${ext}`
    });
  }
  
  // Check for double extensions (e.g., file.txt.exe)
  const doubleExtMatch = filename.match(/\.([^.]+)\.([^.]+)$/);
  if (doubleExtMatch && SUSPICIOUS_EXTENSIONS.includes('.' + doubleExtMatch[2])) {
    findings.push({
      type: 'filename_obfuscation',
      subtype: 'double_extension',
      severity: 'high',
      matched: doubleExtMatch[0],
      position: doubleExtMatch.index,
      message: 'Double file extension detected (possible obfuscation)'
    });
  }
  
  // Check for null bytes in filename
  if (filename.includes('\x00')) {
    findings.push({
      type: 'filename_injection',
      subtype: 'null_byte',
      severity: 'critical',
      matched: '\\x00',
      position: filename.indexOf('\x00'),
      message: 'Null byte in filename (path traversal attempt)'
    });
  }
  
  // Check for path traversal patterns
  if (filename.includes('../') || filename.includes('..\\')) {
    findings.push({
      type: 'filename_injection',
      subtype: 'path_traversal',
      severity: 'high',
      matched: filename.includes('../') ? '../' : '..\\',
      position: Math.max(filename.indexOf('../'), filename.indexOf('..\\')),
      message: 'Path traversal pattern in filename'
    });
  }
  
  // Check for drive-relative path traversal (Windows) — GHSA-qffp-2rhf-9h96
  // Patterns like "C:target" (no backslash) resolve to current dir of that drive,
  // bypassing ../  checks. Also catch absolute paths and UNC paths.
  const driveRelativeMatch = filename.match(/^[A-Za-z]:[^\\\/]/);
  const absolutePathMatch = filename.match(/^[A-Za-z]:[\\\/]/) || filename.startsWith('/') || filename.startsWith('\\\\');
  if (driveRelativeMatch) {
    findings.push({
      type: 'filename_injection',
      subtype: 'drive_relative_traversal',
      severity: 'high',
      matched: driveRelativeMatch[0],
      position: 0,
      message: 'Drive-relative path traversal (Windows) — can escape extraction directory'
    });
  }
  if (absolutePathMatch) {
    findings.push({
      type: 'filename_injection',
      subtype: 'absolute_path',
      severity: 'high',
      matched: filename.substring(0, 10),
      position: 0,
      message: 'Absolute path in filename — may write outside intended directory'
    });
  }
  
  // Check for extremely long filenames (possible buffer overflow attempt)
  if (filename.length > 255) {
    findings.push({
      type: 'filename_anomaly',
      subtype: 'excessive_length',
      severity: 'medium',
      matched: filename.substring(0, 50) + '...',
      position: 255,
      message: `Filename exceeds typical limits (${filename.length} characters)`
    });
  }
  
  return findings;
}

/**
 * Validate MIME type against filename extension
 * @param {string} filename 
 * @param {string} mimeType 
 * @returns {Array} Array of findings
 */
function validateMimeType(filename, mimeType) {
  if (!filename || !mimeType) return [];
  
  const findings = [];
  const ext = path.extname(filename).toLowerCase();
  const expectedMimes = MIME_TYPE_MAP[ext];
  
  if (expectedMimes && !expectedMimes.includes(mimeType)) {
    findings.push({
      type: 'mime_mismatch',
      subtype: 'extension_mismatch',
      severity: 'medium',
      matched: mimeType,
      message: `MIME type '${mimeType}' doesn't match extension '${ext}' (expected: ${expectedMimes.join(' or ')})`
    });
  }
  
  // Check for dangerous MIME types
  const dangerousMimes = [
    'application/x-msdownload',
    'application/x-executable',
    'application/x-msdos-program',
    'application/x-ms-shortcut'
  ];
  
  if (dangerousMimes.includes(mimeType)) {
    findings.push({
      type: 'dangerous_mime_type',
      subtype: 'executable_mime',
      severity: 'critical',
      matched: mimeType,
      message: `Dangerous MIME type detected: ${mimeType}`
    });
  }
  
  return findings;
}

/**
 * Analyze data URL for embedded threats
 * @param {string} dataUrl 
 * @returns {Array} Array of findings
 */
function analyzeDataUrl(dataUrl) {
  if (!dataUrl.startsWith('data:')) return [];
  
  const findings = [];
  
  try {
    // Parse data URL
    const [header, data] = dataUrl.split(',');
    const [mimeType, encoding] = header.replace('data:', '').split(';');
    
    // Check for suspicious MIME types in data URLs
    if (mimeType === 'text/html' || mimeType === 'application/javascript') {
      findings.push({
        type: 'suspicious_data_url',
        subtype: 'executable_content',
        severity: 'high',
        matched: mimeType,
        message: `Potentially dangerous data URL MIME type: ${mimeType}`
      });
    }
    
    if (encoding === 'base64' && data) {
      // Decode base64 and scan for patterns
      try {
        const decoded = Buffer.from(data, 'base64').toString('utf8');
        const injectionFindings = scanForInjectionPatterns(decoded);
        findings.push(...injectionFindings);
        
      } catch (err) {
        // If base64 decode fails, still check the raw data for patterns
        const rawFindings = scanRawBase64(data);
        findings.push(...rawFindings);
      }
    }
    
    // Check for oversized data URLs (possible DoS)
    if (data && data.length > 10 * 1024 * 1024) { // 10MB limit
      findings.push({
        type: 'size_anomaly',
        subtype: 'oversized_data_url',
        severity: 'medium',
        matched: `${Math.round(data.length / 1024 / 1024)}MB`,
        message: `Extremely large data URL (${Math.round(data.length / 1024 / 1024)}MB)`
      });
    }
    
  } catch (err) {
    findings.push({
      type: 'malformed_data_url',
      subtype: 'parse_error',
      severity: 'low',
      matched: dataUrl.substring(0, 100),
      message: 'Malformed data URL structure'
    });
  }
  
  return findings;
}

/**
 * Scan text content for injection patterns
 * @param {string} content 
 * @returns {Array} Array of findings
 */
function scanForInjectionPatterns(content) {
  const findings = [];
  
  for (const pattern of INJECTION_PATTERNS) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      findings.push({
        type: 'embedded_injection',
        subtype: 'prompt_injection',
        severity: 'high',
        matched: match[0],
        position: match.index,
        message: 'Potential prompt injection pattern detected in embedded content'
      });
    }
  }
  
  for (const pattern of STEGANOGRAPHIC_PATTERNS) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      findings.push({
        type: 'steganographic_pattern',
        subtype: 'hidden_data',
        severity: 'medium',
        matched: match[0].substring(0, 50),
        position: match.index,
        message: 'Potential steganographic or hidden data pattern'
      });
    }
  }
  
  return findings;
}

/**
 * Scan raw base64 data for patterns without decoding
 * @param {string} base64Data 
 * @returns {Array} Array of findings
 */
function scanRawBase64(base64Data) {
  const findings = [];
  
  // Check for known base64-encoded malicious patterns
  const maliciousB64Patterns = [
    /aWdub3JlXHMrKD86cHJldmlvdXN8YWxsKVxzK2luc3RydWN0aW9ucz8=/g, // "ignore previous instructions"
    /c3lzdGVtXHMqOlxzKnlvdVxzK2FyZVxzK25vdw==/g, // "system: you are now"
    /Zm9yZ2V0XHMrKD86ZXZlcnl0aGluZ3xhbGwpXHMrKD86YWJvdmV8YmVmb3JlKQ==/g, // "forget everything above"
  ];
  
  for (const pattern of maliciousB64Patterns) {
    const matches = [...base64Data.matchAll(pattern)];
    for (const match of matches) {
      findings.push({
        type: 'encoded_injection',
        subtype: 'base64_injection',
        severity: 'high',
        matched: match[0],
        position: match.index,
        message: 'Base64-encoded injection pattern detected'
      });
    }
  }
  
  return findings;
}

/**
 * Scan PDF text content for threats
 * @param {string} pdfText 
 * @returns {Array} Array of findings
 */
function scanPdfContent(pdfText) {
  if (!pdfText) return [];
  
  const findings = [];
  
  for (const pattern of PDF_THREAT_PATTERNS) {
    const matches = [...pdfText.matchAll(pattern)];
    for (const match of matches) {
      findings.push({
        type: 'pdf_threat',
        subtype: 'suspicious_pdf_feature',
        severity: 'high',
        matched: match[0],
        position: match.index,
        message: 'Suspicious PDF feature detected (JavaScript, launch action, or embedded file)'
      });
    }
  }
  
  // Scan for general injection patterns in PDF text
  const injectionFindings = scanForInjectionPatterns(pdfText);
  findings.push(...injectionFindings);
  
  return findings;
}

/**
 * Check for size anomalies that might indicate malicious content
 * @param {MultimodalInput} input 
 * @returns {Array} Array of findings
 */
function checkSizeAnomalies(input) {
  const findings = [];
  
  if (input.size) {
    // Check for suspiciously small files that claim to be images
    if (input.mimeType && input.mimeType.startsWith('image/') && input.size < 100) {
      findings.push({
        type: 'size_anomaly',
        subtype: 'suspiciously_small',
        severity: 'low',
        matched: `${input.size} bytes`,
        message: `Suspiciously small image file (${input.size} bytes)`
      });
    }
    
    // Check for extremely large files (potential DoS)
    if (input.size > 100 * 1024 * 1024) { // 100MB
      findings.push({
        type: 'size_anomaly',
        subtype: 'extremely_large',
        severity: 'medium',
        matched: `${Math.round(input.size / 1024 / 1024)}MB`,
        message: `Extremely large file (${Math.round(input.size / 1024 / 1024)}MB) - potential DoS`
      });
    }
  }
  
  return findings;
}

/**
 * Main multimodal input scanner
 * @param {MultimodalInput} input 
 * @returns {MultimodalScanResult}
 */
function scanMultimodalInput(input) {
  if (!input) {
    return { safe: true, findings: [], maxSeverity: null };
  }
  
  const findings = [];
  
  // Analyze filename if provided
  if (input.filename) {
    findings.push(...analyzeFilename(input.filename));
  }
  
  // Validate MIME type against filename
  if (input.filename && input.mimeType) {
    findings.push(...validateMimeType(input.filename, input.mimeType));
  }
  
  // Check size anomalies
  findings.push(...checkSizeAnomalies(input));
  
  // Analyze content based on type
  if (input.content) {
    if (input.content.startsWith('data:')) {
      // Data URL analysis
      findings.push(...analyzeDataUrl(input.content));
    } else if (input.mimeType === 'application/pdf') {
      // PDF content analysis
      findings.push(...scanPdfContent(input.content));
    } else if (typeof input.content === 'string') {
      // Generic text content analysis
      findings.push(...scanForInjectionPatterns(input.content));
    }
  }
  
  // Determine overall safety and max severity
  const safe = findings.length === 0;
  let maxSeverity = null;
  
  if (!safe) {
    const severityRank = { low: 0, medium: 1, high: 2, critical: 3 };
    maxSeverity = findings.reduce((max, finding) => {
      return (severityRank[finding.severity] || 0) > (severityRank[max] || 0) 
        ? finding.severity 
        : max;
    }, 'low');
  }
  
  return {
    safe,
    findings,
    maxSeverity
  };
}

/**
 * Convenience function to scan image data URLs
 * @param {string} dataUrl 
 * @param {string} [filename] 
 * @returns {MultimodalScanResult}
 */
function scanImageDataUrl(dataUrl, filename = null) {
  const mimeMatch = dataUrl.match(/data:([^;]+)/);
  const mimeType = mimeMatch ? mimeMatch[1] : null;
  
  return scanMultimodalInput({
    content: dataUrl,
    filename,
    mimeType
  });
}

/**
 * Convenience function to scan file metadata
 * @param {string} filename 
 * @param {string} mimeType 
 * @param {number} [size] 
 * @returns {MultimodalScanResult}
 */
function scanFileMetadata(filename, mimeType, size = null) {
  return scanMultimodalInput({
    content: '',
    filename,
    mimeType,
    size
  });
}

module.exports = {
  scanMultimodalInput,
  scanImageDataUrl,
  scanFileMetadata,
  analyzeFilename,
  validateMimeType,
  analyzeDataUrl,
  scanForInjectionPatterns,
  scanPdfContent
};