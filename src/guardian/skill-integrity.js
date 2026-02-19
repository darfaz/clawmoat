/**
 * ClawMoat Skill Integrity Checker
 * 
 * Hashes skill files on startup, detects modifications, and flags
 * suspicious patterns in skill content.
 * 
 * @module clawmoat/guardian/skill-integrity
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const HASH_FILE = '.clawmoat-hashes.json';

// Suspicious patterns that may indicate malicious skills
const SUSPICIOUS_PATTERNS = [
  { pattern: /\bcurl\s+(?:https?:\/\/|ftp:\/\/)\S+/gi, label: 'curl to external URL', severity: 'warning' },
  { pattern: /\bwget\s+(?:https?:\/\/|ftp:\/\/)\S+/gi, label: 'wget to external URL', severity: 'warning' },
  { pattern: /\beval\s*\(/gi, label: 'eval() usage', severity: 'critical' },
  { pattern: /\bnew\s+Function\s*\(/gi, label: 'new Function() usage', severity: 'critical' },
  { pattern: /\batob\s*\(/gi, label: 'base64 decode (atob)', severity: 'warning' },
  { pattern: /\bbtoa\s*\(/gi, label: 'base64 encode (btoa)', severity: 'warning' },
  { pattern: /Buffer\.from\s*\([^)]*,\s*['"]base64['"]\s*\)/gi, label: 'Buffer base64 decode', severity: 'warning' },
  { pattern: /\bbase64\b.*(?:decode|encode)/gi, label: 'base64 operation', severity: 'warning' },
  { pattern: /(?:\/etc\/passwd|\/etc\/shadow|~\/\.ssh|~\/\.aws|~\/\.gnupg)/g, label: 'sensitive file reference', severity: 'critical' },
  { pattern: /\bexec\s*\(\s*['"`]/gi, label: 'exec() with string', severity: 'warning' },
  { pattern: /\bchild_process\b/gi, label: 'child_process usage', severity: 'warning' },
  { pattern: /\brequire\s*\(\s*['"]child_process['"]\s*\)/gi, label: 'require child_process', severity: 'warning' },
  { pattern: /(?:nc|netcat)\s+-[a-z]*e\s/gi, label: 'reverse shell pattern', severity: 'critical' },
  { pattern: /\|\s*(?:bash|sh|zsh)\b/gi, label: 'pipe to shell', severity: 'critical' },
];

/**
 * Hash a file's contents using SHA-256.
 * @param {string} filePath
 * @returns {string|null} hex hash or null if file unreadable
 */
function hashFile(filePath) {
  try {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
  } catch {
    return null;
  }
}

/**
 * Recursively find skill files in a directory.
 * Returns SKILL.md files and associated scripts (*.js, *.sh, *.py, *.ts).
 * @param {string} dir - Skills directory
 * @returns {string[]} Array of file paths
 */
function findSkillFiles(dir) {
  const files = [];
  if (!fs.existsSync(dir)) return files;

  const walk = (d) => {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.git') continue;
        walk(full);
      } else if (
        entry.name === 'SKILL.md' ||
        /\.(js|sh|py|ts)$/.test(entry.name)
      ) {
        files.push(full);
      }
    }
  };

  walk(dir);
  return files;
}

/**
 * Scan file content for suspicious patterns.
 * @param {string} content - File content
 * @param {string} filePath - File path (for reporting)
 * @returns {{ suspicious: boolean, findings: Array }}
 */
function scanForSuspicious(content, filePath) {
  const findings = [];
  for (const rule of SUSPICIOUS_PATTERNS) {
    // Reset regex lastIndex
    rule.pattern.lastIndex = 0;
    const match = rule.pattern.exec(content);
    if (match) {
      findings.push({
        file: filePath,
        label: rule.label,
        severity: rule.severity,
        matched: match[0].substring(0, 100),
      });
    }
  }
  return { suspicious: findings.length > 0, findings };
}

class SkillIntegrityChecker {
  /**
   * @param {Object} opts
   * @param {string} opts.skillsDir - Path to skills directory
   * @param {string} [opts.hashFile] - Path to hash lockfile
   * @param {Function} [opts.onAlert] - Callback for alerts: (alert) => void
   */
  constructor(opts = {}) {
    this.skillsDir = opts.skillsDir || '';
    this.hashFilePath = opts.hashFile || path.join(this.skillsDir, HASH_FILE);
    this.onAlert = opts.onAlert || null;
    this.hashes = {};
    this.watcher = null;
  }

  /**
   * Initialize: hash all skill files and store/compare with lockfile.
   * @returns {{ files: number, new: number, changed: number, suspicious: Array }}
   */
  init() {
    const files = findSkillFiles(this.skillsDir);
    const currentHashes = {};
    const suspiciousFindings = [];
    let newFiles = 0;
    let changedFiles = 0;

    // Load existing hashes
    const storedHashes = this._loadHashes();

    for (const file of files) {
      const hash = hashFile(file);
      if (!hash) continue;

      const rel = path.relative(this.skillsDir, file);
      currentHashes[rel] = hash;

      // Check for changes
      if (!storedHashes[rel]) {
        newFiles++;
      } else if (storedHashes[rel] !== hash) {
        changedFiles++;
        this._alert({
          severity: 'warning',
          type: 'skill_modified',
          message: `Skill file modified: ${rel}`,
          details: { file: rel, oldHash: storedHashes[rel], newHash: hash },
        });
      }

      // Scan content for suspicious patterns
      try {
        const content = fs.readFileSync(file, 'utf8');
        const scan = scanForSuspicious(content, rel);
        if (scan.suspicious) {
          suspiciousFindings.push(...scan.findings);
        }
      } catch {}
    }

    this.hashes = currentHashes;
    this._saveHashes(currentHashes);

    return {
      files: files.length,
      new: newFiles,
      changed: changedFiles,
      suspicious: suspiciousFindings,
    };
  }

  /**
   * Audit: verify all current skill files against stored hashes.
   * @returns {{ ok: boolean, files: number, changed: string[], missing: string[], suspicious: Array }}
   */
  audit() {
    const storedHashes = this._loadHashes();
    const files = findSkillFiles(this.skillsDir);
    const changed = [];
    const missing = [];
    const suspiciousFindings = [];

    // Check stored files still exist and match
    for (const [rel, storedHash] of Object.entries(storedHashes)) {
      const full = path.join(this.skillsDir, rel);
      const currentHash = hashFile(full);
      if (!currentHash) {
        missing.push(rel);
      } else if (currentHash !== storedHash) {
        changed.push(rel);
      }
    }

    // Scan for suspicious patterns
    for (const file of files) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        const rel = path.relative(this.skillsDir, file);
        const scan = scanForSuspicious(content, rel);
        if (scan.suspicious) suspiciousFindings.push(...scan.findings);
      } catch {}
    }

    return {
      ok: changed.length === 0 && missing.length === 0 && suspiciousFindings.length === 0,
      files: Object.keys(storedHashes).length,
      changed,
      missing,
      suspicious: suspiciousFindings,
    };
  }

  /**
   * Watch skills directory for changes (real-time monitoring).
   * @returns {fs.FSWatcher|null}
   */
  watch() {
    if (!fs.existsSync(this.skillsDir)) return null;

    this.watcher = fs.watch(this.skillsDir, { recursive: true }, (eventType, filename) => {
      if (!filename) return;
      if (filename === HASH_FILE || filename.includes('node_modules')) return;

      const ext = path.extname(filename);
      if (filename !== 'SKILL.md' && !['.js', '.sh', '.py', '.ts'].includes(ext)) return;

      const full = path.join(this.skillsDir, filename);
      const hash = hashFile(full);
      const stored = this.hashes[filename];

      if (hash && stored && hash !== stored) {
        this._alert({
          severity: 'warning',
          type: 'skill_modified',
          message: `Skill file changed: ${filename}`,
          details: { file: filename, oldHash: stored, newHash: hash },
        });
        this.hashes[filename] = hash;
        this._saveHashes(this.hashes);
      } else if (hash && !stored) {
        this._alert({
          severity: 'info',
          type: 'skill_added',
          message: `New skill file: ${filename}`,
          details: { file: filename, hash },
        });
        this.hashes[filename] = hash;
        this._saveHashes(this.hashes);
      }
    });

    return this.watcher;
  }

  stop() {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
  }

  _loadHashes() {
    try {
      return JSON.parse(fs.readFileSync(this.hashFilePath, 'utf8'));
    } catch {
      return {};
    }
  }

  _saveHashes(hashes) {
    try {
      const dir = path.dirname(this.hashFilePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.hashFilePath, JSON.stringify(hashes, null, 2) + '\n');
    } catch {}
  }

  _alert(alert) {
    if (this.onAlert) this.onAlert(alert);
  }
}

module.exports = {
  SkillIntegrityChecker,
  hashFile,
  findSkillFiles,
  scanForSuspicious,
  SUSPICIOUS_PATTERNS,
};
