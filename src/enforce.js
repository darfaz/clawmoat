/**
 * ClawMoat Enforcement Mode — Actually block, not just detect
 * Express/Fastify/Connect middleware + standalone enforce() wrapper
 */

// Lazy-load to avoid circular dependency with index.js
let _moat = null;
function getMoat() {
  if (!_moat) {
    const ClawMoat = require('./index');
    _moat = new ClawMoat();
  }
  return _moat;
}

class ClawMoatBlocked extends Error {
  constructor(findings) {
    const top = findings[0];
    super(`ClawMoat blocked: ${top.label} (${top.severity})`);
    this.name = 'ClawMoatBlocked';
    this.findings = findings;
    this.severity = top.severity;
  }
}

/**
 * Enforce inbound content — throws ClawMoatBlocked on critical/high findings
 * @param {string} text - Text to scan
 * @param {object} options
 * @param {string[]} options.blockOn - Severities to block on (default: ['critical', 'high'])
 * @param {object} options.scanOptions - Options passed to scanInbound
 * @returns {object} scan result if clean
 * @throws {ClawMoatBlocked} if blocked
 */
function enforceInbound(text, options = {}) {
  const { blockOn = ['critical', 'high'], scanOptions = {} } = options;
  const result = getMoat().scanInbound(text, scanOptions);
  const blocked = result.findings.filter(f => blockOn.includes(f.severity));
  if (blocked.length > 0) {
    throw new ClawMoatBlocked(blocked);
  }
  return result;
}

/**
 * Enforce outbound content — throws ClawMoatBlocked on critical/high findings
 * @param {string} text - Text to scan
 * @param {object} options
 * @returns {object} scan result if clean
 * @throws {ClawMoatBlocked} if blocked
 */
function enforceOutbound(text, options = {}) {
  const { blockOn = ['critical', 'high'], scanOptions = {} } = options;
  const result = getMoat().scanOutbound(text, scanOptions);
  const blocked = result.findings.filter(f => blockOn.includes(f.severity));
  if (blocked.length > 0) {
    throw new ClawMoatBlocked(blocked);
  }
  return result;
}

/**
 * Express/Connect/Fastify middleware — blocks requests with dangerous content
 * @param {object} options
 * @param {string[]} options.blockOn - Severities to block on
 * @param {boolean} options.scanBody - Scan request body (default: true)
 * @param {boolean} options.scanQuery - Scan query params (default: true)
 * @param {Function} options.onBlocked - Custom handler (req, res, findings) => void
 * @returns {Function} middleware
 */
function middleware(options = {}) {
  const {
    blockOn = ['critical', 'high'],
    scanBody = true,
    scanQuery = true,
    onBlocked = null,
  } = options;

  return function clawmoatFirewall(req, res, next) {
    const texts = [];

    // Collect text to scan
    if (scanBody && req.body) {
      if (typeof req.body === 'string') {
        texts.push(req.body);
      } else {
        texts.push(JSON.stringify(req.body));
      }
    }
    if (scanQuery && req.query) {
      texts.push(Object.values(req.query).join(' '));
    }
    if (req.params) {
      texts.push(Object.values(req.params).join(' '));
    }

    const combined = texts.join('\n');
    if (!combined.trim()) return next();

    const result = getMoat().scanInbound(combined);
    const blocked = result.findings.filter(f => blockOn.includes(f.severity));

    if (blocked.length > 0) {
      if (onBlocked) {
        return onBlocked(req, res, blocked);
      }
      res.status(403);
      if (typeof res.json === 'function') {
        return res.json({
          error: 'Blocked by ClawMoat Agent Firewall',
          severity: blocked[0].severity,
          findings: blocked.map(f => ({
            label: f.label,
            severity: f.severity,
            category: f.category,
          })),
        });
      }
      res.end(JSON.stringify({ error: 'Blocked by ClawMoat Agent Firewall' }));
      return;
    }

    // Attach scan result for downstream use
    req.clawmoat = result;
    next();
  };
}

/**
 * Wrap an async function with ClawMoat enforcement
 * @param {Function} fn - async function(input) => output
 * @param {object} options
 * @returns {Function} wrapped function that scans input and output
 */
function wrap(fn, options = {}) {
  const { blockOn = ['critical', 'high'] } = options;

  return async function clawmoatWrapped(input, ...args) {
    // Scan input
    if (typeof input === 'string') {
      enforceInbound(input, { blockOn });
    } else if (input && typeof input === 'object') {
      enforceInbound(JSON.stringify(input), { blockOn });
    }

    // Execute
    const output = await fn(input, ...args);

    // Scan output
    if (typeof output === 'string') {
      enforceOutbound(output, { blockOn });
    } else if (output && typeof output === 'object') {
      enforceOutbound(JSON.stringify(output), { blockOn });
    }

    return output;
  };
}

module.exports = {
  enforceInbound,
  enforceOutbound,
  middleware,
  wrap,
  ClawMoatBlocked,
};
