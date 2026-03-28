/**
 * Express/Fastify Middleware Adapter
 * 
 * One-line security for any Express/Fastify API that serves an AI agent.
 * 
 * Usage (Express):
 *   const { clawmoatMiddleware } = require('clawmoat/adapters/express');
 *   app.use(clawmoatMiddleware({ mode: 'enforce' }));
 * 
 * Usage (Fastify):
 *   const { clawmoatPlugin } = require('clawmoat/adapters/express');
 *   fastify.register(clawmoatPlugin, { mode: 'enforce' });
 * 
 * @module adapters/express
 */

'use strict';

/**
 * Express middleware factory
 * @param {Object} [opts] - Options
 * @param {string} [opts.mode='enforce'] - enforce | monitor
 * @param {string[]} [opts.scanPaths=['/api/*','/chat/*','/agent/*']] - Paths to scan
 * @param {string[]} [opts.skipPaths=['/health','/status']] - Paths to skip
 * @param {Function} [opts.onBlock] - (req, findings) => void
 * @param {Function} [opts.onFinding] - (req, finding) => void
 * @returns {Function} Express middleware
 */
function clawmoatMiddleware(opts = {}) {
  const {
    mode = 'enforce',
    scanPaths = null,
    skipPaths = ['/health', '/status', '/ping', '/favicon.ico'],
    onBlock = null,
    onFinding = null,
  } = opts;

  // Lazy load
  let moat = null;
  let obfuscation = null;

  function getMoat() {
    if (!moat) {
      const ClawMoat = require('../index');
      moat = new ClawMoat();
    }
    return moat;
  }

  function getObfuscation() {
    if (!obfuscation) obfuscation = require('../obfuscation-scanner');
    return obfuscation;
  }

  return function clawmoat(req, res, next) {
    // Skip non-matching paths
    if (skipPaths.some(p => req.path === p || req.path.startsWith(p))) {
      return next();
    }

    if (scanPaths && !scanPaths.some(p => {
      if (p.endsWith('*')) return req.path.startsWith(p.slice(0, -1));
      return req.path === p;
    })) {
      return next();
    }

    // Only scan requests with bodies
    if (!req.body || (typeof req.body === 'object' && Object.keys(req.body).length === 0)) {
      return next();
    }

    const text = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    const m = getMoat();
    const o = getObfuscation();

    // Scan inbound
    const inbound = m.scanInbound(text);
    const obfResult = o.scanObfuscation(text);

    const findings = [...(inbound.findings || []), ...(obfResult.findings || [])];

    if (findings.length > 0) {
      // Attach findings to request for downstream use
      req.clawmoat = { findings, blocked: false };

      for (const f of findings) {
        if (onFinding) onFinding(req, f);
      }

      if (mode === 'enforce' && (!inbound.safe || !obfResult.safe)) {
        req.clawmoat.blocked = true;
        if (onBlock) onBlock(req, findings);

        return res.status(422).json({
          error: 'Request blocked by ClawMoat',
          code: 'CLAWMOAT_BLOCKED',
          findings: findings.map(f => ({
            type: f.type,
            subtype: f.subtype,
            severity: f.severity,
            evidence: f.evidence,
          })),
        });
      }
    }

    // Wrap res.json to scan outbound
    const originalJson = res.json.bind(res);
    res.json = function(data) {
      const outText = typeof data === 'string' ? data : JSON.stringify(data);
      const outbound = m.scanOutbound(outText);

      if (outbound.findings && outbound.findings.length > 0) {
        if (!req.clawmoat) req.clawmoat = { findings: [], blocked: false };
        req.clawmoat.findings.push(...outbound.findings);

        if (mode === 'enforce' && !outbound.safe) {
          return originalJson({
            error: 'Response blocked by ClawMoat — potential data leak',
            code: 'CLAWMOAT_OUTPUT_BLOCKED',
          });
        }
      }

      return originalJson(data);
    };

    next();
  };
}

/**
 * Fastify plugin
 */
async function clawmoatPlugin(fastify, opts = {}) {
  const middleware = clawmoatMiddleware(opts);
  
  fastify.addHook('preHandler', (request, reply, done) => {
    // Adapt Fastify request/reply to Express-like interface
    const req = {
      path: request.url,
      body: request.body,
      clawmoat: null,
    };
    const res = {
      status: (code) => ({ json: (data) => reply.code(code).send(data) }),
      json: (data) => reply.send(data),
    };

    middleware(req, res, () => {
      if (req.clawmoat) request.clawmoat = req.clawmoat;
      done();
    });
  });
}

module.exports = {
  clawmoatMiddleware,
  clawmoatPlugin,
};
