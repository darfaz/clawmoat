/**
 * ClawMoat Framework Adapters
 * 
 * Drop-in integrations for popular AI/web frameworks.
 * 
 * Usage:
 *   // LangChain
 *   const { ClawMoatCallbackHandler } = require('clawmoat/adapters/langchain');
 * 
 *   // Express
 *   const { clawmoatMiddleware } = require('clawmoat/adapters/express');
 * 
 *   // Generic (any framework)
 *   const { createGuard } = require('clawmoat/adapters');
 */

'use strict';

const { ClawMoatCallbackHandler, wrapChain } = require('./langchain');
const { clawmoatMiddleware, clawmoatPlugin } = require('./express');

/**
 * Generic guard factory — works with any framework
 * @param {Object} [opts] - Options
 * @returns {Object} Guard with scanInput/scanOutput/scanTool methods
 */
function createGuard(opts = {}) {
  const { mode = 'enforce' } = opts;
  
  // Lazy load all scanners
  let moat, obf, code;
  const getMoat = () => { if (!moat) { const C = require('../index'); moat = new C(); } return moat; };
  const getObf = () => { if (!obf) obf = require('../obfuscation-scanner'); return obf; };
  const getCode = () => { if (!code) code = require('../code-scanner'); return code; };

  function _check(findings) {
    if (findings.length === 0) return { safe: true, findings: [] };
    if (mode === 'monitor') return { safe: true, findings, warning: true };
    const hasCritical = findings.some(f => f.severity === 'critical' || f.severity === 'high');
    return { safe: !hasCritical, findings };
  }

  return {
    /**
     * Scan user/external input before processing
     */
    scanInput(text) {
      const inbound = getMoat().scanInbound(text);
      const obfResult = getObf().scanObfuscation(text);
      return _check([...(inbound.findings || []), ...(obfResult.findings || [])]);
    },

    /**
     * Scan agent output before sending
     */
    scanOutput(text) {
      const outbound = getMoat().scanOutbound(text);
      return _check(outbound.findings || []);
    },

    /**
     * Scan tool call before execution
     */
    scanTool(toolName, args) {
      const text = typeof args === 'string' ? args : JSON.stringify(args);
      const result = getCode().scanCode(text, { tool: toolName });
      return _check(result.findings || []);
    },

    /**
     * Scan tool result before returning to model
     */
    scanToolResult(text) {
      const inbound = getMoat().scanInbound(text);
      return _check(inbound.findings || []);
    },

    /** Get mode */
    get mode() { return mode; },
  };
}

module.exports = {
  // LangChain
  ClawMoatCallbackHandler,
  wrapChain,
  // Express/Fastify
  clawmoatMiddleware,
  clawmoatPlugin,
  // Generic
  createGuard,
};
