/**
 * LangChain Adapter for ClawMoat
 * 
 * Drop-in middleware for LangChain applications.
 * Wraps chains, agents, and tools with ClawMoat security scanning.
 * 
 * Usage:
 *   const { ClawMoatCallbackHandler } = require('clawmoat/adapters/langchain');
 *   const handler = new ClawMoatCallbackHandler({ mode: 'enforce' });
 *   const chain = new LLMChain({ llm, prompt, callbacks: [handler] });
 * 
 * @module adapters/langchain
 */

'use strict';

/**
 * LangChain callback handler that scans inputs/outputs
 */
class ClawMoatCallbackHandler {
  constructor(opts = {}) {
    this.name = 'ClawMoatCallbackHandler';
    this.mode = opts.mode || 'enforce';
    this.onBlock = opts.onBlock || null;
    this.onFinding = opts.onFinding || null;
    this.findings = [];

    // Lazy load to avoid circular deps
    this._moat = null;
    this._obfuscation = null;
    this._codeScanner = null;
  }

  _getMoat() {
    if (!this._moat) {
      const ClawMoat = require('../index');
      this._moat = new ClawMoat();
    }
    return this._moat;
  }

  _getObfuscation() {
    if (!this._obfuscation) this._obfuscation = require('../obfuscation-scanner');
    return this._obfuscation;
  }

  _getCodeScanner() {
    if (!this._codeScanner) this._codeScanner = require('../code-scanner');
    return this._codeScanner;
  }

  /**
   * Called when chain starts — scan input
   */
  async handleChainStart(chain, inputs) {
    const text = typeof inputs === 'string' ? inputs : JSON.stringify(inputs);
    
    // Scan for prompt injection + obfuscation
    const moat = this._getMoat();
    const inbound = moat.scanInbound(text);
    const obfResult = this._getObfuscation().scanObfuscation(text);
    
    const allFindings = [...(inbound.findings || []), ...(obfResult.findings || [])];
    this.findings.push(...allFindings);

    for (const f of allFindings) {
      if (this.onFinding) this.onFinding(f, 'chain_input');
    }

    if (!inbound.safe || !obfResult.safe) {
      if (this.mode === 'enforce') {
        const err = new Error(`[ClawMoat] Blocked: ${allFindings[0]?.evidence || 'threat detected'}`);
        err.code = 'CLAWMOAT_BLOCKED';
        err.findings = allFindings;
        if (this.onBlock) this.onBlock(allFindings, 'chain_input');
        throw err;
      }
    }
  }

  /**
   * Called when chain ends — scan output for leaks
   */
  async handleChainEnd(outputs) {
    const text = typeof outputs === 'string' ? outputs : JSON.stringify(outputs);
    
    const moat = this._getMoat();
    const outbound = moat.scanOutbound(text);
    
    if (outbound.findings) {
      this.findings.push(...outbound.findings);
      for (const f of outbound.findings) {
        if (this.onFinding) this.onFinding(f, 'chain_output');
      }
    }

    if (!outbound.safe && this.mode === 'enforce') {
      const err = new Error(`[ClawMoat] Output blocked: ${outbound.findings[0]?.evidence || 'leak detected'}`);
      err.code = 'CLAWMOAT_BLOCKED';
      err.findings = outbound.findings;
      if (this.onBlock) this.onBlock(outbound.findings, 'chain_output');
      throw err;
    }
  }

  /**
   * Called when tool starts — scan tool call
   */
  async handleToolStart(tool, input) {
    const cs = this._getCodeScanner();
    const text = typeof input === 'string' ? input : JSON.stringify(input);
    const result = cs.scanCode(text, { tool: tool?.name });

    if (result.findings.length > 0) {
      this.findings.push(...result.findings);
      for (const f of result.findings) {
        if (this.onFinding) this.onFinding(f, 'tool_call');
      }
    }

    if (!result.safe && this.mode === 'enforce') {
      const err = new Error(`[ClawMoat] Tool call blocked: ${result.findings[0]?.evidence || 'dangerous code'}`);
      err.code = 'CLAWMOAT_BLOCKED';
      err.findings = result.findings;
      if (this.onBlock) this.onBlock(result.findings, 'tool_call');
      throw err;
    }
  }

  /**
   * Called when tool ends — scan result for injection
   */
  async handleToolEnd(output) {
    const moat = this._getMoat();
    const text = typeof output === 'string' ? output : JSON.stringify(output);
    const result = moat.scanInbound(text);

    if (result.findings) {
      this.findings.push(...result.findings);
    }

    // Don't block tool results in most cases — just log
    // The model needs to see the result to understand what happened
  }

  /**
   * Get all findings collected during execution
   */
  getFindings() {
    return [...this.findings];
  }

  /**
   * Clear collected findings
   */
  clearFindings() {
    this.findings = [];
  }
}

/**
 * Wrap a LangChain chain/agent with ClawMoat protection
 * Convenience function for simple usage
 * @param {Object} chain - LangChain chain or agent
 * @param {Object} [opts] - ClawMoat options
 * @returns {Object} Wrapped chain with security scanning
 */
function wrapChain(chain, opts = {}) {
  const handler = new ClawMoatCallbackHandler(opts);
  
  // Add our handler to the chain's callbacks
  if (!chain.callbacks) chain.callbacks = [];
  chain.callbacks.push(handler);
  
  // Attach findings accessor
  chain._clawmoat = handler;
  chain.getSecurityFindings = () => handler.getFindings();
  
  return chain;
}

module.exports = {
  ClawMoatCallbackHandler,
  wrapChain,
};
