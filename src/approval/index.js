/**
 * Interactive Approval Workflow with Pluggable Notification Channels
 * Security primitive for agent governance — agents must ask before dangerous actions
 * 
 * @module approval
 * @example
 * const { ApprovalWorkflow, ConsoleChannel } = require('./approval');
 * 
 * const workflow = new ApprovalWorkflow({
 *   defaultTimeout: 30000,
 *   channels: [new ConsoleChannel()]
 * });
 * 
 * const approved = await workflow.requestApproval({
 *   action: 'delete_file',
 *   agent: 'maintenance-bot',
 *   reason: 'Cleaning up temporary files in /tmp/agent-cache',
 *   timeout: 60000
 * });
 */

const { randomUUID } = require('crypto');
const { createReadStream, createWriteStream, existsSync } = require('fs');
const { appendFile } = require('fs/promises');
const { createInterface } = require('readline');
const http = require('http');

/**
 * @typedef {Object} ApprovalRequest
 * @property {string} action - Description of the action requiring approval
 * @property {string} agent - Name/ID of the agent requesting approval
 * @property {string} reason - Human-readable explanation of why this action is needed
 * @property {number} [timeout=30000] - Timeout in ms before auto-approval/denial
 */

/**
 * @typedef {Object} ApprovalResponse
 * @property {string} requestId - Unique request identifier
 * @property {boolean} approved - Whether the action was approved
 * @property {string} source - How the decision was made ('user', 'timeout', 'policy')
 * @property {string} [reason] - Optional explanation for the decision
 * @property {number} timestamp - Unix timestamp when decision was made
 */

/**
 * Base interface for notification channels
 */
class NotificationChannel {
  /**
   * Notify about a pending approval request
   * @param {ApprovalRequest & { requestId: string, expiresAt: number }} request
   * @returns {Promise<void>}
   */
  async notify(request) {
    throw new Error('notify() must be implemented');
  }

  /**
   * Check if a response has been provided for this request
   * @param {string} requestId
   * @returns {Promise<{ approved: boolean, reason?: string } | null>}
   */
  async checkResponse(requestId) {
    throw new Error('checkResponse() must be implemented');
  }

  /**
   * Cleanup any resources for this request
   * @param {string} requestId
   * @returns {Promise<void>}
   */
  async cleanup(requestId) {
    // Default: no-op
  }
}

/**
 * Console channel - prompts via stdin/stdout
 */
class ConsoleChannel extends NotificationChannel {
  constructor() {
    super();
    this.pendingRequests = new Map();
  }

  async notify(request) {
    console.log('\n🚨 APPROVAL REQUIRED 🚨');
    console.log(`Agent: ${request.agent}`);
    console.log(`Action: ${request.action}`);
    console.log(`Reason: ${request.reason}`);
    console.log(`Expires: ${new Date(request.expiresAt).toISOString()}`);
    console.log(`Respond with: approve ${request.requestId} OR deny ${request.requestId} [reason]`);
    console.log('');

    // Store for response checking
    this.pendingRequests.set(request.requestId, {
      active: true,
      response: null
    });

    // Start listening for stdin if not already
    if (!this._stdinListener) {
      this._startStdinListener();
    }
  }

  async checkResponse(requestId) {
    const pending = this.pendingRequests.get(requestId);
    if (!pending || !pending.response) return null;
    
    return pending.response;
  }

  async cleanup(requestId) {
    this.pendingRequests.delete(requestId);
  }

  _startStdinListener() {
    this._stdinListener = createInterface({
      input: process.stdin,
      output: process.stdout
    });

    this._stdinListener.on('line', (line) => {
      const match = line.trim().match(/^(approve|deny)\s+([a-f0-9-]+)(?:\s+(.+))?$/i);
      if (!match) return;

      const [, action, requestId, reason] = match;
      const pending = this.pendingRequests.get(requestId);
      
      if (pending && pending.active) {
        pending.response = {
          approved: action.toLowerCase() === 'approve',
          reason: reason || undefined
        };
        pending.active = false;
        
        console.log(`✅ Response recorded: ${action.toUpperCase()} ${requestId}`);
      }
    });
  }
}

/**
 * Webhook channel - sends HTTP POST and polls for response
 */
class WebhookChannel extends NotificationChannel {
  constructor(options = {}) {
    super();
    this.webhookUrl = options.webhookUrl;
    this.responseUrl = options.responseUrl; // URL to poll for responses
    this.secret = options.secret; // Optional webhook signature secret
    
    if (!this.webhookUrl) {
      throw new Error('WebhookChannel requires webhookUrl option');
    }
  }

  async notify(request) {
    const payload = JSON.stringify({
      type: 'approval_request',
      requestId: request.requestId,
      action: request.action,
      agent: request.agent,
      reason: request.reason,
      expiresAt: request.expiresAt,
      timestamp: Date.now()
    });

    const url = new URL(this.webhookUrl);
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'User-Agent': 'ClawMoat-Approval/1.0'
      }
    };

    // Add signature if secret provided
    if (this.secret) {
      const crypto = require('crypto');
      const signature = crypto.createHmac('sha256', this.secret).update(payload).digest('hex');
      options.headers['X-ClawMoat-Signature'] = `sha256=${signature}`;
    }

    return new Promise((resolve, reject) => {
      const req = http.request(options, (res) => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve();
        } else {
          reject(new Error(`Webhook failed: HTTP ${res.statusCode}`));
        }
      });

      req.on('error', reject);
      req.write(payload);
      req.end();
    });
  }

  async checkResponse(requestId) {
    if (!this.responseUrl) return null;

    const url = new URL(this.responseUrl);
    url.searchParams.set('requestId', requestId);

    return new Promise((resolve) => {
      const options = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: 'GET',
        headers: { 'User-Agent': 'ClawMoat-Approval/1.0' }
      };

      const req = http.request(options, (res) => {
        if (res.statusCode !== 200) {
          resolve(null);
          return;
        }

        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const response = JSON.parse(data);
            if (response.requestId === requestId && response.decision) {
              resolve({
                approved: response.decision === 'approve',
                reason: response.reason
              });
            } else {
              resolve(null);
            }
          } catch {
            resolve(null);
          }
        });
      });

      req.on('error', () => resolve(null));
      req.setTimeout(5000, () => {
        req.destroy();
        resolve(null);
      });
      req.end();
    });
  }
}

/**
 * Callback channel - uses provided functions for notification and response checking
 */
class CallbackChannel extends NotificationChannel {
  constructor(options = {}) {
    super();
    this.notifyFn = options.notifyFn;
    this.checkResponseFn = options.checkResponseFn;
    
    if (typeof this.notifyFn !== 'function') {
      throw new Error('CallbackChannel requires notifyFn function');
    }
    if (typeof this.checkResponseFn !== 'function') {
      throw new Error('CallbackChannel requires checkResponseFn function');
    }
  }

  async notify(request) {
    return this.notifyFn(request);
  }

  async checkResponse(requestId) {
    return this.checkResponseFn(requestId);
  }
}

/**
 * Main approval workflow coordinator
 */
class ApprovalWorkflow {
  constructor(options = {}) {
    this.defaultTimeout = options.defaultTimeout || 30000;
    this.defaultAction = options.defaultAction || 'deny'; // 'approve' | 'deny'
    this.channels = options.channels || [];
    this.auditLog = options.auditLog || null; // Path to audit log file
    
    if (this.channels.length === 0) {
      // Default to console channel if none provided
      this.channels = [new ConsoleChannel()];
    }
  }

  /**
   * Request approval for an action
   * @param {ApprovalRequest} request
   * @returns {Promise<ApprovalResponse>}
   */
  async requestApproval(request) {
    const requestId = randomUUID();
    const timeout = request.timeout || this.defaultTimeout;
    const expiresAt = Date.now() + timeout;
    
    const fullRequest = {
      ...request,
      requestId,
      expiresAt
    };

    // Log the request
    await this._auditLog({
      type: 'approval_request',
      requestId,
      action: request.action,
      agent: request.agent,
      reason: request.reason,
      timeout,
      timestamp: Date.now()
    });

    // Notify all channels
    const notificationPromises = this.channels.map(channel => 
      channel.notify(fullRequest).catch(err => {
        console.error(`Channel notification failed: ${err.message}`);
      })
    );
    
    await Promise.allSettled(notificationPromises);

    // Poll for responses with timeout
    return new Promise((resolve) => {
      const pollInterval = Math.min(1000, timeout / 10); // Poll every 1s or 1/10th of timeout
      let timeoutHandle;
      let pollHandle;

      const checkResponses = async () => {
        for (const channel of this.channels) {
          try {
            const response = await channel.checkResponse(requestId);
            if (response) {
              clearTimeout(timeoutHandle);
              clearInterval(pollHandle);
              
              // Cleanup all channels
              await Promise.allSettled(
                this.channels.map(ch => ch.cleanup(requestId))
              );

              const result = {
                requestId,
                approved: response.approved,
                source: 'user',
                reason: response.reason,
                timestamp: Date.now()
              };

              await this._auditLog({
                type: 'approval_response',
                ...result
              });

              resolve(result);
              return;
            }
          } catch (err) {
            // Ignore channel errors during polling
          }
        }
      };

      // Start polling
      pollHandle = setInterval(checkResponses, pollInterval);

      // Set timeout
      timeoutHandle = setTimeout(async () => {
        clearInterval(pollHandle);
        
        // Cleanup all channels
        await Promise.allSettled(
          this.channels.map(ch => ch.cleanup(requestId))
        );

        const result = {
          requestId,
          approved: this.defaultAction === 'approve',
          source: 'timeout',
          reason: `No response within ${timeout}ms, defaulting to ${this.defaultAction}`,
          timestamp: Date.now()
        };

        await this._auditLog({
          type: 'approval_timeout',
          ...result
        });

        resolve(result);
      }, timeout);
    });
  }

  /**
   * Get audit log entries
   * @param {Object} [filter] - Optional filter criteria
   * @returns {Promise<Object[]>}
   */
  async getAuditLog(filter = {}) {
    if (!this.auditLog || !existsSync(this.auditLog)) {
      return [];
    }

    const entries = [];
    const fileStream = createReadStream(this.auditLog);
    const rl = createInterface({ input: fileStream });

    for await (const line of rl) {
      try {
        const entry = JSON.parse(line);
        
        // Apply filters
        if (filter.requestId && entry.requestId !== filter.requestId) continue;
        if (filter.agent && entry.agent !== filter.agent) continue;
        if (filter.type && entry.type !== filter.type) continue;
        if (filter.since && entry.timestamp < filter.since) continue;
        if (filter.until && entry.timestamp > filter.until) continue;
        
        entries.push(entry);
      } catch {
        // Skip malformed lines
      }
    }

    return entries;
  }

  async _auditLog(entry) {
    if (!this.auditLog) return;
    
    const logLine = JSON.stringify(entry) + '\n';
    try {
      await appendFile(this.auditLog, logLine);
    } catch (err) {
      console.error(`Audit log write failed: ${err.message}`);
    }
  }
}

module.exports = {
  ApprovalWorkflow,
  NotificationChannel,
  ConsoleChannel,
  WebhookChannel,
  CallbackChannel
};