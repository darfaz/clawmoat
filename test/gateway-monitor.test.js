const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { GatewayMonitor } = require('../src/guardian/gateway-monitor');

describe('GatewayMonitor', () => {
  describe('constructor', () => {
    it('creates with default options', () => {
      const gm = new GatewayMonitor();
      assert.equal(gm.port, 18789);
      assert.equal(gm.bruteForceThreshold, 10);
    });

    it('accepts custom options', () => {
      const gm = new GatewayMonitor({ port: 9999, bruteForceThreshold: 5 });
      assert.equal(gm.port, 9999);
      assert.equal(gm.bruteForceThreshold, 5);
    });
  });

  describe('recordAuthAttempt', () => {
    it('records a successful attempt', () => {
      const gm = new GatewayMonitor();
      const result = gm.recordAuthAttempt({ source: '127.0.0.1', success: true });
      assert.equal(result.totalAttempts, 1);
      assert.equal(result.failedAttempts, 0);
      assert.equal(result.isBruteForce, false);
    });

    it('records a failed attempt', () => {
      const gm = new GatewayMonitor();
      const result = gm.recordAuthAttempt({ source: '127.0.0.1', success: false });
      assert.equal(result.totalAttempts, 1);
      assert.equal(result.failedAttempts, 1);
      assert.equal(result.isBruteForce, false);
    });

    it('detects brute-force attack', () => {
      const gm = new GatewayMonitor({ bruteForceThreshold: 5 });
      for (let i = 0; i < 5; i++) {
        gm.recordAuthAttempt({ source: '127.0.0.1', success: false });
      }
      const result = gm.recordAuthAttempt({ source: '127.0.0.1', success: false });
      // Threshold is 5, we now have 6 failed
      assert.equal(result.isBruteForce, true);
      assert.equal(result.alerts.length, 1);
      assert.equal(result.alerts[0].type, 'brute_force_detected');
      assert.equal(result.alerts[0].severity, 'critical');
    });

    it('detects suspicious WebSocket origin', () => {
      const gm = new GatewayMonitor();
      const result = gm.recordAuthAttempt({
        source: '127.0.0.1',
        success: false,
        origin: 'https://evil-site.com',
      });
      assert.equal(result.isSuspiciousOrigin, true);
      assert.equal(result.alerts.length, 1);
      assert.equal(result.alerts[0].type, 'suspicious_websocket_origin');
    });

    it('does not flag localhost origin as suspicious', () => {
      const gm = new GatewayMonitor();
      const result = gm.recordAuthAttempt({
        source: '127.0.0.1',
        success: true,
        origin: 'http://localhost:18789',
      });
      assert.equal(result.isSuspiciousOrigin, false);
      assert.equal(result.alerts.length, 0);
    });

    it('detects multiple auth sources', () => {
      const gm = new GatewayMonitor();
      gm.recordAuthAttempt({ source: '10.0.0.1', success: true });
      gm.recordAuthAttempt({ source: '10.0.0.2', success: true });
      const result = gm.recordAuthAttempt({ source: '10.0.0.3', success: true });
      const multiSourceAlert = result.alerts.find(a => a.type === 'multiple_auth_sources');
      assert.ok(multiSourceAlert);
    });

    it('fires onAlert callback', () => {
      const alerts = [];
      const gm = new GatewayMonitor({
        bruteForceThreshold: 3,
        onAlert: (a) => alerts.push(a),
      });
      for (let i = 0; i < 4; i++) {
        gm.recordAuthAttempt({ source: '127.0.0.1', success: false });
      }
      assert.ok(alerts.length > 0);
      assert.equal(alerts[0].type, 'brute_force_detected');
    });
  });

  describe('recordDevicePairing', () => {
    it('records a new device', () => {
      const gm = new GatewayMonitor();
      const result = gm.recordDevicePairing({ deviceId: 'device-1', source: '127.0.0.1' });
      assert.equal(result.isNew, true);
    });

    it('recognizes known device', () => {
      const gm = new GatewayMonitor();
      gm.recordDevicePairing({ deviceId: 'device-1', source: '127.0.0.1' });
      const result = gm.recordDevicePairing({ deviceId: 'device-1', source: '127.0.0.1' });
      assert.equal(result.isNew, false);
    });

    it('detects auto-approved localhost pairing (Oasis attack)', () => {
      const gm = new GatewayMonitor();
      const result = gm.recordDevicePairing({
        deviceId: 'attacker-device',
        source: 'localhost',
        autoApproved: true,
      });
      assert.equal(result.isAutoApproveRisk, true);
      assert.equal(result.alerts.length, 1);
      assert.equal(result.alerts[0].severity, 'critical');
      assert.ok(result.alerts[0].details.reference.includes('oasis'));
    });

    it('warns on auto-approved non-localhost pairing', () => {
      const gm = new GatewayMonitor();
      const result = gm.recordDevicePairing({
        deviceId: 'remote-device',
        source: '10.0.0.5',
        autoApproved: true,
      });
      assert.equal(result.isAutoApproveRisk, true);
      assert.equal(result.alerts[0].severity, 'warning');
    });

    it('detects pairing flood', () => {
      const gm = new GatewayMonitor({ pairingThreshold: 3 });
      gm.recordDevicePairing({ deviceId: 'd1', source: '127.0.0.1' });
      gm.recordDevicePairing({ deviceId: 'd2', source: '127.0.0.1' });
      const result = gm.recordDevicePairing({ deviceId: 'd3', source: '127.0.0.1' });
      assert.equal(result.isPairingFlood, true);
    });
  });

  describe('auditGatewayConfig', () => {
    it('returns results even without config file', () => {
      const gm = new GatewayMonitor();
      const result = gm.auditGatewayConfig();
      assert.ok(result.issues.length > 0);
      assert.equal(result.configFound, false);
    });

    it('has score property', () => {
      const gm = new GatewayMonitor();
      const result = gm.auditGatewayConfig();
      assert.equal(typeof result.score, 'number');
      assert.ok(result.score >= 0 && result.score <= 100);
    });
  });

  describe('generateStrongToken', () => {
    it('generates 64-char hex token', () => {
      const token = GatewayMonitor.generateStrongToken();
      assert.equal(token.length, 64);
      assert.match(token, /^[0-9a-f]{64}$/);
    });

    it('generates unique tokens', () => {
      const t1 = GatewayMonitor.generateStrongToken();
      const t2 = GatewayMonitor.generateStrongToken();
      assert.notEqual(t1, t2);
    });
  });

  describe('getHardenedConfig', () => {
    it('returns config with auto-approve disabled', () => {
      const config = GatewayMonitor.getHardenedConfig();
      assert.equal(config.gateway.autoApprove, false);
    });

    it('returns config with localhost rate limiting enabled', () => {
      const config = GatewayMonitor.getHardenedConfig();
      assert.equal(config.gateway.rateLimit.excludeLocalhost, false);
    });

    it('uses non-default port', () => {
      const config = GatewayMonitor.getHardenedConfig();
      assert.notEqual(config.gateway.port, 18789);
    });

    it('generates strong token', () => {
      const config = GatewayMonitor.getHardenedConfig();
      assert.ok(config.gateway.token.length >= 32);
    });
  });

  describe('getSummary', () => {
    it('returns complete summary', () => {
      const gm = new GatewayMonitor();
      gm.recordAuthAttempt({ source: '127.0.0.1', success: false });
      gm.recordDevicePairing({ deviceId: 'd1', source: '127.0.0.1' });
      const summary = gm.getSummary();
      assert.equal(summary.authAttempts, 1);
      assert.equal(summary.failedAuth, 1);
      assert.equal(summary.devicePairings, 1);
      assert.equal(summary.knownDevices, 1);
    });
  });

  describe('reset', () => {
    it('clears all state', () => {
      const gm = new GatewayMonitor();
      gm.recordAuthAttempt({ source: '127.0.0.1', success: false });
      gm.recordDevicePairing({ deviceId: 'd1', source: '127.0.0.1' });
      gm.reset();
      const summary = gm.getSummary();
      assert.equal(summary.authAttempts, 0);
      assert.equal(summary.devicePairings, 0);
      assert.equal(summary.knownDevices, 0);
      assert.equal(summary.alerts, 0);
    });
  });

  describe('getAlerts', () => {
    it('filters by minimum severity', () => {
      const gm = new GatewayMonitor({ bruteForceThreshold: 2 });
      // Generate a critical alert
      gm.recordAuthAttempt({ source: '127.0.0.1', success: false });
      gm.recordAuthAttempt({ source: '127.0.0.1', success: false });
      gm.recordAuthAttempt({ source: '127.0.0.1', success: false });
      
      const critical = gm.getAlerts('critical');
      const all = gm.getAlerts();
      assert.ok(critical.length > 0);
      assert.ok(critical.every(a => a.severity === 'critical'));
    });
  });
});
