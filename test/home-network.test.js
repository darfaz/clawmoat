/**
 * Tests for ClawMoat Home Network Guard.
 */

const { describe, it } = require('node:test');
const { strictEqual, ok, deepStrictEqual } = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const {
  auditHomeNetwork,
  createHomeWatchReport,
  formatHomeNetworkText,
  formatHomeWatchText,
  parseIpNeighborOutput,
} = require('../src/home-network');

describe('home network guard', () => {
  it('parses Linux neighbor table entries into device inventory records', () => {
    const devices = parseIpNeighborOutput(`
192.168.1.1 dev wlan0 lladdr aa:bb:cc:00:00:01 REACHABLE
192.168.1.42 dev wlan0 lladdr 12:34:56:78:90:ab STALE
fe80::1 dev wlan0 lladdr aa:bb:cc:00:00:02 router STALE
`);

    strictEqual(devices.length, 2);
    strictEqual(devices[0].ip, '192.168.1.1');
    strictEqual(devices[0].mac, 'aa:bb:cc:00:00:01');
    strictEqual(devices[0].interface, 'wlan0');
    strictEqual(devices[1].ip, '192.168.1.42');
  });

  it('flags IoT devices that look like exposed proxy or backdoor risks', () => {
    const report = auditHomeNetwork({
      devices: [
        {
          ip: '192.168.1.42',
          mac: '12:34:56:78:90:ab',
          hostname: 'android-tv-box',
          vendor: 'Unknown',
          openPorts: [5555, 23, 8080],
          dnsQueries: ['peer.proxy.example', 'pool.residential-proxy.test'],
          outboundConnections: [
            { host: '203.0.113.10', asnType: 'datacenter' },
            { host: '198.51.100.20', asnType: 'datacenter' },
            { host: '192.0.2.30', asnType: 'datacenter' },
            { host: '198.51.100.40', asnType: 'residential-proxy' },
          ],
        },
        {
          ip: '192.168.1.10',
          mac: 'aa:bb:cc:00:00:10',
          hostname: 'dar-macbook',
          vendor: 'Apple',
          openPorts: [],
          dnsQueries: [],
          outboundConnections: [],
        },
      ],
    });

    strictEqual(report.type, 'home_network_audit');
    strictEqual(report.summary.devices, 2);
    strictEqual(report.summary.highRiskDevices, 1);
    strictEqual(report.ok, false);

    const risky = report.devices.find((device) => device.ip === '192.168.1.42');
    ok(risky.riskScore >= 80, `expected high-risk device score, got ${risky.riskScore}`);
    ok(risky.findings.some((finding) => finding.id === 'android_debug_bridge_exposed'));
    ok(risky.findings.some((finding) => finding.id === 'telnet_exposed'));
    ok(risky.findings.some((finding) => finding.id === 'residential_proxy_indicator'));
    ok(risky.recommendations.some((item) => item.includes('isolate')));
  });

  it('formats a human-readable home network report with plain-English remediation', () => {
    const report = auditHomeNetwork({
      devices: [{ ip: '192.168.1.51', hostname: 'ip-camera', vendor: 'Unknown', openPorts: [23] }],
    });

    const text = formatHomeNetworkText(report);

    ok(text.includes('ClawMoat Home Network Report'));
    ok(text.includes('1 device'));
    ok(text.includes('ip-camera'));
    ok(text.includes('Move this device to a guest or IoT network'));
  });

  it('prints sample home scan JSON from the CLI for demos and lead magnets', async () => {
    const cli = path.join(process.cwd(), 'bin/clawmoat.js');
    const { stdout } = await execFileAsync('node', [cli, 'home', 'scan', '--sample', '--format', 'json']);
    const report = JSON.parse(stdout);

    strictEqual(report.type, 'home_network_audit');
    ok(report.summary.devices >= 2);
    ok(report.devices.some((device) => device.findings.some((finding) => finding.id === 'residential_proxy_indicator')));
  });

  it('creates a watch report that detects new and missing devices against a saved baseline', () => {
    const baseline = {
      generatedAt: '2026-06-01T00:00:00.000Z',
      devices: [
        { ip: '192.168.1.10', mac: 'aa:bb:cc:00:00:10', hostname: 'dar-macbook', vendor: 'Apple', riskScore: 0, status: 'ok' },
        { ip: '192.168.1.51', mac: 'de:ad:be:ef:00:51', hostname: 'driveway-camera', vendor: 'Unknown', riskScore: 45, status: 'review' },
      ],
    };
    const current = auditHomeNetwork({
      devices: [
        { ip: '192.168.1.10', mac: 'aa:bb:cc:00:00:10', hostname: 'dar-macbook', vendor: 'Apple', openPorts: [] },
        { ip: '192.168.1.42', mac: '12:34:56:78:90:ab', hostname: 'android-tv-box', vendor: 'Unknown', openPorts: [5555, 23] },
      ],
    });

    const watch = createHomeWatchReport({ baseline, current });

    strictEqual(watch.type, 'home_network_watch');
    strictEqual(watch.ok, false);
    deepStrictEqual(watch.changes.newDevices.map((device) => device.ip), ['192.168.1.42']);
    deepStrictEqual(watch.changes.missingDevices.map((device) => device.ip), ['192.168.1.51']);
    strictEqual(watch.alerts.some((alert) => alert.type === 'new_high_risk_device'), true);
    strictEqual(watch.summary.newDevices, 1);
    strictEqual(watch.summary.missingDevices, 1);
  });

  it('writes a baseline and reports no changes on the first home watch run', async () => {
    const cli = path.join(process.cwd(), 'bin/clawmoat.js');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clawmoat-home-watch-'));
    const statePath = path.join(dir, 'baseline.json');

    const { stdout } = await execFileAsync('node', [cli, 'home', 'watch', '--sample', '--once', '--state', statePath, '--format', 'json']);
    const report = JSON.parse(stdout);

    strictEqual(report.type, 'home_network_watch');
    strictEqual(report.firstRun, true);
    strictEqual(report.ok, true);
    ok(fs.existsSync(statePath));
    strictEqual(JSON.parse(fs.readFileSync(statePath, 'utf8')).devices.length >= 2, true);
  });

  it('formats a home watch report for weekly reports and new-device alerts', () => {
    const watch = createHomeWatchReport({
      baseline: { devices: [] },
      current: auditHomeNetwork({ devices: [{ ip: '192.168.1.42', hostname: 'android-tv-box', vendor: 'Unknown', openPorts: [5555] }] }),
    });

    const text = formatHomeWatchText(watch);

    ok(text.includes('ClawMoat Home Watch'));
    ok(text.includes('New devices: 1'));
    ok(text.includes('android-tv-box'));
    ok(text.includes('Weekly summary'));
  });
});
