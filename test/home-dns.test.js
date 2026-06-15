/**
 * Tests for ClawMoat Home DNS Shield.
 */

const { describe, it } = require('node:test');
const { strictEqual, ok } = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const {
  buildHomeDnsBlocklist,
  createHomeDnsShieldPlan,
  formatHomeDnsBlocklist,
  formatHomeDnsShieldPlanText,
} = require('../src/home-dns');
const { sampleHomeNetworkReport } = require('../src/home-network');

describe('home dns shield', () => {
  it('builds a deduplicated DNS blocklist from proxy-like device telemetry', () => {
    const report = sampleHomeNetworkReport();

    const blocklist = buildHomeDnsBlocklist(report);

    ok(blocklist.domains.includes('pool.residential-proxy.example'));
    strictEqual(blocklist.domains.filter((domain) => domain === 'pool.residential-proxy.example').length, 1);
    ok(blocklist.rules.some((rule) => rule.reason.includes('residential proxy')));
    strictEqual(blocklist.source, 'home_network_audit');
  });

  it('formats Pi-hole and AdGuard compatible blocklist output', () => {
    const blocklist = buildHomeDnsBlocklist(sampleHomeNetworkReport());

    const pihole = formatHomeDnsBlocklist(blocklist, { format: 'pihole' });
    const adguard = formatHomeDnsBlocklist(blocklist, { format: 'adguard' });
    const hosts = formatHomeDnsBlocklist(blocklist, { format: 'hosts' });

    ok(pihole.includes('pool.residential-proxy.example'));
    ok(pihole.includes('# ClawMoat Home DNS Shield'));
    ok(adguard.includes('||pool.residential-proxy.example^'));
    ok(hosts.includes('0.0.0.0 pool.residential-proxy.example'));
  });

  it('creates a DNS shield plan with setup instructions for Pi-hole and AdGuard Home', () => {
    const plan = createHomeDnsShieldPlan(sampleHomeNetworkReport(), { publicUrl: 'https://example.com/clawmoat-home-blocklist.txt' });

    strictEqual(plan.type, 'home_dns_shield_plan');
    strictEqual(plan.ok, false);
    ok(plan.blocklist.domains.length >= 1);
    ok(plan.integrations.some((integration) => integration.provider === 'pihole'));
    ok(plan.integrations.some((integration) => integration.provider === 'adguard_home'));
    ok(plan.recommendations.some((item) => item.includes('Add the generated blocklist')));
  });

  it('prints a sample DNS shield plan from the CLI as JSON', async () => {
    const cli = path.join(process.cwd(), 'bin/clawmoat.js');
    const { stdout } = await execFileAsync('node', [cli, 'home', 'dns-plan', '--sample', '--format', 'json']);
    const plan = JSON.parse(stdout);

    strictEqual(plan.type, 'home_dns_shield_plan');
    ok(plan.blocklist.domains.includes('pool.residential-proxy.example'));
  });

  it('writes a Pi-hole blocklist file from the CLI', async () => {
    const cli = path.join(process.cwd(), 'bin/clawmoat.js');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clawmoat-dns-'));
    const output = path.join(dir, 'blocklist.txt');

    const { stdout } = await execFileAsync('node', [cli, 'home', 'dns-blocklist', '--sample', '--format', 'pihole', '--output', output]);

    ok(stdout.includes(output));
    ok(fs.readFileSync(output, 'utf8').includes('pool.residential-proxy.example'));
  });

  it('formats a human-readable DNS shield plan', () => {
    const text = formatHomeDnsShieldPlanText(createHomeDnsShieldPlan(sampleHomeNetworkReport()));

    ok(text.includes('ClawMoat Home DNS Shield'));
    ok(text.includes('Pi-hole'));
    ok(text.includes('AdGuard Home'));
    ok(text.includes('pool.residential-proxy.example'));
  });
});
