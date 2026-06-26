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
  discoverDevices,
  isWsl,
  parseIpNeighborOutput,
  parseArpOutput,
  parseDnsSdBrowseOutput,
  parseDnsSdLookupOutput,
  discoverBonjourDevices,
  probeOpenPorts,
  parseWindowsArpOutput,
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

  it('parses macOS ARP output with non-padded MAC octets and ignores broadcast/multicast entries', () => {
    const devices = parseArpOutput(`
sbe1v1k.lan (192.168.1.1) at dc:8:da:8b:66:35 on en0 ifscope [ethernet]
hpi099e1b.lan (192.168.1.95) at ac:f4:66:9:9e:1b on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
mdns.mcast.net (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
`);

    deepStrictEqual(devices.map((device) => device.ip), ['192.168.1.1', '192.168.1.95']);
    strictEqual(devices[0].mac, 'dc:08:da:8b:66:35');
    strictEqual(devices[1].mac, 'ac:f4:66:09:9e:1b');
  });

  it('parses Bonjour browse and lookup output into identifiable local devices', () => {
    const browse = parseDnsSdBrowseOutput(`
Browsing for _airplay._tcp.local
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
20:07:24.369  Add        3  14 local.               _airplay._tcp.       Roku Ultra
`);
    deepStrictEqual(browse, [{ service: '_airplay._tcp', instance: 'Roku Ultra', domain: 'local' }]);

    const lookup = parseDnsSdLookupOutput('Roku Ultra', '_airplay._tcp', `
Roku\\032Ultra._airplay._tcp.local. can be reached at YJ0066332471.local.:7000 (interface 14)
acl=0 deviceid=5A:76:78:62:48:1E model=4670X manufacturer=Roku serialNumber=f4021343
`);

    strictEqual(lookup.hostname, 'Roku Ultra');
    strictEqual(lookup.mdnsHost, 'YJ0066332471.local');
    strictEqual(lookup.vendor, 'Roku');
    strictEqual(lookup.type, 'streaming-device');
  });

  it('merges Bonjour identities into ARP-discovered devices by resolved IP', () => {
    const outputs = {
      'arp -a': 'rokuultra.lan (192.168.1.227) at 8c:49:62:2:d2:7c on en0 ifscope [ethernet]',
      'dns-sd -B _airplay._tcp local': `
Browsing for _airplay._tcp.local
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
20:07:24.369  Add        2  14 local.               _airplay._tcp.       Roku Ultra
`,
      'dns-sd -L Roku Ultra _airplay._tcp local': `
Roku\\032Ultra._airplay._tcp.local. can be reached at YJ0066332471.local.:7000 (interface 14)
manufacturer=Roku model=4670X
`,
      'dscacheutil -q host -a name YJ0066332471.local': `
name: yj0066332471.local
ip_address: 192.168.1.227
`,
    };

    const devices = discoverDevices({
      platform: 'darwin',
      runner: (bin, args) => outputs[[bin, ...args].join(' ')] || '',
      bonjourServices: ['_airplay._tcp'],
    });

    strictEqual(devices.length, 1);
    strictEqual(devices[0].ip, '192.168.1.227');
    strictEqual(devices[0].hostname, 'Roku Ultra');
    strictEqual(devices[0].vendor, 'Roku');
    strictEqual(devices[0].type, 'streaming-device');
    strictEqual(devices[0].source, 'arp+bonjour');
  });

  it('keeps stronger Bonjour identity when multiple services resolve to the same IP', () => {
    const outputs = {
      'arp -a': 'rokuultra.lan (192.168.1.227) at 8c:49:62:2:d2:7c on en0 ifscope [ethernet]',
      'dns-sd -B _airplay._tcp local': `
20:07:24.369  Add        2  14 local.               _airplay._tcp.       Roku Ultra
`,
      'dns-sd -L Roku Ultra _airplay._tcp local': `
Roku\\032Ultra._airplay._tcp.local. can be reached at YJ0066332471.local.:7000 (interface 14)
manufacturer=Roku model=4670X
`,
      'dns-sd -B _spotify-connect._tcp local': `
20:07:24.369  Add        2  14 local.               _spotify-connect._tcp.       bb3e9496-f97d-5f0b-9763-0241ed4203fd
`,
      'dns-sd -L bb3e9496-f97d-5f0b-9763-0241ed4203fd _spotify-connect._tcp local': `
bb3e9496-f97d-5f0b-9763-0241ed4203fd._spotify-connect._tcp.local. can be reached at YJ0066332471.local.:8009 (interface 14)
`,
      'dscacheutil -q host -a name YJ0066332471.local': `
name: yj0066332471.local
ip_address: 192.168.1.227
`,
    };

    const devices = discoverDevices({
      platform: 'darwin',
      runner: (bin, args) => outputs[[bin, ...args].join(' ')] || '',
      bonjourServices: ['_airplay._tcp', '_spotify-connect._tcp'],
    });

    strictEqual(devices.length, 1);
    strictEqual(devices[0].hostname, 'Roku Ultra');
    strictEqual(devices[0].vendor, 'Roku');
    strictEqual(devices[0].source, 'arp+bonjour');
  });

  it('discovers Bonjour printer identity with resolved IP', () => {
    const outputs = {
      'dns-sd -B _ipp._tcp local': `
Browsing for _ipp._tcp.local
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
20:07:30.402  Add        2  14 local.               _ipp._tcp.           HP Envy 6500e series [099E1B]
`,
      'dns-sd -L HP Envy 6500e series [099E1B] _ipp._tcp local': `
HP\\032Envy\\0326500e\\032series\\032[099E1B]._ipp._tcp.local. can be reached at HPACF466099E1B.local.:631 (interface 14)
usb_MFG=HP ty=HP\\ Envy\\ 6500e\\ series
`,
      'dscacheutil -q host -a name HPACF466099E1B.local': `
name: hpacf466099e1b.local
ip_address: 192.168.1.95
`,
    };

    const devices = discoverBonjourDevices({
      platform: 'darwin',
      runner: (bin, args) => outputs[[bin, ...args].join(' ')] || '',
      bonjourServices: ['_ipp._tcp'],
    });

    strictEqual(devices.length, 1);
    strictEqual(devices[0].ip, '192.168.1.95');
    strictEqual(devices[0].hostname, 'HP Envy 6500e series [099E1B]');
    strictEqual(devices[0].vendor, 'HP');
    strictEqual(devices[0].type, 'printer');
  });

  it('parses Windows host ARP output and ignores virtual/broadcast/multicast entries', () => {
    const devices = parseWindowsArpOutput(`
Interface: 192.168.1.52 --- 0x12
  Internet Address      Physical Address      Type
  192.168.1.1           dc-08-da-8b-66-35     dynamic
  192.168.1.95          ac-f4-66-09-9e-1b     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.251           01-00-5e-00-00-fb     static

Interface: 172.18.32.1 --- 0x27
  Internet Address      Physical Address      Type
  172.18.38.211         00-15-5d-10-c7-30     dynamic
`);

    strictEqual(devices.length, 2);
    deepStrictEqual(devices.map((device) => device.ip), ['192.168.1.1', '192.168.1.95']);
    strictEqual(devices[0].mac, 'dc:08:da:8b:66:35');
    strictEqual(devices[0].interface, '192.168.1.52');
    strictEqual(devices[0].source, 'windows-arp');
  });

  it('detects WSL from Linux proc version text', () => {
    strictEqual(isWsl({ platform: 'linux', procVersion: 'Linux version 5.15.167.4-microsoft-standard-WSL2' }), true);
    strictEqual(isWsl({ platform: 'linux', procVersion: 'Linux version 6.8.0-generic' }), false);
    strictEqual(isWsl({ platform: 'darwin', procVersion: 'Darwin Kernel Version' }), false);
  });

  it('prefers Windows host LAN discovery under WSL over virtual Linux neighbors', () => {
    const outputs = {
      'powershell.exe -NoProfile -Command arp -a': `
Interface: 192.168.1.52 --- 0x12
  Internet Address      Physical Address      Type
  192.168.1.1           dc-08-da-8b-66-35     dynamic
  192.168.1.95          ac-f4-66-09-9e-1b     dynamic

Interface: 172.18.32.1 --- 0x27
  Internet Address      Physical Address      Type
  172.18.38.211         00-15-5d-10-c7-30     dynamic
`,
      'ip neigh show': '172.18.32.1 dev eth0 lladdr 00:15:5d:9b:ae:97 REACHABLE',
      'arp -a': '? (172.18.32.1) at 00:15:5d:9b:ae:97 [ether] on eth0',
    };
    const devices = discoverDevices({
      platform: 'linux',
      procVersion: 'Linux version 5.15.167.4-microsoft-standard-WSL2',
      runner: (bin, args) => outputs[[bin, ...args].join(' ')] || '',
    });

    deepStrictEqual(devices.map((device) => device.ip).sort(), ['192.168.1.1', '192.168.1.95']);
    strictEqual(devices.every((device) => device.source === 'windows-arp'), true);
  });

  it('still parses macOS/Linux ARP output for Apple hosts without WSL', () => {
    const devices = discoverDevices({
      platform: 'darwin',
      runner: (bin, args) => {
        if (bin === 'arp' && args.join(' ') === '-a') return '? (192.168.1.21) at 28:cf:e9:12:34:56 on en0 ifscope [ethernet]';
        return '';
      },
    });

    strictEqual(devices.length, 1);
    strictEqual(devices[0].ip, '192.168.1.21');
    strictEqual(devices[0].mac, '28:cf:e9:12:34:56');
  });

  it('uses OUI and LAN hints to identify common routers, laptops, and private Apple-style devices', () => {
    const report = auditHomeNetwork({
      devices: [
        { ip: '192.168.1.1', mac: 'dc:08:da:8b:66:35' },
        { ip: '192.168.1.52', mac: '3c:55:76:79:8e:d7' },
        { ip: '192.168.1.41', mac: '8a:12:f8:84:53:2d' },
      ],
    });
    const byIp = Object.fromEntries(report.devices.map((device) => [device.ip, device]));

    strictEqual(byIp['192.168.1.1'].vendor, 'ASKEY COMPUTER CORP');
    strictEqual(byIp['192.168.1.1'].type, 'router');
    strictEqual(byIp['192.168.1.52'].vendor, 'Microsoft');
    strictEqual(byIp['192.168.1.52'].type, 'computer-or-phone');
    strictEqual(byIp['192.168.1.41'].vendor, 'Private randomized MAC');
    strictEqual(byIp['192.168.1.41'].type, 'phone-or-tablet');
    strictEqual(report.summary.unknownDevices, 0);
  });

  it('probes selected TCP ports and folds open services into risk scoring', () => {
    const open = new Set(['192.168.1.122:22', '192.168.1.122:5000', '192.168.1.95:9100']);
    const ports = probeOpenPorts('192.168.1.122', {
      ports: [22, 23, 5000],
      runner: (bin, args) => {
        const key = `${args[args.length - 2]}:${args[args.length - 1]}`;
        if (bin === 'nc' && open.has(key)) return '';
        throw new Error('closed');
      },
    });

    deepStrictEqual(ports, [22, 5000]);

    const report = auditHomeNetwork({
      enablePortScan: true,
      portScanPorts: [22, 23, 5000, 9100],
      devices: [
        { ip: '192.168.1.122', mac: '9a:86:3f:36:42:89' },
        { ip: '192.168.1.95', mac: 'ac:f4:66:09:9e:1b' },
      ],
      portRunner: (bin, args) => {
        const key = `${args[args.length - 2]}:${args[args.length - 1]}`;
        if (bin === 'nc' && open.has(key)) return '';
        throw new Error('closed');
      },
    });
    const byIp = Object.fromEntries(report.devices.map((device) => [device.ip, device]));

    deepStrictEqual(byIp['192.168.1.122'].openPorts, [22, 5000]);
    deepStrictEqual(byIp['192.168.1.95'].openPorts, [9100]);
    strictEqual(byIp['192.168.1.95'].type, 'printer');
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
