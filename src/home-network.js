const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RISKY_PORTS = {
  23: {
    id: 'telnet_exposed',
    severity: 'critical',
    score: 35,
    title: 'Telnet is exposed',
    evidence: 'Port 23 is open. Telnet is common on compromised or poorly secured IoT devices.',
    recommendation: 'Move this device to a guest or IoT network and disable Telnet or remove the device.',
  },
  2323: {
    id: 'alternate_telnet_exposed',
    severity: 'high',
    score: 25,
    title: 'Alternate Telnet port is exposed',
    evidence: 'Port 2323 is open. Malware often scans alternate Telnet ports on IoT devices.',
    recommendation: 'Move this device to a guest or IoT network and block inbound access to this port.',
  },
  5555: {
    id: 'android_debug_bridge_exposed',
    severity: 'critical',
    score: 40,
    title: 'Android Debug Bridge is exposed',
    evidence: 'Port 5555 is open. Exposed ADB is a common Android TV box takeover path.',
    recommendation: 'Unplug or isolate this device until ADB is disabled and the firmware is trusted.',
  },
  7547: {
    id: 'router_management_exposed',
    severity: 'high',
    score: 25,
    title: 'Router management protocol is exposed',
    evidence: 'Port 7547 is open. TR-069/CWMP exposure has been abused by botnets.',
    recommendation: 'Disable remote management if possible or isolate the device behind stricter firewall rules.',
  },
  1900: {
    id: 'upnp_exposed',
    severity: 'medium',
    score: 15,
    title: 'UPnP service is visible',
    evidence: 'Port 1900 is open. UPnP can widen the blast radius when devices are compromised.',
    recommendation: 'Disable UPnP on the router or isolate IoT devices from laptops and servers.',
  },
};

const PROXY_TERMS = [
  'proxy',
  'residential-proxy',
  'socks',
  'vpn',
  'tunnel',
  'peer',
  'exit-node',
  'backconnect',
];

const BONJOUR_SERVICES = [
  '_airplay._tcp',
  '_raop._tcp',
  '_ipp._tcp',
  '_ipps._tcp',
  '_companion-link._tcp',
  '_spotify-connect._tcp',
];

const DEFAULT_PORT_SCAN_PORTS = [22, 23, 53, 80, 443, 631, 2323, 5000, 5555, 7547, 8000, 8080, 8443, 9100];

function parseIpNeighborOutput(output = '') {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const ip = line.split(/\s+/)[0];
      if (!isIpv4(ip)) return null;
      const devMatch = line.match(/\bdev\s+(\S+)/);
      const macMatch = line.match(/\blladdr\s+([0-9a-f:]{17})/i);
      if (!macMatch) return null;
      return {
        ip,
        mac: macMatch[1].toLowerCase(),
        interface: devMatch ? devMatch[1] : null,
        source: 'ip-neigh',
      };
    })
    .filter(Boolean);
}

function parseArpOutput(output = '') {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const ipMatch = line.match(/\(?((?:\d{1,3}\.){3}\d{1,3})\)?/);
      const macMatch = line.match(/\bat\s+([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})\b/i);
      if (!ipMatch || !macMatch) return null;
      const ip = ipMatch[1];
      const mac = normalizeMac(macMatch[1]);
      if (!isUsefulLanAddress(ip) || isBroadcastMac(mac)) return null;
      return {
        ip,
        mac,
        source: 'arp',
      };
    })
    .filter(Boolean);
}

function parseDnsSdBrowseOutput(output = '') {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const match = line.match(/^\S+\s+Add\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(.+)$/);
      if (!match) return null;
      return {
        service: normalizeServiceName(match[2]),
        instance: decodeDnsSdEscapes(match[3].trim()),
        domain: String(match[1] || 'local').replace(/\.$/, ''),
      };
    })
    .filter(Boolean);
}

function parseDnsSdLookupOutput(instance, service, output = '') {
  const targetMatch = output.match(/can be reached at\s+([^\s:]+)\.:?(\d+)?/i);
  if (!targetMatch) return null;
  const text = output.replace(/\\\s/g, ' ');
  const mdnsHost = targetMatch[1].replace(/\.$/, '');
  const vendor = inferBonjourVendor(instance, service, text);
  const type = inferBonjourType(instance, service, text, vendor);
  return {
    hostname: decodeDnsSdEscapes(instance),
    mdnsHost,
    mdnsService: normalizeServiceName(service),
    port: targetMatch[2] ? Number(targetMatch[2]) : null,
    vendor,
    type,
    source: 'bonjour',
  };
}

function discoverBonjourDevices(opts = {}) {
  const platform = opts.platform || process.platform;
  if (platform !== 'darwin' && opts.enableBonjour !== true) return [];
  const runner = opts.runner || defaultRunner;
  const services = opts.bonjourServices || BONJOUR_SERVICES;
  const devices = [];
  const seen = new Set();

  for (const service of services) {
    const browseOutput = runDiscoveryCommand(runner, 'dns-sd', ['-B', service, 'local']);
    for (const entry of parseDnsSdBrowseOutput(browseOutput)) {
      const lookupKey = `${entry.service}|${entry.instance}`;
      if (seen.has(lookupKey)) continue;
      seen.add(lookupKey);
      const lookupOutput = runDiscoveryCommand(runner, 'dns-sd', ['-L', entry.instance, entry.service, entry.domain || 'local']);
      const device = parseDnsSdLookupOutput(entry.instance, entry.service, lookupOutput);
      if (!device) continue;
      const hostOutput = runDiscoveryCommand(runner, 'dscacheutil', ['-q', 'host', '-a', 'name', device.mdnsHost]);
      device.ip = parseDscacheutilHostOutput(hostOutput);
      devices.push(device);
    }
  }

  return devices;
}

function parseDscacheutilHostOutput(output = '') {
  for (const line of output.split(/\r?\n/)) {
    const match = line.trim().match(/^ip_address:\s+((?:\d{1,3}\.){3}\d{1,3})$/);
    if (match && isUsefulLanAddress(match[1])) return match[1];
  }
  return null;
}

function runDiscoveryCommand(runner, bin, args) {
  try {
    return runner(bin, args);
  } catch (err) {
    if (err && err.stdout) return Buffer.isBuffer(err.stdout) ? err.stdout.toString('utf8') : String(err.stdout);
    return '';
  }
}

function normalizeServiceName(service) {
  return String(service || '').replace(/\.$/, '');
}

function decodeDnsSdEscapes(value) {
  return String(value || '').replace(/\\(\d{3})/g, (_match, code) => String.fromCharCode(Number(code)));
}

function inferBonjourVendor(instance, service, text = '') {
  const haystack = `${instance} ${service} ${text}`.toLowerCase();
  if (haystack.includes('manufacturer=roku') || haystack.includes('roku')) return 'Roku';
  if (haystack.includes('usb_mfg=hp') || haystack.includes('manufacturer=hp') || haystack.includes('hp envy') || /^hp/i.test(instance)) return 'HP';
  if (haystack.includes('macbook') || haystack.includes('iphone') || haystack.includes('ipad') || haystack.includes('_airplay') || haystack.includes('_raop') || haystack.includes('_companion-link')) return 'Apple';
  return 'Unknown';
}

function inferBonjourType(instance, service, text = '', vendor = 'Unknown') {
  const name = String(instance || '').toLowerCase();
  const svc = normalizeServiceName(service);
  const haystack = `${name} ${text}`.toLowerCase();
  if (svc === '_ipp._tcp' || svc === '_ipps._tcp' || haystack.includes('printer') || haystack.includes('airprint') || haystack.includes('usb_mfg=hp')) return 'printer';
  if (name.includes('roku') || haystack.includes('manufacturer=roku')) return 'streaming-device';
  if (name.includes('tv') || svc === '_airplay._tcp') return 'streaming-device';
  if (name.includes('macbook') || name.includes('iphone') || name.includes('ipad') || svc === '_companion-link._tcp' || svc === '_raop._tcp' || vendor === 'Apple') return 'computer-or-phone';
  if (svc === '_spotify-connect._tcp') return 'streaming-device';
  return 'unknown';
}

function parseWindowsArpOutput(output = '') {
  const groups = [];
  let current = null;

  for (const rawLine of output.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;

    const interfaceMatch = line.match(/^Interface:\s+((?:\d{1,3}\.){3}\d{1,3})\b/i);
    if (interfaceMatch) {
      current = { interfaceIp: interfaceMatch[1], devices: [] };
      groups.push(current);
      continue;
    }

    const entryMatch = line.match(/^((?:\d{1,3}\.){3}\d{1,3})\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+(dynamic|static)\b/i);
    if (!entryMatch || !current) continue;
    const ip = entryMatch[1];
    const mac = entryMatch[2].toLowerCase().replace(/-/g, ':');
    const type = entryMatch[3].toLowerCase();
    if (!isUsefulLanAddress(ip) || isBroadcastMac(mac) || type !== 'dynamic') continue;
    current.devices.push({
      ip,
      mac,
      interface: current.interfaceIp,
      source: 'windows-arp',
    });
  }

  const usefulGroups = groups.filter((group) => isUsefulLanAddress(group.interfaceIp) && group.devices.length > 0);
  if (!usefulGroups.length) return [];
  usefulGroups.sort((a, b) => scoreWindowsInterfaceGroup(b) - scoreWindowsInterfaceGroup(a));
  return usefulGroups[0].devices;
}

function auditHomeNetwork(opts = {}) {
  const rawDevices = opts.devices || discoverDevices(opts);
  const devicesWithPorts = maybeProbeDevicePorts(rawDevices, opts);
  const devices = devicesWithPorts.map(normalizeDevice).map(scoreDevice);
  const summary = summarize(devices);
  return {
    type: 'home_network_audit',
    ok: summary.highRiskDevices === 0 && summary.criticalFindings === 0,
    generatedAt: new Date().toISOString(),
    scope: opts.scope || 'local-network',
    summary,
    devices: devices.sort((a, b) => b.riskScore - a.riskScore || a.ip.localeCompare(b.ip)),
    recommendations: buildNetworkRecommendations(devices),
    limitations: [
      'Passive scans cannot prove a device is clean; they identify risky exposure and suspicious behavior.',
      'Blocking or quarantine requires DNS, router, firewall, Pi-hole, OpenWRT, UniFi, pfSense, or similar integration.',
      'Encrypted traffic hides payloads, so ClawMoat uses metadata, ports, DNS, and behavior indicators.',
    ],
  };
}

function discoverDevices(opts = {}) {
  const runner = opts.runner || defaultRunner;
  const devices = new Map();

  if (isWsl(opts)) {
    const windowsDevices = discoverWindowsHostDevices({ runner });
    if (windowsDevices.length) return dedupeDevices(windowsDevices);
  }

  for (const command of [
    { bin: 'ip', args: ['neigh', 'show'], parser: parseIpNeighborOutput },
    { bin: 'arp', args: ['-a'], parser: parseArpOutput },
  ]) {
    try {
      const output = runner(command.bin, command.args);
      for (const device of command.parser(output)) {
        mergeDiscoveredDevice(devices, device);
      }
    } catch (_err) {
      // Discovery should degrade gracefully. Many laptops lack arp/ip tools or permissions.
    }
  }

  for (const device of discoverBonjourDevices({ ...opts, runner })) {
    mergeDiscoveredDevice(devices, device);
  }

  return Array.from(devices.values());
}

function discoverWindowsHostDevices(opts = {}) {
  const runner = opts.runner || defaultRunner;
  try {
    return parseWindowsArpOutput(runner('powershell.exe', ['-NoProfile', '-Command', 'arp -a']));
  } catch (_err) {
    return [];
  }
}

function defaultRunner(bin, args) {
  return execFileSync(bin, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 });
}

function isWsl(opts = {}) {
  const platform = opts.platform || process.platform;
  if (platform !== 'linux') return false;
  const procVersion = opts.procVersion !== undefined ? opts.procVersion : readProcVersion();
  const text = String(procVersion || '').toLowerCase();
  return text.includes('microsoft') || text.includes('wsl');
}

function readProcVersion() {
  try {
    return fs.readFileSync('/proc/version', 'utf8');
  } catch {
    return '';
  }
}

function dedupeDevices(devices) {
  const byKey = new Map();
  for (const device of devices) {
    const key = device.mac || device.ip;
    byKey.set(key, { ...(byKey.get(key) || {}), ...device });
  }
  return Array.from(byKey.values());
}

function mergeDiscoveredDevice(devices, device) {
  const key = device.ip || device.mac || device.mdnsHost || device.hostname;
  if (!key) return;
  const existing = devices.get(key) || {};
  const merged = { ...existing, ...device };

  if (existing.hostname && (!device.hostname || identitySignalScore(existing) >= identitySignalScore(device))) merged.hostname = existing.hostname;
  if (existing.vendor && existing.vendor !== 'Unknown' && (!device.vendor || device.vendor === 'Unknown')) merged.vendor = existing.vendor;
  if (existing.type && existing.type !== 'unknown' && (!device.type || device.type === 'unknown')) merged.type = existing.type;
  merged.source = mergeSources(existing.source, device.source);

  devices.set(key, merged);
}

function identitySignalScore(device = {}) {
  let score = 0;
  const hostname = String(device.hostname || '');
  if (hostname) score += 2;
  if (hostname && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(hostname)) score += 3;
  if (device.vendor && device.vendor !== 'Unknown') score += 3;
  if (device.type && device.type !== 'unknown') score += 1;
  return score;
}

function mergeSources(...sources) {
  return sources
    .filter(Boolean)
    .flatMap((source) => String(source).split('+'))
    .filter((source, index, all) => all.indexOf(source) === index)
    .join('+') || undefined;
}

function maybeProbeDevicePorts(devices, opts = {}) {
  if (!shouldScanPorts(opts)) return devices;
  return devices.map((device) => {
    if (!device.ip || (Array.isArray(device.openPorts) && device.openPorts.length)) return device;
    const openPorts = probeOpenPorts(device.ip, {
      ports: opts.portScanPorts || DEFAULT_PORT_SCAN_PORTS,
      runner: opts.portRunner || defaultPortRunner,
    });
    return { ...device, openPorts };
  });
}

function shouldScanPorts(opts = {}) {
  if (opts.enablePortScan === true) return true;
  if (opts.enablePortScan === false) return false;
  if (opts.devices) return false;
  return (opts.platform || process.platform) === 'darwin';
}

function probeOpenPorts(ip, opts = {}) {
  if (!isUsefulLanAddress(ip)) return [];
  const runner = opts.runner || defaultPortRunner;
  const ports = opts.ports || DEFAULT_PORT_SCAN_PORTS;
  const open = [];
  for (const port of ports) {
    try {
      runner('nc', ['-G', '1', '-z', ip, String(port)]);
      open.push(Number(port));
    } catch (_err) {
      // Closed, filtered, or nc unavailable. Port probing must never break passive discovery.
    }
  }
  return Array.from(new Set(open)).sort((a, b) => a - b);
}

function defaultPortRunner(bin, args) {
  return execFileSync(bin, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 1500 });
}

function normalizeDevice(device) {
  const hostname = device.hostname || device.name || null;
  const vendor = device.vendor || guessVendor(device.mac) || 'Unknown';
  const openPorts = Array.from(new Set((device.openPorts || []).map(Number).filter(Boolean))).sort((a, b) => a - b);
  return {
    ip: device.ip || 'unknown',
    mac: device.mac || null,
    hostname,
    vendor,
    interface: device.interface || null,
    type: device.type || guessDeviceType({ ip: device.ip, hostname, vendor, openPorts }),
    openPorts,
    dnsQueries: device.dnsQueries || [],
    outboundConnections: device.outboundConnections || [],
    firstSeen: device.firstSeen || null,
    lastSeen: device.lastSeen || null,
    source: device.source || 'provided',
  };
}

function scoreDevice(device) {
  const findings = [];
  let riskScore = 0;

  if (device.vendor === 'Unknown' || !device.mac) {
    findings.push({
      id: 'unknown_device_identity',
      severity: 'medium',
      title: 'Unknown device identity',
      evidence: 'ClawMoat could not identify this device vendor from local network metadata.',
    });
    riskScore += 10;
  }

  for (const port of device.openPorts) {
    const risky = RISKY_PORTS[port];
    if (risky) {
      findings.push({ ...risky, port });
      riskScore += risky.score;
    }
  }

  const proxyDnsHits = device.dnsQueries.filter((query) => PROXY_TERMS.some((term) => String(query).toLowerCase().includes(term)));
  const proxyConnections = device.outboundConnections.filter((conn) => {
    const haystack = [conn.host, conn.domain, conn.asnType, conn.category].filter(Boolean).join(' ').toLowerCase();
    return PROXY_TERMS.some((term) => haystack.includes(term)) || conn.asnType === 'datacenter';
  });

  if (proxyDnsHits.length > 0 || proxyConnections.length >= 3) {
    findings.push({
      id: 'residential_proxy_indicator',
      severity: proxyConnections.length >= 3 ? 'critical' : 'high',
      title: 'Residential proxy behavior indicator',
      evidence: `Observed ${proxyDnsHits.length} proxy-like DNS quer${proxyDnsHits.length === 1 ? 'y' : 'ies'} and ${proxyConnections.length} proxy/datacenter-like outbound connection${proxyConnections.length === 1 ? '' : 's'}.`,
      recommendation: 'Treat this as a possible residential proxy/backdoor signal: isolate the device, review router/DNS logs, and block outbound traffic until verified.',
    });
    riskScore += proxyConnections.length >= 3 ? 35 : 25;
  }

  riskScore = Math.min(100, riskScore);
  const severity = maxSeverity(findings);
  return {
    ...device,
    riskScore,
    severity,
    status: riskScore >= 70 ? 'high-risk' : riskScore >= 35 ? 'review' : findings.length ? 'watch' : 'ok',
    findings,
    recommendations: buildDeviceRecommendations({ ...device, findings, riskScore }),
  };
}

function summarize(devices) {
  const findings = devices.flatMap((device) => device.findings);
  return {
    devices: devices.length,
    highRiskDevices: devices.filter((device) => device.riskScore >= 70).length,
    reviewDevices: devices.filter((device) => device.riskScore >= 35 && device.riskScore < 70).length,
    unknownDevices: devices.filter((device) => device.vendor === 'Unknown' || !device.mac).length,
    criticalFindings: findings.filter((finding) => finding.severity === 'critical').length,
    findings: findings.length,
    riskScore: devices.length ? Math.max(...devices.map((device) => device.riskScore)) : 0,
  };
}

function buildDeviceRecommendations(device) {
  const recs = [];
  if (device.riskScore >= 70) {
    recs.push('Immediately isolate this device from laptops, phones, and servers. Move this device to a guest or IoT network.');
  }
  for (const finding of device.findings) {
    if (finding.recommendation) recs.push(finding.recommendation);
  }
  if (device.openPorts.includes(23) || device.openPorts.includes(2323)) {
    recs.push('Disable Telnet or replace the device if the vendor does not provide a secure firmware update.');
  }
  if (device.openPorts.includes(5555)) {
    recs.push('Disable Android Debug Bridge over the network. Cheap Android TV boxes with exposed ADB are high-risk.');
  }
  if (recs.length === 0) recs.push('No immediate action. Keep firmware updated and keep IoT devices segmented from work machines.');
  return Array.from(new Set(recs));
}

function buildNetworkRecommendations(devices) {
  const recs = [];
  if (devices.some((device) => device.riskScore >= 70)) {
    recs.push('Quarantine high-risk devices on a guest or IoT VLAN before trusting the network.');
    recs.push('Block outbound traffic from high-risk devices until you verify firmware and ownership.');
  }
  if (devices.some((device) => device.openPorts.includes(23) || device.openPorts.includes(2323))) {
    recs.push('Disable Telnet across home devices; exposed Telnet is a botnet magnet.');
  }
  if (devices.some((device) => device.openPorts.includes(5555))) {
    recs.push('Disable network ADB on Android TV boxes and streaming devices.');
  }
  recs.push('For active blocking, connect ClawMoat to DNS/router controls such as Pi-hole, AdGuard Home, OpenWRT, UniFi, pfSense, or OPNsense.');
  return Array.from(new Set(recs));
}

function formatHomeNetworkText(report) {
  const deviceWord = report.summary.devices === 1 ? 'device' : 'devices';
  const lines = [
    '🏰 ClawMoat Home Network Report',
    '',
    `${report.summary.devices} ${deviceWord} found. ${report.summary.highRiskDevices} high-risk. ${report.summary.unknownDevices} unknown.`,
    `Network risk score: ${report.summary.riskScore}/100`,
    '',
  ];

  for (const device of report.devices) {
    const label = device.hostname || device.ip;
    lines.push(`${device.status.toUpperCase()} — ${label} (${device.ip})`);
    lines.push(`  Vendor: ${device.vendor}; Type: ${device.type}; Risk: ${device.riskScore}/100`);
    if (device.openPorts.length) lines.push(`  Open ports: ${device.openPorts.join(', ')}`);
    for (const finding of device.findings) {
      lines.push(`  • ${finding.title}: ${finding.evidence}`);
    }
    if (device.recommendations.length) lines.push(`  Next: ${device.recommendations[0]}`);
    lines.push('');
  }

  lines.push('Recommended actions:');
  for (const rec of report.recommendations) lines.push(`- ${rec}`);
  lines.push('');
  lines.push('Limitations: ClawMoat can detect exposure and suspicious indicators from local metadata. Actual blocking requires DNS/router/firewall integration.');
  return lines.join('\n');
}

function createHomeWatchReport(opts = {}) {
  const current = opts.current || auditHomeNetwork(opts);
  const baseline = opts.baseline || null;
  const baselineDevices = Array.isArray(baseline?.devices) ? baseline.devices : [];
  const currentDevices = Array.isArray(current.devices) ? current.devices : [];
  const baselineByKey = new Map(baselineDevices.map((device) => [deviceIdentity(device), device]));
  const currentByKey = new Map(currentDevices.map((device) => [deviceIdentity(device), device]));
  const firstRun = !baseline;
  const newDevices = firstRun ? [] : currentDevices.filter((device) => !baselineByKey.has(deviceIdentity(device)));
  const missingDevices = firstRun ? [] : baselineDevices.filter((device) => !currentByKey.has(deviceIdentity(device)));
  const changedRiskDevices = currentDevices
    .map((device) => {
      const previous = baselineByKey.get(deviceIdentity(device));
      if (!previous) return null;
      const previousRiskScore = Number(previous.riskScore || 0);
      const riskDelta = device.riskScore - previousRiskScore;
      const previousPorts = Array.isArray(previous.openPorts) ? previous.openPorts : [];
      const addedPorts = (device.openPorts || []).filter((port) => !previousPorts.includes(port));
      if (riskDelta < 20 && addedPorts.length === 0 && previous.status === device.status) return null;
      return { ...device, previousRiskScore, riskDelta, addedPorts, previousStatus: previous.status || null };
    })
    .filter(Boolean);

  const alerts = [];
  for (const device of newDevices) {
    alerts.push({
      type: device.riskScore >= 35 ? 'new_high_risk_device' : 'new_device',
      severity: device.riskScore >= 70 ? 'critical' : device.riskScore >= 35 ? 'high' : 'medium',
      device: summarizeDeviceForAlert(device),
      message: `${device.hostname || device.ip} joined the network with risk ${device.riskScore}/100.`,
    });
  }
  for (const device of changedRiskDevices) {
    alerts.push({
      type: 'device_risk_changed',
      severity: device.riskScore >= 70 ? 'critical' : device.riskScore >= 35 ? 'high' : 'medium',
      device: summarizeDeviceForAlert(device),
      message: `${device.hostname || device.ip} risk changed by ${device.riskDelta} points${device.addedPorts.length ? `; new open ports: ${device.addedPorts.join(', ')}` : ''}.`,
    });
  }

  return {
    type: 'home_network_watch',
    ok: alerts.length === 0,
    firstRun,
    generatedAt: new Date().toISOString(),
    baselineGeneratedAt: baseline?.generatedAt || null,
    current,
    summary: {
      devices: current.summary.devices,
      riskScore: current.summary.riskScore,
      highRiskDevices: current.summary.highRiskDevices,
      newDevices: newDevices.length,
      missingDevices: missingDevices.length,
      changedRiskDevices: changedRiskDevices.length,
      alerts: alerts.length,
    },
    changes: {
      newDevices,
      missingDevices,
      changedRiskDevices,
    },
    alerts,
    weeklySummary: buildWeeklySummary(current, { newDevices, missingDevices, changedRiskDevices, alerts }),
  };
}

function formatHomeWatchText(report) {
  const lines = [
    '🏰 ClawMoat Home Watch',
    '',
    `Devices: ${report.summary.devices}. New devices: ${report.summary.newDevices}. Missing devices: ${report.summary.missingDevices}. Alerts: ${report.summary.alerts}.`,
    `Network risk score: ${report.summary.riskScore}/100`,
    '',
  ];

  if (report.firstRun) {
    lines.push('First run: baseline saved. Future runs will alert when new or riskier devices appear.');
    lines.push('');
  }

  if (report.alerts.length) {
    lines.push('Alerts:');
    for (const alert of report.alerts) lines.push(`- ${alert.severity.toUpperCase()}: ${alert.message}`);
    lines.push('');
  }

  if (report.changes.newDevices.length) {
    lines.push('New devices:');
    for (const device of report.changes.newDevices) {
      lines.push(`- ${device.hostname || device.ip} (${device.ip}) — ${device.vendor}; risk ${device.riskScore}/100; ${device.status}`);
    }
    lines.push('');
  }

  if (report.changes.missingDevices.length) {
    lines.push('Missing devices:');
    for (const device of report.changes.missingDevices) lines.push(`- ${device.hostname || device.ip} (${device.ip})`);
    lines.push('');
  }

  lines.push('Weekly summary:');
  for (const item of report.weeklySummary) lines.push(`- ${item}`);
  lines.push('');
  lines.push('Next: run this from cron/Task Scheduler for weekly reports, or use --daemon once router/DNS integrations are wired in.');
  return lines.join('\n');
}

function loadHomeWatchBaseline(statePath = defaultHomeWatchStatePath()) {
  try {
    return JSON.parse(fs.readFileSync(statePath, 'utf8'));
  } catch {
    return null;
  }
}

function saveHomeWatchBaseline(report, statePath = defaultHomeWatchStatePath()) {
  const baseline = {
    type: 'home_network_baseline',
    generatedAt: report.generatedAt,
    scope: report.scope,
    summary: report.summary,
    devices: report.devices,
  };
  fs.mkdirSync(path.dirname(statePath), { recursive: true });
  fs.writeFileSync(statePath, JSON.stringify(baseline, null, 2));
  return baseline;
}

function defaultHomeWatchStatePath() {
  return path.join(os.homedir(), '.clawmoat', 'home-watch-baseline.json');
}

function deviceIdentity(device) {
  return String(device.mac || device.ip || device.hostname || 'unknown').toLowerCase();
}

function summarizeDeviceForAlert(device) {
  return {
    ip: device.ip,
    mac: device.mac,
    hostname: device.hostname,
    vendor: device.vendor,
    riskScore: device.riskScore,
    status: device.status,
  };
}

function buildWeeklySummary(current, changes) {
  const summary = [];
  summary.push(`${current.summary.devices} devices seen; ${current.summary.highRiskDevices} high-risk; ${current.summary.unknownDevices} unknown.`);
  if (changes.newDevices.length) summary.push(`${changes.newDevices.length} new device${changes.newDevices.length === 1 ? '' : 's'} joined since the saved baseline.`);
  if (changes.changedRiskDevices.length) summary.push(`${changes.changedRiskDevices.length} device${changes.changedRiskDevices.length === 1 ? '' : 's'} became riskier or exposed new ports.`);
  if (current.recommendations.length) summary.push(current.recommendations[0]);
  if (changes.alerts.length === 0) summary.push('No new high-risk device changes since the saved baseline.');
  return summary;
}

function sampleHomeNetworkReport() {
  return auditHomeNetwork({
    scope: 'sample-home-network',
    devices: [
      {
        ip: '192.168.1.1',
        mac: 'aa:bb:cc:00:00:01',
        hostname: 'home-router',
        vendor: 'Router Vendor',
        openPorts: [80, 443],
      },
      {
        ip: '192.168.1.42',
        mac: '12:34:56:78:90:ab',
        hostname: 'living-room-android-tv-box',
        vendor: 'Unknown',
        type: 'streaming-device',
        openPorts: [23, 5555, 8080],
        dnsQueries: ['pool.residential-proxy.example', 'updates.vendor.invalid'],
        outboundConnections: [
          { host: '203.0.113.10', asnType: 'datacenter' },
          { host: '198.51.100.20', asnType: 'datacenter' },
          { host: '192.0.2.30', asnType: 'residential-proxy' },
        ],
      },
      {
        ip: '192.168.1.51',
        mac: 'de:ad:be:ef:00:51',
        hostname: 'driveway-camera',
        vendor: 'Unknown',
        type: 'camera',
        openPorts: [23, 554],
      },
    ],
  });
}

function guessVendor(mac) {
  if (!mac) return null;
  const normalized = normalizeMac(mac);
  const prefix = normalized.slice(0, 8);
  const vendors = {
    '28:cf:e9': 'Apple',
    'f0:18:98': 'Apple',
    '3c:55:76': 'Microsoft',
    '3c:5a:b4': 'Google',
    '8c:49:62': 'Roku',
    'ac:f4:66': 'HP',
    'dc:08:da': 'ASKEY COMPUTER CORP',
    'd8:31:34': 'Raspberry Pi',
    'b8:27:eb': 'Raspberry Pi',
    'dc:a6:32': 'Raspberry Pi',
    '00:04:20': 'Slim Devices',
  };
  if (vendors[prefix]) return vendors[prefix];
  if (isLocallyAdministeredMac(normalized)) return 'Private randomized MAC';
  return null;
}

function guessDeviceType({ ip, hostname, vendor, openPorts }) {
  const name = String(hostname || '').toLowerCase();
  if (name.includes('camera') || openPorts.includes(554)) return 'camera';
  if (name.includes('tv') || name.includes('roku') || name.includes('android') || vendor === 'Roku') return 'streaming-device';
  if (name.includes('printer') || vendor === 'HP' || openPorts.includes(9100) || openPorts.includes(631)) return 'printer';
  if (name.includes('router') || name.includes('gateway') || isLikelyGatewayIp(ip) || vendor === 'ASKEY COMPUTER CORP') return 'router';
  if (vendor === 'Apple' || vendor === 'Microsoft') return 'computer-or-phone';
  if (vendor === 'Private randomized MAC') return 'phone-or-tablet';
  if (vendor === 'Raspberry Pi') return 'single-board-computer';
  return 'unknown';
}

function isLocallyAdministeredMac(mac) {
  const firstOctet = Number.parseInt(String(mac).split(':')[0], 16);
  return Number.isFinite(firstOctet) && (firstOctet & 0x02) === 0x02;
}

function isLikelyGatewayIp(ip) {
  if (!isIpv4(ip)) return false;
  const last = Number(ip.split('.')[3]);
  return last === 1 || last === 254;
}

function maxSeverity(findings) {
  if (!findings.length) return null;
  const rank = { low: 1, medium: 2, high: 3, critical: 4 };
  return findings.reduce((max, finding) => (rank[finding.severity] > rank[max] ? finding.severity : max), 'low');
}

function isIpv4(value) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) && value.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255);
}

function isUsefulLanAddress(value) {
  if (!isIpv4(value)) return false;
  const parts = value.split('.').map(Number);
  if (parts[0] === 0 || parts[0] === 127 || parts[0] === 169 || parts[0] >= 224) return false;
  if (parts[3] === 0 || parts[3] === 255) return false;
  return true;
}

function normalizeMac(mac) {
  if (!mac) return null;
  return mac
    .toLowerCase()
    .split(':')
    .map((part) => part.padStart(2, '0'))
    .join(':');
}

function isBroadcastMac(mac) {
  return !mac || mac === 'ff:ff:ff:ff:ff:ff' || mac.startsWith('01:00:5e:');
}

function scoreWindowsInterfaceGroup(group) {
  const parts = group.interfaceIp.split('.').map(Number);
  let score = group.devices.length;
  if (parts[0] === 192 && parts[1] === 168) score += 100;
  else if (parts[0] === 10) score += 80;
  else if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) score += 40;
  if (parts[0] === 172 && (parts[1] === 17 || parts[1] === 18)) score -= 30;
  return score;
}

function getLocalNetworkHints() {
  const interfaces = os.networkInterfaces();
  return Object.entries(interfaces).flatMap(([name, entries]) =>
    (entries || [])
      .filter((entry) => entry.family === 'IPv4' && !entry.internal)
      .map((entry) => ({ interface: name, address: entry.address, cidr: entry.cidr }))
  );
}

module.exports = {
  auditHomeNetwork,
  createHomeWatchReport,
  defaultHomeWatchStatePath,
  discoverBonjourDevices,
  discoverDevices,
  discoverWindowsHostDevices,
  formatHomeNetworkText,
  formatHomeWatchText,
  getLocalNetworkHints,
  loadHomeWatchBaseline,
  parseArpOutput,
  parseDnsSdBrowseOutput,
  parseDnsSdLookupOutput,
  parseIpNeighborOutput,
  probeOpenPorts,
  parseWindowsArpOutput,
  isWsl,
  sampleHomeNetworkReport,
  saveHomeWatchBaseline,
};
