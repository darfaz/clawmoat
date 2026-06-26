const fs = require('fs');
const path = require('path');

const DEFAULT_BLOCK_TERMS = [
  'proxy',
  'residential-proxy',
  'backconnect',
  'socks',
  'tunnel',
  'exit-node',
  'peer',
];

function buildHomeDnsBlocklist(report, opts = {}) {
  const terms = opts.terms || DEFAULT_BLOCK_TERMS;
  const rulesByDomain = new Map();
  const devices = Array.isArray(report?.devices) ? report.devices : [];

  for (const device of devices) {
    const dnsQueries = Array.isArray(device.dnsQueries) ? device.dnsQueries : [];
    for (const query of dnsQueries) {
      const domain = normalizeDomain(query);
      if (!domain) continue;
      const lower = domain.toLowerCase();
      const matchedTerm = terms.find((term) => lower.includes(String(term).toLowerCase()));
      if (!matchedTerm) continue;
      upsertRule(rulesByDomain, {
        domain,
        reason: `Matched ${matchedTerm} residential proxy indicator from ${device.hostname || device.ip || 'unknown device'}.`,
        sourceDevice: summarizeDevice(device),
        severity: device.riskScore >= 70 ? 'critical' : 'high',
      });
    }

    const findings = Array.isArray(device.findings) ? device.findings : [];
    if (findings.some((finding) => finding.id === 'residential_proxy_indicator')) {
      for (const conn of device.outboundConnections || []) {
        const domain = normalizeDomain(conn.domain || conn.host);
        if (!domain || isIpv4(domain)) continue;
        upsertRule(rulesByDomain, {
          domain,
          reason: `Outbound residential proxy/datacenter indicator from ${device.hostname || device.ip || 'unknown device'}.`,
          sourceDevice: summarizeDevice(device),
          severity: device.riskScore >= 70 ? 'critical' : 'high',
        });
      }
    }
  }

  const rules = Array.from(rulesByDomain.values()).sort((a, b) => a.domain.localeCompare(b.domain));
  return {
    type: 'home_dns_blocklist',
    source: report?.type || 'home_network_audit',
    generatedAt: new Date().toISOString(),
    domains: rules.map((rule) => rule.domain),
    rules,
    empty: rules.length === 0,
  };
}

function createHomeDnsShieldPlan(report, opts = {}) {
  const blocklist = buildHomeDnsBlocklist(report, opts);
  return {
    type: 'home_dns_shield_plan',
    ok: blocklist.domains.length === 0,
    generatedAt: new Date().toISOString(),
    blocklist,
    integrations: [
      {
        provider: 'pihole',
        name: 'Pi-hole',
        blocklistFormat: 'pihole',
        setup: opts.publicUrl
          ? [`Pi-hole admin → Adlists → add ${opts.publicUrl}`, 'Run pihole -g or update Gravity from the admin UI.']
          : ['Generate a pihole blocklist file and host it on a reachable URL.', 'Pi-hole admin → Adlists → add that URL.', 'Run pihole -g or update Gravity from the admin UI.'],
      },
      {
        provider: 'adguard_home',
        name: 'AdGuard Home',
        blocklistFormat: 'adguard',
        setup: opts.publicUrl
          ? [`AdGuard Home → Filters → DNS blocklists → Add blocklist → ${opts.publicUrl}`]
          : ['Generate an adguard blocklist file and host it on a reachable URL.', 'AdGuard Home → Filters → DNS blocklists → Add blocklist → paste that URL.'],
      },
      {
        provider: 'dnsmasq',
        name: 'dnsmasq / OpenWRT',
        blocklistFormat: 'dnsmasq',
        setup: ['Write the dnsmasq output under /etc/dnsmasq.d/clawmoat-home.conf.', 'Restart dnsmasq after reviewing the generated domains.'],
      },
    ],
    recommendations: blocklist.domains.length
      ? [
          'Add the generated blocklist to Pi-hole or AdGuard Home to block suspicious DNS before risky devices connect out.',
          'Keep Home Watch running so new risky domains from new devices are added to the DNS shield plan.',
          'DNS blocking does not clean compromised firmware. Isolate or replace devices that expose ADB, Telnet, or proxy behavior.',
        ]
      : ['No suspicious DNS domains were found in the current report. Keep Home Watch running and import router/DNS logs for stronger coverage.'],
  };
}

function formatHomeDnsBlocklist(blocklist, opts = {}) {
  const format = opts.format || 'pihole';
  const header = [
    '# ClawMoat Home DNS Shield',
    `# Generated: ${blocklist.generatedAt}`,
    '# Review before use. DNS blocking can break device cloud features.',
  ];
  if (format === 'pihole') return [...header, ...blocklist.domains].join('\n') + '\n';
  if (format === 'adguard') return [...header, ...blocklist.domains.map((domain) => `||${domain}^`)].join('\n') + '\n';
  if (format === 'hosts') return [...header, ...blocklist.domains.map((domain) => `0.0.0.0 ${domain}`)].join('\n') + '\n';
  if (format === 'dnsmasq') return [...header, ...blocklist.domains.map((domain) => `address=/${domain}/0.0.0.0`)].join('\n') + '\n';
  throw new Error(`Unsupported DNS blocklist format: ${format}`);
}

function formatHomeDnsShieldPlanText(plan) {
  const lines = [
    '🏰 ClawMoat Home DNS Shield',
    '',
    `${plan.blocklist.domains.length} suspicious domain${plan.blocklist.domains.length === 1 ? '' : 's'} ready for DNS blocking.`,
    '',
  ];

  if (plan.blocklist.rules.length) {
    lines.push('Blocklist:');
    for (const rule of plan.blocklist.rules) lines.push(`- ${rule.domain} — ${rule.reason}`);
    lines.push('');
  }

  lines.push('Integrations:');
  for (const integration of plan.integrations) {
    lines.push(`- ${integration.name}: export --format ${integration.blocklistFormat}`);
  }
  lines.push('');
  lines.push('Recommended actions:');
  for (const rec of plan.recommendations) lines.push(`- ${rec}`);
  return lines.join('\n');
}

function writeHomeDnsBlocklist(blocklist, outputPath, opts = {}) {
  const rendered = formatHomeDnsBlocklist(blocklist, opts);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, rendered);
  return { outputPath, bytes: Buffer.byteLength(rendered), domains: blocklist.domains.length };
}

function upsertRule(map, rule) {
  const existing = map.get(rule.domain);
  if (!existing) {
    map.set(rule.domain, rule);
    return;
  }
  existing.reason = Array.from(new Set([existing.reason, rule.reason])).join(' ');
  if (severityRank(rule.severity) > severityRank(existing.severity)) existing.severity = rule.severity;
}

function summarizeDevice(device) {
  return {
    ip: device.ip || null,
    hostname: device.hostname || null,
    mac: device.mac || null,
    riskScore: device.riskScore || 0,
    status: device.status || null,
  };
}

function normalizeDomain(value) {
  if (!value) return null;
  let domain = String(value).trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  domain = domain.replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
  if (!domain || domain.includes(' ') || domain.length > 253) return null;
  if (!/^[a-z0-9.-]+$/.test(domain)) return null;
  if (!domain.includes('.')) return null;
  return domain;
}

function isIpv4(value) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) && value.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255);
}

function severityRank(severity) {
  return { low: 1, medium: 2, high: 3, critical: 4 }[severity] || 0;
}

module.exports = {
  buildHomeDnsBlocklist,
  createHomeDnsShieldPlan,
  formatHomeDnsBlocklist,
  formatHomeDnsShieldPlanText,
  writeHomeDnsBlocklist,
};
