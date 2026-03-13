#!/usr/bin/env node
/**
 * ClawMoat Agent Setup
 * 
 * Interactive setup: prompts for API key, tests it, writes config,
 * optionally installs as a systemd user service.
 * 
 * Usage: node agent/setup.js [--api-key <key>] [--no-service]
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const readline = require('readline');
const { execSync, exec } = require('child_process');

const CONFIG_DIR = path.join(os.homedir(), '.clawmoat');
const CONFIG_PATH = path.join(CONFIG_DIR, 'agent.json');
const AUDIT_LOG = path.join(CONFIG_DIR, 'audit.log');

// Parse args
const args = process.argv.slice(2);
const NO_SERVICE = args.includes('--no-service');
const API_KEY_ARG = (() => {
  const i = args.indexOf('--api-key');
  return i >= 0 ? args[i + 1] : null;
})();

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function ask(question, defaultVal) {
  return new Promise(resolve => {
    const suffix = defaultVal ? ` [${defaultVal}]` : '';
    rl.question(`${question}${suffix}: `, answer => {
      resolve(answer.trim() || defaultVal || '');
    });
  });
}

function askYN(question, defaultYes = true) {
  const suffix = defaultYes ? '[Y/n]' : '[y/N]';
  return new Promise(resolve => {
    rl.question(`${question} ${suffix}: `, answer => {
      const a = answer.trim().toLowerCase();
      if (!a) resolve(defaultYes);
      else resolve(a === 'y' || a === 'yes');
    });
  });
}

async function testApiKey(apiKey, dashboardUrl) {
  return new Promise((resolve) => {
    if (!apiKey || apiKey === 'cm_live_...') {
      resolve({ ok: false, error: 'No API key provided' });
      return;
    }

    const url = new URL('/api/agent/verify', dashboardUrl);
    const body = JSON.stringify({ source: 'local-agent', version: '1.0.0' });

    const req = https.request({
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout: 8000,
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (res.statusCode === 200 || res.statusCode === 201) {
          resolve({ ok: true });
        } else if (res.statusCode === 401 || res.statusCode === 403) {
          resolve({ ok: false, error: 'Invalid API key' });
        } else if (res.statusCode === 404) {
          // Endpoint may not exist yet — treat as "key format ok, endpoint pending"
          resolve({ ok: true, warning: 'Verify endpoint not found (dashboard may not have it yet)' });
        } else {
          resolve({ ok: false, error: `HTTP ${res.statusCode}` });
        }
      });
    });
    req.on('error', e => resolve({ ok: false, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'Timeout' }); });
    req.write(body);
    req.end();
  });
}

function detectSystemd() {
  try {
    execSync('systemctl --user status', { stdio: 'pipe' });
    return true;
  } catch (e) {
    // In WSL2, systemd might not be running
    try {
      execSync('which systemctl', { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }
}

async function installService(agentDir) {
  const agentScript = path.join(agentDir, 'index.js');
  const nodeBin = process.execPath;
  const serviceScript = path.join(agentDir, 'install-service.sh');

  console.log('\nInstalling systemd user service...');

  return new Promise((resolve) => {
    exec(`bash "${serviceScript}" "${nodeBin}" "${agentScript}"`, (err, stdout, stderr) => {
      if (err) {
        console.error('Service installation failed:', err.message);
        if (stderr) console.error(stderr);
        resolve(false);
      } else {
        console.log(stdout);
        resolve(true);
      }
    });
  });
}

async function main() {
  console.log('\n╔════════════════════════════════════╗');
  console.log('║   ClawMoat Local Agent — Setup    ║');
  console.log('╚════════════════════════════════════╝\n');

  // Load existing config if present
  let existing = {};
  try {
    existing = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    console.log('Found existing config at', CONFIG_PATH);
  } catch {}

  // API Key
  let apiKey = API_KEY_ARG || existing.apiKey || '';
  if (!apiKey || apiKey === 'cm_live_...') {
    console.log('Get your API key from: https://app.clawmoat.com/settings/api-keys\n');
    apiKey = await ask('Enter your ClawMoat API key (cm_live_...)');
  } else {
    console.log(`API key: ${apiKey.slice(0, 12)}...`);
    const change = await askYN('Change API key?', false);
    if (change) {
      apiKey = await ask('Enter new API key');
    }
  }

  // Dashboard URL
  const dashboardUrl = await ask('Dashboard URL', existing.dashboardUrl || 'https://app.clawmoat.com');

  // Test the key
  if (apiKey && apiKey !== 'cm_live_...') {
    process.stdout.write('Testing API key... ');
    const test = await testApiKey(apiKey, dashboardUrl);
    if (test.ok) {
      console.log('✓ OK' + (test.warning ? ` (${test.warning})` : ''));
    } else {
      console.log('✗ Failed:', test.error);
      const cont = await askYN('Continue anyway?', false);
      if (!cont) {
        rl.close();
        process.exit(1);
      }
    }
  }

  // Scan settings
  console.log('\nScan settings:');
  const scanInbound = await askYN('Scan inbound messages?', existing.scanInbound !== false);
  const scanOutbound = await askYN('Scan outbound messages?', existing.scanOutbound !== false);
  const scanToolCalls = await askYN('Scan tool calls?', existing.scanToolCalls !== false);
  const reportToCloud = await askYN('Report findings to cloud dashboard?', existing.reportToCloud !== false);

  // Write config
  const config = {
    apiKey,
    dashboardUrl,
    scanInbound,
    scanOutbound,
    scanToolCalls,
    auditLog: existing.auditLog || '~/.clawmoat/audit.log',
    reportToCloud,
    updatedAt: new Date().toISOString(),
  };

  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
  fs.chmodSync(CONFIG_PATH, 0o600);
  console.log(`\n✓ Config written to ${CONFIG_PATH}`);

  // Ensure audit log dir exists
  fs.mkdirSync(path.dirname(AUDIT_LOG), { recursive: true });
  if (!fs.existsSync(AUDIT_LOG)) {
    fs.writeFileSync(AUDIT_LOG, '');
    console.log(`✓ Audit log initialized at ${AUDIT_LOG}`);
  }

  // Service installation
  if (!NO_SERVICE) {
    const hasSystemd = detectSystemd();
    const isWSL = fs.existsSync('/proc/version') && 
      fs.readFileSync('/proc/version', 'utf8').toLowerCase().includes('microsoft');

    if (isWSL) {
      console.log('\nNote: Running in WSL2. Systemd service requires systemd enabled in WSL.');
    }

    if (hasSystemd) {
      const installSvc = await askYN('\nInstall as systemd user service (auto-start)?', true);
      if (installSvc) {
        const agentDir = path.dirname(__filename);
        await installService(agentDir);
      }
    } else {
      console.log('\nSystemd not available. To run manually:');
      console.log(`  node ${path.join(path.dirname(__filename), 'index.js')}`);
    }
  }

  console.log('\n✓ Setup complete!\n');
  console.log('To start the agent:');
  console.log(`  node ${path.join(path.dirname(__filename), 'index.js')}`);
  console.log('\nTo run in verbose mode:');
  console.log(`  node ${path.join(path.dirname(__filename), 'index.js')} --verbose`);

  rl.close();
}

main().catch(e => {
  console.error('Setup failed:', e);
  rl.close();
  process.exit(1);
});
