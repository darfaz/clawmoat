#!/usr/bin/env node
/**
 * ClawMoat Provider Setup
 * 
 * Interactive setup for AI provider connections.
 * Supports Claude (Anthropic), ChatGPT/Codex (OpenAI), and Kimi (Moonshot).
 * 
 * Usage:
 *   node agent/provider-setup.js              Interactive setup
 *   node agent/provider-setup.js --list       Show configured providers
 *   node agent/provider-setup.js --test       Test all connections
 *   node agent/provider-setup.js --openclaw   Generate OpenClaw config snippet
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const readline = require('readline');

const CONFIG_DIR = path.join(os.homedir(), '.clawmoat');
const PROVIDERS_PATH = path.join(CONFIG_DIR, 'providers.json');

// ─── Colors ───────────────────────────────────────────────────────────────────

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';

// ─── Providers ────────────────────────────────────────────────────────────────

const PROVIDERS = {
  anthropic: {
    name: 'Claude (Anthropic)',
    emoji: '🟣',
    description: 'Claude Max subscription or API key',
    models: ['claude-opus-4-6', 'claude-sonnet-4-6'],
    methods: ['api-key', 'setup-token'],
  },
  'openai-codex': {
    name: 'ChatGPT / Codex (OpenAI)',
    emoji: '🟢',
    description: 'GPT Max subscription (OAuth) or API key',
    models: ['gpt-5.4', 'gpt-5.4-pro'],
    methods: ['oauth', 'api-key'],
  },
  'kimi-coding': {
    name: 'Kimi (Moonshot AI)',
    emoji: '🔵',
    description: 'Kimi annual subscription or API key',
    models: ['kimi-k2.5', 'kimi-k2-thinking'],
    methods: ['kimi-code-key', 'moonshot-api-key'],
  },
};

// ─── Kimi Header Generation ──────────────────────────────────────────────────

function generateKimiHeaders(deviceName) {
  const hostname = deviceName || os.hostname();
  const deviceId = crypto.randomBytes(16).toString('hex');
  const platform = `${os.type()} ${os.release()} ${os.arch()}`;
  const kimiVersion = '1.22.0';

  return {
    'User-Agent': `KimiCLI/${kimiVersion}`,
    'X-Msh-Platform': 'kimi_cli',
    'X-Msh-Version': kimiVersion,
    'X-Msh-Device-Name': hostname,
    'X-Msh-Device-Model': platform,
    'X-Msh-Device-Id': deviceId,
  };
}

// ─── HTTP Helper ──────────────────────────────────────────────────────────────

function httpRequest(url, options = {}) {
  return new Promise((resolve) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const body = options.body ? JSON.stringify(options.body) : null;

    const req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: options.method || 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
        ...(options.headers || {}),
      },
      timeout: 15000,
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data, raw: true });
        }
      });
    });

    req.on('error', e => resolve({ status: 0, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, error: 'Timeout' }); });
    if (body) req.write(body);
    req.end();
  });
}

// ─── Provider Testers ─────────────────────────────────────────────────────────

async function testAnthropic(config) {
  if (config.method === 'setup-token') {
    return { ok: true, note: 'Setup token configured. Run "openclaw models auth paste-token" to activate.' };
  }
  const res = await httpRequest('https://api.anthropic.com/v1/messages', {
    headers: {
      'x-api-key': config.apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: {
      model: 'claude-sonnet-4-6',
      max_tokens: 10,
      messages: [{ role: 'user', content: 'Hi' }],
    },
  });
  if (res.status === 200) return { ok: true };
  if (res.status === 401) return { ok: false, error: 'Invalid API key' };
  if (res.status === 429) return { ok: true, note: 'Rate limited but key is valid' };
  return { ok: false, error: `HTTP ${res.status}: ${JSON.stringify(res.data).slice(0, 100)}` };
}

async function testOpenAICodex(config) {
  if (config.method === 'oauth') {
    return { ok: true, note: 'OAuth configured. Run "openclaw models auth login --provider openai-codex" to authenticate.' };
  }
  const res = await httpRequest('https://api.openai.com/v1/chat/completions', {
    headers: { 'Authorization': `Bearer ${config.apiKey}` },
    body: {
      model: 'gpt-4o-mini',
      max_tokens: 10,
      messages: [{ role: 'user', content: 'Hi' }],
    },
  });
  if (res.status === 200) return { ok: true };
  if (res.status === 401) return { ok: false, error: 'Invalid API key' };
  if (res.status === 429) return { ok: true, note: 'Rate limited but key is valid' };
  return { ok: false, error: `HTTP ${res.status}: ${JSON.stringify(res.data).slice(0, 100)}` };
}

async function testKimiCoding(config) {
  const headers = {
    'Authorization': `Bearer ${config.apiKey}`,
    ...config.headers,
  };
  const res = await httpRequest('https://api.kimi.com/coding/v1/chat/completions', {
    headers,
    body: {
      model: 'kimi-k2.5',
      max_tokens: 10,
      messages: [{ role: 'user', content: 'Hi' }],
    },
  });
  if (res.status === 200) return { ok: true };
  if (res.data && res.data.error) {
    const msg = res.data.error.message || '';
    if (msg.includes('only available for Coding Agents')) {
      return { ok: false, error: 'Missing Kimi CLI headers. This is a bug — please report it.' };
    }
    if (msg.includes('insufficient balance')) {
      return { ok: false, error: 'Insufficient balance on Kimi account' };
    }
    if (msg.includes('Invalid Authentication')) {
      return { ok: false, error: 'Invalid API key' };
    }
    return { ok: false, error: msg.slice(0, 100) };
  }
  if (res.status === 429) return { ok: true, note: 'Rate limited but key is valid' };
  return { ok: false, error: `HTTP ${res.status}` };
}

async function testMoonshotAPI(config) {
  const res = await httpRequest('https://api.moonshot.ai/v1/chat/completions', {
    headers: { 'Authorization': `Bearer ${config.apiKey}` },
    body: {
      model: 'kimi-k2.5',
      max_tokens: 10,
      messages: [{ role: 'user', content: 'Hi' }],
    },
  });
  if (res.status === 200) return { ok: true };
  if (res.data && res.data.error) {
    const msg = res.data.error.message || '';
    if (msg.includes('insufficient balance')) return { ok: false, error: 'Zero balance. Top up at platform.moonshot.ai' };
    if (msg.includes('Invalid Authentication')) return { ok: false, error: 'Invalid API key' };
    return { ok: false, error: msg.slice(0, 100) };
  }
  return { ok: false, error: `HTTP ${res.status}` };
}

const TESTERS = {
  anthropic: testAnthropic,
  'openai-codex': testOpenAICodex,
  'kimi-coding': testKimiCoding,
  'moonshot': testMoonshotAPI,
};

// ─── Config I/O ───────────────────────────────────────────────────────────────

function loadProviders() {
  try {
    return JSON.parse(fs.readFileSync(PROVIDERS_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function saveProviders(providers) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(PROVIDERS_PATH, JSON.stringify(providers, null, 2));
  try { fs.chmodSync(PROVIDERS_PATH, 0o600); } catch {}
}

// ─── OpenClaw Config Generator ────────────────────────────────────────────────

function generateOpenClawConfig(providers) {
  const config = {
    env: {},
    agents: { defaults: { models: {} } },
    models: { mode: 'merge', providers: {} },
  };

  if (providers.anthropic) {
    if (providers.anthropic.method === 'api-key') {
      config.env.ANTHROPIC_API_KEY = providers.anthropic.apiKey;
    }
  }

  if (providers['openai-codex']) {
    const p = providers['openai-codex'];
    if (p.method === 'api-key') {
      config.env.OPENAI_API_KEY = p.apiKey;
    }
    // OAuth needs: openclaw models auth login --provider openai-codex
  }

  if (providers['kimi-coding']) {
    const p = providers['kimi-coding'];
    if (p.method === 'kimi-code-key') {
      config.env.KIMI_API_KEY = p.apiKey;
      config.models.providers['kimi-coding'] = {
        baseUrl: 'https://api.kimi.com/coding/v1',
        apiKey: '${KIMI_API_KEY}',
        api: 'openai-completions',
        headers: p.headers,
        models: [
          { id: 'kimi-k2.5', name: 'Kimi K2.5', contextWindow: 262144, maxTokens: 8192 },
          { id: 'kimi-k2-thinking', name: 'Kimi K2 Thinking', contextWindow: 262144, maxTokens: 8192 },
        ],
      };
    } else if (p.method === 'moonshot-api-key') {
      config.env.MOONSHOT_API_KEY = p.apiKey;
      config.models.providers.moonshot = {
        baseUrl: 'https://api.moonshot.ai/v1',
        apiKey: '${MOONSHOT_API_KEY}',
        api: 'openai-completions',
        models: [
          { id: 'kimi-k2.5', name: 'Kimi K2.5', contextWindow: 262144, maxTokens: 8192 },
        ],
      };
    }
  }

  // Clean up empty sections
  if (!Object.keys(config.env).length) delete config.env;
  if (!Object.keys(config.models.providers).length) delete config.models;
  if (!Object.keys(config.agents.defaults.models).length) delete config.agents;

  return config;
}

// ─── Interactive Setup ────────────────────────────────────────────────────────

function createRL() {
  return readline.createInterface({ input: process.stdin, output: process.stdout });
}

function ask(rl, question, defaultVal) {
  return new Promise(resolve => {
    const suffix = defaultVal ? ` [${defaultVal}]` : '';
    rl.question(`${question}${suffix}: `, answer => {
      resolve(answer.trim() || defaultVal || '');
    });
  });
}

function askYN(rl, question, defaultYes = true) {
  const suffix = defaultYes ? '[Y/n]' : '[y/N]';
  return new Promise(resolve => {
    rl.question(`${question} ${suffix}: `, answer => {
      const a = answer.trim().toLowerCase();
      if (!a) resolve(defaultYes);
      else resolve(a === 'y' || a === 'yes');
    });
  });
}

function askChoice(rl, question, choices) {
  return new Promise(resolve => {
    console.log(`\n${question}`);
    choices.forEach((c, i) => console.log(`  ${CYAN}${i + 1}${RESET}) ${c.label}`));
    rl.question(`\nChoice [1-${choices.length}]: `, answer => {
      const idx = parseInt(answer.trim(), 10) - 1;
      if (idx >= 0 && idx < choices.length) resolve(choices[idx].value);
      else resolve(choices[0].value);
    });
  });
}

async function setupAnthropic(rl, existing) {
  console.log(`\n${BOLD}${MAGENTA}🟣 Claude (Anthropic)${RESET}`);
  console.log(`${DIM}Use your Claude Max subscription or an Anthropic API key.${RESET}\n`);

  const method = await askChoice(rl, 'How do you want to connect?', [
    { label: 'API key (from console.anthropic.com)', value: 'api-key' },
    { label: 'Claude Max (setup-token from Claude CLI)', value: 'setup-token' },
    { label: 'Skip — not using Claude', value: 'skip' },
  ]);

  if (method === 'skip') return null;

  if (method === 'api-key') {
    const apiKey = await ask(rl, 'Anthropic API key (sk-ant-...)');
    if (!apiKey) return null;

    process.stdout.write('Testing connection... ');
    const result = await testAnthropic({ method, apiKey });
    if (result.ok) {
      console.log(`${GREEN}✓ Connected${RESET}${result.note ? ` (${result.note})` : ''}`);
    } else {
      console.log(`${RED}✗ ${result.error}${RESET}`);
      const cont = await askYN(rl, 'Save anyway?', false);
      if (!cont) return null;
    }
    return { method, apiKey, model: 'claude-sonnet-4-6', configuredAt: new Date().toISOString() };
  }

  if (method === 'setup-token') {
    console.log(`\n${YELLOW}To get a setup token:${RESET}`);
    console.log(`  1. Install Claude CLI: ${CYAN}npm install -g @anthropic-ai/claude-code${RESET}`);
    console.log(`  2. Run: ${CYAN}claude setup-token${RESET}`);
    console.log(`  3. Paste the token below\n`);
    const token = await ask(rl, 'Setup token');
    if (!token) return null;
    return { method, setupToken: token, model: 'claude-sonnet-4-6', configuredAt: new Date().toISOString() };
  }
}

async function setupOpenAICodex(rl, existing) {
  console.log(`\n${BOLD}${GREEN}🟢 ChatGPT / Codex (OpenAI)${RESET}`);
  console.log(`${DIM}Use your GPT Max subscription (OAuth) or an OpenAI API key.${RESET}\n`);

  const method = await askChoice(rl, 'How do you want to connect?', [
    { label: 'GPT Max subscription (OAuth — recommended)', value: 'oauth' },
    { label: 'API key (from platform.openai.com)', value: 'api-key' },
    { label: 'Skip — not using ChatGPT', value: 'skip' },
  ]);

  if (method === 'skip') return null;

  if (method === 'oauth') {
    console.log(`\n${YELLOW}To complete OAuth setup:${RESET}`);
    console.log(`  1. Install Codex CLI: ${CYAN}npm install -g @openai/codex${RESET}`);
    console.log(`  2. Run: ${CYAN}openclaw models auth login --provider openai-codex${RESET}`);
    console.log(`  3. Approve in browser when prompted\n`);
    console.log(`${DIM}This uses your GPT Max subscription — no API charges.${RESET}`);
    return { method, model: 'gpt-5.4', configuredAt: new Date().toISOString() };
  }

  if (method === 'api-key') {
    const apiKey = await ask(rl, 'OpenAI API key (sk-...)');
    if (!apiKey) return null;

    process.stdout.write('Testing connection... ');
    const result = await testOpenAICodex({ method, apiKey });
    if (result.ok) {
      console.log(`${GREEN}✓ Connected${RESET}${result.note ? ` (${result.note})` : ''}`);
    } else {
      console.log(`${RED}✗ ${result.error}${RESET}`);
      const cont = await askYN(rl, 'Save anyway?', false);
      if (!cont) return null;
    }
    return { method, apiKey, model: 'gpt-5.4', configuredAt: new Date().toISOString() };
  }
}

async function setupKimiCoding(rl, existing) {
  console.log(`\n${BOLD}${CYAN}🔵 Kimi (Moonshot AI)${RESET}`);
  console.log(`${DIM}Use your Kimi annual subscription or a Moonshot API key.${RESET}\n`);

  const method = await askChoice(rl, 'How do you want to connect?', [
    { label: 'Kimi subscription key (sk-kimi-... from kimi.com/code/console)', value: 'kimi-code-key' },
    { label: 'Moonshot API key (sk-... from platform.moonshot.ai)', value: 'moonshot-api-key' },
    { label: 'Skip — not using Kimi', value: 'skip' },
  ]);

  if (method === 'skip') return null;

  if (method === 'kimi-code-key') {
    console.log(`\n${YELLOW}Get your Kimi Code key:${RESET}`);
    console.log(`  1. Go to ${CYAN}https://kimi.com/code/console${RESET}`);
    console.log(`  2. Click "Create new API Key"`);
    console.log(`  3. Copy the key (starts with sk-kimi-...)\n`);

    const apiKey = await ask(rl, 'Kimi Code API key (sk-kimi-...)');
    if (!apiKey) return null;

    const deviceName = os.hostname();
    const headers = generateKimiHeaders(deviceName);

    process.stdout.write('Testing connection... ');
    const result = await testKimiCoding({ method, apiKey, headers });
    if (result.ok) {
      console.log(`${GREEN}✓ Connected to Kimi K2.5${RESET}`);
    } else {
      console.log(`${RED}✗ ${result.error}${RESET}`);
      const cont = await askYN(rl, 'Save anyway?', false);
      if (!cont) return null;
    }
    return { method, apiKey, headers, model: 'kimi-k2.5', configuredAt: new Date().toISOString() };
  }

  if (method === 'moonshot-api-key') {
    console.log(`\n${YELLOW}Get your Moonshot API key:${RESET}`);
    console.log(`  1. Go to ${CYAN}https://platform.moonshot.ai${RESET}`);
    console.log(`  2. Create an API key (starts with sk-...)`);
    console.log(`  3. ${DIM}Note: this is pay-per-token, separate from Kimi subscription${RESET}\n`);

    const apiKey = await ask(rl, 'Moonshot API key (sk-...)');
    if (!apiKey) return null;

    process.stdout.write('Testing connection... ');
    const result = await testMoonshotAPI({ apiKey });
    if (result.ok) {
      console.log(`${GREEN}✓ Connected${RESET}`);
    } else {
      console.log(`${RED}✗ ${result.error}${RESET}`);
      const cont = await askYN(rl, 'Save anyway?', false);
      if (!cont) return null;
    }
    return { method, apiKey, model: 'kimi-k2.5', configuredAt: new Date().toISOString() };
  }
}

// ─── Commands ─────────────────────────────────────────────────────────────────

async function cmdSetup() {
  const rl = createRL();

  console.log(`\n${BOLD}╔════════════════════════════════════════╗${RESET}`);
  console.log(`${BOLD}║   ClawMoat — AI Provider Setup        ║${RESET}`);
  console.log(`${BOLD}╚════════════════════════════════════════╝${RESET}`);
  console.log(`\nConfigure your AI subscriptions for use with OpenClaw.`);
  console.log(`${DIM}Use your existing paid plans — no extra API costs.${RESET}\n`);

  const existing = loadProviders();

  // Show existing if any
  if (Object.keys(existing).length) {
    console.log(`${DIM}Currently configured:${RESET}`);
    for (const [id, p] of Object.entries(existing)) {
      const info = PROVIDERS[id] || {};
      console.log(`  ${info.emoji || '•'} ${info.name || id} (${p.method}, ${p.model || '?'})`);
    }
    console.log('');
  }

  const providers = { ...existing };

  // Claude
  const wantClaude = await askYN(rl, `Configure ${PROVIDERS.anthropic.emoji} Claude (Anthropic)?`, !existing.anthropic);
  if (wantClaude) {
    const result = await setupAnthropic(rl, existing.anthropic);
    if (result) providers.anthropic = result;
  }

  // OpenAI
  const wantOpenAI = await askYN(rl, `\nConfigure ${PROVIDERS['openai-codex'].emoji} ChatGPT / Codex (OpenAI)?`, !existing['openai-codex']);
  if (wantOpenAI) {
    const result = await setupOpenAICodex(rl, existing['openai-codex']);
    if (result) providers['openai-codex'] = result;
  }

  // Kimi
  const wantKimi = await askYN(rl, `\nConfigure ${PROVIDERS['kimi-coding'].emoji} Kimi (Moonshot AI)?`, !existing['kimi-coding']);
  if (wantKimi) {
    const result = await setupKimiCoding(rl, existing['kimi-coding']);
    if (result) providers['kimi-coding'] = result;
  }

  // Save
  const configured = Object.keys(providers).filter(k => providers[k]);
  if (configured.length) {
    saveProviders(providers);
    console.log(`\n${GREEN}✓ ${configured.length} provider(s) saved to ${PROVIDERS_PATH}${RESET}`);

    // Offer OpenClaw config
    const wantSnippet = await askYN(rl, '\nGenerate OpenClaw config snippet?', true);
    if (wantSnippet) {
      const snippet = generateOpenClawConfig(providers);
      console.log(`\n${BOLD}Add this to your ~/.openclaw/openclaw.json:${RESET}\n`);
      console.log(JSON.stringify(snippet, null, 2));

      const wantSave = await askYN(rl, '\nSave snippet to ~/.clawmoat/openclaw-snippet.json?', true);
      if (wantSave) {
        fs.writeFileSync(path.join(CONFIG_DIR, 'openclaw-snippet.json'), JSON.stringify(snippet, null, 2));
        console.log(`${GREEN}✓ Saved${RESET}`);
      }
    }

    // Next steps
    console.log(`\n${BOLD}Next steps:${RESET}`);
    if (providers['openai-codex'] && providers['openai-codex'].method === 'oauth') {
      console.log(`  ${CYAN}openclaw models auth login --provider openai-codex${RESET}  (one-time browser auth)`);
    }
    if (providers.anthropic && providers.anthropic.method === 'setup-token') {
      console.log(`  ${CYAN}openclaw models auth paste-token --provider anthropic${RESET}`);
    }
    console.log(`  ${CYAN}openclaw gateway restart${RESET}  (apply changes)`);
  } else {
    console.log(`\n${YELLOW}No providers configured.${RESET}`);
  }

  rl.close();
}

async function cmdList() {
  const providers = loadProviders();
  if (!Object.keys(providers).length) {
    console.log(`${YELLOW}No providers configured.${RESET} Run: ${CYAN}clawmoat providers setup${RESET}`);
    return;
  }

  console.log(`\n${BOLD}Configured AI Providers${RESET}\n`);
  for (const [id, p] of Object.entries(providers)) {
    const info = PROVIDERS[id] || {};
    const keyHint = p.apiKey ? `${p.apiKey.slice(0, 12)}...${p.apiKey.slice(-4)}` : '(OAuth/token)';
    console.log(`${info.emoji || '•'} ${BOLD}${info.name || id}${RESET}`);
    console.log(`  Method: ${p.method}`);
    console.log(`  Model:  ${p.model || '?'}`);
    console.log(`  Auth:   ${keyHint}`);
    console.log(`  Added:  ${p.configuredAt || '?'}`);
    console.log('');
  }
}

async function cmdTest() {
  const providers = loadProviders();
  if (!Object.keys(providers).length) {
    console.log(`${YELLOW}No providers configured.${RESET} Run: ${CYAN}clawmoat providers setup${RESET}`);
    return;
  }

  console.log(`\n${BOLD}Testing AI Provider Connections${RESET}\n`);
  let allOk = true;

  for (const [id, p] of Object.entries(providers)) {
    const info = PROVIDERS[id] || {};
    process.stdout.write(`${info.emoji || '•'} ${info.name || id}... `);

    let tester;
    if (id === 'kimi-coding' && p.method === 'moonshot-api-key') {
      tester = TESTERS.moonshot;
    } else {
      tester = TESTERS[id];
    }

    if (!tester) {
      console.log(`${YELLOW}? No tester${RESET}`);
      continue;
    }

    const result = await tester(p);
    if (result.ok) {
      console.log(`${GREEN}✓ OK${RESET}${result.note ? ` ${DIM}(${result.note})${RESET}` : ''}`);
    } else {
      console.log(`${RED}✗ ${result.error}${RESET}`);
      allOk = false;
    }
  }

  console.log(allOk ? `\n${GREEN}All providers connected.${RESET}` : `\n${YELLOW}Some providers need attention.${RESET}`);
}

function cmdOpenClaw() {
  const providers = loadProviders();
  if (!Object.keys(providers).length) {
    console.log(`${YELLOW}No providers configured.${RESET} Run: ${CYAN}clawmoat providers setup${RESET}`);
    return;
  }
  const snippet = generateOpenClawConfig(providers);
  console.log(JSON.stringify(snippet, null, 2));
}

// ─── Main (only when run directly) ────────────────────────────────────────────

if (require.main === module) {
  const args = process.argv.slice(2);
  const command = args[0] || 'setup';

  switch (command) {
    case 'setup':
    case '--setup':
      cmdSetup().catch(e => { console.error(e); process.exit(1); });
      break;
    case 'list':
    case '--list':
      cmdList();
      break;
    case 'test':
    case '--test':
      cmdTest().catch(e => { console.error(e); process.exit(1); });
      break;
    case 'openclaw':
    case '--openclaw':
      cmdOpenClaw();
      break;
    default:
      console.log(`Usage: clawmoat providers [setup|list|test|openclaw]`);
      console.log(`  setup    Interactive provider configuration`);
      console.log(`  list     Show configured providers`);
      console.log(`  test     Test all provider connections`);
      console.log(`  openclaw Generate OpenClaw config snippet`);
  }
}

// Export for use by setup.js
module.exports = { cmdSetup, cmdList, cmdTest, cmdOpenClaw, generateKimiHeaders, loadProviders, PROVIDERS };
