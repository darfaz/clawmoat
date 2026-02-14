/**
 * ClawMoat Configuration Loader
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_CONFIG = {
  version: 1,
  detection: {
    prompt_injection: true,
    jailbreak: true,
    pii_outbound: true,
    secret_scanning: true,
  },
  policies: {
    exec: {
      block_patterns: [
        'rm -rf /',
        'rm -rf ~',
        'rm -rf *',
        'mkfs',
        'dd if=',
        ':(){:|:&};:',              // fork bomb
        'curl *| bash',
        'curl *| sh',
        'curl * | bash',
        'curl * | sh',
        'wget *| bash',
        'wget *| sh',
        'wget * | bash',
        'wget * | sh',
        'python -c * import socket',
        'nc -e',
        'ncat -e',
        'base64 -d | bash',
        'eval $(curl',
        'eval $(wget',
      ],
      require_approval: [],
      log_all: true,
    },
    file: {
      deny_read: [
        '~/.ssh/id_*',
        '~/.ssh/config',
        '~/.aws/credentials',
        '~/.aws/config',
        '**/.env',
        '**/credentials.json',
        '**/auth-profiles.json',
        '~/.gnupg/*',
        '~/.config/gh/hosts.yml',
      ],
      deny_write: [
        '/etc/*',
        '~/.bashrc',
        '~/.bash_profile',
        '~/.zshrc',
        '~/.profile',
        '~/.ssh/authorized_keys',
      ],
    },
    browser: {
      block_domains: [],
      log_all: true,
    },
  },
  alerts: {
    webhook: null,
    email: null,
    telegram: null,
    severity_threshold: 'medium',
  },
  cloud: {
    enabled: false,
    api_key: null,
  },
};

function loadConfig(configPath) {
  if (!configPath) {
    // Search for config in common locations
    const searchPaths = [
      path.join(process.cwd(), 'clawmoat.yml'),
      path.join(process.cwd(), 'clawmoat.yaml'),
      path.join(process.cwd(), '.clawmoat.yml'),
      path.join(process.env.HOME || '', '.clawmoat.yml'),
    ];
    for (const p of searchPaths) {
      if (fs.existsSync(p)) {
        configPath = p;
        break;
      }
    }
  }

  if (!configPath || !fs.existsSync(configPath)) {
    return { ...DEFAULT_CONFIG };
  }

  try {
    // Simple YAML-like parsing for basic configs (avoid dependency)
    const raw = fs.readFileSync(configPath, 'utf8');
    const yaml = parseSimpleYaml(raw);
    return deepMerge(DEFAULT_CONFIG, yaml);
  } catch (err) {
    console.error(`[ClawMoat] Failed to load config from ${configPath}: ${err.message}`);
    return { ...DEFAULT_CONFIG };
  }
}

// Very basic YAML parser for flat/nested configs (avoids js-yaml dependency for now)
function parseSimpleYaml(text) {
  try {
    // Try JSON first (YAML is a superset of JSON)
    return JSON.parse(text);
  } catch {
    // TODO: Add proper YAML parsing or make js-yaml a dependency
    console.warn('[ClawMoat] Complex YAML config detected. Install js-yaml for full support. Using defaults.');
    return {};
  }
}

function deepMerge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      result[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

module.exports = { loadConfig, DEFAULT_CONFIG };
