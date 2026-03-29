/**
 * Tests for clawmoat init command
 */


const { strictEqual, ok } = require('node:assert');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

describe('clawmoat init', () => {
  let testDir;
  let configPath;
  let originalCwd;

  beforeEach(() => {
    originalCwd = process.cwd();
    testDir = fs.mkdtempSync('/tmp/clawmoat-test-');
    configPath = path.join(testDir, 'clawmoat.yml');
    process.chdir(testDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('creates clawmoat.yml config file', async () => {
    const { stdout, stderr } = await execAsync('node ' + path.join(originalCwd, 'bin/clawmoat.js') + ' init');
    
    ok(fs.existsSync(configPath), 'Config file should be created');
    ok(stdout.includes('✅ Created'), 'Should confirm file creation');
    
    const content = fs.readFileSync(configPath, 'utf8');
    ok(content.includes('# ClawMoat Configuration'), 'Should contain header comment');
    ok(content.includes('mode: standard'), 'Should contain default mode');
    ok(content.includes('detection:'), 'Should contain detection section');
    ok(content.includes('policies:'), 'Should contain policies section');
    ok(content.includes('alerts:'), 'Should contain alerts section');
  });

  it('warns if config file already exists', async () => {
    // Create file first
    fs.writeFileSync(configPath, 'existing config');
    
    try {
      await execAsync('node ' + path.join(originalCwd, 'bin/clawmoat.js') + ' init');
      ok(false, 'Should have thrown error');
    } catch (error) {
      ok(error.stdout.includes('already exists'), 'Should warn about existing file');
      strictEqual(error.code, 1, 'Should exit with code 1');
    }
    
    // File should be unchanged
    const content = fs.readFileSync(configPath, 'utf8');
    strictEqual(content, 'existing config', 'Original file should be unchanged');
  });

  it('overwrites with --force flag', async () => {
    // Create file first
    fs.writeFileSync(configPath, 'existing config');
    
    const { stdout } = await execAsync('node ' + path.join(originalCwd, 'bin/clawmoat.js') + ' init --force');
    
    ok(stdout.includes('✅ Created'), 'Should confirm file creation');
    
    const content = fs.readFileSync(configPath, 'utf8');
    ok(content.includes('# ClawMoat Configuration'), 'Should contain new config content');
    ok(!content.includes('existing config'), 'Should not contain old content');
  });

  it('overwrites with -f flag', async () => {
    // Create file first
    fs.writeFileSync(configPath, 'existing config');
    
    const { stdout } = await execAsync('node ' + path.join(originalCwd, 'bin/clawmoat.js') + ' init -f');
    
    ok(stdout.includes('✅ Created'), 'Should confirm file creation');
    
    const content = fs.readFileSync(configPath, 'utf8');
    ok(content.includes('# ClawMoat Configuration'), 'Should contain new config content');
  });

  it('generates valid YAML-like config', async () => {
    await execAsync('node ' + path.join(originalCwd, 'bin/clawmoat.js') + ' init');
    
    const content = fs.readFileSync(configPath, 'utf8');
    
    // Basic YAML structure checks
    ok(content.includes('mode:'), 'Should have mode field');
    ok(content.includes('detection:'), 'Should have detection section');
    ok(content.includes('  prompt_injection:'), 'Should have nested detection fields');
    ok(content.includes('policies:'), 'Should have policies section');
    ok(content.includes('  exec:'), 'Should have nested exec policies');
    ok(content.includes('    block_patterns:'), 'Should have deeply nested arrays');
    ok(content.includes('alerts:'), 'Should have alerts section');
    
    // Check specific default values
    ok(content.includes('mode: standard'), 'Should default to standard mode');
    ok(content.includes('prompt_injection: true'), 'Should enable prompt injection detection');
    ok(content.includes('severity_threshold: medium'), 'Should set medium severity threshold');
    
    // Check comments are present
    ok(content.includes('# ClawMoat Configuration'), 'Should have header comment');
    ok(content.includes('# Security mode:'), 'Should have mode comment');
    ok(content.includes('# Detection settings'), 'Should have section comments');
  });
});