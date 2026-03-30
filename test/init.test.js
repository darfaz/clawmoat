/**
 * Tests for clawmoat init command
 */


const { describe, it, beforeEach, afterEach } = require('node:test');
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
    ok(content.includes('mode: enforce') || content.includes('mode: standard') || content.includes('mode:'), 'Should contain mode setting');
    ok(content.includes('detection:') || content.includes('stages:') || content.includes('scanners:'), 'Should contain scanner config section');
    ok(content.includes('policies:') || content.includes('tools:') || content.includes('scanners:'), 'Should contain policy config section');
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
    ok(content.includes('scanners:') || content.includes('stages:') || content.includes('detection:'), 'Should have scanner config section');
    ok(content.includes('prompt-injection:') || content.includes('prompt_injection:'), 'Should have prompt injection setting');
    ok(content.includes('tools:') || content.includes('policies:') || content.includes('scanners:'), 'Should have policy/tools section');
    ok(content.includes('exec') , 'Should reference exec tool');
    ok(content.includes('alerts:'), 'Should have alerts section');
    
    // Check comments are present
    ok(content.includes('# ClawMoat Configuration'), 'Should have header comment');
  });
});