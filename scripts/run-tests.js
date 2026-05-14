#!/usr/bin/env node
const { readdirSync, statSync } = require('fs');
const { join } = require('path');
const { spawnSync } = require('child_process');

function collectTestFiles(dir) {
  const entries = readdirSync(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectTestFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.test.js')) {
      files.push(fullPath);
    }
  }

  return files.sort();
}

const testDir = join(process.cwd(), 'test');
if (!statSync(testDir, { throwIfNoEntry: false })?.isDirectory()) {
  console.error('Could not find test directory:', testDir);
  process.exit(1);
}

const testFiles = collectTestFiles(testDir);
if (testFiles.length === 0) {
  console.error('No .test.js files found in:', testDir);
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...testFiles], {
  stdio: 'inherit',
  env: process.env,
});

if (result.error) {
  console.error(result.error);
  process.exit(1);
}

process.exit(result.status ?? 1);
