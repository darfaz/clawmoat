#!/usr/bin/env node
/**
 * ClawMoat Evaluation Runner
 * 
 * Runs all attack cases against ClawMoat scanners and reports results.
 * 
 * Usage: node evals/run.js [--json] [--category prompt_injection]
 */

'use strict';

const path = require('path');
const fs = require('fs');

// Load ClawMoat
const ClawMoat = require('../src/index');
const { scanObfuscation } = require('../src/obfuscation-scanner');
const { scanCode } = require('../src/code-scanner');
const { scanLanguage } = require('../src/language-detector');

const moat = new ClawMoat();

// Load cases
const cases = JSON.parse(fs.readFileSync(path.join(__dirname, 'cases.json'), 'utf8')).cases;

// Parse args
const args = process.argv.slice(2);
const jsonOut = args.includes('--json');
const filterCategory = args.find(a => !a.startsWith('--'));

// Run evaluation
function evaluate(testCase) {
  const { input, expect: expected, stage, tool } = testCase;
  const results = { findings: [], scanners: [] };

  try {
    // Stage-appropriate scanning
    if (stage === 'pre-input' || stage === 'post-tool-result') {
      const inbound = moat.scanInbound(input);
      if (inbound.findings?.length) {
        results.findings.push(...inbound.findings);
        results.scanners.push('inbound');
      }

      const obf = scanObfuscation(input);
      if (obf.findings?.length) {
        results.findings.push(...obf.findings);
        results.scanners.push('obfuscation');
      }

      const lang = scanLanguage(input, { expectedLanguages: ['latin'] });
      if (lang.findings?.length) {
        results.findings.push(...lang.findings);
        results.scanners.push('language');
      }
    }

    if (stage === 'pre-tool-call') {
      const code = scanCode(input, { tool: tool || 'exec' });
      if (code.findings?.length) {
        results.findings.push(...code.findings);
        results.scanners.push('code');
      }

      // Also check inbound for injection in tool args
      const inbound = moat.scanInbound(input);
      if (inbound.findings?.length) {
        results.findings.push(...inbound.findings);
        results.scanners.push('inbound');
      }
    }

    if (stage === 'pre-output') {
      const outbound = moat.scanOutbound(input);
      if (outbound.findings?.length) {
        results.findings.push(...outbound.findings);
        results.scanners.push('outbound');
      }
    }
  } catch (err) {
    results.error = err.message;
  }

  const detected = results.findings.length > 0;
  let outcome;

  if (expected === 'blocked') {
    outcome = detected ? 'blocked' : 'missed';
  } else if (expected === 'allowed') {
    outcome = detected ? 'false_positive' : 'allowed';
  }

  return {
    id: testCase.id,
    name: testCase.name,
    category: testCase.category,
    expected,
    outcome,
    correct: (expected === 'blocked' && outcome === 'blocked') || (expected === 'allowed' && outcome === 'allowed'),
    findingCount: results.findings.length,
    scanners: [...new Set(results.scanners)],
    topSeverity: results.findings.length > 0 
      ? results.findings.reduce((max, f) => {
          const rank = { critical: 4, high: 3, medium: 2, low: 1 };
          return (rank[f.severity] || 0) > (rank[max] || 0) ? f.severity : max;
        }, 'low')
      : null,
  };
}

// Filter cases
const filtered = filterCategory 
  ? cases.filter(c => c.category === filterCategory)
  : cases;

// Run all
const results = filtered.map(evaluate);

// Compute stats
const stats = {
  total: results.length,
  correct: results.filter(r => r.correct).length,
  blocked: results.filter(r => r.outcome === 'blocked').length,
  allowed: results.filter(r => r.outcome === 'allowed').length,
  missed: results.filter(r => r.outcome === 'missed').length,
  false_positive: results.filter(r => r.outcome === 'false_positive').length,
};
stats.accuracy = Math.round((stats.correct / stats.total) * 100);
stats.detection_rate = Math.round((stats.blocked / results.filter(r => r.expected === 'blocked').length) * 100);
stats.false_positive_rate = Math.round((stats.false_positive / Math.max(1, results.filter(r => r.expected === 'allowed').length)) * 100);

// Per-category stats
const categories = {};
for (const r of results) {
  if (!categories[r.category]) {
    categories[r.category] = { total: 0, correct: 0, cases: [] };
  }
  categories[r.category].total++;
  if (r.correct) categories[r.category].correct++;
  categories[r.category].cases.push(r);
}

if (jsonOut) {
  console.log(JSON.stringify({ stats, categories, results }, null, 2));
  process.exit(stats.missed > 0 || stats.false_positive > 0 ? 1 : 0);
}

// Pretty output
console.log('\n🏰 ClawMoat Evaluation Results\n');
console.log('═══════════════════════════════════════════════════════════');

for (const [cat, data] of Object.entries(categories)) {
  const pct = Math.round((data.correct / data.total) * 100);
  const icon = pct === 100 ? '✅' : pct >= 80 ? '⚠️' : '❌';
  console.log(`\n${icon} ${cat.replace(/_/g, ' ').toUpperCase()} (${data.correct}/${data.total} = ${pct}%)`);
  console.log('───────────────────────────────────────────────────────────');
  
  for (const c of data.cases) {
    const mark = c.correct ? '  ✓' : '  ✗';
    const color = c.correct ? '\x1b[32m' : '\x1b[31m';
    const reset = '\x1b[0m';
    const detail = c.correct 
      ? `${c.outcome}` 
      : `${c.outcome} (expected ${c.expected})`;
    console.log(`${color}${mark} ${c.name}: ${detail}${reset}`);
    if (!c.correct) {
      console.log(`     Scanners tried: ${c.scanners.join(', ') || 'none matched'}`);
    }
  }
}

console.log('\n═══════════════════════════════════════════════════════════');
console.log(`\n📊 OVERALL: ${stats.correct}/${stats.total} correct (${stats.accuracy}%)`);
console.log(`   🛡️  Detection rate: ${stats.detection_rate}% (${stats.blocked} attacks blocked)`);
console.log(`   ✅ Safe tasks: ${stats.allowed} allowed correctly`);
console.log(`   ❌ Missed attacks: ${stats.missed}`);
console.log(`   ⚠️  False positives: ${stats.false_positive} (${stats.false_positive_rate}% FP rate)\n`);

// Exit code: 0 = perfect, 1 = has issues
process.exit(stats.missed > 0 || stats.false_positive > 0 ? 1 : 0);
