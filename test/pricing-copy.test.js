const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const purchasePages = [
  'docs/index.html',
  'docs/agent-seatbelt/index.html',
  'docs/pricing.html',
  'docs/pricing/index.html',
  'docs/team-onboarding/index.html',
];

test('customer-facing purchase pages match live Stripe prices', () => {
  const forbidden = [
    '$19<span>/mo</span>',
    '$190/year',
    '$99<span>/mo</span>',
    '$990/year',
    'Start Pro trial',
    'Start Team trial',
    '30-day trial',
  ];

  for (const relativePath of purchasePages) {
    const html = fs.readFileSync(path.join(root, relativePath), 'utf8');
    for (const phrase of forbidden) {
      assert.equal(html.includes(phrase), false, `${relativePath} still contains ${phrase}`);
    }
  }

  const pricing = fs.readFileSync(path.join(root, 'docs/pricing/index.html'), 'utf8');
  assert.match(pricing, /\$14\.99<span>\/mo<\/span>/);
  assert.match(pricing, /\$149\/year/);
  assert.match(pricing, /\$49<span>\/mo<\/span>/);
  assert.match(pricing, /\$499\/year/);
});

test('checkout does not add a trial that is absent from Stripe prices', () => {
  const server = fs.readFileSync(path.join(root, 'server/index.js'), 'utf8');
  assert.equal(server.includes('trial_period_days'), false);
});
