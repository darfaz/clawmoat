const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

function freshBilling() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clawmoat-billing-'));
  process.env.CLAWMOAT_DATA_DIR = dir;
  process.env.LICENSE_STORE_PATH = path.join(dir, 'licenses.json');
  process.env.EMAIL_OUTBOX_PATH = path.join(dir, 'email-outbox.jsonl');
  delete require.cache[require.resolve('../server/billing')];
  return { billing: require('../server/billing'), dir };
}

test('fulfills checkout sessions into a durable license store', () => {
  const { billing } = freshBilling();
  const result = billing.fulfillCheckoutSession({
    id: 'cs_test_123',
    customer: 'cus_123',
    subscription: 'sub_123',
    customer_details: { email: 'buyer@example.com' },
    metadata: { plan: 'team-monthly', utm_source: 'google' },
  });

  assert.equal(result.duplicate, false);
  assert.match(result.licenseKey, /^CM-/);
  assert.equal(result.license.email, 'buyer@example.com');
  assert.equal(result.license.plan, 'team-monthly');
  assert.equal(result.license.tier, 'team');
  assert.equal(result.license.seats, 10);

  const validation = billing.validateLicense(result.licenseKey);
  assert.equal(validation.valid, true);
  assert.equal(validation.tier, 'team');
});

test('checkout fulfillment is idempotent for webhook retries', () => {
  const { billing } = freshBilling();
  const session = {
    id: 'cs_retry_123',
    customer: 'cus_retry',
    subscription: 'sub_retry',
    customer_email: 'retry@example.com',
    metadata: { plan: 'pro-monthly' },
  };

  const first = billing.fulfillCheckoutSession(session);
  const second = billing.fulfillCheckoutSession(session);

  assert.equal(second.duplicate, true);
  assert.equal(second.licenseKey, first.licenseKey);
  assert.equal(Object.keys(billing.loadLicenseStore().licenses).length, 1);
});

test('subscription updates deactivate licenses', () => {
  const { billing } = freshBilling();
  const { licenseKey } = billing.fulfillCheckoutSession({
    id: 'cs_cancel_123',
    customer: 'cus_cancel',
    subscription: 'sub_cancel',
    customer_email: 'cancel@example.com',
    metadata: { plan: 'pro-yearly' },
  });

  billing.updateSubscriptionStatus({ id: 'sub_cancel', status: 'canceled' });
  assert.deepEqual(billing.validateLicense(licenseKey), { valid: false });
});

test('all self-serve paid plans have live Stripe price fallbacks', () => {
  const { billing } = freshBilling();
  assert.equal(billing.priceIdForPlan('pro-monthly'), 'price_1T5F23AUiOw2ZIor2oUgTD8W');
  assert.equal(billing.priceIdForPlan('pro-yearly'), 'price_1T5F23AUiOw2ZIorQLdy51G0');
  assert.equal(billing.priceIdForPlan('team-monthly'), 'price_1T5F2aAUiOw2ZIorodyK4wwQ');
  assert.equal(billing.priceIdForPlan('team-yearly'), 'price_1T5F2vAUiOw2ZIor5Jcga7kB');
  assert.deepEqual(
    billing.publicPlanList().map((plan) => ({ plan: plan.plan, configured: plan.configured, displayPrice: plan.displayPrice })),
    [
      { plan: 'pro-monthly', configured: true, displayPrice: '$14.99/mo' },
      { plan: 'pro-yearly', configured: true, displayPrice: '$149/yr' },
      { plan: 'team-monthly', configured: true, displayPrice: '$49/mo' },
      { plan: 'team-yearly', configured: true, displayPrice: '$499/yr' },
    ]
  );
});

test('environment price IDs override live fallbacks', () => {
  process.env.PRICE_PRO_MONTHLY = 'price_env_pro_monthly';
  const { billing } = freshBilling();
  assert.equal(billing.priceIdForPlan('pro-monthly'), 'price_env_pro_monthly');
  delete process.env.PRICE_PRO_MONTHLY;
});

test('welcome email queues locally when no provider is configured', async () => {
  const { billing, dir } = freshBilling();
  delete process.env.RESEND_API_KEY;
  const { licenseKey, license } = billing.fulfillCheckoutSession({
    id: 'cs_email_123',
    customer: 'cus_email',
    subscription: 'sub_email',
    customer_email: 'email@example.com',
    metadata: { plan: 'pro-monthly' },
  });

  const result = await billing.sendWelcomeEmail(licenseKey, license);
  assert.equal(result.queued, true);
  const outbox = fs.readFileSync(path.join(dir, 'email-outbox.jsonl'), 'utf8');
  assert.match(outbox, /email@example.com/);
  assert.match(outbox, new RegExp(licenseKey));
});
