const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = process.env.CLAWMOAT_DATA_DIR || path.join(__dirname, 'data');
const LICENSE_STORE_PATH = process.env.LICENSE_STORE_PATH || path.join(DATA_DIR, 'licenses.json');
const EMAIL_OUTBOX_PATH = process.env.EMAIL_OUTBOX_PATH || path.join(DATA_DIR, 'email-outbox.jsonl');
const SITE_URL = process.env.SITE_URL || 'https://clawmoat.com';
const APP_URL = process.env.APP_URL || SITE_URL;

const PLAN_CATALOG = {
  'pro-monthly': {
    plan: 'pro-monthly',
    tier: 'pro',
    label: 'ClawMoat Pro',
    billing: 'monthly',
    seats: 1,
    displayPrice: '$14.99/mo',
    env: 'PRICE_PRO_MONTHLY',
    liveFallback: 'price_1T5F23AUiOw2ZIor2oUgTD8W',
  },
  'pro-yearly': {
    plan: 'pro-yearly',
    tier: 'pro',
    label: 'ClawMoat Pro',
    billing: 'yearly',
    seats: 1,
    displayPrice: '$149/yr',
    env: 'PRICE_PRO_YEARLY',
    liveFallback: 'price_1T5F23AUiOw2ZIorQLdy51G0',
  },
  'team-monthly': {
    plan: 'team-monthly',
    tier: 'team',
    label: 'ClawMoat Team',
    billing: 'monthly',
    seats: 10,
    displayPrice: '$49/mo',
    env: 'PRICE_TEAM_MONTHLY',
    liveFallback: 'price_1T5F2aAUiOw2ZIorodyK4wwQ',
  },
  'team-yearly': {
    plan: 'team-yearly',
    tier: 'team',
    label: 'ClawMoat Team',
    billing: 'yearly',
    seats: 10,
    displayPrice: '$499/yr',
    env: 'PRICE_TEAM_YEARLY',
    liveFallback: 'price_1T5F2vAUiOw2ZIor5Jcga7kB',
  },
  'security-kit': {
    plan: 'security-kit',
    tier: 'kit',
    label: 'ClawMoat Security Kit',
    billing: 'one-time',
    seats: 1,
    displayPrice: '$29',
    env: 'PRICE_SECURITY_KIT',
    legacyFallback: 'price_1T5F3LAUiOw2ZIorTAPB0Q76',
    allowLegacyFallback: true,
    oneTime: true,
  },
};

const PLAN_ALIASES = {
  'shield-monthly': 'pro-monthly',
  'shield-yearly': 'pro-yearly',
  'dev-monthly': 'pro-monthly',
  'dev-yearly': 'pro-yearly',
};

function canonicalPlan(plan) {
  return PLAN_ALIASES[plan] || plan;
}

function planConfig(plan) {
  return PLAN_CATALOG[canonicalPlan(plan)] || null;
}

function priceIdForPlan(plan) {
  const config = planConfig(plan);
  if (!config) return null;
  const stripeStyleEnv = config.env ? `STRIPE_${config.env}` : null;
  const legacyStripeStyleEnv = config.legacyEnv ? `STRIPE_${config.legacyEnv}` : null;
  return process.env[config.env]
    || (stripeStyleEnv ? process.env[stripeStyleEnv] : undefined)
    || (config.legacyEnv ? process.env[config.legacyEnv] : undefined)
    || (legacyStripeStyleEnv ? process.env[legacyStripeStyleEnv] : undefined)
    || (config.allowLegacyFallback ? config.legacyFallback : undefined)
    || config.liveFallback
    || null;
}

function publicPlanList() {
  return Object.values(PLAN_CATALOG)
    .filter((plan) => plan.tier === 'pro' || plan.tier === 'team')
    .map((plan) => ({
      plan: plan.plan,
      tier: plan.tier,
      label: plan.label,
      billing: plan.billing,
      seats: plan.seats,
      displayPrice: plan.displayPrice,
      configured: Boolean(priceIdForPlan(plan.plan)),
    }));
}

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function emptyStore() {
  return { version: 1, licenses: {}, sessions: {}, subscriptions: {}, customers: {}, updatedAt: null };
}

function loadLicenseStore() {
  try {
    const parsed = JSON.parse(fs.readFileSync(LICENSE_STORE_PATH, 'utf8'));
    return { ...emptyStore(), ...parsed };
  } catch {
    return emptyStore();
  }
}

function saveLicenseStore(store) {
  ensureDataDir();
  const next = { ...store, updatedAt: new Date().toISOString() };
  const tempPath = `${LICENSE_STORE_PATH}.${process.pid}.tmp`;
  fs.writeFileSync(tempPath, JSON.stringify(next, null, 2));
  fs.renameSync(tempPath, LICENSE_STORE_PATH);
  return next;
}

function generateLicenseKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const segments = [];
  for (let s = 0; s < 4; s++) {
    let seg = '';
    for (let i = 0; i < 5; i++) seg += chars[Math.floor(Math.random() * chars.length)];
    segments.push(seg);
  }
  return `CM-${segments.join('-')}`;
}

function uniqueLicenseKey(store) {
  for (let i = 0; i < 20; i++) {
    const key = generateLicenseKey();
    if (!store.licenses[key]) return key;
  }
  return `CM-${crypto.randomBytes(15).toString('hex').toUpperCase().match(/.{1,5}/g).join('-')}`;
}

function inferEmailFromSession(session) {
  return session.customer_email || session.customer_details?.email || session.metadata?.email || null;
}

function fulfillCheckoutSession(session) {
  const store = loadLicenseStore();
  if (store.sessions[session.id]) {
    const existingKey = store.sessions[session.id];
    return { licenseKey: existingKey, license: store.licenses[existingKey], duplicate: true };
  }

  const licenseKey = uniqueLicenseKey(store);
  const requestedPlan = canonicalPlan(session.metadata?.plan || 'pro-monthly');
  const config = planConfig(requestedPlan) || PLAN_CATALOG['pro-monthly'];
  const email = inferEmailFromSession(session);
  const now = new Date().toISOString();
  const subscriptionId = session.subscription || null;
  const customerId = session.customer || null;

  const license = {
    key: licenseKey,
    email,
    customerId,
    subscriptionId,
    checkoutSessionId: session.id,
    plan: config.plan,
    tier: config.tier,
    seats: config.seats,
    status: 'active',
    active: true,
    createdAt: now,
    updatedAt: now,
    attribution: {
      utm_source: session.metadata?.utm_source || '',
      utm_medium: session.metadata?.utm_medium || '',
      utm_campaign: session.metadata?.utm_campaign || '',
      utm_content: session.metadata?.utm_content || '',
      utm_term: session.metadata?.utm_term || '',
      landing_page: session.metadata?.landing_page || '',
    },
  };

  store.licenses[licenseKey] = license;
  store.sessions[session.id] = licenseKey;
  if (subscriptionId) store.subscriptions[subscriptionId] = licenseKey;
  if (customerId) store.customers[customerId] = licenseKey;
  saveLicenseStore(store);
  return { licenseKey, license, duplicate: false };
}

function updateSubscriptionStatus(subscription) {
  const store = loadLicenseStore();
  const licenseKey = store.subscriptions[subscription.id];
  if (!licenseKey || !store.licenses[licenseKey]) return null;
  const status = subscription.status || 'unknown';
  store.licenses[licenseKey] = {
    ...store.licenses[licenseKey],
    status,
    active: status === 'active' || status === 'trialing',
    updatedAt: new Date().toISOString(),
  };
  saveLicenseStore(store);
  return store.licenses[licenseKey];
}

function validateLicense(key) {
  const store = loadLicenseStore();
  const license = store.licenses[key];
  if (!license || !license.active) return { valid: false };
  return {
    valid: true,
    plan: license.plan,
    tier: license.tier,
    seats: license.seats,
    email: license.email,
    status: license.status,
  };
}

function findLicenseByKeyOrEmail({ key, email }) {
  const store = loadLicenseStore();
  if (key && store.licenses[key]) return store.licenses[key];
  if (email) {
    return Object.values(store.licenses).find((license) => license.email === email && license.active) || null;
  }
  return null;
}

function welcomeEmail({ email, licenseKey, license }) {
  const installCommand = 'npm install -g clawmoat';
  const activateCommand = `clawmoat activate ${licenseKey}`;
  return {
    to: email,
    subject: `Your ${license?.tier === 'team' ? 'ClawMoat Team' : 'ClawMoat Pro'} license key`,
    text: [
      'Welcome to ClawMoat.',
      '',
      `Plan: ${license?.plan || 'pro'}`,
      `License key: ${licenseKey}`,
      '',
      'Install and activate:',
      installCommand,
      activateCommand,
      '',
      'Fast path:',
      '1. Run: clawmoat scan-mcp --json',
      '2. Add a clawmoat.yml policy file to your repo.',
      '3. For teams, commit the policy and run ClawMoat in CI.',
      '',
      'Docs: https://clawmoat.com/team-onboarding/',
      'Pricing/account help: https://clawmoat.com/pricing/',
      '',
      'No custom implementation is included by default. Email hello@clawmoat.com if checkout or activation breaks.',
    ].join('\n'),
    html: `
      <p>Welcome to ClawMoat.</p>
      <p><strong>Plan:</strong> ${license?.plan || 'pro'}<br>
      <strong>License key:</strong> <code>${licenseKey}</code></p>
      <p>Install and activate:</p>
      <pre>${installCommand}\n${activateCommand}</pre>
      <p>Fast path:</p>
      <ol>
        <li>Run <code>clawmoat scan-mcp --json</code></li>
        <li>Add a <code>clawmoat.yml</code> policy file to your repo.</li>
        <li>For teams, commit the policy and run ClawMoat in CI.</li>
      </ol>
      <p><a href="https://clawmoat.com/team-onboarding/">Team onboarding docs</a></p>
      <p>No custom implementation is included by default. Email hello@clawmoat.com if checkout or activation breaks.</p>
    `,
  };
}

async function sendEmail(message) {
  if (!message.to) return { sent: false, skipped: true, reason: 'missing_email' };

  if (process.env.RESEND_API_KEY) {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: process.env.EMAIL_FROM || 'ClawMoat <hello@clawmoat.com>',
        to: message.to,
        subject: message.subject,
        text: message.text,
        html: message.html,
      }),
    });
    const body = await response.text();
    if (!response.ok) throw new Error(`Resend failed: ${response.status} ${body}`);
    return { sent: true, provider: 'resend', response: body };
  }

  ensureDataDir();
  fs.appendFileSync(EMAIL_OUTBOX_PATH, `${JSON.stringify({ ...message, queuedAt: new Date().toISOString() })}\n`);
  return { sent: false, queued: true, provider: 'local-outbox', outboxPath: EMAIL_OUTBOX_PATH };
}

async function sendWelcomeEmail(licenseKey, license) {
  return sendEmail(welcomeEmail({ email: license.email, licenseKey, license }));
}

module.exports = {
  PLAN_CATALOG,
  PLAN_ALIASES,
  canonicalPlan,
  planConfig,
  priceIdForPlan,
  publicPlanList,
  loadLicenseStore,
  saveLicenseStore,
  fulfillCheckoutSession,
  updateSubscriptionStatus,
  validateLicense,
  findLicenseByKeyOrEmail,
  sendWelcomeEmail,
  welcomeEmail,
};
