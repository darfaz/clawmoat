const http = require('http');
const fs = require('fs');
const path = require('path');
const Stripe = require('stripe');
const {
  canonicalPlan,
  findLicenseByKeyOrEmail,
  fulfillCheckoutSession,
  planConfig,
  priceIdForPlan,
  publicPlanList,
  sendWelcomeEmail,
  updateSubscriptionStatus,
  validateLicense,
} = require('./billing');

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const PORT = process.env.PORT || 3000;
const SITE_URL = process.env.SITE_URL || 'https://clawmoat.com';
const APP_URL = process.env.APP_URL || SITE_URL;

// ─── Threat Intel helpers ─────────────────────────────────────────────────────

const THREATS_PATH = path.join(__dirname, 'data/threats.json');
const API_KEYS_PATH = path.join(__dirname, 'data/api-keys.json');

function loadThreats() {
  try { return JSON.parse(fs.readFileSync(THREATS_PATH, 'utf8')); }
  catch { return []; }
}

function loadApiKeys() {
  try { return JSON.parse(fs.readFileSync(API_KEYS_PATH, 'utf8')); }
  catch { return {}; }
}

function saveApiKeys(keys) {
  fs.writeFileSync(API_KEYS_PATH, JSON.stringify(keys, null, 2));
}

function checkApiKey(req) {
  const key = req.headers['x-api-key'];
  if (!key) return null;
  const keys = loadApiKeys();
  return keys[key] ? { key, ...keys[key] } : null;
}

function trackApiUsage(apiKey) {
  const keys = loadApiKeys();
  if (keys[apiKey]) {
    keys[apiKey].calls_this_month = (keys[apiKey].calls_this_month || 0) + 1;
    saveApiKeys(keys);
  }
}

function parseQuery(url) {
  const u = new URL(url, 'http://localhost');
  return Object.fromEntries(u.searchParams.entries());
}

function generateLicenseKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const segments = [];
  for (let s = 0; s < 4; s++) {
    let seg = '';
    for (let i = 0; i < 5; i++) seg += chars[Math.floor(Math.random() * chars.length)];
    segments.push(seg);
  }
  return 'CM-' + segments.join('-');
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key');
}

function json(res, status, data) {
  cors(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); }
      catch { resolve({}); }
    });
  });
}

const server = http.createServer(async (req, res) => {
  cors(res);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  // Health check
  if (req.url === '/health') {
    return json(res, 200, { status: 'ok', version: '0.1.0' });
  }

  if (req.method === 'GET' && req.url === '/api/plans') {
    return json(res, 200, { plans: publicPlanList() });
  }

  // Create checkout session
  if (req.method === 'POST' && req.url === '/api/checkout') {
    const body = await readBody(req);
    const plan = canonicalPlan(body.plan);
    const config = planConfig(plan);
    const priceId = priceIdForPlan(plan);

    if (!config) {
      return json(res, 400, { error: 'Invalid plan. Use: pro-monthly, pro-yearly, team-monthly, team-yearly' });
    }
    if (!priceId) {
      return json(res, 503, { error: `Stripe price is not configured for ${plan}` });
    }

    try {
      const isOneTime = Boolean(config.oneTime);
      const attribution = {
        plan,
        utm_source: body.campaign?.utm_source || '',
        utm_medium: body.campaign?.utm_medium || '',
        utm_campaign: body.campaign?.utm_campaign || '',
        utm_content: body.campaign?.utm_content || '',
        utm_term: body.campaign?.utm_term || '',
        landing_page: body.campaign?.landing_page || '',
      };
      const sessionParams = {
        mode: isOneTime ? 'payment' : 'subscription',
        line_items: [{ price: priceId, quantity: 1 }],
        success_url: `${SITE_URL}/thanks/?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${SITE_URL}/pricing/`,
        allow_promotion_codes: true,
        customer_email: body.email || undefined,
        client_reference_id: body.client_reference_id || undefined,
        metadata: attribution,
      };
      if (!isOneTime) {
        sessionParams.subscription_data = {
          trial_period_days: 30,
          metadata: attribution,
        };
      }
      const session = await stripe.checkout.sessions.create(sessionParams);
      return json(res, 200, { url: session.url });
    } catch (err) {
      return json(res, 500, { error: err.message });
    }
  }

  // Stripe webhook
  if (req.method === 'POST' && req.url === '/api/webhook') {
    const rawBody = await new Promise((resolve) => {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => resolve(body));
    });

    const sig = req.headers['stripe-signature'];
    const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

    let event;
    if (endpointSecret && sig) {
      try {
        event = stripe.webhooks.constructEvent(rawBody, sig, endpointSecret);
      } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return json(res, 400, { error: 'Invalid signature' });
      }
    } else {
      try { event = JSON.parse(rawBody); }
      catch { return json(res, 400, { error: 'Invalid JSON' }); }
    }

    console.log(`Webhook: ${event.type}`);

    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const { licenseKey, license, duplicate } = fulfillCheckoutSession(session);
        console.log(`Checkout fulfilled: ${license.email || 'no-email'}, plan=${license.plan}, license=${licenseKey}, duplicate=${duplicate}`);
        if (!duplicate) {
          try {
            const emailResult = await sendWelcomeEmail(licenseKey, license);
            console.log(`Welcome email result: ${JSON.stringify(emailResult)}`);
          } catch (err) {
            console.error('Welcome email failed:', err.message);
          }
        }
        break;
      }
      case 'customer.subscription.deleted':
      case 'customer.subscription.updated': {
        const sub = event.data.object;
        const license = updateSubscriptionStatus(sub);
        if (license) console.log(`License ${license.key}: active=${license.active} (status=${license.status})`);
        break;
      }
    }

    return json(res, 200, { received: true });
  }

  // Stripe customer portal. Requires a valid license key or purchaser email.
  if (req.method === 'POST' && req.url === '/api/portal') {
    const body = await readBody(req);
    const license = findLicenseByKeyOrEmail({ key: body.key, email: body.email });
    if (!license || !license.customerId) {
      return json(res, 404, { error: 'No active customer found for that license/email' });
    }

    try {
      const session = await stripe.billingPortal.sessions.create({
        customer: license.customerId,
        return_url: `${APP_URL}/pricing/`,
      });
      return json(res, 200, { url: session.url });
    } catch (err) {
      return json(res, 500, { error: err.message });
    }
  }

  // Live stats endpoint (cached 15 min)
  if (req.method === 'GET' && req.url === '/api/stats') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const CACHE_TTL = 15 * 60 * 1000; // 15 minutes
    const now = Date.now();
    
    if (global._statsCache && (now - global._statsCacheTime) < CACHE_TTL) {
      return json(res, 200, global._statsCache);
    }
    
    try {
      const https = require('https');
      const fetchJSON = (url) => new Promise((resolve, reject) => {
        https.get(url, { headers: { 'User-Agent': 'ClawMoat-Stats/1.0' } }, (r) => {
          let data = '';
          r.on('data', c => data += c);
          r.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
        }).on('error', reject);
      });
      
      const [npmWeek, npmTotal] = await Promise.all([
        fetchJSON('https://api.npmjs.org/downloads/point/last-week/clawmoat'),
        fetchJSON('https://api.npmjs.org/downloads/point/2026-01-01:2099-12-31/clawmoat'),
      ]);
      
      // GitHub stats (public API, no auth needed)
      const ghRepo = await fetchJSON('https://api.github.com/repos/darfaz/clawmoat');
      
      // Try to get clone stats (needs auth, may fail on public API)
      let clones = 0;
      try {
        const ghClones = await fetchJSON('https://api.github.com/repos/darfaz/clawmoat/traffic/clones');
        clones = ghClones?.count || 0;
      } catch {}
      
      const stats = {
        npm_downloads_week: npmWeek?.downloads || 0,
        npm_downloads_total: npmTotal?.downloads || 0,
        github_stars: ghRepo?.stargazers_count || 0,
        github_forks: ghRepo?.forks_count || 0,
        github_issues: ghRepo?.open_issues_count || 0,
        github_clones: clones || 870, // fallback to last known if API requires auth
        total: (npmTotal?.downloads || 0) + (clones || 870) + (ghRepo?.forks_count || 0),
        updated_at: new Date().toISOString(),
      };
      
      global._statsCache = stats;
      global._statsCacheTime = now;
      
      return json(res, 200, stats);
    } catch (err) {
      return json(res, 200, global._statsCache || { error: 'Stats temporarily unavailable' });
    }
  }

  // Contact form (Business inquiries)
  if (req.method === 'POST' && req.url === '/api/contact') {
    const body = await readBody(req);
    const { name, email, company, teamSize, agents, concerns } = body;
    if (!email) return json(res, 400, { error: 'Email required' });
    
    console.log(`🏢 Business inquiry: ${name} <${email}> @ ${company} (${teamSize}, ${agents} agents)`);
    console.log(`   Concerns: ${concerns}`);
    
    // TODO: Send notification email, store in CRM
    // For now, log it — we'll check server logs
    return json(res, 200, { success: true, message: 'Thank you! We\'ll be in touch within 24 hours.' });
  }

  // ─── Threat Intel API ──────────────────────────────────────────────────────

  // GET /api/v1/threats
  if (req.method === 'GET' && req.url.startsWith('/api/v1/threats')) {
    const apiUser = checkApiKey(req);
    if (!apiUser) return json(res, 401, { error: 'API key required. Add X-API-Key header. Get a free key at clawmoat.com/api' });

    // Rate limit free tier
    if (apiUser.tier === 'free' && apiUser.calls_this_month >= (apiUser.monthly_limit || 100)) {
      return json(res, 429, { error: 'Free tier limit reached (100 calls/month). Upgrade at clawmoat.com/#pricing' });
    }

    trackApiUsage(apiUser.key);
    const threats = loadThreats();

    // Single threat by id: /api/v1/threats/CLAWMOAT-2026-0001
    const idMatch = req.url.match(/^\/api\/v1\/threats\/([^?]+)/);
    if (idMatch) {
      const threat = threats.find(t => t.id === idMatch[1]);
      if (!threat) return json(res, 404, { error: 'Threat not found' });
      return json(res, 200, { threat });
    }

    // List with filters
    const q = parseQuery(req.url);
    let filtered = threats;
    if (q.category) filtered = filtered.filter(t => t.category === q.category);
    if (q.severity)  filtered = filtered.filter(t => t.severity === q.severity);
    if (q.tags)      filtered = filtered.filter(t => q.tags.split(',').every(tag => t.tags.includes(tag)));
    if (q.since)     filtered = filtered.filter(t => t.published >= q.since);
    const limit = Math.min(parseInt(q.limit) || 20, 100);
    filtered = filtered.slice(0, limit);

    const updated = threats.reduce((max, t) => t.updated > max ? t.updated : max, '');
    return json(res, 200, { threats: filtered, count: filtered.length, total: threats.length, updated });
  }

  // GET /api/v1/ioc — aggregated indicators of compromise
  if (req.method === 'GET' && req.url.startsWith('/api/v1/ioc')) {
    const apiUser = checkApiKey(req);
    if (!apiUser) return json(res, 401, { error: 'API key required. Add X-API-Key header. Get a free key at clawmoat.com/api' });

    if (apiUser.tier === 'free' && apiUser.calls_this_month >= (apiUser.monthly_limit || 100)) {
      return json(res, 429, { error: 'Free tier limit reached (100 calls/month). Upgrade at clawmoat.com/#pricing' });
    }

    trackApiUsage(apiUser.key);
    const threats = loadThreats();

    const ioc = { domains: new Set(), files: new Set(), patterns: new Set() };
    for (const t of threats) {
      (t.ioc?.domains  || []).forEach(d => ioc.domains.add(d));
      (t.ioc?.files    || []).forEach(f => ioc.files.add(f));
      (t.ioc?.patterns || []).forEach(p => ioc.patterns.add(p));
    }

    const updated = threats.reduce((max, t) => t.updated > max ? t.updated : max, '');
    return json(res, 200, {
      domains:  [...ioc.domains],
      files:    [...ioc.files],
      patterns: [...ioc.patterns],
      threat_count: threats.length,
      updated,
    });
  }

  // POST /api/v1/keys — generate free API key
  if (req.method === 'POST' && req.url === '/api/v1/keys') {
    const body = await readBody(req);
    if (!body.email) return json(res, 400, { error: 'email required' });

    const newKey = 'cm-' + require('crypto').randomBytes(16).toString('hex');
    const keys = loadApiKeys();
    keys[newKey] = {
      tier: 'free',
      email: body.email,
      calls_this_month: 0,
      monthly_limit: 100,
      created: new Date().toISOString().slice(0, 10),
      label: 'Free tier — ' + body.email,
    };
    saveApiKeys(keys);
    console.log(`New API key issued: ${body.email}`);
    return json(res, 201, {
      api_key: newKey,
      tier: 'free',
      monthly_limit: 100,
      docs: 'https://clawmoat.com/docs/api',
    });
  }

  // ─── License validation endpoint (called by CLI) ──────────────────────────
  // License validation endpoint (called by CLI)
  if (req.method === 'POST' && req.url === '/api/validate') {
    const body = await readBody(req);
    const key = body.key;
    if (!key) return json(res, 400, { error: 'Missing key' });

    return json(res, 200, validateLicense(key));
  }

  json(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`🏰 ClawMoat server listening on port ${PORT}`);
});
