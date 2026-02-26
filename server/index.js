const http = require('http');
const Stripe = require('stripe');

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const PORT = process.env.PORT || 3000;
const SITE_URL = process.env.SITE_URL || 'https://clawmoat.com';

const PRICES = {
  // Security Kit (one-time purchase)
  'security-kit':   process.env.PRICE_SECURITY_KIT   || null,  // $29 one-time — create in Stripe dashboard
  // Pro subscriptions
  'shield-monthly': process.env.PRICE_SHIELD_MONTHLY || 'price_1T0an4AUiOw2ZIorxQRyAxvQ',  // $14.99/mo
  'shield-yearly':  process.env.PRICE_SHIELD_YEARLY  || 'price_1T0an4AUiOw2ZIorfHx7RowT',  // $149/yr
  // Team subscriptions
  'team-monthly':   process.env.PRICE_TEAM_MONTHLY   || 'price_1T0aqrAUiOw2ZIorh4gjBPGt',  // $49/mo
  'team-yearly':    process.env.PRICE_TEAM_YEARLY    || 'price_1T0asRAUiOw2ZIorxAi69uwl',  // $499/yr
};

const ONE_TIME_PLANS = new Set(['security-kit']);

// In-memory license store (replace with DB in production)
const licenses = new Map();

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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
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

  // Create checkout session
  if (req.method === 'POST' && req.url === '/api/checkout') {
    const body = await readBody(req);
    const priceId = PRICES[body.plan];

    if (!priceId) {
      return json(res, 400, { error: 'Invalid plan. Use: shield-monthly, shield-yearly, team-monthly, team-yearly' });
    }

    try {
      const isOneTime = ONE_TIME_PLANS.has(body.plan);
      const sessionParams = {
        mode: isOneTime ? 'payment' : 'subscription',
        line_items: [{ price: priceId, quantity: 1 }],
        success_url: `${SITE_URL}/thanks.html?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${SITE_URL}/#pricing`,
        allow_promotion_codes: true,
        customer_email: body.email || undefined,
      };
      if (!isOneTime) {
        sessionParams.subscription_data = {
          trial_period_days: 30,
          metadata: { plan: body.plan },
        };
      } else {
        sessionParams.metadata = { plan: body.plan };
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
        const email = session.customer_email || session.customer_details?.email;
        const licenseKey = generateLicenseKey();
        console.log(`New customer: ${email}, license: ${licenseKey}`);
        // TODO: Store in database, send welcome email with license key
        // For now, log it — license fulfillment is manual via email
        licenses.set(licenseKey, {
          email,
          customerId: session.customer,
          subscriptionId: session.subscription,
          plan: session.metadata?.plan || 'unknown',
          createdAt: new Date().toISOString(),
          active: true,
        });
        break;
      }
      case 'customer.subscription.deleted':
      case 'customer.subscription.updated': {
        const sub = event.data.object;
        // Deactivate license if subscription cancelled
        for (const [key, lic] of licenses.entries()) {
          if (lic.subscriptionId === sub.id) {
            lic.active = sub.status === 'active' || sub.status === 'trialing';
            console.log(`License ${key}: active=${lic.active} (status=${sub.status})`);
          }
        }
        break;
      }
    }

    return json(res, 200, { received: true });
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

  // License validation endpoint (called by CLI)
  if (req.method === 'POST' && req.url === '/api/validate') {
    const body = await readBody(req);
    const key = body.key;
    if (!key) return json(res, 400, { error: 'Missing key' });

    const lic = licenses.get(key);
    if (!lic || !lic.active) {
      return json(res, 200, { valid: false });
    }
    return json(res, 200, { valid: true, plan: lic.plan, email: lic.email });
  }

  json(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`🏰 ClawMoat server listening on port ${PORT}`);
});
