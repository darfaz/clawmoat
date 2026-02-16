const http = require('http');
const Stripe = require('stripe');

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const PORT = process.env.PORT || 3000;
const SITE_URL = process.env.SITE_URL || 'https://clawmoat.com';

const PRICES = {
  // One-time purchase
  'pro-skill':     process.env.PRICE_PRO_SKILL     || 'price_1T1avaAUiOw2ZIordarLcoff',
  // Subscriptions (30-day free trial)
  'shield-monthly': process.env.PRICE_SHIELD_MONTHLY || 'price_1T1avaAUiOw2ZIorQXuxNyM3',
  'shield-yearly':  process.env.PRICE_SHIELD_YEARLY  || 'price_1T1avaAUiOw2ZIorAtBLXBOg',
  'team-monthly':   process.env.PRICE_TEAM_MONTHLY   || 'price_1T1avaAUiOw2ZIorAqeOaahQ',
  'team-yearly':    process.env.PRICE_TEAM_YEARLY    || 'price_1T1avbAUiOw2ZIorDLUicwin',
};

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
      return json(res, 400, { error: 'Invalid plan. Use: pro-monthly, pro-yearly, team-monthly, team-yearly' });
    }

    try {
      const mode = body.plan === 'pro-skill' ? 'payment' : 'subscription';
      const session = await stripe.checkout.sessions.create({
        mode,
        line_items: [{ price: priceId, quantity: 1 }],
        success_url: `${SITE_URL}/thanks.html?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${SITE_URL}/#pricing`,
        allow_promotion_codes: true,
      });
      return json(res, 200, { url: session.url });
    } catch (err) {
      return json(res, 500, { error: err.message });
    }
  }

  // Stripe webhook (for future use)
  if (req.method === 'POST' && req.url === '/api/webhook') {
    // TODO: handle subscription events
    return json(res, 200, { received: true });
  }

  json(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`🏰 ClawMoat server listening on port ${PORT}`);
});
