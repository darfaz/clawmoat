const http = require('http');
const Stripe = require('stripe');

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const PORT = process.env.PORT || 3000;
const SITE_URL = process.env.SITE_URL || 'https://clawmoat.com';

const PRICES = {
  'pro-monthly':  process.env.PRICE_PRO_MONTHLY  || 'price_1T0an4AUiOw2ZIorxQRyAxvQ',
  'pro-yearly':   process.env.PRICE_PRO_YEARLY   || 'price_1T0an4AUiOw2ZIorfHx7RowT',
  'team-monthly': process.env.PRICE_TEAM_MONTHLY || 'price_1T0aqrAUiOw2ZIorh4gjBPGt',
  'team-yearly':  process.env.PRICE_TEAM_YEARLY  || 'price_1T0asRAUiOw2ZIorxAi69uwl',
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
      const session = await stripe.checkout.sessions.create({
        mode: 'subscription',
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
