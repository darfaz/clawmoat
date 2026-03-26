# ClawMoat Threat Intel API — Implementation Plan

> **For implementation:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Ship an MVP API endpoint that serves structured AI agent security threat intelligence, with Stripe metered billing.

**Architecture:** Express.js server (extends existing ~/clawmoat/server/), backed by a JSON threat database that Leo populates from daily security news scans. Endpoints serve filtered threat data. Stripe usage-based billing tracks API calls per key. Deployed on Railway.

**Tech Stack:** Express.js, Stripe metered billing, JSON flat-file storage (MVP), API key auth, Railway deploy

---

## Task 1: Threat Database Schema & Seed Data

**Files:**
- Create: `server/data/threats.json`
- Create: `server/data/schema.md`

**Step 1: Define the threat schema**

```json
{
  "id": "CLAWMOAT-2026-0001",
  "title": "LiteLLM .pth File Injection",
  "published": "2026-03-24T00:00:00Z",
  "updated": "2026-03-26T00:00:00Z",
  "severity": "critical",
  "category": "supply-chain",
  "tags": ["python", "pypi", "credential-theft", "pth-injection"],
  "summary": "LiteLLM versions 1.82.7-1.82.8 contain credential-stealing .pth payload",
  "affected": {
    "packages": ["litellm==1.82.7", "litellm==1.82.8"],
    "ecosystems": ["pypi"]
  },
  "ioc": {
    "domains": ["models.litellm.cloud"],
    "files": ["litellm_init.pth"],
    "hashes": [],
    "patterns": ["exec(base64.b64decode(", ".pth import subprocess"]
  },
  "detection": {
    "clawmoat_module": "scanners/supply-chain",
    "clawmoat_function": "scanSkillContent",
    "rules_triggered": ["obfuscated_exec_b64", "pth_file_injection", "exfil_litellm_lookalike"]
  },
  "references": [
    "https://github.com/BerriAI/litellm/issues/24512",
    "https://news.ycombinator.com/item?id=47501426",
    "https://awesomeagents.ai/news/litellm-supply-chain-compromise-credential-theft/"
  ],
  "mitigation": "Rotate all credentials on affected systems. Check: pip show litellm | grep Version. Search: find / -name litellm_init.pth"
}
```

**Step 2: Seed with this week's 5 threats**

Populate threats.json with:
1. LiteLLM .pth injection (CLAWMOAT-2026-0001)
2. Meta AI agent data leak (CLAWMOAT-2026-0002)
3. API key exposure on 10K websites (CLAWMOAT-2026-0003)
4. LeakBase credential marketplace (CLAWMOAT-2026-0004)
5. Gemini API key theft — $82K bill (CLAWMOAT-2026-0005)

**Step 3: Commit**

```
git commit -m "feat: threat intel database schema + seed data (5 threats)"
```

---

## Task 2: API Endpoint — GET /api/v1/threats

**Files:**
- Create: `server/routes/threats.js`
- Modify: `server/index.js` (mount route)
- Create: `server/middleware/api-key-auth.js`
- Test: `server/tests/threats.test.js`

**Step 1: Write failing test**

```javascript
const request = require('supertest');
const app = require('../index');

describe('GET /api/v1/threats', () => {
  it('returns 401 without API key', async () => {
    const res = await request(app).get('/api/v1/threats');
    expect(res.status).toBe(401);
  });

  it('returns threats with valid API key', async () => {
    const res = await request(app)
      .get('/api/v1/threats')
      .set('X-API-Key', 'test-key-123');
    expect(res.status).toBe(200);
    expect(res.body.threats).toBeInstanceOf(Array);
    expect(res.body.threats.length).toBeGreaterThan(0);
  });

  it('filters by category', async () => {
    const res = await request(app)
      .get('/api/v1/threats?category=supply-chain')
      .set('X-API-Key', 'test-key-123');
    expect(res.body.threats.every(t => t.category === 'supply-chain')).toBe(true);
  });

  it('filters by severity', async () => {
    const res = await request(app)
      .get('/api/v1/threats?severity=critical')
      .set('X-API-Key', 'test-key-123');
    expect(res.body.threats.every(t => t.severity === 'critical')).toBe(true);
  });

  it('filters by date range', async () => {
    const res = await request(app)
      .get('/api/v1/threats?since=2026-03-24')
      .set('X-API-Key', 'test-key-123');
    expect(res.body.threats.length).toBeGreaterThan(0);
  });
});
```

**Step 2: Run test, confirm failure**

**Step 3: Implement API key middleware**

```javascript
// server/middleware/api-key-auth.js
const validKeys = new Map(); // loaded from server/data/api-keys.json

function apiKeyAuth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ error: 'API key required' });
  const record = validKeys.get(key);
  if (!record) return res.status(403).json({ error: 'Invalid API key' });
  req.apiUser = record;
  next();
}
```

**Step 4: Implement threats route**

Query params: `category`, `severity`, `since`, `tags`, `limit` (default 20, max 100)

Response format:
```json
{
  "threats": [...],
  "count": 5,
  "total": 5,
  "updated": "2026-03-26T15:00:00Z"
}
```

**Step 5: Run tests, confirm pass**

**Step 6: Commit**

```
git commit -m "feat: GET /api/v1/threats endpoint with filtering + API key auth"
```

---

## Task 3: GET /api/v1/threats/:id — Single Threat Detail

**Files:**
- Modify: `server/routes/threats.js`
- Modify: `server/tests/threats.test.js`

Returns full threat object including IOCs, detection rules, mitigation steps.

---

## Task 4: GET /api/v1/ioc — Indicators of Compromise Feed

**Files:**
- Create: `server/routes/ioc.js`
- Test: `server/tests/ioc.test.js`

Aggregates all IOCs across threats into a flat feed. Useful for agents to bulk-update their blocklists.

```json
{
  "domains": ["models.litellm.cloud", ...],
  "files": ["litellm_init.pth", ...],
  "patterns": ["exec(base64.b64decode(", ...],
  "updated": "2026-03-26T15:00:00Z"
}
```

---

## Task 5: Stripe Metered Billing

**Files:**
- Create: `server/middleware/usage-tracker.js`
- Create: `server/billing/stripe.js`
- Modify: `server/middleware/api-key-auth.js` (link to Stripe customer)

**Pricing:**
- Free tier: 100 calls/month (no card required)
- Pro: $4.99/mo flat + $0.001/call over 5,000
- Unlimited: $19.99/mo

**Implementation:**
1. On each API call, increment usage counter in api-keys.json
2. Stripe webhook on subscription create → generate API key → email to user
3. Daily cron: report usage to Stripe metered billing
4. Free tier: check call count, return 429 when exceeded

---

## Task 6: API Key Self-Service

**Files:**
- Create: `server/routes/keys.js`
- Test: `server/tests/keys.test.js`

POST /api/v1/keys — generate a free-tier API key (email required)
GET /api/v1/keys/:key/usage — check your usage

---

## Task 7: Railway Deploy

**Files:**
- Modify: `server/package.json` (start script)
- Create: `server/Procfile`
- Create: `server/.env.example`

Environment vars: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, API_MASTER_KEY

Deploy to Railway on clawmoat.com subdomain: `api.clawmoat.com`

---

## Task 8: Documentation

**Files:**
- Create: `docs/api/README.md`
- Create: `docs/api/openapi.yaml`
- Modify: `README.md` (add Threat Intel API section)

OpenAPI spec for the full API. Add to clawmoat.com as /docs/api page.

---

## MVP Scope (Tonight)

Tasks 1-3 + 7 = working API with seed data, deployed on Railway.
Tasks 4-6 + 8 = fast follow (this week).

**Total estimated time: 4-5 hours for MVP, 2-3 more for billing + docs.**
