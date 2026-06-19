# ClawMoat Research Preflight Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Add a DB equity-research sales wedge and a working `clawmoat research preflight` CLI that turns AI-assisted drafts, transcripts, filings, models, and restricted lists into supervisor-ready evidence packets.

**Architecture:** Keep ClawMoat's existing agent-firewall core, but add a regulated-research vertical. The CLI performs deterministic first-pass checks for unsupported claims, model tie-outs, prompt injection in source documents, restricted issuer mentions, and AI usage attestation. The site adds a focused vertical landing page and a sample preflight report.

**Tech Stack:** Static HTML under `docs/`, Node.js CLI under `bin/clawmoat.js`, reusable logic under `src/research-preflight.js`, Node built-in test runner under `test/research-preflight.test.js`.

---

### Task 1: Add failing Research Preflight tests

**Objective:** Define expected behavior before implementation.

**Files:**
- Create: `test/research-preflight.test.js`

**Steps:**
1. Test `runResearchPreflight()` flags unsupported claims, model tie-out gaps, AI attestation gaps, prompt injection in source text, and restricted issuers.
2. Test markdown formatting includes workflow, Gemini provider, evidence receipt, and supervisor checklist.
3. Test CLI command writes JSON and prints markdown.
4. Run `node --test test/research-preflight.test.js`.
5. Expected RED: missing `src/research-preflight.js`.

### Task 2: Implement Research Preflight module

**Objective:** Add minimal deterministic checks to pass the tests.

**Files:**
- Create: `src/research-preflight.js`

**Checks:**
- Extract numeric and research-claim-like sentences from draft.
- Compare claims against approved source corpus.
- Compare draft numbers against model CSV-like text.
- Reuse ClawMoat prompt-injection scanner on source docs.
- Check draft/source/model against restricted issuer list.
- Detect AI-provider mentions without review/attestation language.
- Produce SHA-256 hashes for draft, model, restricted list, and sources.

### Task 3: Wire CLI

**Objective:** Make the workflow usable locally and demoable for DB conversations.

**Files:**
- Modify: `bin/clawmoat.js`

**Command:**
```bash
clawmoat research preflight --draft draft.md --source transcript.txt --model model.csv --restricted restricted.csv --provider Gemini --analyst "Demo Analyst" --output report.json
```

**Behavior:**
- Print Markdown report by default.
- Support `--format json`.
- Write JSON evidence with `--output`.
- Exit non-zero when critical/high findings require supervisor review.

### Task 4: Add sales page

**Objective:** Create a public vertical page for DB-style equity research buyers.

**Files:**
- Create: `docs/equity-research-ai-control/index.html`

**Message:**
- AI Preflight for Equity Research.
- Fits teams already using Gemini in limited ways.
- ClawMoat wraps Gemini/Copilot/ChatGPT/internal models with research-specific controls.
- Outputs claim checks, model tie-outs, restricted-list hits, prompt-injection source warnings, and audit receipts.

### Task 5: Add sample report page

**Objective:** Make the sales conversation concrete.

**Files:**
- Create: `docs/research-preflight-report-demo/index.html`

**Content:**
- Demo findings for unsupported price target, model mismatch, prompt injection in transcript, restricted issuer, and AI usage attestation.
- Evidence receipt and supervisor checklist.

### Task 6: Wire site and docs

**Objective:** Ensure the new vertical is discoverable.

**Files:**
- Modify: `docs/index.html`
- Modify: `docs/request/index.html`
- Modify: `docs/sitemap.xml`
- Modify: `README.md`

### Task 7: Verify and commit

**Commands:**
```bash
node --test test/research-preflight.test.js
npm test
npm run lint
node bin/clawmoat.js research preflight --draft /tmp/draft.md --source /tmp/source.txt --model /tmp/model.csv --restricted /tmp/restricted.csv --provider Gemini --analyst Demo --output /tmp/report.json
```

Commit:
```bash
git add bin/clawmoat.js src/research-preflight.js test/research-preflight.test.js docs/equity-research-ai-control docs/research-preflight-report-demo docs/index.html docs/request/index.html docs/sitemap.xml README.md docs/plans/2026-06-19-research-preflight.md
git commit -m "feat: add equity research AI preflight"
```
