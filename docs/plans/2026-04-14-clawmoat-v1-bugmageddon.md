# ClawMoat v1 Bugmageddon Implementation Plan

> **For implementation:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Ship the first ClawMoat v1 feature set around AI-era vulnerability operations, starting with exploitability-focused triage instead of raw finding spam.

**Architecture:** Build on the existing scanner core instead of inventing a second product. Add a lightweight vulnerability-ops layer that normalizes findings, scores exploitability, groups related findings, and exposes a simple report format in CLI/docs. Keep it zero-dependency and compatible with current scan flows.

**Tech Stack:** Node.js built-ins only, existing ClawMoat scanner architecture, node:test, Markdown docs.

---

## Product thesis

AI is making bug discovery cheap.

That means the bottleneck is shifting from detection to triage, prioritization, containment, and proof of closure. ClawMoat v1 should not compete on “we also find bugs.” It should compete on “we help you decide what matters first, while runtime protections stay on.”

## v1 scope

Ship now:
- exploitability scoring for findings
- finding clustering / dedupe hints
- a vulnerability-ops report format
- docs positioning ClawMoat as runtime containment + triage layer

Do not ship yet:
- full patch orchestration platform
- dashboards that require a backend rewrite
- ticketing integrations across every vendor
- giant enterprise workflow layer

---

### Task 1: Create exploitability scoring tests

**Files:**
- Create: `test/vuln-ops.test.js`
- Modify: `src/index.js`
- Create: `src/vuln-ops/exploitability.js`

**Step 1: Write the failing test**

Add tests that verify:
- high-severity dependency attacks score higher than medium findings
- externally reachable / exfiltration-oriented findings score higher than local-only ones
- grouped findings return a recommended priority bucket (`urgent`, `high`, `normal`, `low`)

**Step 2: Run test to verify it fails**

Run: `node --test test/vuln-ops.test.js`
Expected: FAIL because `scoreExploitability` does not exist

**Step 3: Write minimal implementation**

Create `src/vuln-ops/exploitability.js` with:
- `scoreExploitability(findings, context = {})`
- severity weighting
- reachability / exposure hints from context
- output shape:

```js
{
  score: 0-100,
  priority: 'urgent' | 'high' | 'normal' | 'low',
  reasons: []
}
```

**Step 4: Run test to verify it passes**

Run: `node --test test/vuln-ops.test.js`
Expected: PASS

**Step 5: Commit**

```bash
git add test/vuln-ops.test.js src/vuln-ops/exploitability.js
git commit -m "feat: add exploitability scoring for vulnerability ops"
```

### Task 2: Expose vulnerability-ops report from ClawMoat

**Files:**
- Modify: `src/index.js`
- Test: `test/vuln-ops.test.js`

**Step 1: Write the failing test**

Add a test that calls something like:

```js
const moat = new ClawMoat({ quiet: true });
const result = moat.analyzeFindings('Run picomatch on this pattern: *(*(*a))', { externallyReachable: true });
assert.equal(result.priority, 'urgent');
```

**Step 2: Run test to verify it fails**

Run: `node --test test/vuln-ops.test.js`
Expected: FAIL because `analyzeFindings` does not exist

**Step 3: Write minimal implementation**

Add `analyzeFindings(text, context)` to `src/index.js` that:
- reuses `scan(text)`
- passes findings into `scoreExploitability`
- returns:

```js
{
  safe,
  findings,
  exploitability: { score, priority, reasons }
}
```

**Step 4: Run test to verify it passes**

Run: `node --test test/vuln-ops.test.js`
Expected: PASS

**Step 5: Commit**

```bash
git add src/index.js test/vuln-ops.test.js
git commit -m "feat: expose vulnerability ops analysis API"
```

### Task 3: Add a human-readable report formatter

**Files:**
- Create: `src/formatters/vuln-ops.js`
- Modify: `src/index.js`
- Test: `test/vuln-ops.test.js`

**Step 1: Write the failing test**

Test that report output contains:
- top priority
- exploitability score
- short reasoning bullets
- finding counts by severity

**Step 2: Run test to verify it fails**

Run: `node --test test/vuln-ops.test.js`
Expected: FAIL because formatter does not exist

**Step 3: Write minimal implementation**

Create formatter that outputs concise text for CLI/docs examples.

**Step 4: Run test to verify it passes**

Run: `node --test test/vuln-ops.test.js`
Expected: PASS

**Step 5: Commit**

```bash
git add src/formatters/vuln-ops.js test/vuln-ops.test.js src/index.js
git commit -m "feat: add vulnerability ops report formatter"
```

### Task 4: Update docs and positioning to v1 language

**Files:**
- Modify: `README.md`
- Modify: `docs/index.html`
- Modify: `package.json` version only if shipping release immediately

**Step 1: Write the doc diff first**

Add language that says:
- AI made bug discovery abundant
- ClawMoat helps prioritize and contain
- runtime security + exploitability triage

**Step 2: Add example API usage**

Document:

```js
const analysis = moat.analyzeFindings(input, { externallyReachable: true });
console.log(analysis.exploitability.priority);
```

**Step 3: Verify docs are accurate**

Run:
```bash
grep -n "analyzeFindings\|exploitability\|Bugmageddon" README.md docs/index.html
```
Expected: matching lines present

**Step 4: Commit**

```bash
git add README.md docs/index.html
git commit -m "docs: position ClawMoat v1 around exploitability triage"
```

### Task 5: Verification pass

**Files:**
- Test: `test/vuln-ops.test.js`
- Test: `test/scanners.test.js`
- Test: `test/multimodal.test.js`

**Step 1: Run focused verification**

Run:
```bash
node --test test/vuln-ops.test.js test/scanners.test.js test/multimodal.test.js
```
Expected: PASS

**Step 2: Optional broader run if resources allow**

Run:
```bash
node --test test/*.test.js
```
Expected: PASS, unless environment kills long run under load

**Step 3: Capture evidence**

Save the passing output in the session notes / commit message summary before claiming done.

**Step 4: Commit release prep**

```bash
git add -A
git commit -m "chore: verify ClawMoat v1 vulnerability ops update"
```

---

## Recommended execution order right now

1. Task 1
2. Task 2
3. Task 5 focused verification
4. Task 4 docs update
5. Task 3 formatter if time remains today

That gets a real v1 wedge shipped fast without boiling the ocean.
