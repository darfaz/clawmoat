# Equity Research Pre-Publication Review Scenario

## Buyer pain today

Equity research teams are letting analysts use copilots for first drafts, table summaries, and valuation notes, but supervision still has to prove three things before publication:

1. the draft did not use MNPI or client-confidential material,
2. rating / price target language is supported and not promissory,
3. Reg AC and source-trail evidence exists before the report leaves the firm.

The immediate buyer objection is not "can your AI write research?" It is "can I show Compliance why AI-assisted research was safe to publish?"

## Six-month assumption

By late 2026, buyers will expect AI research controls to look less like generic DLP and more like a pre-publication evidence packet: draft hash, model/workflow metadata, policy findings, supervisory disposition, and mapped controls. FINRA/SEC retention language may vary by firm, but the direction is obvious: if an AI touched the research, the audit trail needs to survive review.

## Synthetic dogfood case

Analyst uses an equity-research agent to draft an ACME upgrade:

```text
Upgrade ACME to Buy, PT $58. We know from a wall-crossed conversation that
unannounced earnings will beat consensus. Source: internal channel notes.
```

Expected ClawMoat result:

- `action: block`
- critical `possible_mnpi` finding mapped to `MNPI-01`
- high `unsupported_price_target` finding mapped to `PT-01`
- high `missing_reg_ac_certification` finding mapped to `REGAC-01`
- evidence object with a SHA-256 draft hash for retention / tamper-evidence anchoring

Clean release candidate:

```text
Rating: Outperform. Price target $42, based on 14x FY27 EPS and peer P/E multiples.
Sources: company 10-K, Q1 10-Q, earnings transcript, and FactSet consensus.
Analyst certification: I certify that the views expressed accurately reflect my
personal views and that my compensation was not related to the specific recommendation.
```

Expected ClawMoat result: `action: allow` with evidence checks for rating, price target, valuation rationale, source trail, and analyst certification.

## Product surface added

```js
const { ResearchReviewGuard } = require('clawmoat');

const guard = new ResearchReviewGuard();
const review = guard.reviewDraft(draft, {
  ticker: 'ACME',
  analyst: 'analyst-17',
  model: 'research-agent-v2',
});

if (review.action !== 'allow') {
  routeToSupervisor(review);
  guard.recordDisposition(review.reviewId, {
    decision: 'rejected',
    supervisor: 'supervisor-3',
    rationale: 'Draft uses wall-crossed MNPI and cannot be published.',
  });
}

const evidence = guard.exportEvidence({
  archive: {
    firmId: 'demo-bank',
    retentionYears: 6,
  },
});
console.log(evidence.supervisorAttestationPacket.packetDigest);
console.log(evidence.archiveManifest.archiveDigest);
```

The evidence export now includes two buyer-visible artifacts:

- `equity_research_supervisor_attestation_packet`: named supervisor decision, rationale, timestamp, mapped controls, pending reviews, and a packet digest.
- `equity_research_retention_archive_manifest`: one row per review, a SHA-256 digest of each review record, the supervisor disposition digest, and a hash chain linking entries together.

It is not a WORM store by itself. It is the packet a firm can hand to its archive vendor or SEC/FINRA books-and-records workflow so the review evidence can be exported, retained, and checked for tampering later.

This is intentionally small. It gives a demo-visible answer to "show me the supervisor signoff" and a second answer to "what survives retention review?" without pretending to be a full archive, WORM store, or supervisory workstation yet.
