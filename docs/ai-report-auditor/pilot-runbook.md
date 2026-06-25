# Research Pilot Runbook

Buyer: DB Equities

1. Review buyer-summary.md for the pilot verdict and remaining blockers.
2. Open research-preflight.json and confirm findings match the supplied draft, source, model, and restricted-list inputs.
3. Inspect supervision-ledger.jsonl and verify each review/approval event has an entry hash and previous-hash chain.
4. Check retention-manifest.json for the WORM/object-lock retention target and ledger head hash.
5. Hand enterprise-readiness.json to security/procurement as the blocker list for production use.

Approval gate: a real pilot needs one bounded workflow, no client distribution, named reviewers, and customer-approved retention target.
