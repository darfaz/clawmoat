# Buyer Summary

Buyer: DB Equities

## Verdict

Controlled pilot ready. Not approved for official production use.

## What ClawMoat checked

- Source support and citation evidence
- Approved model tie-out and model-risk register
- MNPI, restricted-list, prompt-injection, disclosure, and AI-attribution checks
- Supervisor/compliance review events and tamper-evident ledger chain
- Retention manifest and enterprise-readiness blockers

## What passed

- Synthetic workflow generated complete preflight, ledger, retention, readiness, and buyer-summary artifacts.

## Blockers

- DB-EQ-07: Enterprise SSO/RBAC and role provisioning are configured
- DB-EQ-08: Customer environment connectors and data-boundary controls are configured
- DB-EQ-09: Operational owner, support path, and incident response are defined

## Evidence retained

- research-preflight.json
- supervision-ledger.jsonl
- retention-manifest.json
- enterprise-readiness.json

## Next approval step

Run the demo against one bounded real workflow with approved source files, an approved model export, and named supervisor/compliance reviewers. Use the generated packet to decide whether to proceed to a controlled pilot.
