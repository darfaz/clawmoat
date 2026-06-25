# ClawMoat Research Preflight

Generated: 2026-06-19T12:00:00.000Z
Workflow: db-equity-research
Analyst: Maya Chen
Model/provider: Gemini
Policy pack: investment-banking-research-v1
Disposition: compliance_hold

## Summary

- Total findings: 13
- Critical: 1
- High: 9
- Medium: 3
- Low: 0

## Findings

### 1. missing_claim_citation (medium)

Evidence: AI-assisted draft: ACME Software revenue increased 18% to $2.4 billion

Recommendation: Add an explicit source citation such as [S:transcript] or [S:model] for every material claim before supervisor review.

### 2. unsupported_claim (high)

Evidence: AI-assisted draft: ACME Software revenue increased 18% to $2.4 billion

Recommendation: Link the claim to an approved transcript, filing, model cell, or remove it before supervisor review.

### 3. missing_claim_citation (high)

Evidence: We rate ACME Software Buy and raise the price target to $82 on 31% EBITDA margin expansion

Recommendation: Add an explicit source citation such as [S:transcript] or [S:model] for every material claim before supervisor review.

### 4. unsupported_claim (high)

Evidence: We rate ACME Software Buy and raise the price target to $82 on 31% EBITDA margin expansion

Recommendation: Link the claim to an approved transcript, filing, model cell, or remove it before supervisor review.

### 5. unsupported_claim_citation (high)

Evidence: Claim cites approved-model, but that artifact does not support the cited numbers/text. Missing numbers: none. Claim: [S:approved-model]
The CFO privately told the analyst that next quarter revenue will beat consensus before public release

Recommendation: Cite the artifact that actually supports the claim, attach the missing source, or revise/remove the claim before supervisor review.

### 6. unsupported_claim (high)

Evidence: [S:approved-model]
The CFO privately told the analyst that next quarter revenue will beat consensus before public release

Recommendation: Link the claim to an approved transcript, filing, model cell, or remove it before supervisor review.

### 7. unsupported_claim (high)

Evidence: Risk factors: demand volatility, execution risk, and margin compression could pressure the thesis

Recommendation: Link the claim to an approved transcript, filing, model cell, or remove it before supervisor review.

### 8. missing_claim_citation (high)

Evidence: Valuation methodology: price target derived from a peer multiple and approved model export

Recommendation: Add an explicit source citation such as [S:transcript] or [S:model] for every material claim before supervisor review.

### 9. unsupported_claim (high)

Evidence: Valuation methodology: price target derived from a peer multiple and approved model export

Recommendation: Link the claim to an approved transcript, filing, model cell, or remove it before supervisor review.

### 10. model_tie_out (medium)

Evidence: Draft uses 18%; model values include $2.4billion, $82, 31%

Recommendation: Tie every price target, estimate, and margin number to the approved model version before publication.

### 11. prompt_injection_source (high)

Evidence: earnings-call-source.txt: instruction_override

Recommendation: Treat the source as untrusted. Do not allow source text to control tools, retrieval scope, recipients, or model/system instructions.

### 12. ai_usage_attestation (medium)

Evidence: Draft references AI assistance but no analyst review/attestation language was detected.

Recommendation: Record analyst review, source verification, and supervisor approval before relying on AI-assisted content.

### 13. potential_mnpi (critical)

Evidence: The CFO privately told the analyst that next quarter revenue will beat consensus before public release.

Recommendation: Stop distribution. Route to compliance, confirm public-source provenance, and document wall-crossing / information-barrier clearance before any AI-assisted use.

## Release gate

- Status: blocked
- Required approvals: supervisor, compliance
- Blockers: 10
- Open action: Link the claim to an approved transcript, filing, model cell, or remove it before supervisor review.
- Open action: Add an explicit source citation such as [S:transcript] or [S:model] for every material claim before supervisor review.
- Open action: Cite the artifact that actually supports the claim, attach the missing source, or revise/remove the claim before supervisor review.
- Open action: Treat the source as untrusted. Do not allow source text to control tools, retrieval scope, recipients, or model/system instructions.
- Open action: Stop distribution. Route to compliance, confirm public-source provenance, and document wall-crossing / information-barrier clearance before any AI-assisted use.
- Note: Do not distribute or archive as final until all blockers are remediated or explicitly approved by the required roles.

## Evidence receipt

- Draft artifact hash: 8e78ccbf164a66825f08f04e68e474b9b9bdc8fd3a3d11175c1dfbbe600b193f
- Model hash: d2f4133cd6936e002f2e7d757cb384236d6d449a89bc583b1a0da486213a372a
- Restricted list hash: 9f3dc9e23faa90f5fbb58938983b2d85c439f39f2cf84fdf9c3db337e9352910
- Source earnings-call-source.txt hash: 68d1d46b8c34da536a368878007b9b38c7971d240c60e5b1744b51a2641b3032
- Controls applied: claim_source_support, model_number_tie_out, prompt_injection_source_scan, restricted_issuer_check, ai_usage_attestation_check, claim_citation_required, claim_citation_source_verification, mnpi_selective_disclosure_hold, research_disclosure_check, audit_retention_packet
- Retention class: research-supervision-audit-packet
- Retention note: Archive with the final research artifact, approval workflow, and firm books-and-records system.

## Control matrix

- FINRA-3110-GENAI: Reasonably designed supervision for GenAI use (FINRA Regulatory Notice 24-09 / Rule 3110)
- FINRA-2210-COMMS: Communications content standards apply to AI-generated output (FINRA Regulatory Notice 24-09 / Rule 2210)
- IB-RESEARCH-CITATIONS: Material claims require source citations (ClawMoat investment-banking research policy)
- IB-RESEARCH-MNPI: Potential MNPI and selective-disclosure hold (ClawMoat investment-banking research policy)
- IB-RESEARCH-DISCLOSURES: Research disclosure and analyst-certification checks (ClawMoat investment-banking research policy)
- IB-RESEARCH-MODEL-RISK: Research workflows must use approved AI model providers (ClawMoat model-risk supervision policy)

## Supervisor checklist

- [ ] Analyst confirmed AI output reflects their personal view.
- [ ] Unsupported claims were removed or tied to approved sources.
- [ ] Price target, estimates, and percentages tie to the approved model.
- [ ] Every material claim has an explicit source citation.
- [ ] Potential MNPI, restricted-list, and information-barrier hits were cleared by compliance.
- [ ] Required research disclosures, risk factors, valuation methodology, and analyst certification were added or documented as not applicable.
- [ ] Restricted-list and information-barrier hits were cleared.
- [ ] Evidence receipt was archived with the final research artifact.