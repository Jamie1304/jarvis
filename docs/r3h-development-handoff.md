# V1-I-R3H source handoff (superseded development note)

This file is retained as the development history. The repaired source closure
and its current evidence boundary are documented in `docs/r3h-review-closure.md`.

The repaired source implements the provider-neutral fabric on top of the qualified
R3G source. The focused source cases are in
`tests/test_r3h_intelligence_fabric.py`; they cover catalog completeness,
dynamic model registration, route identity, lifecycle, policy inheritance,
guarded approvals, budget unknown-cost behavior, task quarantine, decision
authority isolation, remote privacy, endpoint containment, and credential
secrecy.

The catalog and adapters are controlled-fixture contracts. They do
not prove real account authentication, billing, quota, regional entitlement,
provider outage, or physical Jev behavior. Those remain independent
qualification work. The review policy leaves full canonical quality
unexecuted: `CANONICAL_FULL_QUALITY: NOT_EXECUTED_BY_REVIEW_POLICY`.

## Architecture audit

| Area | R3G state | R3H result |
| --- | --- | --- |
| Generative provider contract | production partial | existing `AIProvider` preserved under `IntelligenceProvider` |
| Registry/knowledge/routing | production partial | existing owners extended by bounded discovery and governance seams |
| Decision intelligence | missing | typed `DecisionProvider`, Jev adapter, negative authority tests |
| Provider packages/catalog | missing | complete canonical manifest catalog; physical status explicit |
| Exact operational identity | production partial | `ExactRouteIdentity` and route-key-bound approvals |
| Usability | production partial | existing `ModelUsabilityEvidence` reused; connected remains distinct from usable |
| Cost/budget | production partial | provenance-bearing cost evidence, separate usage receipts, local budget ledger |
| Privacy | production partial | existing generative boundary retained and non-generative gateway added |
| Onboarding/UI | production partial | Vault-backed onboarding and real registry/policy model projection |
| Zero Cloud | production partial | no cloud dependency added; local Ollama path remains the existing authority |

Recommended next action: `V1-I-R3H-Q — new-worktree exact-SHA frozen qualification + push + hosted CI`.
