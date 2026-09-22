# V1-I-R3H development handoff

This worktree implements the provider-neutral fabric on top of the qualified
R3G source. The focused source cases are in
`tests/test_r3h_intelligence_fabric.py`; they cover catalog completeness,
dynamic model registration, route identity, lifecycle, policy inheritance,
guarded approvals, budget unknown-cost behavior, task quarantine, decision
authority isolation, remote privacy, endpoint containment, and credential
secrecy.

The development catalog and adapters are controlled-fixture contracts. They do
not prove real account authentication, billing, quota, regional entitlement,
provider outage, or physical Jev behavior. Those remain independent
qualification work. Full canonical quality is intentionally deferred by the
R3H development contract.

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

Recommended next action: independent R3H architecture/security/provider-contract
review, focused repair, then frozen qualification.
