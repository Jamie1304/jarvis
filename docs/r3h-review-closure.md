# V1-I-R3H provider execution and review closure

This source contains the R3H intelligence-fabric review repairs on the exact
R3G-qualified parent. The implementation is composed through the existing
registry, knowledge, routing, policy, credential, runtime, facade, and Qt
owners. It does not add a second provider registry, router, knowledge store,
credential vault, privacy boundary, resource governor, permission broker, or
planning/task plane.

## Closed source contracts

| Area | Source closure |
| --- | --- |
| Exact operational identity | `ModelIdentity` persists endpoint, region, model/version, deployment, account scope, intelligence kind, quantization, and runtime. v1 databases migrate atomically with explicit `unknown` route dimensions. |
| Discovery and aliases | Bounded discovery updates the existing `ProviderRegistry` and `ModelKnowledgeService`; aliases resolve to distinct evidence identities. Same weights at different endpoints remain separate routes. |
| Provider catalog | The catalog contains 28 manifests with explicit support truth. Named OpenAI-compatible, Cohere, Anthropic, Gemini, regional, enterprise, MiniMax, and typed Jev packages use shared or typed adapters; all 28 are source-executable and controlled-protocol tested. |
| Governance | Provider/model policy, exact-route guarded approval, durable usage receipts, persisted budget policy, route-bound trusted price history, and task-family quarantine are local and restart-safe. Routing-disabled is distinct from disconnected and from explicit credential deletion. |
| Decision intelligence | `DecisionProvider` is typed separately from generative inference. Remote decision payloads pass through the privacy gateway, including task text; outputs are advisory and cannot assert authority. A deterministic local decision fallback is composed at runtime. |
| Onboarding and credentials | One-key onboarding validates typed configuration, stores secrets only through `CredentialVault`, persists only credential references and non-secret configuration, and provides explicit delete semantics. |
| Runtime composition | `ApplicationRuntime` owns the R3H policy ledger, quarantine, discovery, onboarding, model projection, and decision router using canonical application-data paths. |
| Qt surface | The Intelligence page is a real facade-backed page with provider connection, routing, credential deletion, model policy, budget controls, endpoint containment, and bounded model/provider projections. Safe Mode leaves controls unavailable and projections empty. |
| Zero Cloud | Local operation remains possible without a cloud provider. Unknown-cost remote routes are guarded under cost-efficient selection; local costless routes do not become cloud budget failures. |

## Evidence boundary

The focused review cases independently exercise route persistence/migration,
durability and idempotency, credential lifecycle, provider support truth,
discovery, routing, and existing R3H contracts. They do not claim real
provider authentication, billing, quota, regional entitlement, outage
behavior, physical Qt accessibility, physical Jev behavior, or hosted CI.
Those are qualification and physical evidence concerns, not source assertions.

The final provider source-closure policy leaves the canonical full-quality gate
unexecuted: `CANONICAL_FULL_QUALITY:
NOT_EXECUTED_BY_FINAL_SOURCE_CLOSURE_POLICY`.

Recommended next action: `V1-I-R3H-Q — new-worktree exact-SHA frozen qualification + push + hosted CI`.
