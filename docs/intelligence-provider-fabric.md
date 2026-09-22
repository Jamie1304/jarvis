# R3H intelligence provider fabric

R3H extends the existing `AIProvider` contract with the provider-neutral
`IntelligenceProvider` root. `AIProvider` remains the generative
specialization used by `ConversationService`, `ProviderRouter`, and
`InferenceDispatcher`. `DecisionProvider` is a separate typed capability;
decision results contain labels, bounded scores, and evidence only. They
cannot assert permission, security, release, identity, or effect authority.

The standard package description is `ProviderPackageManifest`. It owns setup
fields, authentication description, protocol family, discovery/probe support,
help links, lifecycle, and external support status. The application consumes
the manifest through generic catalog and onboarding services; vendor names are
not routing branches.

## Discovery and route identity

`ModelDiscoveryService` updates the existing `ProviderRegistry` and
`ModelKnowledgeService`. A provider may return up to 1,024 model observations.
Each observed ID is registered as an exact route without a Core source change;
metadata not returned by the provider stays unknown. `ExactRouteIdentity`
includes provider, endpoint, region, model/version, deployment, account scope,
intelligence kind, quantization, and runtime. Different operational routes for
the same weights therefore retain separate evidence.

`latest` and other aliases are descriptive metadata (`alias_target`); they are
not permission to reuse historical calibration when the resolved identity
changes. Retired routes remain readable in knowledge but are not executable.

## Governance and cost

`PolicyStore` is the durable owner for provider, exact-model, and typed bulk
policy. `PolicyEngine` resolves the most restrictive applicable policy. A
newly discovered model is evaluated through the same path immediately. A
`GuardedApproval` binds actor, task, exact route, purpose, scope, cost ceiling,
and expiry. `BudgetLedger` stores actual usage receipts separately from
pre-call estimates; it also retains route-bound trusted price observations,
their provenance/history, and expiry. The newest non-stale price drives later
routing; `COST_UNKNOWN` is never treated as zero.

`TaskQuarantine` records narrow task-family failures. Learned state changes
ranking only and cannot loosen explicit user policy.

`DecisionRouter` evaluates typed decision providers generically, routes through
the same remote privacy gateway, and retains a local/deterministic fallback
when Jev or another remote decision provider is offline. The existing
`ProviderRegistry` owns non-generative registrations as well as generative
definitions; no second provider registry is introduced.

## Privacy and credentials

`RemoteIntelligencePrivacyGateway` handles bounded non-generative payloads.
The existing `PrivacyBoundary` remains the generative text enforcement seam.
Both require local classification, minimize fields, redact known local values,
and reject secret/local-only input. `ProviderOnboardingService` stores raw
credentials only through the existing `CredentialVault`; returned connection
projections contain credential IDs and non-secret configuration only.

The `openai-compatible` package is first class. Remote endpoints require TLS,
loopback endpoints require explicitly trusted `LOCAL` metadata, and the
adapter accepts only typed configuration plus an injected transport—never
user-supplied executable hooks.

The desktop facade exposes `model_intelligence_view()` as a read-only
projection from the existing router registry. Safe Mode returns an empty,
truthful projection and never enables cloud or credential use.

## Zero Cloud and physical status

The catalog is descriptive and controlled-fixture qualified in development.
`CONTRACT_ONLY` and `EXTERNAL_PROTOCOL_FACT_NOT_PROVEN` are truthful package
statuses; no real provider account, quota, billing, region, or outage result is
claimed by source tests. Local Ollama remains the existing runtime path, and
the generic routing/privacy contracts do not require any cloud provider.
