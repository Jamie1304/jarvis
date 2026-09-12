# Production capability growth

**Status:** mutable R4 remediation baseline

JARVIS remains a minimal adaptive core. A normal unknown capability does not
require a product-specific branch in core and no donor framework is a runtime
dependency or authority.

## One production path

`ApplicationRuntime.create(Settings(environment="production", ...))` owns the
following generic graph:

```text
GoalSupervisor
  -> CapabilityAcquisitionCoordinator
     -> CapabilityRegistry / CapabilityGapDetector
     -> EnvironmentDiscoveryService (evidence only)
     -> SolutionDiscovery (DISCOVER / ADOPT / REUSE / BUILD)
     -> CapabilityFactory
        -> ProviderRouter -> ProviderRegistry -> bounded AgentLoop
        -> AgentRuntimeCapabilityGenerator
     -> PackageReviewer
     -> PackageCertifier
     -> ProductionSandboxRunner / Windows AppContainer
     -> SetupConductor -> typed ProvisioningEngine
     -> PackageActivationService
        -> trusted Shadow/Canary effect attestations
        -> HotLoadManager / registry projection
     -> VerificationEngine
```

The coordinator delegates. It is not a second planner, task engine,
permission broker, certifier, or verifier. `PlanningEngine` remains the only
durable task/control authority; `PermissionBroker` remains mandatory for every
effectful capability; `VerificationEngine` does not accept model or package
claims as proof.

Production `SolutionDiscovery` also receives a generic
`EnvironmentAdoptionCandidateProvider`. It translates bounded local discovery
observations into advisory candidates only; it does not authenticate or adopt
them. `SetupConductor` re-inspects the exact candidate through the trusted
adoption identity/provenance policy and performs the TOCTOU check before any
attestation. If no compatible candidate is found, the factory continues to
REUSE/BUILD. A local runtime observation is not offered as a candidate for an
unrelated capability.

`CapabilityFactory` owns its ResourceGovernor reservation with one
`try/finally` release boundary. Successful and bounded non-exceptional results
release as `COMPLETE`; exceptions release as `CRASH`; no terminal path can
leave an active reservation or release it twice.

Opportunity preparation preserves evidence for failed or uncertain work, but
evidence does not imply readiness. Only a certified successful preparation is
`READY_TO_PROPOSE`; waiting, failed, security-blocked, and unknown-outcome
results remain non-ready and cannot be accepted as a proposal.

## Model and generation boundary

The configured provider is resolved by `ProviderRegistry` and admitted by
`ProviderRouter` with local/structured-output policy and ResourceGovernor
admission. The bounded `AgentLoop` receives only the request and immutable
security context. It does not receive `PermissionBroker`, `CredentialVault`,
activation, lifecycle, or trusted audit objects.

The model can propose a bounded JSON package specification. The trusted
application validates it and creates an inactive generic package candidate.
Malformed output, unavailable provider, or a route that cannot satisfy the
policy fails closed as a waiting/degraded condition. No model output can write
certification, activation, permission, or verification state.

## Package ownership and runtime

`ProductionPackageStore` owns immutable package metadata and source snapshots
under the external `packages/` data root. Each package is addressed by
identity/version/hash, source entry hashes are checked, package paths reject
traversal/reparse components, and package data is not stored in Trusted Core.
The store is not the lifecycle authority: certification and activation are
durably owned by `SQLiteCapabilityLifecycleStore`.

On Windows, certified executable package code is launched only by the native
capability-free AppContainer path with scoped read/execute ACLs, a disposable
write root, an explicit IPC handle list, and Job Object ownership. The child
receives typed bounded JSON IPC and no broker, vault, trusted audit writer, or
runtime container object. If the mandatory native boundary cannot be
established, certification/activation fails closed; it is not downgraded to a
same-user unrestricted process.

The generated worker exposes only its diagnostics (`health`, `inspect`, and
staged activation probes) plus the exact semantic actions declared in its
validated `CapabilityActionSpec` records. Each declared action is wrapped by
the application-owned `GeneratedCapabilityToolAdapter`; input and output
schemas are strict, and the package process never receives ToolRegistry or
PermissionBroker authority. Effectful actions must declare broker permissions
and still use the normal trusted host/broker path. A package callback cannot
create a trusted effect attestation or self-promote.

The application obtains the activation-only registration port from the sealed
`ToolRegistry` during composition. `PackageActivationService` supplies the
exact package, certification, and durable ACTIVE lifecycle evidence; the port
rejects unsealed registration, non-adapter tools, identity/hash mismatches,
collisions, and replacement of built-in tools. Quarantine/deactivation removes
the generated action projection.

## Activation and restart

The package lifecycle is:

```text
candidate -> review -> sandbox -> certification -> setup/provision
          -> CERTIFIED -> SHADOW -> CANARY -> ACTIVE -> verify
```

Shadow broker attestations prove suppressed dispatch and zero trusted effects.
Canary promotion requires trusted broker attestations and independent
VerificationEngine evidence. A fresh version does not inherit activation.

After restart, the runtime-owned `CapabilityLifecycleRestorer` loads the exact
lifecycle row and resolves only the recorded package ID, version, and hash. It
revalidates package source hashes, certification fingerprints, UI simulation
binding, configuration metadata, adoption attestation when present, and the
mandatory AppContainer status before calling `PackageActivationService.restore`.
Only a valid ACTIVE row starts the real package runtime and rebuilds the
registry projection. DEGRADED is projected as unavailable/degraded without
auto-promotion; SHADOW and CANARY are reattached as staged lifecycle sessions
without replaying effects. Missing content, a changed hash, stale
certification, unavailable AppContainer, invalid configuration, or failed
startup is contained by a durable QUARANTINED transition for that package;
JARVIS remains available. The restorer also rehydrates the trusted behavior
baseline reference into `CapabilityHealthService`, so ComponentDoctor and
behavior drift see the actual restored lifecycle state. Registry and hot-load
state are projections/caches, not competing durable authorities.

`RuntimeContainer.capability_lifecycle_restorer` is the sole production
restoration path. The older `RuntimeTestFixture.lifecycle_restore` callback is
retained only for deterministic fixture compositions and is never consulted by
`Settings(environment="production")`.

## Deterministic proof

`tests/test_v1_acceptance.py::test_v1_production_composition_acquires_randomized_capability_and_restores_it`
uses no `RuntimeTestFixture`. It supplies only a randomized synthetic provider
and local package source through the production `ProviderRegistry`, then proves
generation of a typed semantic action, package storage, review, native sandbox
probe, certification, staged activation, trusted registration, selection by
`PlanningEngine` through `ToolRegistry` and `PermissionBroker`, package-runtime
execution, schema validation, `VerificationEngine` completion, and restart
reuse with a different input. Existing fixture tests remain explicitly
test-only observations and do not replace this path.

The test uses `TestOnlyInMemorySecretBackend` only as an explicit deterministic
test dependency. Normal production composition uses the Windows-backed
CredentialVault backend and never silently falls back to plaintext.

## Safe absence and optional services

No model/provider, unsupported sandbox, missing credential backend, or missing
typed provisioning authority produces an uncontrolled fallback. The capability
request remains waiting/degraded/failed at the named owner boundary. Voice,
camera, browser, and other expensive hardware resources remain optional and do
not alter authority policy or prevent the rest of the runtime from starting.
