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

The v1 generated worker is observation-only. A future effectful package must
declare a typed capability and use the normal trusted host/broker path. A
package callback cannot create a trusted effect attestation or self-promote.

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
uses no `RuntimeTestFixture`. It supplies only a synthetic provider through the
production `ProviderRegistry`, then proves generation, package storage, review,
native sandbox probe, certification, staged activation, trusted attestation,
ACTIVE projection, safe local invocation, and restart restoration. Existing
fixture tests remain explicitly test-only observations and do not replace this
path.

The test uses `TestOnlyInMemorySecretBackend` only as an explicit deterministic
test dependency. Normal production composition uses the Windows-backed
CredentialVault backend and never silently falls back to plaintext.

## Safe absence and optional services

No model/provider, unsupported sandbox, missing credential backend, or missing
typed provisioning authority produces an uncontrolled fallback. The capability
request remains waiting/degraded/failed at the named owner boundary. Voice,
camera, browser, and other expensive hardware resources remain optional and do
not alter authority policy or prevent the rest of the runtime from starting.
