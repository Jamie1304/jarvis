# v1 Functional Acceptance

Date: 2026-08-25
Suite: `v1-acceptance`
Fixture policy: deterministic, repository-owned, randomized capability/package IDs, no
external network, account, device, donor runtime, or product-specific adapter.

## Composition contract

The suite starts JARVIS with `ApplicationRuntime.create(Settings(...))`. Lower-level
deterministic scenarios use the explicit `RuntimeTestFixture` seam for synthetic
package/discovery/activation observations; those scenarios are deterministic contract
evidence only, not production-composition proof. The composition root still constructs and owns the
`PermissionBroker`, `ToolRegistry`, PlanningEngine, lifecycle store, activation service,
effect-attestation store, acquisition coordinator, setup/provisioning services, opportunity
engine, attention policy, trace/golden stores, ArtifactStore, and optional services.

The production-growth and compensation scenarios deliberately supply no `RuntimeTestFixture`.
They register only deterministic trusted application test inputs through the normal
composition boundary (a fake model, and a generic synthetic file tool), then use the production
`ProviderRouter` -> `AgentLoop` -> `CapabilityFactory` -> package review/sandbox/certification
-> Setup/Provision -> Shadow/Canary -> activation/hot-load -> verification path. The fake
provider and file tool are test inputs; they are not production capability adapters. The
compensation scenario additionally uses the runtime-owned sealed `EffectStateObserverRegistry`
and generic bounded `FilesystemStateObserver`; no callback or package assertion supplies trusted
state or verification.

The suite does not call a standalone `CapabilityFactory` to certify or activate a package and
does not write `ACTIVE` directly. The anti-shortcut assertions check that the production
coordinator and runtime-owned lifecycle store are used.

The production-composition evidence is intentionally narrower and explicit:

- Security-blocked opportunity state is a terminal production lifecycle
  boundary: passive same/new evidence, expiry, restart, proposal, acceptance,
  decline, and ordinary preparation cannot reopen it. Focused OpportunityEngine
  regressions exercise the durable state and fail-closed prepare guard; a future
  trusted security-reconsideration operation would be a separate contract.

- `test_v1_production_composition_acquires_randomized_capability_and_restores_it` uses
  `Settings(environment="production")`, a registry-registered synthetic provider, no
  `RuntimeTestFixture`, and the concrete generator, package store/runtime, sandbox,
  reviewer/certifier, setup/provisioning, staged activation, hot-load, registry, verifier,
  lifecycle-restorer, trace, and ComponentDoctor services created by `ApplicationRuntime`.
  It proves the generic BUILD path, typed semantic action selection/execution through
  `PlanningEngine -> ToolRegistry -> PermissionBroker`, schema-valid package output,
  VerificationEngine completion, and exact restart restoration; it does not claim that an
  arbitrary external package or an adopted machine binary is universally safe.
- The same test exercises `CapabilityOpportunityEngine.prepare()` through the production
  coordinator. Its intentionally oracle-less generated action fails certification closed and
  remains `FAILED`, proving evidence alone cannot produce `READY_TO_PROPOSE`. Repeating ordinary
  evidence observation preserves `FAILED/FAILED`, the failure decision, and the diagnostic error,
  proving passive observation is not an implicit retry; successful
  certified preparation remains proposal-ready in the dedicated opportunity tests. An
  acquisition and preparation-provider exceptions are durably `FAILED`; proposal and
  acceptance revalidate the preparation state, including after restart. Preparation does not grant authority or
  activate a package.
- `test_v1_acceptance_production_composed_compensation_uses_trusted_observer` is the
  production-composed compensation/verification proof. It uses the sealed application-owned
  observer registry after restart; the fixture callback path is compatibility-only.

All other rows that cite fixture helpers remain `PROVEN_DETERMINISTICALLY`; they must not be
read as evidence that a fresh production runtime has a configured browser companion, MCP
server, physical voice/camera/audio path, desktop renderer, or adopted external installation.

## Scenario results

| # | Scenario | Result | Evidence |
|---:|---|---|---|
| 1 | TaskController -> PlanningEngine normal task | PASS | `test_v1_acceptance_composed_runtime_and_task_controller` |
| 2 | Unknown capability through CapabilityAcquisitionCoordinator | PASS | `test_v1_acceptance_unknown_capability_certifies_activates_verifies_and_restarts` |
| 3 | Existing capability reuse | PASS | `test_v1_acceptance_existing_reuse_and_adoption_before_install` |
| 4 | Adopt before install | PASS | Same test; compatible synthetic installation is adopted through trusted identity/provenance evidence and the generator remains unused |
| 5 | Static review and certification | PASS | Package-specific `PackageCertificationPlan` runs declared actions in the native sandbox, validates output schemas, and requires trusted semantic evidence; wrong-output and missing-oracle regressions fail closed |
| 6 | Shadow trusted no-effect attestation | PASS | Activation fixture records `SUPPRESSED`, `dispatched=False` through runtime-owned store |
| 7 | Canary trusted effect attestation | PASS | Canary records one bounded trusted dispatch and independent verification |
| 8 | ACTIVE persistence/restart | PASS | The composed runtime restores the exact package/version/hash, safely reattaches the active runtime, and reuses the capability after a fresh `ApplicationRuntime.create` |
| 9 | CapabilityRegistry restoration | PASS | A trusted lifecycle restore seam rehydrates the registry projection only after exact package/certification/hash validation |
| 10 | Goal persistence of intent | PASS | GoalSupervisor state is loaded after restart with the original goal ID |
| 11 | Opportunity autonomous safe preparation | PASS | Composed OpportunityEngine prepares without granting authority |
| 12 | Attention restart/expiry | PASS | Urgent unresolved item survives a fresh runtime; policy remains durable |
| 13 | Vault metadata/scoped use through production path | PASS | `test_v1_acceptance_vault_uses_runtime_owned_typed_credential_broker` reaches a local authenticated service through the runtime-owned `CredentialBroker`/HostProxy path; exact identity, package, destination, workspace, scope, expiry, and no-secret representation are asserted |
| 14 | Provisioning durable resume | PASS | Runtime-owned `SQLiteProvisioningStore` preserves verified/recovering action outcomes; restart re-inspects reality and never blind-replays `UNKNOWN_OUTCOME` |
| 15 | Setup resume/adoption | PASS | Runtime-owned `SQLiteSetupStore` preserves setup decisions/steps and `AdoptionAttestation`; rerun re-inspects the candidate and avoids duplicate installation |
| 16 | EnvironmentDiscovery lifecycle | PASS | Runtime-owned discovery service consumes a synthetic local observation and exposes evidence only |
| 17 | BrowserSemanticBridge production broker | PASS | Runtime composition installs the broker adapter; the fake backend is reached only through the bridge or the call fails closed |
| 18 | Trace attached across canonical boundaries | PASS | `test_v1_acceptance_composed_runtime_and_task_controller` and `test_v1_acceptance_unknown_capability_certifies_activates_verifies_and_restarts` assert goal/task lineage, plan/step/completion, acquisition package metadata, trusted attestation references, and stable trace reload after restart |
| 19 | EffectPreview/Compensation integration | PASS | `test_v1_acceptance_production_composed_compensation_uses_trusted_observer` uses no RuntimeTestFixture: the runtime-owned sealed observer registry and generic filesystem observer revalidate the exact target/state after restart, compensation executes through PlanningEngine/PermissionBroker, and hash-only trusted evidence reaches VerificationEngine; the callback-based case also remains covered for compatibility |
| 20 | UI simulation evidence attached to UI certification | PASS | `test_v1_acceptance_ui_certification_is_bound_through_composed_activation` runs the runtime-owned harness against a randomized package, captures ArtifactStore evidence, certifies the attestation, stages Shadow/Canary/Active, persists the digest, and restores it after restart |
| 21 | Presence/Presentation service composition | PASS | Runtime-owned PresenceProjection and ArtifactStore-backed PresentationSurface are exercised |
| 22 | ResourceGovernor admission for background/model work | PASS | Runtime-owned governor returns bounded `ALLOW`/`REDUCE` decision for a background request |
| 23 | WorkflowTemplate/Procedure persistence | PASS | `test_v1_acceptance_workflow_and_procedure_state_survives_runtime_restart` proves versioned template lookup, PlanValidator -> PlanningEngine execution, trusted-evidence repeated learning, scoped context hints, candidate linkage, and restart restoration |
| 24 | Golden Workflow gate | PASS | Runtime-owned GoldenWorkflowStore/Service requires and passes a synthetic integration-update gate |
| 25 | Trusted UpdatePreview | PASS | ControlledSelfUpdate derives and validates the exact candidate/diff/gate/rollback preview |
| 26 | Recovery/LKG authenticated record | PASS | Production composition verifies the authenticated record after restart; `tests/test_recovery_authority.py` covers exact application/manifest hashes, transaction, installation, schema compatibility, monotonic generation, tamper, missing-backend, failed-health, promotion, and future-schema behavior |
| 27 | Safe Mode composition | PASS | Three synthetic failed starts cause the composed runtime to enter Safe Mode without creating the normal container |
| 28 | Graceful shutdown/restart | PASS | Container shutdown is idempotent and the application can be restarted from the same data root |
| 29 | Adoption identity/provenance | PASS | Synthetic tests bind stable file identity, content hash, signer status, independent dependency provenance, exact scope/expiry, and reject reparse, stale, changed, forged, or unavailable evidence |
| 30 | Complete production capability growth | PASS | `test_v1_production_composition_acquires_randomized_capability_and_restores_it` uses no fixture, reaches generated package ACTIVE through the real AppContainer/certification/attestation path, selects the randomized typed action through PlanningEngine/ToolRegistry/PermissionBroker, validates output with VerificationEngine, and restores/reuses the exact package/version/hash after restart |

## Earlier composition evidence

The focused acceptance file contains 23 deterministic tests covering the rows above; the
matrix has 30 scenarios because several tests prove multiple boundaries. The production
growth proof enters through `GoalSupervisor.start()`, rather than calling the acquisition
coordinator directly, and the supervisor then delegates the ordinary task to the canonical
`PlanningTaskController`/`PlanningEngine` path.
The registered system-test command is:

```text
  python scripts/run_system_tests.py --suite v1-acceptance
```

Recorded checks (current mutable tree, 2026-08-26):

- `v1-acceptance`: PASS, 23 passed; run `bb5e1a37-cd96-4354-93a8-8e26f62aba5e`;
- `deterministic-workflows`: PASS, 26 passed; run `fdb95a5b-e2f0-4488-8aaa-fb2abdabf5fe`;
- `deterministic-permissions`: PASS, 72 passed, 1 skipped; run
  `d59ed34e-36be-41d2-b306-89116ab82c5a`;
- `quality.py` with explicit `JARVIS_ENVIRONMENT=test`: PASS, 1,446 passed and
  7 skipped; Ruff format/check, mypy, and 90% combined statement/branch
  coverage passed. The default local run is blocked on this host by Windows
  Credential Manager Win32 error 8 during secure recovery-key creation; no
  plaintext fallback is used;
- the production-growth test is a native Windows AppContainer check and is still distinct
  from the deterministic fixture scenarios.

The suite distinguishes deterministic composition proof from platform evidence. Active
restoration, registry projection, provisioning resume, setup rerun, crash-loop Safe Mode, and
the complete generic package acquisition path are proven through `ApplicationRuntime.create`;
changed package hashes fail closed. The fixture lifecycle restore callback remains a
deterministic local package-resolution seam, not a donor runtime or a second lifecycle
authority.

## R4O mutable revalidation (2026-08-30)

This later mutable revalidation supersedes the dated counts in the preceding
historical evidence section; it does not create Candidate 12 or claim exact-SHA
CI. The same default application composition path passed all 23 deterministic
acceptance tests directly in 317.43 seconds. The hardened controlled runner
also passed the suite twice in fresh owned Windows Job processes:

- run `4caae60c-2d7f-4915-ba50-c19483864d64`: 23 passed;
- run `56cddff2-2315-452f-badb-553da150e7f0`: 23 passed.

The controlled-run records identify immutable Git HEAD Candidate 11 because a
mutable working tree has no commit SHA of its own. They nevertheless executed
the reviewed mutable files in this checkout. They are local prefreeze evidence,
not Candidate 11 CI evidence and not Candidate 12 evidence.

R4O specifically revalidated the adjacent release-critical boundaries:

- `ARCHIVED` or `SECURITY_BLOCKED` durable opportunity data canonicalizes to
  `ARCHIVED / SECURITY_BLOCKED / NONE`, including after SQLite restart; ordinary
  observation, expiry, decline, proposal, acceptance, and preparation cannot
  reopen it.
- `UNKNOWN_OUTCOME` canonicalizes to `ASSESSING / UNKNOWN_OUTCOME / NONE` and
  ordinary preparation cannot replay it. Explicit `FAILED / FAILED` retry
  remains distinct.
- The controlled runner requires coherent final pytest/structured output,
  treats cancellation/timeout and cleanup errors as non-pass, bounds live
  output, and uses exact owned Windows Job cleanup without process-name-wide
  termination.

Related mutable evidence: deterministic workflows passed 26, deterministic
permissions passed 72 with one documented local symlink/junction capability
skip, security/trusted-core regressions passed 447 with the same local skip,
self-expansion regressions passed 156, and focused opportunity/runner/native
tests passed 112. The direct and controlled acceptance suite continues to use
randomized generic capability names and does not add a product-specific
adapter or donor runtime.

## Evidence classification

The opt-in adoption check separately exercises the native Windows file identity
and Authenticode status providers against the configured local Python
executable. It is observation-only and does not claim that a valid signature
makes an executable safe.

`PROVEN_DETERMINISTICALLY`: task/control ownership, capability certification and staged
activation, exact active restoration, registry projection restoration, provisioning outcome
durability and UNKNOWN_OUTCOME recovery, setup persistence/adoption rerun, authenticated
recovery/LKG selection, recovery crash-loop Safe Mode entry, and the existing rows marked
PASS above.

`REQUIRES_REAL_WINDOWS_EVIDENCE`: Windows process/token/AppContainer or Job Object guarantees,
reparse/ACL/TOCTOU behavior, physical voice/camera/audio devices, browser companion/accessibility
behavior, desktop trusted approval UI, and measured model/resource behavior. This run makes no
hardware or Windows claim.

## R3 evidence still required

This local suite does not certify Windows-specific behavior. R3 must run owned-process and
hardware/manual evidence for:

- Windows integration process token/Job Object containment, inherited handles, ACL/reparse and
  process-tree cleanup;
- microphone/camera/audio devices, wake/PTT, persistent TTS output, and barge-in timing;
- browser companion availability and real accessibility/document-generation behavior;
- actual desktop trusted approval presentation and Safe Mode UI;
- model/provider/resource behavior under measured CPU, GPU/VRAM, battery, and disk pressure.

The rows above are deterministic PASS results. The separately listed platform/manual items
remain `NOT_EXECUTED`/`NOT_PROVEN` until the owned Windows and hardware evidence is collected;
no release authorization is implied by this record.
