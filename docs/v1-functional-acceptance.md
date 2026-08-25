# v1 Functional Acceptance

Date: 2026-08-25
Suite: `v1-acceptance`
Fixture policy: deterministic, repository-owned, randomized capability/package IDs, no
external network, account, device, donor runtime, or product-specific adapter.

## Composition contract

The suite starts JARVIS with `ApplicationRuntime.create(Settings(...))`. Test-only package,
discovery, activation, certification, and package-runtime observations enter only through
the explicit `RuntimeTestFixture` seam. The composition root still constructs and owns the
`PermissionBroker`, `ToolRegistry`, planning engine, lifecycle store, activation service,
effect-attestation store, acquisition coordinator, setup/provisioning services, opportunity
engine, attention policy, trace/golden stores, ArtifactStore, and optional services.

The suite does not call a standalone `CapabilityFactory` to certify or activate a package and
does not write `ACTIVE` directly. The anti-shortcut assertions check that the production
coordinator and runtime-owned lifecycle store are used.

## Scenario results

| # | Scenario | Result | Evidence |
|---:|---|---|---|
| 1 | TaskController -> PlanningEngine normal task | PASS | `test_v1_acceptance_composed_runtime_and_task_controller` |
| 2 | Unknown capability through CapabilityAcquisitionCoordinator | PASS | `test_v1_acceptance_unknown_capability_certifies_activates_verifies_and_restarts` |
| 3 | Existing capability reuse | PASS | `test_v1_acceptance_existing_reuse_and_adoption_before_install` |
| 4 | Adopt before install | PASS | Same test; compatible synthetic installation is adopted through trusted identity/provenance evidence and the generator remains unused |
| 5 | Static review and certification | PASS | Unknown-capability coordinator path invokes package review and all certification stages |
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
| 19 | EffectPreview/Compensation integration | PASS | `test_v1_acceptance_production_compensation_verifies_and_traces` uses the runtime-owned CompensationService, survives restart between the original effect and compensation, revalidates stale state, executes through PlanningEngine/PermissionBroker, persists lifecycle metadata, and requires independent VerificationEngine evidence |
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

## Current run

The focused acceptance test currently contains 21 deterministic tests covering the rows above.
The registered system-test command is:

```text
python scripts/run_system_tests.py --suite v1-acceptance
```

Recorded checks:

- `v1-acceptance`: PASS, 21 passed; run `0ac58287-a1c2-4e88-a3dc-a37295fc6298`;
- `deterministic-workflows`: PASS, 26 passed; run `a6ccfbfe-9d5d-4079-b7da-62dae9dda1cb`;
- `deterministic-permissions`: PASS, 72 passed, 1 skipped; run `01b7e1f3-408c-4691-a230-8fe0981fab2b`;
- `quality.py`: PASS, 1,360 passed and 6 skipped, 90% combined statement/branch coverage;
  formatting, ruff, and mypy passed.

The suite distinguishes deterministic composition proof from platform evidence. Active
restoration, registry projection, provisioning resume, setup rerun, and crash-loop Safe Mode
are now proven through `ApplicationRuntime.create`; changed package hashes fail closed. The
trusted lifecycle restore callback is a deterministic local package-resolution seam, not a
donor runtime or a second lifecycle authority.

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

The remaining `NOT_PROVEN` rows above require implementation or a separately accepted v1 scope decision
before v1 can be called complete. No release authorization is implied by this record.
