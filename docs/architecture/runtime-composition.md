# Runtime composition and service ownership

**Status:** v1 composition contract
**Updated:** 2026-08-24

`ApplicationRuntime` is the composition root. `RuntimeContainer` owns the
application services it creates and owns their shutdown. UI adapters receive
application interfaces; they do not construct `PermissionBroker`, vaults,
planning engines, lifecycle stores, providers, or hardware resources.

This document records the production boundary for the current v1 baseline. A
service being present in the Python package does not make it a v1 capability.
Optional services are either configured explicitly or remain unavailable.

## Service classification

| Service | Classification | One production owner/path | Availability boundary |
|---|---|---|---|
| `PermissionBroker` / `PolicyEngine` | `PRODUCTION_OWNED` | `RuntimeContainer.permission_broker` | Always created before tools and planning; no UI or model-owned broker |
| `CredentialVault` / `CredentialBroker` | `PRODUCTION_OWNED` | `RuntimeContainer.credential_vault` plus `.credential_broker`, metadata in `credentials.sqlite3` | Integrations receive only exact opaque refs; PermissionBroker authorizes before trusted Vault resolution; unavailable backend fails closed |
| `PlanningEngine` / `TaskController` | `PRODUCTION_OWNED` | `planning.sqlite3` and `RuntimeContainer.task_controller` | Canonical durable task/control plane |
| `GoalSupervisor` | `PRODUCTION_OWNED` | `goals.sqlite3` and `RuntimeContainer.goal_supervisor` | Supervises intent and acquisition; delegates execution to PlanningEngine |
| `CapabilityAcquisitionCoordinator` | `PRODUCTION_OWNED` | `RuntimeContainer.capability_acquisition` | One coordinator delegates gap, discovery, build, certification and activation |
| `CapabilityRegistry` / `CapabilityFactory` | `PRODUCTION_OWNED` | `RuntimeContainer.capability_registry` / `.capability_factory` | Factory output is inactive until trusted certification and activation |
| `PackageReviewer` / `PackageCertifier` | `PRODUCTION_OWNED` | `RuntimeContainer.package_reviewer` / `.package_certifier` | Generated packages cannot write review or certification evidence |
| `ProvisioningEngine` / `SetupConductor` | `PRODUCTION_OWNED` | `RuntimeContainer.provisioning_engine` / `.setup_conductor` | Default provider/handler is explicit unavailable; no arbitrary shell fallback |
| `CapabilityLifecycleStore` | `PRODUCTION_OWNED` | `capability-lifecycle.sqlite3` and `RuntimeContainer.capability_lifecycle_store` | Sole durable package/certification/activation lifecycle truth |
| `PackageActivationService` / `HotLoadManager` | `PRODUCTION_OWNED` | `RuntimeContainer.package_activation` / `.hot_load` | Activation uses the same lifecycle store; fresh versions do not inherit ACTIVE |
| `EnvironmentDiscoveryService` | `PRODUCTION_OWNED` | `RuntimeContainer.environment_discovery` | Evidence-only service; v1 default has no discovery providers and reports degraded |
| `BrowserSemanticBridge` / `BrowserBrokerAdapter` | `PRODUCTION_OPTIONAL` | Runtime-created only when an explicit supported backend is supplied | Missing companion/backend is unavailable/degraded; no uncontrolled fallback |
| `AgentSessionStore` / voice binding | `PRODUCTION_OWNED` / `PRODUCTION_OPTIONAL` | `sessions.sqlite3`; live `VoiceRuntime` is configured separately | Session records are production-owned; voice hardware/providers are opt-in |
| `TraceService` / `TraceStore` / execution trace | `PRODUCTION_OWNED` | Runtime-owned event projection over `trace.sqlite3` (schema v2) and `RuntimeContainer.trace_service`/`.trace_store` | Derived sanitized observability only; never completion, credential resolution, or authority |
| `SQLiteWorkflowProcedureStore` | `PRODUCTION_OWNED` | `workflow-procedures.sqlite3` and `RuntimeContainer.workflow_procedure_store` | Sole durable owner for template versions, sanitized learning state, linkage, and user lifecycle |
| `EffectPreview` / `CompensationService` | `PRODUCTION_OWNED` | `RuntimeContainer.compensation_service` over `compensation.sqlite3`, the shared PlanningEngine/registry/broker/verifier, and the original-effect binding | One-step compensation is a normal PlanningEngine task; lifecycle metadata is durable, approval is fresh, and independent evidence is required |
| `PresenceProjection` | `PRODUCTION_OWNED` | `RuntimeContainer.presence_projection` | Derived from EventBus; never task, permission, or runtime truth |
| `PresentationSurface` | `PRODUCTION_OWNED` | `RuntimeContainer.presentation_surface` | Typed artifact/declarative surface; physical renderer is optional |
| `UISimulationHarness` | `PRODUCTION_OPTIONAL` | Package-scoped certification service, created only for a package test | No global harness is needed; simulated actions have no real effects |
| `ResourceGovernor` | `PRODUCTION_OWNED` | `RuntimeContainer.resource_governor` | Shared by provider routing, CapabilityFactory and startup warmup; consumers may decline when no governor is supplied in isolated tests |
| `WorkflowTemplateRegistry` | `PRODUCTION_OWNED` | `RuntimeContainer.workflow_templates` | Template instantiation produces a proposed plan for PlanningEngine |
| `ProcedureBank` | `PRODUCTION_OWNED` | `RuntimeContainer.procedure_bank` over `workflow-procedures.sqlite3` | Candidate learning is a durable proposal boundary, not an execution engine; only trusted canonical evidence and normal validation can advance linkage |
| `CapabilityOpportunityEngine` | `PRODUCTION_OWNED` | `opportunities.sqlite3` and `RuntimeContainer.opportunity_engine` | Preparation may be autonomous; accepted activation uses the acquisition coordinator |
| `AttentionPolicy` | `PRODUCTION_OWNED` | `attention.sqlite3` and `RuntimeContainer.attention_policy` | Delivery is separate from permission authority; important items survive restart |

`PRODUCTION_OPTIONAL` means the application owns the construction boundary and
the unavailable state. It does not mean the resource is constructed at every
startup. `TEST_ONLY` means the contract is intentionally outside the v1
production activation path and must not be mistaken for a missing owner.

## Startup ordering

The composition root follows this dependency order:

1. Validate trusted project and app-data paths, recovery state, crash-loop
   policy, and configuration.
2. Open the EventBus, audit sink, recovery store, and secure credential
   metadata store. Construct the single `CredentialBroker` wrapper; a secure
   credential backend is never replaced by plaintext.
3. Construct the single `PolicyEngine` and `PermissionBroker`, then construct
   the `ToolRegistry` with that broker. Tool registration is sealed before
   planning or external package lifecycle services run.
4. Open the authoritative planning, memory, User Model, knowledge, session,
   artifact, trace, automation, goal, setup, effect-attestation, compensation, lifecycle,
   opportunity, attention, and golden-workflow stores.
5. Reconcile durable task and lifecycle state before exposing READY. A changed
   package hash, invalid certification, future schema, or incomplete lifecycle
   transaction remains failed/recovering rather than becoming ACTIVE.
6. Construct PlanningEngine, TaskController, GoalSupervisor, capability
   acquisition, review/certification, setup/provisioning, activation/hot-load,
   verification, compensation, health/doctor, opportunity, and attention
   services using those already-owned dependencies.
7. Construct derived PresenceProjection and PresentationSurface. Presence
   subscribes to canonical events only; the subscription is cancelled by the
   same container that owns it.
8. Register generic application projections, test-drive checks, and startup
   warmup. Warmup is non-blocking and is admitted through the shared
   ResourceGovernor.
9. Construct optional browser services only for an explicitly supplied trusted
   backend. Voice, camera, and other expensive hardware are not created merely
   because their modules exist.
10. Publish READY only after required stores and trusted services are open.

Safe Mode stops before normal privileged/autonomous service construction. It
retains the recovery/security report and can expose a safe diagnostic UI. It
does not create a normal broker, provider, planner, package activation path,
voice/camera resource, or scheduler effect path.

## Optional service health

`RuntimeContainer.service_status()` and `service_statuses()` expose bounded
application-owned availability views. In the default configuration:

- voice is `UNAVAILABLE` when voice providers are not configured;
- camera is `UNAVAILABLE` when camera providers are not configured;
- browser is `UNAVAILABLE` when no supported trusted companion/backend exists;
- environment discovery is `DEGRADED` when the evidence service has no sources;
- the typed presentation and package-scoped UI simulation contracts are
  available even when no physical renderer is installed.

These states never alter `PermissionBroker` policy and never trigger an unsafe
fallback. A configured optional service may still fail later and must degrade
through its own health boundary.

## Shutdown ownership

`RuntimeContainer.aclose()` is the only normal shutdown owner for composed
resources. It holds an async close lock, marks the container closed before
closing children, cancels and joins startup/event subscription tasks, then
closes each resource at most once by object identity. The resource list is
deduplicated so an injected object shared by two services is not closed twice.

`ApplicationRuntime.aclose()` owns the container reference and is itself
idempotent. Startup failures close partially-created stores; a failed startup
never hands ownership of a half-built container to UI code.

## UI boundary

The desktop/application layer may call `TaskController`, memory controls,
Control Center, trusted permission surfaces, presentation queries, and other
application services. It must not import or instantiate security/runtime
authorities directly. In particular, UI cannot construct a new broker, vault,
planning engine, lifecycle store, provider, or browser low-level object.

## Composition regression evidence

`tests/test_runtime.py` proves the canonical runtime owns one broker, one
credential vault, one capability lifecycle store, one acquisition path, and
the derived presentation/effect services. It also proves that the default
voice, camera, and browser states are safe unavailable states, that optional
health is exposed, that the presence/presentation services are application
owned, and that shutdown remains idempotent.

The runtime tests also cover crash-loop Safe Mode. No hardware or real browser
acceptance is implied by these composition tests.

## Validation

- `.venv\\Scripts\\python.exe -m pytest tests/test_runtime.py -q`: **5 passed**
- `.venv\\Scripts\\python.exe scripts/run_system_tests.py --suite deterministic-workflows`:
  **26 passed**
- `.venv\\Scripts\\python.exe scripts/quality.py`: Ruff format/check, strict
  mypy, and the full suite **passed**; **1,335 passed, 6 skipped**, with 90%
  combined statement/branch coverage. No coverage exclusion or security-test
  weakening was added in this composition change.

The system Python invocation of `python scripts/quality.py` cannot import the
repository's development tools on this host; the repository `.venv` was used
for the equivalent quality run above.
