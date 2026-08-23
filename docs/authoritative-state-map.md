# JARVIS authoritative state map

**Status:** v1 baseline  
**Updated:** 2026-08-23

This document defines the ownership rule for durable truth:

> Every durable domain has exactly one authoritative store and owner. Derived
> projections, caches, events, indexes, and UI models may exist, but they may
> not decide or overwrite the domain's truth.

Future runs must update this map before introducing a new durable domain, store,
migration, recovery rule, or competing projection.

## Current ownership map

| Domain | Authoritative owner/store | Derived or secondary data | Current status and boundary |
|---|---|---|---|
| Task, plan, step, budget, retry, operation reservation | `PlanningEngine` over `SQLitePlanningStore` (`planning.sqlite3`) | `ApplicationStateMachine`, lifecycle audit, typed events, `TaskController` result views | IMPLEMENTED_AND_WIRED. Planning records are the only task-control truth. Writes of task/plan versions are atomic. |
| Plan inspection, user edits, and checkpoint revisions | `PlanningEngine` + `PlanValidator` over the same `SQLitePlanningStore` | Typed `PlanInspection`, `PlanRevision`, UI projections, lifecycle audit | IMPLEMENTED_AND_WIRED. Edits create immutable revisions; no second planner exists. Effect-fingerprint changes invalidate unconsumed broker authority, while confirmed evidence alone may be inherited by a checkpoint branch. |
| Application/task lifecycle projection | `ApplicationStateMachine` over `SQLiteStateStore` (`state.sqlite3`) | UI state, transition/event consumers | IMPLEMENTED_AND_WIRED as a rebuildable projection. It must not decide planning completion or authorization. |
| Permission policy | `PolicyEngine` and trusted broker composition | Policy evaluations and permission events | IMPLEMENTED_AND_WIRED. Policy rules are code/configuration authority; model text and events cannot modify them. |
| Approval request, receipt, remembered grant | `PermissionBroker` in the current process | Audit records, approval events, UI request views | PARTIAL DURABILITY. Exact task/tool/action/argument fingerprint, permission, normalized scope, identity, expiry, and consumption are enforced in the broker. Approval state is process-local; restart intentionally invalidates pending approval and requires a fresh request. Receipts are never persisted or replayed. |
| Audit | Runtime-owned `SQLiteAuditSink` (`audit.sqlite3`) | Logs, event observations | IMPLEMENTED_AND_WIRED. Permission decisions and outcomes are append-only secret-safe records; planning lifecycle records are separate audit entries. Audit is evidence, not task or permission authority. |
| Episodic and long-term memory | Runtime-owned `SQLiteMemoryStore` (`memory.sqlite3`) through memory services | Retrieval hits, conversation context, system-memory views | IMPLEMENTED_AND_WIRED. Memory cannot authorize, complete tasks, or become instructions merely because it is retrieved. |
| Conversation context | `ConversationContextService` (process-local) | UI conversation views, provider requests | IMPLEMENTED as transient context. It is not long-term memory or task truth. |
| Execution sessions | `AgentSessionStore` over `sessions.sqlite3` | Provider requests, voice/session projections | IMPLEMENTED_AND_WIRED. Owns session identity, provider/model binding, context metadata, usage/cost, parentage, archive state, and synchronization status only; it cannot own task, goal, approval, or memory truth. |
| Project knowledge libraries | Generated project index plus `KnowledgeStore` | Search results and `ProjectSystemMemory` | PARTIAL. The generated index is the source artifact for the current local knowledge view, but it is derived from repository/docs sources and is not policy or task authority. Revision freshness must remain explicit. |
| Runtime readiness and startup security | `ApplicationRuntime` and `StartupSecurityValidator` | Health API, runtime status, security report | IMPLEMENTED_AND_WIRED. Readiness is derived from validated configuration and successfully opened stores; health cannot enable capabilities. |
| Typed coordination events | `InMemoryEventBus` | Subscriber queues, metrics, UI observations | IMPLEMENTED but intentionally non-durable. Events describe facts and never grant permission, change policy, or replace an owner store. |
| Artifacts | `ArtifactStore` over the app-owned `artifacts/` content directory and `artifacts.sqlite3` metadata store | Opaque references, event observations, and future Trace, PresentationSurface, Knowledge-import, and Backup projections | IMPLEMENTED_AND_WIRED. `ArtifactStore` is the sole authoritative owner of artifact metadata and content. Immutable versions and derivations are workspace-scoped; evidence, memory, planning, audit, and credentials remain separate. Credential secrets are rejected. |
| Ambient presence and presentation | No new durable authority: canonical `EventBus`/runtime facts feed `PresenceProjection`; `PresentationSurface` owns only its current surface projection | `PresenceSnapshot`, `PresenceThemeManifest`, `UiStateSnapshot`, renderer/observer state, and verification results | IMPLEMENTED as derived application primitives. Presence cannot mutate task/runtime/permission truth. Presentation accepts typed artifact/package references or bounded declarative data, never arbitrary paths or executable UI, and `query_state()` is the actual surface observation used for verification. |
| Verification and outcome evidence | `VerificationEngine` evaluates immutable `VerificationPlan`/`EvidenceRecord` values; `PlanningEngine` remains the sole durable task/plan outcome authority | Bounded evidence records, verification levels, contradictions, stale observations, model-claim rejections, and diagnose/replan or user-confirmation dispositions | IMPLEMENTED as an observation boundary. Execution results and model claims are not proof; screen evidence comes from actual `PresentationSurface.query_state()`. No verification result grants authority, mutates plans, or creates a competing durable task truth. A future durable evidence store must be added here first. |
| Effect previews and compensation | Trusted capability preview metadata plus `CompensationExecutor` using `ToolRegistry`/`PermissionBroker`/`VerificationEngine`; `PlanningEngine` remains task authority | `EffectPreview`, compensation requests/results, state fingerprints, bounded prior state, Plan Studio projections, and trace observations | IMPLEMENTED as a non-authoritative contract. Model prose cannot create preview metadata; Undo is unavailable for irreversible/unknown effects without a real compensation definition. Stale baselines and failed/unknown/unverified compensation remain explicit; trace and Plan Studio are derived projections. |
| Human-readable execution trace and replay preparation | `ExecutionTrace` with optional versioned `TraceStore`; domain owners remain authoritative for the facts it projects | Rendered trace text, sanitized arguments/results, usage, artifact links, replay plans, and operator views | IMPLEMENTED as a derived observability projection. It records no prompts or hidden chain-of-thought, cannot grant authority or completion, never inherits approvals, and never executes replay. Simulation has zero effects; `UNKNOWN_OUTCOME` blocks replay until trusted reconciliation. |
| Long-horizon goal intent and supervision | `GoalSupervisorStore` for immutable `GoalIntent` and bounded supervisor coordination; `PlanningEngine` remains the linked task/plan authority | Goal status, acquisition/research evidence, examined alternatives, resource usage, task IDs, and recovery views | IMPLEMENTED as a coordination owner. Original user outcome survives plans, capability acquisition, retries, and restart. The supervisor cannot raise budgets, activate generated packages, grant permission, or replay active/unknown operations. Before `BLOCKED`, architecture/API/library/MCP/workaround/model/tool/infrastructure/user-input alternatives are examined. |
| Specialist worker contracts and delegation | `AgentRegistry`/`DelegationValidator`/`MultiAgentCoordinator`; no worker-owned durable truth | Worker profiles and model policy, tool/capability allowlists, filesystem/network scopes, data ceilings, delegation policy, typed output, cancellation, and aggregate evidence | IMPLEMENTED as bounded execution metadata and a derived orchestration result. Workers cannot expand parent ceilings, receive secret context, create approvals, access the registry/broker, or recursively spawn. `PlanningEngine` remains task authority; worker results remain untrusted until schema and goal-level evidence validation. |
| Capability/integration metadata | `CapabilityRegistry` for canonical capability manifests and `ToolRegistry`/`MCPExtensionManager` for executable adapter lifecycle | Capability discovery candidates, generated knowledge, MCP descriptions/results, environment observations, events | IMPLEMENTED as descriptive metadata plus adapter lifecycle. The registry does not execute or authorize; MCP servers remain untrusted, namespaced adapters only, cannot grant permissions, and cannot become a second authority. EnvironmentGraph is a credential-free observation projection. |
| Integration package boundaries, review, certification, and activation | Validated `IntegrationPackage`, native `GeneratedPackageReviewer`, `PackageCertifier`, and trusted `PackageActivationService`; package runtime registration remains the serialized `HotLoadManager` boundary; generated execution uses transient `SandboxProcess` instances | Package code manifests/source hashes, external user config/data, Vault references, rebuildable cache, diagnostics, migrations, provenance, review findings, certification records, UI simulation evidence, activation predictions/broker observations/canary effects/verification/decisions, sandbox IPC observations | IMPLEMENTED as contracts and review/certification/staged-lifecycle primitives. Package code is immutable/hash-bound; unreviewed source is manual-review-only; unsafe hooks, execution, deserialization, process/network bypasses, traversal, secret logging, and approval spoofing are rejected. `CertificationRecord` binds exact source/dependency/manifest/package hashes, permissions, test/audit/health/verification evidence, authority approval, rollback target, and Shadow/Canary eligibility. UI-bearing packages must have native `UISimulationHarness` evidence before certification. `PackageActivationService` is the sole activation authority: every version starts at CERTIFIED, Shadow has zero effects, Canary is bounded and rollback-aware, and generated packages cannot self-promote. CERTIFIED is distinct from ACTIVE; user config and package data remain external and preserved across update/uninstall; credentials are references only. |
| Sandbox host-proxy authorization and effects | Existing `PermissionBroker`/policy/audit plus trusted composition-owned `HostProxy` bindings; no proxy-specific durable store | Bounded proxy audit observations, untrusted network/file/action results, and sandbox lifecycle facts | IMPLEMENTED as a transient boundary contract. Exact package identity, manifest capability/action, scope, and broker receipt are required; no proxy state becomes a competing task, credential, artifact, or audit authority. |
| Provisioning plans and execution | `ProvisioningEngine` with injected typed providers; no provisioning-specific durable store yet | Provider reality observations, action results, broker/audit evidence, rollback outcomes | IMPLEMENTED as a transient coordinator. Exact plans/actions are immutable, providers inspect reality before effects, unknown outcomes recover rather than replay, and provisioning cannot become package/task/permission authority. A future durable execution store must be added to this map first. |
| Setup runs and adoption decisions | `SetupConductor` plus versioned `SQLiteSetupStore`/`InMemorySetupStore` | Setup inspections, adoption candidates, normalized decisions, step verification, and resumable setup state | IMPLEMENTED as setup coordination evidence. It does not own task/plan, permissions, credentials, audit, artifacts, package data, or user folders; all effects remain typed provisioning actions. |
| Desktop shell, onboarding, test drive, and startup warmup | `DesktopShellService`, `FirstRunWizard` over `SetupConductor`, `TestDriveRegistry`, and `StartupWarmupRegistry` | Navigation/profile selection, setup availability, test-drive evidence, warmup results | IMPLEMENTED as application/UI coordination evidence. It has no durable security or domain authority; launch profiles do not change policy, test-drive readiness cannot authorize effects, and warmup failures degrade optional capability readiness only. |
| Control Center and channel presentation | `ControlCenterService`, `OutputMediumProfileRegistry`, and `TrustedPermissionSurface` | Refreshable section projections, semantic action metadata, and channel-specific views derived from one trusted permission presentation | IMPLEMENTED as a derived application projection. It does not execute actions or own domain truth; model text cannot register controls or create approval, and desktop/voice formatting cannot change facts, goals, authority, or policy. |
| Capability acquisition and generated proposals | `CapabilityFactory` for acquisition ordering and lifecycle proposal state; `CapabilityRegistry` remains descriptive | Gap/solution evidence, adoption decisions, setup results, generated package proposals | IMPLEMENTED as a transient coordinator. It enforces DISCOVER → ADOPT → REUSE → BUILD; generated output stops inactive at `READY_FOR_APPROVAL` and cannot grant authority or replace package/task/permission ownership. |
| Skill manifests and context priming | `SkillRegistry` and the canonical agent-runtime `ContextManager` | Bounded primed context, retrieval hits, procedure projections | IMPLEMENTED. Skill requirements are retrieval hints only; memory, knowledge, workspace documents, artifacts, task truth, and permissions retain their existing owners. Workspace, classification, privacy, and token checks fail closed. |
| Credentials and secrets | `CredentialVault` with metadata-only app-owned SQLite and an explicit secure secret backend (`WindowsCredentialManagerBackend` in production composition) | Opaque credential references, metadata/status events, and trusted proxy use | IMPLEMENTED_NOT_WIRED. `CredentialVault` is the sole secret authority. Raw secrets are never stored in ordinary DB/config/log/memory/audit/event/artifact/backup paths; unsupported hosts fail closed rather than falling back to plaintext. Authentication providers are generic adapters and cannot grant authority. |
| Automation/scheduling | No production scheduler or durable automation store | Automation event contracts only | MISSING/disabled. No task, approval, or receipt may be resurrected by a future scheduler without a new trusted design. |
| Recovery snapshots, restore points, LKG, startup/crash evidence | `RecoveryStore` over the runtime recovery directory | Health checks and runtime status | IMPLEMENTED as recovery authority. It records revision/configuration/schema/migrations/integration/generated-state metadata and selected restore artifacts; it cannot replace task, permission, audit, memory, or integration ownership. |

## Persistence and recovery invariants

The canonical planning database is the durable unit for task execution. Its
schema migrations are ordered and versioned; future schema versions and
migration identity mismatches fail closed. SQLite stores enable WAL, foreign
keys, a bounded busy timeout, and integrity checks. Task/plan writes use one
transaction, and operation reservations bind an exact operation key to a
fingerprint. A different fingerprint for an existing key is rejected.

At startup, `ApplicationRuntime` opens and validates each store, then
`PlanningEngine.reconcile_after_restart()` rebuilds the state projection from
planning truth. A task interrupted during execution, verification, or replanning
is persisted as `RECOVERING` with `unknown_operation_outcome`; it is never
replayed blindly. A permission-waiting task is requeued with old request IDs
removed, so the next execution must create a fresh broker request.

The broker's approval request binds the exact task, tool/action, keyed arguments
fingerprint, action fingerprint, permission, normalized scope, trusted identity,
requester, expiry, and lifecycle status. The paired trusted verifier consumes
the context once. Broker receipts expire no later than their approval/scope and
are claimed at effect time. Audit intent is written before an effect; an
unresolved outcome is recorded as unknown and prevents automatic retry or
replanning.

## Ownership rules for future domains

Before adding durable state, a change must answer all of these questions in this
document and in the relevant ADR:

1. What exact domain does the state represent?
2. Which single store owns creation, mutation, versioning, and recovery?
3. Which data is merely a projection, cache, index, event, or artifact?
4. What transaction/effect boundary prevents partial or duplicate authority?
5. How do migration, future-schema refusal, corruption, restart, and
   `UNKNOWN_OUTCOME` behave?
6. What secrets or untrusted external content are excluded?
7. Which application service exposes read/write access without allowing UI,
   model, event, or integration code to bypass the owner?

No new domain is production-ready until the map, owner, migration, recovery
tests, and security boundary agree.
