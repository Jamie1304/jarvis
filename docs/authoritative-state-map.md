# JARVIS authoritative state map

**Status:** v1 production ownership baseline
**Updated:** 2026-08-25

This map describes the implementation in the current repository, not the
desired future architecture. Every state domain has exactly one owner. A
projection, cache, event stream, UI model, or backup copy may read that owner,
but may not become a competing writer.

## Classification

- `AUTHORITATIVE_DURABLE`: the owner persists the state required for restart
  correctness or user-visible product continuity.
- `AUTHORITATIVE_EPHEMERAL`: the owner is authoritative only for a bounded
  live operation; restart deliberately discards or reconstructs it.
- `DERIVED_PROJECTION`: rebuildable view of another owner and never a writer of
  that domain's truth.
- `CACHE`: performance state that is safe to discard and rebuild.
- `EXTERNAL_AUTHORITY`: durable state owned outside JARVIS; JARVIS stores only a
  validated reference or metadata.
- `NOT_IN_V1`: the concept exists as a library/test contract or future boundary,
  but is not a production-owned v1 state domain.

## Final ownership matrix

| Domain | Class | Owner and store/schema | Migration owner | Retention | Reconstructible? | Consumers | Forbidden competing writers |
|---|---|---|---|---|---|---|---|
| Task/plan/step/budget/retry/idempotency | `AUTHORITATIVE_DURABLE` | `PlanningEngine` over `SQLitePlanningStore`, `planning.sqlite3`; ordered planning migrations | `SQLitePlanningStore` | Task history follows planning policy; active tasks retained | No while correctness depends on it | `TaskController`, `GoalSupervisor`, automation, UI | `ApplicationStateMachine`, events, UI, legacy orchestrators |
| Goal intent and supervisor state | `AUTHORITATIVE_DURABLE` | `GoalSupervisorStore`, `goals.sqlite3`; versioned goal-supervisor schema | `GoalSupervisorStore` | Goal history retained by store policy; no approval data | No: original outcome must survive restart | acquisition coordinator, PlanningEngine, UI | model output, task status, UI |
| Permission policy | `AUTHORITATIVE_DURABLE` | Trusted `PolicyEngine` code/configuration, composed once by `RuntimeContainer` | Trusted application/update gates | Versioned with trusted configuration | Reconstructed from trusted code/config | `PermissionBroker`, provisioning, tools | model, event payload, integration, launch profile |
| Approval requests/receipts/grants | `AUTHORITATIVE_EPHEMERAL` | `PermissionBroker` in process; no approval database by design | None; restart invalidates pending approvals | TTL, consumption, or process shutdown | Yes: request is reissued from durable task/step state | TaskController, trusted desktop approval | audit, event, voice, model, backup |
| Audit | `AUTHORITATIVE_DURABLE` | `SQLiteAuditSink`, `audit.sqlite3`, schema v1 | `SQLiteAuditSink` | Append-only operational/security retention; no automatic destructive purge | No for audit history/integrity | security review, recovery, operators | logs, model, UI, package, event bus |
| Episodic/long-term memory | `AUTHORITATIVE_DURABLE` | `SQLiteMemoryStore`, `memory.sqlite3`, ordered memory migrations | `SQLiteMemoryStore` | Per-record retention/sensitivity policy | No for retained memory | retrieval, UserModel services, ContextManager | summaries, embeddings, model, UI |
| Conversation context | `AUTHORITATIVE_EPHEMERAL` | `ConversationContextService` memory; no store | None | Conversation/session lifetime | Yes from conversation input; not long-term truth | providers, voice, desktop | memory store, model claims, audit |
| User Model facts/preferences | `AUTHORITATIVE_DURABLE` | `UserModelStore`, `user-model.sqlite3`, versioned store schema | `UserModelStore` | Per-fact retention and deletion policy | No for explicit user facts | routing, UI, opportunities, attention preferences | inferred summaries, knowledge, model, permission policy |
| Knowledge Libraries | `AUTHORITATIVE_DURABLE` | `KnowledgeLibrary`, `knowledge-library.sqlite3`, ordered knowledge migrations; source files remain external | `KnowledgeLibrary` | Source/index retention and user deletion policy | Index can rebuild from approved sources; source cannot be reconstructed from index | retrieval, Skill/Workflow context priming | UserModel, model text, whole-filesystem scanners |
| Credential metadata | `AUTHORITATIVE_DURABLE` | `CredentialVault`, `credentials.sqlite3`; metadata schema v1 | `CredentialVault` | Vault status/expiry/revocation policy | References can be reloaded; raw secret cannot | trusted proxies/auth adapters | ordinary DBs, logs, memory, artifacts, backup |
| Credential secret bytes | `EXTERNAL_AUTHORITY` | Windows Credential Manager through `CredentialVault`; no plaintext fallback | OS secure-storage authority | OS credential lifecycle | No | trusted vault operations only | JARVIS SQLite, model, package, backup |
| Credential operation references | `AUTHORITATIVE_EPHEMERAL` | `CredentialBroker` over the single `CredentialVault`; typed `CredentialRef` is metadata-only and short-lived | `CredentialVault` validation contract | Reference expiry, credential revocation, and operation completion | Yes: issue a new exact reference; raw secret is never reconstructed | trusted host/auth adapters | integration, model, EventBus, Trace, artifacts, memory, backup |
| Artifacts and immutable versions | `AUTHORITATIVE_DURABLE` | `ArtifactStore`, `artifacts/artifacts.sqlite3` plus owned content; schema v1 | `ArtifactStore` | `ArtifactRetentionPolicy`, expiry and max versions | No for deliverables; content hash is checked | tasks, evidence references, presentation, backup | evidence store, memory, arbitrary filesystem writers |
| Automation definitions and runs | `AUTHORITATIVE_DURABLE` | `AutomationService` over `SQLiteAutomationStore`, `automations.sqlite3`; versioned migrations | `SQLiteAutomationStore` | Cooldown, dedupe, run and user retention policy | No for durable subscriptions/runs | EventBus, Attention, GoalSupervisor/PlanningEngine | Scheduler, event payload, direct tool execution |
| Attention items/decisions/digests | `AUTHORITATIVE_DURABLE` | `AttentionPolicy` over `SQLiteAttentionStore`, `attention.sqlite3`; schema v1 | `SQLiteAttentionStore` | expiry, resolution, dedupe and digest policy | No for unresolved user-action/security notices | notification transports, UI, voice narration | transport, UserModel inferred preference, permission policy |
| Capability opportunities | `AUTHORITATIVE_DURABLE` | `CapabilityOpportunityEngine` over `SQLiteOpportunityStore`, `opportunities.sqlite3`; schema v1 | `SQLiteOpportunityStore` | cooldown and expiry; archived history policy | No while cooldown/preparation continuity matters | Attention, acquisition coordinator | opportunity evidence, model, trigger, direct activation |
| WorkflowTemplates / versions / user lifecycle | `AUTHORITATIVE_DURABLE` | `SQLiteWorkflowProcedureStore`, `workflow-procedures.sqlite3`, schema v1; `WorkflowTemplateRegistry` is the active projection | `SQLiteWorkflowProcedureStore` | Version history retained; user disable/retire/delete policy | Active projection rebuilds from durable versions; task/verification history is never deleted | PlanValidator, PlanningEngine/TaskController, Automation, context priming | model/UI/package writers, registry cache, approval store, second planner |
| Procedure observations / candidates / learned linkage | `AUTHORITATIVE_DURABLE` | `SQLiteWorkflowProcedureStore`, sanitized `procedure_routines` and `procedure_candidates` tables; `ProcedureBank` is the proposal projection | `SQLiteWorkflowProcedureStore` plus trusted `ProcedureEvidenceAuthority` for issuance | Candidate lifecycle and user state policy; exact histories/secrets are not retained | Candidates rebuild from sanitized routines; canonical task/verification evidence remains in its owner | Skills, WorkflowTemplates, PlanValidator, context priming, Trace references | caller booleans, model text, integration callbacks, approvals, PlanningEngine execution |
| Golden Workflows and regression runs | `AUTHORITATIVE_DURABLE` | `GoldenWorkflowStore`, `golden-workflows.sqlite3`; schema/migration checks | `GoldenWorkflowStore` | User-retire/delete plus bounded run history | Definitions no; run evidence may be regenerated but not expected results | self-improvement/update gates | candidate output, broken run, UI, model |
| Capability/package lifecycle | `AUTHORITATIVE_DURABLE` | `SQLiteCapabilityLifecycleStore`, `capability-lifecycle.sqlite3`; schema v1; `CapabilityLifecycleRestorer` is the production startup reader/coordinator | `SQLiteCapabilityLifecycleStore` | Active/LKG/rollback retention and package policy | No for certification/activation continuity | registry projection, activation, hot-load, health/doctor, restart reconciliation | in-memory registry, package code, callback, UI, test-only restore hook in production |
| Package code/source snapshots | `AUTHORITATIVE_DURABLE` | `ProductionPackageStore` under the external `packages/` root; versioned `package.json` metadata and hash-verified source layout (schema 1) | `ProductionPackageStore` package-format validation; lifecycle migration does not own package bytes | Immutable certified versions retained by package/update policy; user config/data are separate | No for exact package provenance; a missing/changed source fails closed | reviewer, certifier, AppContainer runtime, hot-load, recovery reconciliation | lifecycle store, generated code, UI, model, arbitrary filesystem writers |
| Trusted effect attestations | `AUTHORITATIVE_DURABLE` | `EffectAttestationStore`, `effect-attestation.sqlite3`; schema v1 | `EffectAttestationStore` | Activation/certification evidence retention policy | No for promotion evidence | activation, VerificationEngine, Trace, audit | integration callback, model claim, UI, ordinary event payload |
| Effect preview and compensation lifecycle | `AUTHORITATIVE_DURABLE` | `CompensationService` over `CompensationStore`, `compensation.sqlite3`; `EffectPreview` is immutable request metadata and `CompensationExecutor` is compatibility-only. `EffectStateObserverRegistry` is the application-owned trusted observation boundary; `FilesystemStateObserver` is the generic bounded v1 provider | `CompensationStore`, schema v1; observer registrations are startup-owned and sealed, not durable truth | Bounded request lifecycle and trace/approval references; raw secrets are never stored; observer evidence is hash-only for filesystem state | No for in-flight or terminal compensation decisions; observers are re-registered from trusted composition and current state is always re-observed | Plan Studio, Trace, VerificationEngine, TaskController, audit, trusted broker/tool adapters | UI, model prose, integration callback, package self-report, direct tool invocation, approval store, unregistered observer |
| Certification records | `AUTHORITATIVE_DURABLE` | Certification facts persist in lifecycle certification columns/JSON; `PackageCertifier` is the trusted producer. UI-bearing records persist only the trusted `UISimulationAttestation` reference/digest; render artifacts remain in `ArtifactStore` | Lifecycle migration; certifier validates exact package/source/dependency/manifest/UI evidence hashes | Until package/version retirement or policy expiry | No for certification authority | activation, update preview, audit, UI simulation evidence | generated package, activation callback, model prose, free-form UI flags |
| Activation state | `AUTHORITATIVE_DURABLE` | Lifecycle store activation state/revision/transaction marker; `PackageActivationService` is coordinator | Lifecycle migration | Active, degraded, quarantine, rollback policy | No during staged activation/recovery | HotLoadManager, CapabilityRegistry, health/drift | package self-promotion, registry, UI |
| Certified behavior baselines | `AUTHORITATIVE_DURABLE` | Expected baseline/reference stored with certification/lifecycle record; trusted certifier owns creation; `CapabilityLifecycleRestorer` rehydrates the health projection from that reference | Lifecycle migration | Same as certification; new version gets a new baseline | No for security comparison | CapabilityHealth/BehaviorDrift, ComponentDoctor, activation | generated integration, health callback, model |
| Live capability health | `AUTHORITATIVE_EPHEMERAL` | `CapabilityHealthService` in memory; package last-health summary is copied into lifecycle metadata; startup baseline/activation projection is restored by `CapabilityLifecycleRestorer` | Lifecycle migration for package summary only | Current observation/attention policy | Yes by re-probing; unknown remains unknown | ComponentDoctor, Attention, Control Center | model claim, package self-report, UI |
| Standalone provisioning transaction | `AUTHORITATIVE_DURABLE` | `ProvisioningEngine` over `SQLiteProvisioningStore`, `provisioning.sqlite3`; schema v1 stores bounded action outcomes only | `SQLiteProvisioningStore` | Completed/recovering plan outcomes follow provisioning retention policy | No for outcome history; external reality is still re-inspected before resume | `SetupConductor`, CapabilityFactory, broker | setup UI, provider callback, task engine |
| Setup/adoption state | `AUTHORITATIVE_DURABLE` | `SetupConductor` over `SQLiteSetupStore`, `setup.sqlite3`; schema v1 stores normalized decisions, identity evidence fingerprints, and `AdoptionAttestation` references | `SQLiteSetupStore` plus trusted `AdoptionIdentityInspector`/`AdoptionPolicy` issuance contract | Completed/failed setup history, attestation expiry, and resumable run policy | No for normalized decisions/attestation continuity; current executable identity is always re-observed | onboarding, acquisition, provisioning, Trace, lifecycle provenance | independent component interviews, package code, candidate assertions, UI, PermissionBroker |
| Workspaces and AgentProfiles | `NOT_IN_V1` | No production `WorkspaceStore`/`AgentProfileStore` exists. `WorkspaceContext` and profile registries are bounded runtime inputs/projections only | None | No v1 durable retention | Yes from user/application configuration once implemented | factory/context/profile consumers | treating transient context as durable authority or permission |
| AgentSessions | `AUTHORITATIVE_DURABLE` | `AgentSessionStore`, `sessions.sqlite3`, schema v1 with migration marker | `AgentSessionStore` | Archive policy; active session continuity retained | No for session identity/usage/synchronization | ConversationService, voice binding, agent runtime | Task/Goal/UserModel stores |
| Hardware/model inventory and benchmarks | `AUTHORITATIVE_EPHEMERAL` | `HardwareInventoryService` and `ModelInventory` in memory; model files are app-owned filesystem artifacts managed by `LocalModelManager` | None | Last probe/benchmark only for process lifetime | Yes by re-probe/rebenchmark; `None` means unmeasured | ModelRouter, ResourceGovernor, diagnostics | router claiming measurements, model package, UserModel |
| Trace | `DERIVED_PROJECTION` | `TraceService` is the one runtime-owned projection subscriber; `TraceStore`, `trace.sqlite3`, schema v2, durably stores sanitized events and goal/task lineage | `TraceStore` | No automatic purge currently; future policy belongs in TraceStore | Yes from domain records, though retained trace aids auditability | UI, replay preparation, diagnostics, artifact/evidence links | trace cannot complete tasks, authorize, resolve credentials, or replay effects |
| Evidence and Verification | `AUTHORITATIVE_EPHEMERAL` | `VerificationEngine` evaluates immutable plans/records in process; task evidence is durably copied by PlanningEngine and certification evidence by lifecycle store | PlanningEngine/lifecycle migrations for copied facts | Verification-plan/record lifetime; domain owner retention applies to copies | Yes only when source observations can be recollected; model claims are never evidence | PlanningEngine, acquisition, activation, Trace | model saying “done”, Trace, UI, package callback |
| Recovery snapshots/LKG | `AUTHORITATIVE_DURABLE` | `RecoveryStore` recovery directory; manifest schema `CURRENT_SCHEMA=3`; authenticated `TrustedRecoveryRecord` in `last-known-good.json`; evidence/attempt files | `RecoveryStore` manifest migration/validation; `TrustedRecoveryAuthority` authenticates promotion | Snapshot retention plus authenticated LKG pin; bounded crash-loop evidence; secure generation floor prevents stale replay | No for rollback point; health can be rerun only after record validation | ApplicationRuntime, RecoveryCoordinator, update gates | BackupService, package/model/UI, candidate callbacks, ordinary mutable files |
| Backup metadata/bundles | `EXTERNAL_AUTHORITY` | `BackupService` validates encrypted bundle manifests in app-owned `backups/`; bundle is user-controlled transport, not a domain store | Backup format/version handlers | User-selected file retention | Bundle can be reread; source domains remain authorities | restore/migration, reauthorization, relinking | backup cannot overwrite domain truth without applier and normal gates |
| Resource admission/reservations | `AUTHORITATIVE_EPHEMERAL` | One `ResourceGovernor` in `RuntimeContainer`; reservations exist only while work runs | None | Release on complete/cancel/crash/timeout | Yes from current telemetry; reservations are not restart truth | ProviderRouter, CapabilityFactory, Sandbox, warmup, multi-agent | model/provider, scheduler, UI |
| Typed events | `DERIVED_PROJECTION` | In-memory `EventBus`; no durable event log | None | Bounded queue/subscriber lifetime | Yes from authoritative stores | Presence, health, automation, UI | event cannot grant permission or replace a store |

## Runtime ownership and migrations

`RuntimeContainer` creates exactly one instance of each durable owner listed
above. Package bytes/source are owned by `ProductionPackageStore`, while
certification/activation state remains solely in
`SQLiteCapabilityLifecycleStore`; neither store is a competing authority for
the other. In particular, the single `PermissionBroker` is passed to
`ToolRegistry`, planning, provisioning, and brokered capabilities; the single
`CredentialVault` is wrapped by the runtime-owned `CredentialBroker` before a
trusted host adapter can perform an authenticated operation. Integrations and
models receive only exact, expiring `CredentialRef` metadata; they never
receive the Vault, backend, or secret bytes. The single
`SQLiteCapabilityLifecycleStore` is shared by activation and hot-load. The
single `SQLiteWorkflowProcedureStore` is shared by the template registry and
ProcedureBank; it is not an execution engine. UI services receive application
interfaces and cannot construct these owners.

SQLite correctness-critical stores use WAL, foreign keys, busy timeouts, and a
version marker with future-schema refusal. The following stores have explicit
schema gates in the current tree: planning, state, audit, memory, User Model,
KnowledgeLibrary, artifacts, AgentSessions, goals, setup, provisioning, effect
 attestations, compensation, capability lifecycle, opportunities, attention, automation, Trace,
Golden Workflows, and Workflow/Procedure state. Recovery and encrypted Backup use their own versioned
manifest formats rather than SQLite migrations.

`TrustedRecoveryAuthority` is a trusted authentication component, not a second
recovery store: `RecoveryStore` owns the record file and snapshot/evidence
state, while the authority owns only secure HMAC verification, promotion, and
the installation-scoped generation floor. Candidate code and ordinary
application data cannot write a known-good record through a supported API.

`TraceStore` is schema v2 and migrates schema-v1 events while refusing future
versions. `ArtifactStore` and `AgentSessionStore` were historically created with tables
but no schema marker. Version-1 baseline migrations now register existing
compatible tables without rewriting data; unknown future versions fail closed.

## Retention and cleanup rule

Retention is owned by the domain in the matrix. Artifact expiry/version trim,
opportunity expiry/cooldown, attention resolution/expiry, recovery snapshot
retention, setup lifecycle, capability lifecycle, and UserModel/memory policies
are domain operations. Audit is append-only by default because deletion would
damage security evidence. Trace currently has no automatic purge; it is a
runtime-owned derived operational projection and any future retention policy
must be added to `TraceStore` rather than deleting source task/audit truth.
Trace entries may contain credential IDs and package/effect-attestation IDs,
but never secret values. Backup files are
user-owned external bundles and are never silently deleted by package updates.

## Future-domain rule

Before adding durable state, update this map and the relevant ADR with the exact
domain, one owner/store, schema and migration owner, retention, restart/recovery
semantics, projection/cache boundary, and forbidden writers. No raw credential
bytes may be persisted outside the external CredentialVault authority. No new
SQLite store may duplicate an existing domain without an explicit transaction
and recovery justification.
