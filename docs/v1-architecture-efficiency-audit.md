# JARVIS v1 Architecture and Efficiency Audit

Audit date: 2026-08-24
Repository: `Jamie1304/jarvis`
Branch: `agent/v1-integration`
Audited revision: `e1cb175b6cc9fbcc6c2e95ca290cfbfd3e9815b5`
Result: **CORE GO / COMPLETE SELF-EXPANSION BASELINE NO-GO**

This is an architecture and efficiency audit, not a feature implementation. It
records what is actually present and composed at the audited revision. The
existing local changes (`.env.example` and `.jarvis/`) were preserved and are
not part of the audit revision.

## Executive result

The canonical safety-critical path is coherent:

```text
application/UI -> TaskController -> PlanningEngine -> ToolRegistry
-> Tool -> PermissionBroker -> verification -> durable state/audit/events
```

`PlanningEngine` is the only production task/control authority in the default
composition. Model output, external events, memory, discovery, skills,
automations, presentation, and donor studies do not create authority. The
repository contains no donor runtime dependency and no product-specific core
integration match in the audit search.

The baseline is not a complete production self-expansion system yet. The
following are the material blockers:

1. Capability acquisition, package certification, Shadow/Canary activation, and
   durable capability lifecycle are separate contracts/services rather than one
   default production coordinator and authoritative lifecycle store.
2. `GoalSupervisor`, `SetupConductor`, `CapabilityFactory`, browser, Vault,
   sandbox runtime, voice runtime, UI simulation, and the package activation
   path are not all composed by `ApplicationRuntime`.
3. There is no dedicated `OpportunityEngine` or durable priority-aware
   `AttentionPolicy` queue. `AttentionNotice` is a bounded derived notification
   list, not a restart-safe critical-event delivery service.
4. Workspace and AgentProfile contracts are incomplete as a canonical persisted
   domain. `WorkspaceContext` is currently an acquisition scope, not a full
   workspace authority, and no `AgentProfile` implementation was found.
5. Durable stores are inconsistent. Planning has WAL, foreign keys, migration
   identity, future-schema refusal, and integrity checks; several other stores
   use ad-hoc table creation without the same migration/schema contract.
6. Agent sessions are durable metadata, but `AgentLoop` is not bound to an
   `AgentSession` in the default runtime. Conversation session reuse exists as
   a separate service path.
7. Context limits use character estimates rather than provider/tokenizer-aware
   accounting in both conversation and agent context preparation.

These are architecture/wiring findings, not failed test claims. The quality
gate and deterministic suites pass, but they do not prove the absent production
composition paths.

## Classification

- **IMPLEMENTED_AND_WIRED**: implemented and reachable from the default
  composition root, with relevant tests.
- **IMPLEMENTED_NOT_WIRED**: native implementation/contracts and tests exist,
  but the default production graph does not own or invoke them.
- **PARTIAL**: the boundary exists but has a material persistence, lifecycle,
  integration, or efficiency gap.
- **MISSING**: no production owner/service was found for the requested contract.
- **DEPRECATED**: retained only for compatibility, migration, or tests and not
  an allowed production authority.
- **UNKNOWN**: not proven by the inspected code/tests.

## Authority and domain audit

| Area | Authority and evidence | Status | Finding |
|---|---|---|---|
| Runtime/task ownership | `ApplicationRuntime`, `RuntimeContainer`, `TaskController`, `PlanningEngine`, `SQLitePlanningStore` | IMPLEMENTED_AND_WIRED | The default path has one task engine. `ApplicationStateMachine` is a derived lifecycle projection. |
| Legacy task engine | `jarvis/autonomy/orchestrator.py`, `autonomy/store.py` | DEPRECATED | `AgentOrchestrator` and `InMemoryTaskStore` remain compatibility/test code. They must not be reintroduced into production composition. |
| GoalSupervisor | `goal_supervisor.py`, `GoalSupervisorStore` | IMPLEMENTED_NOT_WIRED | Durable goal intent and bounded supervision are tested, but `GoalSupervisorStore` is not owned by `RuntimeContainer` and does not drive the default pipeline. |
| Agent Runtime | `agent_runtime.py`, `AgentLoop`, `AgenticPlanningStepExecutor` | PARTIAL | Bounds, validation, loop guards, cancellation, unknown-effect refusal, and ToolRegistry routing exist. Default planning uses `SafeBuiltinPlanAdvisor`; the agentic executor and session binding are not default production paths. |
| Context | `ContextManager`, `LoopGuard` | PARTIAL | Protected security context and bounded compaction exist. Token estimates are character-based, provider context/tokenizer metadata is not used, and protected context is serialized into each model request. |
| Providers | `ProviderRegistry`, `ProviderRouter`, local provider in `bootstrap.py` | IMPLEMENTED_AND_WIRED | Provider-neutral registry/router is composed. The built-in Ollama adapter is a local model transport, not a service-specific capability integration. |
| Sessions | `ai/sessions.py`, `ConversationService` | PARTIAL | Session metadata is persisted and conversation reuse/rebuild is tested. `AgentLoop` has no session-store binding in the default runtime; the session schema has no migration/version/integrity contract comparable to planning. |
| Voice Runtime | `voice/activation.py`, `speech/*`, `voice/warmup.py` | IMPLEMENTED_NOT_WIRED | Deterministic streaming, barge-in, stale-response, PTT, degradation, and approval tests exist. `RuntimeContainer.voice` is `None` by default and the live controller is not composed. |
| Workspaces | `WorkspaceContext` in `capability_factory.py` | PARTIAL | Acquisition scope validation exists. There is no canonical persisted WorkspaceStore covering filesystem, memory, credentials, model policy, retention, and knowledge namespace. |
| Agent profiles | search for `AgentProfile` and profile stores | MISSING | Launch profiles and output-medium profiles exist; a persisted capability-ceiling AgentProfile domain was not found. |
| Output medium | `OutputMediumProfile`, `TrustedPermissionSurface` | IMPLEMENTED_AND_WIRED | Channel formatting and trusted narration are application-owned and separate from personality, facts, authority, and policy. |
| Artifacts | `ArtifactStore`, `ArtifactRecord`/versions, runtime composition | IMPLEMENTED_AND_WIRED | App-owned immutable artifact metadata/content is persisted and linked to tasks/workspaces/events. Path, traversal, collision, classification, and restart tests exist. |
| Evidence | `VerificationEngine`, planning evidence verifiers, trace links | PARTIAL | Evidence is separate from artifacts and memory. A dedicated durable evidence authority is still future work; current evidence is bounded observation/plan state. |
| Memory | `SQLiteMemoryStore`, memory services, `UserModelStore` | IMPLEMENTED_AND_WIRED | Episodic/conversation memory and user facts/preferences have distinct owners and controls; Vault secrets are excluded. |
| Knowledge | `KnowledgeLibrary`, `KnowledgeStore`, indexer | IMPLEMENTED_AND_WIRED | Documentary indexing is separate from User Model facts and source deletion is not implied by index deletion. Generated project knowledge and personal library are distinct stores. |
| MCP | `MCPExtensionManager`, typed adapter/client, ToolRegistry | IMPLEMENTED_AND_WIRED | Manager is composed and external descriptions/results are treated as untrusted. No broker, Vault, or Trusted Core object is passed to an MCP process. No MCP server is required by default. |
| Skills | `SkillManifest`, `SkillRegistry`, context requirements | PARTIAL | Skill/Tool/Integration/Agent contracts are distinct and skills do not grant authority. Registry is present in the container, but package-driven skill activation is not a complete durable production flow. |
| Workflow/procedure learning | `WorkflowTemplateRegistry`, `ProcedureBank`, golden workflows | PARTIAL | Templates instantiate proposed plans and learning requires verified repeated success. Procedure banking is not a second execution engine, but the bank is not a default durable runtime owner. |
| Capabilities | `CapabilityManifest`, `CapabilityRegistry`, environment graph | PARTIAL | Generic vocabulary and descriptive lookup exist. Registry state and lifecycle are in memory; no single durable capability metadata/activation owner is composed. |
| Integration packages | `integration_package.py`, reviewer, certifier, runtime | IMPLEMENTED_NOT_WIRED | Layout, hashes, provenance, user-data separation, review, certification, and UI evidence contracts exist. Full install/update/activation lifecycle is not in the default composition. |
| Discovery | `environment_discovery.py`, discovery models/providers | IMPLEMENTED_NOT_WIRED | Generic passive/read-only/active evidence contracts exist. Default runtime exposes a capability-gap detector, not the complete environment discovery service. |
| Research/donors | `improvement/donor_study.py`, improvement models/docs | IMPLEMENTED_NOT_WIRED | Donor research is reference/provenance material only. No donor package, binary, ACP, server, or UI runtime import was found. There is no default research-to-factory coordinator. |
| Browser | `browser.py`, browser tests | IMPLEMENTED_NOT_WIRED | Generic scoped semantic bridge and stale-origin/document references exist. It is not composed in the default runtime. |
| Credential Vault | `credentials.py`, Vault boundary tests | IMPLEMENTED_NOT_WIRED | Metadata-only credential records and secure-storage contracts exist. The default runtime does not compose a CredentialVault service, so the production authentication path is incomplete. |
| Brokers/sandbox | `PermissionBroker`, `ToolRegistry`, `sandbox.py`, `sandbox_proxies.py` | PARTIAL | Brokered tools are default-wired and privileged defaults are closed. Sandbox process/IPC and narrow host proxies are tested but not part of the default runtime graph; actual Windows isolation guarantees remain platform-dependent. |
| Provisioning | `provisioning.py` | IMPLEMENTED_NOT_WIRED | Typed idempotent actions, verification, resume, rollback, and unsupported-provider tests exist. No default provisioning coordinator is composed. |
| SetupConductor | `setup_conductor.py`, setup stores/tests | IMPLEMENTED_NOT_WIRED | Adoption-before-install, one interview, idempotency, and data preservation are implemented. The conductor is not owned by the production runtime. `SetupContext` contains choices/references and does not grant permission. |
| CapabilityFactory | `capability_factory.py` | IMPLEMENTED_NOT_WIRED | DISCOVER -> ADOPT -> REUSE -> BUILD and inactive generated output are enforced in tests. It stops at `READY_FOR_APPROVAL` and is not connected to the default certification/activation root. |
| Certification | `package_certification.py`, `GeneratedPackageReviewer` | IMPLEMENTED_NOT_WIRED | Generated packages cannot self-certify and hashes/evidence/permission diffs are bound. Certification records are not a default durable lifecycle store. |
| Shadow/Canary | `package_activation.py`, activation tests | IMPLEMENTED_NOT_WIRED | Central staged lifecycle and zero-effect Shadow/ bounded Canary rules exist. The activation service is not composed by `ApplicationRuntime`; package versions therefore do not have a default end-to-end production path. |
| Desktop/onboarding | `application.py`, `desktop_shell.py`, test-drive/warmup registries | PARTIAL | Generic shell/application services, optional onboarding, test-drive, safe startup, and non-blocking warmup contracts exist. The default warmup registers only the model health check; hardware/voice/model/session prewarm is not wired. |
| Presence/presentation | `presence.py`, `presentation.py` | IMPLEMENTED_NOT_WIRED | Presence is derived from events/runtime state and PresentationSurface uses safe artifact references/query state. Neither is a default RuntimeContainer service. |
| UI simulation | `ui_simulation.py` | IMPLEMENTED_NOT_WIRED | Declarative states, semantic checks, no-effect action endpoints, artifacts, and approval-spoof checks are tested. It is not connected to default package certification composition. |
| Plan Studio | `planning/editing.py`, `PlanningEngine`, application methods | IMPLEMENTED_AND_WIRED | Edits create revisions, revalidate, invalidate changed approval fingerprints, and preserve only valid evidence. No second planner is present. |
| Verification/compensation | `verification.py`, `effects.py`, planning verifiers | PARTIAL | Verification levels, evidence rejection, previews, and normal brokered compensation contracts exist. Generic VerificationEngine/compensation are not separate durable authorities in the default container. |
| Trace | `trace.py`, `TraceStore`, automation/health wiring | PARTIAL | Human-readable trace and safe replay rules exist and secrets/chain-of-thought are excluded. Trace is not uniformly attached to every default task/agent/provider boundary. |
| Models/resource control | `ResourceGovernor`, `ProviderRouter`, `LocalModelManager` | PARTIAL | A single governor is composed and provider routing consumes it. Model manager, AgentLoop budgets, sandbox, factory, and all warmup paths are not centrally connected in the default graph. |
| User Model/Knowledge | `UserModelStore`, `KnowledgeLibrary` | IMPLEMENTED_AND_WIRED | Separate authoritative stores and scoped retrieval/consolidation are present. Cross-domain durable coordination remains application-level. |
| Scheduler/Automation/Attention | `AutomationService`, `SQLiteAutomationStore`, `AttentionNotice` | PARTIAL | Automations dispatch normal TaskController/PlanningEngine work and are durable/restart-safe. No distinct Scheduler service or priority-aware AttentionPolicy queue exists; attention notices are bounded derived notifications. |
| Health/drift/doctor | `CapabilityHealthService`, `ComponentDoctor` | PARTIAL | Trusted observations, baseline drift, ownership-aware diagnosis, repair gates, and degradation are implemented and composed. Baselines, repair attempts, and attention state are in memory; package-declared doctor ownership is not end-to-end wired. |
| Migrations | planning/memory/knowledge/user-model stores and other SQLite stores | PARTIAL | Several authoritative stores have migrations and future-schema refusal. Sessions, artifacts, automation, trace, golden workflow, audit, setup, and state stores do not all expose the same explicit version/migration/integrity contract. |
| Opportunity/donors | donor study and capability gap contracts | MISSING | No `OpportunityEngine` or durable opportunity queue was found. Donor frameworks remain reference-only. |
| Golden workflows | `GoldenWorkflowStore`, `GoldenWorkflowService` | IMPLEMENTED_AND_WIRED | Candidate sanitization, verification gates, tamper resistance, restart, and regression blocking are present and the store is composed. |
| Self-update | recovery/build startup logic | PARTIAL | Bad-build detection, LKG, rollback, crash-loop guard, and Safe Mode exist. A complete package self-update coordinator with migration/certification/activation gates is not default-wired. |
| Backup/recovery | `BackupService`, `RecoveryStore`, runtime | IMPLEMENTED_AND_WIRED | Encrypted user backup/restore is separate from technical LKG snapshots; restore preview, reauth, migration, recertification, and rollback tests exist. |

## Required separation invariants

| Invariant | Verdict | Evidence/qualification |
|---|---|---|
| `WorkflowTemplate != PlanningEngine` | PASS | Templates produce proposed plans; `PlanningEngine` validates and executes. |
| `Skill != Tool != Integration != Agent` | PASS | Separate manifests/registries/contracts; skills provide procedure/context and no authority. |
| `Artifact != Evidence != Memory` | PASS | ArtifactStore owns deliverables; verification observes proof; memory stores retained knowledge. The durable evidence owner remains incomplete. |
| `Automation != Scheduler != task engine` | PARTIAL | Automation delegates to TaskController/PlanningEngine, but a distinct Scheduler/Attention service is not present. |
| `PresenceProjection` is derived | PASS | Presence consumes canonical event/runtime state and cannot write task truth. |
| `Backup != LKG snapshot` | PASS | User-facing encrypted selectable backup and technical recovery snapshots have separate stores/purposes. |
| Knowledge != User Model | PASS | Documentary source/index entities and personal facts/preferences use separate stores and policies. |
| Attention != permission authority | PASS | Attention notices are derived; PermissionBroker remains authoritative. There is no durable critical attention queue. |
| OutputMediumProfile != personality/security | PASS | Profiles alter formatting only; trusted permission object is shared across channels. |
| LaunchProfile != separate runtime/security policy | PASS | Launch selection preserves the security policy version and does not bypass broker policy. |
| SetupContext does not grant permissions | PASS | Setup choices and credential references are validated separately from PermissionBroker. |
| SetupConductor adopts safely before installing | PASS | Existing compatible installation/data is inspected and adoption choices are explicit. |
| ComponentDoctor respects subsystem ownership | PASS | Core/provider/sandbox/provisioning/capability ownership and typed repair actions are enforced. Default package-owner wiring is incomplete. |
| ResourceGovernor is centralized | PASS / PARTIAL CONSUMPTION | One governor is composed. Not every resource consumer is registered or budgeted through it. |
| Shadow/Canary is centrally controlled | PASS / NOT WIRED | `PackageActivationService` enforces it in isolation; it is not default-composed. |
| ProcedureLearner banks only verified methods | PASS | Repeated verified success is required; unknown/unverified/secret-bearing histories are rejected. |
| Every durable domain has one authoritative store | PARTIAL | Task/plan, memory, user model, knowledge, artifacts, audit, automations, trace, golden workflows, and recovery have owners. Capability lifecycle/certification/activation, sessions, evidence, model inventory, diagnostics, setup, workspace/profile, and opportunities are not all represented by one durable owner. |
| Package code and user data are separated | PASS | Package code is immutable/hash/certified; config/data/cache are external and migratable; credentials are references. |
| Donors are not runtime dependencies | PASS | Static import/dependency search found no Goose, Agent Zero, fullstack-agent, Backtalk, ai-visualizer, ai-memory-vault, or barehands runtime import. |

## Duplicate control planes and compatibility debt

1. **Task execution:** `PlanningEngine`/`SQLitePlanningStore` is the allowed
   production authority. `AgentOrchestrator`/`TaskStore` is deprecated
   compatibility code and remains in workflow tests. This is safe today only
   because the default runtime does not instantiate it; it is a migration/dead
   code removal item.
2. **Status representation:** `ApplicationStateMachine` has task projection
   statuses separate from planning statuses. Documentation and reconciliation
   identify the state machine as derived, but the duplicate enum surface can
   drift if new transitions are added without a single mapping test.
3. **Goal supervision:** `GoalSupervisor` is a coordinator above planning, not a
   second task engine. It is currently disconnected from the default runtime,
   so there is no production duplicate, but also no production long-horizon
   path.
4. **Automation/workflows:** `AutomationService` creates normal tasks and
   templates; it does not execute plans itself. This is the correct ownership
   direction.
5. **Package activation:** `PackageActivationService` owns lifecycle decisions;
   `HotLoadManager` owns runtime registration/drain. These are separate roles,
   but their state is not consolidated into a durable lifecycle store.
6. **Knowledge/memory:** `KnowledgeStore` is generated project context while
   `KnowledgeLibrary` is user-document indexing; `SQLiteMemoryStore` and
   `UserModelStore` are separate retained-memory domains. This is intentional,
   not a duplicate authority.

## Minimal-core and product-specific search

Searches over production `jarvis/**/*.py` excluded test fixtures and found:

- no Spotify, Hue, Home Assistant, Discord, printer, NAS, car, social,
  messaging, or website-specific capability branching;
- no hard-coded product-specific browser commands or product-specific voice
  command tree;
- only generic/local endpoints such as the configured local model endpoint and
  package-reviewer detection patterns;
- no donor framework imports or runtime dependency names.

The built-in tools (`calculator`, `local_time`, and unavailable weather) are
generic/safe defaults. A normal new external capability can use manifests,
ToolRegistry/MCP adapters, sandbox proxies, SetupConductor, certification, and
activation without adding a product branch to core. The qualification is that
the missing production coordinator/lifecycle store must be completed before
that statement is true for autonomous generated activation rather than merely
for package-level contracts.

## Efficiency and lifecycle audit

### Token and model use

- `ContextManager` and `ConversationService` bound context by approximate
  characters (`~4 chars/token`), not provider tokenizer accounting. This can
  under-use context or exceed a provider-specific limit and makes reserved
  output budgeting imprecise.
- Protected context is serialized into a system message on each agent turn;
  older tool-pair compaction is bounded, but repeated protected metadata and
  tool-result summaries can consume avoidable context.
- The default safe planner avoids an LLM for the built-in deterministic paths;
  this is a good minimal-core default. `AgentLoop` is bounded but not session-
  or cache-coordinated with the provider/router.
- Provider health is invoked by the runtime test-drive provider step, the
  Control Center health projection, and the startup warmup registration. These
  calls are health probes rather than generations, but they can duplicate
  network/process work if all UI/startup paths run together.
- No provider response cache, shared in-flight health result, or tokenizer
  service is present. These are efficiency opportunities, not authority gaps.

### Startup and prewarm

- Startup synchronously validates the storage layout repeatedly while opening
  many SQLite stores and loading generated project knowledge. This is simple
  and deterministic but increases cold-start latency.
- `StartupWarmupRegistry` is non-blocking and ResourceGovernor-aware, but the
  default registration contains only `default-model` health. STT, wake, TTS,
  audio output, embeddings, and session restoration are not composed by the
  default runtime.
- Automation startup is launched as a background task and is cancelled by the
  container. This is correct lifecycle ownership, but startup readiness does
  not expose a durable warmup/readiness report.

### Resources and process lifecycle

- `RuntimeContainer.aclose()` is lock-protected, idempotent, deduplicates
  shared object identities, cancels automation startup, and continues closing
  after an individual close error. Runtime tests cover normal exit, init/start
  failure, task shutdown, and double close.
- Camera, audio, sandbox, subprocess, and MCP paths have bounded cancellation
  and cleanup tests. Blocking native calls are not falsely claimed to be
  force-cancellable.
- The startup Safe Mode early return and partial-start exception paths should
  be reviewed for complete closure of every resource created before the return;
  the partial-store helper closes the main stores but recovery and every
  future optional resource are not represented uniformly. This is a lifecycle
  risk, not a demonstrated leak in the current tests.
- Sandbox/resource governor consumers are not all in the default graph, so
  system-wide concurrency and pressure policy is only partially effective.

### Durable data and cost

- Durable task, memory, knowledge, user-model, artifact, audit, automation,
  trace, golden-workflow, session, backup, and recovery records are justified
  domain data or operational evidence. Generated project index and caches are
  rebuildable and should not be treated as user source data.
- Raw model prompts, credentials, and secrets must remain outside ordinary
  trace/memory/artifact paths; current tests cover the main redaction/Vault
  boundaries.
- The largest cost risk is architectural fan-out: many later services are
  individually implemented and tested but not composed, so future integration
  work may duplicate health, session, setup, or certification calls unless the
  missing coordinators are made the only entry points.

## Test and CI evidence

Executed with `D:\JARVIS\.venv\Scripts\python.exe`:

| Command | Result |
|---|---|
| `python scripts/quality.py` | PASS — 1,138 passed, 5 skipped; ruff format/check pass; mypy strict pass for 257 source files; 90% total coverage |
| `python scripts/run_system_tests.py --suite deterministic-workflows` | PASS — 26 passed |
| `python scripts/run_system_tests.py --suite deterministic-permissions` | PASS — 70 passed, 1 skipped |
| `python scripts/run_system_tests.py --suite windows-hardware-manual` | SKIPPED — `hardware_suite_disabled` |

The repository has no single `v1-acceptance` catalog entry that executes the
full A–W acceptance matrix. The deterministic catalog currently exposes the
workflow, permission, and opt-in hardware suites; the broader acceptance
matrix remains a documented/tested collection rather than one executable
system suite.

Unexecuted or not proven by this run:

- physical microphone, camera, speaker, wake-word, and Windows Accessibility
  behavior;
- real authenticated permission presentation/owner identity;
- real third-party MCP, browser, Vault, package installation, generated code,
  package certification/activation, Shadow/Canary, or host-isolation runs;
- end-to-end Opportunity -> preparation -> authority attention delivery;
- a production GoalSupervisor/Factory/SetupConductor/voice/session composition;
- failure-injected crash/restart at every external effect boundary;
- measured startup latency, provider tokenization, GPU/VRAM, battery, and
  concurrency benchmarks on a target machine.

## Prioritized next run

1. Add one composition-owned, durable capability lifecycle coordinating
   discovery/adoption/setup, review, certification, Shadow, Canary, promotion,
   rollback, health, and restart reconciliation.
2. Add the durable Opportunity/Attention owner and prove critical permission
   requests survive bundling, restart, and resource pressure.
3. Decide and implement canonical durable Workspace/AgentProfile ownership and
   bind `GoalSupervisor`, `AgentLoop`, voice, and capability acquisition to it.
4. Standardize schema versioning/WAL/foreign keys/integrity/future-schema
   refusal across every authoritative SQLite store, or explicitly classify
   ephemeral stores as non-authoritative.
5. Make context accounting provider-aware and share session/provider/health
   state to avoid repeated probes and duplicated model context.
6. Complete resource-governor registration and staged non-blocking prewarm for
   the services that are actually composed.
7. Remove or isolate deprecated `AgentOrchestrator`/`TaskStore` compatibility
   paths after migration evidence, and add one executable full acceptance suite
   catalog entry.

## Audit decision

**GO** for the minimal adaptive core, canonical PlanningEngine task path,
brokered safety boundaries, generic primitive contracts, and current tested
baseline.

**NO-GO** for claiming the complete autonomous self-expansion architecture is
production-wired. The missing coordinator, durable lifecycle/attention owners,
and default composition gaps above must be resolved before a generated unknown
capability can safely traverse the entire requested pipeline without bespoke
core changes.
