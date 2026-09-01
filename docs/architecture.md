# Architecture

> The authoritative v1 security boundary is defined in
> [`security-constitution.md`](security-constitution.md). Generated code,
> integrations, and self-improvement may not weaken that boundary.

Phase 0 establishes a local-first Python 3.12+ application with a small FastAPI health surface. The package boundaries are intentional:

- `core` owns configuration, errors, logging, and cross-cutting primitives.
- `ai/providers` contains provider interfaces and future adapters. Provider SDKs must not leak into core orchestration.
- `tools` is the only future entry point for capabilities that may affect the host.
- `permissions` will become the deny-by-default permission broker.
- `memory`, `computer`, and `autonomy` are reserved domain boundaries and contain no capability implementation yet.
- `security` owns security policy and controls.
- `frontend` is separate from domain models and services.

AI code may not directly access privileged OS capabilities. Privileged operations must go through a tool and the permission broker. Domain models must not depend on UI code. Long-running operations must carry task IDs, support cancellation, and emit observability data as those capabilities are introduced.

Phase 1 adds a deliberately narrow conversational path: normalized text or transient microphone audio is sent through a provider-neutral conversation service, then surfaced to the desktop UI and optionally local TTS. `bootstrap.py` is the composition root and is the only application location that selects Ollama, faster-whisper, sounddevice, or pyttsx3. The PySide6 UI calls `JarvisAssistantService`, never a provider directly.

Conversation history is process-local and typed. The ordinary chat path has no long-term memory, tool execution, computer control, planning, or autonomous behavior. Raw microphone samples remain in memory only and are discarded after transcription. Long-running streams have cancellation requests and UI-visible status events.

Provider selection is registry-based and persistent execution sessions are
separate from task, goal, user-memory, and conversation-memory authorities;
see [provider-and-session-runtime.md](provider-and-session-runtime.md).

Phase 2 adds a separate, bounded task path while preserving the ordinary chat path:

`request → interpret → construct task → plan → select capability → execute → observe → verify → respond`

`AgentOrchestrator` owns task lifecycle transitions and delegates interpretation, planning, capability selection, execution, observation, verification, and response generation to focused services. Task and plan snapshots are typed immutable records stored through `TaskStore`; Phase 2 uses `InMemoryTaskStore`, but the interface supports a later SQLite adapter.

Model planning is treated as untrusted input. `SchemaValidatedPlanner` validates it through strict Pydantic schemas before it becomes an application-owned `Plan`. The model cannot select unregistered capabilities, alter task state, override budgets, or determine final success. `ToolRegistry` currently permits only explicitly injected fake/test tools; no OS-capable tools are implemented.

Each execution has maximum-step, timeout, cancellation, and replan limits. A tool observation is not success: a `StepVerifier` must return explicit success evidence. Failed or unverifiable results replan within budget or transition to an observable failure state.

Phase 3 replaces the minimal capability string contract with a versioned Tool/Skill boundary. Every registered tool exposes a `ToolManifest`, strict input/output schemas, declared permissions, supported platforms, timeout guidance, and health state. The orchestrator passes only `ToolExecutionContext`, then consumes a structured `ToolResult`; it does not import a tool implementation or expose an application container. The current registry contains only calculator, local-time, and unavailable-weather tools. See `docs/tools.md` for the authoring contract.

Phase 4 makes `ToolRegistry` the central capability catalog. Registration is
explicit and deterministic; duplicate IDs cannot replace an implementation.
Registration, enabled state, platform support, health, and usability are
tracked separately. Unknown-directory plugin discovery is prohibited.

The health API remains health-only. It reports application version, health state, and startup completion; it intentionally does not expose shell, filesystem, computer-control, camera, or autonomous behavior.

Phase 5 replaces caller-supplied permission sets with a mandatory brokered tool
path:

`AI/planner -> strict tool input -> trusted action descriptor -> PermissionBroker -> policy -> optional trusted-user approval -> private authorized implementation`

`ToolRegistry` binds each exact tool instance and its manifest permissions to one
`PermissionBroker`. `Tool.invoke` is the reserved entry point; subclasses cannot
override it or define a public `execute` method. The base validates model arguments,
asks the broker to authorize the exact fingerprinted action, attaches the broker
receipt, invokes `_execute_authorized`, and records the outcome. Unknown tools,
permissions, scopes, and policy all fail closed. See `docs/threat-model.md` and
`docs/permission-model.md` for the trust assumptions and policy contract.

Optional MCP servers enter through the native `MCPExtensionManager` before the
registry is sealed. The manager validates local configuration and untrusted MCP
tool schemas, applies an `mcp:<extension>:<tool>` namespace, and registers a
typed adapter. MCP descriptions/results are data only; every invocation still
uses `ToolRegistry -> PermissionBroker -> Policy`, and no broker, vault, or
trusted-core object is passed into the MCP process. See `docs/mcp.md`.

Generated integration code is never imported into Trusted Core. The native
`SandboxProcess` owns a separate child process, dedicated work/data directories,
sanitized startup environment, bounded JSON-over-stdio IPC, and Windows Job
Object process-tree/resource cleanup. It passes no broker, policy, Vault,
approval, audit, mutation, or runtime-container object. Job Objects are not a
complete filesystem/network sandbox; see `docs/sandbox-isolation.md` for the
actual guarantees and remaining AppContainer/restricted-token boundary.

Sandbox host access is available only through the trusted-side typed
`HostProxy`. Its manifest binds exact integration/package identity, declared
capability/action, roots, origins, credential bindings, and bounds before the
normal `Tool -> PermissionBroker -> Policy -> approval` path. Network defaults
to deny; filesystem requests name only package-data or explicitly approved user
roots; credentials remain opaque and are resolved by `CredentialVault` on the
trusted side; process/device operations are typed declarations rather than
arbitrary spawn. See `docs/sandbox-host-proxies.md`.

Generated packages also pass through the data-only `GeneratedPackageReviewer`.
It verifies manifest/provenance/source hashes and statically rejects unsafe
execution, deserialization, process/network bypasses, path traversal, secret
logging, and approval spoofing. Missing source, binaries, migrations, unknown
network destinations, and elevated permissions require manual review. The
reviewer cannot execute a package or modify reviewer, policy, broker, or
approval authority; a passing result does not replace certification or runtime
sandbox and broker gates. See `docs/generated-package-review.md`.

Before staged activation, `PackageCertifier` runs BUILD, static audit, unit and
sandbox integration tests, permission diff, trusted authority decision,
install, healthcheck, and verification. Its immutable `CertificationRecord`
binds exact package/source/dependency/manifest hashes and evidence. CERTIFIED
is not ACTIVE; `PackageActivationService` owns the separate
CERTIFIED/SHADOW/CANARY/ACTIVE/DEGRADED/QUARANTINED/ROLLED_BACK lifecycle and
hot-load registration remains a broker-gated runtime operation. See
`docs/package-certification.md` and `docs/package-activation.md`.

Generic provisioning uses the same boundary through typed
`ProvisioningPlan`/`ProvisioningAction` records. Providers inspect reality
before every effect, never receive arbitrary shell scripts, and return bounded
outcomes for verification, recovery, and explicit rollback. Each action has
one exact brokered permission and an idempotency declaration; provisioning is
not a second package catalog or execution authority. See
`docs/provisioning.md`.

`SetupConductor` coordinates adoption-first onboarding and future capability
setup around that provisioning boundary. It collects one normalized
`SetupContext`, preserves existing installations and user data unless the user
chooses otherwise, and persists resumable setup state. Setup state is not task,
permission, credential, audit, or artifact authority. See
`docs/setup-conductor.md`.

`CapabilityFactory` applies the central `DISCOVER -> ADOPT -> REUSE -> BUILD`
order. It reuses active JARVIS capabilities and compatible machine/API/library
capabilities before requesting setup or generating an inactive package
proposal. Generated proposals stop at `READY_FOR_APPROVAL`; they cannot become
active or authoritative through factory output alone. See
`docs/capability-factory.md`.

The desktop adapter is a minimal generic shell with Home, Tasks, Memory,
Capabilities, Activity, and Settings surfaces. `FirstRunWizard` delegates
optional/resumable areas to `SetupConductor`; `TestDriveRegistry` reports
component-level PASS/FAIL/SKIPPED/NOT_AVAILABLE evidence and only declares
full readiness when required configured checks pass. `StartupWarmupRegistry`
prewarms optional local components asynchronously and cannot grant authority.
Launch profiles are presentation/startup preferences, never permission or
security-policy switches. See `docs/desktop-shell.md` and
`docs/onboarding-test-drive.md`.

The composition root also owns one `ResourceGovernor` and passes it to
resource-consuming services. It observes available host telemetry without
fabricating unsupported GPU, battery, idle, or foreground-workload facts.
Priority-aware decisions can defer background/indexing/benchmark work, reduce
concurrency, or select a smaller acceptable model; they never grant
PermissionBroker authority or unnecessarily cancel an important foreground
task. See `docs/resource-governor.md`.

The generic Control Center is a refreshable application projection over explicit
capability, tool, skill, agent, MCP, model, planning, memory, knowledge,
permission, audit, health, and recovery services. Its semantic action metadata
is discovered dynamically and is not a hard-coded voice command tree. Desktop
and voice use `OutputMediumProfile` for formatting only and receive the same
trusted permission presentation object; neither channel can create authority.
See `docs/control-center.md`.

Human-readable execution facts are provided by `ExecutionTrace` and the
versioned `TraceStore`. They record bounded lifecycle facts, sanitized
arguments, usage, permissions, results, artifact links, evidence, and
verification outcomes without storing prompts or hidden chain-of-thought.
Trace replay produces only a guarded plan: simulation has zero effects,
checkpoint replay creates no external effects, and safe re-execution requires
an explicitly replay-safe operation plus fresh current authorization. Recorded
approvals are never inherited and `UNKNOWN_OUTCOME` blocks replay until trusted
reconciliation. See `docs/execution-trace-and-replay.md`.

Long-horizon goals use `GoalSupervisor` only as a bounded coordinator around
the canonical `PlanningEngine`. `GoalSupervisorStore` persists immutable user
intent and high-level recovery state; it does not own task, plan, permission,
capability, artifact, or verification truth. Missing capabilities go through
the registry and existing `DISCOVER -> ADOPT -> REUSE -> BUILD` factory, and
only active certified capability results may proceed. Before `BLOCKED`, all
generic alternative categories are examined. Time, token, cost, retry,
replan, disk, network, and risk ceilings are trusted immutable limits; active
or unknown execution outcomes require reconciliation rather than blind retry.
See `docs/goal-supervisor.md`.

Phase 6 adds a controlled computer capability layer without changing that boundary:

`AI/planner -> typed computer tool -> PermissionBroker -> policy/approval -> adapter -> Windows`

The planner sees semantic tool contracts such as application launch, window focus,
and control text entry. It does not receive Windows library objects, handles, raw
process launch, a shell-string primitive, or direct clipboard/filesystem/screenshot
APIs. `ComputerAdapter` is the platform-neutral interface; the optional
`WindowsUiAutomationAdapter` translates authorized semantic requests to Windows UI
Automation. Coordinate clicks are an explicitly labelled fallback tool rather than
the normal control path. Screenshot bytes stay in a trusted `ScreenshotStore`; tool
results expose only metadata and an opaque reference. Controlled terminal execution
resolves a trusted command ID to a fixed executable and command family, uses an
argument array with `shell=False`, and supports timeout and cancellation.

Phase 7 adds a provider-neutral visual workflow above the computer tools:

`OBSERVE -> UNDERSTAND -> GROUND -> ACT -> OBSERVE AGAIN -> VERIFY`

`BrokeredDesktopObserver` obtains screenshots, windows, and optional accessibility
trees only through registered screen-read tools. A `VisionProvider` receives a
screenshot reference, objective, semantic tree, and prior observation and returns
structured suggestions. Trusted fusion assigns target IDs, validates DPI-aware
geometry, and fingerprints the current display. `VisualInteractionService`
re-observes immediately before action, rejects stale or materially changed state,
uses the existing brokered computer tool for the action, then obtains a new
observation for explicit success/failure/uncertain verification. Vision code has no
direct keyboard, mouse, window, or policy access.

Phase 8 adds a separate one-shot camera boundary:

Phase 17 adds optional local voice activation in `jarvis/voice`. The controller
owns one UI-visible voice state machine and sends idle frames only to a local
wake-word provider. After wake it uses VAD and existing transient STT, then
delegates task creation/cancellation to the canonical `TaskController` through a typed
adapter. `OrchestratorVoiceTaskRunner` is retained only as a deprecated migration
adapter. TTS interruption is explicit and does not bypass the Permission
Broker. See `docs/voice-activation.md` for lifecycle and privacy guarantees.

Phase 18 makes `jarvis.state.ApplicationStateMachine` the formal lifecycle
coordinator. It owns separate global application and per-task state, explicit
fail-closed transition tables, durable task recovery snapshots, and auditable
transition records. Planner, legacy orchestrator, and optional voice adapters
can publish progress through it without allowing UI/model code to mutate state.
See `docs/state-machine.md`.

The typed `jarvis.events` bus is the bounded observational coordination channel
for task, goal/plan/step, tool, permission, runtime, voice, camera,
capability/integration, health, automation, and error facts. Event envelopes are
strictly typed and carry correlation/causation metadata, but events never grant
authority or replace the owning state, planning, permission, or audit store.
Subscriber queues and correlation ledgers are bounded; slow/failing subscribers
are isolated, and shutdown cancels consumers. External/model content remains
untrusted event data.

## Canonical runtime composition

`ApplicationRuntime` is the only production composition owner. It creates one
settings object, provider, conversation service, bounded event bus, durable state
and planning stores, state machine, policy engine, SQLite audit sink, permission
broker with a deny-all approval verifier, tool registry, `PlanningEngine`,
`TaskController`, memory services, and project knowledge store. The production path
is:

`Application/UI -> TaskController -> PlanningEngine -> ToolRegistry -> Tool -> PermissionBroker -> verification -> durable state/audit/event`

`TaskController` is the only application-facing task API. It delegates creation,
submission, inspection, execution, resume, cancellation, permission decisions,
status, and result/evidence retrieval to the runtime-owned `PlanningEngine` and
its stores. UI adapters do not construct an orchestrator or select an execution
engine. `AgentOrchestrator` remains compatibility-only and is not part of the
production composition.

Approval will eventually use a separate trusted-local path:

`authenticated local UI -> isolated TrustedApprovalAuthenticator -> exact single-use context -> TaskController -> PermissionBroker`

The canonical runtime currently creates no minting authenticator and its broker
therefore denies every submitted approval context. Before privileged providers are
enabled, a separately authenticated local UI service must encapsulate the minting
capability and give only its paired verifier to the broker. Model, tool, worker, and
integration contexts receive neither capability.

`PlanningEngine` is the canonical production task engine. The legacy
`AgentOrchestrator` remains for compatibility tests and migration only; it is not
accepted by the application service or desktop composition. Safe calculator/local
time tools are enabled by default. Computer control, camera, application/package
management, self-improvement, remote approval, autonomous scheduling, and
multi-agent execution are disabled. Because those production compositions do not
yet exist, requesting them in v1 configuration fails startup into safe mode rather
than silently enabling or ignoring them.

`AI/planner -> camera.list/camera.capture -> PermissionBroker(camera.read) -> CameraController -> CameraProvider`

The controller owns device opening, bounded frame capture, visible inactive/opening/
active/error state, and `finally` cleanup. Camera tools never expose an unrestricted
stream. Captured bytes are placed only in an expiring in-memory frame store by
default; `CameraVisionBridge` passes an expiring reference to the existing
`VisionProvider` and releases it after analysis. Camera image reasoning remains
separate from camera hardware and from permission decisions.

Phase 9 adds an opt-in controlled application-manager boundary:

`AI/planner -> typed application tool -> PermissionBroker -> policy + fresh trusted approval -> immutable plan -> provider/runtime -> Windows`

Inventory and package-search results are evidence, not authority. Trusted composition
injects an inventory provider, package provider, managed runtime, and ephemeral plan
store; none is registered in the default tool catalog. A package plan is immutable,
expires, and is consumed before the provider operation. Installation/update tools
receive `application.install` and the hard `software_installation` safety class, so
even an allow policy requires a fresh trusted-user approval. The approval describes
the exact provider-issued package ID, source, publisher, and version. The runtime
accepts a current `ApplicationRecord`, never a model executable/path, and can close
only processes it launched and tracks. Post-operation verification re-queries the
inventory, checks identity/version/executable, and confirms launch capability.

Phase 10 adds an advisory capability-gap boundary:

`missing capability -> discover evidence -> explainable evaluation -> recommendation -> user/policy decision`

`CapabilityGap` records the unmet task requirement and evidence. Provider-neutral
discovery can read a trusted internal tool catalog, trusted plugin/integration/software
catalogs, or already-authorized controlled web research. Every candidate remains data:
it is not a tool registration, installation plan, permission grant, setup action, or
execution request. External descriptions are isolated as untrusted hashed evidence;
they never become instructions. Rankings score functional fit, source quality,
privileges, maintenance, compatibility, reversibility, and testability with stable
factor explanations. A future tool adapter can be proposed only as a data-only
specification; generated source is neither written, imported, nor executed.

The native browser boundary is a provider-neutral semantic bridge. It exposes
only bounded tab/document observations and stable references, with API/protocol,
semantic DOM/accessibility, OS accessibility, vision, and coordinate fallbacks
owned by the adapter. Every browser operation remains behind the normal
`Tool -> PermissionBroker -> Policy` boundary; page content is untrusted data,
password values are redacted, and cross-origin semantic data is not exposed.
Navigation, mutation, and tab-close events are observational only. See
`docs/browser-semantic-bridge.md`.

Credentials have a separate sole authority: `CredentialVault` stores metadata in
its own database and secret bytes only through an explicitly selected secure
backend. The production Windows backend is Credential Manager; unsupported
hosts fail closed. Models and ordinary services receive opaque references, while
trusted authenticated-request proxies perform scoped use. Generic authentication
providers cannot grant permission or become a second secret authority. See
`docs/credential-vault.md` and `docs/authoritative-state-map.md`.

Phase 11 adds a high-risk, proposal-and-test improvement boundary:

`observe -> identify -> specify -> assess risk -> isolate -> modify -> gate -> evaluate -> propose`

`ImprovementEngine` separates structured candidate reasoning, a data-only coding
agent, trusted worktree creation and file application, dependency analysis,
sandboxed test gates, independent security checking, protected regression
evaluation, and proposal storage. The coding agent receives a bounded specification
and safe evidence records, then returns typed text changes; it receives no filesystem,
command, Git, permission, approval, merge, or deployment primitive. Trusted code
applies those changes only to a generated detached worktree outside the clean
production checkout and repeatedly verifies that production stayed at the same
full revision.

A run may normally select no worthwhile improvement. A selected change must pass
format/lint, type, unit, integration, security, regression, and startup/health gates,
plus the default-deny dependency guard. Protected evaluation compares the candidate
with a baseline captured before modification; generated tests alone cannot establish
improvement. Success produces only an expiring, fingerprinted
`AWAITING_TRUSTED_APPROVAL` proposal with previous-known-good rollback metadata.
Phase 11 has no autonomous approval, merge, push, installation, deployment, or
production-write path. See `docs/autonomous-improvement.md`.

Open-source donor study is a separate metadata-only boundary. `DonorStudyService`
requires an authoritative upstream, exact revision, inspected license/notices,
source-file digests, concept comparison, risk/benefit, tests, and benchmarks
before creating a review-only `NativeAdaptationProposal`. It cannot clone,
import, execute, install, add dependencies, or alter production. A proposal is
handed to the existing `ImprovementEngine` as an unexecuted signal; the same
isolated workspace, security, dependency, protected benchmark, regression,
rollback, and trusted-approval gates remain mandatory. See
`docs/native-donor-study.md`.

Phase 12 adds repository-grounded project knowledge without creating a new
authorization path. Human-authored `docs/` and ADRs remain authoritative or
historical sources; `knowledge/generated/project-index.json` is a disposable
generated view with per-source hashes, Git revision, and generation time. The
indexer derives components from package source and tools/permissions from the
trusted registry and enums. `KnowledgeStore` provides local lexical search and
stale-source detection. Knowledge is context only: it cannot register tools,
grant permissions, execute actions, or rewrite historical decisions.

Phase 13 adds a controlled system-test boundary:

`trusted suite catalog -> controlled subprocess -> redacted evidence -> TestRun -> diagnosis`

Test suites contain fixed executable/argument vectors, a project-relative working
directory, timeout, output format, category, and hardware policy. `ControlledTestRunner`
does not expose a model-selectable shell; unknown suites and scope escapes fail closed.
Structured results and separate artifacts can inform Phase 11 evaluation, but test
success does not authorize an improvement, merge, deployment, installation, or any
host capability. Deterministic fake-provider workflow suites run in CI, while startup
and hardware tests require explicit trusted/manual enablement. See
`docs/system-testing.md`.

Phase 14 adds four explicitly separate memory domains without adding authority:

`bounded process-local conversation context | policy-gated SQLite user memory | compact SQLite action episodes | read-only Phase 12 project knowledge`

`ConversationContextService` owns only bounded in-process context and optional
trusted summarization. `LongTermMemoryService` requires an explicit trusted policy
decision and user confirmation before persisting a user-sourced fact. `EpisodicMemoryService`
retains compact completed-action outcomes instead of permission audit logs. `ProjectSystemMemory`
queries `KnowledgeStore` directly, retaining provenance/staleness without copying
project data into user memory. The durable SQLite store uses reviewed sequential
migrations, retention expiry, secret rejection, and user-facing inspection/deletion
operations. Retrieval returns separate conversation, long-term, episodic, and system
lists; untrusted historical content remains data, never instructions. See
`docs/memory.md`.

Phase 15 introduces a durable single-agent planning control plane:

`goal -> untrusted proposal -> validated owned DAG -> brokered execution -> step verification -> goal verification -> replan / complete`

`PlanValidator` resolves every node against the live `ToolRegistry`, validates exact
capability, manifest permissions, Pydantic arguments, dependencies, graph bounds, and
trusted verification rules. `PlanningEngine` alone owns lifecycle transitions,
budgets, scheduling, cancellation, retries, permission pauses, and replanning.
`SQLitePlanningStore` atomically retains the complete task plus versioned plan, so a
broker pause resumes without reconstructing the task. Resume never grants permission;
the same exact action re-enters the broker. Step success is evidence only, and the
plan completes only after goal-level verification. See `docs/planning-engine.md`.

Pending plans are inspected and edited through the typed application task
service (`PlanInspection`/`PlanEdit`). `PlanningEngine` converts each edit
through `PlanValidator` and persists a new revision; it remains the only
planner and task authority. A checkpoint branch carries only confirmed step
evidence and never undoes or replays an external effect. See
`docs/plan-editing.md`.

Phase 16 adds an optional bounded coordinator above, without replacing Phase 15:

`single-agent default | proposal -> contract/scope validation -> shared delegated DAG -> bounded parallel workers -> typed aggregate result`

Only `MultiAgentCoordinator` creates delegated nodes. `AgentRegistry` contains exact
trusted worker contracts for Research, Coding, IntegrationBuilder, Verification,
Diagnostics, and the existing computer role; the main role remains application code
and cannot be registered as a worker. Nodes receive selected context and evidence
references rather than global conversation state, plus an immutable profile/model
policy, tool/capability allowlists, narrowed filesystem/network scope, data ceiling,
delegation policy, and output schema. Independent specialist nodes may run concurrently,
while dependencies, cancellation, timeouts, partial failure, and model/token/cost
budgets remain deterministic. Delegated scopes must be subsets of both the parent and
worker contract; secret context is rejected; and privileged actions still pass through
the normal tool and Permission Broker path. Registered contracts are snapshotted
against mutation, recursion is bounded to one delegated level, and all successful
nodes still require aggregate goal evidence before completion. See
`docs/multi-agent-orchestration.md`.

Phase 17 adds a derived ambient presentation boundary without adding authority:

`canonical EventBus/runtime facts -> PresenceProjection -> PresenceSnapshot`

`PresenceProjection` is a rebuildable view of task, voice, permission, tool, health,
error, runtime, and Safe Mode facts. It does not own lifecycle state, permission
decisions, or task completion. Optional microphone/audio/activity signals are
bounded display hints only. `PresenceThemeManifest` is declarative and may refer
only to validated package-owned asset references; trusted desktop UI does not
execute theme HTML, JavaScript, Python, or arbitrary code.

`PresentationSurface` is the generic application boundary for presenting typed
artifact references, package assets, bounded documents/charts/plans/comparisons,
and declarative controls. It never loads an arbitrary filesystem path. Its
`query_state()` result is an observed `UiStateSnapshot`, not an echo of the last
request, so `VerificationEngine` can compare intended and actual surface state.
Presentation controls are metadata rendered by application services; they do not
bypass the normal TaskController, PlanningEngine, Tool, or PermissionBroker
paths. Gesture/camera control remains a future self-built capability candidate,
not a core feature or donor runtime. See
`docs/presence-and-presentation.md`.

Execution is not proof of the requested outcome. The typed
`jarvis.verification.VerificationEngine` evaluates a trusted
`VerificationPlan` against bounded `EvidenceRecord` observations and returns a
separate verification level/disposition. Model claims are never evidence;
stale or contradictory observations cannot complete a goal. A failed
verification preserves the original goal and returns diagnosis/replan or an
explicit user-confirmation request when the physical result cannot be observed.
`PresentationSurface.query_state()` can supply screen evidence, but the
queried state—not the presentation request—is authoritative for that
observation. Verification does not execute, authorize, or replace
`PlanningEngine`.

Effect previews and compensation remain separate from execution. Trusted
capability code may provide a structured `EffectPreview` with exact target,
change, permissions, resources, reversibility, artifacts, and verification
metadata; model prose cannot create that metadata. `CompensationExecutor`
re-enters the normal `ToolRegistry -> PermissionBroker -> Policy/approval`
boundary and requires a matching state baseline plus fresh
`VerificationEngine` evidence. Stale state, failed compensation, unknown
outcomes, and failed verification are explicit results.
`PlanStudioEffectProjection` and optional effect trace records are derived
presentation/observability projections only. See
`docs/effect-previews-and-compensation.md`.

Phase 18 adds deterministic pre-activation UI evidence:

`declarative package UI -> UISimulationHarness -> semantic checks/render artifact -> certification evidence`

`UISimulationHarness` loads only a validated package-matching manifest. It
renders built-in and manifest-declared safe states, exposes fake capability
endpoints, and has no real Tool, broker, process, network, or authority path.
Each shot records deterministic semantic view/control-tree fingerprints,
binding and asset checks, approval-spoof checks, layout success, and zero
external effects. `ArtifactStore` may retain the bounded render/screenshot
artifact. Semantic/control-tree evidence is primary; pixel equality is never the
sole acceptance criterion. UI-bearing packages must supply this evidence to
`PackageCertifier` before certification and cannot treat it as activation. See
`docs/ui-simulation-harness.md`.

Phase 19 adds empirical hardware/model inventory without adding authority:

`trusted hardware probe -> measured HardwareProfile -> ModelPlanner -> compatible model combination`

`HardwareInventoryService` records CPU, RAM, GPU/VRAM, driver/runtime, disk, OS,
and scheduling-concurrency facts only when a trusted probe establishes them.
Unavailable values stay unknown. `ModelMetadata` tracks all supported model
roles plus family/version/quantization, runtime/source, modalities, context,
resource requirements, license, compatibility, and provenance. Published and
community claims remain distinct from timestamped `MEASURED_ON_THIS_MACHINE`
results. `ModelPlanner` is a bounded descriptive selector: it checks role
coverage, exact compatibility tags, aggregate or peak memory, disk, VRAM, and
concurrency for combinations, and returns `UNKNOWN` when required capacity is
not measured. It does not download, load, activate, authorize, or claim that a
model works on a different machine. CI uses fake hardware/model fixtures; real
hardware and model measurements remain explicitly unexecuted unless separately
run. See `docs/hardware-and-models.md`.

Phase 20 adds local model lifecycle and inference routing without adding a
provider or vendor authority:

`typed catalog -> hash/size verification -> app-owned model root -> typed runtime`

`LocalModelManager` supports discovery, compatibility checks, download,
integrity, install, load/unload, health, benchmark, removal, and repair. It has
no shell or arbitrary post-install hook. `ProviderRouter` applies explicit
privacy, quality, speed, cost, latency, context, tool/schema, health, resource,
and concurrency constraints. Provider-neutral STT/TTS definitions use the same
router and degrade to `NO_LLM`/text-only when policy allows. Routing never
grants permission or activates a model. See
`docs/model-management-and-routing.md`.

## Hierarchical diagnostics and repair

`ComponentDoctor` is the transient composition-root-owned diagnostic
orchestrator. `CapabilityHealthService` remains the health authority and
routes failures to the explicit CORE, PROVIDER, SANDBOX, PROVISIONING, or
package-declared CAPABILITY owner. Package declarations provide only bounded
read-only probes, approval-bound repair metadata, fallback strategies, and
expected verification; trusted application code binds executable callbacks.
Unknown repair outcomes quarantine without replay, while a safe fallback may
degrade one capability without silently changing privacy or authority
semantics. See `docs/component-doctor.md`.
