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

## Canonical runtime composition

`ApplicationRuntime` is the only production composition owner. It creates one
settings object, provider, conversation service, bounded event bus, durable state
and planning stores, state machine, policy engine, SQLite audit sink, permission
broker with a deny-all approval verifier, tool registry, `PlanningEngine`,
`TaskController`, memory services, and project knowledge store. The production path
is:

`Application/UI -> TaskController -> PlanningEngine -> ToolRegistry -> Tool -> PermissionBroker -> verification -> durable state/audit/event`

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

Phase 16 adds an optional bounded coordinator above, without replacing Phase 15:

`single-agent default | proposal -> contract/scope validation -> shared delegated DAG -> bounded parallel workers -> typed aggregate result`

Only `MultiAgentCoordinator` creates delegated nodes. `AgentRegistry` contains exact
trusted worker contracts for research, coding, and computer roles; the main role
remains application code and cannot be registered as a worker. Nodes receive selected
context and evidence references rather than global conversation state. Independent
specialist nodes may run concurrently, while dependencies, cancellation, timeouts,
partial failure, and model/token/cost budgets remain deterministic. Delegated scopes
must be subsets of both the parent and worker contract, and privileged actions still
pass through the normal tool and Permission Broker path. Registered contracts are
snapshotted against mutation, and all successful nodes still require aggregate goal
evidence before completion. See
`docs/multi-agent-orchestration.md`.
