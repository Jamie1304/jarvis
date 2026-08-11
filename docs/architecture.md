# Architecture

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

`AI/planner -> camera.list/camera.capture -> PermissionBroker(camera.read) -> CameraController -> CameraProvider`

The controller owns device opening, bounded frame capture, visible inactive/opening/
active/error state, and `finally` cleanup. Camera tools never expose an unrestricted
stream. Captured bytes are placed only in an expiring in-memory frame store by
default; `CameraVisionBridge` passes an expiring reference to the existing
`VisionProvider` and releases it after analysis. Camera image reasoning remains
separate from camera hardware and from permission decisions.
