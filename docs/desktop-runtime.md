# Desktop Runtime Foundation

The optional Qt desktop is a pure rendering client. `DesktopBackendHost` owns a
single background thread and a single long-lived asyncio event loop. That owner
creates the canonical `ApplicationRuntime`, its assistant facade, and all
SQLite-backed services. Qt submits typed work and receives queued signals; it
does not create per-request event loops or access runtime stores.

`DesktopApplicationFacade` is the desktop boundary. It exposes bounded runtime,
task, memory, control-center, provider, settings, speech, and trusted permission
projections, plus read-only Overview, Attention, Episode, and factual Activity
projections. Actionable rows retain canonical opaque identifiers: task IDs,
typed memory references, automation IDs, tool IDs, and approval request IDs.
Memory correction, deletion, retention, explicit confirmation, reverification,
and category forgetting call the application memory service. Tool health checks
and automation removal call their owning services; tool execution, generated
capability activation, certification, and lifecycle promotion remain outside
the UI boundary.

The P2 product dataflow is:

`Raw Event -> SemanticEvent/SemanticPattern -> Episode and/or
InterruptionIntelligence -> Attention + Trace -> DesktopApplicationFacade ->
native Qt desktop`.

Semantic events and patterns are bounded observations. An Episode is a durable,
bounded experience assembled only at an authoritative terminal task boundary.
Attention decides when and how a fact deserves presentation; it is not delivery,
acknowledgement, or authority. Trace is factual observability and cannot complete
tasks, grant permissions, or replay effects. The desktop is a projection and
command surface. `PermissionBroker`, reached through the trusted desktop approval
surface, remains the authority for permission and external effects. Qt does not
open any runtime store directly, and Episode rows remain separate from editable
fact/preference memory.

Overview and Activity retain explicit EMPTY and UNAVAILABLE states. Attention
items expose decision and delivery separately; refresh/list/render operations do
not acknowledge delivery. Unknown Episode outcomes remain visibly UNKNOWN and
are never presented as verified success.

Projection convergence is event-driven. `EpisodeComposer` emits an application
projection update only after the durable Episode is retrievable, and
`TraceService` emits one only after the factual Trace record is appended.
`ApplicationRuntime` owns those observers; `DesktopBackendHost` forwards the
typed update to Qt, and the Qt signal performs the main-thread refresh. Task
completion and elapsed time are not treated as evidence that Episode, Attention,
or Activity is ready. The observer chain is removed before runtime shutdown, and
late updates are dropped when the desktop is closing. Rendering never calls
`mark_delivered`.

Desktop one-time permission choices are submitted through
`TrustedDesktopApprovalSurface`. The facade reloads the canonical pending request
and creates a fingerprint-bound handoff before the runtime-owned trusted UI
authenticator submits the decision to `PermissionBroker`; visible labels and
row contents do not authorize a request. Safe Mode has no normal runtime
container and exposes only diagnostic state and configuration; chat, task,
speech, capability, automation, and permission-execution controls remain
unavailable.

Settings resolves `JARVIS_ENV_FILE`, then a checkout `.env`, then the stable
application `.env`, before defaults. Process environment values override file
values. Saves validate the complete typed candidate then atomically replace the
file. Provider/model, speech, path, and security-sensitive values require a
controlled restart.

Ollama is managed only for literal loopback endpoints. The manager probes first,
adopts an existing server, records only an exact JARVIS-owned process handle,
and never kills by image name. It projects installed, loaded, and configured
model state independently. Speech components are lazy and optional: STT uses
faster-whisper and Piper remains an optional GPL-3.0-or-later local provider.

## R4R-A3 sandbox host note

The current Copilot/VS Code agent process is itself inside a Windows Job. Its
virtual-environment `python.exe` redirector needs to start the base interpreter,
which conflicts with the sandbox's deliberate one-process Job limit and exits
with code 101. The exact Candidate 14 source and the mutable source reproduce
the same six test failures in that host; `sys._base_executable` passes the
unchanged sandbox suite 24/24. This is an agent-host validation limitation, not
a JARVIS sandbox regression. The security contract is unchanged: do not increase
the process limit, weaken Job ownership, or replace the production executable.
