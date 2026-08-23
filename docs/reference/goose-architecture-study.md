# Goose architecture study — reference only

**Status:** research only; no implementation authority

Goose is a donor/reference project. JARVIS must not add a Goose package,
binary, ACP server, runtime import, MCP client, extension, or compatibility
layer as a consequence of this study.

## Provenance boundary

The checked-out JARVIS documentation does not contain the “reference pinned
Goose revision” named in the task. That pin is therefore **UNRESOLVED** and no
claim below treats a moving branch as the project pin. For orientation only,
the current upstream branch was observed at:

- Repository: <https://github.com/aaif-goose/goose>
- Observed branch: `main`
- Observed SHA: `8d844eecbdfd65626a881c9e8784ae8dc6093f1d`
- Observation date: 2026-08-23
- Upstream overview: <https://github.com/aaif-goose/goose/blob/main/documentation/docs/goose-architecture/goose-architecture.md>

The SHA above is not a substitute for the missing project pin. Before this
document is used for implementation or licensing decisions, the project owner
must supply the intended immutable revision and re-run the file-level study.

Disposition vocabulary:

- **PORT:** not approved by this research note; would require provenance,
  license review, and a JARVIS-specific security design.
- **REIMPLEMENT:** reproduce only the generic behavior in JARVIS-native code,
  with JARVIS stores, brokers, limits, and tests.
- **INSPIRE:** useful design idea, not a code-port target.
- **REJECT:** conflicts with JARVIS architecture or security rules.

## Pattern study

### AgentLoop

- **Upstream file/revision:** `crates/goose/src/agents/agent.rs`, observed
  `main@8d844eecbdfd65626a881c9e8784ae8dc6093f1d`; exact pinned revision
  unresolved. Summary: the agent owns the interactive reply/process loop and
  routes provider messages, tool calls, results, and final responses.
- **Problem:** turn-by-turn model interaction needs bounded continuation and a
  place to handle tool results.
- **Approach:** a central agent loop repeatedly sends conversation context to a
  provider, dispatches tool calls, adds results, and stops on a final response
  or an error/limit.
- **JARVIS destination:** `PlanningEngine` for durable task execution and the
  application conversation service for transient dialogue. Do not create a
  second production task loop.
- **Security differences:** JARVIS requires typed plan validation, exact
  budgets, idempotency, durable audit, `Tool -> PermissionBroker -> Policy`,
  and `UNKNOWN_OUTCOME -> RECOVERING`; model continuation cannot authorize an
  effect.
- **Tests:** planning lifecycle, exact budget, retry exhaustion, cancellation,
  unknown outcome, restart reconciliation, and conversation-provider tests.
- **Disposition:** **REIMPLEMENT** only at the existing JARVIS ownership
  boundaries.

### Operation pipeline

- **Upstream file/revision:** `crates/goose/src/agents/agent.rs` and
  `documentation/docs/goose-architecture/goose-architecture.md`, observed
  `main@8d844eecbdfd65626a881c9e8784ae8dc6093f1d`.
- **Problem:** provider output must become an executed operation and then be
  represented back to the provider.
- **Approach:** request -> provider chat -> structured extension/tool call ->
  execution -> tool result -> provider continuation.
- **JARVIS destination:** typed application services, `PlanningEngine`, and
  `ToolRegistry`; events remain observations only.
- **Security differences:** Goose’s general extension flow is not JARVIS
  authority. JARVIS rejects malformed security metadata, requires pre-effect
  audit and broker policy, and never treats tool results or external content as
  policy.
- **Tests:** malformed tool calls, permission pause/resume, audit ordering,
  fingerprint mismatch, and forbidden direct UI/tool paths.
- **Disposition:** **INSPIRE**.

### Tool calling and unknown tools

- **Upstream file/revision:** `crates/goose/src/agents/agent.rs` and the Goose
  error-handling documentation linked from the architecture guide, observed
  `main@8d844eecbdfd65626a881c9e8784ae8dc6093f1d`.
- **Problem:** providers can emit invalid JSON, missing tool names, or calls
  that are no longer available.
- **Approach:** convert errors into tool responses so the model can continue.
- **JARVIS destination:** strict `ToolRegistry` lookup and typed planning
  validation; unknown tools fail the plan/task visibly and cannot become a
  dynamically trusted capability.
- **Security differences:** a model cannot register a tool, select a provider,
  broaden permissions, or recover an unknown external effect by retrying.
- **Tests:** unknown tool, malformed arguments, invalid permission metadata,
  duplicate calls, and fail-closed planner behavior.
- **Disposition:** **REIMPLEMENT** the validation/error contract; **REJECT**
  model-directed dynamic tool registration.

### Context revision and compaction

- **Upstream file/revision:** `crates/goose/src/agents/agent.rs` plus the
  context-revision section of
  `documentation/docs/goose-architecture/goose-architecture.md`, observed
  `main@8d844eecbdfd65626a881c9e8784ae8dc6093f1d`.
- **Problem:** messages, tool output, resources, and instructions exceed the
  provider context budget.
- **Approach:** remove stale material, summarize, and reduce verbose outputs;
  Goose describes smaller/faster summarization and selective rewriting.
- **JARVIS destination:** transient conversation context and bounded model
  prompts. Durable task/plan/audit truth remains in its authoritative stores;
  compaction cannot rewrite it.
- **Security differences:** summaries are untrusted derived context, never
  policy, approval, identity, or evidence of execution. Secrets remain outside
  ordinary prompts and summaries.
- **Tests:** context limits, compaction determinism, secret exclusion, and
  preservation of task IDs/correlation IDs and exact tool results.
- **Disposition:** **INSPIRE**.

### Retry, repetition, and max turns

- **Upstream file/revision:** `crates/goose/src/agents/agent.rs` and related
  agent tests, observed `main@8d844eecbdfd65626a881c9e8784ae8dc6093f1d`.
- **Problem:** a provider can repeat a call, loop indefinitely, or continue
  after a failed operation.
- **Approach:** bounded turns and error feedback keep the loop progressing or
  stop it.
- **JARVIS destination:** existing exact step budgets, bounded retries,
  repetition/idempotency reservations, cancellation, and recovery state in
  `PlanningEngine`.
- **Security differences:** permission waiting does not consume an effect
  attempt; safe pre-effect failure may retry; `UNKNOWN_OUTCOME` is never blindly
  replayed and is reconciled as `RECOVERING`.
- **Tests:** budget boundary/final verification, duplicate reservation,
  fingerprint mismatch, safe transient retry, unknown outcome, and exhaustion.
- **Disposition:** **REIMPLEMENT** using existing durable planning contracts.

### ProviderRegistry

- **Upstream file/revision:** `crates/goose/src/providers/canonical/` and
  provider configuration modules, observed
  `main@8d844eecbdfd65626a881c9e8784ae8dc6093f1d`.
- **Problem:** multiple model providers need discovery and provider-specific
  configuration.
- **Approach:** registry/catalog metadata maps provider/model choices to
  implementations and capabilities.
- **JARVIS destination:** narrow AI provider abstraction and trusted startup
  configuration; future user-created capabilities may be adapters outside the
  minimal core.
- **Security differences:** v1 allows only the validated literal-loopback
  Ollama path. Model/provider configuration cannot enable unsupported
  privileges or alter policy.
- **Tests:** provider allowlist, endpoint validation, malformed configuration,
  no ambient credentials, and no runtime donor dependency.
- **Disposition:** **INSPIRE**; **REJECT** a broad built-in integration catalog.

### Sessions

- **Upstream file/revision:** `crates/goose/src/session/` and agent session
  references, observed `main@8d844eecbdfd65626a881c9e8784ae8dc6093f1d`.
- **Problem:** conversations need identity, history, model settings, and
  restart/resume behavior.
- **Approach:** session manager owns session records and exposes them to agent
  and extensions.
- **JARVIS destination:** future warm `AgentSession` interface for voice and
  conversation; durable task truth remains PlanningEngine and durable memory
  remains its own store.
- **Security differences:** session history is data, not authorization;
  approval receipts and unknown effects are not resurrected from conversation
  state.
- **Tests:** session isolation, cancellation/rebuild after barge-in, restart
  boundaries, secret handling, and task/session separation.
- **Disposition:** **INSPIRE** pending the project’s session contract.

### MCP and ExtensionManager

- **Upstream file/revision:** `crates/goose/src/agents/extension_manager.rs`,
  `crates/goose/src/agents/mcp_client/`, and
  `crates/goose/src/agents/platform_extensions/ext_manager.rs`, observed
  `main@8d844eecbdfd65626a881c9e8784ae8dc6093f1d`.
- **Problem:** external servers expose discoverable tools and resources through
  a common protocol.
- **Approach:** an extension manager starts/connects MCP extensions, lists
  tools, dispatches calls, and can manage enabled extensions.
- **JARVIS destination:** future external capabilities only through a separate,
  least-privilege process and typed broker-owned IPC. Generic tool contracts
  may be reused conceptually; no Goose manager belongs in the runtime.
- **Security differences:** JARVIS generated/unreviewed code cannot run inside
  the trusted process; discovery cannot register authority; every privileged
  call still passes the JARVIS broker and policy; Safe Mode disables generated
  activation.
- **Tests:** process isolation, capability allowlists, protocol fuzzing,
  shutdown, timeout, broker enforcement, and Safe Mode activation denial.
- **Disposition:** **INSPIRE** for a future capability boundary; **REJECT**
  in-process donor extension management.

### Skills

- **Upstream file/revision:** `crates/goose/src/skills/` and the skills platform
  extension, observed `main@8d844eecbdfd65626a881c9e8784ae8dc6093f1d`.
- **Problem:** reusable instructions and workflows need discovery and
  injection into an agent context.
- **Approach:** discover skill instructions from built-ins/filesystem and make
  them available to the agent.
- **JARVIS destination:** reviewed, inert documentation may inform prompts;
  generated or user content remains untrusted data and cannot become policy or
  executable startup code.
- **Security differences:** no skill can grant permission, mutate Trusted Core,
  register tools, or bypass planning and audit.
- **Tests:** path classification, prompt-injection resistance, inert-file
  validation, size limits, and permission boundary tests.
- **Disposition:** **INSPIRE**; **REJECT** automatic executable skill loading.

### Custom agents and subagents/delegation

- **Upstream file/revision:** `crates/goose/src/agents/` platform extension
  modules, including orchestrator/summon-related modules, observed
  `main@8d844eecbdfd65626a881c9e8784ae8dc6093f1d`.
- **Problem:** separate agents can handle parallel or specialized work.
- **Approach:** create/manage agent sessions and delegate messages/tasks via an
  extension or agent manager.
- **JARVIS destination:** no second production task/control plane. Future
  delegation must submit bounded work through `TaskController` and the single
  `PlanningEngine`, with inherited principal, scope, budget, and cancellation.
- **Security differences:** delegation cannot broaden authority, create trusted
  identity, approve itself, or turn model output into owner approval. Generated
  agents remain outside the trusted process.
- **Tests:** one-plane topology, inherited budgets/permissions, cancellation,
  duplicate delegation, persistence, and forbidden legacy paths.
- **Disposition:** **INSPIRE** only; **REJECT** independent delegated task
  authorities.

### Hooks

- **Upstream file/revision:** Goose hook/event integration locations under
  `crates/goose/src/` and extension/platform event code, observed
  `main@8d844eecbdfd65626a881c9e8784ae8dc6093f1d`; exact hook file must be
  rechecked at the missing pinned revision.
- **Problem:** lifecycle observers need to run before/after agent or tool
  operations.
- **Approach:** hook-like notifications expose lifecycle events to UI,
  extensions, or automation.
- **JARVIS destination:** typed `EventEnvelope` facts and audit evidence;
  subscribers are isolated and cannot mutate authority through events.
- **Security differences:** hooks cannot bypass application services, approve
  actions, alter policy, or replay effects. External content is data.
- **Tests:** event validation, bounded queues, subscriber failure isolation,
  recursion protection, unsubscribe, shutdown, and audit ordering.
- **Disposition:** **REIMPLEMENT** only as JARVIS typed events/audit, not donor
  hooks.

### Tool restrictions

- **Upstream file/revision:** Goose permission/tool policy and extension
  configuration areas under `crates/goose/src/`, observed
  `main@8d844eecbdfd65626a881c9e8784ae8dc6093f1d`.
- **Problem:** available tools and extensions must be constrained by mode,
  configuration, or user choice.
- **Approach:** Goose exposes extension/tool controls and permission-related
  modes around its agent runtime.
- **JARVIS destination:** sealed `ToolRegistry`, `PermissionBroker`, policy,
  exact trusted operation narration, Safe Mode gates, and application-owned
  configuration.
- **Security differences:** JARVIS has no global bypass switch; model text,
  skills, hooks, sessions, or UI cannot disable authority. Restrictions are
  deny-by-default and fail closed on malformed metadata.
- **Tests:** forged identity, approval replay, changed arguments/path,
  ambiguous spoken approval, generated Trusted Core mutation, and Safe Mode
  restrictions.
- **Disposition:** **REIMPLEMENT** with JARVIS security contracts; **REJECT**
  donor mode semantics as an authority model.

## Conclusions

The useful research boundary is behavioral: bounded agent continuation,
structured tool-error feedback, context reduction, provider abstraction,
session separation, and typed lifecycle observations. JARVIS already owns or
has destinations for these concerns. Goose’s extension catalog, in-process
agent/extension authority, MCP management, custom-agent control plane, and
mode semantics must not become JARVIS production architecture.

No Goose package, binary, ACP runtime, MCP runtime, or donor implementation was
added by this study. Because the project’s pinned revision was not found in the
checked-out documentation, this note is not a substitute for a future
revision-pinned provenance/licensing review.
