# Development

JARVIS targets Python 3.12+ and Windows first. Create a virtual environment and install the pinned baseline:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.lock

Production/runtime installation can use `requirements.lock`; development and test tools are isolated in `requirements-dev.lock`.
```

Configuration precedence is: explicit `JARVIS_` process environment variables, then
typed defaults in `jarvis/core/config.py`. Production startup never implicitly reads
`.env` from the current working directory. A local launcher may load an owner-selected
configuration file and export its values before starting JARVIS; never commit that file
or its secrets.

Run the health-only service with `python -m uvicorn jarvis.api:app --reload`. Run the full quality gate with `python scripts/quality.py`. It checks formatting, linting, static typing, tests, and the 90% coverage threshold.

## Optional Phase 6 Windows integration

The controlled computer layer is not enabled by the default catalog. To install its
optional Windows UI Automation dependencies for a manually configured, brokered
integration, run `python -m pip install -e ".[windows]"`. Real desktop checks are
opt-in: set `JARVIS_WINDOWS_INTEGRATION=true` and run
`python -m pytest -m windows_integration`. Run them only on a dedicated interactive
Windows desktop with a trusted application and policy configuration. The ordinary
CI suite uses mocks and does not claim a desktop action was performed.

## Phase 2 orchestration

Phase 2 is a core service, not an enabled desktop workflow yet. `AgentOrchestrator` requires an injected `TaskStore`, planner, tool registry, executor, observer, verifier, response generator, and finite limits. Production composition intentionally provides no OS-capable tools. Use deterministic fake planners and tools in tests while adding new capability types.

The relevant safeguards are configured through `JARVIS_AGENT_MAX_STEPS`, `JARVIS_AGENT_TIMEOUT_SECONDS`, and `JARVIS_AGENT_MAX_REPLANS`. Cancellation persists to the task store and interrupts an active asynchronous tool call. Any future persistent store must implement `TaskStore` without moving lifecycle state transitions out of the orchestrator.

## Phase 11 improvement adapters

Phase 11 has no default autonomous runner. Compose it only in a trusted development
or review process, with the production checkout and a dedicated worktree parent as
disjoint canonical directories. The production checkout must be clean and pinned to
the reviewed full revision. Never put the workspace parent under the repository,
shared Git directory, a symlink, or a junction; never give that path, a revision, or
Git arguments to model output.

The coding adapter must implement `CodingAgent` as a data-only change proposer. It
must not receive a path object for production, an open file, subprocess/shell API,
Git client, network client, credentials, permission broker, approval service, or
application container. All changes pass through `TrustedWorkspaceChangeApplier`.
Do not extend the writable control-path set to include `.git`, workflows, or the
quality script, and do not reinterpret generated prose as a path, command, policy,
gate definition, dependency exception, or approval.

Executable gates require host-owned absolute executables, fixed argument arrays,
timeouts, full process-tree cancellation, and a concrete sandbox adapter. The native
`SandboxProcess` supplies bounded JSON IPC, dedicated paths, sanitized environment,
and Windows Job Object process/resource ownership. It is not a complete filesystem
or network sandbox; the repository intentionally has no permissive in-process
implementation. Fake adapters are appropriate for deterministic unit
tests but must never be used to justify a real proposal. A production security gate
should compose deeper static/dependency scanning in addition to the built-in minimum
preflight.

Dependency exceptions are operator-reviewed configuration bound to exact before and
after manifest digests, package records, risk analysis, and reversibility. Do not
allow names, version ranges, registries, or coding-model explanations as wildcard
exceptions. Phase 11 does not install or download dependencies.

To exercise the worktree and sandbox integration manually, use a disposable clone,
an empty sibling workspace directory, no credentials or production secrets, disabled
network, strict CPU/memory/disk/process limits, and a non-production account. Capture
the initial full revision/status, run one bounded proposal cycle, and confirm the
original revision and status are identical afterward. Report Git/worktree and
sandbox evidence separately from fake-adapter CI evidence. Do not approve, merge,
push, install, restart, or deploy as part of this procedure.

## Phase 14 memory storage

Compose `SQLiteMemoryStore` with an application-owned local path outside the source
checkout and an authenticated user boundary. Run its reviewed migrations when the
application initializes; do not place database files, exports, or backup copies in
Git. Persist a long-term candidate only through `LongTermMemoryService`, after an
explicit user confirmation and allow decision. Use `EpisodicMemoryService` for
compact completed task evidence, not the permission audit sink. Call the provided
inspection/deletion/retention-cleanup operations from trusted UI/API code only.

Never send tokens, passwords, cookies, or `.env` values to this store. Historical
web/tool content must retain its untrusted-data label on retrieval. For a temporary
migration check, run `python -m pytest tests/test_memory.py -q`; the tests create and
remove only temporary databases.

## Phase 15 planning composition

Construct `PlanValidator` and `BrokeredPlanningStepExecutor` from the same trusted
`ToolRegistry`; do not provide a second registry or direct tool/adapter executor.
Planner output must cross the strict proposal schema before persistence. Add new
verification rules only as reviewed deterministic application code, never as model
expressions. Store the SQLite database in an application-owned directory and apply
the ordered migrations during trusted startup.

Cancellation-aware executors must stop the active action when possible and report a
structured outcome. If a restarted task contains a running/verifying step, preserve
the fail-closed unknown-outcome behavior unless the individual tool provides a
reviewed idempotency and evidence protocol. Do not infer approval from the plan or
modify broker state during resume. Run `python -m pytest tests/test_planning_engine.py
-q` for focused control-plane checks and `python scripts/run_system_tests.py --suite
deterministic-workflows` for the meeting workflow evaluation.

## Phase 16 optional multi-agent composition

Leave `JARVIS_MULTI_AGENT_ENABLED=false` unless trusted composition has registered
reviewed worker adapters and a representative evaluation shows a concrete benefit.
Construct contracts with strict task/result schemas and least-privilege tool,
capability, permission, and resource scopes. Never register an orchestrator as a
worker or give a worker the coordinator, registry, broker approval API, application
container, global conversation, raw memory store, or arbitrary command/OS handle.

A model-backed worker adapter must construct resource usage from trusted provider
metadata, not model text. Any worker needing a privileged action must use a narrow
brokered tool port; the contract's permission list does not authorize execution.
Select only the node's required context/evidence references and exclude secrets and
unrelated conversation. Run `python -m pytest tests/test_multi_agent.py -q` and the
`multi-agent-comparison` deterministic workflow when changing contracts or scheduling.

## Phase 1 manual smoke test

1. Install [Ollama](https://ollama.com/) for Windows, then run `ollama pull llama3.2:3b`. Ollama normally starts its local server automatically; if it is not running, use `ollama serve` in a separate terminal.
2. Use `.env.example` only as a reference for variables exported by your trusted local
   launcher. Set `JARVIS_AI_MODEL` to a locally pulled model and leave
   `JARVIS_AI_ENDPOINT=http://127.0.0.1:11434`.
3. Install the desktop client with `python -m pip install -e ".[desktop]"`, then start it with `python -m jarvis.desktop`.
4. Send `Jarvis, hoeveel is 25 procent van 800?`. The expected response is 200 (or an equivalent explanation).
5. Microphone and TTS provider adapters are available for opt-in manual provider
   tests, but the canonical v1 runtime does not activate them. Do not treat
   `JARVIS_STT_ENABLED` or `JARVIS_TTS_ENABLED` alone as hardware authorization.
   The compatibility assistant helper now refuses privileged speech activation;
   conversational voice remains disabled until it is brokered by the canonical
   runtime.

## Trusted Core changes

Before changing security, permission, tool invocation, runtime composition, or
self-improvement enforcement code, read
[`security-constitution.md`](security-constitution.md). Routine generated repair
must not modify paths classified as `TRUSTED_CORE`. A production-core update needs
the complete trusted gates and independent update authority; a Trusted Core change
requires a separate owner security release. Risk labels and passing tests are not
mutation authorization.

Approval handlers must submit a `TrustedApprovalContext` minted by the
runtime-owned local approval authenticator after authenticating the human. Never
accept an `ApprovalIdentity`, `ApprovalSource`, request ID, or model/UI text as a
decision on its own, and never pass the authenticator to a planner, tool, worker,
event consumer, or integration.
