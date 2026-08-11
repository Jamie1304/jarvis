# Optional multi-agent orchestration

Phase 16 adds an opt-in execution mode for tasks with demonstrably independent work.
The Phase 15 `PlanningEngine` remains unchanged and is still the default.

`single-agent request -> optional delegation proposal -> trusted validation -> bounded shared DAG -> typed results`

`MultiAgentCoordinator` is the only delegation authority. It accepts an untrusted
proposal, validates it against exact registered `AgentContract` records, and schedules
explicit nodes. Delegated workers receive one `AgentInvocation`; they receive no
coordinator, spawn method, agent registry, permission broker, approval state,
application container, or global conversation.

## Contracts and roles

The initial roles are main/orchestrator, research, coding, and computer. The main role
is trusted application code and cannot be registered as a worker. A contract declares
the stable agent ID/type, responsibility, strict Pydantic task and result schemas,
allowed tools/capabilities/permissions, resource budget, availability, and delegation
authority. Only an orchestrator contract may declare delegation authority, and the
worker registry rejects orchestrator or delegating workers.
The registry snapshots each immutable contract at registration and checks it again at
execution, so a worker cannot swap its schema or scope after graph validation.

Each graph node records its agent, objective, validated canonical input, dependencies,
minimum selected context keys, shared evidence references, required scope, timeout,
reserved resource budget, lifecycle state, typed result, and error. Communication is
request/result only; there is no unbounded agent-to-agent chat channel.

## Delegation policy and execution

The initial deterministic policy uses multi-agent mode only when the graph contains
independent nodes assigned to different specialisms. A disabled flag, absent proposal,
one-node plan, or fully sequential plan uses the single-agent adapter. Unknown or
unavailable agents also fall back before delegated execution. Malformed graphs,
privilege escalation, cycles, unknown context/evidence, and resource violations reject
or fail closed rather than falling back into a potentially broader path.

Ready independent nodes run concurrently up to the trusted concurrency limit.
Dependencies require complete success, not a partial result. Cancellation is shared
with all workers and active tasks are cancelled; dependent queued nodes become blocked.
Per-node and orchestration timeouts are separate. A failed independent node does not
erase successful evidence: the result is explicitly `PARTIAL`, while dependants are
blocked. There is no automatic retry or recursive spawning in this phase.
Even when every node succeeds, `EvidenceMultiAgentGoalVerifier` must observe every
trusted request-level completion reference before the orchestration can complete.

Model-call, token, cost-unit, and elapsed-time budgets exist at contract, node, and
task levels. Node reservations must fit before any worker starts, and trusted adapters
report actual provider usage, which is checked again at completion. Model-authored
usage claims are not authoritative.

## Privilege and context boundary

Delegated tool, capability, and permission sets must be subsets of both the parent
task scope and the selected agent contract. These are declarations, not grants. A
computer-agent action must still invoke a registered controlled computer tool through
`PermissionBroker`; delegation or another agent's request cannot create an approval or
receipt. Worker adapters are trusted composition and must expose only brokered,
scope-limited capability ports to a model provider.

Trusted application code selects context keys and evidence references. It must not
copy the full conversation, secrets, credentials, approval material, or unrelated
memory into a node. External/tool evidence remains referenced untrusted data rather
than instructions.

## Evaluation

The deterministic `multi-agent-comparison` fixture performs independent research and
coding work followed by one dependent computer-analysis node. It runs the same
objective through disabled (single-agent) and enabled modes. A local implementation
run measured 125.25 ms of single-agent work versus a 56.25 ms multi-agent work
critical path, a 55% reduction, with equal abstract model-call/token/cost consumption.
End-to-end timings are retained as informational evidence but are not the deterministic
pass criterion because coverage instrumentation can dominate scheduler overhead. This
demonstrates a concrete parallel critical-path advantage only; it does not claim
quality improvement from multiple models or predict production-provider latency.

## Residual assumptions

Python interfaces are not an OS sandbox. Registered worker adapters, provider usage
accounting, clocks, contracts, validator, coordinator, single-agent fallback, and any
brokered capability ports are trusted. An adapter that directly imports OS APIs can
bypass architectural interfaces and must not be composed. Phase 16 state is
process-local; restart persistence and distributed leases are not claimed. The
coordinator deliberately provides no multi-agent persistence, recursive delegation,
agent-created nodes, or dynamic agent/plugin discovery.
