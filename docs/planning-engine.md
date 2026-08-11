# Planning engine

Phase 15 provides a durable, single-agent control plane for multi-step work:

`GOAL -> PROPOSED PLAN -> VALIDATED DAG -> EXECUTION -> VERIFICATION -> REPLAN / COMPLETE`

The planning model is advisory. It returns strict data only. `PlanValidator` resolves
every tool against the live `ToolRegistry`, checks the tool's capability and exact
declared permissions, validates its Pydantic argument schema, bounds the graph, and
rejects missing dependencies or cycles. Only the resulting `OwnedPlan` is executable.
The planner cannot create a broker receipt, approval request, policy decision, or
successful lifecycle state.

## Schema and lifecycle

An owned plan records the immutable task goal, assumptions, constraints, required
capabilities and permissions, explicit completion criteria, and versioned DAG steps.
Each step has a stable ID and key, dependencies, exact tool/capability, canonical JSON
input, expected output/evidence, a trusted verification rule, retry limit, attempts,
status, result, and structured error.

The task state machine distinguishes planning, ready, running, waiting for permission,
verifying, replanning, completed, failed, cancelled, and budget exhausted. A permission
pause persists the broker-issued request IDs and the entire task/plan snapshot. Resume
does not grant approval: it invokes the same exact tool input through the broker again,
which consumes a valid trusted approval or pauses/denies again.

`SQLitePlanningStore` stores task snapshots and versioned current plans atomically and
uses ordered, identity-checked migrations. On restart, queued and permission-paused
work can continue. A persisted running or verifying step has an unknown external
outcome, so the engine fails closed instead of replaying it.

## Execution, verification, and replanning

The engine schedules ready nodes in deterministic graph order and uses one executor.
`BrokeredPlanningStepExecutor` accepts only a registry tool ID and invokes that exact
tool through `Tool.invoke`; it cannot call `_execute_authorized` or an OS adapter.
Successful tool output is only evidence. The step verifier must accept the declared
rule, and after every step succeeds the goal verifier must independently accept all
goal completion criteria before the task can complete.

Transient failures retry only within both the per-step and task retry budgets.
Deterministic or exhausted failures may request a new proposal, but the replan request
contains the actual structured failure/evidence and the validator requires the
original goal, assumptions, and constraints unchanged. Prior plan versions remain in
SQLite. A malformed or constraint-changing replan fails; it does not replace the
protected task contract.

Budgets independently limit graph size, elapsed time, planner calls, expensive
actions, and retries. Cancellation persists first, signals an active cancellable
executor, cancels queued nodes, and blocks downstream nodes. No multi-agent scheduling
or parallel action execution is implemented in this phase.

## Trust and safety boundaries

- Proposed plan JSON, tool results, stored evidence, and planner explanations are
  untrusted data.
- `ToolRegistry`, tool manifests/schemas, `PlanValidator`, lifecycle engine, broker,
  store migrations, clock, executors, and verifiers are trusted application code.
- Known permission names in a proposal are declarations, not grants. The live tool
  manifest must match them exactly, and the broker makes the execution decision.
- Unknown tools, capabilities, permissions, rules, dependencies, malformed arguments,
  cycles, stale running states, and missing budgets fail closed.
- SQLite durability is local integrity, not multi-user authorization or encrypted
  secret storage. Production composition must protect the database path and user/task
  ownership boundary.
- A process crash can leave an external action's outcome unknown. The engine refuses
  silent replay; future idempotency/evidence adapters may provide a narrower recovery
  policy for individual tools.

The deterministic meeting-preparation evaluation uses fake calendar, notes, and focus
tools. Calendar and notes are independent DAG nodes; focus depends on both. It sends no
messages and accesses no real desktop, calendar, microphone, camera, or network.
