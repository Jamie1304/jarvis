# Long-horizon GoalSupervisor

`GoalSupervisor` coordinates a durable user outcome across capability
analysis, acquisition, task execution, verification, and bounded replanning:

```text
Goal -> analyze -> CapabilityRegistry -> plan
     -> missing capability? -> research -> DISCOVER/ADOPT/REUSE/BUILD
     -> certify/activate -> execute -> verify -> replan -> complete
```

This is a coordination boundary, not a second task engine. `PlanningEngine`
remains the sole durable task/plan authority. `AgentLoop` is the bounded
reasoning primitive used by an injected analyzer/researcher, and all privileged
effects still use `ToolRegistry -> PermissionBroker -> Policy -> approval`.
Generated or discovered metadata cannot grant authority.

## Intent and restart

`GoalIntent.original_outcome` is immutable and is persisted with assumptions,
constraints, required capability IDs, and a scoped metadata object. It is
carried unchanged into research and the canonical PlanningEngine task. A
`GoalSupervisorStore` owns only this intent and supervisor coordination state;
the task ID is a link to PlanningEngine truth, not a competing task record.

The store is SQLite-backed, uses WAL, foreign keys, a busy timeout, and a
versioned schema that refuses future versions. An active-run marker is durable.
If a process stops during analysis, acquisition, planning, execution, or
verification, the next load changes the supervisor state to `RECOVERING`.
Recovery does not rerun an active task. A trusted caller must explicitly call
`resume(..., reconciled=True)` after reconciling any effect boundary. A waiting
permission state is returned as-is and cannot be turned into a new task by an
ordinary restart.

## Acquisition and alternatives

The registry-first analyzer identifies missing active capabilities. Research
returns a typed `CapabilityAcquisitionRequest` for the existing
`CapabilityFactory`, whose acquisition order remains:

`DISCOVER -> ADOPT -> REUSE -> BUILD`

Only an active factory result can proceed to execution. Certified, generated,
or ready-for-approval output is not silently activated by the supervisor.

Before `BLOCKED`, the supervisor calls the trusted `AlternativeExaminer` and
records all of these categories, including unavailable categories:

- alternate architecture
- API/library
- MCP
- workaround
- model
- tool
- infrastructure
- user input

Safe viable alternatives are selected once and researched again. The same
alternative is never attempted twice. If no safe alternative remains, the
goal becomes `BLOCKED` with the original intent and examined alternatives
preserved. Unknown or untrusted external instructions are not alternatives.

## Budgets and effect safety

`GoalBudget` is immutable and bounds elapsed time, tokens, cost, retries,
replans, disk bytes, network bytes, risk, planning steps, model calls, and
expensive actions. Reports are measured against the trusted ceiling before the
next stage; a model cannot increase it. The PlanningEngine receives a bounded
`ExecutionBudgets` projection for each canonical task attempt.

The supervisor may only select a new high-level attempt when a trusted runner
marks the failure replay-safe. Confirmed and unknown effects are never treated
as replay-safe. Permission waiting, unknown outcome, and recovery are explicit
non-terminal handoff states rather than automatic retries.
