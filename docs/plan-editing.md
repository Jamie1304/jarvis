# Safe plan inspection and editing

JARVIS exposes significant pending plans through the application task service.
Desktop and voice layers receive a typed `PlanInspection`; they do not read
the planning database, construct a second plan, or invoke an executor.

`PlanningEngine` remains the only durable task/control authority and
`PlanValidator` remains the only boundary that turns a proposal into an owned
plan. A plan edit is a typed `PlanEdit` containing bounded constraints,
alternatives, optional-step removals, field-level step edits, and an optional
pause-checkpoint marker. The engine converts that request to a proposal,
preserves the original goal and assumptions, validates it, and persists a new
plan ID and version. Every revision records provenance and is available from
the planning store after restart.

Inspection includes:

- ordered steps and dependency keys;
- declared effects, capabilities, permissions, and verification evidence;
- task/plan status and observed evidence;
- execution budgets and current resource usage.

Only queued or pre-effect permission-waiting steps can be edited. A step with
dependents, required completion evidence, confirmed execution, active
execution, or uncertain outcome cannot be removed or changed. A replan is
delegated to the existing `PlanAdvisor`; the editor is not a planner.

When a revision changes an exact tool/effect fingerprint, the runtime invokes
the trusted `PermissionBroker` to invalidate unconsumed pending/approved
requests and issued receipts. Consumed approvals remain audit evidence and
are never released for replay. If the revision does not change the effect
fingerprint, an otherwise valid approval may remain bound to the same exact
operation.

## Checkpoint branches

A checkpoint branch creates another validated plan revision without attempting
to undo the external world. Confirmed successful steps may carry their
durable `StepResult` evidence into the branch; queued and pre-effect waiting
steps remain executable. Running, verifying, failed, or `UNKNOWN_OUTCOME`
steps cannot be inherited. An unknown effect remains `RECOVERING` and is never
replayed or silently incorporated into a branch.

The branch operation itself performs no tool call. It is safe to inspect,
revise, persist, restart, and only then explicitly run the resulting plan.
