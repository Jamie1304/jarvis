# Generic event-driven automation

JARVIS automations turn typed observations into ordinary user goals or reusable
workflow proposals. They do not create a privileged execution path:

```text
Event -> TriggerDefinition -> Condition -> AutomationRun
      -> TaskController -> PlanningEngine -> PermissionBroker -> Verification
```

## Contracts

`AutomationDefinition` is durable configuration. It has one bounded
`TriggerDefinition`, a workspace and presentation/profile scope, and exactly one
of:

- a fixed goal string; or
- a registered `WorkflowTemplate` ID plus static typed parameters.

`Condition` is a declarative read-only predicate over the event type, source,
IDs, or bounded typed payload fields. It cannot execute code, select a tool,
create an approval, or widen scope. External event data is never copied into a
goal, approval, credential, or policy decision.

`AutomationRun` is durable coordination evidence. It records event identity,
correlation, deduplication fingerprint, trace ID, status, and any linked task
ID. Raw event payloads are deliberately not persisted in the automation store.
The planning store remains the authority for task/plan/step truth and the audit
store remains the security evidence authority.

## Delivery and restart behavior

Definitions are the durable subscription intent. `AutomationService.start()`
subscribes to the EventBus, reconciles runs left by a prior process, and resumes
only runs that are still safely queued. A run interrupted before a task ID was
durably bound becomes failed with `restart_unknown_submission`; a bound run is
resolved from `TaskController`/`PlanningEngine`. No unknown external effect is
blindly replayed.

Triggers support bounded debounce, cooldown, deduplication, and queues. The
concurrency policy is one of `DROP`, `QUEUE`, `RESTART_IF_SAFE`, or
`PARALLEL_BOUNDED`. Safe restart is limited to work that has not submitted a
task/effect. Queue and active counts are bounded by the definition.

Simulation records a `SIMULATED` run and trace without creating a planning task.
Every accepted, transitioned, and completed run is represented in the
human-readable execution trace as an observation; traces do not contain hidden
chain-of-thought and do not grant authority.

## Security and ownership

Automation state is application-owned and instantiated by the composition root.
The service has no `ToolRegistry` execution capability and no `PermissionBroker`
authority. It may only call the typed `TaskController`, which routes to the
canonical `PlanningEngine`. Permission waiting is reported as a normal task
state and requires the existing trusted desktop/voice approval object. Trigger
events—including permission-looking events—cannot satisfy that requirement.

Future automation features must update
[`authoritative-state-map.md`](authoritative-state-map.md) before adding a new
durable domain or treating a projection as truth.
