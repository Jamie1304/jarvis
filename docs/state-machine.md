# Phase 18 application/task state machine

`jarvis.state.ApplicationStateMachine` is the authoritative transition-rule
coordinator and the durable UI/recovery projection. `SQLitePlanningStore` remains
the authoritative task/plan data source; successful planning commits are projected
through the state machine and startup reconciliation repairs projection drift. UI
code reads immutable snapshots and transition history; it does not assign states.
Invalid events raise `InvalidStateTransition` before any projection is persisted.

## Global application states

The global state describes the application/foreground lifecycle. It is not a
copy of every task:

```text
IDLE -> LISTENING -> PROCESSING -> THINKING -> PLANNING
                                      |          |
                                      v          v
                              WAITING_FOR_PERMISSION
                                      |
                                      v
                                  EXECUTING -> VERIFYING -> SPEAKING -> IDLE
                                      |             |
                                      v             v
                                   WAITING       THINKING (replan)

any active state -> ERROR -> RECOVERING -> IDLE/THINKING/ERROR
IDLE -> UPDATING -> RESTARTING -> IDLE
```

The executable table in `jarvis.state.machine` is the source of truth; this
diagram is a readable summary. Update/restart is exclusive and is rejected
while any non-terminal task exists. `WAITING` means an application-owned wait
that is not a permission decision.

## Individual task states

```text
CREATED -> THINKING -> PLANNING -> WAITING_FOR_PERMISSION -> EXECUTING
                                      ^                         |
                                      |                         v
                                  WAITING <--------------- VERIFYING
                                      |  ^                      |
                                      +--+                      +-> COMPLETED
                                      +-> THINKING (replan)

Any non-terminal execution state -> CANCELLED
THINKING/PLANNING/WAITING/EXECUTING/VERIFYING -> ERROR
ERROR -> RECOVERING -> THINKING/COMPLETED/ERROR
```

Cancellation is durable and valid from planning, permission waiting,
execution, verification, waiting, recovery, and the initial thinking state.
Terminal `COMPLETED` and `CANCELLED` states cannot be silently reused. Recovery
loads the persisted task/plan snapshot and performs an explicit
`RECOVERY_STARTED` transition; it never assumes that an interrupted tool
succeeded.

## Transition records and persistence

Every projected transition records `from_state`, `to_state`, event, optional task
ID, UTC timestamp, bounded reason, metadata, and whether it belongs to the
application or task domain. Invalid transitions are visible exceptions and do
not append history. `SQLiteStateStore` applies an ordered migration and stores
task recovery fields (state, cancellation request, active step, plan revision,
and bounded metadata) plus the transition history. This store is inspectable but
rebuildable from committed planning state; it is not a second task source of truth.
Transient UI details such as cursor position or animation are not persisted.

Multiple tasks have independent snapshots. The coordinator exposes a
foreground-task ID for UI prioritization; a transition for a non-foreground
task cannot overwrite another task's state. Application update/restart remains
blocked until all tasks are terminal. Task execution, planning, and voice
adapters optionally publish their progress through this coordinator while
retaining their existing typed result records for compatibility.

## Trust boundaries

Planner/model output proposes work but cannot assign a state. The deterministic
planner, executor, permission broker, and recovery service emit typed events.
Voice wake/transcription and UI actions are inputs only. State transitions do
not grant permissions, approve tools, or imply verification; those remain
separate broker and verifier decisions.
