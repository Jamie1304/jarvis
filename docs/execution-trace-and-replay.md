# Execution trace and guarded replay

JARVIS exposes a human-readable execution trace as a factual observability
projection. It makes the execution path legible:

`goal -> plan revision -> step -> agent execution -> provider/model ->
capability/tool -> permission -> result -> artifact/evidence -> verification ->
retry/replan -> completion`

The trace is not a second task, plan, permission, artifact, or verification
store. `PlanningEngine`, `PermissionBroker`, `ArtifactStore`, and
`VerificationEngine` remain the owners of those domains. A trace event records
only a bounded fact supplied by a trusted application adapter. There are no
prompt, hidden chain-of-thought, scratchpad, or private model-reasoning fields.
Model output cannot create a trusted trace fact.

## Recorded facts

`jarvis.trace.TraceEvent` records an event type, timestamp, optional duration,
task/plan/step/turn/request/effect/correlation IDs, provider model, bounded
usage/cost, sanitized arguments, permissions, bounded results, opaque artifact
links, evidence summaries, errors, and the trusted effect outcome when one is
known. `ExecutionTrace.render_text()` is an operator-facing projection; it is
not an authorization or completion decision.

Arguments and results are passed through the existing artifact data
classification vocabulary. `SENSITIVE`, `CONFIDENTIAL`, and
`CREDENTIAL_SECRET` values are redacted, and secret-shaped keys such as token,
password, cookie, authorization, and private key are redacted even in an
internal record. Artifact links include only artifact ID, version, and
workspace ID; storage paths are never rendered or persisted in a trace event.

## Persistence and restart

`TraceStore` is a bounded SQLite projection with WAL and a busy timeout. It is
versioned and refuses a future schema. Reopening the store reconstructs the
trace in sequence order, but does not reconstruct task authority, approvals,
or external outcomes. Trace-store loss must not change the task or permission
decision.

Compensation callbacks can be adapted through `EffectTraceSinkAdapter` so
effect lifecycle facts appear in the same human-readable trace. Sink failure
does not turn compensation into success.

## Replay modes

`TraceReplayService` prepares a `ReplayPlan`; it never invokes a tool.

| Mode | Meaning | External effects |
|---|---|---|
| `SIMULATION` | Re-display and inspect recorded facts | zero; no tool execution |
| `REPLAN_FROM_CHECKPOINT` | Give a trusted planner facts through a named checkpoint | none are replayed; the planner creates a new validated plan |
| `SAFE_REEXECUTE` | Permit only explicitly replay-safe operations | only records marked replay-safe, with current policy and fresh authorization |

Recorded approvals are never inherited. A replay that needs permission must
create a new exact permission request and obtain current approval through the
normal broker. Changed arguments, paths, fingerprints, policy, or scope require
fresh validation and approval.

`UNKNOWN_OUTCOME` is a hard replay barrier. Safe replay refuses it until a
trusted reconciliation explicitly identifies the outcome. Even after
reconciliation, a recorded external effect is not automatically safe: it must
also be explicitly replay-safe and pass current broker, policy, and
verification gates. Confirmed effects are never blindly repeated.

The trace is therefore suitable for diagnostics, simulation, checkpoint-based
replanning, and cautious operator review without exposing hidden chain of
thought or turning history into authority.
