# Runtime trace correlation

**Status:** v1 production composition contract
**Updated:** 2026-08-24

`TraceService` is the single runtime-owned subscriber that projects canonical
application events into the durable, human-readable `TraceStore`. It is an
observability projection, not a task engine, permission authority, evidence
authority, or replay executor.

## Stable lineage

The service maps a goal/task/correlation identity to one deterministic trace ID.
`TraceStore` persists the lineage alias and refuses rebinding an identity to a
different root. `GoalSupervisor` binds goal/task IDs when the canonical task is
created; task, plan, step, permission, tool, artifact, health, lifecycle,
automation, and error events then project into the same trace.

Capability acquisition records are written by the production
`CapabilityAcquisitionCoordinator` with the goal ID, run ID, package ID/version/
hash, lifecycle stage, and trusted effect-attestation references. The
effect-attestation store is authoritative for broker observations; Trace stores
only sanitized references and outcome metadata.

Credential activity is represented by credential IDs and operation/status
metadata only. No secret bytes, bearer headers, prompts, hidden model reasoning,
or untrusted success claims are trace fields.

## Restart behavior

Trace schema v2 migrates the previous event schema and adds the durable lineage
table. `TraceStore.load()` loads events into the in-memory projection without
re-persisting them, so a resumed trace keeps one event history. New events append
through the runtime-owned `TraceService`; UI and test code cannot create a
competing production projection through `RuntimeContainer`.

Restart reopens the same store and reconstructs the same deterministic trace ID
for the goal/task. Durable task, goal, package lifecycle, effect-attestation,
artifact, and verification owners remain authoritative; Trace only reflects
their facts. A trace cannot authorize a permission, resolve a credential, mark a
model claim verified, or replay an unknown external effect.

## Evidence

`test_v1_acceptance_composed_runtime_and_task_controller` proves one composed
task trace contains goal, plan, step, and completion facts and reloads the same
trace after restart. The unknown-capability acceptance path additionally proves
that acquisition stages, package version, and trusted activation attestation
references are attached to the goal lineage and remain after restart.

`tests/test_trace.py` covers event projection, stable lineage, no raw goal text
in rendered trace output, schema migration, writable reload, and restart.
