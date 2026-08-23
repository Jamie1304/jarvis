# ADR: Persistence and crash consistency

## Decision

JARVIS uses model A: `SQLitePlanningStore` is the authoritative durable source for
canonical task, plan, step, budget, and operation-idempotency state. The
`ApplicationStateMachine` is a durable but rebuildable projection for UI and
diagnostic transition history. It must never advance before the planning task/plan
transaction commits. The audit record follows the authoritative planning commit;
the state projection and events follow it as non-authoritative observations.

Memory, knowledge, and audit remain separate stores because they have different
retention and authority boundaries. `SQLiteMemoryStore` remains the sole authority
for durable memory records, conflict findings, quarantine, supersession, and
confidence history. Consistency findings do not become instructions or approvals.
They do not decide task completion. EventBus is in-process only and is never a
persistence or authorization source.

## Transaction model

Planning task/plan versions are written atomically in one SQLite transaction. The
engine writes that unit before advancing the durable state projection. Planning and
tool lifecycle events are best-effort observations and may be queued before a later
planning write fails; consumers must reconcile them against the planning store. A
projection write failure leaves planning truth intact, and startup rebuilds the
projection from the planning store.

SQLite stores enable foreign keys, WAL, a bounded busy timeout, ordered migrations,
future-schema refusal, and `PRAGMA integrity_check`. Corrupt or future persistence
opens place `ApplicationRuntime` in `SAFE_MODE`; no task is guessed, replayed, or
silently repaired.

Memory consistency remediation is explicit: revalidation appends evidence and a
confidence event, user correction creates a replacement and supersession record,
and quarantine only removes a record from normal retrieval. Duplicate or
contradictory records are never merged because embeddings or lexical similarity
looked close. Prompt-injected or impossible-provenance content is treated as data
or quarantine evidence, never as a personal fact.

## Restart semantics

At startup, the runtime reconciles every planning task into the state projection.
Tasks interrupted while executing, verifying, or replanning, or containing a
running/verifying step, become `RECOVERING` with an `unknown_operation_outcome`
error. They require explicit operator diagnosis and are not replayed.

Tasks waiting for permission have their in-memory approval references invalidated.
Their waiting step is requeued and a future run must enter `PermissionBroker` again,
creating a fresh request bound to the exact current task, action, fingerprint,
permission, scope, and expiry. No approval, receipt, remembered grant, or model
claim is restored from a process restart.

## Audit and idempotency

`SQLiteAuditSink` stores secret-safe permission records and planning lifecycle
records. Broker records contain only names, fingerprints, normalized scopes,
decisions, trusted approval identity/source, and outcomes—not raw arguments,
prompts, credentials, clipboard values, or camera data.

The planning store reserves a task/step idempotency key before an expensive action.
The key is bound to a SHA-256 input fingerprint. A duplicate key with a different
fingerprint fails closed; a duplicate exact reservation is never automatically
executed again. This is a local crash barrier, not proof that a remote external
effect did or did not occur; unknown external outcomes remain in recovery.

## Consequences

This avoids an unsafe dual authority between plan status and application state while
preserving inspectable state history. It does not provide distributed transactions,
cross-process locks, encrypted SQLite, or provider-specific exactly-once effects.
Those require capability-specific adapters and remain explicit future work.
