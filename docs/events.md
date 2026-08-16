# Typed event system (Phase 19)

JARVIS uses a bounded in-process `EventBus` for coordination, UI updates, and diagnostics. It is not a state store, authorization mechanism, or security audit trail.

## Contract

Each `EventEnvelope` has an immutable event ID, schema version (`1`), typed
`EventType`, timezone-aware timestamp, source label, optional task ID, correlation
ID, optional causation ID, a matching typed payload, and a bus-assigned sequence
number. Canonical producers create correlation and causation metadata from
application/task context rather than model text. The public in-process constructor
does not authenticate a source label or correlation ID, so consumers treat all
event metadata as observation and reconcile it against the owning service.

Payloads currently cover:

- task: created and state changed
- plans and steps: created, updated, started, completed, failed
- permissions: requested, granted, denied
- tools: started, completed, failed
- camera and voice state changes
- capability changes and bounded system errors

Payload schemas permit only bounded summaries and identifiers and enforce the
`EventType`/payload pairing. Every producer is responsible for redaction: generic
payload construction does not prove that an arbitrary bounded string is secret-free.
Canonical producers must not include raw tool arguments, credentials, prompts,
clipboard values, camera frames, audio, or authorization receipts. `PermissionBroker`
and `AuditSink` remain the authoritative decision and durable security records.

## Delivery semantics

`InMemoryEventBus` assigns monotonically increasing sequence numbers under a process lock. A subscriber has a bounded queue. When full, the oldest observational event is dropped and a metric is recorded; publishers never wait for a slow consumer. Subscriber exceptions are logged and isolated from other subscribers. Unsubscribe cancels its consumer; `close()` cancels all consumers and rejects later publication.

The bus accepts asynchronous typed handlers. `publish_nowait()` is provided for synchronous state/adaptor boundaries and returns false when no running loop or after shutdown. Cancellation never changes authoritative state by itself.

To prevent accidental feedback storms, each correlation chain has a bounded event
count (256 by default). The correlation ledger itself is a bounded LRU (4096 chains
by default), so unique correlation IDs cannot make bookkeeping grow without bound.
Events beyond the per-chain cap are dropped and counted; least-recently-used chain
state is evicted at the global cap. Consumers must not republish indefinitely; any
state or permission change must go through its owning service.

This bounds process memory and accidental single-chain recursion; it is not a
sandbox against a malicious in-process subscriber that continuously rotates fresh
correlation IDs. Such code is not loaded as an untrusted integration in v1.

## Versioning and compatibility

Schema version `1` is additive-only for the current release. Consumers must ignore unknown event types and tolerate unknown payload fields when decoding persisted/forwarded events. Producers must not reuse an existing event type with changed field meaning. A breaking payload or metadata change requires a new schema version (and, where needed, a new event type) plus a compatibility window. Event IDs and sequence numbers are process-local observability identifiers, not durable audit IDs.

## Integration boundaries

- `ApplicationStateMachine` emits state observations after recording its validated projection transition.
- `PlanningEngine` emits plan and step lifecycle observations; its planning store remains authoritative for durable task/plan data.
- `PermissionBroker` emits request/grant/deny observations; events never grant permission.
- `Tool.invoke` emits lifecycle observations only after broker authorization and never accepts event-supplied authorization.
- Voice and camera controllers emit state observations while their existing lifecycle/permission checks remain authoritative.

No event consumer may mutate state directly, bypass `PermissionBroker`, or treat an
event as proof that an action succeeded. Generic event logging must still apply
redaction because the public bus does not authenticate producers or prove arbitrary
text secret-free; detailed security evidence belongs in the audit sink and
controlled artifacts.

Delivery is best effort, and some lifecycle observations can be queued before the
corresponding durable store write completes. A subscriber must read the authoritative
planning/state owner before displaying or acting on consequential status.
