# Typed event system (Phase 19)

JARVIS uses a bounded in-process `EventBus` for coordination, UI updates, and diagnostics. It is not a state store, authorization mechanism, or security audit trail.

## Contract

Each `EventEnvelope` has an immutable event ID, schema version (`1`), typed `EventType`, timezone-aware timestamp, trusted source, optional task ID, trusted correlation ID, optional causation ID, typed payload, and a bus-assigned sequence number. Correlation and causation IDs are created by application/task code; model text cannot supply them.

Payloads currently cover:

- task: created and state changed
- plans and steps: created, updated, started, completed, failed
- permissions: requested, granted, denied
- tools: started, completed, failed
- camera and voice state changes
- capability changes and bounded system errors

Payloads contain bounded summaries and identifiers only. They do not contain raw tool arguments, credentials, prompts, clipboard values, camera frames, audio, or authorization receipts. `PermissionBroker` and `AuditSink` remain the authoritative decision and durable security records respectively.

## Delivery semantics

`InMemoryEventBus` assigns monotonically increasing sequence numbers under a process lock. A subscriber has a bounded queue. When full, the oldest observational event is dropped and a metric is recorded; publishers never wait for a slow consumer. Subscriber exceptions are logged and isolated from other subscribers. Unsubscribe cancels its consumer; `close()` cancels all consumers and rejects later publication.

The bus accepts asynchronous typed handlers. `publish_nowait()` is provided for synchronous state/adaptor boundaries and returns false when no running loop or after shutdown. Cancellation never changes authoritative state by itself.

To prevent accidental feedback storms, each correlation chain has a bounded event count (256 by default). Events beyond the cap are dropped and counted. Consumers must not republish indefinitely; any state or permission change must go through its owning service.

## Versioning and compatibility

Schema version `1` is additive-only for the current release. Consumers must ignore unknown event types and tolerate unknown payload fields when decoding persisted/forwarded events. Producers must not reuse an existing event type with changed field meaning. A breaking payload or metadata change requires a new schema version (and, where needed, a new event type) plus a compatibility window. Event IDs and sequence numbers are process-local observability identifiers, not durable audit IDs.

## Integration boundaries

- `ApplicationStateMachine` emits state observations after recording its authoritative transition.
- `PlanningEngine` emits plan and step lifecycle observations; it still owns DAG execution and persistence.
- `PermissionBroker` emits request/grant/deny observations; events never grant permission.
- `Tool.invoke` emits lifecycle observations only after broker authorization and never accepts event-supplied authorization.
- Voice and camera controllers emit state observations while their existing lifecycle/permission checks remain authoritative.

No event consumer may mutate state directly, bypass `PermissionBroker`, or treat an event as proof that an action succeeded. Generic event logs are safe-to-observe summaries; detailed security evidence belongs in the audit sink and controlled artifacts.
