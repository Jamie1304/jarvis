# Snapshot and recovery

Recovery is owned by `jarvis.recovery.RecoveryStore` and
`RecoveryCoordinator`. It is a local evidence and restore service, not a task
engine, permission authority, scheduler, integration registry, or update
executor. Agent Zero Time Travel and other donor projects are reference-only;
none is imported at runtime.

## Lifecycle

An owner-controlled change follows:

`PREPARE -> SNAPSHOT -> APPLY -> START -> HEALTH_CHECK -> COMMIT`

The snapshot manifest records an opaque transaction ID, application revision,
non-secret configuration metadata, database/schema metadata, migration IDs,
integration version metadata, generated-package state, and explicitly selected
regular-file artifacts. Manifests are schema-versioned and future schemas are
refused. Writes use a temporary file plus `fsync` and atomic replacement.

Startup writes an active marker before work begins. A marker left by a crash is
failed-start evidence on the next startup. A committed startup clears the marker
and advances the last-known-good (LKG) pointer only to a validated snapshot.
Retention is bounded and never removes the LKG restore point.

## Failure behavior

Every failure is evidence with transaction, phase, outcome, and timestamp. The
trusted owner must execute `FAIL -> ROLLBACK -> RESTORE_LAST_KNOWN_GOOD ->
HEALTH_CHECK`; repeated uncommitted starts may enter `SAFE_MODE`. Recovery never
turns an unknown external effect into a retry instruction and never fabricates
approval or bypasses `Tool -> PermissionBroker -> Policy`.

Safe Mode disables privileged mutations, generated integration activation,
autonomous self-update, and scheduler effects. Diagnostics, audit, rollback, and
the safe UI remain available. Microphone/listening mode is unrelated to these
gates.

Snapshot metadata is not a substitute for the authoritative planning, audit,
memory, or permission stores. Each of those domains retains its existing owner;
the [authoritative state map](authoritative-state-map.md) records this boundary.
