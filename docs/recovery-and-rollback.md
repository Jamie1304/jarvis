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

`RecoveryCoordinator.boot_candidate()` writes a typed startup attempt before
starting a candidate. The attempt binds the candidate build and snapshot to the
transaction, records the current LKG, migration references, and a bounded
health deadline. A committed startup clears the marker and advances the LKG
pointer only to a validated snapshot. Retention is bounded and never removes
the LKG restore point.

## Failure behavior

Every failure is evidence with transaction, phase, outcome, and timestamp. A
candidate is attempted once. The bounded recovery path is
`FAIL -> ROLLBACK -> RESTORE_LAST_KNOWN_GOOD -> START -> HEALTH_CHECK`; a
migration reconciliation hook runs before the LKG restart. A healthy LKG is
committed; an LKG restart or health failure enters `SAFE_MODE`. Failed candidate
snapshots are not retried, and the crash-loop threshold prevents indefinite
restart loops. Recovery never turns an unknown external effect into a retry
instruction and never fabricates approval or bypasses
`Tool -> PermissionBroker -> Policy`.

The callbacks supplied to `boot_candidate()` are trusted composition-root hooks:
the coordinator does not execute builds, migrations, processes, or privileged
operations. The normal runtime uses the same bounded startup marker and
crash-loop guard; an updater/build owner must supply the candidate start,
migration reconciliation, restart, and health hooks to perform an actual
candidate-to-LKG process handoff. Malformed markers, manifests, migration
metadata, deadlines, and evidence fail closed.

Safe Mode disables privileged mutations, generated integration activation,
autonomous self-update, and scheduler effects. Diagnostics, audit, rollback, and
the safe UI remain available. Microphone/listening mode is unrelated to these
gates.

Snapshot metadata is not a substitute for the authoritative planning, audit,
memory, or permission stores. Each of those domains retains its existing owner;
the [authoritative state map](authoritative-state-map.md) records this boundary.
