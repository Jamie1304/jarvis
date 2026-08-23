# Staged Package Activation

`PackageCertifier` and activation are separate trusted application concerns.
Certification proves that one exact package revision is admissible; it does
not make that revision active. `PackageActivationService` is the sole owner of
the activation state machine:

```text
CERTIFIED -> SHADOW -> CANARY -> ACTIVE
                 |        |        |
                 +------> QUARANTINED
                          ACTIVE -> DEGRADED
                          ACTIVE -> ROLLED_BACK
```

Each `(package_id, version)` receives a fresh lifecycle. A newer version does
not inherit ACTIVE state, broker observations, approvals, predictions, canary
effects, or runtime state from an earlier version. The service validates the
certification against the exact source snapshot before registering `CERTIFIED`.

## Trusted boundaries

The composition root supplies `ActivationHooks`. They are application-owned
broker adapters; generated package code cannot supply them, invoke them, or
make a promotion decision.

Shadow execution receives a zero-effect broker. Any reported effect is a
fail-closed side-effect violation and moves the version to `QUARANTINED`.
Shadow records predictions, broker behavior, and verification evidence.

Canary execution receives a trusted `CanaryLimits` object containing the exact
scope, call/effect limits, budget, and wall-time bound. The service rejects
scope expansion, missing verification, and any bound overrun. Effects are
recorded and a trusted rollback hook is invoked before quarantine when a
canary fails.

Only a successful canary may call `HotLoadManager.manual_refresh`. This keeps
`CERTIFIED` distinct from runtime registration. Promotion, degradation,
quarantine, rollback, and restart are application service operations; package
metadata and model output cannot request or authorize them.

`ActivationRecord` records the exact package/certification binding, predictions,
broker behavior, canary effects, verification, promotion decision, rollback
evidence, and bounded transition history. Runtime swapping remains serialized
by `HotLoadManager`; a trusted rollback may restore a previously certified
version or remove the active package when no prior version is available.

The state service is intentionally not a second task, permission, audit, or
package-content store. PermissionBroker and policy remain mandatory for every
privileged broker effect, and activation evidence remains derived lifecycle
evidence owned by this service.
