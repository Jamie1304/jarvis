# Capability lifecycle restoration

**Status:** v1 production remediation baseline
**Updated:** 2026-08-25

`SQLiteCapabilityLifecycleStore` is the one durable authority for package,
certification, activation, health-summary, baseline-reference, and rollback
metadata. `CapabilityRegistry` and `HotLoadManager` are projections/runtime
caches. `CapabilityLifecycleRestorer`, owned by `RuntimeContainer`, is the one
normal production startup path that turns durable lifecycle rows back into
validated runtime state.

## Restore contract

For each durable row, the restorer:

1. resolves the exact package ID, semantic version, and package hash recorded
   in the row; it never selects “latest” or lets a new version inherit an old
   activation;
2. checks the immutable package layout, every package-code entry, source
   hashes, certification fingerprints, permission metadata, configuration
   version, and any adoption attestation reference;
3. checks UI-bearing certification evidence through the immutable
   simulation-attestation reference/digest required by `ActivationRequest`;
4. requires the native AppContainer/executable-isolation contract for
   executable packages. ACTIVE performs a trusted sandbox probe; staged states
   require the mandatory capability to be available before they are reattached;
5. calls `PackageActivationService.restore`, which is the only path allowed to
   attach a lifecycle session or start an ACTIVE hot-loaded runtime; and
6. rebuilds the registry projection only after those checks pass, then
   rehydrates the trusted baseline reference into `CapabilityHealthService` for
   ComponentDoctor and behavior-drift continuity.

The production path is invoked by `ApplicationRuntime.create` for
`Settings(environment="production")`. It does not use
`RuntimeTestFixture.lifecycle_restore`; that callback remains test-only.

## State policy

| Durable state | Startup behavior |
|---|---|
| `ACTIVE` | Validate, AppContainer-probe, restore the real package runtime, then rebuild the active registry projection. |
| `DEGRADED` | Validate and reattach the durable session; expose a degraded projection without auto-promoting or executing it. |
| `SHADOW` | Reattach staged state only; no effect-capable broker dispatch is replayed. |
| `CANARY` | Reattach staged state only; no canary effect is replayed automatically. A trusted lifecycle action must resume it. |
| `CERTIFIED` | Validate package/certification and leave inactive for explicit activation. |
| `QUARANTINED` / `ROLLED_BACK` | Remain inactive and preserve evidence. |
| Unknown/future state | The lifecycle store refuses the unsupported schema/state; startup does not silently activate it. |

## Failure containment

A package-specific failure (missing package, changed source/hash, stale
certification, missing UI evidence binding, invalid adoption evidence,
unavailable AppContainer, configuration mismatch, or package startup failure)
creates a durable `QUARANTINED` transition for that row. No registry/runtime
projection is created for the failed package, while unrelated JARVIS services
remain available. If containment persistence itself is concurrently stale, the
restorer still starts no package; the failure remains observable in the
startup result and the lifecycle row is not treated as active.

Store migration or future-schema refusal is different: it is a correctness
failure of the authoritative store and remains a startup-level failure. It is
never bypassed by falling back to an in-memory lifecycle store.

## Trust and ownership

Generated package code can report its own intended behavior but cannot write
restoration results, certification, activation state, behavior baselines, or
registry projections. The restorer receives package content only through the
hash-addressed `ProductionPackageStore`, uses trusted sandbox status, and
delegates lifecycle attachment to `PackageActivationService`. The lifecycle
store remains the only durable writer for lifecycle truth.

## Evidence

The production v1 acceptance path proves:

- an ACTIVE generated capability is restored through `ApplicationRuntime.create`;
- the registry, hot-load invocation, lifecycle row, and behavior baseline are
  rebuilt from the exact durable package identity; and
- deleting the immutable package before restart leaves the core `READY`,
  durably quarantines the package, and creates no registry projection.

The test uses a randomized local provider and package only. It does not claim
that arbitrary hostile same-user processes are isolated beyond the documented
Windows AppContainer contract, and it does not constitute physical hardware
acceptance.
