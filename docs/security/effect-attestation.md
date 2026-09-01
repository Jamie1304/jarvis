# Trusted effect attestation

## Purpose

Generated integration code may report an intended action or a result returned to
it. It cannot prove that an external effect occurred. Staged activation therefore
uses broker-owned observations as the only effect evidence.

The native path is:

```text
package request -> trusted host proxy -> PermissionBroker
  -> EffectAttemptRecord (durable before dispatch)
  -> broker dispatch or SHADOW suppression
  -> BrokerEffectObservation
  -> EffectAttestationStore
  -> trusted activation decision
```

`EffectAttemptRecord`, `BrokerEffectObservation`, `EffectAttestation`, and
`EffectAttestationStatus` live in `jarvis/effect_attestation.py`. The store uses
SQLite WAL, a busy timeout, bounded typed fields, and refuses a future schema.
An unfinished attempt is reconciled as `UNKNOWN_OUTCOME` on restart. It is never
treated as a successful or replayable effect.

## Trust contract

Only an application-owned `TrustedEffectObserver` issued by
`EffectAttestationStore` can begin or complete an attempt. The observer is
provided by the activation service to trusted composition hooks; it is not
constructed or supplied by package code. A package callback's `effects`,
`passed`, or “I did nothing” text is diagnostic only.

Each observation is bound to:

- integration ID and version;
- exact package hash;
- activation ID and activation state;
- action and request IDs;
- broker name, normalized target and scope;
- requested effect, authorization, dispatch flag, result category;
- timestamp, task ID and correlation ID where available.

The store mints an attestation only from its own observations. A forged,
modified, unregistered, or package/version-mismatched attestation is rejected.
Raw credential values are not fields in this model and are not written to audit,
trace, or effect evidence.

`PackageActivationService` requires an explicitly composed
`EffectAttestationStore`; it does not create an ephemeral fallback store.

## Shadow

The host proxy begins an attempt and records `SUPPRESSED` before any dispatch.
For supported network, filesystem, process, and device typed-proxy operations,
SHADOW raises before the executor/native client is called. Promotion data must
show a trusted `SUPPRESSED` attestation with `zero_trusted_dispatch=True`.
Integration claims cannot substitute for that proof.

## Canary and promotion

CANARY records actual trusted broker dispatches and their result category. The
activation service enforces request/effect counts from the attestation, rejects
unknown outcomes, requires `EFFECT_CONFIRMED`, and requires an independent
application-owned `VerificationResult` with non-model evidence. Callback success
alone cannot reach `CANARY` or `ACTIVE`.

`ActivationRecord.attestation_ids` exposes the evidence references. Host-proxy
audit events include the completed observation reference, and `TraceEvent` can
carry `effect_attestation_ids` for the Trace Explorer projection.

## Failure and residual limits

- `GUARANTEED_BY_JARVIS`: package/version/activation binding, fail-closed missing
  evidence, SHADOW suppression at the host-proxy dispatch boundary, durable
  unfinished-attempt reconciliation, and no package write path to promotion.
- `ENFORCED_BY_JARVIS_BROKER`: permission authorization, receipt lifecycle, and
  host proxy dispatch routing.
- `BEST_EFFORT`: the store cannot independently observe an effect after a trusted
  broker has dispatched it; the broker records dispatch and result category, while
  `VerificationEngine` supplies independent outcome evidence.
- `NOT_GUARANTEED`: an effectful path that is not composed through the typed host
  proxy and observer. Such a path cannot produce a trusted activation attestation
  and therefore cannot pass staged promotion.

The attestation path does not turn the broker into a filesystem/network sandbox;
the separate Windows integration isolation contract remains applicable. It also
does not claim that a successful dispatch proves the external world changed:
independent verification is still required.

## Defensive tests

`tests/test_effect_attestation.py` covers Shadow suppression and zero dispatch,
trusted CANARY dispatch, forged and mismatched attestation rejection, restart
reconciliation to `UNKNOWN_OUTCOME`, and a local host-proxy network fixture whose
executor is proven not to run in SHADOW. Activation regressions in
`tests/test_package_activation.py` exercise trusted attestation and independent
verification before promotion.

## Validation for this remediation

- `python scripts/quality.py` via the repository `.venv`: **1,172 passed, 6
  skipped**, Ruff format/check passed, mypy passed, 90% combined coverage.
- `python scripts/run_system_tests.py --suite deterministic-workflows`: **26
  passed**, run ID `e0df889a-24d2-4bf6-a4fb-3f95fd83e89b`.
- focused activation, host-proxy, trace, and attestation tests: **40 passed**.

The system harness records the current committed HEAD because this worktree is
intentionally uncommitted; the tests themselves ran against the final local
working tree. No external systems or real credentials were used.
