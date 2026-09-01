# Hierarchical diagnostics and repair

JARVIS degrades an unhealthy capability before degrading the assistant, but
only when the fallback preserves the active privacy, integrity, and authority
guarantees. A repair is never an implicit permission grant and a capability
failure must not become a runtime-wide crash.

## Troubleshooting ownership

`ComponentDoctor` routes a `ComponentProblem` to exactly one declared owner:

| Owner | Responsibility |
| --- | --- |
| `CORE` | JARVIS composition, runtime seams, stores, and application lifecycle |
| `PROVIDER` | Provider, model runtime, and model-internal health |
| `SANDBOX` | Sandboxed process, typed IPC, resource, and crash containment |
| `PROVISIONING` | Installation, environment setup, migrations, and setup reality |
| `CAPABILITY` | An `IntegrationPackage`-owned capability when it declares the contract |

The owner is trusted application metadata, not a model or external event. A
problem whose owner disagrees with the registered playbook is rejected. The
doctor does not become a second task, permission, package-certification, or
activation authority.

## Contracts and trust boundary

The native contracts are in `jarvis.component_doctor`:

- `DiagnosticProbe` and `DiagnosticProbeResult` are bounded read-only checks;
- `FailureSignature` identifies a known failure;
- `RepairPlaybook` joins an owner, signatures, probes, repair declarations,
  fallback strategy, and expected verification;
- `RepairAction` is the validated package repair declaration;
- `RepairAttempt` records each bounded effect attempt and outcome; and
- `ComponentDoctor` coordinates diagnosis, repair, fallback, trace, and health.

Package metadata is declarative. The composition root must bind each declared
probe or action ID to an application-owned callback. Generated package source,
model research, event payloads, and diagnostic prose cannot provide a callback,
grant approval, or rewrite a certified baseline. Repair actions must remain
approval-bound and pass through the normal `PermissionBroker`/policy path.

## Pipeline

```text
problem
  -> CapabilityHealthService
  -> owner playbook and read-only probes
  -> known failure signature?
       yes -> trusted declared repair
       no  -> bounded research/solution candidate
  -> sandbox/security validation for a new candidate
  -> fresh exact approval when required
  -> typed repair callback
  -> verification
  -> health result, trace, and fallback/quarantine
```

Research candidates are not actionable until they are marked trusted,
sandbox-verified, and security-reviewed by trusted application code. A
candidate that is merely suggested by an LLM remains `RESEARCH_REQUIRED`.
There is no arbitrary shell or package hook in the doctor.

Repair outcomes are explicit:

- `PRE_EFFECT_FAILURE` and `SAFE_TO_RETRY` may retry within the bounded attempt
  limit;
- `EFFECT_CONFIRMED` requires verification and all declared verification
  evidence;
- `UNKNOWN_OUTCOME` stops retries, records the repair as quarantined, and never
  blindly replays the effect.

Repair callbacks and fallback callbacks are exception-isolated. Their failure
becomes a bounded diagnostic result and cannot crash the whole assistant.
`CapabilityHealthService` records health and emits the existing health/trace
projections; it does not authorize the repair.

## Safe degradation

Fallbacks are package/application declarations and must explicitly preserve
privacy and security. Typical examples are wake word to push-to-talk, TTS to
text-only, camera to a non-camera workflow, a preferred model to an allowed
fallback, an unhealthy generated package to its last-known-good version, or a
rich UI to generic controls. A fallback that changes listening privacy,
permission policy, credential scope, or integrity guarantees is rejected.

Fallback success is recorded as `DEGRADED`, not as a repaired capability.
Approval-bound fallbacks require a fresh trusted authorization callback.

## Learning boundary

A successful repair is evidence for the current incident only. A playbook or
repair may become a reusable Skill only through the normal verified procedure
learning pipeline: repeated verified success, privacy sanitization, testing,
and normal activation validation. Unknown or unverified outcomes and secret-
bearing histories are never learned.

## Ownership and limitations

`ComponentDoctor` is a transient orchestration service owned by the runtime
composition root. It owns no durable domain truth. Health reports belong to
`CapabilityHealthService`, package declarations and certified behavior belong
to package review/certification, permissions belong to `PermissionBroker`,
plans/tasks belong to `PlanningEngine`, and evidence belongs to the existing
verification contracts. The authoritative-state map must be updated before a
future durable diagnostic or repair store is introduced.

Passive probes do not prove an external effect. Native process, filesystem,
network, device, and reparse-point guarantees remain those of their trusted
brokers/providers; the doctor only consumes their bounded typed results.
