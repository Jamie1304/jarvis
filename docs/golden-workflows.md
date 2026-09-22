# Privacy-safe golden workflows

Golden workflows are installation-specific regression definitions for behavior
that matters enough to protect across model, integration, self-improvement, or
self-update changes. They are tests and evidence, not a second planner and not
an authority to execute effects.

## Contract

`GoldenWorkflow` is identified by a safe ID and immutable `Version`. It contains
bounded `Fixture` inputs and an `ExpectedResult`. `ExpectedResult` stores semantic
criteria and a `VerificationPlan`; it does not store an expected response string.
The injected executor only supplies observations. `GoldenWorkflowService` sends
those observations to `VerificationEngine`, so a model saying that a workflow
passed is never enough.

The workflow classes are:

- `DETERMINISTIC`: synthetic inputs and stable local observations;
- `SEMI_DETERMINISTIC`: bounded environment variation with stable criteria;
- `INTEGRATION_REQUIRED`: an explicitly configured integration is needed;
- `HARDWARE_REQUIRED`: a physical device or sensor is needed.

An unavailable integration or device produces `SKIPPED`, which cannot satisfy a
gate. A failed, rejected, cancelled, or skipped run blocks the change. A change
with no applicable active regression coverage also blocks: absence of evidence is
not a pass.

## Privacy and provenance

Fixtures default to synthetic data. `Fixture` sanitizes and bounds input at the
boundary: secret-like fields and values are redacted, personal values and local
paths are generalized, and unsupported or oversized data is rejected. A trace
derived workflow keeps only a generalized event shape/count and a digest of that
shape. It requires verification and completion facts and rejects failed or
`UNKNOWN_OUTCOME` traces. It never copies prompts, credentials, or raw history.

The expected criteria are fixed before a run. A run cannot regenerate them from
its output. A candidate must provide provenance and verified-success count; it
cannot mark existing workflows excluded, replace their fingerprint, or weaken
their criteria. Repeated routines and frequent chains require repeated verified
successes. Critical generated capabilities and user-marked important workflows
still pass the same trusted candidate gate.

## Durable ownership

`GoldenWorkflowStore` is the sole owner of golden definitions and run results.
It uses SQLite WAL, foreign keys, a bounded busy timeout, schema versioning, and
future-schema refusal. Definitions are fingerprint checked after restart and
before execution. Run IDs are idempotent: reusing one with different evidence is
rejected. The store does not own tasks, plans, trace truth, artifacts, or
verification policy.

Users can inspect active or retired workflows, retire an obsolete workflow, and
delete it only after retirement. Candidate/model/integration code has no delete
or registration authority. The application must bind the user operation to its
normal authenticated user service; the `GoldenActor` value is only the typed
boundary contract, not an identity proof.

## Required change gate

Before applying any relevant change, the owning trusted change service must call:

```text
GoldenWorkflowService.require_before(
    MODEL_CHANGE | INTEGRATION_UPDATE |
    SELF_IMPROVEMENT | SELF_UPDATE,
    trusted_fixture_executor,
)
```

The executor may use normal application services and read-only/sandboxed test
adapters, but it cannot receive a permission bypass or direct mutation path.
The gate is required before the changed model, integration, improvement, or
updater is activated. This service exposes the common gate contract; each future
change pipeline remains responsible for invoking it at its own activation
boundary and recording the returned `RunResult` evidence in its normal trace.

Golden workflows do not replace unit, integration, hardware, or manual tests.
Hardware and integration classes remain explicit, and unexecuted checks are not
reported as passed. Retiring or deleting obsolete tests is a user-controlled,
auditable action and must not be used to make a change pass.

See [`authoritative-state-map.md`](authoritative-state-map.md) for the durable
ownership entry and [`verification-and-outcomes.md`](verification-and-outcomes.md)
for the evidence rules.
