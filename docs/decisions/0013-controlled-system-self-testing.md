# ADR 0013: controlled system-level self-testing

## Decision

Introduce a typed `TestSuiteCatalog` and `ControlledTestRunner` for fixed,
non-hardware system-test commands. Preserve raw redacted artifacts separately from
machine-readable `TestRun` results and advisory diagnosis. Keep startup smoke tests
optional and localhost-only. Run deterministic catalog entries in CI after the full
quality gate.

## Consequences

The agent cannot turn self-testing into arbitrary shell execution, credential access,
hardware activation, software installation, messaging, deletion, or deployment.
Tests can be evaluated by Phase 11 without treating a diagnosis as authoritative raw
evidence. Real desktop, voice, camera, and process-isolation smoke tests remain
explicitly manual/trusted because they require environmental controls outside ordinary
CI.
