# ADR 0005: Central tool registry

## Decision

JARVIS registers tools explicitly in a typed `ToolRegistry`. Records track
registration, enabled state, platform support, health, and usability separately.
Capability resolution is deterministic by semantic version and implementation
identifier.

## Rationale

The orchestrator needs a stable capability boundary without knowing how a tool
works. Explicit registration avoids arbitrary code execution during discovery,
while health transitions make temporary unavailability observable.

## Consequences

Duplicate IDs are errors and cannot replace an existing implementation. Trusted
factories may report initialization failures in the registry snapshot. Dynamic
untrusted plugins and privileged tools remain out of scope.
