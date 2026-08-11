# Tool and skill system

Phase 4 adds `ToolRegistry` as the central capability catalog. The orchestrator
resolves capabilities through the registry and never imports a concrete
implementation.

Tools are explicitly registered by trusted internal code or an explicitly
configured factory. The registry does not scan directories, import arbitrary
modules, or execute untrusted plugin code. Duplicate IDs are rejected.

Registry state is deliberately separate from runtime health:

- `registered`: the manifest and implementation were accepted;
- `enabled`: the manifest permits use;
- `healthy`: the last health check reported availability;
- `usable`: all required conditions, including platform support, hold.

Use `snapshot()` for diagnostics and UI. It contains safe manifest and health
metadata only; secrets and provider internals must not be added.

Tools are explicit, versioned capabilities. A tool describes what it does through
a `ToolManifest`; the orchestrator resolves a capability through the registry and
never depends on implementation details.

## Contract

Every tool provides a unique `tool_id`, name, description, semantic version, capability tags, strict Pydantic input and output schemas, declared permissions, supported platforms, timeout, and health state. Tools receive only `ToolExecutionContext`: task ID, correlation ID, caller, cancellation token, permission context, and logger.

`ToolResult` always has a status: `success`, `expected_failure`, `unavailable`, `permission_denied`, `timeout`, `validation_error`, `cancelled`, or `internal_failure`. It may include typed output, structured evidence, safe metadata, and a stable error code/message. Raw library exceptions must be logged inside the tool boundary and never returned to callers.

## Creating a tool

1. Define strict Pydantic input and output models with `ConfigDict(extra="forbid", strict=True)`.
2. Implement `Tool[InputModel, OutputModel]` with a complete `ToolManifest`, `input_model`, and `execute(context, validated_input)`.
3. Return `ToolResult` from every expected outcome. Do not use `eval`, shell execution, application containers, or hidden global state.
4. Register the tool explicitly in `ToolRegistry`; dynamic discovery is intentionally out of scope.
5. Test it independently with `ToolHarness`, including unknown fields, invalid types, cancellation, timeout, and failure mapping.

Manifests also declare an implementation identifier, enabled flag, and optional
dependency names. Usable implementations are selected by highest semantic
version, then implementation identifier, so selection is deterministic.

The base `invoke` method validates untrusted arguments before `execute` runs, rejects unknown fields, checks declared permissions and health, enforces the manifest timeout, and maps unexpected exceptions to `internal_failure`.

## Security and versioning

Use semantic versions. Increment the major version for a breaking schema or behavior change, minor for compatible capability additions, and patch for compatible fixes. Keep declared permissions minimal; current tools request no privileged permissions. Future filesystem, shell, computer-control, camera, or network tools require dedicated provider abstractions and permission-broker integration before registration.

Calculator and local-time are safe local tools. Weather is an explicit unavailable placeholder until an approved network provider exists.
