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

Every tool provides a unique `tool_id`, name, description, semantic version, capability tags, strict Pydantic input and output schemas, declared permissions, supported platforms, timeout, and health state. Tools receive only `ToolExecutionContext`: task ID, correlation ID, caller, cancellation token, logger, optional trusted user ID, and a broker-minted authorization receipt. Callers cannot supply the receipt.

`ToolResult` always has a status: `success`, `expected_failure`, `unavailable`, `permission_denied`, `timeout`, `validation_error`, `cancelled`, or `internal_failure`. It may include typed output, structured evidence, safe metadata, and a stable error code/message. Raw library exceptions must be logged inside the tool boundary and never returned to callers.

## Creating a tool

1. Define strict Pydantic input and output models with `ConfigDict(extra="forbid", strict=True)`.
2. Implement `Tool[InputModel, OutputModel]` with a complete `ToolManifest`, `input_model`, and private `_execute_authorized(context, validated_input)` hook.
3. Privileged tools must override `_describe_action` in trusted code with a static action label, secret-safe argument summary, risk/safety class, granular permissions, and least-privilege scope. Never accept those values from model fields.
4. Return `ToolResult` from every expected outcome. Do not use `eval`, application containers, hidden global state, or unbrokered host APIs.
5. Register the tool explicitly in `ToolRegistry`; dynamic discovery is intentionally out of scope.
6. Test it independently with `ToolHarness`, including unknown fields, invalid types, policy denial, approval mutation/replay, cancellation, timeout, and failure mapping.

Manifests also declare an implementation identifier, enabled flag, and optional
dependency names. Usable implementations are selected by highest semantic
version, then implementation identifier, so selection is deterministic.

The reserved `invoke` method validates untrusted arguments, obtains an exact broker
authorization, checks health, enforces the manifest timeout, calls only the private
authorized hook, maps exceptions, and audits the outcome. Subclasses that attempt
to replace `invoke` or define a public `execute` entry point are rejected.

## Security and versioning

Use semantic versions. Increment the major version for a breaking schema or behavior change, minor for compatible capability additions, and patch for compatible fixes. Keep declared permissions minimal; current tools request no privileged permissions. Future filesystem, shell, computer-control, camera, or network tools require dedicated provider abstractions, an explicit policy, a trusted action descriptor, and adversarial permission tests before registration.

Calculator and local-time are safe local tools. Weather is an explicit unavailable placeholder until an approved network provider exists.

## Computer-tool rules

Computer tools are privileged tools. Keep their planner-facing interfaces semantic:
use application IDs, window IDs, control IDs, and text-entry operations rather than
Windows-library types or coordinate clicks. Coordinate actions are a separately
named fallback, require `computer.input`, and must include a safe trusted reason.

Never expose a `shell(command)` or `subprocess`-string tool. Resolve a model-supplied
command ID through a trusted catalogue, validate each argument separately, include
a bounded timeout and cancellation token, and execute with `shell=False`. Resolve
application IDs in the same way. A filesystem implementation must consume only the
authorized canonical scope path from the broker receipt. Screenshot implementations
must persist bytes behind a trusted artifact reference and return metadata/evidence,
not an image blob. Add deterministic mock-adapter tests for every adapter-facing
action and keep actual Windows desktop tests explicitly opt-in.

## Visual-understanding rules

Vision providers and action planners are untrusted inputs. They may suggest visible
elements and intended targets, but trusted fusion code creates target IDs and only
the brokered computer tools may act. Do not call adapters, input libraries, or a
tool's private authorized hook from visual code. Never translate a detected `Send`,
delete, install, or other sensitive target into permission; the mapped computer tool
must still obtain its normal policy decision and trusted-user approval when required.

Visual actions must use an observation from the current screen state, re-observe
before input, and verify from a fresh observation afterward. Coordinate actions must
be based on normalized bounds and trusted current display/DPI geometry. A retry must
run a new observe/diagnose/ground cycle and use a materially revised action; repeat
clicks with stale state are prohibited.
