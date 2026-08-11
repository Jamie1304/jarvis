# ADR 0004: Versioned tool contract

## Decision

Adopt a versioned `ToolManifest` and strict Pydantic schema boundary for all capabilities. Invoke tools through `execute(context, validated_input)` behind a base `invoke` method that validates raw input, checks health and declared permissions, applies timeout/cancellation handling, and returns `ToolResult`.

## Rationale

This keeps capability implementation details outside the orchestrator and prevents untrusted model arguments from bypassing validation. Tool outcomes remain explicit and independently verifiable, while future privileged tools can be blocked until a permission broker is ready.
