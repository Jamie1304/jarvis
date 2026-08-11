# ADR 0009: One-shot brokered camera capture with ephemeral vision handoff

## Decision

Use a provider-neutral `CameraProvider` and a single-owner `CameraController` behind
brokered `camera.list` and `camera.capture` tools. Capture is one-shot, bounded, and
closes the provider session in all lifecycle paths. Frames are stored in memory with a
short expiry and handed to the existing vision provider by opaque reference through
`CameraVisionBridge`.

## Rationale

Camera hardware is a privacy-sensitive resource. An unrestricted stream or direct
provider access would make accidental activation, cleanup, and user-visible state
difficult to enforce. Separating hardware lifecycle from vision reasoning preserves
the permission boundary and allows deterministic mock testing.

## Consequences

Hardware support requires explicit trusted composition and user-visible policy. The
optional OpenCV provider and manual procedure are Windows-specific; CI does not access
physical cameras. Future streaming must be a separately approved, UI-visible feature,
not an extension of the agent capture tool.
