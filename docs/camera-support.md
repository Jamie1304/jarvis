# Controlled camera support

## Boundary

Phase 8 exposes exactly two agent-facing capabilities:

- `camera.list`: enumerate devices and report visible controller state;
- `camera.capture`: open one trusted device, capture one bounded frame, then close it.

Both require the granular `camera.read` permission. The default tool catalog does not
register them. Trusted application composition supplies `CameraProvider`, an explicit
allowed-device ID set, `CameraController`, and an `EphemeralFrameStore`.

Mentioning a camera in a prompt does nothing. The model cannot open a device, pass an
arbitrary hardware path, or request an infinite stream. Streaming hooks exist only as
an optional provider lifecycle for a future user-visible application feature; no agent
tool exposes them.

## Provider and state

`CameraProvider` is platform/model-neutral and supports enumeration, open, health, and
session capture/close. The optional `OpenCvCameraProvider` uses OpenCV on Windows and
is installed with `python -m pip install -e ".[camera]"`.

`CameraController.status` is application/UI-visible:

- `inactive`: no device handle is owned;
- `opening`: a trusted capture is opening a selected device;
- `active`: a frame capture is in progress;
- `error`: the last operation failed and includes a safe detail.

The controller serializes concurrent capture requests. Every provider session is
closed in a `finally` path, including provider errors, camera-busy/disconnected
devices, timeout, task cancellation, and application shutdown.

## Privacy and vision handoff

`InMemoryFrameStore` is the default and never writes camera frames to disk. Each frame
gets an opaque `camera-frame:<id>` reference and a 30-second expiry; the vision bridge
releases it immediately after the provider returns or fails. Tool output contains only
reference, dimensions, timestamp, expiry, and content type.

`CameraVisionBridge` converts the live reference into the existing `VisionRequest` with
`source=VisualSource.CAMERA`. Camera hardware and image reasoning remain separate;
vision output cannot grant permissions or authorize computer input.

## Manual Windows hardware test

1. Use a dedicated interactive Windows session and close applications that may own
   the camera. Install the optional dependency: `python -m pip install -e ".[camera]"`.
2. Compose `OpenCvCameraProvider`, an explicit allowed device ID (for example `0`),
   `CameraController`, `InMemoryFrameStore`, and a `PermissionBroker` policy for
   `camera.list`/`camera.capture`.
3. Register `create_camera_tools(...)` explicitly and invoke `camera.list` as a
   trusted user action. Confirm the UI reports `inactive` after enumeration.
4. Invoke `camera.capture` with trusted-user authorization. Confirm the UI visibly
   transitions through `opening` and `active`, then returns to `inactive`; inspect
   that the frame reference expires or is released after vision handoff.
5. Unplug the camera, repeat capture, and confirm `error` plus handle cleanup. Stop
   the application during a capture and confirm shutdown releases the device.

These steps are manual hardware checks. Deterministic CI uses mocks and must never
claim that a physical camera was accessed.
