import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from jarvis.camera.controller import CameraController
from jarvis.camera.models import (
    CameraBusyError,
    CameraCaptureCancelledError,
    CameraCaptureTimeoutError,
    CameraDevice,
    CameraFrame,
    CameraHealth,
    CameraHealthState,
    CameraProviderError,
    CameraState,
)
from jarvis.camera.provider import CameraProvider, CameraSession
from jarvis.camera.store import InMemoryFrameStore
from jarvis.camera.tools import CameraCaptureTool, CameraListTool
from jarvis.camera.vision import CameraVisionBridge
from jarvis.permissions import (
    Decision,
    Permission,
    PermissionBroker,
    PolicyEngine,
    PolicyRule,
    ScopeConstraint,
)
from jarvis.tools.harness import ToolHarness
from jarvis.tools.models import ToolResultStatus
from jarvis.tools.registry import ToolRegistry
from jarvis.vision.models import VisionAnalysis, VisualSource
from jarvis.vision.providers import VisionProvider


class FakeCameraSession(CameraSession):
    def __init__(
        self,
        device_id: str,
        *,
        wait_for_cancellation: bool = False,
        fail: CameraProviderError | None = None,
    ) -> None:
        self._device_id = device_id
        self.wait_for_cancellation = wait_for_cancellation
        self.fail = fail
        self.started = asyncio.Event()
        self.closed = False

    @property
    def device_id(self) -> str:
        return self._device_id

    async def capture_frame(
        self, timeout_seconds: float, cancellation: asyncio.Event
    ) -> CameraFrame:
        del timeout_seconds
        self.started.set()
        if self.wait_for_cancellation:
            await cancellation.wait()
            raise asyncio.CancelledError
        if self.fail is not None:
            raise self.fail
        return CameraFrame(b"frame", 640, 480, datetime.now(UTC))

    async def close(self) -> None:
        self.closed = True


class FakeCameraProvider(CameraProvider):
    def __init__(
        self,
        *,
        devices: tuple[CameraDevice, ...] = (CameraDevice("0", "Mock camera", "mock"),),
        open_error: CameraProviderError | None = None,
        session: FakeCameraSession | None = None,
    ) -> None:
        self.devices = devices
        self.open_error = open_error
        self.session = session
        self.open_count = 0
        self.active_sessions = 0
        self.max_active_sessions = 0

    async def enumerate_devices(self) -> tuple[CameraDevice, ...]:
        return self.devices

    async def open_device(self, device_id: str) -> CameraSession:
        self.open_count += 1
        if self.open_error is not None:
            raise self.open_error
        session = self.session or FakeCameraSession(device_id)
        self.active_sessions += 1
        self.max_active_sessions = max(self.max_active_sessions, self.active_sessions)
        original_close = session.close

        async def close_once() -> None:
            if not session.closed:
                await original_close()
                self.active_sessions -= 1

        session.close = close_once  # type: ignore[method-assign]
        return session

    async def health(self, device_id: str | None = None) -> CameraHealth:
        return CameraHealth(device_id, CameraHealthState.AVAILABLE, "mock ready")


class RecordingVisionProvider(VisionProvider):
    def __init__(self) -> None:
        self.sources: list[VisualSource] = []

    async def observe(self, request: object) -> VisionAnalysis:
        self.sources.append(request.source)  # type: ignore[attr-defined]
        return VisionAnalysis((), (), 1.0)


def broker(*, allow: bool = True) -> PermissionBroker:
    if not allow:
        return PermissionBroker(PolicyEngine())
    return PermissionBroker(
        PolicyEngine(
            (
                PolicyRule(
                    "camera-list",
                    Permission.CAMERA_READ,
                    Decision.ALLOW,
                    ScopeConstraint(tools=frozenset({"camera.list"})),
                    frozenset({"list cameras"}),
                ),
                PolicyRule(
                    "camera-capture",
                    Permission.CAMERA_READ,
                    Decision.ALLOW,
                    ScopeConstraint(tools=frozenset({"camera.capture"})),
                    frozenset({"capture camera frame"}),
                ),
            )
        )
    )


def harness_for(tool: object, permission_broker: PermissionBroker) -> ToolHarness:
    ToolRegistry((tool,), permission_broker=permission_broker)  # type: ignore[arg-type]
    return ToolHarness(broker=permission_broker)


@pytest.mark.asyncio
async def test_camera_list_reports_no_device_without_opening_hardware() -> None:
    provider = FakeCameraProvider(devices=())
    controller = CameraController(provider, frozenset())
    tool = CameraListTool(controller)
    result = await harness_for(tool, broker()).invoke(tool, {})

    assert result.status is ToolResultStatus.SUCCESS
    assert result.output is not None and result.output.model_dump()["devices"] == ()
    assert provider.open_count == 0
    assert controller.status.state is CameraState.INACTIVE


@pytest.mark.asyncio
async def test_camera_capture_permission_denial_does_not_open_device() -> None:
    provider = FakeCameraProvider()
    controller = CameraController(provider, frozenset({"0"}))
    tool = CameraCaptureTool(controller, InMemoryFrameStore())

    result = await harness_for(tool, broker(allow=False)).invoke(
        tool, {"device_id": "0", "timeout_seconds": 2}
    )

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert provider.open_count == 0
    assert controller.status.state is CameraState.INACTIVE


@pytest.mark.asyncio
async def test_camera_capture_success_is_one_shot_and_frame_is_ephemeral() -> None:
    provider = FakeCameraProvider()
    frames = InMemoryFrameStore()
    controller = CameraController(provider, frozenset({"0"}))
    tool = CameraCaptureTool(controller, frames)

    result = await harness_for(tool, broker()).invoke(
        tool, {"device_id": "0", "timeout_seconds": 2}
    )

    assert result.status is ToolResultStatus.SUCCESS
    assert result.output is not None
    frame_id = result.output.model_dump()["frame_id"]
    assert await frames.read(frame_id) is not None
    assert controller.status.state is CameraState.INACTIVE
    assert provider.active_sessions == 0


@pytest.mark.asyncio
async def test_camera_busy_failure_exposes_error_state_and_releases_handles() -> None:
    provider = FakeCameraProvider(open_error=CameraBusyError("busy"))
    controller = CameraController(provider, frozenset({"0"}))
    tool = CameraCaptureTool(controller, InMemoryFrameStore())

    result = await harness_for(tool, broker()).invoke(tool, {"device_id": "0"})

    assert result.status is ToolResultStatus.EXPECTED_FAILURE
    assert controller.status.state is CameraState.ERROR
    assert provider.active_sessions == 0


@pytest.mark.asyncio
async def test_capture_timeout_closes_session() -> None:
    session = FakeCameraSession("0", wait_for_cancellation=True)
    provider = FakeCameraProvider(session=session)
    controller = CameraController(provider, frozenset({"0"}))

    with pytest.raises(CameraCaptureTimeoutError):
        await controller.capture_once("0", timeout_seconds=0.01, cancellation=asyncio.Event())

    assert session.closed is True
    assert provider.active_sessions == 0
    assert controller.status.state is CameraState.ERROR


@pytest.mark.asyncio
async def test_capture_cancellation_and_shutdown_release_session() -> None:
    session = FakeCameraSession("0", wait_for_cancellation=True)
    provider = FakeCameraProvider(session=session)
    controller = CameraController(provider, frozenset({"0"}))
    cancellation = asyncio.Event()
    running = asyncio.create_task(
        controller.capture_once("0", timeout_seconds=10, cancellation=cancellation)
    )

    await session.started.wait()
    shutdown = asyncio.create_task(controller.shutdown())
    cancellation.set()
    with pytest.raises(CameraCaptureCancelledError):
        await running
    await shutdown

    assert session.closed is True
    assert provider.active_sessions == 0
    assert controller.status.state is CameraState.INACTIVE


@pytest.mark.asyncio
async def test_concurrent_captures_are_serialized_to_one_device_session() -> None:
    provider = FakeCameraProvider()
    controller = CameraController(provider, frozenset({"0"}))
    cancellation = asyncio.Event()

    frames = await asyncio.gather(
        controller.capture_once("0", timeout_seconds=2, cancellation=cancellation),
        controller.capture_once("0", timeout_seconds=2, cancellation=cancellation),
    )

    assert len(frames) == 2
    assert provider.max_active_sessions == 1
    assert provider.active_sessions == 0


@pytest.mark.asyncio
async def test_camera_frame_handoff_uses_existing_vision_provider_and_releases_frame() -> None:
    frames = InMemoryFrameStore()
    frame = CameraFrame(b"frame", 320, 240, datetime.now(UTC))
    artifact = await frames.save("0", frame, ttl_seconds=30)
    provider = RecordingVisionProvider()
    bridge = CameraVisionBridge(frames, provider)

    result = await bridge.analyze(
        artifact.reference, task_id=uuid4(), task_objective="Describe the camera frame"
    )

    assert result.confidence == 1.0
    assert provider.sources == [VisualSource.CAMERA]
    assert await frames.read(artifact.reference) is None
