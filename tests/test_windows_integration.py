"""Opt-in real Windows acceptance checks; CI reports skipped, never simulated success."""

import asyncio
import os
import subprocess
from hashlib import sha256

import pytest
from jarvis.camera.controller import CameraController
from jarvis.camera.provider import OpenCvCameraProvider
from jarvis.computer.accessibility import WindowsAccessibilityAdapter
from jarvis.computer.adapters import ComputerAdapterError, WindowsUiAutomationAdapter
from jarvis.computer.models import ApplicationDefinition, WindowInfo

pytestmark = pytest.mark.windows_integration


@pytest.mark.skipif(
    os.environ.get("JARVIS_WINDOWS_INTEGRATION") != "true",
    reason="Set JARVIS_WINDOWS_INTEGRATION=true to enable Windows desktop integration checks",
)
async def test_real_notepad_semantic_computer_acceptance() -> None:
    """Touch only the Notepad process this test launched in an interactive desktop."""

    pytest.importorskip("pywinauto")
    pytest.importorskip("PIL")
    adapter = WindowsUiAutomationAdapter(
        {"notepad": ApplicationDefinition("notepad", "notepad.exe")}
    )
    process_id: int | None = None
    try:
        launched = await adapter.launch_application("notepad")
        process_id = launched.process_id
        windows: tuple[WindowInfo, ...] = ()
        for _ in range(30):
            windows = await adapter.discover_windows("notepad")
            if any(item.process_id == process_id for item in windows):
                break
            await asyncio.sleep(0.2)
        window = next((item for item in windows if item.process_id == process_id), None)
        if window is None:
            pytest.fail("Notepad process was created but no interactive window was observed")
        focused = await adapter.focus_window(window.window_id)
        assert focused.process_id == process_id and focused.is_focused
        nodes = await WindowsAccessibilityAdapter().read_accessibility(window.window_id)
        edit = next(
            (
                item
                for item in nodes
                if item.control_type.casefold() == "edit" and item.automation_id
            ),
            None,
        )
        if edit is None:
            pytest.skip("The installed Notepad exposed no semantic editable control")
        text = "JARVIS Windows acceptance text"
        updated = await adapter.set_text(window.window_id, edit.automation_id or "", text)
        assert updated.window_id == window.window_id
        await adapter.write_clipboard(text)
        assert await adapter.read_clipboard() == text
        capture = await adapter.capture_screen()
        assert capture.width > 0 and capture.height > 0 and capture.png_bytes
        assert sha256(capture.png_bytes).hexdigest()
    except ComputerAdapterError as error:
        pytest.skip(f"Interactive Windows capability unavailable: {error}")
    finally:
        if process_id is not None:
            subprocess.run(
                ["taskkill", "/PID", str(process_id), "/T", "/F"],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


@pytest.mark.skipif(
    os.environ.get("JARVIS_CAMERA_INTEGRATION") != "true",
    reason="Set JARVIS_CAMERA_INTEGRATION=true to enable a real one-shot camera check",
)
@pytest.mark.asyncio
async def test_real_camera_capture_is_one_shot_and_releases_device() -> None:
    pytest.importorskip("cv2")
    provider = OpenCvCameraProvider(allowed_device_ids=frozenset({"0"}))
    devices = await provider.enumerate_devices()
    if not any(device.device_id == "0" for device in devices):
        pytest.skip("No explicitly allowed camera 0 is available")
    controller = CameraController(provider, frozenset({"0"}))
    frame = await controller.capture_once("0", timeout_seconds=10, cancellation=asyncio.Event())
    assert frame.width > 0 and frame.height > 0 and frame.data
    await controller.shutdown()
    assert controller.status.state.value == "inactive"
