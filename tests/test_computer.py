import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from jarvis.computer.adapters import ComputerAdapter
from jarvis.computer.artifacts import InMemoryScreenshotStore
from jarvis.computer.filesystem import FilesystemAdapter
from jarvis.computer.models import (
    CapturedScreen,
    CommandDefinition,
    CommandExecution,
    ControlState,
    LaunchInfo,
    MouseActionState,
    WindowInfo,
)
from jarvis.computer.terminal import (
    CommandAdapter,
    ControlledCommandService,
    SubprocessCommandAdapter,
)
from jarvis.computer.tools import (
    CaptureScreenTool,
    ControlledCommandTool,
    DiscoverWindowsTool,
    FocusWindowTool,
    LaunchApplicationTool,
    MouseFallbackTool,
    ReadClipboardTool,
    ReadTextFileTool,
    SetTextTool,
    WriteClipboardTool,
)
from jarvis.permissions import (
    Decision,
    Permission,
    PermissionBroker,
    PolicyEngine,
    PolicyRule,
    SafetyClass,
    ScopeConstraint,
)
from jarvis.tools.harness import ToolHarness
from jarvis.tools.models import ToolEvidence, ToolResultStatus
from jarvis.tools.registry import ToolRegistry


class FakeComputerAdapter(ComputerAdapter):
    def __init__(self) -> None:
        self.windows = (WindowInfo(101, "Notepad", 42, False),)
        self.clipboard = "initial clipboard"
        self.launches: list[str] = []
        self.focuses: list[int] = []
        self.text_updates: list[tuple[int, str, str]] = []
        self.mouse_clicks: list[MouseActionState] = []
        self.capture_count = 0

    async def discover_windows(self, title_contains: str | None) -> tuple[WindowInfo, ...]:
        if title_contains is None:
            return self.windows
        return tuple(
            item for item in self.windows if title_contains.casefold() in item.title.casefold()
        )

    async def launch_application(self, application_id: str) -> LaunchInfo:
        self.launches.append(application_id)
        return LaunchInfo(application_id, 777)

    async def focus_window(self, window_id: int) -> WindowInfo:
        self.focuses.append(window_id)
        return WindowInfo(window_id, "Notepad", 42, True)

    async def set_text(self, window_id: int, control_id: str, text: str) -> ControlState:
        self.text_updates.append((window_id, control_id, text))
        return ControlState(window_id, control_id, text)

    async def mouse_click(self, x: int, y: int, button: str) -> MouseActionState:
        state = MouseActionState(x, y, button)
        self.mouse_clicks.append(state)
        return state

    async def capture_screen(self) -> CapturedScreen:
        self.capture_count += 1
        return CapturedScreen(b"not-a-real-png", 800, 600, datetime.now(UTC))

    async def read_clipboard(self) -> str:
        return self.clipboard

    async def write_clipboard(self, text: str) -> int:
        self.clipboard = text
        return len(text)


class FakeFilesystemAdapter(FilesystemAdapter):
    def __init__(self, content: str = "contents") -> None:
        self.content = content
        self.paths: list[str] = []

    async def read_text(self, normalized_path: str, max_characters: int) -> str:
        self.paths.append(normalized_path)
        return self.content[:max_characters]


class FakeCommandAdapter(CommandAdapter):
    def __init__(self, outcome: CommandExecution, *, wait_for_cancel: bool = False) -> None:
        self.outcome = outcome
        self.wait_for_cancel = wait_for_cancel
        self.started = asyncio.Event()
        self.calls: list[tuple[CommandDefinition, tuple[str, ...], str, float]] = []

    async def execute(
        self,
        command: CommandDefinition,
        arguments: tuple[str, ...],
        working_directory: str,
        timeout_seconds: float,
        cancellation: asyncio.Event,
    ) -> CommandExecution:
        self.calls.append((command, arguments, working_directory, timeout_seconds))
        self.started.set()
        if self.wait_for_cancel:
            await cancellation.wait()
            return CommandExecution(None, "partial stdout", "", cancelled=True)
        return self.outcome


def broker_for(root: Path, *, clipboard_write: bool = True) -> PermissionBroker:
    rules = [
        PolicyRule(
            "discover-windows",
            Permission.SCREEN_READ,
            Decision.ALLOW,
            ScopeConstraint(tools=frozenset({"computer.discover_windows"})),
            frozenset({"discover windows"}),
        ),
        PolicyRule(
            "capture-screen",
            Permission.SCREEN_READ,
            Decision.ALLOW,
            ScopeConstraint(tools=frozenset({"computer.capture_screen"})),
            frozenset({"capture screen"}),
        ),
        PolicyRule(
            "launch-notepad",
            Permission.APPLICATION_LAUNCH,
            Decision.ALLOW,
            ScopeConstraint(
                applications=("notepad",),
                tools=frozenset({"computer.launch_application"}),
            ),
            frozenset({"launch application"}),
        ),
        PolicyRule(
            "focus-window",
            Permission.COMPUTER_INPUT,
            Decision.ALLOW,
            ScopeConstraint(tools=frozenset({"computer.focus_window"})),
            frozenset({"focus window"}),
        ),
        PolicyRule(
            "set-text",
            Permission.COMPUTER_INPUT,
            Decision.ALLOW,
            ScopeConstraint(tools=frozenset({"computer.set_text"})),
            frozenset({"set text"}),
        ),
        PolicyRule(
            "mouse-fallback",
            Permission.COMPUTER_INPUT,
            Decision.ALLOW,
            ScopeConstraint(tools=frozenset({"computer.mouse_fallback"})),
            frozenset({"mouse fallback click"}),
        ),
        PolicyRule(
            "read-clipboard",
            Permission.CLIPBOARD_READ,
            Decision.ALLOW,
            ScopeConstraint(tools=frozenset({"computer.read_clipboard"})),
            frozenset({"read clipboard"}),
        ),
        PolicyRule(
            "read-file",
            Permission.FILESYSTEM_READ,
            Decision.ALLOW,
            ScopeConstraint(
                paths=(str(root),),
                tools=frozenset({"computer.read_text_file"}),
            ),
            frozenset({"read text file"}),
        ),
        PolicyRule(
            "controlled-command",
            Permission.TERMINAL_EXECUTE,
            Decision.ALLOW,
            ScopeConstraint(
                paths=(str(root),),
                command_families=("git.status",),
                tools=frozenset({"computer.execute_command"}),
                max_duration_seconds=60,
            ),
            frozenset({"execute controlled command"}),
        ),
    ]
    if clipboard_write:
        rules.append(
            PolicyRule(
                "write-clipboard",
                Permission.CLIPBOARD_WRITE,
                Decision.ALLOW,
                ScopeConstraint(tools=frozenset({"computer.write_clipboard"})),
                frozenset({"write clipboard"}),
            )
        )
    return PermissionBroker(PolicyEngine(tuple(rules)))


def harness_for(tool: object, broker: PermissionBroker) -> ToolHarness:
    ToolRegistry((tool,), permission_broker=broker)  # type: ignore[arg-type]
    return ToolHarness(broker=broker)


@pytest.mark.asyncio
async def test_permission_denied_prevents_screen_capture(tmp_path: Path) -> None:
    adapter = FakeComputerAdapter()
    tool = CaptureScreenTool(adapter, InMemoryScreenshotStore())
    harness = harness_for(tool, PermissionBroker(PolicyEngine()))

    result = await harness.invoke(tool, {})

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert result.error is not None
    assert result.error.code == "missing_policy"
    assert adapter.capture_count == 0


@pytest.mark.asyncio
async def test_application_launch_is_cataloged_and_observable(tmp_path: Path) -> None:
    adapter = FakeComputerAdapter()
    tool = LaunchApplicationTool(adapter, frozenset({"notepad"}))
    harness = harness_for(tool, broker_for(tmp_path))

    result = await harness.invoke(tool, {"application_id": "notepad"})

    assert result.status is ToolResultStatus.SUCCESS
    assert result.output is not None
    assert result.output.model_dump() == {"application_id": "notepad", "process_id": 777}
    assert result.evidence == (ToolEvidence("process_id", "777"),)
    assert adapter.launches == ["notepad"]


@pytest.mark.asyncio
async def test_semantic_window_interaction_precedes_coordinates(tmp_path: Path) -> None:
    adapter = FakeComputerAdapter()
    focus = FocusWindowTool(adapter)
    text = SetTextTool(adapter)
    broker = broker_for(tmp_path)
    ToolRegistry((focus, text), permission_broker=broker)
    harness = ToolHarness(broker=broker)

    focused = await harness.invoke(focus, {"window_id": 101})
    updated = await harness.invoke(
        text,
        {"window_id": 101, "control_id": "DocumentText", "text": "hello"},
    )

    assert focused.status is ToolResultStatus.SUCCESS
    assert updated.status is ToolResultStatus.SUCCESS
    assert adapter.focuses == [101]
    assert adapter.text_updates == [(101, "DocumentText", "hello")]


@pytest.mark.asyncio
async def test_coordinate_action_is_explicit_fallback(tmp_path: Path) -> None:
    adapter = FakeComputerAdapter()
    tool = MouseFallbackTool(adapter)
    harness = harness_for(tool, broker_for(tmp_path))

    result = await harness.invoke(
        tool,
        {"x": 120, "y": 52, "button": "left", "fallback_reason": "control unavailable"},
    )

    assert result.status is ToolResultStatus.SUCCESS
    assert result.output is not None and result.output.model_dump()["used_fallback"] is True
    assert adapter.mouse_clicks == [MouseActionState(120, 52, "left")]


@pytest.mark.asyncio
async def test_command_timeout_returns_captured_output(tmp_path: Path) -> None:
    adapter = FakeCommandAdapter(
        CommandExecution(None, "partial stdout", "partial stderr", timed_out=True)
    )
    service = ControlledCommandService(
        {
            "git-status": CommandDefinition(
                "git-status",
                "git.exe",
                "git.status",
                frozenset({("status",)}),
                SafetyClass.ORDINARY,
            )
        },
        adapter,
    )
    tool = ControlledCommandTool(service)
    broker = broker_for(tmp_path)
    harness = harness_for(tool, broker)

    result = await harness.invoke(
        tool,
        {
            "command_id": "git-status",
            "arguments": ("status",),
            "working_directory": str(tmp_path),
            "timeout_seconds": 5,
        },
    )

    assert result.status is ToolResultStatus.TIMEOUT
    assert result.output is not None
    assert result.output.model_dump()["stdout"] == "partial stdout"
    assert adapter.calls[0][0].executable == "git.exe"


@pytest.mark.asyncio
async def test_real_no_shell_command_adapter_preserves_argument_boundaries(tmp_path: Path) -> None:
    command = CommandDefinition(
        "python-echo",
        sys.executable,
        "python.echo",
        frozenset({("-c", "import sys; print(sys.argv[1])", "argument with spaces")}),
        SafetyClass.ORDINARY,
    )
    result = await SubprocessCommandAdapter().execute(
        command,
        ("-c", "import sys; print(sys.argv[1])", "argument with spaces"),
        str(tmp_path),
        5,
        asyncio.Event(),
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == "argument with spaces"


@pytest.mark.asyncio
async def test_command_service_propagates_cancellation_to_adapter(tmp_path: Path) -> None:
    adapter = FakeCommandAdapter(CommandExecution(None, "", ""), wait_for_cancel=True)
    service = ControlledCommandService(
        {
            "git-status": CommandDefinition(
                "git-status",
                "git.exe",
                "git.status",
                frozenset({("status",)}),
                SafetyClass.ORDINARY,
            )
        },
        adapter,
    )
    cancellation = asyncio.Event()
    running = asyncio.create_task(
        service.execute("git-status", ("status",), str(tmp_path), 5, cancellation)
    )

    await adapter.started.wait()
    cancellation.set()
    result = await running

    assert result.cancelled is True
    assert result.stdout == "partial stdout"


@pytest.mark.asyncio
async def test_command_rejects_arguments_outside_the_trusted_catalog(tmp_path: Path) -> None:
    adapter = FakeCommandAdapter(CommandExecution(0, "", ""))
    service = ControlledCommandService(
        {
            "git-status": CommandDefinition(
                "git-status",
                "git.exe",
                "git.status",
                frozenset({("status",)}),
                SafetyClass.ORDINARY,
            )
        },
        adapter,
    )
    tool = ControlledCommandTool(service)
    broker = broker_for(tmp_path)
    harness = harness_for(tool, broker)

    result = await harness.invoke(
        tool,
        {
            "command_id": "git-status",
            "arguments": ("config", "--global", "core.editor", "unsafe"),
            "working_directory": str(tmp_path),
            "timeout_seconds": 5,
        },
    )

    assert result.status is ToolResultStatus.EXPECTED_FAILURE
    assert result.error is not None and result.error.code == "command_arguments_rejected"
    assert adapter.calls == []


@pytest.mark.asyncio
async def test_terminal_commands_require_approval_until_trusted_catalogue_classifies_them(
    tmp_path: Path,
) -> None:
    adapter = FakeCommandAdapter(CommandExecution(0, "", ""))
    service = ControlledCommandService(
        {
            "git-status": CommandDefinition(
                "git-status", "git.exe", "git.status", frozenset({("status",)})
            )
        },
        adapter,
    )
    tool = ControlledCommandTool(service)
    broker = broker_for(tmp_path)
    harness = harness_for(tool, broker)

    result = await harness.invoke(
        tool,
        {
            "command_id": "git-status",
            "arguments": ("status",),
            "working_directory": str(tmp_path),
            "timeout_seconds": 5,
        },
    )

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert result.error is not None and result.error.code == "approval_pending"
    request_id = UUID(
        dict((item.key, item.value) for item in result.metadata)["approval_request_id"]
    )
    request = await broker.get_approval(request_id)
    assert request is not None and request.reason.value == "hard_safety_approval_required"
    assert adapter.calls == []


@pytest.mark.asyncio
async def test_filesystem_scope_denial_does_not_reach_adapter(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    filesystem = FakeFilesystemAdapter()
    tool = ReadTextFileTool(filesystem)
    harness = harness_for(tool, broker_for(allowed))

    result = await harness.invoke(
        tool,
        {"path": str(tmp_path / "outside.txt"), "max_characters": 10},
    )

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert result.error is not None
    assert result.error.code == "scope_outside_policy"
    assert filesystem.paths == []


@pytest.mark.asyncio
async def test_clipboard_read_and_write_have_separate_permissions(tmp_path: Path) -> None:
    adapter = FakeComputerAdapter()
    read = ReadClipboardTool(adapter)
    write = WriteClipboardTool(adapter)
    broker = broker_for(tmp_path, clipboard_write=False)
    ToolRegistry((read, write), permission_broker=broker)
    harness = ToolHarness(broker=broker)

    read_result = await harness.invoke(read, {"max_characters": 5})
    write_result = await harness.invoke(write, {"text": "new clipboard"})

    assert read_result.status is ToolResultStatus.SUCCESS
    assert read_result.output is not None and read_result.output.model_dump()["text"] == "initi"
    assert write_result.status is ToolResultStatus.PERMISSION_DENIED
    assert adapter.clipboard == "initial clipboard"


@pytest.mark.asyncio
async def test_screenshot_returns_secure_reference_and_keeps_bytes_out_of_result(
    tmp_path: Path,
) -> None:
    adapter = FakeComputerAdapter()
    screenshots = InMemoryScreenshotStore()
    tool = CaptureScreenTool(adapter, screenshots)
    harness = harness_for(tool, broker_for(tmp_path))

    result = await harness.invoke(tool, {})

    assert result.status is ToolResultStatus.SUCCESS
    assert result.output is not None
    output = result.output.model_dump()
    assert output["reference"].startswith("screenshot:")
    assert output["width"] == 800
    assert "png_bytes" not in output
    assert screenshots.metadata(output["reference"]) is not None


@pytest.mark.asyncio
async def test_window_discovery_returns_observable_semantic_results(tmp_path: Path) -> None:
    adapter = FakeComputerAdapter()
    tool = DiscoverWindowsTool(adapter)
    harness = harness_for(tool, broker_for(tmp_path))

    result = await harness.invoke(tool, {"title_contains": "note"})

    assert result.status is ToolResultStatus.SUCCESS
    assert result.output is not None
    assert result.output.model_dump()["windows"][0]["window_id"] == 101
    assert result.evidence == (ToolEvidence("window_count", "1"),)
