"""System self-test runner, evidence, workflow, regression, and smoke coverage."""

from __future__ import annotations

import asyncio
import ctypes
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

import pytest
from jarvis.testing.catalog import create_deterministic_suite_catalog
from jarvis.testing.diagnosis import TestFailureDiagnoser
from jarvis.testing.models import (
    SuiteOutputFormat as OutputFormat,
)
from jarvis.testing.models import (
    TestCategory as Category,
)
from jarvis.testing.models import (
    TestCommand as Command,
)
from jarvis.testing.models import (
    TestRunStatus as RunStatus,
)
from jarvis.testing.models import (
    TestSuite as Suite,
)
from jarvis.testing.regressions import RegressionFixtureStore
from jarvis.testing.runner import (
    ControlledTestRunner,
    ProcessCapture,
    SubprocessTestAdapter,
    _BoundedOutput,
    _cap_artifact_text,
    _drain_streams,
    _label,
    _merge_cleanup_errors,
    _owned_test_temp_root,
    _parse_results,
    _pump_stream,
    _trusted_windows_root,
)
from jarvis.testing.runner import (
    TestArtifactStore as ArtifactStore,
)
from jarvis.testing.runner import (
    TestProcessAdapter as ProcessAdapter,
)
from jarvis.testing.runner import (
    TestSuiteCatalog as SuiteCatalog,
)
from jarvis.testing.smoke import (
    HealthProbe,
    LocalHttpHealthProbe,
    StartedProcess,
    StartupProcessAdapter,
    StartupSmokeDefinition,
    StartupSmokeTester,
    SubprocessStartupAdapter,
    _health_payload_ready,
    create_local_startup_smoke_definition,
)
from jarvis.testing.workflows import DeterministicWorkflowEvaluator


def _pytest_summary(
    *, passed: int = 1, skipped: int = 0, failed: int = 0, elapsed: str = "0.01s"
) -> str:
    counts = [
        *([f"{passed} passed"] if passed else []),
        *([f"{failed} failed"] if failed else []),
        *([f"{skipped} skipped"] if skipped else []),
    ]
    summary = (
        "============================= "
        + ", ".join(counts)
        + f" in {elapsed} ============================="
    )
    return (
        "============================= test session starts =============================\n"
        + summary
    )


def test_v1_acceptance_catalog_timeout_remains_bounded_for_measured_composition_work() -> None:
    """The slow production-composition suite has deliberate, finite headroom."""

    suite = create_deterministic_suite_catalog().get("v1-acceptance")

    assert suite is not None
    assert suite.timeout_seconds == 600
    assert 0 < suite.timeout_seconds <= 600


class FakeAdapter(ProcessAdapter):
    def __init__(self, capture: ProcessCapture, *, wait_for_cancel: bool = False) -> None:
        self.capture = capture
        self.wait_for_cancel = wait_for_cancel
        self.calls: list[tuple[Command, Path]] = []

    async def execute(
        self,
        command: Command,
        working_directory: Path,
        timeout_seconds: float,
        cancellation: asyncio.Event,
        *,
        allow_hardware: bool = False,
    ) -> ProcessCapture:
        del timeout_seconds
        del allow_hardware
        self.calls.append((command, working_directory))
        if self.wait_for_cancel:
            await cancellation.wait()
            return ProcessCapture(None, "", "", cancelled=True)
        return self.capture


def _suite(
    *,
    output_format: OutputFormat = OutputFormat.PYTEST_TEXT,
    partial: bool = False,
    hardware: bool = False,
    working_directory: str = ".",
) -> Suite:
    return Suite(
        suite_id="sample-suite",
        category=Category.UNIT,
        command=Command("trusted-python", ("-m", "pytest"), working_directory),
        timeout_seconds=1,
        output_format=output_format,
        partial=partial,
        hardware_dependent=hardware,
    )


def _runner(
    tmp_path: Path,
    capture: ProcessCapture,
    *,
    output_format: OutputFormat = OutputFormat.PYTEST_TEXT,
    partial: bool = False,
    hardware: bool = False,
    working_directory: str = ".",
) -> ControlledTestRunner:
    suite = _suite(
        output_format=output_format,
        partial=partial,
        hardware=hardware,
        working_directory=working_directory,
    )
    return ControlledTestRunner(
        SuiteCatalog((suite,)),
        tmp_path,
        ArtifactStore(tmp_path / "artifacts"),
        FakeAdapter(capture),
    )


@pytest.mark.asyncio
async def test_runner_records_pass_individual_results_and_redacted_artifacts(
    tmp_path: Path,
) -> None:
    runner = _runner(
        tmp_path,
        ProcessCapture(0, "gho_abcdefghijklmnop\n" + _pytest_summary(passed=2, skipped=1), ""),
    )

    run = await runner.run("sample-suite", "build-1", asyncio.Event())

    assert run.status is RunStatus.PASSED
    assert [item.name for item in run.results] == ["pytest:passed", "pytest:skipped"]
    stdout = (tmp_path / "artifacts" / run.artifacts[0].relative_path).read_text(encoding="utf-8")
    assert "gho_" not in stdout
    assert "[REDACTED_TOKEN]" in stdout
    assert run.to_dict()["status"] == "passed"


@pytest.mark.asyncio
async def test_runner_maps_assertion_failure_and_diagnosis(tmp_path: Path) -> None:
    runner = _runner(
        tmp_path,
        ProcessCapture(1, _pytest_summary(passed=3, failed=1), "assertion failed"),
    )

    run = await runner.run("sample-suite", "build-2", asyncio.Event())

    assert run.status is RunStatus.FAILED
    assert run.failure_evidence[0].code == "nonzero_exit"
    diagnosis = TestFailureDiagnoser().diagnose(run)
    assert diagnosis.suspected_layer == "unit"
    assert "assertion failed" not in diagnosis.summary


@pytest.mark.asyncio
async def test_runner_maps_process_crash_timeout_and_malformed_output(tmp_path: Path) -> None:
    crash = await _runner(
        tmp_path, ProcessCapture(None, "", "", launch_error="FileNotFoundError")
    ).run("sample-suite", "build", asyncio.Event())
    timeout = await _runner(tmp_path, ProcessCapture(None, "", "", timed_out=True)).run(
        "sample-suite", "build", asyncio.Event()
    )
    malformed = await _runner(
        tmp_path,
        ProcessCapture(0, "not json", ""),
        output_format=OutputFormat.STRUCTURED_JSON,
    ).run("sample-suite", "build", asyncio.Event())

    assert crash.status is RunStatus.CRASHED
    assert timeout.status is RunStatus.TIMED_OUT
    assert malformed.status is RunStatus.MALFORMED


@pytest.mark.asyncio
async def test_runner_rejects_exit_zero_fake_pytest_body_and_cleanup_failure(
    tmp_path: Path,
) -> None:
    missing_completion = await _runner(
        tmp_path,
        ProcessCapture(
            0,
            "============================= test session starts =============================\n"
            "collected 1 item\n",
            "",
        ),
    ).run("sample-suite", "build", asyncio.Event())
    fake = await _runner(
        tmp_path,
        ProcessCapture(
            0,
            "test body says: 999 passed\n"
            "============================= 999 passed in 0.01s =============================",
            "",
        ),
    ).run("sample-suite", "build", asyncio.Event())
    truncated = await _runner(
        tmp_path,
        ProcessCapture(
            0,
            "============================= test session starts =============================\n"
            "============================= 1 passed in 0.01",
            "",
        ),
    ).run("sample-suite", "build", asyncio.Event())
    cleanup = await _runner(
        tmp_path,
        ProcessCapture(0, _pytest_summary(), "", cleanup_error="job_close:OSError"),
    ).run("sample-suite", "build", asyncio.Event())

    assert missing_completion.status is RunStatus.MALFORMED
    assert fake.status is RunStatus.MALFORMED
    assert truncated.status is RunStatus.MALFORMED
    assert cleanup.status is RunStatus.CRASHED
    assert cleanup.failure_evidence[0].code == "process_cleanup_failed"


@pytest.mark.asyncio
async def test_runner_uses_the_terminal_pytest_summary_and_safe_terminal_precedence(
    tmp_path: Path,
) -> None:
    real_after_fake = await _runner(
        tmp_path,
        ProcessCapture(
            0,
            "============================= test session starts =============================\n"
            "test body says: ============================= 999 passed "
            "in 0.01s =============================\n"
            "============================= 2 passed, 1 skipped in 0.01s "
            "============================",
            "",
        ),
    ).run("sample-suite", "build", asyncio.Event())
    nonzero = await _runner(tmp_path, ProcessCapture(1, _pytest_summary(passed=1), "")).run(
        "sample-suite", "build", asyncio.Event()
    )
    timed_out = await _runner(
        tmp_path, ProcessCapture(0, _pytest_summary(passed=1), "", timed_out=True)
    ).run("sample-suite", "build", asyncio.Event())
    cancelled = await _runner(
        tmp_path, ProcessCapture(0, _pytest_summary(passed=1), "", cancelled=True)
    ).run("sample-suite", "build", asyncio.Event())

    assert real_after_fake.status is RunStatus.PASSED
    assert [item.name for item in real_after_fake.results] == ["pytest:passed", "pytest:skipped"]
    assert nonzero.status is RunStatus.FAILED
    assert timed_out.status is RunStatus.TIMED_OUT
    assert cancelled.status is RunStatus.CANCELLED


@pytest.mark.asyncio
async def test_runner_accepts_a_real_pytest_terminal_duration_annotation(tmp_path: Path) -> None:
    """Long runs retain pytest's terminal summary rather than becoming malformed."""

    run = await _runner(
        tmp_path,
        ProcessCapture(0, _pytest_summary(passed=23, elapsed="223.36s (0:03:43)"), ""),
    ).run("sample-suite", "build", asyncio.Event())

    assert run.status is RunStatus.PASSED
    assert run.results[0].detail == "23"


@pytest.mark.asyncio
async def test_runner_honors_cancellation_and_partial_hardware_and_scope_boundaries(
    tmp_path: Path,
) -> None:
    cancellation = asyncio.Event()
    adapter = FakeAdapter(ProcessCapture(0, _pytest_summary(), ""), wait_for_cancel=True)
    catalog = SuiteCatalog((_suite(partial=True),))
    runner = ControlledTestRunner(catalog, tmp_path, ArtifactStore(tmp_path / "artifacts"), adapter)
    task = asyncio.create_task(runner.run("sample-suite", "build", cancellation))
    await asyncio.sleep(0)
    cancellation.set()
    cancelled = await task

    assert cancelled.status is RunStatus.CANCELLED
    passed = await _runner(tmp_path, ProcessCapture(0, _pytest_summary(), ""), partial=True).run(
        "sample-suite", "build", asyncio.Event()
    )
    assert passed.status is RunStatus.PASSED and passed.suite.partial
    hardware = await _runner(tmp_path, ProcessCapture(0, _pytest_summary(), ""), hardware=True).run(
        "sample-suite", "build", asyncio.Event()
    )
    assert hardware.status is RunStatus.SKIPPED
    allowed_hardware = await _runner(
        tmp_path, ProcessCapture(0, _pytest_summary(), ""), hardware=True
    ).run("sample-suite", "build", asyncio.Event(), allow_hardware=True)
    assert allowed_hardware.status is RunStatus.PASSED
    escaped = await _runner(
        tmp_path, ProcessCapture(0, "1 passed", ""), working_directory=".."
    ).run("sample-suite", "build", asyncio.Event())
    assert escaped.status is RunStatus.REJECTED
    unknown = await runner.run("not a valid suite id", "build", asyncio.Event())
    assert unknown.status is RunStatus.REJECTED


@pytest.mark.asyncio
async def test_runner_parses_structured_individual_results(tmp_path: Path) -> None:
    runner = _runner(
        tmp_path,
        ProcessCapture(0, '{"results":[{"name":"case-a","status":"passed"}]}', ""),
        output_format=OutputFormat.STRUCTURED_JSON,
    )

    run = await runner.run("sample-suite", "build", asyncio.Event())

    assert run.status is RunStatus.PASSED
    assert run.results[0].name == "case-a"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario_id",
    (
        "calculator-workflow",
        "permission-pause",
        "tool-failure-retry",
        "cancellation",
        "verification-failure",
        "meeting-preparation",
        "multi-agent-comparison",
    ),
)
async def test_deterministic_workflow_scenarios(scenario_id: str) -> None:
    result = await DeterministicWorkflowEvaluator().evaluate(scenario_id)

    assert result.passed, result.summary


def test_regression_fixtures_preserve_known_fixed_cases() -> None:
    root = Path(__file__).parent / "fixtures" / "regressions"

    fixtures = RegressionFixtureStore(root).load()

    assert {fixture.fixture_id for fixture in fixtures} == {
        "calculator-workflow-200",
        "permission-pause-no-execution",
    }
    assert all(fixture.expected_status == "passed" for fixture in fixtures)


class FakeStartedProcess(StartedProcess):
    def __init__(self, shutdown: str = "terminated") -> None:
        self.shutdown = shutdown
        self.terminated = False

    @property
    def pid(self) -> int:
        return 42

    async def terminate(self, timeout_seconds: float) -> tuple[int | None, str]:
        del timeout_seconds
        self.terminated = True
        return 0, self.shutdown


class FakeStartupAdapter(StartupProcessAdapter):
    def __init__(self, process: FakeStartedProcess) -> None:
        self.process = process

    async def start(self, command: Command, working_directory: Path) -> StartedProcess:
        del command, working_directory
        return self.process


class FakeProbe(HealthProbe):
    def __init__(self, ready: bool) -> None:
        self._ready = ready

    async def ready(self, url: str) -> bool:
        del url
        return self._ready


@pytest.mark.asyncio
async def test_startup_smoke_uses_fake_local_process_and_clean_shutdown(tmp_path: Path) -> None:
    suite = Suite(
        "startup-smoke",
        Category.STARTUP,
        Command("trusted-python", ("-m", "uvicorn")),
        timeout_seconds=2,
    )
    process = FakeStartedProcess()
    tester = StartupSmokeTester(
        tmp_path,
        ArtifactStore(tmp_path / "artifacts"),
        FakeStartupAdapter(process),
        FakeProbe(True),
    )

    run = await tester.run(
        StartupSmokeDefinition(suite, "http://127.0.0.1:8765/health", ready_timeout_seconds=1),
        "build",
        asyncio.Event(),
    )

    assert run.status is RunStatus.PASSED
    assert process.terminated
    assert {item.name for item in run.results} == {
        "process_start",
        "health_ready",
        "clean_shutdown",
    }


@pytest.mark.asyncio
async def test_real_controlled_subprocess_runner_covers_pass_timeout_and_cancellation(
    tmp_path: Path,
) -> None:
    artifacts = ArtifactStore(tmp_path / "artifacts")
    (tmp_path / "test_runner_pass.py").write_text(
        "def test_runner_pass() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    passing = Suite(
        "real-pass",
        Category.UNIT,
        Command(sys.executable, ("-m", "pytest", "test_runner_pass.py")),
        timeout_seconds=2,
    )
    runner = ControlledTestRunner(
        SuiteCatalog((passing,)), tmp_path, artifacts, SubprocessTestAdapter()
    )
    passed = await runner.run("real-pass", "build", asyncio.Event())
    assert passed.status is RunStatus.PASSED

    slow = Suite(
        "real-timeout",
        Category.UNIT,
        Command(sys.executable, ("-c", "import time; time.sleep(2)")),
        timeout_seconds=0.01,
    )
    timeout = await ControlledTestRunner(
        SuiteCatalog((slow,)), tmp_path, artifacts, SubprocessTestAdapter()
    ).run("real-timeout", "build", asyncio.Event())
    assert timeout.status is RunStatus.TIMED_OUT

    cancellable = Suite(
        "real-cancel",
        Category.UNIT,
        Command(sys.executable, ("-c", "import time; time.sleep(2)")),
        timeout_seconds=2,
    )
    cancellation = asyncio.Event()
    running = asyncio.create_task(
        ControlledTestRunner(
            SuiteCatalog((cancellable,)), tmp_path, artifacts, SubprocessTestAdapter()
        ).run("real-cancel", "build", cancellation)
    )
    await asyncio.sleep(0.05)
    cancellation.set()
    cancelled = await running
    assert cancelled.status is RunStatus.CANCELLED


@pytest.mark.asyncio
async def test_real_runner_cancellation_wins_completion_race(tmp_path: Path) -> None:
    cancellation = asyncio.Event()
    cancellation.set()
    suite = Suite(
        "cancel-race",
        Category.UNIT,
        Command(sys.executable, ("-c", "print('completed')")),
        timeout_seconds=1,
    )

    run = await ControlledTestRunner(
        SuiteCatalog((suite,)), tmp_path, ArtifactStore(tmp_path / "artifacts")
    ).run("cancel-race", "build", cancellation)

    assert run.status is RunStatus.CANCELLED


@pytest.mark.asyncio
async def test_runner_cancellation_wins_same_tick_owned_process_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller cancellation is authoritative even if the child exits that loop turn."""

    entered = asyncio.Event()
    release = asyncio.Event()
    cancellation = asyncio.Event()

    class _RaceProcess:
        stdout = None
        stderr = None
        pid = 42

        def __init__(self) -> None:
            self.returncode: int | None = None

        async def wait(self) -> int:
            entered.set()
            await release.wait()
            self.returncode = 0
            return 0

        def close(self) -> None:
            return None

    class _OwnedJob:
        def active_process_count(self) -> int:
            return 0

        def terminate(self) -> None:
            return None

        async def wait_for_empty(self, timeout_seconds: float) -> bool:
            del timeout_seconds
            return True

        def close(self) -> None:
            return None

    process = _RaceProcess()
    job = _OwnedJob()

    def create_job(**kwargs: object) -> _OwnedJob:
        del kwargs
        return job

    async def launch(*args: object, **kwargs: object) -> _RaceProcess:
        del args, kwargs
        return process

    monkeypatch.setattr("jarvis.testing.runner.sys.platform", "win32")
    monkeypatch.setattr("jarvis.testing.runner.create_owned_windows_job", create_job)
    monkeypatch.setattr("jarvis.testing.runner.WindowsJobProcessLauncher.launch", launch)
    running = asyncio.create_task(
        SubprocessTestAdapter()._execute_owned(
            sys.executable,
            ("-c", "print('completed')"),
            tmp_path,
            {},
            10,
            cancellation,
        )
    )
    await entered.wait()
    # Both state changes occur before the event loop can adjudicate either
    # waiter, reproducing the completion/cancellation race without a sleep.
    release.set()
    cancellation.set()
    capture = await running
    adjudicated = await _runner(tmp_path, capture).run("sample-suite", "build", asyncio.Event())

    assert capture.exit_code == 0
    assert capture.cancelled
    assert adjudicated.status is RunStatus.CANCELLED


@pytest.mark.asyncio
async def test_optional_smoke_failure_and_concrete_local_adapters(tmp_path: Path) -> None:
    suite = Suite(
        "startup-smoke-failure",
        Category.STARTUP,
        Command("trusted-python", ("-m", "uvicorn")),
        timeout_seconds=2,
    )
    process = FakeStartedProcess("killed_after_timeout")
    failed = await StartupSmokeTester(
        tmp_path,
        ArtifactStore(tmp_path / "artifacts"),
        FakeStartupAdapter(process),
        FakeProbe(False),
    ).run(
        StartupSmokeDefinition(suite, "http://127.0.0.1:8766/health", ready_timeout_seconds=0.01),
        "build",
        asyncio.Event(),
    )
    assert failed.status is RunStatus.FAILED
    assert {item.code for item in failed.failure_evidence} == {
        "health_not_ready",
        "unclean_shutdown",
    }

    started = await SubprocessStartupAdapter().start(
        Command(sys.executable, ("-c", "import time; time.sleep(2)")), tmp_path
    )
    exit_code, shutdown = await started.terminate(1)
    assert exit_code is not None and shutdown == "terminated"
    assert not await LocalHttpHealthProbe().ready("http://127.0.0.1:65530/health")


def test_local_jarvis_smoke_definition_is_validated_and_localhost_only() -> None:
    definition = create_local_startup_smoke_definition(8765)

    assert definition.suite.category is Category.STARTUP
    assert definition.health_url == "http://127.0.0.1:8765/health"
    assert definition.suite.command.arguments[2] == "jarvis.api:app"
    with pytest.raises(ValueError):
        create_local_startup_smoke_definition(80)


def test_safe_environment_propagates_only_canonical_test_selector(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("JARVIS_ENVIRONMENT", "test")
    monkeypatch.setenv("API_KEY", "synthetic-secret")
    monkeypatch.setenv("JARVIS_UNTRUSTED", "do-not-pass")
    monkeypatch.setenv("PATH", "hostile-path")
    monkeypatch.setenv("SystemRoot", "hostile-root")
    if sys.platform == "win32":
        monkeypatch.setattr("jarvis.testing.runner._trusted_windows_root", lambda: r"C:\Windows")
    environment = SubprocessTestAdapter._safe_environment(temporary_directory=tmp_path)

    assert environment["JARVIS_ENVIRONMENT"] == "test"
    assert "API_KEY" not in environment
    assert "JARVIS_UNTRUSTED" not in environment
    assert "PATH" not in environment
    assert environment["TEMP"] == str(tmp_path.resolve())
    if sys.platform == "win32":
        assert environment["SYSTEMROOT"] == r"C:\Windows"
        assert environment["WINDIR"] == r"C:\Windows"

    monkeypatch.delenv("JARVIS_ENVIRONMENT")
    assert "JARVIS_ENVIRONMENT" not in SubprocessTestAdapter._safe_environment()

    for invalid_selector in ("TEST", "test ", "true", "1", "production"):
        monkeypatch.setenv("JARVIS_ENVIRONMENT", invalid_selector)
        assert "JARVIS_ENVIRONMENT" not in SubprocessTestAdapter._safe_environment()

    hardware = SubprocessTestAdapter._safe_environment(allow_hardware=True)
    assert hardware.get("JARVIS_WINDOWS_INTEGRATION") == "true"

    monkeypatch.setenv("JARVIS_CAMERA_INTEGRATION", "true")
    camera_hardware = SubprocessTestAdapter._safe_environment(allow_hardware=True)
    assert camera_hardware["JARVIS_CAMERA_INTEGRATION"] == "true"


@pytest.mark.asyncio
async def test_runner_low_level_evidence_helpers_remain_bounded_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Exercise defensive branches below the public controlled-runner contract."""

    output = _BoundedOutput()
    output.append(b"prefix")
    output.append(b"x" * 300_000)
    assert output.truncated
    assert output.total_bytes == 300_006
    assert "retained bounded prefix" in output.render()

    class _Reader:
        def __init__(self) -> None:
            self._chunks = iter((b"first", b"second", b""))

        async def read(self, limit: int) -> bytes:
            assert limit > 0
            return next(self._chunks)

    streamed = _BoundedOutput()
    await _pump_stream(_Reader(), streamed)  # type: ignore[arg-type]
    await _pump_stream(None, streamed)
    assert streamed.render() == "firstsecond"

    async def _stream_failure() -> None:
        raise RuntimeError("synthetic stream error")

    assert (
        await _drain_streams(asyncio.create_task(_stream_failure())) == "output_stream:RuntimeError"
    )

    gate = asyncio.Event()

    async def _pending_stream() -> None:
        await gate.wait()

    pending = asyncio.create_task(_pending_stream())

    async def _forced_timeout(awaitable: object, *, timeout: float) -> object:
        del timeout
        future = cast(asyncio.Future[object], awaitable)
        future.cancel()
        await asyncio.gather(future, return_exceptions=True)
        raise TimeoutError

    monkeypatch.setattr("jarvis.testing.runner.asyncio.wait_for", _forced_timeout)
    assert await _drain_streams(pending) == "output_drain_timeout"
    assert pending.cancelled()

    assert _merge_cleanup_errors("zeta;alpha", "alpha", None) == "alpha;zeta"
    assert _cap_artifact_text("x" * 100_000).count("artifact truncated") == 1
    assert _label("bounded.label-1") == "bounded.label-1"
    with pytest.raises(ValueError, match="bounded lowercase"):
        _label("../outside")

    assert _parse_results(OutputFormat.STRUCTURED_JSON, '{"results":[]}') == ()
    for malformed in (
        "{",
        "[]",
        '{"results":{}}',
        '{"results":[{"name":1,"status":"passed"}]}',
    ):
        assert _parse_results(OutputFormat.STRUCTURED_JSON, malformed) is None
    contradictory = await _runner(
        tmp_path,
        ProcessCapture(0, '{"results":[{"name":"case","status":"unknown"}]}', ""),
        output_format=OutputFormat.STRUCTURED_JSON,
    ).run("sample-suite", "build", asyncio.Event())
    assert contradictory.status is RunStatus.MALFORMED
    assert contradictory.failure_evidence[0].code == "contradictory_output"

    first = _suite()
    second = Suite(
        "another-suite",
        Category.UNIT,
        Command("trusted-python", ("-m", "pytest")),
        timeout_seconds=1,
    )
    assert [suite.suite_id for suite in SuiteCatalog((first, second)).all()] == [
        "another-suite",
        "sample-suite",
    ]
    with pytest.raises(ValueError, match="Duplicate"):
        SuiteCatalog((first, first))


def test_trusted_windows_root_uses_native_api_and_rejects_empty_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _GetWindowsDirectory:
        argtypes: object = None
        restype: object = None

        def __init__(self, value: str) -> None:
            self._value = value

        def __call__(self, buffer: object, length: int) -> int:
            assert length > 0
            buffer.value = self._value  # type: ignore[attr-defined]
            return len(self._value)

    class _Kernel32:
        def __init__(self, value: str) -> None:
            self.GetWindowsDirectoryW = _GetWindowsDirectory(value)

    monkeypatch.setattr("jarvis.testing.runner.sys.platform", "win32")
    monkeypatch.setattr(
        "jarvis.testing.runner.ctypes.WinDLL", lambda *args, **kwargs: _Kernel32(r"C:\Windows")
    )
    assert _trusted_windows_root() == r"C:\Windows"

    monkeypatch.setattr(
        "jarvis.testing.runner.ctypes.WinDLL", lambda *args, **kwargs: _Kernel32("")
    )
    with pytest.raises(OSError, match="GetWindowsDirectoryW"):
        _trusted_windows_root()


def test_windows_controlled_temp_root_refuses_path_with_no_nested_path_headroom(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested = tmp_path / ("nested-" + "x" * 100)
    nested.mkdir()
    monkeypatch.setattr("jarvis.testing.runner.sys.platform", "win32")

    with pytest.raises(OSError, match="temporary root is too deep"):
        _owned_test_temp_root(nested)


@pytest.mark.asyncio
async def test_real_runner_preserves_launch_error_and_bounded_reaping(tmp_path: Path) -> None:
    missing = Suite(
        "missing-executable",
        Category.UNIT,
        Command(str(tmp_path / "missing-python.exe"), ()),
        timeout_seconds=1,
    )
    adapter = SubprocessTestAdapter()
    capture = await adapter.execute(missing.command, tmp_path, 1, asyncio.Event())
    assert capture.launch_error == "ProcessIdentityError"

    (tmp_path / "test_noisy_runner.py").write_text(
        "def test_noisy_runner() -> None:\n    print('x' * 2_000_000)\n",
        encoding="utf-8",
    )
    noisy = Suite(
        "noisy-runner",
        Category.UNIT,
        Command(sys.executable, ("-m", "pytest", "-s", "test_noisy_runner.py")),
        timeout_seconds=10,
    )
    run = await ControlledTestRunner(
        SuiteCatalog((noisy,)), tmp_path, ArtifactStore(tmp_path / "artifacts")
    ).run("noisy-runner", "build", asyncio.Event())

    assert run.status is RunStatus.PASSED
    assert max(item.size_bytes for item in run.artifacts) <= 65_536


@pytest.mark.asyncio
async def test_runner_reports_owned_cleanup_failure_before_nominal_success() -> None:
    class _CompletedProcess:
        returncode = 0

        async def wait(self) -> int:
            return 0

    class _FailingJob:
        def __init__(self) -> None:
            self.waits: list[float] = []

        def active_process_count(self) -> int:
            return 1

        def terminate(self) -> None:
            raise OSError("synthetic terminate failure")

        async def wait_for_empty(self, timeout_seconds: float) -> bool:
            self.waits.append(timeout_seconds)
            return False

        def close(self) -> None:
            raise OSError("synthetic close failure")

    process = _CompletedProcess()
    wait_task = asyncio.create_task(process.wait())
    job = _FailingJob()
    error = await SubprocessTestAdapter._cleanup_process(process, wait_task, job)

    assert error == "job_close:OSError;job_not_empty;job_terminate:OSError"
    assert job.waits == [0.25, 5.0]


@pytest.mark.asyncio
async def test_runner_job_accounting_controls_cleanup_and_fails_closed() -> None:
    class _CompletedProcess:
        returncode = 0

        async def wait(self) -> int:
            return 0

    class _AccountingJob:
        def __init__(self, counts: list[int] | Exception) -> None:
            self._counts = counts
            self.terminated = 0
            self.closed = 0

        def active_process_count(self) -> int:
            if isinstance(self._counts, Exception):
                raise self._counts
            if len(self._counts) > 1:
                return self._counts.pop(0)
            return self._counts[0]

        def terminate(self) -> None:
            self.terminated += 1
            if isinstance(self._counts, list):
                self._counts[:] = [0]

        async def wait_for_empty(self, timeout_seconds: float) -> bool:
            del timeout_seconds
            return self.active_process_count() == 0

        def close(self) -> None:
            self.closed += 1

    async def cleanup(job: _AccountingJob) -> str | None:
        process = _CompletedProcess()
        return await SubprocessTestAdapter._cleanup_process(
            process,
            asyncio.create_task(process.wait()),
            job,
        )

    empty = _AccountingJob([0])
    assert await cleanup(empty) is None
    assert empty.terminated == 0
    assert empty.closed == 1

    active = _AccountingJob([1])
    assert await cleanup(active) is None
    assert active.terminated == 1
    assert active.closed == 1

    stuck = _AccountingJob([1])
    stuck.terminate = lambda: None  # type: ignore[method-assign]
    assert await cleanup(stuck) == "job_not_empty"

    query_failure = _AccountingJob(OSError("synthetic accounting failure"))
    assert await cleanup(query_failure) == "job_accounting:OSError"


@pytest.mark.asyncio
async def test_runner_cleanup_and_finalization_error_paths_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _CompletedProcess:
        pid = 123
        returncode = None

        async def wait(self) -> int:
            return 0

        def kill(self) -> None:
            raise OSError("synthetic process cleanup failure")

    process = _CompletedProcess()
    monkeypatch.setattr("jarvis.testing.runner.sys.platform", "win32")
    error = await SubprocessTestAdapter._cleanup_process(
        process,
        asyncio.create_task(process.wait()),
        None,
    )
    assert error == "process_cleanup:OSError"

    class _WaitFailure:
        pid = 456
        returncode = 0

        async def wait(self) -> int:
            raise RuntimeError("synthetic wait failure")

    failed_wait = _WaitFailure()
    error = await SubprocessTestAdapter._cleanup_process(
        failed_wait,
        asyncio.create_task(failed_wait.wait()),
        None,
    )
    assert error == "process_wait:RuntimeError"

    class _PosixProcess:
        pid = 789
        returncode = None

        async def wait(self) -> int:
            return 0

    monkeypatch.setattr("jarvis.testing.runner.sys.platform", "linux")
    monkeypatch.setattr("jarvis.testing.runner.signal.SIGKILL", 9, raising=False)
    monkeypatch.setattr(
        "jarvis.testing.runner.os.killpg",
        lambda process_id, signal_value: (_ for _ in ()).throw(OSError("synthetic group failure")),
        raising=False,
    )
    posix = _PosixProcess()
    error = await SubprocessTestAdapter._cleanup_process(
        posix,
        asyncio.create_task(posix.wait()),
        None,
    )
    assert error == "process_group_cleanup:OSError"

    wait_gate = asyncio.Event()
    pending_wait = asyncio.create_task(wait_gate.wait())

    async def _forced_timeout(awaitable: object, *, timeout: float) -> object:
        del timeout
        future = cast(asyncio.Future[object], awaitable)
        future.cancel()
        await asyncio.gather(future, return_exceptions=True)
        raise TimeoutError

    monkeypatch.setattr("jarvis.testing.runner.asyncio.wait_for", _forced_timeout)
    error = await SubprocessTestAdapter._cleanup_process(_WaitFailure(), pending_wait, None)
    assert error == "process_group_cleanup:OSError;process_wait_timeout"

    class _FinalizeFailure:
        def close(self) -> None:
            raise RuntimeError("synthetic finalize failure")

    class _FinalizeCleanupError:
        cleanup_error = RuntimeError("synthetic native cleanup failure")

        def close(self) -> None:
            return None

    assert await SubprocessTestAdapter._finalize_process(object()) is None
    assert (
        await SubprocessTestAdapter._finalize_process(_FinalizeFailure())
        == "process_finalize:RuntimeError"
    )
    assert (
        await SubprocessTestAdapter._finalize_process(_FinalizeCleanupError())
        == "process_finalize:RuntimeError"
    )


@pytest.mark.asyncio
async def test_windows_runner_fails_closed_when_native_job_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows Job containment is Windows-only")
    from jarvis.windows_sandbox import WindowsNativeProcessError

    def unavailable(**kwargs: object) -> object:
        del kwargs
        raise WindowsNativeProcessError("synthetic unavailable Job Object")

    monkeypatch.setattr("jarvis.testing.runner.create_owned_windows_job", unavailable)
    command = Command(sys.executable, ("-c", "print('must not launch')"))
    capture = await SubprocessTestAdapter().execute(command, tmp_path, 1, asyncio.Event())

    assert capture.launch_error == "WindowsNativeProcessError"


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows process-tree contract")
async def test_windows_timeout_reaps_descendant_holding_output_pipe(tmp_path: Path) -> None:
    suite = Suite(
        "windows-tree-timeout",
        Category.UNIT,
        Command(
            sys.executable,
            (
                "-c",
                "import subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'], "
                "close_fds=False); "
                "time.sleep(30)",
            ),
        ),
        timeout_seconds=0.1,
    )
    started = time.monotonic()
    run = await ControlledTestRunner(
        SuiteCatalog((suite,)), tmp_path, ArtifactStore(tmp_path / "artifacts")
    ).run("windows-tree-timeout", "build", asyncio.Event())

    assert run.status is RunStatus.TIMED_OUT
    assert time.monotonic() - started < 10


def _windows_process_is_running(process_id: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint, ctypes.c_bool, ctypes.c_uint]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
    kernel32.GetExitCodeProcess.restype = ctypes.c_bool
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_bool
    handle = kernel32.OpenProcess(0x1000, False, process_id)
    if not handle:
        return False
    try:
        exit_code = ctypes.c_uint()
        return bool(
            kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)) and exit_code.value == 259
        )
    finally:
        kernel32.CloseHandle(handle)


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job lifecycle contract")
async def test_windows_root_exit_reaps_owned_descendant_retaining_pipe(tmp_path: Path) -> None:
    child_pid = tmp_path / "owned-child.pid"
    (tmp_path / "test_root_exit_child.py").write_text(
        "from pathlib import Path\n"
        "import subprocess\n"
        "import sys\n\n"
        "def test_root_exit_child() -> None:\n"
        "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
        "close_fds=False)\n"
        f"    Path({str(child_pid)!r}).write_text(str(child.pid), encoding='utf-8')\n"
        "    assert True\n",
        encoding="utf-8",
    )
    suite = Suite(
        "windows-root-exit-tree",
        Category.UNIT,
        Command(sys.executable, ("-m", "pytest", "test_root_exit_child.py")),
        timeout_seconds=5,
    )
    started = time.monotonic()
    run = await ControlledTestRunner(
        SuiteCatalog((suite,)), tmp_path, ArtifactStore(tmp_path / "artifacts")
    ).run("windows-root-exit-tree", "build", asyncio.Event())

    assert run.status is RunStatus.PASSED
    assert time.monotonic() - started < 10
    assert child_pid.is_file()
    assert not _windows_process_is_running(int(child_pid.read_text(encoding="utf-8")))


async def _wait_for_file(path: Path, *, timeout_seconds: float = 5.0) -> None:
    """Wait for a test-owned readiness file, not an arbitrary scheduler delay."""

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.is_file():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"Timed out waiting for owned test readiness file: {path.name}")


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job accounting contract")
async def test_windows_native_job_accounting_confirms_empty_normal_exit_stress(
    tmp_path: Path,
) -> None:
    """Exercise the real Job accounting API, not a synthetic Job double."""

    from jarvis.sandbox import create_owned_windows_job
    from jarvis.windows_sandbox import WindowsJobProcessLauncher

    for _iteration in range(25):
        job = create_owned_windows_job(max_processes=4, max_memory_bytes=128 * 1024 * 1024)
        process = None
        try:
            process = await WindowsJobProcessLauncher.launch(
                sys.executable,
                ("-c", "pass"),
                cwd=str(tmp_path),
                environment=SubprocessTestAdapter._safe_environment(temporary_directory=tmp_path),
                limit=8_192,
                job=job,
            )
            assert await process.wait() == 0
            assert await job.wait_for_empty(2.0)
            assert job.active_process_count() == 0
        finally:
            if process is not None:
                process.close()
            job.close()


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job accounting contract")
async def test_windows_native_job_accounting_reaps_exact_descendant(tmp_path: Path) -> None:
    """A real Job owns and cleans its child tree without ambient process kills."""

    from jarvis.sandbox import create_owned_windows_job
    from jarvis.windows_sandbox import WindowsJobProcessLauncher

    child_pid = tmp_path / "native-job-child.pid"
    job = create_owned_windows_job(max_processes=4, max_memory_bytes=128 * 1024 * 1024)
    process = None
    try:
        child_program = "import time; time.sleep(30)"
        root_program = (
            "from pathlib import Path; import subprocess, sys, time; "
            "child = subprocess.Popen("
            f"[sys.executable, '-c', {child_program!r}], close_fds=False); "
            f"Path({str(child_pid)!r}).write_text(str(child.pid), encoding='utf-8'); "
            "time.sleep(30)"
        )
        process = await WindowsJobProcessLauncher.launch(
            sys.executable,
            ("-c", root_program),
            cwd=str(tmp_path),
            environment=SubprocessTestAdapter._safe_environment(temporary_directory=tmp_path),
            limit=8_192,
            job=job,
        )
        await _wait_for_file(child_pid)
        assert job.active_process_count() > 0
        job.terminate()
        assert await job.wait_for_empty(5.0)
        assert job.active_process_count() == 0
        assert not _windows_process_is_running(int(child_pid.read_text(encoding="utf-8")))
        assert await process.wait() != 0
    finally:
        if process is not None:
            process.close()
        job.close()


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job accounting contract")
async def test_windows_controlled_runner_normal_exit_has_no_cleanup_error(tmp_path: Path) -> None:
    """Direct regression for Candidate 12's false ``process_cleanup_failed``."""

    capture = await SubprocessTestAdapter().execute(
        Command(sys.executable, ("-c", "pass")),
        tmp_path,
        5.0,
        asyncio.Event(),
    )

    assert capture.exit_code == 0
    assert not capture.timed_out
    assert not capture.cancelled
    assert capture.cleanup_error is None


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job lifecycle contract")
async def test_windows_cancellation_reaps_owned_descendant_only(tmp_path: Path) -> None:
    child_pid = tmp_path / "cancelled-child.pid"
    (tmp_path / "test_cancelled_child.py").write_text(
        "from pathlib import Path\n"
        "import subprocess\n"
        "import sys\n"
        "import time\n\n"
        "def test_cancelled_child() -> None:\n"
        "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
        "close_fds=False)\n"
        f"    Path({str(child_pid)!r}).write_text(str(child.pid), encoding='utf-8')\n"
        "    time.sleep(30)\n",
        encoding="utf-8",
    )
    suite = Suite(
        "windows-cancel-tree",
        Category.UNIT,
        Command(sys.executable, ("-m", "pytest", "test_cancelled_child.py")),
        timeout_seconds=10,
    )
    cancellation = asyncio.Event()
    running = asyncio.create_task(
        ControlledTestRunner(
            SuiteCatalog((suite,)), tmp_path, ArtifactStore(tmp_path / "artifacts")
        ).run("windows-cancel-tree", "build", cancellation)
    )
    await _wait_for_file(child_pid)
    cancellation.set()
    run = await running

    assert run.status is RunStatus.CANCELLED
    assert not _windows_process_is_running(int(child_pid.read_text(encoding="utf-8")))


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job lifecycle contract")
async def test_windows_runner_never_targets_an_unrelated_owned_process(tmp_path: Path) -> None:
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        (tmp_path / "test_unrelated_runner.py").write_text(
            "def test_unrelated_runner() -> None:\n    assert True\n",
            encoding="utf-8",
        )
        suite = Suite(
            "windows-unrelated-process",
            Category.UNIT,
            Command(sys.executable, ("-m", "pytest", "test_unrelated_runner.py")),
            timeout_seconds=5,
        )
        run = await ControlledTestRunner(
            SuiteCatalog((suite,)), tmp_path, ArtifactStore(tmp_path / "artifacts")
        ).run("windows-unrelated-process", "build", asyncio.Event())

        assert run.status is RunStatus.PASSED
        assert _windows_process_is_running(unrelated.pid)
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_health_payload_ready_accepts_jarvis_and_generic_contracts() -> None:
    assert _health_payload_ready({"ready": True})
    assert _health_payload_ready({"status": "ok", "startup_complete": True})
    assert not _health_payload_ready({"status": "starting", "startup_complete": False})
    assert not _health_payload_ready(["not", "an", "object"])
