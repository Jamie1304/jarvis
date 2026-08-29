"""System self-test runner, evidence, workflow, regression, and smoke coverage."""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import Any, cast

import pytest
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
        ProcessCapture(0, "2 passed, 1 skipped\ngho_abcdefghijklmnop", ""),
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
    runner = _runner(tmp_path, ProcessCapture(1, "1 failed, 3 passed", "assertion failed"))

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
async def test_runner_honors_cancellation_and_partial_hardware_and_scope_boundaries(
    tmp_path: Path,
) -> None:
    cancellation = asyncio.Event()
    adapter = FakeAdapter(ProcessCapture(0, "1 passed", ""), wait_for_cancel=True)
    catalog = SuiteCatalog((_suite(partial=True),))
    runner = ControlledTestRunner(catalog, tmp_path, ArtifactStore(tmp_path / "artifacts"), adapter)
    task = asyncio.create_task(runner.run("sample-suite", "build", cancellation))
    await asyncio.sleep(0)
    cancellation.set()
    cancelled = await task

    assert cancelled.status is RunStatus.CANCELLED
    passed = await _runner(tmp_path, ProcessCapture(0, "1 passed", ""), partial=True).run(
        "sample-suite", "build", asyncio.Event()
    )
    assert passed.status is RunStatus.PASSED and passed.suite.partial
    hardware = await _runner(tmp_path, ProcessCapture(0, "1 passed", ""), hardware=True).run(
        "sample-suite", "build", asyncio.Event()
    )
    assert hardware.status is RunStatus.SKIPPED
    allowed_hardware = await _runner(
        tmp_path, ProcessCapture(0, "1 passed", ""), hardware=True
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
    passing = Suite(
        "real-pass",
        Category.UNIT,
        Command(sys.executable, ("-c", "print('1 passed')")),
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
) -> None:
    monkeypatch.setenv("JARVIS_ENVIRONMENT", "test")
    monkeypatch.setenv("API_KEY", "synthetic-secret")
    monkeypatch.setenv("JARVIS_UNTRUSTED", "do-not-pass")
    environment = SubprocessTestAdapter._safe_environment()

    assert environment["JARVIS_ENVIRONMENT"] == "test"
    assert "API_KEY" not in environment
    assert "JARVIS_UNTRUSTED" not in environment

    monkeypatch.delenv("JARVIS_ENVIRONMENT")
    assert "JARVIS_ENVIRONMENT" not in SubprocessTestAdapter._safe_environment()

    monkeypatch.setenv("JARVIS_ENVIRONMENT", "production")
    assert "JARVIS_ENVIRONMENT" not in SubprocessTestAdapter._safe_environment()

    hardware = SubprocessTestAdapter._safe_environment(allow_hardware=True)
    assert hardware.get("JARVIS_WINDOWS_INTEGRATION") == "true"


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
    assert capture.launch_error == "FileNotFoundError"

    communication = cast(
        "asyncio.Task[tuple[bytes, bytes]]", asyncio.create_task(asyncio.sleep(30))
    )
    monkeypatch = pytest.MonkeyPatch()
    try:

        async def raise_timeout(*args: object, **kwargs: object) -> object:
            del args, kwargs
            raise TimeoutError

        monkeypatch.setattr("jarvis.testing.runner.asyncio.wait_for", raise_timeout)

        class Process:
            returncode = 0

        assert await SubprocessTestAdapter._terminate(cast(Any, Process()), communication) == (
            b"",
            b"",
        )
        assert communication.done()
    finally:
        monkeypatch.undo()


@pytest.mark.asyncio
async def test_windows_tree_cleanup_targets_only_owned_pid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del tmp_path
    calls: list[tuple[str, ...]] = []

    class Killer:
        async def wait(self) -> int:
            return 0

        def kill(self) -> None:
            calls.append(("killer-kill",))

    async def create_killer(*args: str, **kwargs: object) -> Killer:
        del kwargs
        calls.append(args)
        return Killer()

    class Process:
        pid = 32123
        returncode = None

        def kill(self) -> None:
            calls.append(("process-kill",))

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr("jarvis.testing.runner.asyncio.create_subprocess_exec", create_killer)
        monkeypatch.setenv("SystemRoot", r"C:\Windows")
        await SubprocessTestAdapter._terminate_windows_tree(cast(Any, Process()))
    finally:
        monkeypatch.undo()

    assert calls == [
        (r"C:\Windows\System32\taskkill.exe", "/PID", "32123", "/T", "/F"),
    ]


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
                "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
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


def test_health_payload_ready_accepts_jarvis_and_generic_contracts() -> None:
    assert _health_payload_ready({"ready": True})
    assert _health_payload_ready({"status": "ok", "startup_complete": True})
    assert not _health_payload_ready({"status": "starting", "startup_complete": False})
    assert not _health_payload_ready(["not", "an", "object"])
