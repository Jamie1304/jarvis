"""Controlled no-shell test execution with redacted evidence artifacts."""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import hashlib
import json
import os
import re
import signal
import sys
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from jarvis.computer.process import ProcessIdentityError, resolve_trusted_executable
from jarvis.sandbox import create_owned_windows_job
from jarvis.testing.models import (
    FailureEvidence,
    IndividualTestResult,
    IndividualTestStatus,
    SuiteOutputFormat,
    TestArtifact,
    TestCategory,
    TestCommand,
    TestEnvironment,
    TestRun,
    TestRunStatus,
    TestSuite,
)
from jarvis.windows_sandbox import WindowsJobProcessLauncher, WindowsNativeProcessError

_MAX_OUTPUT_CHARACTERS = 65_536
_MAX_OUTPUT_BYTES = _MAX_OUTPUT_CHARACTERS * 4
_MAX_OUTPUT_PREFIX_BYTES = 8_192
_MAX_OUTPUT_TAIL_BYTES = _MAX_OUTPUT_BYTES - _MAX_OUTPUT_PREFIX_BYTES
_STREAM_CHUNK_BYTES = 8_192
_WINDOWS_SAFE_TEMP_ROOT_MAX_CHARACTERS = 96
_TEST_TEMP_PREFIX = "j-"
_SECRET = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)"
    r"\s*[:=]\s*(['\"]?)[^\s'\"]+\1"
)
_TOKEN = re.compile(r"\b(?:gh[oprsu][_-]|sk-)[A-Za-z0-9_-]{12,}\b")
_PYTEST_COUNT = re.compile(r"(?P<count>\d+) (?P<status>passed|failed|skipped)")
_PYTEST_FINAL_SUMMARY = re.compile(
    r"=+\s+(?P<summary>(?:\d+ (?:passed|failed|skipped)(?:,\s*)?)+)\s+"
    # Pytest adds a human-friendly elapsed form for sufficiently long runs,
    # e.g. ``23 passed in 223.36s (0:03:43)``.  It remains part of the
    # terminal framework-generated summary, not a test-body assertion.
    r"in\s+\d+(?:\.\d+)?s(?:\s+\(\d+(?::\d+){1,2}\))?\s+=+"
)
_PYTEST_SESSION_START = re.compile(r"=+\s+test session starts\s+=+")


@dataclass(frozen=True, slots=True)
class ProcessCapture:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    cancelled: bool = False
    launch_error: str | None = None
    cleanup_error: str | None = None
    output_truncated: bool = False


@dataclass(slots=True)
class _BoundedOutput:
    """Retain bounded context from both ends while continuously draining a child."""

    prefix: bytearray = field(default_factory=bytearray)
    tail: bytearray = field(default_factory=bytearray)
    total_bytes: int = 0
    truncated: bool = False

    def append(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.total_bytes += len(chunk)
        prefix_remaining = _MAX_OUTPUT_PREFIX_BYTES - len(self.prefix)
        if prefix_remaining > 0:
            self.prefix.extend(chunk[:prefix_remaining])
            chunk = chunk[prefix_remaining:]
        excess = len(self.tail) + len(chunk) - _MAX_OUTPUT_TAIL_BYTES
        if excess > 0:
            del self.tail[:excess]
        self.tail.extend(chunk)
        self.truncated = self.total_bytes > _MAX_OUTPUT_BYTES

    def render(self) -> str:
        if self.truncated:
            return (
                _decode(bytes(self.prefix))
                + "\n[output truncated; retained bounded prefix and final tail]\n"
                + _decode(bytes(self.tail))
            )
        return _decode(bytes(self.prefix) + bytes(self.tail))


class TestProcessAdapter(ABC):
    """Subprocess boundary; adapters receive only a trusted catalog command."""

    @abstractmethod
    async def execute(
        self,
        command: TestCommand,
        working_directory: Path,
        timeout_seconds: float,
        cancellation: asyncio.Event,
        *,
        allow_hardware: bool = False,
    ) -> ProcessCapture:
        """Run one explicit executable/argv command without a shell."""


class SubprocessTestAdapter(TestProcessAdapter):
    """Run only catalogued test commands with bounded owned-process evidence."""

    _WINDOWS_MAX_PROCESSES = 32
    _WINDOWS_MAX_MEMORY_BYTES = 1_024 * 1024 * 1024

    async def execute(
        self,
        command: TestCommand,
        working_directory: Path,
        timeout_seconds: float,
        cancellation: asyncio.Event,
        *,
        allow_hardware: bool = False,
    ) -> ProcessCapture:
        try:
            executable = resolve_trusted_executable(command.executable)
        except (OSError, ProcessIdentityError, TypeError):
            return ProcessCapture(None, "", "", launch_error="ProcessIdentityError")
        try:
            # Pytest derives multiple nested directories from TEMP/TMP.  Keep
            # the trusted per-run root compact enough for the production
            # composition acceptance fixture to remain below Windows' legacy
            # path boundary; an unsafe host temp root fails closed instead of
            # producing a misleading test failure later in the child.
            with tempfile.TemporaryDirectory(prefix=_TEST_TEMP_PREFIX) as temporary:
                environment = self._safe_environment(
                    allow_hardware=allow_hardware,
                    temporary_directory=_owned_test_temp_root(Path(temporary)),
                )
                return await self._execute_owned(
                    str(executable),
                    command.arguments,
                    working_directory,
                    environment,
                    timeout_seconds,
                    cancellation,
                )
        except (OSError, WindowsNativeProcessError) as error:
            return ProcessCapture(None, "", "", launch_error=type(error).__name__)

    async def _execute_owned(
        self,
        executable: str,
        arguments: tuple[str, ...],
        working_directory: Path,
        environment: dict[str, str],
        timeout_seconds: float,
        cancellation: asyncio.Event,
    ) -> ProcessCapture:
        job: Any | None = None
        try:
            if sys.platform == "win32":
                job = create_owned_windows_job(
                    max_processes=self._WINDOWS_MAX_PROCESSES,
                    max_memory_bytes=self._WINDOWS_MAX_MEMORY_BYTES,
                )
                process: Any = await WindowsJobProcessLauncher.launch(
                    executable,
                    arguments,
                    cwd=str(working_directory),
                    environment=environment,
                    limit=_STREAM_CHUNK_BYTES,
                    job=job,
                )
            else:
                process = await asyncio.create_subprocess_exec(
                    executable,
                    *arguments,
                    cwd=working_directory,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=environment,
                    start_new_session=True,
                )
        except Exception:
            if job is not None:
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(job.close)
            raise

        stdout = _BoundedOutput()
        stderr = _BoundedOutput()
        stdout_task = asyncio.create_task(_pump_stream(getattr(process, "stdout", None), stdout))
        stderr_task = asyncio.create_task(_pump_stream(getattr(process, "stderr", None), stderr))
        wait_task = asyncio.create_task(process.wait())
        cancellation_wait = asyncio.create_task(cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {wait_task, cancellation_wait},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            # A caller's cancellation wins an exact race with normal process
            # completion.  The terminal record therefore never claims a pass
            # after the caller has withdrawn its request.
            cancelled = cancellation.is_set() or cancellation_wait in done
            timed_out = not done
            cleanup_error = await self._cleanup_process(
                process,
                wait_task,
                job,
            )
            stream_error = await _drain_streams(stdout_task, stderr_task)
            finalize_error = await self._finalize_process(process)
            cleanup_error = _merge_cleanup_errors(cleanup_error, stream_error, finalize_error)
            return ProcessCapture(
                getattr(process, "returncode", None),
                stdout.render(),
                stderr.render(),
                timed_out=timed_out,
                cancelled=cancelled,
                cleanup_error=cleanup_error,
                output_truncated=stdout.truncated or stderr.truncated,
            )
        except asyncio.CancelledError:
            await self._cleanup_process(process, wait_task, job)
            await _drain_streams(stdout_task, stderr_task)
            await self._finalize_process(process)
            raise
        finally:
            if not cancellation_wait.done():
                cancellation_wait.cancel()
            await asyncio.gather(cancellation_wait, return_exceptions=True)

    @staticmethod
    async def _cleanup_process(
        process: Any,
        wait_task: asyncio.Task[int],
        job: Any | None,
    ) -> str | None:
        errors: list[str] = []
        if job is not None:
            try:
                # A successful root exit is insufficient evidence that an
                # owned descendant has gone away. Terminate the exact Job and
                # wait for it to empty before a nominal run is adjudicated.
                await asyncio.to_thread(job.terminate)
            except Exception as error:
                errors.append(f"job_terminate:{type(error).__name__}")
            wait_for_empty = getattr(job, "wait_for_empty", None)
            if callable(wait_for_empty):
                try:
                    if not await wait_for_empty(5.0):
                        errors.append("job_not_empty")
                except Exception as error:
                    errors.append(f"job_wait_empty:{type(error).__name__}")
            try:
                # Kill-on-close remains the final backstop if a process was
                # created during cleanup or native termination raced a child.
                await asyncio.to_thread(job.close)
            except Exception as error:
                errors.append(f"job_close:{type(error).__name__}")
        elif sys.platform != "win32":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as error:
                errors.append(f"process_group_cleanup:{type(error).__name__}")
        elif getattr(process, "returncode", None) is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except OSError as error:
                errors.append(f"process_cleanup:{type(error).__name__}")
        try:
            await asyncio.wait_for(asyncio.shield(wait_task), timeout=5.0)
        except TimeoutError:
            errors.append("process_wait_timeout")
        except Exception as error:
            errors.append(f"process_wait:{type(error).__name__}")
        return ";".join(sorted(set(errors))) or None

    @staticmethod
    async def _finalize_process(process: Any) -> str | None:
        """Close native stream transports after their bounded readers reach EOF."""

        close = getattr(process, "close", None)
        if not callable(close):
            return None
        try:
            close()
            # Proactor transports close asynchronously; give the owning loop
            # one turn so they do not leak into interpreter finalization.
            await asyncio.sleep(0)
        except Exception as error:
            return f"process_finalize:{type(error).__name__}"
        cleanup_error = getattr(process, "cleanup_error", None)
        if cleanup_error is not None:
            return f"process_finalize:{type(cleanup_error).__name__}"
        return None

    @staticmethod
    def _safe_environment(
        *,
        allow_hardware: bool = False,
        temporary_directory: Path | None = None,
    ) -> dict[str, str]:
        """Keep only exact bootstrap values; tests never receive user credentials."""

        values = {"PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        if sys.platform == "win32":
            root = _trusted_windows_root()
            values.update({"SYSTEMROOT": root, "WINDIR": root, "SYSTEMDRIVE": Path(root).drive})
        if temporary_directory is not None:
            temporary = temporary_directory.resolve(strict=True)
            values.update({"TEMP": str(temporary), "TMP": str(temporary)})
        # Test mode is an explicit, narrowly accepted selector.  Arbitrary
        # JARVIS_* values remain excluded from the sanitized child process.
        if os.environ.get("JARVIS_ENVIRONMENT") == "test":
            values["JARVIS_ENVIRONMENT"] = "test"
        if allow_hardware:
            values["JARVIS_WINDOWS_INTEGRATION"] = "true"
            if os.environ.get("JARVIS_CAMERA_INTEGRATION") == "true":
                values["JARVIS_CAMERA_INTEGRATION"] = "true"
        return values


async def _pump_stream(reader: asyncio.StreamReader | None, output: _BoundedOutput) -> None:
    """Drain output from process start so an owned child cannot block on pipes."""

    if reader is None:
        return
    while chunk := await reader.read(_STREAM_CHUNK_BYTES):
        output.append(chunk)


async def _drain_streams(*tasks: asyncio.Task[None]) -> str | None:
    """Finish bounded reader tasks without allowing a retained pipe to hang a run."""

    try:
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True), timeout=5.0
        )
    except TimeoutError:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        return "output_drain_timeout"
    errors = sorted(
        {
            f"output_stream:{type(result).__name__}"
            for result in results
            if isinstance(result, BaseException)
        }
    )
    return ";".join(errors) or None


def _merge_cleanup_errors(*values: str | None) -> str | None:
    parts = sorted({item for value in values if value for item in value.split(";")})
    return ";".join(parts) or None


def _trusted_windows_root() -> str:
    """Read Windows' own directory through the native API, not mutable PATH/env."""

    if sys.platform != "win32":
        raise OSError("Windows system root is unavailable")
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.GetWindowsDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    kernel32.GetWindowsDirectoryW.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32_768)
    length = kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer) or not buffer.value:
        raise OSError(ctypes.get_last_error(), "GetWindowsDirectoryW failed")
    return buffer.value


def _owned_test_temp_root(path: Path) -> Path:
    """Return a compact, owned temporary root suitable for nested test paths."""

    resolved = path.resolve(strict=True)
    if sys.platform == "win32" and len(str(resolved)) > _WINDOWS_SAFE_TEMP_ROOT_MAX_CHARACTERS:
        raise OSError("Controlled test temporary root is too deep on Windows")
    return resolved


class TestSuiteCatalog:
    """Explicit trusted test-suite catalog; unknown suites fail closed."""

    def __init__(self, suites: tuple[TestSuite, ...]) -> None:
        self._suites = {suite.suite_id: suite for suite in suites}
        if len(self._suites) != len(suites):
            raise ValueError("Duplicate test suite IDs are not permitted")

    def get(self, suite_id: str) -> TestSuite | None:
        return self._suites.get(suite_id)

    def all(self) -> tuple[TestSuite, ...]:
        return tuple(sorted(self._suites.values(), key=lambda suite: suite.suite_id))


class TestArtifactStore:
    """Stores capped, redacted logs below one application-owned artifact root."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    def write(self, run_id: UUID, kind: str, content: str) -> TestArtifact:
        safe_kind = _label(kind)
        directory = self._root / str(run_id)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{safe_kind}.log"
        text = _cap_artifact_text(_redact(content))
        path.write_text(text, encoding="utf-8", newline="\n")
        data = path.read_bytes()
        return TestArtifact(
            artifact_id=f"{run_id}:{safe_kind}",
            kind=safe_kind,
            relative_path=path.relative_to(self._root).as_posix(),
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
        )


class ControlledTestRunner:
    """Execute only catalogued non-hardware suites through a constrained adapter."""

    def __init__(
        self,
        catalog: TestSuiteCatalog,
        project_root: Path,
        artifacts: TestArtifactStore,
        adapter: TestProcessAdapter | None = None,
    ) -> None:
        self._catalog = catalog
        self._project_root = project_root.resolve()
        self._artifacts = artifacts
        self._adapter = adapter or SubprocessTestAdapter()

    async def run(
        self,
        suite_id: str,
        revision: str,
        cancellation: asyncio.Event,
        *,
        allow_hardware: bool = False,
    ) -> TestRun:
        suite = self._catalog.get(suite_id)
        if suite is None:
            return self._rejected_run(suite_id, revision, "unknown_suite")
        if suite.hardware_dependent and not allow_hardware:
            return self._skipped_run(suite, revision, "hardware_suite_disabled")
        try:
            working_directory = self._working_directory(suite.command.working_directory)
        except ValueError:
            return self._rejected_run(suite_id, revision, "invalid_working_directory", suite)
        run_id = uuid4()
        started = datetime.now(UTC)
        capture = await self._adapter.execute(
            suite.command,
            working_directory,
            suite.timeout_seconds,
            cancellation,
            allow_hardware=allow_hardware,
        )
        artifacts = (
            self._artifacts.write(run_id, "stdout", capture.stdout),
            self._artifacts.write(run_id, "stderr", capture.stderr),
        )
        status, results, evidence = _interpret_capture(suite, capture, artifacts)
        return TestRun(
            run_id=run_id,
            revision=revision,
            suite=suite,
            started_at=started,
            finished_at=datetime.now(UTC),
            environment=TestEnvironment(
                platform=sys.platform,
                python_version=sys.version.split()[0],
                ci=os.environ.get("CI", "").casefold() == "true",
            ),
            status=status,
            results=results,
            artifacts=artifacts,
            timeout_seconds=suite.timeout_seconds,
            exit_code=capture.exit_code,
            failure_evidence=evidence,
        )

    def _working_directory(self, relative: str) -> Path:
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts or "\x00" in relative:
            raise ValueError("Test working directory must be a safe project-relative path")
        resolved = (self._project_root / candidate).resolve(strict=True)
        if not resolved.is_relative_to(self._project_root):
            raise ValueError("Test working directory escaped project root")
        return resolved

    def _rejected_run(
        self,
        suite_id: str,
        revision: str,
        code: str,
        suite: TestSuite | None = None,
    ) -> TestRun:
        now = datetime.now(UTC)
        record = suite or _synthetic_suite(suite_id)
        return TestRun(
            run_id=uuid4(),
            revision=revision,
            suite=record,
            started_at=now,
            finished_at=now,
            environment=TestEnvironment(sys.platform, sys.version.split()[0], False),
            status=TestRunStatus.REJECTED,
            results=(),
            artifacts=(),
            timeout_seconds=record.timeout_seconds,
            exit_code=None,
            failure_evidence=(FailureEvidence(code, "Test suite request was rejected", ()),),
        )

    def _skipped_run(self, suite: TestSuite, revision: str, code: str) -> TestRun:
        now = datetime.now(UTC)
        return TestRun(
            run_id=uuid4(),
            revision=revision,
            suite=suite,
            started_at=now,
            finished_at=now,
            environment=TestEnvironment(sys.platform, sys.version.split()[0], False),
            status=TestRunStatus.SKIPPED,
            results=(IndividualTestResult(suite.suite_id, IndividualTestStatus.SKIPPED, code),),
            artifacts=(),
            timeout_seconds=suite.timeout_seconds,
            exit_code=None,
        )


def _interpret_capture(
    suite: TestSuite, capture: ProcessCapture, artifacts: tuple[TestArtifact, ...]
) -> tuple[TestRunStatus, tuple[IndividualTestResult, ...], tuple[FailureEvidence, ...]]:
    artifact_ids = tuple(item.artifact_id for item in artifacts)
    cleanup_evidence = (
        (
            FailureEvidence(
                "process_cleanup_failed",
                "Owned test-process cleanup did not complete safely",
                artifact_ids,
            ),
        )
        if capture.cleanup_error is not None
        else ()
    )
    if capture.cancelled:
        return (
            TestRunStatus.CANCELLED,
            (IndividualTestResult(suite.suite_id, IndividualTestStatus.UNKNOWN, "cancelled"),),
            (FailureEvidence("cancelled", "Test process was cancelled", artifact_ids),)
            + cleanup_evidence,
        )
    if capture.timed_out:
        return (
            TestRunStatus.TIMED_OUT,
            (IndividualTestResult(suite.suite_id, IndividualTestStatus.UNKNOWN, "timeout"),),
            (FailureEvidence("timeout", "Test process exceeded its timeout", artifact_ids),)
            + cleanup_evidence,
        )
    if capture.launch_error is not None:
        return (
            TestRunStatus.CRASHED,
            (IndividualTestResult(suite.suite_id, IndividualTestStatus.UNKNOWN, "launch_error"),),
            (FailureEvidence("launch_error", "Test process could not start", artifact_ids),),
        )
    if capture.cleanup_error is not None:
        return (
            TestRunStatus.CRASHED,
            (IndividualTestResult(suite.suite_id, IndividualTestStatus.UNKNOWN, "cleanup_error"),),
            cleanup_evidence,
        )
    results = _parse_results(suite.output_format, capture.stdout)
    if results is None:
        return (
            TestRunStatus.MALFORMED,
            (),
            (
                FailureEvidence(
                    "malformed_output", "Test output did not match suite format", artifact_ids
                ),
            ),
        )
    if capture.exit_code == 0:
        # A structured suite that reports an unresolved or failed individual
        # result cannot coherently certify a passing aggregate run.  Preserve
        # the parsed records as evidence, but never translate a contradictory
        # child statement into trusted green release evidence.
        if any(
            result.status in {IndividualTestStatus.FAILED, IndividualTestStatus.UNKNOWN}
            for result in results
        ):
            return (
                TestRunStatus.MALFORMED,
                results,
                (
                    FailureEvidence(
                        "contradictory_output",
                        "Successful process exit contradicted an individual test result",
                        artifact_ids,
                    ),
                ),
            )
        return TestRunStatus.PASSED, results, ()
    return (
        TestRunStatus.FAILED,
        results,
        (FailureEvidence("nonzero_exit", "Test process exited unsuccessfully", artifact_ids),),
    )


def _parse_results(
    output_format: SuiteOutputFormat, stdout: str
) -> tuple[IndividualTestResult, ...] | None:
    if output_format is SuiteOutputFormat.STRUCTURED_JSON:
        try:
            payload = json.loads(stdout)
            records = payload["results"]
        except (json.JSONDecodeError, KeyError, TypeError):
            return None
        if not isinstance(records, list):
            return None
        parsed: list[IndividualTestResult] = []
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("name"), str):
                return None
            try:
                status = IndividualTestStatus(record["status"])
            except (KeyError, ValueError, TypeError):
                return None
            parsed.append(
                IndividualTestResult(record["name"], status, str(record.get("detail", "")))
            )
        return tuple(parsed)
    lines = stdout.rstrip().splitlines()
    if not lines:
        return None
    match = _PYTEST_FINAL_SUMMARY.fullmatch(lines[-1])
    if match is None or not any(_PYTEST_SESSION_START.fullmatch(line) for line in lines[:-1]):
        return None
    counts = list(_PYTEST_COUNT.finditer(match.group("summary")))
    if not counts:
        return None
    return tuple(
        IndividualTestResult(
            name=f"pytest:{match.group('status')}",
            status=IndividualTestStatus(match.group("status")),
            detail=match.group("count"),
        )
        for match in counts
    )


def _synthetic_suite(suite_id: str) -> TestSuite:
    safe_id = re.sub(r"[^a-z0-9_.-]+", "-", suite_id.casefold()).strip("-.") or "unknown"
    safe_id = safe_id[:96]
    return TestSuite(
        suite_id=safe_id,
        category=TestCategory.UNIT,
        command=TestCommand(sys.executable, ("-m", "pytest")),
        timeout_seconds=1,
        description="Synthetic rejected-suite record",
    )


def _label(value: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", value):
        raise ValueError("Artifact and suite labels must be bounded lowercase identifiers")
    return value


def _redact(value: str) -> str:
    return _TOKEN.sub("[REDACTED_TOKEN]", _SECRET.sub("[REDACTED_SECRET]", value))


def _cap_artifact_text(value: str) -> str:
    """Keep enough beginning and end evidence without letting one log dominate disk."""

    if len(value) <= _MAX_OUTPUT_CHARACTERS:
        return value
    marker = "\n[artifact truncated; retained bounded prefix and final tail]\n"
    prefix_size = min(4_096, _MAX_OUTPUT_CHARACTERS // 4)
    tail_size = _MAX_OUTPUT_CHARACTERS - prefix_size - len(marker)
    return value[:prefix_size] + marker + value[-tail_size:]


def _decode(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")
