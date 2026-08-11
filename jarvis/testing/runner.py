"""Controlled no-shell test execution with redacted evidence artifacts."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

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

_MAX_OUTPUT_CHARACTERS = 65_536
_SECRET = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)"
    r"\s*[:=]\s*(['\"]?)[^\s'\"]+\1"
)
_TOKEN = re.compile(r"\b(?:gh[oprsu][_-]|sk-)[A-Za-z0-9_-]{12,}\b")
_PYTEST_SUMMARY = re.compile(r"(?P<count>\d+) (?P<status>passed|failed|skipped)")


@dataclass(frozen=True, slots=True)
class ProcessCapture:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    cancelled: bool = False
    launch_error: str | None = None


class TestProcessAdapter(ABC):
    """Subprocess boundary; adapters receive only a trusted catalog command."""

    @abstractmethod
    async def execute(
        self,
        command: TestCommand,
        working_directory: Path,
        timeout_seconds: float,
        cancellation: asyncio.Event,
    ) -> ProcessCapture:
        """Run one explicit executable/argv command without a shell."""


class SubprocessTestAdapter(TestProcessAdapter):
    """Default process adapter using asyncio.create_subprocess_exec only."""

    async def execute(
        self,
        command: TestCommand,
        working_directory: Path,
        timeout_seconds: float,
        cancellation: asyncio.Event,
    ) -> ProcessCapture:
        try:
            process = await asyncio.create_subprocess_exec(
                command.executable,
                *command.arguments,
                cwd=working_directory,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._safe_environment(),
            )
        except OSError as error:
            return ProcessCapture(None, "", "", launch_error=type(error).__name__)
        communication = asyncio.create_task(process.communicate())
        cancellation_wait = asyncio.create_task(cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {communication, cancellation_wait},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if communication in done:
                stdout, stderr = await communication
                return ProcessCapture(process.returncode, _decode(stdout), _decode(stderr))
            if cancellation_wait in done:
                stdout, stderr = await self._terminate(process, communication)
                return ProcessCapture(
                    process.returncode,
                    _decode(stdout),
                    _decode(stderr),
                    cancelled=True,
                )
            stdout, stderr = await self._terminate(process, communication)
            return ProcessCapture(
                process.returncode,
                _decode(stdout),
                _decode(stderr),
                timed_out=True,
            )
        except asyncio.CancelledError:
            await self._terminate(process, communication)
            raise
        finally:
            if not cancellation_wait.done():
                cancellation_wait.cancel()
            await asyncio.gather(cancellation_wait, return_exceptions=True)

    @staticmethod
    async def _terminate(
        process: asyncio.subprocess.Process,
        communication: asyncio.Task[tuple[bytes, bytes]],
    ) -> tuple[bytes, bytes]:
        if process.returncode is None:
            process.kill()
        return await communication

    @staticmethod
    def _safe_environment() -> dict[str, str]:
        """Keep only process bootstrap values; tests never receive user credentials."""

        values = {
            key: os.environ[key]
            for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
            if key in os.environ
        }
        values["PYTHONUTF8"] = "1"
        values["PYTHONDONTWRITEBYTECODE"] = "1"
        return values


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
        text = _redact(content)[:_MAX_OUTPUT_CHARACTERS]
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
            suite.command, working_directory, suite.timeout_seconds, cancellation
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
    if capture.cancelled:
        return (
            TestRunStatus.CANCELLED,
            (IndividualTestResult(suite.suite_id, IndividualTestStatus.UNKNOWN, "cancelled"),),
            (FailureEvidence("cancelled", "Test process was cancelled", artifact_ids),),
        )
    if capture.timed_out:
        return (
            TestRunStatus.TIMED_OUT,
            (IndividualTestResult(suite.suite_id, IndividualTestStatus.UNKNOWN, "timeout"),),
            (FailureEvidence("timeout", "Test process exceeded its timeout", artifact_ids),),
        )
    if capture.launch_error is not None:
        return (
            TestRunStatus.CRASHED,
            (IndividualTestResult(suite.suite_id, IndividualTestStatus.UNKNOWN, "launch_error"),),
            (FailureEvidence("launch_error", "Test process could not start", artifact_ids),),
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
    counts = list(_PYTEST_SUMMARY.finditer(stdout))
    if not counts:
        return (IndividualTestResult("process", IndividualTestStatus.UNKNOWN),)
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


def _decode(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")[:_MAX_OUTPUT_CHARACTERS]
