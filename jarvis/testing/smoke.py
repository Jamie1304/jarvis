"""Optional isolated localhost startup/health/shutdown smoke testing."""

from __future__ import annotations

import asyncio
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx

from jarvis.testing.models import (
    FailureEvidence,
    IndividualTestResult,
    IndividualTestStatus,
    TestCategory,
    TestCommand,
    TestEnvironment,
    TestRun,
    TestRunStatus,
    TestSuite,
)
from jarvis.testing.runner import TestArtifactStore


@dataclass(frozen=True, slots=True)
class StartupSmokeDefinition:
    suite: TestSuite
    health_url: str
    ready_timeout_seconds: float = 15
    shutdown_timeout_seconds: float = 10

    def __post_init__(self) -> None:
        if not self.health_url.startswith("http://127.0.0.1:"):
            raise ValueError("Startup smoke health URL must use localhost IPv4")


class StartedProcess(ABC):
    @property
    @abstractmethod
    def pid(self) -> int:
        """Return the OS process identity for evidence only."""

    @abstractmethod
    async def terminate(self, timeout_seconds: float) -> tuple[int | None, str]:
        """Request a clean shutdown, escalating only after its deadline."""


class StartupProcessAdapter(ABC):
    @abstractmethod
    async def start(self, command: TestCommand, working_directory: Path) -> StartedProcess:
        """Launch an explicit trusted localhost command without a shell."""


class _AsyncioStartedProcess(StartedProcess):
    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self._process = process

    @property
    def pid(self) -> int:
        return self._process.pid

    async def terminate(self, timeout_seconds: float) -> tuple[int | None, str]:
        if self._process.returncode is None:
            self._process.terminate()
        try:
            await asyncio.wait_for(self._process.wait(), timeout_seconds)
            return self._process.returncode, "terminated"
        except TimeoutError:
            self._process.kill()
            await self._process.wait()
            return self._process.returncode, "killed_after_timeout"


class SubprocessStartupAdapter(StartupProcessAdapter):
    async def start(self, command: TestCommand, working_directory: Path) -> StartedProcess:
        process = await asyncio.create_subprocess_exec(
            command.executable,
            *command.arguments,
            cwd=working_directory,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return _AsyncioStartedProcess(process)


class HealthProbe(ABC):
    @abstractmethod
    async def ready(self, url: str) -> bool:
        """Return whether the isolated local endpoint reports ready health."""


class LocalHttpHealthProbe(HealthProbe):
    async def ready(self, url: str) -> bool:
        async with httpx.AsyncClient(timeout=1) as client:
            try:
                response = await client.get(url)
            except httpx.HTTPError:
                return False
        try:
            payload = response.json()
        except ValueError:
            return False
        return response.status_code == 200 and _health_payload_ready(payload)


def create_local_startup_smoke_definition(port: int) -> StartupSmokeDefinition:
    """Build the fixed localhost-only JARVIS API smoke command for manual trusted use."""

    if isinstance(port, bool) or not 1024 <= port <= 65535:
        raise ValueError("Startup smoke port must be an unprivileged TCP port")
    suite = TestSuite(
        suite_id="jarvis-local-startup-smoke",
        category=TestCategory.STARTUP,
        command=TestCommand(
            sys.executable,
            (
                "-m",
                "uvicorn",
                "jarvis.api:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--log-level",
                "warning",
            ),
        ),
        timeout_seconds=30,
        description="Optional isolated localhost JARVIS API smoke test.",
    )
    return StartupSmokeDefinition(suite, f"http://127.0.0.1:{port}/health")


def _health_payload_ready(payload: object) -> bool:
    """Accept both the generic ready contract and JARVIS's health-status contract."""

    if not isinstance(payload, dict):
        return False
    return payload.get("ready") is True or (
        payload.get("status") == "ok" and payload.get("startup_complete") is True
    )


class StartupSmokeTester:
    """Optional smoke test. It never starts unless trusted composition calls it."""

    def __init__(
        self,
        project_root: Path,
        artifacts: TestArtifactStore,
        process_adapter: StartupProcessAdapter | None = None,
        health_probe: HealthProbe | None = None,
    ) -> None:
        self._project_root = project_root.resolve()
        self._artifacts = artifacts
        self._process_adapter = process_adapter or SubprocessStartupAdapter()
        self._health_probe = health_probe or LocalHttpHealthProbe()

    async def run(
        self, definition: StartupSmokeDefinition, revision: str, cancellation: asyncio.Event
    ) -> TestRun:
        run_id, started = uuid4(), datetime.now(UTC)
        process: StartedProcess | None = None
        results: list[IndividualTestResult] = []
        evidence: list[FailureEvidence] = []
        status = TestRunStatus.FAILED
        exit_code: int | None = None
        try:
            working_directory = self._working_directory(definition.suite.command.working_directory)
            process = await self._process_adapter.start(definition.suite.command, working_directory)
            results.append(IndividualTestResult("process_start", IndividualTestStatus.PASSED))
            ready = await self._wait_ready(definition, cancellation)
            if not ready:
                results.append(IndividualTestResult("health_ready", IndividualTestStatus.FAILED))
                evidence.append(
                    FailureEvidence("health_not_ready", "Health endpoint did not become ready", ())
                )
            else:
                results.append(IndividualTestResult("health_ready", IndividualTestStatus.PASSED))
                status = TestRunStatus.PASSED
        except asyncio.CancelledError:
            raise
        except (OSError, ValueError) as error:
            evidence.append(FailureEvidence("startup_error", type(error).__name__, ()))
            results.append(IndividualTestResult("process_start", IndividualTestStatus.FAILED))
            status = TestRunStatus.CRASHED
        finally:
            if process is not None:
                exit_code, shutdown = await process.terminate(definition.shutdown_timeout_seconds)
                shutdown_status = (
                    IndividualTestStatus.PASSED
                    if shutdown == "terminated"
                    else IndividualTestStatus.FAILED
                )
                results.append(IndividualTestResult("clean_shutdown", shutdown_status, shutdown))
                if shutdown_status is IndividualTestStatus.FAILED:
                    status = TestRunStatus.FAILED
                    evidence.append(FailureEvidence("unclean_shutdown", shutdown, ()))
        artifact = self._artifacts.write(
            run_id,
            "smoke",
            f"health_url={definition.health_url}\nstatus={status.value}\nexit_code={exit_code}\n",
        )
        if evidence:
            evidence = [
                FailureEvidence(item.code, item.summary, (artifact.artifact_id,))
                for item in evidence
            ]
        return TestRun(
            run_id=run_id,
            revision=revision,
            suite=definition.suite,
            started_at=started,
            finished_at=datetime.now(UTC),
            environment=TestEnvironment(sys.platform, sys.version.split()[0], False),
            status=status,
            results=tuple(results),
            artifacts=(artifact,),
            timeout_seconds=definition.suite.timeout_seconds,
            exit_code=exit_code,
            failure_evidence=tuple(evidence),
        )

    async def _wait_ready(
        self, definition: StartupSmokeDefinition, cancellation: asyncio.Event
    ) -> bool:
        try:
            async with asyncio.timeout(definition.ready_timeout_seconds):
                while not cancellation.is_set():
                    if await self._health_probe.ready(definition.health_url):
                        return True
                    await asyncio.sleep(0.05)
        except TimeoutError:
            return False
        return False

    def _working_directory(self, relative: str) -> Path:
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError("Startup working directory must be project-relative")
        resolved = (self._project_root / candidate).resolve(strict=True)
        if not resolved.is_relative_to(self._project_root):
            raise ValueError("Startup working directory escaped project root")
        return resolved
