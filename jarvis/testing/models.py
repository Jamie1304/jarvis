"""Typed, machine-readable records for controlled system test execution."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID


class TestCategory(StrEnum):
    UNIT = "unit"
    INTEGRATION = "integration"
    TOOLS = "tools"
    PERMISSIONS = "permissions"
    API = "api"
    UI = "ui"
    VOICE = "voice"
    AGENT_WORKFLOWS = "agent_workflows"
    REGRESSION = "regression"
    STARTUP = "startup"
    SHUTDOWN = "shutdown"
    HEALTH = "health"


class TestRunStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    CRASHED = "crashed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    MALFORMED = "malformed"
    REJECTED = "rejected"
    SKIPPED = "skipped"


class IndividualTestStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"


class SuiteOutputFormat(StrEnum):
    PYTEST_TEXT = "pytest_text"
    STRUCTURED_JSON = "structured_json"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class TestCommand:
    """Trusted executable and argument vector; never a shell command string."""

    executable: str
    arguments: tuple[str, ...]
    working_directory: str = "."

    def __post_init__(self) -> None:
        values = (self.executable, *self.arguments, self.working_directory)
        if not self.executable.strip() or any("\x00" in value for value in values):
            raise ValueError("Test command values must be non-empty and NUL-free")
        if any("\r" in value or "\n" in value for value in values):
            raise ValueError("Test command values must be single-line")


@dataclass(frozen=True, slots=True)
class TestSuite:
    """One trusted, catalogued test suite with explicit safety characteristics."""

    suite_id: str
    category: TestCategory
    command: TestCommand
    timeout_seconds: float
    output_format: SuiteOutputFormat = SuiteOutputFormat.PYTEST_TEXT
    hardware_dependent: bool = False
    partial: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        if not self.suite_id or self.suite_id != self.suite_id.strip() or len(self.suite_id) > 128:
            raise ValueError("Suite ID must be a bounded, non-empty label")
        if not isinstance(self.category, TestCategory):
            raise ValueError("Suite category must be a TestCategory")
        if not isinstance(self.output_format, SuiteOutputFormat):
            raise ValueError("Suite output format must be recognized")
        if self.timeout_seconds <= 0:
            raise ValueError("Suite timeout must be positive")


@dataclass(frozen=True, slots=True)
class TestEnvironment:
    """Non-secret execution environment facts retained with a run."""

    platform: str
    python_version: str
    ci: bool


@dataclass(frozen=True, slots=True)
class IndividualTestResult:
    name: str
    status: IndividualTestStatus
    detail: str = ""


@dataclass(frozen=True, slots=True)
class TestArtifact:
    artifact_id: str
    kind: str
    relative_path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class FailureEvidence:
    code: str
    summary: str
    artifact_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TestRun:
    """Complete evidence record for one controlled test-suite execution."""

    run_id: UUID
    revision: str
    suite: TestSuite
    started_at: datetime
    finished_at: datetime
    environment: TestEnvironment
    status: TestRunStatus
    results: tuple[IndividualTestResult, ...]
    artifacts: tuple[TestArtifact, ...]
    timeout_seconds: float
    exit_code: int | None
    failure_evidence: tuple[FailureEvidence, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "started_at", _utc(self.started_at))
        object.__setattr__(self, "finished_at", _utc(self.finished_at))
        if self.finished_at < self.started_at:
            raise ValueError("Test run finish time cannot precede start")
        if not self.revision.strip() or len(self.revision) > 256:
            raise ValueError("Revision/build label must be a bounded non-empty string")
        if self.timeout_seconds <= 0:
            raise ValueError("Test run timeout must be positive")

    def to_dict(self) -> dict[str, Any]:
        """Return a secret-safe JSON-ready result for improvement/evaluation systems."""

        return {
            "run_id": str(self.run_id),
            "revision": self.revision,
            "suite": self.suite.suite_id,
            "category": self.suite.category.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "environment": {
                "platform": self.environment.platform,
                "python_version": self.environment.python_version,
                "ci": self.environment.ci,
            },
            "status": self.status.value,
            "results": [
                {"name": item.name, "status": item.status.value, "detail": item.detail}
                for item in self.results
            ],
            "artifacts": [
                {
                    "id": item.artifact_id,
                    "kind": item.kind,
                    "path": item.relative_path,
                    "sha256": item.sha256,
                    "size_bytes": item.size_bytes,
                }
                for item in self.artifacts
            ],
            "timeout_seconds": self.timeout_seconds,
            "exit_code": self.exit_code,
            "failure_evidence": [
                {
                    "code": item.code,
                    "summary": item.summary,
                    "artifact_ids": list(item.artifact_ids),
                }
                for item in self.failure_evidence
            ],
        }


@dataclass(frozen=True, slots=True)
class TestDiagnosis:
    """Interpretation derived from run metadata, never a replacement for raw artifacts."""

    run_id: UUID
    status: TestRunStatus
    summary: str
    suspected_layer: str | None
    evidence_codes: tuple[str, ...]
