"""Typed acceptance contracts. Model text is never an evidence authority."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any


class TestClassification(StrEnum):
    AUTO = "AUTO"
    REAL_WINDOWS = "REAL_WINDOWS"
    VM = "VM"
    SYNTHETIC_HARDWARE = "SYNTHETIC_HARDWARE"
    EXTERNAL_TEST_SERVICE = "EXTERNAL_TEST_SERVICE"
    REAL_HARDWARE = "REAL_HARDWARE"
    LONG_RUNNING = "LONG_RUNNING"
    HUMAN_JUDGMENT = "HUMAN_JUDGMENT"


class AutomationLevel(StrEnum):
    FULLY_AUTOMATED_NOW = "FULLY_AUTOMATED_NOW"
    AUTOMATABLE_WITH_VM = "AUTOMATABLE_WITH_VM"
    AUTOMATABLE_WITH_REAL_WINDOWS = "AUTOMATABLE_WITH_REAL_WINDOWS"
    AUTOMATABLE_WITH_SYNTHETIC_FIXTURE = "AUTOMATABLE_WITH_SYNTHETIC_FIXTURE"
    AUTOMATABLE_WITH_EXTERNAL_TEST_SERVICE = "AUTOMATABLE_WITH_EXTERNAL_TEST_SERVICE"
    REAL_HARDWARE_REQUIRED = "REAL_HARDWARE_REQUIRED"
    HUMAN_JUDGMENT_REQUIRED = "HUMAN_JUDGMENT_REQUIRED"
    LONG_RUNNING = "LONG_RUNNING"
    FUTURE_PRODUCT_FEATURE_REQUIRED = "FUTURE_PRODUCT_FEATURE_REQUIRED"


class AcceptanceStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_EXECUTED = "NOT_EXECUTED"
    BLOCKED_ENVIRONMENT = "BLOCKED_ENVIRONMENT"
    BLOCKED_FEATURE = "BLOCKED_FEATURE"
    REAL_HARDWARE_REQUIRED = "REAL_HARDWARE_REQUIRED"
    EXTERNAL_SERVICE_REQUIRED = "EXTERNAL_SERVICE_REQUIRED"
    HUMAN_JUDGMENT_REQUIRED = "HUMAN_JUDGMENT_REQUIRED"
    LONG_RUNNING_PENDING = "LONG_RUNNING_PENDING"
    UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"


class EvidenceTrust(StrEnum):
    MACHINE_VERIFIED = "MACHINE_VERIFIED"
    TRUSTED_BROKER_RECEIPT = "TRUSTED_BROKER_RECEIPT"
    NATIVE_OS_OBSERVATION = "NATIVE_OS_OBSERVATION"
    VM_OBSERVATION = "VM_OBSERVATION"
    SYNTHETIC_TEST_OBSERVATION = "SYNTHETIC_TEST_OBSERVATION"
    EXTERNAL_SERVICE_OBSERVATION = "EXTERNAL_SERVICE_OBSERVATION"
    USER_CONFIRMED = "USER_CONFIRMED"
    MODEL_REPORTED = "MODEL_REPORTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class EvidenceEnvelope:
    evidence_id: str
    run_id: str
    test_id: str
    source: str
    source_type: str
    environment: str
    trust: EvidenceTrust
    result: AcceptanceStatus
    observed_state: dict[str, Any] = field(default_factory=dict)
    expected_state: dict[str, Any] = field(default_factory=dict)
    artifact_path: str | None = None
    sha256: str | None = None
    operation_id: str | None = None
    freshness: str = "current"
    notes: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def satisfies_critical_assertion(self) -> bool:
        return (
            self.trust is not EvidenceTrust.MODEL_REPORTED
            and self.trust is not EvidenceTrust.UNKNOWN
        )


@dataclass(frozen=True, slots=True)
class TestSpec:
    test_id: str
    title: str
    phase: str
    objective: str
    classification: TestClassification
    automation_level: AutomationLevel
    tags: tuple[str, ...]
    risk: str
    mutation_level: str
    required_environment: str
    required_capabilities: tuple[str, ...]
    prerequisites: tuple[str, ...]
    execution_contract: str
    expected_outcomes: tuple[str, ...]
    assertions: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    cleanup: str
    timeout_seconds: int
    retry_policy: str
    human_requirement: str | None
    owner_approval_required: bool
    host_access_required: bool
    vm_policy: str
    security_relevance: str
    failure_severity: str
    spec_version: str = "1.0"

    def __post_init__(self) -> None:
        if (
            len(self.test_id) != 3
            or not self.test_id.isdigit()
            or not 1 <= int(self.test_id) <= 115
        ):
            raise ValueError(f"invalid canonical test ID: {self.test_id}")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout must be positive")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self) | {
            "classification": self.classification.value,
            "automation_level": self.automation_level.value,
        }


@dataclass(frozen=True, slots=True)
class AssertionResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True, slots=True)
class AcceptanceResult:
    test_id: str
    status: AcceptanceStatus
    assertions: tuple[AssertionResult, ...] = ()
    evidence: tuple[EvidenceEnvelope, ...] = ()
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    finished_at: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "status": self.status.value,
            "assertions": [asdict(item) for item in self.assertions],
            "evidence": [
                asdict(item) | {"trust": item.trust.value, "result": item.result.value}
                for item in self.evidence
            ],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
        }


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
