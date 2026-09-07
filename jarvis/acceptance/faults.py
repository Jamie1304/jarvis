"""Safe, reversible fault-injection transactions for lab fixtures and disposable guests."""

from __future__ import annotations

import json
import tempfile
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class FaultFamily(StrEnum):
    PROCESS_STOP = "PROCESS_STOP"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    CONFIG_INVALID = "CONFIG_INVALID"
    API_SCHEMA_MUTATION = "API_SCHEMA_MUTATION"
    API_RESPONSE_ERROR = "API_RESPONSE_ERROR"
    NETWORK_TIMEOUT = "NETWORK_TIMEOUT"
    GENERATED_CAPABILITY_CRASH = "GENERATED_CAPABILITY_CRASH"
    TEST_FAILURE = "TEST_FAILURE"
    STARTUP_FAILURE = "STARTUP_FAILURE"
    PERMISSION_REVOKED = "PERMISSION_REVOKED"


@dataclass(frozen=True, slots=True)
class FaultSpec:
    fault_id: str
    family: FaultFamily
    target_environment: str
    target_resource: str
    precondition: str
    injection_action: str
    expected_symptom: str
    cleanup_action: str
    maximum_lifetime_seconds: int
    risk_class: str
    evidence_requirements: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FaultResult:
    fault_id: str
    occurred: bool
    evidence: dict[str, object]
    cleaned: bool
    base_environment_healthy: bool
    orphaned: bool = False


class FaultTransaction(AbstractContextManager["FaultTransaction"]):
    """Transaction defaults to an isolated temp fixture; no host/workbench mutation."""

    def __init__(self, spec: FaultSpec, *, root: Path | None = None) -> None:
        self.spec = spec
        if spec.target_environment not in {"DISPOSABLE_TEST_VM", "SYNTHETIC_FIXTURE"}:
            raise ValueError("fault injection is restricted to disposable/synthetic environments")
        self.root = root or Path(tempfile.mkdtemp(prefix="jarvis-fault-"))
        self.result: FaultResult | None = None
        self._marker = self.root / "fault-present.json"

    def prepare(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "baseline.json").write_text(json.dumps({"healthy": True}), encoding="utf-8")

    def inject(self) -> None:
        self._marker.write_text(
            json.dumps({"fault_id": self.spec.fault_id, "family": self.spec.family.value}),
            encoding="utf-8",
        )

    def verify_fault_present(self) -> bool:
        return self._marker.exists() and self.spec.fault_id in self._marker.read_text(
            encoding="utf-8"
        )

    def cleanup(self) -> bool:
        self._marker.unlink(missing_ok=True)
        return not self._marker.exists()

    def verify_cleanup(self) -> bool:
        return (
            not self._marker.exists()
            and json.loads((self.root / "baseline.json").read_text(encoding="utf-8"))["healthy"]
            is True
        )

    def __enter__(self) -> FaultTransaction:
        self.prepare()
        self.inject()
        occurred = self.verify_fault_present()
        cleaned = self.cleanup()
        healthy = self.verify_cleanup()
        self.result = FaultResult(
            self.spec.fault_id,
            occurred,
            {"fault_present": occurred, "family": self.spec.family.value},
            cleaned,
            healthy,
            not cleaned,
        )
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if not self._marker.exists():
            return None
        self.cleanup()
        return None


def default_faults() -> tuple[FaultSpec, ...]:
    common = ("fault marker", "machine result", "cleanup verification")
    values = (
        (FaultFamily.PROVIDER_UNAVAILABLE, "local provider", "provider returns unavailable"),
        (FaultFamily.PROCESS_STOP, "guest process", "guest command exits non-zero"),
        (FaultFamily.DEPENDENCY_MISSING, "fixture dependency", "dependency lookup fails"),
        (FaultFamily.CONFIG_INVALID, "fixture config", "configuration validation fails"),
        (FaultFamily.API_SCHEMA_MUTATION, "synthetic API", "schema digest changes"),
        (FaultFamily.NETWORK_TIMEOUT, "synthetic API", "bounded timeout occurs"),
        (FaultFamily.GENERATED_CAPABILITY_CRASH, "generated fixture", "capability raises"),
        (FaultFamily.TEST_FAILURE, "controlled test", "test assertion fails"),
        (FaultFamily.STARTUP_FAILURE, "candidate fixture", "health probe fails"),
        (FaultFamily.PERMISSION_REVOKED, "scoped fixture permission", "receipt is rejected"),
    )
    return tuple(
        FaultSpec(
            f"fault-{index:02}",
            family,
            "SYNTHETIC_FIXTURE",
            resource,
            "baseline healthy",
            symptom,
            symptom,
            "remove fixture marker and verify baseline",
            60,
            "low",
            common,
        )
        for index, (family, resource, symptom) in enumerate(values, 1)
    )
