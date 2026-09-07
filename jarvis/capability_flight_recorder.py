"""Bounded, observation-only evidence for one capability lifecycle.

This module deliberately does not own lifecycle decisions.  It records trusted
control-flow observations and exact caller-supplied resource identities so a
failed acquisition can be compared with an isolated or preceding run.
"""

from __future__ import annotations

import os
import re
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

_MAX_RECORDS = 512
_MAX_TEXT = 512
_SECRET = re.compile(r"(?i)(api[_-]?key|authorization|bearer|credential|password|secret|token)")


def _safe(value: object, *, key: str = "") -> object:
    """Bound and redact diagnostic values before they enter evidence."""

    if _SECRET.search(key):
        return "[REDACTED]"
    if isinstance(value, str):
        return value[:_MAX_TEXT] + ("...[truncated]" if len(value) > _MAX_TEXT else "")
    if isinstance(value, Mapping):
        return {str(k)[:128]: _safe(v, key=str(k)) for k, v in list(value.items())[:64]}
    if isinstance(value, tuple | list | set | frozenset):
        return [_safe(item) for item in list(value)[:64]]
    if isinstance(value, int | float | bool) or value is None:
        return value
    return str(value)[:_MAX_TEXT]


@dataclass(frozen=True, slots=True)
class FlightRecord:
    sequence: int
    lifecycle_run_id: str
    capability_id: str | None
    component: str
    stage: str
    operation: str
    monotonic_ns: int
    wall_clock: datetime
    resource_identity: Mapping[str, object] = field(default_factory=dict)
    state_before: Mapping[str, object] = field(default_factory=dict)
    state_after: Mapping[str, object] = field(default_factory=dict)
    result: str = "observed"
    error_class: str | None = None
    detail: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "lifecycle_run_id": self.lifecycle_run_id,
            "capability_id": self.capability_id,
            "component": self.component,
            "stage": self.stage,
            "operation": self.operation,
            "monotonic_ns": self.monotonic_ns,
            "wall_clock": self.wall_clock.isoformat(),
            "resource_identity": dict(self.resource_identity),
            "state_before": dict(self.state_before),
            "state_after": dict(self.state_after),
            "result": self.result,
            "error_class": self.error_class,
            "detail": self.detail,
        }


class CapabilityFlightRecorder:
    """A bounded recorder bound permanently to one lifecycle run."""

    def __init__(
        self,
        lifecycle_run_id: UUID | str,
        *,
        capability_id: str | None = None,
        max_records: int = _MAX_RECORDS,
    ) -> None:
        identifier = str(lifecycle_run_id)
        if not identifier or len(identifier) > 128:
            raise ValueError("lifecycle_run_id is malformed")
        if type(max_records) is not int or not 1 <= max_records <= _MAX_RECORDS:
            raise ValueError("max_records is malformed")
        self.lifecycle_run_id = identifier
        self.capability_id = capability_id
        self._max_records = max_records
        self._records: list[FlightRecord] = []
        self._sequence = 0
        self.record(
            component="acquisition",
            stage="start",
            operation="lifecycle_started",
            resource_identity={"pid": os.getpid()},
            state_after=self.process_snapshot(),
        )

    @staticmethod
    def process_snapshot() -> dict[str, object]:
        """Capture only the current owned process; no name-wide enumeration."""

        return {
            "pid": os.getpid(),
            "parent_pid": None,
            "alive": True,
            "executable": sys.executable,
            "base_executable": getattr(sys, "_base_executable", sys.executable),
        }

    def record(
        self,
        *,
        component: str,
        stage: str,
        operation: str,
        resource_identity: Mapping[str, object] | None = None,
        state_before: Mapping[str, object] | None = None,
        state_after: Mapping[str, object] | None = None,
        result: str = "observed",
        error: BaseException | None = None,
        detail: str = "",
    ) -> FlightRecord:
        if len(self._records) >= self._max_records:
            self._records.pop(0)
        self._sequence += 1
        item = FlightRecord(
            self._sequence,
            self.lifecycle_run_id,
            self.capability_id,
            component[:128],
            stage[:128],
            operation[:128],
            time.monotonic_ns(),
            datetime.now(UTC),
            cast(Mapping[str, object], _safe(resource_identity or {})),
            cast(Mapping[str, object], _safe(state_before or {})),
            cast(Mapping[str, object], _safe(state_after or {})),
            result[:64],
            type(error).__name__ if error is not None else None,
            str(_safe(detail))[:_MAX_TEXT],
        )
        self._records.append(item)
        return item

    def snapshot(
        self, label: str, *, resources: Mapping[str, object] | None = None
    ) -> FlightRecord:
        return self.record(
            component="lifecycle",
            stage="snapshot",
            operation=label,
            resource_identity=resources,
            state_after={"process": self.process_snapshot(), "resources": resources or {}},
        )

    def safe_snapshot(self, label: str, *, resources: Mapping[str, object] | None = None) -> None:
        """Diagnostic failure never replaces the product failure."""

        try:
            self.snapshot(label, resources=resources)
        except Exception as error:  # pragma: no cover - defensive evidence boundary
            self.record(
                component="lifecycle",
                stage="snapshot",
                operation=label,
                result="snapshot_failed",
                error=error,
            )

    def records(self) -> tuple[FlightRecord, ...]:
        return tuple(self._records)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "jarvis-capability-flight-recorder-1",
            "lifecycle_run_id": self.lifecycle_run_id,
            "capability_id": self.capability_id,
            "records": [record.as_dict() for record in self._records],
        }


__all__ = ["CapabilityFlightRecorder", "FlightRecord"]
