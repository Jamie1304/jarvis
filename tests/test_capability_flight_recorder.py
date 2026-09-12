from __future__ import annotations

import sys
import time
from typing import cast
from uuid import uuid4

import pytest
from jarvis.capability_flight_recorder import CapabilityFlightRecorder


def test_recorder_binds_run_and_uses_real_wall_and_monotonic_clocks() -> None:
    recorder = CapabilityFlightRecorder(uuid4(), capability_id="capability-a")
    first = recorder.record(
        component="sandbox",
        stage="launch",
        operation="runtime_started",
        resource_identity={"pid": 1234},
    )
    time.sleep(0.001)
    second = recorder.record(
        component="ipc",
        stage="readiness",
        operation="handshake",
    )

    assert first.lifecycle_run_id == second.lifecycle_run_id == recorder.lifecycle_run_id
    assert second.sequence > first.sequence
    assert second.monotonic_ns >= first.monotonic_ns
    assert second.wall_clock.year >= 2026
    assert second.wall_clock.isoformat() != "2026-09-05T00:00:00+00:00"
    assert second.wall_clock.tzinfo is not None
    assert recorder.process_snapshot()["executable"] == sys.executable


def test_recorder_redacts_secrets_and_bounds_records() -> None:
    recorder = CapabilityFlightRecorder("run-1", max_records=3)
    recorder.record(
        component="test",
        stage="x",
        operation="redaction",
        resource_identity={"api_key": "do-not-store", "safe": "x" * 900},
    )
    assert "...[truncated]" in str(recorder.as_dict())
    for index in range(5):
        recorder.record(component="test", stage="x", operation=str(index))

    payload = recorder.as_dict()
    assert len(cast(list[object], payload["records"])) == 3
    assert "do-not-store" not in str(payload)


def test_snapshot_failure_does_not_escape_original_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = CapabilityFlightRecorder("run-2")

    def fail(*args: object, **kwargs: object) -> object:
        raise RuntimeError("diagnostic failure")

    monkeypatch.setattr(recorder, "snapshot", fail)
    recorder.safe_snapshot("pre_cleanup_failure")
    assert recorder.records()[-1].result == "snapshot_failed"
    assert recorder.records()[-1].error_class == "RuntimeError"


def test_process_snapshot_does_not_enumerate_unowned_processes() -> None:
    snapshot = CapabilityFlightRecorder.process_snapshot()
    assert set(snapshot) == {"pid", "parent_pid", "alive", "executable", "base_executable"}
