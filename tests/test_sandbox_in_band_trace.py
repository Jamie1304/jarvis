"""Deterministic in-band child-trace protocol matrix for R4R-D6A4."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from jarvis.capability_flight_recorder import CapabilityFlightRecorder
from jarvis.sandbox import (
    SandboxLimits,
    SandboxMessage,
    SandboxProcess,
    SandboxProcessError,
    SandboxProtocolError,
    SandboxTimeout,
    WindowsContainmentMode,
)

CHILD = r"""
import json, os, sys, time

def emit(message, stage, sequence, **metadata):
    if not message.get("diagnostics"):
        return
    frame = {"version": 1, "request_id": message["request_id"],
             "integration_id": message["integration_id"], "kind": "trace",
             "response": False, "lifecycle_run_id": message.get("lifecycle_run_id"),
             "payload": {"sequence": sequence, "stage": stage, **metadata}}
    print(json.dumps(frame, separators=(",", ":")), flush=True)

for line in sys.stdin:
    message = json.loads(line)
    mode = message.get("payload", {}).get("fixture", "healthy")
    emit(message, "ENTRYPOINT_STARTED", 1)
    emit(message, "PROTOCOL_LOOP_STARTED", 2)
    if mode == "exit_before_request":
        os._exit(21)
    emit(message, "FRAME_RECEIVED", 3)
    emit(message, "FRAME_PARSED", 4)
    emit(message, "REQUEST_VALIDATED", 5)
    if mode == "exit_after_request":
        os._exit(22)
    if mode == "handler_exception":
        emit(message, "HEALTH_DISPATCH_BEGIN", 6)
        emit(message, "HEALTH_HANDLER_EXCEPTION", 7, secret="SECRET_CANARY_D6A4_92841")
        os._exit(23)
    if mode == "no_final_response":
        emit(message, "HEALTH_DISPATCH_BEGIN", 6)
        time.sleep(30)
    if mode == "malformed_response":
        print("{", flush=True)
        os._exit(24)
    if mode == "wrong_request_id":
        response_id = "00000000-0000-0000-0000-000000000000"
    else:
        response_id = message["request_id"]
    response_integration = (
        "other.integration" if mode == "wrong_integration_id" else message["integration_id"]
    )
    response_version = 2 if mode == "wrong_protocol_version" else 1
    status = "unhealthy" if mode == "unhealthy_status" else "healthy"
    if mode == "trace_flood":
        for sequence in range(6, 80):
            emit(message, "TRACE_FLOOD", sequence, secret="SECRET_CANARY_D6A4_92841")
    emit(message, "HEALTH_STATE_READ", 6)
    emit(message, "HEALTH_RESULT_COMPUTED", 7)
    response = {"version": response_version, "request_id": response_id,
                "integration_id": response_integration, "kind": "result",
                "response": True, "payload": {"status": status}}
    print(json.dumps(response, separators=(",", ":")), flush=True)
"""


def _process(tmp_path: Path, *, diagnostics: bool, recorder: Any = None) -> SandboxProcess:
    # The base interpreter is intentional: the venv redirector cannot create its
    # base process inside a one-process Job on this Windows host.
    return SandboxProcess(
        Path(sys.base_prefix) / "python.exe",
        ("-c", CHILD),
        integration_id="trace.integration",
        parent_directory=tmp_path / "owned",
        limits=SandboxLimits(
            timeout_seconds=0.15,
            max_message_bytes=65_536,
            windows_containment=WindowsContainmentMode.JOB_OBJECT_ONLY,
        ),
        diagnostics_enabled=diagnostics,
        flight_recorder=recorder,
    )


async def _run(
    tmp_path: Path, fixture: str, *, diagnostics: bool = True
) -> tuple[SandboxProcess, dict[str, object] | None, BaseException | None]:
    recorder = CapabilityFlightRecorder("d6a4-test-run") if diagnostics else None
    process = _process(tmp_path, diagnostics=diagnostics, recorder=recorder)
    await process.start()
    try:
        result = await process.request("health", {"fixture": fixture})
        return process, result, None
    except BaseException as error:
        return process, None, error


@pytest.mark.asyncio
async def test_d6a4_healthy_trace_and_diagnostics_equivalence(tmp_path: Path) -> None:
    off, off_result, off_error = await _run(tmp_path / "off", "healthy", diagnostics=False)
    on, on_result, on_error = await _run(tmp_path / "on", "healthy", diagnostics=True)
    assert off_error is None and on_error is None
    assert off_result == on_result == {"status": "healthy"}
    assert off.protocol_diagnostics.response_received
    assert on.protocol_diagnostics.response_received
    assert [item["stage"] for item in on.protocol_diagnostics.child_events] == [
        "ENTRYPOINT_STARTED",
        "PROTOCOL_LOOP_STARTED",
        "FRAME_RECEIVED",
        "FRAME_PARSED",
        "REQUEST_VALIDATED",
        "HEALTH_STATE_READ",
        "HEALTH_RESULT_COMPUTED",
    ]
    await off.close()
    await on.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fixture", "error_type", "classification"),
    (
        ("exit_before_request", SandboxProcessError, "STDOUT_EOF"),
        ("exit_after_request", SandboxProcessError, "STDOUT_EOF"),
        ("malformed_response", SandboxProtocolError, "MALFORMED_RESPONSE"),
        ("wrong_request_id", SandboxProtocolError, "REQUEST_ID_MISMATCH"),
        ("wrong_integration_id", SandboxProtocolError, "INTEGRATION_ID_MISMATCH"),
        ("wrong_protocol_version", SandboxProtocolError, "PROTOCOL_VERSION_MISMATCH"),
        ("handler_exception", SandboxProcessError, "STDOUT_EOF"),
        ("no_final_response", SandboxTimeout, "RESPONSE_TIMEOUT"),
    ),
)
async def test_d6a4_fault_matrix_is_classified_and_cleaned(
    tmp_path: Path, fixture: str, error_type: type[BaseException], classification: str
) -> None:
    process, result, error = await _run(tmp_path, fixture)
    assert result is None
    assert isinstance(error, error_type)
    assert process.protocol_diagnostics.classification == classification
    if fixture in {"exit_after_request", "handler_exception", "no_final_response"}:
        assert process.protocol_diagnostics.child_events
    if fixture == "handler_exception":
        assert process.protocol_diagnostics.child_events[-1]["stage"] == "HEALTH_HANDLER_EXCEPTION"
        assert "SECRET_CANARY_D6A4_92841" not in repr(process.protocol_diagnostics.as_dict())
    assert not process.is_running
    await process.close()
    assert not any((tmp_path / "owned").glob("jarvis-sandbox-*"))


@pytest.mark.asyncio
async def test_d6a4_trace_order_identity_and_flood_bounds(tmp_path: Path) -> None:
    process, _result, error = await _run(tmp_path / "flood", "trace_flood")
    assert isinstance(error, SandboxProtocolError)
    assert process.protocol_diagnostics.classification == "TRACE_OVERFLOW"
    assert len(process.protocol_diagnostics.child_events) <= 32
    assert "SECRET_CANARY_D6A4_92841" not in repr(process.protocol_diagnostics.as_dict())
    await process.close()


@pytest.mark.asyncio
async def test_d6a4_unhealthy_response_is_valid_but_not_healthy(tmp_path: Path) -> None:
    process, result, error = await _run(tmp_path / "unhealthy", "unhealthy_status")
    assert error is None
    assert result == {"status": "unhealthy"}
    assert process.protocol_diagnostics.response_received
    assert not result["status"] == "healthy"
    await process.close()


def test_d6a4_trace_frame_round_trip_is_optional() -> None:
    message = SandboxMessage(
        __import__("uuid").uuid4(),
        "trace.integration",
        "trace",
        {"sequence": 1, "stage": "ENTRYPOINT_STARTED"},
        lifecycle_run_id="d6a4-test-run",
    )
    assert SandboxMessage.decode(message.encode()) == message
