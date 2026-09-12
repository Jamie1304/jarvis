"""Deterministic, non-production D6A6 perturbation and recorder fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from jarvis.sandbox import SandboxLimits, SandboxMessage, SandboxProcess, WindowsContainmentMode

CHILD = r"""
import json, sys
for line in sys.stdin:
    message = json.loads(line)
    mode = message.get("diagnostic_mode")
    if mode == "COMPUTE_ONLY":
        json.dumps({"stage": "computed", "request": message["request_id"]})
    elif mode == "FLUSH_ONLY":
        sys.stdout.flush()
    print(json.dumps({"version": 1, "request_id": message["request_id"],
        "integration_id": message["integration_id"], "kind": "result",
        "response": True, "payload": {"status": "healthy"}}), flush=True)
"""


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ("BASELINE_OFF", "COMPUTE_ONLY", "FLUSH_ONLY", "TRACE_ON"))
async def test_d6a6_modes_preserve_authoritative_health_and_record_parent_only(
    tmp_path: Path, mode: str
) -> None:
    process = SandboxProcess(
        Path(sys.base_prefix) / "python.exe",
        ("-c", CHILD),
        integration_id="d6a6.fixture",
        parent_directory=tmp_path / mode,
        limits=SandboxLimits(
            timeout_seconds=1,
            windows_containment=WindowsContainmentMode.JOB_OBJECT_ONLY,
        ),
        diagnostics_enabled=mode == "TRACE_ON",
        diagnostic_mode=mode,
        parent_only_recorder=True,
    )
    await process.start()
    try:
        assert await process.request("health", {}) == {"status": "healthy"}
        recorder = process.protocol_diagnostics.as_dict()["parent_flight_recorder"]
        assert isinstance(recorder, dict)
        stages = [item["stage"] for item in recorder["records"]]
        assert "PROCESS_CREATED" in stages
        assert "REQUEST_WRITE_COMPLETE" in stages
        assert "RESPONSE_DATA_RECEIVED" in stages
    finally:
        await process.close()


def test_d6a6_mode_is_protocol_round_trip() -> None:
    from uuid import uuid4

    message = SandboxMessage(uuid4(), "d6a6.fixture", "health", {}, diagnostic_mode="COMPUTE_ONLY")
    assert SandboxMessage.decode(message.encode()) == message
