from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from jarvis.sandbox import (
    SandboxCleanupError,
    SandboxCleanupOutcomeUnknown,
    SandboxPaths,
    SandboxProcess,
    _pending_native_cleanup_receipts,
    _write_native_cleanup_receipt,
)
from jarvis.windows_sandbox import NativeCleanupState


@pytest.mark.asyncio
async def test_native_cleanup_failure_closes_job_before_propagation() -> None:
    class FakeProcess:
        pid = 1234
        stdin = None
        stdout = None
        returncode = 0

        def __init__(self) -> None:
            self.closed = False

        def close_streams(self) -> None:
            return

        def close(self) -> None:
            self.closed = True
            self.cleanup_error = RuntimeError("synthetic native cleanup failure")

    class FakeJob:
        def __init__(self) -> None:
            self.closed = False
            self.empty_waited = False

        async def wait_for_empty(self, timeout: float) -> bool:
            assert timeout == 2
            self.empty_waited = True
            return True

        def close(self) -> None:
            self.closed = True

    process = FakeProcess()
    job = FakeJob()
    sandbox_process: Any = object.__new__(SandboxProcess)
    sandbox_process._process = process
    sandbox_process._job = job
    sandbox_process._stderr_task = None
    sandbox_process._parent_recorder = None

    with pytest.raises(SandboxCleanupError):
        await sandbox_process._stop_locked()

    assert process.closed is True
    assert job.empty_waited is True
    assert job.closed is True
    assert sandbox_process.cleanup_observations == ()
    assert sandbox_process.cleanup_diagnostics == (
        {"stage": "JOB_EMPTY_WAIT", "state": "CONFIRMED", "job_empty": True},
        {
            "stage": "SECURITY_CLEANUP",
            "state": "UNKNOWN",
            "failure_class": "RuntimeError",
        },
        {"stage": "JOB_CLOSE", "state": "CONFIRMED"},
    )


@pytest.mark.asyncio
async def test_unknown_native_cleanup_closes_job_but_quarantines_sandbox() -> None:
    class FakeProcess:
        pid = 1234
        stdin = None
        stdout = None
        returncode = 0
        cleanup_state = NativeCleanupState.OUTCOME_UNKNOWN
        cleanup_operation_id = "cleanup-test"
        cleanup_evidence = {"cleanup_terminal": False}

        def close_streams(self) -> None:
            return

        def close(self, *, cleanup_deadline_seconds: float) -> None:
            assert cleanup_deadline_seconds == 15.0

    class FakeJob:
        async def wait_for_empty(self, timeout: float) -> bool:
            assert timeout == 2
            return True

        def close(self) -> None:
            return

    sandbox_process: Any = object.__new__(SandboxProcess)
    sandbox_process._process = FakeProcess()
    sandbox_process._job = FakeJob()
    sandbox_process._stderr_task = None
    sandbox_process._parent_recorder = None
    sandbox_process._paths = None

    with pytest.raises(SandboxCleanupOutcomeUnknown):
        await sandbox_process._stop_locked()

    assert sandbox_process._cleanup_quarantined is True
    assert sandbox_process.cleanup_observations == ()
    assert sandbox_process.cleanup_diagnostics[-3:] == (
        {"stage": "JOB_EMPTY_WAIT", "state": "CONFIRMED", "job_empty": True},
        {
            "stage": "SECURITY_CLEANUP",
            "state": "CLEANUP_OUTCOME_UNKNOWN",
            "failure_class": "SandboxCleanupOutcomeUnknown",
        },
        {"stage": "JOB_CLOSE", "state": "CONFIRMED"},
    )


def test_authoritative_receipts_are_separate_from_supplementary_diagnostics(
    tmp_path: Path,
) -> None:
    class FakeProcess:
        pid = 1234
        cleanup_operation_id = "cleanup-first"
        cleanup_evidence = {"cleanup_terminal": True}

    sandbox_process: Any = object.__new__(SandboxProcess)
    sandbox_process._paths = SandboxPaths.create(tmp_path, "cleanup-separation")
    sandbox_process._integration_id = "cleanup-separation"
    sandbox_process._recovery_integrity_signer = None
    sandbox_process._cleanup_observations = []
    sandbox_process._cleanup_diagnostics = []

    sandbox_process._record_native_cleanup_receipt(NativeCleanupState.CONFIRMED, FakeProcess())
    sandbox_process._append_cleanup_observation("JOB_CLOSE", "CONFIRMED")

    assert sandbox_process.cleanup_observations == (
        {
            "operation_id": "cleanup-first",
            "state": "CLEANUP_CONFIRMED",
            "evidence": {"cleanup_terminal": True},
        },
    )
    assert sandbox_process.cleanup_diagnostics == ({"stage": "JOB_CLOSE", "state": "CONFIRMED"},)

    sandbox_process._paths = SandboxPaths.create(tmp_path, "cleanup-separation-latest")
    FakeProcess.cleanup_operation_id = "cleanup-latest"
    sandbox_process._record_native_cleanup_receipt(NativeCleanupState.CONFIRMED, FakeProcess())
    assert sandbox_process.cleanup_observations[-1]["operation_id"] == "cleanup-latest"
    assert sandbox_process.cleanup_observations[-1]["state"] == "CLEANUP_CONFIRMED"


def test_pending_cleanup_receipt_denies_reuse_until_terminal_observation(tmp_path: Path) -> None:
    paths = SandboxPaths.create(tmp_path, "cleanup-recovery")
    _write_native_cleanup_receipt(
        paths.cleanup_receipt,
        {"schema": 1, "operation_id": "cleanup-test", "state": "CLEANUP_OUTCOME_UNKNOWN"},
    )

    assert paths.cleanup_receipt in _pending_native_cleanup_receipts(tmp_path)

    _write_native_cleanup_receipt(
        paths.cleanup_receipt,
        {"schema": 1, "operation_id": "cleanup-test", "state": "CLEANUP_CONFIRMED"},
    )

    assert _pending_native_cleanup_receipts(tmp_path) == ()
