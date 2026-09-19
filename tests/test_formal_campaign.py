from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest
from jarvis.acceptance.campaign import CampaignState, ConsecutiveQualificationCampaign
from jarvis.acceptance.evidence import (
    QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA,
    QualificationLifecycleEvidence,
)
from jarvis.acceptance.formal_campaign import (
    FormalCampaignError,
    FormalCampaignExecutor,
    FormalCampaignKind,
    LifecycleSubprocessEvidence,
    RealQualificationLifecycleExecutor,
    adapt_lifecycle_terminal_output,
    validate_lifecycle_record,
)
from scripts.acceptance import run_formal_campaign

SEAL = "a" * 64


def record(index: int) -> QualificationLifecycleEvidence:
    return QualificationLifecycleEvidence(
        f"run-{index}",
        "runtime-a",
        f"cap-{index}",
        f"action-{index}",
        f"pkg-{index}",
        sha256(f"package-{index}".encode()).hexdigest(),
        sha256(f"payload-{index}".encode()).hexdigest(),
        sha256(f"manifest-{index}".encode()).hexdigest(),
        "PASS",
        f"activation-{index}",
        ("CERTIFIED", "SHADOW", "CANARY", "ACTIVE"),
        True,
        f"cap-{index}",
        "OBSERVED",
        "OBSERVED",
        (f"cleanup-{index}",),
        ("CLEANUP_CONFIRMED",),
        (),
        (1000 + index,),
        True,
        1,
        1,
        0,
        True,
        "QUALIFICATION_PASS",
        evidence={
            "record_schema": QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA,
            "worker_identity": f"worker-{index}",
            "worker_compatibility_hash": sha256(f"worker-{index}".encode()).hexdigest(),
        },
        eventbus_closed=True,
    )


class FakeLifecycleExecutor:
    def __init__(self, outcomes: Sequence[QualificationLifecycleEvidence | Exception]) -> None:
        self.outcomes = tuple(outcomes)
        self.calls: list[str] = []

    def execute(self, qualification_run_id: str) -> QualificationLifecycleEvidence:
        self.calls.append(qualification_run_id)
        outcome = self.outcomes[len(self.calls) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        assert isinstance(outcome, QualificationLifecycleEvidence)
        return outcome


class SealSequence:
    def __init__(self, values: Sequence[str]) -> None:
        self.values = tuple(values)
        self.index = 0

    def __call__(self) -> str:
        value = self.values[min(self.index, len(self.values) - 1)]
        self.index += 1
        return value


def execute(
    kind: FormalCampaignKind,
    outcomes: Sequence[QualificationLifecycleEvidence | Exception],
    *,
    seal_provider: Callable[[], str] | None = None,
) -> tuple[FormalCampaignExecutor, FakeLifecycleExecutor]:
    lifecycle = FakeLifecycleExecutor(outcomes)
    campaign = ConsecutiveQualificationCampaign(
        required_success_count=kind.required_count,
        source_seal=SEAL,
        record_schema=QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA,
    )
    executor = FormalCampaignExecutor(
        campaign=campaign,
        campaign_run_id="campaign-test",
        kind=kind,
        lifecycle_executor=lifecycle,
        source_seal=SEAL,
        source_seal_provider=seal_provider or (lambda: SEAL),
        source_bound_file_count=360,
        interpreter="python312",
        base_executable="python312",
    )
    return executor, lifecycle


def test_three_successes_are_exactly_three_calls() -> None:
    executor, lifecycle = execute(FormalCampaignKind.THREE_OF_THREE, [record(i) for i in range(3)])
    result = executor.execute()
    assert result.terminal_status is CampaignState.SUCCEEDED
    assert result.attempt_count == result.accepted_count == 3
    assert len(lifecycle.calls) == 3


def test_second_lifecycle_failure_stops_without_replacement_or_retry() -> None:
    executor, lifecycle = execute(
        FormalCampaignKind.THREE_OF_THREE,
        [record(1), replace(record(2), result="EXECUTION_FAILURE"), record(3)],
    )
    result = executor.execute()
    assert result.terminal_status is CampaignState.FAILED
    assert result.first_failure == "LIFECYCLE_FAILURE"
    assert len(lifecycle.calls) == 2
    assert result.replacement_attempts == result.retry_attempts == 0


def test_third_lifecycle_failure_makes_three_calls_and_no_fourth() -> None:
    executor, lifecycle = execute(
        FormalCampaignKind.THREE_OF_THREE,
        [
            record(1),
            record(2),
            replace(record(3), result="EXECUTION_FAILURE"),
            record(4),
        ],
    )
    result = executor.execute()
    assert result.terminal_status is CampaignState.FAILED
    assert result.first_failure == "LIFECYCLE_FAILURE"
    assert result.attempt_count == 3
    assert len(lifecycle.calls) == 3


def test_first_failure_makes_one_call() -> None:
    executor, lifecycle = execute(
        FormalCampaignKind.THREE_OF_THREE,
        [replace(record(1), activation_id=None, result="EXECUTION_FAILURE"), record(2)],
    )
    result = executor.execute()
    assert result.terminal_status is CampaignState.FAILED
    assert len(lifecycle.calls) == 1


def test_source_change_before_second_attempt_stops() -> None:
    seals = SealSequence([SEAL, SEAL, "b" * 64])
    executor, lifecycle = execute(
        FormalCampaignKind.THREE_OF_THREE,
        [record(1), record(2)],
        seal_provider=seals,
    )
    result = executor.execute()
    assert result.first_failure == "SOURCE_SEAL_MISMATCH"
    assert result.attempt_count == 1
    assert len(lifecycle.calls) == 1


def test_source_change_after_lifecycle_fails_campaign() -> None:
    seals = SealSequence([SEAL, "b" * 64, "b" * 64])
    executor, lifecycle = execute(
        FormalCampaignKind.THREE_OF_THREE,
        [record(1), record(2)],
        seal_provider=seals,
    )
    result = executor.execute()
    assert result.first_failure == "SOURCE_SEAL_MISMATCH"
    assert result.accepted_count == 0
    assert len(lifecycle.calls) == 1


@pytest.mark.parametrize(
    ("field", "value", "failure"),
    [
        ("capability_id", "cap-1", "DUPLICATE_CAPABILITY"),
        ("package_id", "pkg-1", "DUPLICATE_PACKAGE"),
        ("package_hash", record(1).package_hash, "DUPLICATE_HASH"),
        ("activation_id", "activation-1", "DUPLICATE_ACTIVATION"),
    ],
)
def test_duplicate_identity_is_rejected(field: str, value: str, failure: str) -> None:
    first = record(1)
    second = record(2)
    if field == "capability_id":
        second = replace(second, capability_id=value)
    elif field == "package_id":
        second = replace(second, package_id=value)
    elif field == "package_hash":
        second = replace(second, package_hash=value)
    elif field == "activation_id":
        second = replace(second, activation_id=value)
    else:
        raise AssertionError(field)
    executor, lifecycle = execute(FormalCampaignKind.THREE_OF_THREE, [first, second, record(3)])
    result = executor.execute()
    assert result.first_failure == failure
    assert len(lifecycle.calls) == 2


@pytest.mark.parametrize(
    "bad_record",
    [
        replace(record(1), activation_id=None, result="EXECUTION_FAILURE"),
        replace(record(1), cleanup_transaction_ids=(), result="EXECUTION_FAILURE"),
        replace(record(1), cleanup_states=("CLEANUP_RUNNING",), result="EXECUTION_FAILURE"),
        replace(record(1), unresolved_recovery_receipts=("receipt",)),
        replace(record(1), runtime_closed=False),
        replace(record(1), eventbus_closed=False),
        replace(record(1), eventbus_pending_consumers=1),
    ],
)
def test_incomplete_lifecycle_evidence_is_rejected(
    bad_record: QualificationLifecycleEvidence,
) -> None:
    executor, lifecycle = execute(FormalCampaignKind.THREE_OF_THREE, [bad_record, record(2)])
    result = executor.execute()
    assert result.terminal_status is CampaignState.FAILED
    assert len(lifecycle.calls) == 1


def test_final_ten_has_exactly_ten_calls_and_no_attempt_eleven() -> None:
    executor, lifecycle = execute(
        FormalCampaignKind.FINAL_TEN, [record(index) for index in range(10)]
    )
    result = executor.execute()
    assert result.terminal_status is CampaignState.SUCCEEDED
    assert len(lifecycle.calls) == result.attempt_count == 10


def test_final_ten_failure_on_seven_stops_at_seven() -> None:
    outcomes = [record(index) for index in range(6)] + [
        replace(record(7), result="EXECUTION_FAILURE")
    ]
    executor, lifecycle = execute(FormalCampaignKind.FINAL_TEN, outcomes)
    result = executor.execute()
    assert result.terminal_status is CampaignState.FAILED
    assert result.attempt_count == 7
    assert len(lifecycle.calls) == 7


def test_final_ten_subprocess_failure_retains_attempt_evidence_without_retry() -> None:
    subprocess_evidence = LifecycleSubprocessEvidence(
        argv=("python.exe", "-m", "pytest", "lifecycle"),
        pid=7007,
        started_at="2026-09-06T20:00:00Z",
        ended_at="2026-09-06T20:00:01Z",
        returncode=1,
        stdout_path="artifacts/acceptance/attempt-7.stdout.log",
        stderr_path="artifacts/acceptance/attempt-7.stderr.log",
        stdout_sha256="a" * 64,
        stderr_sha256="b" * 64,
        terminal_output=None,
        last_completed_phase=None,
    )
    failure = FormalCampaignError(
        "SUBPROCESS_NONZERO",
        "real lifecycle exited 1",
        subprocess_evidence=subprocess_evidence,
    )
    executor, lifecycle = execute(
        FormalCampaignKind.FINAL_TEN,
        [record(index) for index in range(1, 7)] + [failure, record(8)],
    )

    result = executor.execute()

    assert result.terminal_status is CampaignState.FAILED
    assert result.first_failure == "SUBPROCESS_NONZERO"
    assert result.attempt_count == 7
    assert len(lifecycle.calls) == 7
    assert result.failed_attempt is not None
    assert result.failed_attempt["attempt"] == 7
    assert result.failed_attempt["failure_code"] == "SUBPROCESS_NONZERO"
    retained = result.failed_attempt["subprocess"]
    assert isinstance(retained, dict)
    assert retained["returncode"] == 1
    assert retained["stdout_path"] == "artifacts/acceptance/attempt-7.stdout.log"
    assert retained["stderr_path"] == "artifacts/acceptance/attempt-7.stderr.log"
    assert result.retry_attempts == result.replacement_attempts == 0


def test_adapter_rejects_malformed_terminal_output() -> None:
    with pytest.raises(FormalCampaignError, match="acquisition"):
        adapt_lifecycle_terminal_output({})


def test_real_executor_rejects_nonzero_and_timeout_without_counting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    interpreter = tmp_path / "python.exe"
    interpreter.write_bytes(b"test")
    executor = RealQualificationLifecycleExecutor(
        interpreter=interpreter,
        root=tmp_path,
        timeout_seconds=1,
    )

    class FakeProcess:
        pid = 1234
        returncode = 1

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            return "child stdout", "child stderr"

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    with pytest.raises(FormalCampaignError, match="exited") as caught:
        executor.execute("run")
    assert caught.value.subprocess_evidence is not None
    evidence = caught.value.subprocess_evidence
    assert evidence.argv[-1].endswith(
        "test_v1_production_composition_acquires_randomized_capability_and_restores_it"
    )
    assert evidence.pid == 1234
    assert evidence.returncode == 1
    assert evidence.stdout_path is not None
    assert evidence.stderr_path is not None
    assert (tmp_path / evidence.stdout_path).read_text() == "child stdout"
    assert (tmp_path / evidence.stderr_path).read_text() == "child stderr"

    def timeout(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("python", 1)

    monkeypatch.setattr(subprocess, "Popen", timeout)
    with pytest.raises(FormalCampaignError, match="hard timeout"):
        executor.execute("run")


def test_result_is_machine_serializable() -> None:
    executor, _ = execute(FormalCampaignKind.THREE_OF_THREE, [record(i) for i in range(3)])
    result = executor.execute()
    encoded = json.dumps(result.as_dict(), sort_keys=True)
    assert "formal-qualification-campaign-result-1" in encoded
    assert result.replacement_attempts == result.retry_attempts == 0


def test_validate_requires_native_worker_evidence() -> None:
    with pytest.raises(FormalCampaignError, match="worker identity"):
        validate_lifecycle_record(
            replace(record(1), evidence={"record_schema": QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA})
        )


def test_cli_injected_success_and_failures_have_exit_contract(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        run_formal_campaign.main(
            ["--campaign", "three"],
            lifecycle_executor=FakeLifecycleExecutor([record(i) for i in range(3)]),
        )
        == 0
    )
    success = json.loads(capsys.readouterr().out)
    assert success["terminal_status"] == "SUCCEEDED"

    assert (
        run_formal_campaign.main(
            ["--campaign", "three"],
            lifecycle_executor=FakeLifecycleExecutor(
                [FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", "bad terminal")]
            ),
        )
        != 0
    )
    assert json.loads(capsys.readouterr().out)["first_failure"] == "MALFORMED_TERMINAL_OUTPUT"

    assert (
        run_formal_campaign.main(
            ["--campaign", "three"],
            lifecycle_executor=FakeLifecycleExecutor(
                [FormalCampaignError("TIMEOUT", "hard timeout")]
            ),
        )
        != 0
    )
    assert json.loads(capsys.readouterr().out)["first_failure"] == "TIMEOUT"


def test_cli_seal_mismatch_is_nonzero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = 0

    def changing_seal(_root: Path) -> tuple[str, tuple[str, ...]]:
        nonlocal calls
        calls += 1
        return (SEAL if calls == 1 else "b" * 64, tuple(f"file-{i}" for i in range(360)))

    monkeypatch.setattr(run_formal_campaign, "qualification_source_seal", changing_seal)
    assert (
        run_formal_campaign.main(
            ["--campaign", "three"],
            lifecycle_executor=FakeLifecycleExecutor([record(1)]),
        )
        != 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["first_failure"] == "SOURCE_SEAL_MISMATCH"
    assert result["attempt_count"] == 0
