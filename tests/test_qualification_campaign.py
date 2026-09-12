from dataclasses import replace
from hashlib import sha256

import pytest
from jarvis.acceptance.campaign import (
    CampaignError,
    CampaignState,
    ConsecutiveQualificationCampaign,
)
from jarvis.acceptance.evidence import QualificationLifecycleEvidence

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
        (),
        True,
        1,
        1,
        0,
        True,
        "QUALIFICATION_PASS",
        evidence={
            "record_schema": ConsecutiveQualificationCampaign.RECORD_SCHEMA,
            "worker_identity": "worker-a",
            "worker_compatibility_hash": "a" * 64,
        },
        eventbus_closed=True,
    )


def campaign(size: int) -> ConsecutiveQualificationCampaign:
    return ConsecutiveQualificationCampaign(
        required_success_count=size,
        source_seal=SEAL,
        record_schema=ConsecutiveQualificationCampaign.RECORD_SCHEMA,
    )


def test_three_consecutive_successes_and_two_are_not_complete() -> None:
    incomplete = campaign(3)
    incomplete.submit(record(1), source_seal=SEAL)
    incomplete.submit(record(2), source_seal=SEAL)
    assert incomplete.snapshot.state is CampaignState.RUNNING
    complete = campaign(3)
    for index in range(3):
        complete.submit(record(index), source_seal=SEAL)
    assert complete.snapshot.state is CampaignState.SUCCEEDED
    assert len(complete.records) == 3


def test_failure_stops_and_replacement_is_forbidden() -> None:
    controller = campaign(3)
    controller.submit(record(1), source_seal=SEAL)
    controller.submit(replace(record(2), result="EXECUTION_FAILURE"), source_seal=SEAL)
    assert controller.snapshot.state is CampaignState.FAILED
    with pytest.raises(CampaignError, match="replacement"):
        controller.submit(record(3), source_seal=SEAL)


def test_missing_activation_fails_closed() -> None:
    controller = campaign(3)
    controller.submit(
        replace(record(1), activation_id=None, result="EXECUTION_FAILURE"),
        source_seal=SEAL,
    )
    assert controller.snapshot.failure_code == "MISSING_ACTIVATION"


def test_missing_cleanup_fails_closed() -> None:
    controller = campaign(3)
    controller.submit(replace(record(1), cleanup_states=()), source_seal=SEAL)
    assert controller.snapshot.failure_code == "MISSING_CLEANUP"


def test_unresolved_recovery_fails_closed() -> None:
    controller = campaign(3)
    controller.submit(
        replace(record(1), unresolved_recovery_receipts=("receipt",)),
        source_seal=SEAL,
    )
    assert controller.snapshot.failure_code == "UNRESOLVED_RECOVERY"


def test_seal_duplicate_and_eleven_attempt_rules() -> None:
    mismatch = campaign(3)
    mismatch.submit(record(1), source_seal="b" * 64)
    assert mismatch.snapshot.failure_code == "SOURCE_SEAL_MISMATCH"
    duplicate = campaign(3)
    duplicate.submit(record(1), source_seal=SEAL)
    duplicate.submit(record(1), source_seal=SEAL)
    assert duplicate.snapshot.failure_code == "DUPLICATE_CAPABILITY"
    eleven = campaign(10)
    for index in range(9):
        eleven.submit(record(index), source_seal=SEAL)
    eleven.submit(replace(record(9), result="EXECUTION_FAILURE"), source_seal=SEAL)
    assert eleven.snapshot.state is CampaignState.FAILED
    with pytest.raises(CampaignError):
        eleven.submit(record(10), source_seal=SEAL)


def test_campaign_rejects_incomplete_or_nonterminal_records() -> None:
    controller = campaign(3)
    controller.submit(replace(record(1), evidence={"record_schema": "wrong"}), source_seal=SEAL)
    assert controller.snapshot.failure_code == "RECORD_SCHEMA_MISMATCH"

    controller = campaign(3)
    controller.submit(
        replace(record(1), cleanup_states=("CLEANUP_RUNNING",), result="EXECUTION_FAILURE"),
        source_seal=SEAL,
    )
    assert controller.snapshot.failure_code == "CLEANUP_NOT_TERMINAL"

    controller = campaign(3)
    controller.submit(replace(record(1), result="EXECUTION_FAILURE"), source_seal=SEAL)
    assert controller.snapshot.failure_code == "LIFECYCLE_FAILURE"

    controller = campaign(3)
    controller.submit(record(1), source_seal=SEAL)
    controller.submit(replace(record(1), package_id="pkg-unique"), source_seal=SEAL)
    assert controller.snapshot.failure_code == "DUPLICATE_CAPABILITY"


def test_campaign_rejects_bad_constructor_and_terminal_submission() -> None:
    with pytest.raises(CampaignError):
        ConsecutiveQualificationCampaign(
            required_success_count=True,
            source_seal=SEAL,
            record_schema=ConsecutiveQualificationCampaign.RECORD_SCHEMA,
        )
    with pytest.raises(CampaignError):
        ConsecutiveQualificationCampaign(
            required_success_count=1,
            source_seal="",
            record_schema=ConsecutiveQualificationCampaign.RECORD_SCHEMA,
        )
    with pytest.raises(CampaignError):
        ConsecutiveQualificationCampaign(
            required_success_count=0,
            source_seal=SEAL,
            record_schema=ConsecutiveQualificationCampaign.RECORD_SCHEMA,
        )
    with pytest.raises(CampaignError):
        ConsecutiveQualificationCampaign(
            required_success_count=1,
            source_seal=SEAL,
            record_schema="unsupported",
        )
    controller = campaign(1)
    controller.submit(record(1), source_seal=SEAL)
    with pytest.raises(CampaignError, match="terminal"):
        controller.submit(record(2), source_seal=SEAL)


def test_campaign_rejects_incomplete_and_missing_cleanup_records() -> None:
    controller = campaign(2)
    controller.submit(object(), source_seal=SEAL)  # type: ignore[arg-type]
    assert controller.snapshot.failure_code == "INCOMPLETE_EVIDENCE"

    controller = campaign(2)
    controller.submit(
        replace(record(1), cleanup_transaction_ids=(), result="EXECUTION_FAILURE"),
        source_seal=SEAL,
    )
    assert controller.snapshot.failure_code == "MISSING_CLEANUP"

    controller = campaign(2)
    controller.submit(record(1), source_seal=SEAL)
    controller.submit(replace(record(2), package_id="pkg-1"), source_seal=SEAL)
    assert controller.snapshot.failure_code == "DUPLICATE_PACKAGE"


def test_campaign_accepts_explicit_confirmed_cleanup_failure_as_terminal() -> None:
    controller = campaign(1)
    result = controller.submit(
        replace(record(1), cleanup_states=("CLEANUP_FAILED_CONFIRMED",)),
        source_seal=SEAL,
    )
    assert result.state is CampaignState.SUCCEEDED


@pytest.mark.parametrize(
    ("invalid_state", "failure"),
    [
        ("certification", "CERTIFICATION_NOT_PASS"),
        ("activation", "INCOMPLETE_ACTIVATION"),
        ("runtime", "RUNTIME_NOT_CLOSED"),
        ("eventbus", "EVENTBUS_NOT_CLOSED"),
        ("pending", "OWNED_PENDING_TASKS"),
    ],
)
def test_campaign_rejects_invalid_authority_lifecycle_state(
    invalid_state: str, failure: str
) -> None:
    controller = campaign(1)
    if invalid_state == "certification":
        invalid = replace(record(1), certification_result="FAIL")
    elif invalid_state == "activation":
        invalid = replace(record(1), active=False)
    elif invalid_state == "runtime":
        invalid = replace(record(1), runtime_closed=False)
    elif invalid_state == "eventbus":
        invalid = replace(record(1), eventbus_closed=False)
    else:
        assert invalid_state == "pending"
        invalid = replace(record(1), eventbus_pending_consumers=1)
    controller.submit(invalid, source_seal=SEAL)
    assert controller.snapshot.failure_code == failure


def test_campaign_rejects_duplicate_run_identity() -> None:
    controller = campaign(2)
    controller.submit(record(1), source_seal=SEAL)
    controller.submit(replace(record(2), qualification_run_id="run-1"), source_seal=SEAL)
    assert controller.snapshot.failure_code == "DUPLICATE_RUN"


def test_campaign_abort_and_fail_closed_are_terminal_and_validated() -> None:
    aborted = campaign(1)
    assert aborted.abort("ABORTED").failure_code == "ABORTED"
    with pytest.raises(CampaignError, match="terminal"):
        aborted.abort("AGAIN")
    with pytest.raises(CampaignError, match="malformed"):
        campaign(1).abort("")

    failed = campaign(1)
    failed.submit(replace(record(1), result="EXECUTION_FAILURE"), source_seal=SEAL)
    assert failed.fail_closed("SOURCE_CHANGED").failure_code == "LIFECYCLE_FAILURE"

    completed = campaign(1)
    completed.submit(record(1), source_seal=SEAL)
    assert completed.fail_closed("SOURCE_CHANGED").failure_code == "SOURCE_CHANGED"
    with pytest.raises(CampaignError, match="malformed"):
        campaign(1).fail_closed("")
