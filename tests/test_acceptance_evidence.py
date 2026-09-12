import asyncio
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import jarvis.acceptance.evidence as evidence_module
import pytest
from jarvis.acceptance.evidence import (
    ClipboardObservation,
    ClipboardObservationStatus,
    HostSideEffectMonitor,
    QualificationEvidenceError,
    QualificationLifecycleEvidence,
    QualificationPairBudget,
    QualificationPairProgress,
    QualificationPairTimeoutError,
    QualificationTerminalFailure,
    _emit_lifecycle_progress,
    _qualification_failure_snapshot,
    _raise_for_terminal_result,
    collect_qualification_failure,
    collect_qualification_lifecycle,
    derive_pair_budget,
    qualification_source_manifest,
    qualification_source_seal,
    run_same_runtime_pair,
    serialize_lifecycle_evidence,
    source_binding_fingerprint,
    utc_artifact_timestamp,
    validate_same_runtime_pair,
    write_json,
)
from jarvis.acceptance.models import AcceptanceStatus
from jarvis.ai.models import GenerationRequest, GenerationResult
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderDefinition,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.core.config import Settings
from jarvis.credentials import TestOnlyInMemorySecretBackend
from jarvis.goal_supervisor import GoalIntent, RegistryGoalAnalyzer
from jarvis.runtime import ApplicationRuntime

from tests.fakes import FakeAIProvider


class _QueuedProvider(FakeAIProvider):
    def __init__(self, responses: tuple[str, ...]) -> None:
        super().__init__()
        self._responses = list(responses)

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        self.requests.append(request)
        if not self._responses:
            raise AssertionError("queued pair provider was exhausted")
        return GenerationResult(content=self._responses.pop(0), model=request.model)


def _pair_response(suffix: str) -> str:
    action = f"transform-{suffix}"
    return json.dumps(
        {
            "kind": "response",
            "content": json.dumps(
                {
                    "name": f"Pair capability {suffix}",
                    "description": "A bounded qualification capability",
                    "actions": [
                        {
                            "action_id": action,
                            "semantic_name": "Transform pair input",
                            "description": "Transform bounded pair input",
                            "input_schema": {
                                "type": "object",
                                "properties": {
                                    "value": {"type": "string"},
                                    "salt": {"type": "string"},
                                },
                                "required": ["value", "salt"],
                                "additionalProperties": False,
                            },
                            "output_schema": {
                                "type": "object",
                                "properties": {"result": {"type": "string"}},
                                "required": ["result"],
                                "additionalProperties": False,
                            },
                            "effect": {
                                "classification": "observation",
                                "reversibility": "read_only",
                            },
                            "permissions": [],
                            "verification": ["adapter_output_schema", "action_completed"],
                            "operation": "concat_strings",
                            "fields": ["value", "salt"],
                            "delimiter": "|",
                        }
                    ],
                },
                sort_keys=True,
            ),
        },
        sort_keys=True,
    )


def _lifecycle(
    *,
    runtime: str = "runtime-a",
    capability: str = "cap-a",
    package: str = "pkg-a",
    activation: str | None = "activation-a",
    activation_states: tuple[str, ...] = ("CERTIFIED", "ACTIVE"),
    result: str = "QUALIFICATION_PASS",
    cleanup: tuple[str, ...] = ("cleanup-a",),
) -> QualificationLifecycleEvidence:
    return QualificationLifecycleEvidence(
        "qualification-a",
        runtime,
        capability,
        "action-" + capability,
        package,
        sha256((capability + package).encode()).hexdigest(),
        sha256((capability + package + "payload").encode()).hexdigest(),
        sha256((capability + package + "manifest").encode()).hexdigest(),
        "PASS",
        activation,
        activation_states,
        result == "QUALIFICATION_PASS",
        capability,
        "OBSERVED",
        "NOT_CAPTURED",
        cleanup,
        ("CLEANUP_CONFIRMED",) if cleanup else (),
        (),
        (123,),
        True,
        1,
        1,
        0,
        False,
        result,
    )


def test_qualification_evidence_requires_activation_and_cleanup() -> None:
    with pytest.raises(QualificationEvidenceError):
        _lifecycle(activation=None)
    with pytest.raises(QualificationEvidenceError):
        _lifecycle(cleanup=())


def test_failure_evidence_is_not_promoted_to_qualification_pass() -> None:
    evidence = _lifecycle(activation=None, result="EXECUTION_FAILURE", cleanup=())
    assert evidence.result == "EXECUTION_FAILURE"
    assert evidence.activation_id is None
    assert evidence.cleanup_transaction_ids == ()


def test_same_runtime_pair_rejects_substitution_and_pending_consumers() -> None:
    first = _lifecycle()
    second = _lifecycle(capability="cap-b", package="pkg-b", activation="activation-b")
    passed = validate_same_runtime_pair(first, second, pending_event_consumers=0)
    assert passed["result"] == "PASS"
    blocked = validate_same_runtime_pair(
        first,
        second,
        pending_event_consumers=1,
        unexpected_event_consumers=1,
    )
    assert blocked["result"] == "NOT_PROVEN"
    different_runtime = _lifecycle(
        runtime="runtime-b",
        capability="cap-b",
        package="pkg-b",
        activation="activation-b",
    )
    assert (
        validate_same_runtime_pair(first, different_runtime, pending_event_consumers=0)["result"]
        == "NOT_PROVEN"
    )


def test_ten_record_serialization_preserves_exact_lifecycle_evidence() -> None:
    records = tuple(
        _lifecycle(
            capability=f"cap-{index}",
            package=f"pkg-{index}",
            activation=f"activation-{index}",
            cleanup=(f"cleanup-{index}",),
        )
        for index in range(10)
    )
    encoded = serialize_lifecycle_evidence(records)
    assert encoded.count('"activation_id":"activation-') == 10
    assert encoded.count('"cleanup_transaction_ids":["cleanup-') == 10
    assert all(record.package_hash in encoded for record in records)


def test_pair_budget_is_two_lifecycles_and_finite() -> None:
    budget = derive_pair_budget(
        120.0,
        setup_seconds=10.0,
        between_run_evidence_seconds=5.0,
        runtime_close_seconds=7.0,
        scheduling_margin_seconds=3.0,
    )
    assert budget.hard_deadline_seconds == 265.0
    assert budget.hard_deadline_seconds > 120.0


def test_pair_budget_rejects_nonfinite_and_nonpositive_values() -> None:
    with pytest.raises(QualificationEvidenceError, match="malformed"):
        QualificationPairBudget(float("nan"), 1.0, 1.0, 1.0, 1.0)
    with pytest.raises(QualificationEvidenceError, match="positive"):
        QualificationPairBudget(1.0, 0.0, 1.0, 1.0, 1.0)


def test_lifecycle_evidence_rejects_incomplete_identity_and_nonterminal_cleanup() -> None:
    with pytest.raises(QualificationEvidenceError, match="identity"):
        _lifecycle().__class__(
            "",
            "runtime-a",
            "cap-a",
            "action-cap-a",
            "pkg-a",
            "hash",
            "payload",
            "manifest",
            "PASS",
            "activation-a",
            ("ACTIVE",),
            True,
            "cap-a",
            "OBSERVED",
            "OBSERVED",
            ("cleanup-a",),
            ("CLEANUP_CONFIRMED",),
            (),
            (),
            True,
            1,
            1,
            0,
            True,
            "QUALIFICATION_PASS",
        )
    with pytest.raises(QualificationEvidenceError, match="terminal"):
        _lifecycle(cleanup=("cleanup-a",)).__class__(
            "qualification-a",
            "runtime-a",
            "cap-a",
            "action-cap-a",
            "pkg-a",
            sha256(b"package").hexdigest(),
            sha256(b"payload").hexdigest(),
            sha256(b"manifest").hexdigest(),
            "PASS",
            "activation-a",
            ("ACTIVE",),
            True,
            "cap-a",
            "OBSERVED",
            "OBSERVED",
            ("cleanup-a",),
            ("CLEANUP_RUNNING",),
            (),
            (),
            True,
            1,
            1,
            0,
            True,
            "QUALIFICATION_PASS",
        )


def test_pair_validation_reports_each_contamination_dimension() -> None:
    first = _lifecycle()
    second = replace(first, runtime_instance_id="runtime-b", active=False)
    checks = validate_same_runtime_pair(
        first,
        second,
        pending_event_consumers=-1,
        unresolved_recovery_receipts=("receipt",),
        unexpected_event_consumers=1,
    )["checks"]
    assert isinstance(checks, dict)
    assert not checks["same_runtime"]
    assert not checks["independent_capabilities"]
    assert not checks["independent_packages"]
    assert not checks["independent_hashes"]
    assert not checks["independent_certification"]
    assert not checks["independent_payloads"]
    assert not checks["independent_activations"]
    assert not checks["both_active"]
    assert not checks["distinct_registry_records"]
    assert not checks["expected_shared_event_consumers"]
    assert not checks["no_unexpected_event_consumers"]
    assert not checks["no_unresolved_recovery"]


def test_serialization_and_failed_projection_reject_missing_inputs() -> None:
    with pytest.raises(QualificationEvidenceError, match="records"):
        serialize_lifecycle_evidence(cast(Sequence[QualificationLifecycleEvidence], "not-records"))
    with pytest.raises(QualificationEvidenceError, match="identity"):
        collect_qualification_failure(
            SimpleNamespace(last_run=None),
            qualification_run_id="failure",
            failure_stage="CERTIFYING",
            typed_failure_code="CERTIFICATION_FAILED",
        )
    failed = collect_qualification_failure(
        SimpleNamespace(
            last_run=SimpleNamespace(
                package_hash="a" * 64,
                package_id=None,
                capability_id=None,
            )
        ),
        qualification_run_id="failure",
        failure_stage="CERTIFYING",
        typed_failure_code="CERTIFICATION_FAILED",
    )
    assert failed.result == "EXECUTION_FAILURE"
    assert failed.package_id == "NOT_AVAILABLE"


@pytest.mark.asyncio
async def test_pair_success_emits_terminal_acquisition_and_runtime_stages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = iter(
        (
            _lifecycle(activation_states=("CERTIFIED", "SHADOW", "CANARY", "ACTIVE")),
            _lifecycle(
                capability="cap-b",
                package="pkg-b",
                activation="activation-b",
                activation_states=("CERTIFIED", "SHADOW", "CANARY", "ACTIVE"),
            ),
        )
    )
    monkeypatch.setattr(
        evidence_module,
        "collect_qualification_lifecycle",
        lambda _container, *, qualification_run_id: next(records),
    )
    container = SimpleNamespace(
        runtime_instance_id="runtime-a",
        event_bus=SimpleNamespace(pending_consumer_count=0, closed=False),
        capability_acquisition=SimpleNamespace(last_run=None),
        closed=False,
    )
    progress: list[str] = []

    async def close_runtime() -> None:
        container.closed = True
        container.event_bus.closed = True

    result = await run_same_runtime_pair(
        container,
        first_request=object(),
        second_request=object(),
        acquire=lambda _request: asyncio.sleep(0, result=object()),
        qualification_run_id="success-control",
        progress_callback=lambda item: progress.append(item.stage),
        close_runtime=close_runtime,
    )
    assert result["result"] == "PASS"
    assert progress == [
        "PAIR_RUNTIME_CREATED",
        "A_PREPARATION_STARTED",
        "A_PREPARATION_TERMINAL",
        "A_PACKAGE_CREATED",
        "A_CERTIFICATION_TERMINAL",
        "A_SHADOW_TERMINAL",
        "A_CANARY_TERMINAL",
        "A_ACTIVATION_TERMINAL",
        "A_CLEANUP_TERMINAL",
        "BETWEEN_RUN_TERMINALITY",
        "B_PREPARATION_STARTED",
        "B_PREPARATION_TERMINAL",
        "B_PACKAGE_CREATED",
        "B_CERTIFICATION_TERMINAL",
        "B_SHADOW_TERMINAL",
        "B_CANARY_TERMINAL",
        "B_ACTIVATION_TERMINAL",
        "B_CLEANUP_TERMINAL",
        "RUNTIME_CLOSE_STARTED",
        "RUNTIME_CLOSED",
        "EVENTBUS_CLOSED",
        "PAIR_TERMINAL",
    ]


def test_host_side_effect_evidence_is_bounded_and_observation_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        HostSideEffectMonitor,
        "_clipboard_digest",
        staticmethod(lambda: ClipboardObservation(ClipboardObservationStatus.SNAPSHOT_OK, 1)),
    )
    monkeypatch.setattr(HostSideEffectMonitor, "_foreground_window", staticmethod(lambda: None))
    monkeypatch.setattr(HostSideEffectMonitor, "_cursor_position", staticmethod(lambda: None))
    monkeypatch.setattr(HostSideEffectMonitor, "_processes", staticmethod(lambda: {1}))
    monkeypatch.setattr(HostSideEffectMonitor, "_gui_processes", staticmethod(lambda: ()))
    monitor = HostSideEffectMonitor(tmp_path)
    monitor.snapshot()
    (tmp_path / "owned.txt").write_text("bounded", encoding="utf-8")
    evidence = monitor.evidence("run", "test", "control")
    assert evidence.result.value == "PASS"
    assert evidence.observed_state["host_filesystem_mutation"] == "OBSERVED_CHANGE"


def test_clipboard_observation_uses_pointer_free_sequence_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Function:
        def __init__(self, result: int) -> None:
            self.result = result
            self.argtypes: object = None
            self.restype: object = None

        def __call__(self) -> int:
            return self.result

    sequence = _Function(123)

    class _User32:
        GetClipboardSequenceNumber = sequence

    evidence_private = cast(Any, evidence_module)
    monkeypatch.setattr(evidence_private.os, "name", "nt")
    monkeypatch.setattr(evidence_private.ctypes, "WinDLL", lambda *args, **kwargs: _User32())
    observation = HostSideEffectMonitor._clipboard_digest()  # noqa: SLF001

    assert observation == ClipboardObservation(
        ClipboardObservationStatus.SNAPSHOT_OK, sequence_number=123
    )
    assert sequence.argtypes == ()
    assert sequence.restype is evidence_private.wintypes.DWORD


@pytest.mark.parametrize(
    ("sequence", "status"),
    [
        (0, ClipboardObservationStatus.UNAVAILABLE),
        (None, ClipboardObservationStatus.NATIVE_ERROR),
    ],
)
def test_clipboard_observation_fail_closed_for_unavailable_or_native_error(
    monkeypatch: pytest.MonkeyPatch,
    sequence: int | None,
    status: ClipboardObservationStatus,
) -> None:
    class _Function:
        argtypes: object = None
        restype: object = None

        def __call__(self) -> int:
            if sequence is None:
                raise OSError("clipboard API unavailable")
            return sequence

    class _User32:
        GetClipboardSequenceNumber = _Function()

    evidence_private = cast(Any, evidence_module)
    monkeypatch.setattr(evidence_private.os, "name", "nt")
    monkeypatch.setattr(evidence_private.ctypes, "WinDLL", lambda *args, **kwargs: _User32())
    observation = HostSideEffectMonitor._clipboard_digest()  # noqa: SLF001

    assert observation.status is status


def test_clipboard_unknown_is_not_interpreted_as_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observations = iter(
        (
            ClipboardObservation(ClipboardObservationStatus.SNAPSHOT_OK, 1),
            ClipboardObservation(ClipboardObservationStatus.UNAVAILABLE),
        )
    )
    monkeypatch.setattr(
        HostSideEffectMonitor,
        "_clipboard_digest",
        staticmethod(lambda: next(observations)),
    )
    monkeypatch.setattr(HostSideEffectMonitor, "_foreground_window", staticmethod(lambda: None))
    monkeypatch.setattr(HostSideEffectMonitor, "_cursor_position", staticmethod(lambda: None))
    monkeypatch.setattr(HostSideEffectMonitor, "_processes", staticmethod(lambda: {1}))
    monkeypatch.setattr(HostSideEffectMonitor, "_gui_processes", staticmethod(lambda: ()))
    monitor = HostSideEffectMonitor(tmp_path)
    monitor.snapshot()
    after = monitor.snapshot()
    evidence = monitor.evidence("run", "test", "control", after=after)

    assert evidence.result is AcceptanceStatus.UNKNOWN_OUTCOME
    assert evidence.observed_state["clipboard_mutation"] == "NOT_PROVEN"


@pytest.mark.parametrize(
    ("second_sequence", "expected_mutation"),
    [(1, "NONE"), (2, "OBSERVED_CHANGE")],
)
def test_clipboard_sequence_comparison_detects_change_without_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    second_sequence: int,
    expected_mutation: str,
) -> None:
    observations = iter(
        (
            ClipboardObservation(ClipboardObservationStatus.SNAPSHOT_OK, 1),
            ClipboardObservation(ClipboardObservationStatus.SNAPSHOT_OK, second_sequence),
        )
    )
    monkeypatch.setattr(
        HostSideEffectMonitor,
        "_clipboard_digest",
        staticmethod(lambda: next(observations)),
    )
    monkeypatch.setattr(HostSideEffectMonitor, "_foreground_window", staticmethod(lambda: None))
    monkeypatch.setattr(HostSideEffectMonitor, "_cursor_position", staticmethod(lambda: None))
    monkeypatch.setattr(HostSideEffectMonitor, "_processes", staticmethod(lambda: {1}))
    monkeypatch.setattr(HostSideEffectMonitor, "_gui_processes", staticmethod(lambda: ()))
    monitor = HostSideEffectMonitor(tmp_path)
    monitor.snapshot()
    evidence = monitor.evidence("run", "test", "control", after=monitor.snapshot())

    assert evidence.observed_state["clipboard_mutation"] == expected_mutation
    assert evidence.result is (
        AcceptanceStatus.FAIL if expected_mutation == "OBSERVED_CHANGE" else AcceptanceStatus.PASS
    )


@pytest.mark.asyncio
async def test_pair_hard_deadline_is_not_extended_by_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import jarvis.acceptance.evidence as evidence_module

    records = iter((_lifecycle(), _lifecycle(capability="cap-b", package="pkg-b")))
    monkeypatch.setattr(
        evidence_module,
        "collect_qualification_lifecycle",
        lambda _container, *, qualification_run_id: next(records),
    )
    progress: list[str] = []

    async def slow_acquire(_request: object) -> object:
        await asyncio.sleep(0.05)
        progress.append("authoritative-acquire-returned")
        return object()

    with pytest.raises(QualificationPairTimeoutError) as timeout:
        await run_same_runtime_pair(
            object(),
            first_request=object(),
            second_request=object(),
            acquire=slow_acquire,
            qualification_run_id="timeout-control",
            budget=derive_pair_budget(
                0.01,
                setup_seconds=0.01,
                between_run_evidence_seconds=0.01,
                runtime_close_seconds=0.01,
                scheduling_margin_seconds=0.01,
            ),
            progress_callback=lambda item: progress.append(item.stage),
        )
    assert "PAIR_RUNTIME_CREATED" in progress
    assert "B_PREPARATION_STARTED" not in progress
    assert "eventbus_pending_consumers" in timeout.value.evidence


@pytest.mark.asyncio
async def test_pair_terminal_failure_is_typed_and_closes_runtime() -> None:
    closed = False

    async def close_runtime() -> None:
        nonlocal closed
        closed = True

    class FailedState:
        status = "FAILED"

    async def failed_acquire(_request: object) -> FailedState:
        return FailedState()

    with pytest.raises(QualificationTerminalFailure) as failure:
        await run_same_runtime_pair(
            object(),
            first_request=object(),
            second_request=object(),
            acquire=failed_acquire,
            qualification_run_id="terminal-failure-control",
            close_runtime=close_runtime,
        )
    assert failure.value.failure_stage == "A_FAILED"
    assert failure.value.typed_failure_code == "FAILED"
    assert closed


@pytest.mark.asyncio
@pytest.mark.real_qualification
async def test_real_same_runtime_pair_control(tmp_path: Path) -> None:
    suffix_a = "a-" + sha256(os.urandom(8)).hexdigest()[:8]
    suffix_b = "b-" + sha256(os.urandom(8)).hexdigest()[:8]
    responses = (_pair_response(suffix_a), _pair_response(suffix_b))
    provider = _QueuedProvider(responses)
    provider_registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("synthetic-pair", "Synthetic pair provider", "1", True),
                lambda _configuration: provider,
                (ModelMetadata("synthetic-pair-model", 4096, frozenset({"structured_output"})),),
            ),
        )
    )
    runtime = ApplicationRuntime.create(
        Settings(
            environment="production",
            app_data_dir=tmp_path / "pair-data",
            ai_provider="synthetic-pair",
            ai_model="synthetic-pair-model",
            _env_file=None,
        ),
        provider_registry=provider_registry,
        recovery_key_backend=TestOnlyInMemorySecretBackend(),
        certification_oracle=lambda action, action_input: {
            "result": f"{action_input['value']}|{action_input['salt']}"
            if action.action_id.startswith("transform-")
            else "observed"
        },
    )
    assert runtime.container is not None
    container = runtime.container
    intents = (
        GoalIntent(
            f"perform pair capability {suffix_a}",
            required_capabilities=(f"synthetic-capability-{suffix_a}",),
            metadata={
                "generated_action_input": {"value": f"input-{suffix_a}", "salt": "salt-a"},
                "generated_expected_output": f"input-{suffix_a}|salt-a",
            },
        ),
        GoalIntent(
            f"perform pair capability {suffix_b}",
            required_capabilities=(f"synthetic-capability-{suffix_b}",),
            metadata={
                "generated_action_input": {"value": f"input-{suffix_b}", "salt": "salt-b"},
                "generated_expected_output": f"input-{suffix_b}|salt-b",
            },
        ),
    )

    async def acquire(intent: object) -> object:
        assert isinstance(intent, GoalIntent)
        analysis = await RegistryGoalAnalyzer().analyze(
            intent, cast(Any, container).capability_registry
        )
        research = await cast(Any, container).capability_acquisition.research(intent, analysis)
        assert research.acquisition is not None
        report = await cast(Any, container).capability_acquisition.acquire(research.acquisition)
        assert report.active, report.detail
        assert report.stage == "active"
        return report

    progress: list[dict[str, object]] = []

    def capture_progress(item: QualificationPairProgress) -> None:
        progress.append(
            {
                "stage": item.stage,
                "monotonic_seconds": item.monotonic_seconds,
                "interpreter": sys.executable,
                "base_executable": getattr(sys, "_base_executable", sys.executable),
            }
        )

    try:
        pair = await run_same_runtime_pair(
            container,
            first_request=intents[0],
            second_request=intents[1],
            acquire=acquire,
            qualification_run_id="same-runtime-pair-control",
            budget=derive_pair_budget(120.0),
            progress_callback=capture_progress,
            close_runtime=runtime.aclose,
        )
    except QualificationPairTimeoutError:
        print(
            "R4R_PAIR_TIMEOUT "
            + json.dumps(
                {
                    "sys_executable": sys.executable,
                    "base_executable": getattr(sys, "_base_executable", sys.executable),
                    "pytest_executable": sys.argv[0],
                    "progress": progress,
                    "last_authoritative_stage": progress[-1]["stage"] if progress else None,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        raise
    else:
        assert pair["result"] == "PASS", pair
        first = pair["A"]
        second = pair["B"]
        assert isinstance(first, dict) and isinstance(second, dict)
        assert first["runtime_instance_id"] == second["runtime_instance_id"]
        assert first["activation_id"] != second["activation_id"]
        assert first["package_hash"] != second["package_hash"]
        print(
            "R4R_PAIR_RESULT "
            + json.dumps(
                {"pair": pair, "progress": progress},
                sort_keys=True,
            ),
            flush=True,
        )
        artifact_target = os.environ.get("JARVIS_R4R_D6B2R3R1_ARTIFACT")
    finally:
        await runtime.aclose()
    assert container.closed
    assert container.event_bus.closed
    assert container.event_bus.pending_consumer_count == 0
    if artifact_target:
        from jarvis.acceptance.evidence import qualification_source_seal, write_json

        seal, manifest = qualification_source_seal(Path.cwd())
        write_json(
            Path(artifact_target),
            {
                "schema": "r4r-d6b2r3b-1",
                "run_id": "R4R-D6B2R3B",
                "source_identity": {
                    "branch": "agent/v1-integration",
                    "head": "77eaa48ea9370b792e9df51f2a43e1853873a0b8",
                    "version": "1.0.0",
                    "candidate": "15 NOT_CREATED",
                },
                "starting_source_seal": {
                    "sha256": "4c21a1655f265b55c2ed70d8e6b2494687fd88b89fb94de9e08d367653eff724",
                    "bound_file_count": 345,
                },
                "final_source_seal": {"sha256": seal, "bound_file_count": len(manifest)},
                "pair_fixture": {
                    "architecture": (
                        "one caller-owned ApplicationRuntime and RuntimeContainer; "
                        "two sequential GoalIntent acquisitions; distinct queued "
                        "typed model responses"
                    ),
                    "shared_runtime_id": first["runtime_instance_id"],
                },
                "A": first,
                "between_run_residue": {
                    "pending_event_consumers": 0,
                    "unexpected_event_consumers": 0,
                    "unresolved_recovery_receipts": [],
                },
                "B": second,
                "cross_contamination": pair["checks"],
                "runtime_close": {
                    "container_closed": container.closed,
                    "event_bus_closed": container.event_bus.closed,
                    "pending_consumers_after_close": container.event_bus.pending_consumer_count,
                },
                "pair_progress": progress,
                "artifact_exporter_regression": "PASS",
                "ten_record_serialization": "PASS",
                "missing_evidence_fail_closed": "PASS",
                "eligibility": "HARNESS_VALIDATION_ONLY; FRESH_B2R3_REQUIRED",
                "result": "HARNESS_VALIDATION_PASS",
            },
        )


def test_artifact_timestamp_does_not_convert_date_only_to_midnight() -> None:
    moment = datetime(2026, 9, 5, 10, 44, 24, 842551, tzinfo=UTC)
    assert utc_artifact_timestamp(moment) == "20260905T104424Z"


def test_midnight_timestamp_is_allowed_when_capture_is_actually_midnight() -> None:
    assert utc_artifact_timestamp(datetime(2026, 9, 5, tzinfo=UTC)) == "20260905T000000Z"


def test_artifact_timestamp_rejects_naive_wall_time() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        utc_artifact_timestamp(datetime(2026, 9, 5, 10))


def test_source_binding_excludes_artifact_filename(tmp_path: Path) -> None:
    source = tmp_path / "source.py"
    source.write_text("source", encoding="utf-8")
    first = source_binding_fingerprint(tmp_path, ("source.py",))
    (tmp_path / "evidence-20260905T104424Z.json").write_text("one", encoding="utf-8")
    second = source_binding_fingerprint(tmp_path, ("source.py",))
    assert first == second


def test_qualification_source_seal_binds_paths_and_excludes_generated_artifacts(
    tmp_path: Path,
) -> None:
    (tmp_path / "jarvis").mkdir()
    (tmp_path / "scripts" / "acceptance").mkdir(parents=True)
    (tmp_path / "tests").mkdir()
    (tmp_path / "jarvis" / "core.py").write_text("one", encoding="utf-8")
    (tmp_path / "scripts" / "acceptance" / "run.py").write_text("two", encoding="utf-8")
    (tmp_path / "tests" / "test_core.py").write_text("three", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[tool.test]", encoding="utf-8")
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts" / "generated.json").write_text("ignored", encoding="utf-8")

    first, paths = qualification_source_seal(tmp_path)
    assert paths == qualification_source_manifest(tmp_path)
    assert "artifacts/generated.json" not in paths
    (tmp_path / "artifacts" / "generated.json").write_text("changed", encoding="utf-8")
    second, _ = qualification_source_seal(tmp_path)
    assert first == second

    (tmp_path / "jarvis" / "core.py").write_text("changed", encoding="utf-8")
    third, _ = qualification_source_seal(tmp_path)
    assert third != first


def _projection_container(*, diagnostics: tuple[dict[str, object], ...] = ()) -> object:
    action = SimpleNamespace(
        capability_id="cap-projection",
        action_id="action-projection",
    )
    package = SimpleNamespace(
        package_id="pkg-projection",
        package_hash="a" * 64,
        action_specs=(action,),
    )
    run = SimpleNamespace(
        capability_id="cap-projection",
        package_id="pkg-projection",
        package_hash="a" * 64,
        package_version="1.0.0",
        activation=SimpleNamespace(
            activation_id="activation-projection",
            state=SimpleNamespace(value="ACTIVE"),
            history=(
                SimpleNamespace(to_state=SimpleNamespace(value="CERTIFIED")),
                SimpleNamespace(to_state=SimpleNamespace(value="SHADOW")),
                SimpleNamespace(to_state=SimpleNamespace(value="CANARY")),
                SimpleNamespace(to_state=SimpleNamespace(value="ACTIVE")),
            ),
        ),
        certification=SimpleNamespace(
            manifest_hash="b" * 64,
            stages=(SimpleNamespace(passed=True),),
        ),
        stage=SimpleNamespace(value="active"),
    )
    return SimpleNamespace(
        runtime_instance_id="runtime-projection",
        capability_acquisition=SimpleNamespace(last_run=run),
        package_store=SimpleNamespace(
            load=lambda *_args: package,
            source_files=lambda _package: (SimpleNamespace(content="payload"),),
        ),
        capability_registry=SimpleNamespace(
            inspect=lambda _capability_id: SimpleNamespace(capability_id="cap-projection")
        ),
        production_sandbox=SimpleNamespace(
            protocol_diagnostic_history=lambda: diagnostics,
            status=lambda: SimpleNamespace(executable_isolation=True, max_processes=1),
        ),
        event_bus=SimpleNamespace(pending_consumer_count=0),
        closed=True,
    )


def test_lifecycle_projection_retains_typed_diagnostics_and_terminal_truth() -> None:
    container = _projection_container(
        diagnostics=(
            {
                "integration_id": "worker-projection",
                "pid": 321,
                "cleanup_observations": (
                    {"operation_id": "cleanup-projection", "state": "CLEANUP_CONFIRMED"},
                    {"operation_id": "cleanup-projection", "state": "CLEANUP_CONFIRMED"},
                    {"state": "CLEANUP_CONFIRMED"},
                    "malformed",
                ),
                "predicates": {
                    "executable_isolation": True,
                    "job_process_limit": 2,
                    "active_process_count": 1,
                },
                "job": {
                    "configured_active_process_limit": 1,
                    "active_process_count": 1,
                },
                "phase": "cleanup_terminal",
            },
        )
    )
    evidence = collect_qualification_lifecycle(container, qualification_run_id="projection-control")
    assert evidence.result == "QUALIFICATION_PASS"
    assert evidence.worker_pids == (321,)
    assert evidence.job_limit == 1
    assert evidence.max_active == 1
    assert evidence.evidence["worker_identity"] == "worker-projection"
    assert evidence.evidence["sandbox_phase"] == "cleanup_terminal"
    assert evidence.cleanup_transaction_ids == ("cleanup-projection",)
    assert evidence.cleanup_states == ("CLEANUP_CONFIRMED",)


def test_lifecycle_projection_fails_closed_for_malformed_optional_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import jarvis.package_certification as package_certification

    def fail_worker_fingerprint() -> str:
        raise RuntimeError("worker fingerprint unavailable")

    monkeypatch.setattr(
        package_certification, "worker_compatibility_fingerprint", fail_worker_fingerprint
    )
    container = _projection_container(
        diagnostics=(
            {
                "integration_id": 0,
                "pid": "not-a-pid",
                "cleanup_observations": (
                    "malformed",
                    {},
                    {"operation_id": "", "state": ""},
                    {"operation_id": 0, "state": 0},
                ),
                "predicates": {
                    "executable_isolation": "unknown",
                    "job_process_limit": "unknown",
                    "active_process_count": "unknown",
                },
                "job": {
                    "configured_active_process_limit": "unknown",
                    "active_process_count": "unknown",
                },
            },
        )
    )
    cast(Any, container).production_sandbox.status = lambda: None

    evidence = collect_qualification_lifecycle(
        container,
        qualification_run_id="malformed-projection",
        failure_stage="A_FAILED",
    )

    assert evidence.result == "QUALIFICATION_NOT_PROVEN"
    assert evidence.worker_pids == ()
    assert evidence.evidence["worker_compatibility_hash"] is None
    assert evidence.cleanup_transaction_ids == ()

    unavailable = _projection_container(
        diagnostics=(
            {
                "cleanup_observations": "not-a-sequence",
                "predicates": None,
                "job": None,
            },
        )
    )
    cast(Any, unavailable).production_sandbox.status = lambda: SimpleNamespace(
        executable_isolation=False,
        max_processes="unknown",
    )
    assert (
        collect_qualification_lifecycle(
            unavailable,
            qualification_run_id="optional-diagnostics-unavailable",
        ).result
        == "EXECUTION_PASS"
    )


@pytest.mark.parametrize(
    ("container", "message"),
    [
        (SimpleNamespace(capability_acquisition=SimpleNamespace(last_run=None)), "identity"),
        (
            SimpleNamespace(
                capability_acquisition=SimpleNamespace(
                    last_run=SimpleNamespace(
                        capability_id="cap",
                        package_id="pkg",
                        package_hash="hash",
                        activation=None,
                        certification=None,
                    )
                ),
                package_store=None,
            ),
            "certification",
        ),
    ],
)
def test_lifecycle_projection_rejects_unavailable_authoritative_inputs(
    container: object, message: str
) -> None:
    with pytest.raises(QualificationEvidenceError, match=message):
        collect_qualification_lifecycle(container, qualification_run_id="invalid")


def test_lifecycle_projection_rejects_incomplete_package_and_registry() -> None:
    base = _projection_container()
    package_store = cast(SimpleNamespace, cast(Any, base).package_store)
    package_store.source_files = lambda _package: ()
    with pytest.raises(QualificationEvidenceError, match="package evidence"):
        collect_qualification_lifecycle(base, qualification_run_id="missing-package-evidence")

    base = _projection_container()
    cast(Any, base).capability_registry = None
    with pytest.raises(QualificationEvidenceError, match="registry"):
        collect_qualification_lifecycle(base, qualification_run_id="missing-registry")


@pytest.mark.asyncio
async def test_pair_validation_inputs_and_generic_failure_preserve_closure() -> None:
    with pytest.raises(QualificationEvidenceError, match="acquisition callback"):
        await run_same_runtime_pair(
            object(),
            first_request=1,
            second_request=2,
            acquire=cast(Any, None),
            qualification_run_id="invalid-acquire",
        )
    with pytest.raises(QualificationEvidenceError, match="budget"):
        await run_same_runtime_pair(
            object(),
            first_request=1,
            second_request=2,
            acquire=lambda _request: asyncio.sleep(0),
            qualification_run_id="invalid-budget",
            budget=cast(Any, object()),
        )
    with pytest.raises(QualificationEvidenceError, match="close callback"):
        await run_same_runtime_pair(
            object(),
            first_request=1,
            second_request=2,
            acquire=lambda _request: asyncio.sleep(0),
            qualification_run_id="invalid-close",
            close_runtime=cast(Any, object()),
        )

    closed = False

    async def close_runtime() -> None:
        nonlocal closed
        closed = True

    async def broken_acquire(_request: object) -> object:
        raise RuntimeError("synthetic acquisition defect")

    with pytest.raises(QualificationTerminalFailure) as failure:
        await run_same_runtime_pair(
            SimpleNamespace(
                runtime_instance_id="runtime-failure",
                capability_acquisition=SimpleNamespace(last_run=None),
                event_bus=SimpleNamespace(pending_consumer_count=4),
            ),
            first_request=1,
            second_request=2,
            acquire=broken_acquire,
            qualification_run_id="generic-failure",
            close_runtime=close_runtime,
        )
    assert failure.value.failure_stage == "PAIR_ACQUIRE"
    assert failure.value.typed_failure_code == "RuntimeError"
    assert failure.value.evidence["eventbus_pending_consumers"] == 4
    assert closed


@pytest.mark.asyncio
async def test_pair_timeout_is_rethrown_and_close_observations_remain_bounded() -> None:
    container = SimpleNamespace(
        capability_acquisition=SimpleNamespace(last_run=None),
        event_bus=SimpleNamespace(pending_consumer_count=0, closed=False),
        closed=False,
    )

    async def timed_out(_request: object) -> object:
        raise QualificationPairTimeoutError("inner timeout", {"phase": "acquire"})

    async def close_runtime() -> None:
        return None

    with pytest.raises(QualificationPairTimeoutError, match="inner timeout"):
        await run_same_runtime_pair(
            container,
            first_request=1,
            second_request=2,
            acquire=timed_out,
            qualification_run_id="inner-timeout",
            close_runtime=close_runtime,
        )


@pytest.mark.asyncio
async def test_lifecycle_progress_keeps_optional_terminal_stages_observation_only() -> None:
    progress: list[str] = []
    _emit_lifecycle_progress(
        lambda item: progress.append(item.stage),
        "A",
        replace(
            _lifecycle(result="EXECUTION_FAILURE"),
            certification_result="FAIL",
            activation_states=(),
            cleanup_states=(),
        ),
        0.0,
    )
    assert progress == ["A_PACKAGE_CREATED"]


def test_pair_terminal_result_helper_is_fail_closed_and_snapshots_state() -> None:
    container = SimpleNamespace(
        runtime_instance_id="runtime-helper",
        capability_acquisition=SimpleNamespace(
            last_run=SimpleNamespace(
                capability_id="cap-helper",
                package_id="pkg-helper",
                package_hash="hash-helper",
                stage=SimpleNamespace(value="failed"),
            )
        ),
        event_bus=SimpleNamespace(pending_consumer_count=2),
    )
    _raise_for_terminal_result(container, "A", SimpleNamespace(status="ok", stage="ok"))
    with pytest.raises(QualificationTerminalFailure, match="A_DENIED"):
        _raise_for_terminal_result(container, "A", SimpleNamespace(status="DENIED"))
    assert _qualification_failure_snapshot(container) == {
        "runtime_instance_id": "runtime-helper",
        "capability_id": "cap-helper",
        "package_id": "pkg-helper",
        "package_hash": "hash-helper",
        "acquisition_stage": "failed",
        "eventbus_pending_consumers": 2,
    }


def test_host_observation_helpers_cover_bounded_file_and_process_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monitor = HostSideEffectMonitor(tmp_path / "missing")
    assert monitor._tree_digest() == sha256(b"").hexdigest()  # noqa: SLF001
    (tmp_path / "small.txt").write_text("small", encoding="utf-8")
    assert monitor._tree_digest()  # noqa: SLF001
    monkeypatch.setattr(
        evidence_module,
        "os",
        SimpleNamespace(name="nt", getpid=lambda: 99),
    )
    evidence_private = cast(Any, evidence_module)
    monkeypatch.setattr(
        evidence_private.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout='"one","42"\nmalformed\n'),
    )
    assert HostSideEffectMonitor._processes() == {42}  # noqa: SLF001
    assert HostSideEffectMonitor._gui_processes() == ("one",)  # noqa: SLF001


def test_host_observation_helpers_cover_unavailable_platform_and_rejected_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monitor = HostSideEffectMonitor(tmp_path)
    (tmp_path / "oversized.bin").write_bytes(b"x" * 10_000_000)
    assert monitor._tree_digest()  # noqa: SLF001

    evidence_private = cast(Any, evidence_module)
    monkeypatch.setattr(evidence_private.os, "name", "posix")
    assert HostSideEffectMonitor._foreground_window() is None  # noqa: SLF001
    assert HostSideEffectMonitor._cursor_position() is None  # noqa: SLF001
    observation = HostSideEffectMonitor._clipboard_digest()  # noqa: SLF001
    assert observation.status is ClipboardObservationStatus.UNAVAILABLE
    assert HostSideEffectMonitor._gui_processes() == ()  # noqa: SLF001
    assert HostSideEffectMonitor._processes() == {evidence_private.os.getpid()}  # noqa: SLF001

    monkeypatch.setattr(evidence_private.os, "name", "nt")

    class _User32:
        def GetForegroundWindow(self) -> int:
            return 0

        def GetCursorPos(self, _point: object) -> int:
            return 0

    monkeypatch.setattr(evidence_private.ctypes, "WinDLL", lambda *args, **kwargs: _User32())
    assert HostSideEffectMonitor._foreground_window() is None  # noqa: SLF001
    assert HostSideEffectMonitor._cursor_position() is None  # noqa: SLF001

    (tmp_path / "jarvis").mkdir()
    (tmp_path / "jarvis" / "unsupported.txt").write_text("ignored", encoding="utf-8")
    assert "unsupported.txt" not in qualification_source_manifest(tmp_path)


def test_source_binding_and_manifest_filters_fail_closed_and_write_json(tmp_path: Path) -> None:
    assert qualification_source_manifest(tmp_path) == ()
    with pytest.raises(ValueError, match="escaped"):
        source_binding_fingerprint(tmp_path, ("../outside",))
    (tmp_path / "jarvis").mkdir()
    (tmp_path / "scripts" / "acceptance").mkdir(parents=True)
    (tmp_path / "tests").mkdir()
    (tmp_path / "jarvis" / "valid.py").write_text("x", encoding="utf-8")
    (tmp_path / "jarvis" / "ignored.toml").write_text("x", encoding="utf-8")
    (tmp_path / "jarvis" / ".pytest_cache").mkdir()
    assert "jarvis/valid.py" in qualification_source_manifest(tmp_path)
    assert "jarvis/ignored.toml" in qualification_source_manifest(tmp_path)
    assert all(".pytest_cache" not in item for item in qualification_source_manifest(tmp_path))
    digest = write_json(tmp_path / "nested" / "evidence.json", {"safe": True})
    assert len(digest) == 64
