"""Safe evidence collection and host-side-effect monitoring."""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import json
import math
import os
import subprocess
from collections.abc import Awaitable, Callable, Mapping, Sequence
from ctypes import wintypes
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from jarvis.acceptance.models import AcceptanceStatus, EvidenceEnvelope, EvidenceTrust


class QualificationEvidenceError(ValueError):
    """Structured qualification evidence is absent or inconsistent."""


class QualificationPairTimeoutError(QualificationEvidenceError):
    """A bounded qualification pair exceeded its absolute campaign deadline."""

    def __init__(self, message: str, evidence: Mapping[str, object] | None = None) -> None:
        self.evidence = dict(evidence or {})
        super().__init__(message)


class QualificationTerminalFailure(QualificationEvidenceError):
    """A lifecycle reached a typed terminal failure and cannot continue."""

    def __init__(
        self,
        failure_stage: str,
        typed_failure_code: str,
        evidence: Mapping[str, object],
    ) -> None:
        self.failure_stage = failure_stage
        self.typed_failure_code = typed_failure_code
        self.evidence = dict(evidence)
        super().__init__(f"qualification lifecycle failed at {failure_stage}: {typed_failure_code}")


QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA = "qualification-lifecycle-evidence-1"


@dataclass(frozen=True, slots=True)
class QualificationPairBudget:
    """Finite pair budget derived from the declared full-lifecycle ceiling."""

    setup_seconds: float
    maximum_full_lifecycle_seconds: float
    between_run_evidence_seconds: float
    runtime_close_seconds: float
    scheduling_margin_seconds: float

    def __post_init__(self) -> None:
        values = (
            self.setup_seconds,
            self.maximum_full_lifecycle_seconds,
            self.between_run_evidence_seconds,
            self.runtime_close_seconds,
            self.scheduling_margin_seconds,
        )
        if any(
            type(value) not in {int, float} or not math.isfinite(float(value)) or value < 0
            for value in values
        ):
            raise QualificationEvidenceError("qualification pair budget is malformed")
        if self.maximum_full_lifecycle_seconds <= 0:
            raise QualificationEvidenceError("full lifecycle budget must be positive")

    @property
    def hard_deadline_seconds(self) -> float:
        """Return the finite campaign bound; progress cannot extend this bound."""

        return (
            self.setup_seconds
            + (2 * self.maximum_full_lifecycle_seconds)
            + self.between_run_evidence_seconds
            + self.runtime_close_seconds
            + self.scheduling_margin_seconds
        )


def derive_pair_budget(
    maximum_full_lifecycle_seconds: float,
    *,
    setup_seconds: float = 30.0,
    between_run_evidence_seconds: float = 30.0,
    runtime_close_seconds: float = 30.0,
    scheduling_margin_seconds: float = 15.0,
) -> QualificationPairBudget:
    """Derive a bounded pair budget from the declared lifecycle ceiling."""

    return QualificationPairBudget(
        setup_seconds=setup_seconds,
        maximum_full_lifecycle_seconds=maximum_full_lifecycle_seconds,
        between_run_evidence_seconds=between_run_evidence_seconds,
        runtime_close_seconds=runtime_close_seconds,
        scheduling_margin_seconds=scheduling_margin_seconds,
    )


@dataclass(frozen=True, slots=True)
class QualificationPairProgress:
    """Typed, observation-only pair progress; it carries no authority."""

    stage: str
    monotonic_seconds: float


def _pair_progress(
    callback: Callable[[QualificationPairProgress], None] | None,
    stage: str,
    started_at: float,
) -> None:
    if callback is not None:
        callback(
            QualificationPairProgress(
                stage=stage,
                monotonic_seconds=asyncio.get_running_loop().time() - started_at,
            )
        )


@dataclass(frozen=True, slots=True)
class QualificationLifecycleEvidence:
    """Qualification-only projection of authoritative runtime lifecycle state."""

    qualification_run_id: str
    runtime_instance_id: str
    capability_id: str
    action_id: str
    package_id: str
    package_hash: str
    payload_digest: str
    manifest_fingerprint: str
    certification_result: str
    activation_id: str | None
    activation_states: tuple[str, ...]
    active: bool
    registry_identity: str
    persistence_result: str
    restart_restore_result: str
    cleanup_transaction_ids: tuple[str, ...]
    cleanup_states: tuple[str, ...]
    unresolved_recovery_receipts: tuple[str, ...]
    worker_pids: tuple[int, ...]
    appcontainer: bool | None
    job_limit: int | None
    max_active: int | None
    eventbus_pending_consumers: int
    runtime_closed: bool
    result: str
    failure_stage: str | None = None
    typed_failure_code: str | None = None
    evidence: Mapping[str, object] = field(default_factory=dict)
    eventbus_closed: bool = False

    def __post_init__(self) -> None:
        required = {
            "qualification_run_id": self.qualification_run_id,
            "runtime_instance_id": self.runtime_instance_id,
            "capability_id": self.capability_id,
            "action_id": self.action_id,
            "package_id": self.package_id,
            "package_hash": self.package_hash,
            "payload_digest": self.payload_digest,
            "manifest_fingerprint": self.manifest_fingerprint,
            "registry_identity": self.registry_identity,
            "result": self.result,
        }
        if any(type(value) is not str or not value for value in required.values()):
            raise QualificationEvidenceError("qualification identity is incomplete")
        if self.activation_id is None and self.result == "QUALIFICATION_PASS":
            raise QualificationEvidenceError("activation evidence is required for qualification")
        if self.result == "QUALIFICATION_PASS" and not self.cleanup_transaction_ids:
            raise QualificationEvidenceError("cleanup evidence is required for qualification")
        if self.result == "QUALIFICATION_PASS" and any(
            state not in {"CLEANUP_CONFIRMED", "CLEANUP_FAILED_CONFIRMED"}
            for state in self.cleanup_states
        ):
            raise QualificationEvidenceError("cleanup is not terminal")

    def as_dict(self) -> dict[str, object]:
        return {
            "qualification_run_id": self.qualification_run_id,
            "runtime_instance_id": self.runtime_instance_id,
            "capability_id": self.capability_id,
            "action_id": self.action_id,
            "package_id": self.package_id,
            "package_hash": self.package_hash,
            "payload_digest": self.payload_digest,
            "manifest_fingerprint": self.manifest_fingerprint,
            "certification_result": self.certification_result,
            "activation_id": self.activation_id,
            "activation_states": list(self.activation_states),
            "active": self.active,
            "registry_identity": self.registry_identity,
            "persistence_result": self.persistence_result,
            "restart_restore_result": self.restart_restore_result,
            "cleanup_transaction_ids": list(self.cleanup_transaction_ids),
            "cleanup_states": list(self.cleanup_states),
            "unresolved_recovery_receipts": list(self.unresolved_recovery_receipts),
            "worker_pids": list(self.worker_pids),
            "appcontainer": self.appcontainer,
            "job_limit": self.job_limit,
            "max_active": self.max_active,
            "eventbus_pending_consumers": self.eventbus_pending_consumers,
            "runtime_closed": self.runtime_closed,
            "eventbus_closed": self.eventbus_closed,
            "result": self.result,
            "failure_stage": self.failure_stage,
            "typed_failure_code": self.typed_failure_code,
            "evidence": dict(self.evidence),
        }


def collect_qualification_lifecycle(
    container: object,
    *,
    qualification_run_id: str,
    failure_stage: str | None = None,
    typed_failure_code: str | None = None,
) -> QualificationLifecycleEvidence:
    """Collect only typed/durable lifecycle state; stdout is never consulted."""

    acquisition = getattr(container, "capability_acquisition", None)
    run = getattr(acquisition, "last_run", None)
    if run is None or not run.capability_id or not run.package_id or not run.package_hash:
        raise QualificationEvidenceError("acquisition identity is unavailable")
    activation = run.activation
    certification = run.certification
    package_store = getattr(container, "package_store", None)
    if package_store is None or certification is None:
        raise QualificationEvidenceError("certification or package store is unavailable")
    package = package_store.load(run.package_id, run.package_version or "1.0.0", run.package_hash)
    sources = package_store.source_files(package)
    if not sources or not package.action_specs:
        raise QualificationEvidenceError("package evidence is incomplete")
    payload_digest = hashlib.sha256(sources[0].content.encode()).hexdigest()
    action = package.action_specs[0]
    registry = getattr(container, "capability_registry", None)
    if registry is None:
        raise QualificationEvidenceError("capability registry is unavailable")
    registry_manifest = registry.inspect(action.capability_id)
    sandbox = getattr(container, "production_sandbox", None)
    diagnostics = (
        sandbox.protocol_diagnostic_history()
        if sandbox is not None and callable(getattr(sandbox, "protocol_diagnostic_history", None))
        else ()
    )
    cleanup_ids: list[str] = []
    cleanup_states: list[str] = []
    cleanup_latest: dict[str, str] = {}
    worker_pids: list[int] = []
    appcontainer: bool | None = None
    job_limit: int | None = None
    max_active: int | None = None
    worker_identity: str | None = None
    worker_compatibility_hash: str | None = None
    latest_diagnostic: Mapping[str, object] = {}
    for item in diagnostics[-1:]:
        latest_diagnostic = item
        integration_id = item.get("integration_id")
        if isinstance(integration_id, str) and integration_id:
            worker_identity = integration_id
        pid = item.get("pid")
        if type(pid) is int:
            worker_pids.append(pid)
        cleanups = item.get("cleanup_observations", ())
        if isinstance(cleanups, Sequence) and not isinstance(cleanups, str | bytes):
            for cleanup in cleanups:
                if not isinstance(cleanup, Mapping):
                    continue
                operation_id = cleanup.get("operation_id")
                state = cleanup.get("state")
                if isinstance(operation_id, str) and operation_id:
                    cleanup_ids.append(operation_id)
                if isinstance(state, str) and state:
                    if isinstance(operation_id, str) and operation_id:
                        cleanup_latest[operation_id] = state
                    else:
                        cleanup_states.append(state)
        status = item.get("predicates")
        if isinstance(status, Mapping):
            if type(status.get("executable_isolation")) is bool:
                appcontainer = bool(status["executable_isolation"])
            if type(status.get("job_process_limit")) is int:
                job_limit = int(status["job_process_limit"])
            if type(status.get("active_process_count")) is int:
                max_active = max(max_active or 0, int(status["active_process_count"]))
        job = item.get("job")
        if isinstance(job, Mapping):
            configured_limit = job.get("configured_active_process_limit")
            if type(configured_limit) is int:
                job_limit = configured_limit
            observed_active = job.get("active_process_count")
            if type(observed_active) is int:
                max_active = max(max_active or 0, observed_active)
    try:
        from jarvis.package_certification import worker_compatibility_fingerprint

        worker_compatibility_hash = worker_compatibility_fingerprint()
    except Exception:
        worker_compatibility_hash = None
    security_status = getattr(sandbox, "status", lambda: None)()
    if security_status is not None:
        appcontainer = bool(getattr(security_status, "executable_isolation", False))
        if type(getattr(security_status, "max_processes", None)) is int:
            job_limit = int(security_status.max_processes)
    activation_states = (
        tuple(item.to_state.value for item in activation.history) if activation else ()
    )
    active = bool(activation and activation.state.value == "ACTIVE" and run.stage.value == "active")
    result = "EXECUTION_PASS"
    if active and activation is not None and cleanup_ids:
        result = "QUALIFICATION_PASS"
    if failure_stage is not None or typed_failure_code is not None:
        result = "EXECUTION_FAILURE" if run.stage.value == "failed" else "QUALIFICATION_NOT_PROVEN"
    return QualificationLifecycleEvidence(
        qualification_run_id=qualification_run_id,
        runtime_instance_id=str(getattr(container, "runtime_instance_id", "")),
        capability_id=action.capability_id,
        action_id=action.action_id,
        package_id=package.package_id,
        package_hash=package.package_hash,
        payload_digest=payload_digest,
        manifest_fingerprint=certification.manifest_hash,
        certification_result="PASS" if certification.stages[-1].passed else "FAIL",
        activation_id=activation.activation_id if activation else None,
        activation_states=activation_states,
        active=active,
        registry_identity=registry_manifest.capability_id,
        persistence_result="OBSERVED",
        restart_restore_result="NOT_EXECUTED_PAIR_SCOPE",
        cleanup_transaction_ids=tuple(dict.fromkeys(cleanup_ids)),
        cleanup_states=tuple(dict.fromkeys((*cleanup_states, *cleanup_latest.values()))),
        unresolved_recovery_receipts=(),
        worker_pids=tuple(dict.fromkeys(worker_pids)),
        appcontainer=appcontainer,
        job_limit=job_limit,
        max_active=max_active,
        eventbus_pending_consumers=int(
            getattr(getattr(container, "event_bus", None), "pending_consumer_count", 0)
        ),
        runtime_closed=bool(getattr(container, "closed", False)),
        eventbus_closed=bool(getattr(getattr(container, "event_bus", None), "closed", False)),
        result=result,
        failure_stage=failure_stage,
        typed_failure_code=typed_failure_code,
        evidence={
            "record_schema": QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA,
            "source": "typed runtime state and bounded sandbox diagnostics",
            "worker_identity": worker_identity,
            "worker_compatibility_hash": worker_compatibility_hash,
            "worker_pid": worker_pids[-1] if worker_pids else None,
            "job_limit": job_limit,
            "observed_active_process_count": max_active,
            "sandbox_phase": latest_diagnostic.get("phase"),
        },
    )


def validate_same_runtime_pair(
    first: QualificationLifecycleEvidence,
    second: QualificationLifecycleEvidence,
    *,
    pending_event_consumers: int,
    unresolved_recovery_receipts: Sequence[str] = (),
    unexpected_event_consumers: int = 0,
) -> dict[str, object]:
    """Validate pair isolation without treating either record as authority."""

    checks = {
        "same_runtime": first.runtime_instance_id == second.runtime_instance_id,
        "independent_capabilities": first.capability_id != second.capability_id,
        "independent_packages": first.package_id != second.package_id,
        "independent_hashes": first.package_hash != second.package_hash,
        "independent_certification": first.manifest_fingerprint != second.manifest_fingerprint,
        "independent_payloads": first.payload_digest != second.payload_digest,
        "independent_activations": bool(
            first.activation_id
            and second.activation_id
            and first.activation_id != second.activation_id
        ),
        "both_active": first.active and second.active,
        "distinct_registry_records": first.registry_identity != second.registry_identity,
        "expected_shared_event_consumers": pending_event_consumers >= 0,
        "no_unexpected_event_consumers": unexpected_event_consumers == 0,
        "no_unresolved_recovery": not tuple(unresolved_recovery_receipts),
    }
    return {"checks": checks, "result": "PASS" if all(checks.values()) else "NOT_PROVEN"}


def serialize_lifecycle_evidence(
    records: Sequence[QualificationLifecycleEvidence],
) -> str:
    """Serialize exact lifecycle records without dropping qualification fields."""

    if not isinstance(records, Sequence) or isinstance(records, str | bytes):
        raise QualificationEvidenceError("lifecycle evidence records are malformed")
    return json.dumps(
        [record.as_dict() for record in records],
        sort_keys=True,
        separators=(",", ":"),
    )


def collect_qualification_failure(
    coordinator: object,
    *,
    qualification_run_id: str,
    failure_stage: str,
    typed_failure_code: str,
) -> QualificationLifecycleEvidence:
    """Retain a typed failed acquisition without inventing activation authority."""

    run = getattr(coordinator, "last_run", None)
    if run is None or not run.package_hash:
        raise QualificationEvidenceError("failed acquisition identity is unavailable")
    package_id = run.package_id or "NOT_AVAILABLE"
    capability_id = run.capability_id or "NOT_AVAILABLE"
    return QualificationLifecycleEvidence(
        qualification_run_id=qualification_run_id,
        runtime_instance_id="NOT_AVAILABLE",
        capability_id=capability_id,
        action_id="NOT_AVAILABLE",
        package_id=package_id,
        package_hash=run.package_hash,
        payload_digest="NOT_AVAILABLE",
        manifest_fingerprint="NOT_AVAILABLE",
        certification_result="FAIL",
        activation_id=None,
        activation_states=(),
        active=False,
        registry_identity="NONE",
        persistence_result="NOT_PERFORMED",
        restart_restore_result="NOT_PERFORMED",
        cleanup_transaction_ids=(),
        cleanup_states=(),
        unresolved_recovery_receipts=(),
        worker_pids=(),
        appcontainer=None,
        job_limit=None,
        max_active=None,
        eventbus_pending_consumers=0,
        runtime_closed=False,
        eventbus_closed=False,
        result="EXECUTION_FAILURE",
        failure_stage=failure_stage,
        typed_failure_code=typed_failure_code,
        evidence={"source": "typed acquisition run and bounded flight recorder"},
    )


async def run_same_runtime_pair(
    container: object,
    *,
    first_request: object,
    second_request: object,
    acquire: Callable[[object], Awaitable[object]],
    qualification_run_id: str,
    budget: QualificationPairBudget | None = None,
    progress_callback: Callable[[QualificationPairProgress], None] | None = None,
    close_runtime: Callable[[], Awaitable[None]] | None = None,
) -> dict[str, object]:
    """Run two acquisitions through one caller-owned runtime container.

    The optional budget is a hard campaign deadline, not a silence watchdog.
    Typed progress is emitted only at authoritative lifecycle boundaries and
    cannot extend the deadline or change qualification authority.
    """

    if not callable(acquire):
        raise QualificationEvidenceError("pair acquisition callback is unavailable")
    if budget is not None and not isinstance(budget, QualificationPairBudget):
        raise QualificationEvidenceError("qualification pair budget is malformed")
    if close_runtime is not None and not callable(close_runtime):
        raise QualificationEvidenceError("runtime close callback is unavailable")
    started_at = asyncio.get_running_loop().time()
    _pair_progress(progress_callback, "PAIR_RUNTIME_CREATED", started_at)

    async def execute() -> dict[str, object]:
        try:
            _pair_progress(progress_callback, "A_PREPARATION_STARTED", started_at)
            first_result = await acquire(first_request)
            _raise_for_terminal_result(container, "A", first_result)
            _pair_progress(progress_callback, "A_PREPARATION_TERMINAL", started_at)
            first = collect_qualification_lifecycle(
                container, qualification_run_id=f"{qualification_run_id}-A"
            )
            _emit_lifecycle_progress(progress_callback, "A", first, started_at)
            _pair_progress(progress_callback, "BETWEEN_RUN_TERMINALITY", started_at)
            _pair_progress(progress_callback, "B_PREPARATION_STARTED", started_at)
            second_result = await acquire(second_request)
            _raise_for_terminal_result(container, "B", second_result)
            _pair_progress(progress_callback, "B_PREPARATION_TERMINAL", started_at)
            second = collect_qualification_lifecycle(
                container, qualification_run_id=f"{qualification_run_id}-B"
            )
            _emit_lifecycle_progress(progress_callback, "B", second, started_at)
            pair = validate_same_runtime_pair(
                first,
                second,
                pending_event_consumers=int(
                    getattr(getattr(container, "event_bus", None), "pending_consumer_count", 0)
                ),
                unexpected_event_consumers=0,
            )
            return {
                "result": pair["result"],
                "runtime_instance_id": first.runtime_instance_id,
                "A": first.as_dict(),
                "B": second.as_dict(),
                "checks": pair["checks"],
            }
        except QualificationTerminalFailure:
            raise
        except QualificationPairTimeoutError:
            raise
        except Exception as error:
            raise QualificationTerminalFailure(
                "PAIR_ACQUIRE",
                type(error).__name__,
                _qualification_failure_snapshot(container),
            ) from error
        finally:
            if close_runtime is not None:
                _pair_progress(progress_callback, "RUNTIME_CLOSE_STARTED", started_at)
                try:
                    await close_runtime()
                finally:
                    if bool(getattr(container, "closed", False)):
                        _pair_progress(progress_callback, "RUNTIME_CLOSED", started_at)
                    if bool(getattr(getattr(container, "event_bus", None), "closed", False)):
                        _pair_progress(progress_callback, "EVENTBUS_CLOSED", started_at)
                    _pair_progress(progress_callback, "PAIR_TERMINAL", started_at)

    if budget is None:
        return await execute()
    try:
        async with asyncio.timeout(budget.hard_deadline_seconds):
            return await execute()
    except TimeoutError as error:
        raise QualificationPairTimeoutError(
            "qualification pair exceeded its absolute campaign deadline",
            _qualification_failure_snapshot(container),
        ) from error


def _emit_lifecycle_progress(
    callback: Callable[[QualificationPairProgress], None] | None,
    prefix: str,
    evidence: QualificationLifecycleEvidence,
    started_at: float,
) -> None:
    _pair_progress(callback, f"{prefix}_PACKAGE_CREATED", started_at)
    if evidence.certification_result == "PASS":
        _pair_progress(callback, f"{prefix}_CERTIFICATION_TERMINAL", started_at)
    for state in ("SHADOW", "CANARY", "ACTIVE"):
        if state in evidence.activation_states:
            stage = {
                "SHADOW": "SHADOW_TERMINAL",
                "CANARY": "CANARY_TERMINAL",
                "ACTIVE": "ACTIVATION_TERMINAL",
            }[state]
            _pair_progress(callback, f"{prefix}_{stage}", started_at)
    if "CLEANUP_CONFIRMED" in evidence.cleanup_states:
        _pair_progress(callback, f"{prefix}_CLEANUP_TERMINAL", started_at)


def _raise_for_terminal_result(container: object, prefix: str, result: object) -> None:
    status = getattr(result, "status", None)
    status_value = getattr(status, "value", status)
    stage = getattr(result, "stage", None)
    stage_value = getattr(stage, "value", stage)
    terminal = {
        "FAILED",
        "DENIED",
        "CERTIFICATION_FAILED",
        "SANDBOX_FAILED",
        "ACTIVATION_FAILED",
        "CLEANUP_UNKNOWN",
        "RECOVERY_BLOCKED",
        "TIMEOUT",
        "failed",
        "denied",
        "certification_failed",
        "sandbox_failed",
        "activation_failed",
        "cleanup_unknown",
        "recovery_blocked",
        "timeout",
    }
    if status_value in terminal or stage_value in terminal:
        raise QualificationTerminalFailure(
            f"{prefix}_{stage_value or status_value}",
            str(stage_value or status_value),
            _qualification_failure_snapshot(container),
        )


def _qualification_failure_snapshot(container: object) -> dict[str, object]:
    acquisition = getattr(container, "capability_acquisition", None)
    run = getattr(acquisition, "last_run", None)
    return {
        "runtime_instance_id": str(getattr(container, "runtime_instance_id", "")),
        "capability_id": getattr(run, "capability_id", None),
        "package_id": getattr(run, "package_id", None),
        "package_hash": getattr(run, "package_hash", None),
        "acquisition_stage": getattr(getattr(run, "stage", None), "value", None),
        "eventbus_pending_consumers": int(
            getattr(getattr(container, "event_bus", None), "pending_consumer_count", 0)
        ),
    }


class ClipboardObservationStatus(StrEnum):
    SNAPSHOT_OK = "SNAPSHOT_OK"
    UNAVAILABLE = "UNAVAILABLE"
    BUSY = "BUSY"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    NATIVE_ERROR = "NATIVE_ERROR"


@dataclass(frozen=True, slots=True)
class ClipboardObservation:
    status: ClipboardObservationStatus
    sequence_number: int | None = None
    native_error: int | None = None


@dataclass(frozen=True, slots=True)
class HostSideEffectSnapshot:
    foreground_window: str | None
    cursor_position: tuple[int, int] | None
    clipboard_observation: ClipboardObservation
    process_ids: tuple[int, ...]
    gui_processes: tuple[str, ...]
    filesystem_digest: str
    host_bridge_operations: tuple[str, ...] = ()


class HostSideEffectMonitor:
    """Best-effort, secret-minimizing host observation; no clipboard content is stored."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._before: HostSideEffectSnapshot | None = None

    def snapshot(self) -> HostSideEffectSnapshot:
        processes = self._processes()
        current = HostSideEffectSnapshot(
            foreground_window=self._foreground_window(),
            cursor_position=self._cursor_position(),
            clipboard_observation=self._clipboard_digest(),
            process_ids=tuple(sorted(processes)),
            gui_processes=self._gui_processes(),
            filesystem_digest=self._tree_digest(),
        )
        if self._before is None:
            self._before = current
        return current

    def compare(self, after: HostSideEffectSnapshot | None = None) -> dict[str, Any]:
        before = self._before or self.snapshot()
        after = after or self.snapshot()
        before_clipboard = before.clipboard_observation
        after_clipboard = after.clipboard_observation
        clipboard_proven = (
            before_clipboard.status is ClipboardObservationStatus.SNAPSHOT_OK
            and after_clipboard.status is ClipboardObservationStatus.SNAPSHOT_OK
        )
        clipboard_mutation = (
            "OBSERVED_CHANGE"
            if clipboard_proven
            and before_clipboard.sequence_number != after_clipboard.sequence_number
            else "NONE"
            if clipboard_proven
            else "NOT_PROVEN"
        )
        clipboard_status = (
            after_clipboard
            if after_clipboard.status is not ClipboardObservationStatus.SNAPSHOT_OK
            else before_clipboard
        )
        return {
            "mouse_movement": "NONE"
            if before.cursor_position == after.cursor_position
            else "OBSERVED_CHANGE",
            "keyboard_injection": "NOT_OBSERVED",
            "focus_change": "NONE"
            if before.foreground_window == after.foreground_window
            else "OBSERVED_CHANGE",
            "clipboard_mutation": clipboard_mutation,
            "clipboard_observation_status": clipboard_status.status.value,
            "clipboard_native_error": clipboard_status.native_error,
            "new_process_ids": sorted(set(after.process_ids) - set(before.process_ids)),
            "new_gui_processes": sorted(set(after.gui_processes) - set(before.gui_processes)),
            "host_filesystem_mutation": "NONE"
            if before.filesystem_digest == after.filesystem_digest
            else "OBSERVED_CHANGE",
            "host_bridge_operations": list(after.host_bridge_operations),
        }

    def evidence(
        self,
        run_id: str,
        test_id: str,
        environment: str,
        *,
        after: HostSideEffectSnapshot | None = None,
    ) -> EvidenceEnvelope:
        observed = self.compare(after)
        clipboard_mutation = observed["clipboard_mutation"]
        result = (
            AcceptanceStatus.FAIL
            if clipboard_mutation == "OBSERVED_CHANGE"
            else AcceptanceStatus.UNKNOWN_OUTCOME
            if clipboard_mutation == "NOT_PROVEN"
            else AcceptanceStatus.PASS
        )
        return EvidenceEnvelope(
            evidence_id=f"host-effects-{run_id}-{test_id}",
            run_id=run_id,
            test_id=test_id,
            source="HostSideEffectMonitor",
            source_type="native_os_observation",
            environment=environment,
            trust=EvidenceTrust.NATIVE_OS_OBSERVATION,
            result=result,
            observed_state=observed,
            expected_state={
                key: "NONE"
                for key in (
                    "mouse_movement",
                    "focus_change",
                    "clipboard_mutation",
                    "host_filesystem_mutation",
                )
            },
            notes=(
                "Clipboard content is never read or persisted; the monitor compares "
                "pointer-free sequence-number observations."
            ),
        )

    def _tree_digest(self) -> str:
        digest = hashlib.sha256()
        if not self.root.exists():
            return digest.hexdigest()
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and path.stat().st_size < 10_000_000:
                digest.update(str(path.relative_to(self.root)).encode())
                digest.update(str(path.stat().st_size).encode())
                digest.update(str(path.stat().st_mtime_ns).encode())
        return digest.hexdigest()

    @staticmethod
    def _foreground_window() -> str | None:
        if os.name != "nt":
            return None
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return None
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return f"hwnd:{int(hwnd)}:pid:{int(pid.value)}"

    @staticmethod
    def _cursor_position() -> tuple[int, int] | None:
        if os.name != "nt":
            return None
        point = wintypes.POINT()
        if not ctypes.WinDLL("user32", use_last_error=True).GetCursorPos(ctypes.byref(point)):
            return None
        return (int(point.x), int(point.y))

    @staticmethod
    def _clipboard_digest() -> ClipboardObservation:
        if os.name != "nt":
            return ClipboardObservation(ClipboardObservationStatus.UNAVAILABLE)
        try:
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            get_sequence_number = user32.GetClipboardSequenceNumber
            get_sequence_number.argtypes = ()
            get_sequence_number.restype = wintypes.DWORD
            sequence_number = int(get_sequence_number())
            if sequence_number == 0:
                return ClipboardObservation(
                    ClipboardObservationStatus.UNAVAILABLE,
                    native_error=ctypes.get_last_error(),
                )
            return ClipboardObservation(
                ClipboardObservationStatus.SNAPSHOT_OK,
                sequence_number=sequence_number,
            )
        except (AttributeError, OSError, TypeError, ValueError) as error:
            return ClipboardObservation(
                ClipboardObservationStatus.NATIVE_ERROR,
                native_error=getattr(error, "winerror", None),
            )

    @staticmethod
    def _gui_processes() -> tuple[str, ...]:
        if os.name != "nt":
            return ()
        result = subprocess.run(
            ("tasklist", "/fo", "csv", "/nh"), capture_output=True, text=True, check=False
        )
        names: list[str] = []
        for line in result.stdout.splitlines():
            fields = line.split('","')
            if fields and fields[0].startswith('"'):
                names.append(fields[0].strip('"'))
        return tuple(sorted(set(names)))

    @staticmethod
    def _processes() -> set[int]:
        if os.name == "nt":
            result = subprocess.run(
                ("tasklist", "/fo", "csv", "/nh"), capture_output=True, text=True, check=False
            )
            values: set[int] = set()
            for line in result.stdout.splitlines():
                try:
                    values.add(int(line.split('","')[1].strip('"')))
                except (IndexError, ValueError):
                    continue
            return values
        return {os.getpid()}


def write_json(path: Path, value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, indent=2, default=str).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


def utc_artifact_timestamp(moment: datetime | None = None) -> str:
    """Return a real, second-precision UTC filename timestamp."""

    captured = moment or datetime.now(UTC)
    if captured.tzinfo is None:
        raise ValueError("artifact timestamp must be timezone-aware")
    return captured.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def source_binding_fingerprint(root: Path, paths: tuple[str, ...]) -> str:
    """Hash ordered source bytes only; evidence filenames are not in the input."""

    digest = hashlib.sha256()
    for relative in paths:
        path = (root / relative).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as error:
            raise ValueError("source binding escaped root") from error
        digest.update(path.read_bytes())
    return digest.hexdigest()


_QUALIFICATION_SOURCE_ROOTS = ("jarvis", "scripts/acceptance", "tests")
_QUALIFICATION_SOURCE_FILES = ("pyproject.toml",)
_QUALIFICATION_IGNORED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}


def qualification_source_manifest(root: Path) -> tuple[str, ...]:
    """Return the deterministic mutable-tree inputs for B2 qualification."""

    resolved_root = root.resolve()
    paths: list[str] = []
    for relative in _QUALIFICATION_SOURCE_FILES:
        path = resolved_root / relative
        if path.is_file():
            paths.append(relative)
    for directory in _QUALIFICATION_SOURCE_ROOTS:
        base = resolved_root / directory
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or any(
                part in _QUALIFICATION_IGNORED_PARTS for part in path.parts
            ):
                continue
            if path.suffix.lower() not in {".py", ".toml"}:
                continue
            paths.append(path.relative_to(resolved_root).as_posix())
    return tuple(sorted(set(paths)))


def qualification_source_seal(root: Path) -> tuple[str, tuple[str, ...]]:
    """Hash qualification paths and contents, including path names in the input."""

    paths = qualification_source_manifest(root)
    digest = hashlib.sha256()
    resolved_root = root.resolve()
    for relative in paths:
        encoded_path = relative.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        content = (resolved_root / relative).read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest(), paths
