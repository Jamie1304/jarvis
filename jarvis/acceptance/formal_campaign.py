"""Executable real-lifecycle campaigns for pre-self-repair qualification.

This module deliberately keeps campaign authority in
``ConsecutiveQualificationCampaign``.  It only executes one fresh lifecycle,
adapts its typed terminal evidence, and submits that evidence once.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol, cast

from jarvis.acceptance.campaign import (
    CampaignSnapshot,
    CampaignState,
    ConsecutiveQualificationCampaign,
)
from jarvis.acceptance.evidence import (
    QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA,
    QualificationEvidenceError,
    QualificationLifecycleEvidence,
)

FORMAL_CAMPAIGN_RESULT_SCHEMA: Final[str] = "formal-qualification-campaign-result-1"
LIFECYCLE_TERMINAL_PREFIX: Final[str] = "R4R_LIFECYCLE_TERMINAL "
DEFAULT_LIFECYCLE_TEST: Final[str] = (
    "tests/test_v1_acceptance.py::"
    "test_v1_production_composition_acquires_randomized_capability_and_restores_it"
)


class FormalCampaignError(ValueError):
    """A lifecycle or sealed campaign result is malformed or cannot qualify."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        subprocess_evidence: LifecycleSubprocessEvidence | None = None,
    ) -> None:
        self.code = code
        self.subprocess_evidence = subprocess_evidence
        super().__init__(message)


class FormalCampaignKind(StrEnum):
    THREE_OF_THREE = "THREE_OF_THREE"
    FINAL_TEN = "FINAL_TEN"

    @property
    def required_count(self) -> int:
        return 3 if self is FormalCampaignKind.THREE_OF_THREE else 10


@dataclass(frozen=True, slots=True)
class LifecycleSubprocessEvidence:
    """Durable, non-authoritative evidence for one lifecycle child process."""

    argv: tuple[str, ...]
    pid: int | None
    started_at: str
    ended_at: str
    returncode: int | None
    stdout_path: str | None
    stderr_path: str | None
    stdout_sha256: str | None
    stderr_sha256: str | None
    terminal_output: Mapping[str, object] | None
    last_completed_phase: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "pid": self.pid,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "returncode": self.returncode,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "terminal_output": self.terminal_output,
            "last_completed_phase": self.last_completed_phase,
        }


class LifecycleExecutor(Protocol):
    """The one-lifecycle seam used by the formal executor and its unit tests."""

    def execute(self, qualification_run_id: str) -> QualificationLifecycleEvidence: ...


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", f"{field} is not an object")
    return value


def _string(mapping: Mapping[str, object], field: str, *, nonempty: bool = True) -> str:
    value = mapping.get(field)
    if type(value) is not str or (nonempty and not value):
        raise FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", f"{field} is not a string")
    return value


def _boolean(mapping: Mapping[str, object], field: str) -> bool:
    value = mapping.get(field)
    if type(value) is not bool:
        raise FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", f"{field} is not boolean")
    return value


def _integer(mapping: Mapping[str, object], field: str) -> int:
    value = mapping.get(field)
    if type(value) is not int:
        raise FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", f"{field} is not integer")
    return value


def _strings(mapping: Mapping[str, object], field: str) -> tuple[str, ...]:
    value = mapping.get(field)
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", f"{field} is not a sequence")
    result = tuple(value)
    if not all(type(item) is str for item in result):
        raise FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", f"{field} contains non-strings")
    return cast(tuple[str, ...], result)


def adapt_lifecycle_terminal_output(payload: object) -> QualificationLifecycleEvidence:
    """Adapt one real runner terminal line into the trusted typed record."""

    root = _mapping(payload, "terminal output")
    if root.get("terminal") is False:
        raise FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", "terminal marker is false")
    acquisition = _mapping(root.get("acquisition"), "acquisition")
    native = _mapping(root.get("native"), "native")
    source = _mapping(acquisition.get("lifecycle_evidence"), "lifecycle_evidence")
    evidence = _mapping(source.get("evidence"), "lifecycle_evidence.evidence")
    if evidence.get("record_schema") != QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA:
        raise FormalCampaignError(
            "RECORD_SCHEMA_MISMATCH", "lifecycle record schema is unsupported"
        )

    worker_identity = _string(native, "worker_identity")
    worker_hash = _string(native, "worker_compatibility_hash")
    if len(worker_hash) > 4096:
        raise FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", "worker hash is malformed")
    terminal_evidence = dict(evidence)
    terminal_evidence.update(
        {
            "worker_identity": worker_identity,
            "worker_compatibility_hash": worker_hash,
            "interpreter": _string(native, "interpreter"),
            "base_executable": _string(native, "base_executable"),
        }
    )
    if _integer(native, "owned_pending_tasks") != 0:
        raise FormalCampaignError("OWNED_PENDING_TASKS", "native terminal output has pending tasks")
    if not _boolean(native, "runtime_closed") or not _boolean(native, "eventbus_closed"):
        raise FormalCampaignError("NONTERMINAL_RUNTIME", "native runtime terminality is absent")
    if not _boolean(native, "appcontainer") or _integer(native, "job_limit") != 1:
        raise FormalCampaignError(
            "CONTAINMENT_EVIDENCE_INCOMPLETE", "native containment is incomplete"
        )
    try:
        record = QualificationLifecycleEvidence(
            qualification_run_id=_string(source, "qualification_run_id"),
            runtime_instance_id=_string(source, "runtime_instance_id"),
            capability_id=_string(source, "capability_id"),
            action_id=_string(source, "action_id"),
            package_id=_string(source, "package_id"),
            package_hash=_string(source, "package_hash"),
            payload_digest=_string(source, "payload_digest"),
            manifest_fingerprint=_string(source, "manifest_fingerprint"),
            certification_result=_string(source, "certification_result"),
            activation_id=_string(source, "activation_id"),
            activation_states=_strings(source, "activation_states"),
            active=_boolean(source, "active"),
            registry_identity=_string(source, "registry_identity"),
            persistence_result=_string(source, "persistence_result"),
            restart_restore_result=_string(source, "restart_restore_result"),
            cleanup_transaction_ids=_strings(source, "cleanup_transaction_ids"),
            cleanup_states=_strings(source, "cleanup_states"),
            unresolved_recovery_receipts=_strings(source, "unresolved_recovery_receipts"),
            worker_pids=tuple(_integer_sequence(source, "worker_pids")),
            appcontainer=_optional_boolean(source, "appcontainer"),
            job_limit=_optional_integer(source, "job_limit"),
            max_active=_optional_integer(source, "max_active"),
            eventbus_pending_consumers=_integer(source, "eventbus_pending_consumers"),
            runtime_closed=_boolean(source, "runtime_closed"),
            result=_string(source, "result"),
            failure_stage=_optional_string(source, "failure_stage"),
            typed_failure_code=_optional_string(source, "typed_failure_code"),
            evidence=terminal_evidence,
            eventbus_closed=_boolean(native, "eventbus_closed"),
        )
    except QualificationEvidenceError as error:
        raise FormalCampaignError("INCOMPLETE_EVIDENCE", str(error)) from error
    return record


def _integer_sequence(mapping: Mapping[str, object], field: str) -> tuple[int, ...]:
    value = mapping.get(field)
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", f"{field} is not a sequence")
    result = tuple(value)
    if not all(type(item) is int for item in result):
        raise FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", f"{field} contains non-integers")
    return cast(tuple[int, ...], result)


def _optional_string(mapping: Mapping[str, object], field: str) -> str | None:
    value = mapping.get(field)
    if value is not None and type(value) is not str:
        raise FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", f"{field} is not optional string")
    return value


def _optional_boolean(mapping: Mapping[str, object], field: str) -> bool | None:
    value = mapping.get(field)
    if value is not None and type(value) is not bool:
        raise FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", f"{field} is not optional boolean")
    return value


def _optional_integer(mapping: Mapping[str, object], field: str) -> int | None:
    value = mapping.get(field)
    if value is not None and type(value) is not int:
        raise FormalCampaignError("MALFORMED_TERMINAL_OUTPUT", f"{field} is not optional integer")
    return value


class RealQualificationLifecycleExecutor:
    """Execute exactly one fresh production lifecycle in a child process."""

    def __init__(
        self,
        *,
        interpreter: Path,
        root: Path,
        timeout_seconds: float = 600.0,
    ) -> None:
        if not interpreter.is_file():
            raise FormalCampaignError("INTERPRETER_UNAVAILABLE", str(interpreter))
        if timeout_seconds <= 0:
            raise FormalCampaignError("TIMEOUT_MALFORMED", "lifecycle timeout must be positive")
        self.interpreter = interpreter.resolve()
        self.root = root.resolve()
        self.timeout_seconds = timeout_seconds

    def execute(self, qualification_run_id: str) -> QualificationLifecycleEvidence:
        command = [
            str(self.interpreter),
            "-m",
            "pytest",
            "-q",
            "-s",
            DEFAULT_LIFECYCLE_TEST,
        ]
        environment = os.environ.copy()
        environment["JARVIS_R4R_ACQUISITION_ONLY"] = "1"
        environment["JARVIS_R4R_QUALIFICATION_RUN_ID"] = qualification_run_id
        started = datetime.now(UTC)
        process: subprocess.Popen[str] | None = None
        try:
            process = subprocess.Popen(
                command,
                cwd=self.root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=environment,
            )
            stdout, stderr = process.communicate(timeout=self.timeout_seconds)
        except subprocess.TimeoutExpired as error:
            if process is not None:
                process.kill()
                stdout, stderr = process.communicate()
            else:
                stdout, stderr = "", ""
            evidence = self._subprocess_evidence(
                qualification_run_id,
                command,
                process,
                started,
                stdout,
                stderr,
            )
            raise FormalCampaignError(
                "TIMEOUT",
                "real lifecycle exceeded hard timeout",
                subprocess_evidence=evidence,
            ) from error
        except OSError as error:
            raise FormalCampaignError("SUBPROCESS_START_FAILED", str(error)) from error
        assert process is not None
        returncode = process.returncode
        if returncode != 0:
            evidence = self._subprocess_evidence(
                qualification_run_id,
                command,
                process,
                started,
                stdout,
                stderr,
            )
            raise FormalCampaignError(
                "SUBPROCESS_NONZERO",
                f"real lifecycle exited {returncode}",
                subprocess_evidence=evidence,
            )
        lines = [
            line[len(LIFECYCLE_TERMINAL_PREFIX) :]
            for line in stdout.splitlines()
            if line.startswith(LIFECYCLE_TERMINAL_PREFIX)
        ]
        if len(lines) != 1:
            evidence = self._subprocess_evidence(
                qualification_run_id,
                command,
                process,
                started,
                stdout,
                stderr,
            )
            raise FormalCampaignError(
                "TERMINAL_RECORD_COUNT",
                f"expected one terminal record, found {len(lines)}",
                subprocess_evidence=evidence,
            )
        try:
            payload = json.loads(lines[0])
        except json.JSONDecodeError as error:
            evidence = self._subprocess_evidence(
                qualification_run_id,
                command,
                process,
                started,
                stdout,
                stderr,
            )
            raise FormalCampaignError(
                "MALFORMED_TERMINAL_OUTPUT",
                "terminal JSON is malformed",
                subprocess_evidence=evidence,
            ) from error
        evidence = self._subprocess_evidence(
            qualification_run_id,
            command,
            process,
            started,
            stdout,
            stderr,
            payload if isinstance(payload, Mapping) else None,
        )
        record = adapt_lifecycle_terminal_output(payload)
        if record.qualification_run_id != qualification_run_id:
            raise FormalCampaignError(
                "IDENTITY_MISMATCH",
                "terminal run identity does not match request",
                subprocess_evidence=evidence,
            )
        native = _mapping(_mapping(payload, "terminal output").get("native"), "native")
        if os.path.normcase(str(native["interpreter"])) != os.path.normcase(str(self.interpreter)):
            raise FormalCampaignError(
                "INTERPRETER_MISMATCH",
                "terminal interpreter is not bound",
                subprocess_evidence=evidence,
            )
        return record

    def _subprocess_evidence(
        self,
        qualification_run_id: str,
        command: Sequence[str],
        process: subprocess.Popen[str] | None,
        started: datetime,
        stdout: str,
        stderr: str,
        terminal_output: Mapping[str, object] | None = None,
    ) -> LifecycleSubprocessEvidence:
        ended = datetime.now(UTC)
        artifact_dir = self.root / "artifacts" / "acceptance"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        safe_id = "".join(
            character if character.isalnum() or character in "-_." else "_"
            for character in qualification_run_id
        )
        stdout_file = artifact_dir / f"{safe_id}.stdout.log"
        stderr_file = artifact_dir / f"{safe_id}.stderr.log"
        stdout_file.write_text(stdout, encoding="utf-8")
        stderr_file.write_text(stderr, encoding="utf-8")
        return LifecycleSubprocessEvidence(
            argv=tuple(command),
            pid=process.pid if process is not None else None,
            started_at=started.isoformat().replace("+00:00", "Z"),
            ended_at=ended.isoformat().replace("+00:00", "Z"),
            returncode=process.returncode if process is not None else None,
            stdout_path=stdout_file.relative_to(self.root).as_posix(),
            stderr_path=stderr_file.relative_to(self.root).as_posix(),
            stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest(),
            terminal_output=terminal_output,
            last_completed_phase=_last_completed_phase(terminal_output),
        )


def validate_lifecycle_record(record: object) -> QualificationLifecycleEvidence:
    """Apply the formal eligibility checks before controller submission."""

    if not isinstance(record, QualificationLifecycleEvidence):
        raise FormalCampaignError("INCOMPLETE_EVIDENCE", "lifecycle result is not typed evidence")
    if record.certification_result != "PASS":
        raise FormalCampaignError("CERTIFICATION_NOT_PASS", "certification did not pass")
    required_states = {"CERTIFIED", "SHADOW", "CANARY", "ACTIVE"}
    if not record.active or not required_states.issubset(record.activation_states):
        raise FormalCampaignError("INCOMPLETE_ACTIVATION", "activation lifecycle is incomplete")
    if not record.activation_id:
        raise FormalCampaignError("MISSING_ACTIVATION", "activation identity is absent")
    if not record.cleanup_transaction_ids or not record.cleanup_states:
        raise FormalCampaignError("MISSING_CLEANUP", "cleanup evidence is absent")
    if any(
        state not in {"CLEANUP_CONFIRMED", "CLEANUP_FAILED_CONFIRMED"}
        for state in record.cleanup_states
    ):
        raise FormalCampaignError("CLEANUP_NOT_TERMINAL", "cleanup is not terminal")
    if record.unresolved_recovery_receipts:
        raise FormalCampaignError("UNRESOLVED_RECOVERY", "recovery remains unresolved")
    if not record.runtime_closed:
        raise FormalCampaignError("RUNTIME_NOT_CLOSED", "runtime is not terminal")
    if not record.eventbus_closed:
        raise FormalCampaignError("EVENTBUS_NOT_CLOSED", "EventBus is not terminal")
    if record.eventbus_pending_consumers != 0:
        raise FormalCampaignError("OWNED_PENDING_TASKS", "owned pending tasks remain")
    if record.appcontainer is not True or record.job_limit != 1 or record.max_active != 1:
        raise FormalCampaignError(
            "CONTAINMENT_EVIDENCE_INCOMPLETE", "native containment evidence is incomplete"
        )
    if record.result != "QUALIFICATION_PASS":
        raise FormalCampaignError("LIFECYCLE_FAILURE", "lifecycle did not qualify")
    worker_hash = record.evidence.get("worker_compatibility_hash")
    worker_identity = record.evidence.get("worker_identity")
    if type(worker_identity) is not str or not worker_identity:
        raise FormalCampaignError("WORKER_EVIDENCE_INCOMPLETE", "worker identity is absent")
    if type(worker_hash) is not str or not worker_hash or len(worker_hash) > 4096:
        raise FormalCampaignError("WORKER_EVIDENCE_INCOMPLETE", "worker hash is malformed")
    return record


@dataclass(frozen=True, slots=True)
class FormalCampaignResult:
    campaign_run_id: str
    campaign_kind: FormalCampaignKind
    required_count: int
    attempt_count: int
    accepted_count: int
    terminal_status: CampaignState
    source_seal: str
    source_bound_file_count: int
    started_at: str
    ended_at: str
    interpreter: str
    base_executable: str
    lifecycle_records: tuple[dict[str, object], ...]
    first_failure: str | None
    failed_attempt: dict[str, object] | None
    replacement_attempts: int
    retry_attempts: int

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": FORMAL_CAMPAIGN_RESULT_SCHEMA,
            "campaign_run_id": self.campaign_run_id,
            "campaign_kind": self.campaign_kind.value,
            "required_count": self.required_count,
            "attempt_count": self.attempt_count,
            "accepted_count": self.accepted_count,
            "terminal_status": self.terminal_status.value,
            "source_seal": self.source_seal,
            "source_bound_file_count": self.source_bound_file_count,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "interpreter": self.interpreter,
            "base_executable": self.base_executable,
            "lifecycle_records": list(self.lifecycle_records),
            "first_failure": self.first_failure,
            "failed_attempt": self.failed_attempt,
            "replacement_attempts": self.replacement_attempts,
            "retry_attempts": self.retry_attempts,
        }


class FormalCampaignExecutor:
    """Run one finite, sealed campaign with no retry or replacement path."""

    def __init__(
        self,
        *,
        campaign: ConsecutiveQualificationCampaign,
        campaign_run_id: str,
        kind: FormalCampaignKind,
        lifecycle_executor: LifecycleExecutor,
        source_seal: str,
        source_seal_provider: Callable[[], str],
        source_bound_file_count: int,
        interpreter: str,
        base_executable: str,
        source_bound_file_count_provider: Callable[[], int] | None = None,
    ) -> None:
        if campaign_run_id == "" or source_seal == "":
            raise FormalCampaignError("IDENTITY_MALFORMED", "campaign identity is malformed")
        if source_bound_file_count <= 0:
            raise FormalCampaignError("SOURCE_BINDING_MALFORMED", "bound file count is malformed")
        if campaign.snapshot.required_success_count != kind.required_count:
            raise FormalCampaignError("CAMPAIGN_KIND_MISMATCH", "campaign kind and count differ")
        self._campaign = campaign
        self._campaign_run_id = campaign_run_id
        self._kind = kind
        self._lifecycle_executor = lifecycle_executor
        self._source_seal = source_seal
        self._source_seal_provider = source_seal_provider
        self._source_bound_file_count = source_bound_file_count
        self._interpreter = interpreter
        self._base_executable = base_executable
        self._source_bound_file_count_provider = source_bound_file_count_provider

    def _source_matches(self) -> bool:
        return self._source_seal_provider() == self._source_seal and (
            self._source_bound_file_count_provider is None
            or self._source_bound_file_count_provider() == self._source_bound_file_count
        )

    def execute(self) -> FormalCampaignResult:
        started = datetime.now(UTC)
        records: list[dict[str, object]] = []
        attempts = 0
        first_failure: str | None = None
        failed_attempt: dict[str, object] | None = None
        for attempt in range(1, self._kind.required_count + 1):
            if not self._source_matches():
                first_failure = "SOURCE_SEAL_MISMATCH"
                self._fail(first_failure)
                break
            attempts += 1
            try:
                record = validate_lifecycle_record(
                    self._lifecycle_executor.execute(f"{self._campaign_run_id}-attempt-{attempt}")
                )
            except FormalCampaignError as error:
                first_failure = error.code
                failed_attempt = _failed_attempt(attempt, error)
                self._fail(first_failure)
                break
            except Exception:  # defensive boundary for native/subprocess failures
                first_failure = "LIFECYCLE_EXECUTION_ERROR"
                failed_attempt = {
                    "attempt": attempt,
                    "failure_code": first_failure,
                }
                self._fail(first_failure)
                break
            if not self._source_matches():
                first_failure = "SOURCE_SEAL_MISMATCH"
                self._fail(first_failure)
                break
            snapshot = self._campaign.submit(record, source_seal=self._source_seal)
            if snapshot.state is CampaignState.FAILED:
                first_failure = snapshot.failure_code or "CAMPAIGN_FAILED"
                break
            records.append(_record_result(record))
            if snapshot.state is CampaignState.SUCCEEDED:
                break
        if not self._source_matches():
            first_failure = first_failure or "SOURCE_SEAL_MISMATCH"
            self._fail(first_failure)
        snapshot = self._campaign.snapshot
        ended = datetime.now(UTC)
        return FormalCampaignResult(
            campaign_run_id=self._campaign_run_id,
            campaign_kind=self._kind,
            required_count=self._kind.required_count,
            attempt_count=attempts,
            accepted_count=snapshot.accepted_records,
            terminal_status=snapshot.state,
            source_seal=self._source_seal,
            source_bound_file_count=self._source_bound_file_count,
            started_at=started.isoformat().replace("+00:00", "Z"),
            ended_at=ended.isoformat().replace("+00:00", "Z"),
            interpreter=self._interpreter,
            base_executable=self._base_executable,
            lifecycle_records=tuple(records),
            first_failure=first_failure or snapshot.failure_code,
            failed_attempt=failed_attempt,
            replacement_attempts=0,
            retry_attempts=0,
        )

    def _fail(self, code: str) -> CampaignSnapshot:
        if self._campaign.snapshot.state is CampaignState.FAILED:
            return self._campaign.snapshot
        if self._campaign.snapshot.state is CampaignState.SUCCEEDED:
            return self._campaign.fail_closed(code)
        return self._campaign.abort(code)


def _record_result(record: QualificationLifecycleEvidence) -> dict[str, object]:
    encoded = json.dumps(record.as_dict(), sort_keys=True, separators=(",", ":")).encode()
    return {
        "qualification_run_id": record.qualification_run_id,
        "capability_id": record.capability_id,
        "action_id": record.action_id,
        "package_id": record.package_id,
        "package_hash": record.package_hash,
        "activation_id": record.activation_id,
        "evidence_digest": hashlib.sha256(encoded).hexdigest(),
    }


def _failed_attempt(attempt: int, error: FormalCampaignError) -> dict[str, object]:
    result: dict[str, object] = {
        "attempt": attempt,
        "failure_code": error.code,
    }
    if error.subprocess_evidence is not None:
        result["subprocess"] = error.subprocess_evidence.as_dict()
    return result


def _last_completed_phase(payload: Mapping[str, object] | None) -> str | None:
    if payload is None:
        return None
    acquisition = payload.get("acquisition")
    if not isinstance(acquisition, Mapping):
        return None
    lifecycle = acquisition.get("lifecycle_evidence")
    if not isinstance(lifecycle, Mapping):
        return None
    evidence = lifecycle.get("evidence")
    if not isinstance(evidence, Mapping):
        return None
    phase = evidence.get("sandbox_phase")
    return phase if type(phase) is str and phase else None


def interpreter_identity(interpreter: Path) -> tuple[str, str]:
    """Return the executable identity recorded by the campaign result."""

    if interpreter.resolve() == Path(sys.executable).resolve():
        return str(interpreter), str(getattr(sys, "_base_executable", sys.executable))
    return str(interpreter), str(interpreter)
