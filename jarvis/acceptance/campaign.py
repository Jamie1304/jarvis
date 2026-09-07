"""Fail-closed deterministic controllers for future formal campaigns."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from jarvis.acceptance.evidence import (
    QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA,
    QualificationLifecycleEvidence,
)


class CampaignState(StrEnum):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class CampaignError(ValueError):
    """A campaign record cannot be accepted or the campaign cannot continue."""


@dataclass(frozen=True, slots=True)
class CampaignSnapshot:
    required_success_count: int
    attempts: int
    accepted_records: int
    state: CampaignState
    failure_code: str | None


class ConsecutiveQualificationCampaign:
    """Consume authoritative complete records without retry/replacement semantics."""

    RECORD_SCHEMA: Final[str] = QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA

    def __init__(
        self, *, required_success_count: int, source_seal: str, record_schema: str
    ) -> None:
        if type(required_success_count) is not int or required_success_count <= 0:
            raise CampaignError("required success count is malformed")
        if type(source_seal) is not str or not source_seal:
            raise CampaignError("source seal is malformed")
        if record_schema != self.RECORD_SCHEMA:
            raise CampaignError("record schema is unsupported")
        self._required = required_success_count
        self._source_seal = source_seal
        self._attempts = 0
        self._records: list[QualificationLifecycleEvidence] = []
        self._state = CampaignState.RUNNING
        self._failure_code: str | None = None
        self._capability_ids: set[str] = set()
        self._package_ids: set[str] = set()
        self._package_hashes: set[str] = set()
        self._activation_ids: set[str] = set()
        self._run_ids: set[str] = set()

    @property
    def snapshot(self) -> CampaignSnapshot:
        return CampaignSnapshot(
            self._required,
            self._attempts,
            len(self._records),
            self._state,
            self._failure_code,
        )

    @property
    def records(self) -> tuple[QualificationLifecycleEvidence, ...]:
        return tuple(self._records)

    def submit(
        self, record: QualificationLifecycleEvidence, *, source_seal: str
    ) -> CampaignSnapshot:
        if self._state is not CampaignState.RUNNING:
            raise CampaignError("campaign is terminal; replacement or retry is prohibited")
        self._attempts += 1
        if source_seal != self._source_seal:
            return self._fail("SOURCE_SEAL_MISMATCH")
        if not isinstance(record, QualificationLifecycleEvidence):
            return self._fail("INCOMPLETE_EVIDENCE")
        if record.evidence.get("record_schema") != self.RECORD_SCHEMA:
            return self._fail("RECORD_SCHEMA_MISMATCH")
        if not record.activation_id:
            return self._fail("MISSING_ACTIVATION")
        if record.certification_result != "PASS":
            return self._fail("CERTIFICATION_NOT_PASS")
        if not record.active or "ACTIVE" not in record.activation_states:
            return self._fail("INCOMPLETE_ACTIVATION")
        if not record.cleanup_transaction_ids or not record.cleanup_states:
            return self._fail("MISSING_CLEANUP")
        if any(
            state not in {"CLEANUP_CONFIRMED", "CLEANUP_FAILED_CONFIRMED"}
            for state in record.cleanup_states
        ):
            return self._fail("CLEANUP_NOT_TERMINAL")
        if record.unresolved_recovery_receipts:
            return self._fail("UNRESOLVED_RECOVERY")
        if not record.runtime_closed:
            return self._fail("RUNTIME_NOT_CLOSED")
        if not record.eventbus_closed:
            return self._fail("EVENTBUS_NOT_CLOSED")
        if record.eventbus_pending_consumers != 0:
            return self._fail("OWNED_PENDING_TASKS")
        if record.result != "QUALIFICATION_PASS":
            return self._fail("LIFECYCLE_FAILURE")
        if record.capability_id in self._capability_ids:
            return self._fail("DUPLICATE_CAPABILITY")
        if record.package_id in self._package_ids:
            return self._fail("DUPLICATE_PACKAGE")
        if record.package_hash in self._package_hashes:
            return self._fail("DUPLICATE_HASH")
        if record.activation_id in self._activation_ids:
            return self._fail("DUPLICATE_ACTIVATION")
        if record.qualification_run_id in self._run_ids:
            return self._fail("DUPLICATE_RUN")
        self._capability_ids.add(record.capability_id)
        self._package_ids.add(record.package_id)
        self._package_hashes.add(record.package_hash)
        self._activation_ids.add(record.activation_id)
        self._run_ids.add(record.qualification_run_id)
        self._records.append(record)
        if len(self._records) == self._required:
            self._state = CampaignState.SUCCEEDED
        return self.snapshot

    def _fail(self, code: str) -> CampaignSnapshot:
        self._state = CampaignState.FAILED
        self._failure_code = code
        return self.snapshot

    def abort(self, code: str) -> CampaignSnapshot:
        """Terminally abort an execution that cannot produce a record."""

        if self._state is not CampaignState.RUNNING:
            raise CampaignError("campaign is terminal; replacement or retry is prohibited")
        if type(code) is not str or not code:
            raise CampaignError("campaign failure code is malformed")
        return self._fail(code)

    def fail_closed(self, code: str) -> CampaignSnapshot:
        """Invalidate a completed result when its final source seal changed."""

        if self._state is CampaignState.FAILED:
            return self.snapshot
        if type(code) is not str or not code:
            raise CampaignError("campaign failure code is malformed")
        return self._fail(code)
