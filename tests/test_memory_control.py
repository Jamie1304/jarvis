"""Application/UI coverage for transparent, policy-bound memory controls."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from jarvis.application import JarvisAssistantService
from jarvis.conversation.service import ConversationService
from jarvis.memory.control import (
    MemoryControlDomain,
    MemoryControlEntry,
    MemoryControlQuery,
    MemoryControlReference,
    MemoryControlService,
    MemoryCorrection,
    MemoryVerificationViewStatus,
)
from jarvis.memory.models import (
    LongTermMemoryCandidate,
    MemoryProvenance,
    MemoryRecord,
    MemorySource,
    MemoryType,
    RetentionPolicy,
    Sensitivity,
)
from jarvis.memory.services import LongTermMemoryService
from jarvis.memory.store import SQLiteMemoryStore
from jarvis.user_model import (
    UserModelKind,
    UserModelOrigin,
    UserModelRecord,
    UserModelSource,
    UserModelStore,
)

from tests.fakes import FakeAIProvider


def _durable(now: datetime, *, source_reference: str = "ui:user") -> MemoryRecord:
    return MemoryRecord(
        memory_id=uuid4(),
        memory_type=MemoryType.LONG_TERM,
        content="The user prefers the concise format.",
        data=json.dumps({"preference": "concise"}),
        created_at=now,
        provenance=MemoryProvenance(MemorySource.USER, source_reference, now),
        confidence=0.9,
        retention=RetentionPolicy.ONE_YEAR,
        sensitivity=Sensitivity.PRIVATE,
        expires_at=RetentionPolicy.ONE_YEAR.expiry(now),
        updated_at=now,
    )


def _user(now: datetime) -> UserModelRecord:
    return UserModelRecord(
        record_id=uuid4(),
        workspace_id="workspace-a",
        key="communication.style",
        kind=UserModelKind.PREFERENCE,
        category="communication",
        value={"style": "concise"},
        source=UserModelSource.MODEL,
        source_reference="model:inference-1",
        confidence=0.8,
        created_at=now,
        updated_at=now,
        last_verified_at=None,
        sensitivity=Sensitivity.PRIVATE,
        retention=RetentionPolicy.ONE_YEAR,
        origin=UserModelOrigin.INFERRED,
    )


def _services(
    tmp_path: Path, now: datetime
) -> tuple[SQLiteMemoryStore, UserModelStore, MemoryControlService]:
    memory = SQLiteMemoryStore(tmp_path / "memory.sqlite3", clock=lambda: now)
    user_model = UserModelStore(tmp_path / "user-model.sqlite3", clock=lambda: now)
    return memory, user_model, MemoryControlService(memory, user_model, clock=lambda: now)


def test_inspection_exposes_filters_explanations_and_safe_provenance(tmp_path: Path) -> None:
    now = datetime(2026, 8, 24, tzinfo=UTC)
    memory, user_model, control = _services(tmp_path, now)
    try:
        durable = _durable(now, source_reference="Bearer secret-source-token")
        inferred = _user(now)
        memory.put(durable)
        user_model.create(inferred)

        user_entries = control.inspect(
            MemoryControlQuery(
                workspace_id="workspace-a",
                category="communication",
                sources=frozenset({"model"}),
                min_confidence=0.8,
            )
        )
        assert len(user_entries) == 1
        assert user_entries[0].reference.domain is MemoryControlDomain.USER_MODEL
        assert user_entries[0].belief == '{"style":"concise"}'
        assert "inferred" in user_entries[0].why
        assert user_entries[0].verification is MemoryVerificationViewStatus.NOT_VERIFIED

        durable_entries = control.inspect(
            MemoryControlQuery(category=MemoryType.LONG_TERM.value, sources=frozenset({"user"}))
        )
        assert len(durable_entries) == 1
        assert "Bearer" not in durable_entries[0].provenance
        assert "redacted" in durable_entries[0].provenance
        exported = control.export(MemoryControlQuery(category=MemoryType.LONG_TERM.value))
        assert exported[0]["belief"] == durable.content
        assert "secret-source-token" not in repr(exported)
    finally:
        memory.close()
        user_model.close()


def test_correction_retention_delete_and_retrieval_use_authoritative_stores(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 24, tzinfo=UTC)
    memory, user_model, control = _services(tmp_path, now)
    durable = _durable(now)
    inferred = _user(now)
    try:
        memory.put(durable)
        user_model.create(inferred)
        durable_ref = MemoryControlReference(MemoryControlDomain.DURABLE_MEMORY, durable.memory_id)
        corrected = control.correct(
            durable_ref,
            MemoryCorrection(
                "The user prefers the detailed format.",
                data={"preference": "detailed"},
                evidence=("user confirmed the correction",),
            ),
        )
        assert corrected.belief == "The user prefers the detailed format."
        assert (
            memory.search("detailed", MemoryType.LONG_TERM)[0].record.memory_id
            == corrected.reference.record_id
        )
        assert memory.search("concise", MemoryType.LONG_TERM) == ()

        changed = control.change_retention(corrected.reference, RetentionPolicy.THIRTY_DAYS)
        assert changed.retention is RetentionPolicy.THIRTY_DAYS

        user_ref = MemoryControlReference(MemoryControlDomain.USER_MODEL, inferred.record_id)
        explicit = control.mark_explicit(user_ref)
        assert explicit.source == "user"
        assert explicit.verification is MemoryVerificationViewStatus.VERIFIED
        assert control.delete(user_ref) is True
        assert control.inspect(MemoryControlQuery(workspace_id="workspace-a")) == ()
    finally:
        memory.close()
        user_model.close()


def test_learning_pause_and_reverification_are_durable_and_scoped(tmp_path: Path) -> None:
    now = datetime(2026, 8, 24, tzinfo=UTC)
    memory, user_model, control = _services(tmp_path, now)
    inferred = _user(now)
    try:
        assert control.pause_learning(True) is True
        assert control.learning_paused() is True
        with pytest.raises(PermissionError, match="paused"):
            user_model.create(inferred)
        with pytest.raises(PermissionError, match="paused"):
            LongTermMemoryService(memory).persist(
                LongTermMemoryCandidate(
                    content="The user prefers concise updates.",
                    data='{"preference":"concise"}',
                    provenance=MemoryProvenance(MemorySource.USER, "ui:user", now),
                    confidence=0.9,
                    retention=RetentionPolicy.ONE_YEAR,
                    sensitivity=Sensitivity.PRIVATE,
                    user_confirmed=True,
                )
            )
        assert control.pause_learning(False) is False
        user_model.create(inferred)
        reference = MemoryControlReference(MemoryControlDomain.USER_MODEL, inferred.record_id)
        request = control.request_reverification(reference, reason="please check this preference")
        assert request.status.value == "pending"
        assert control.inspect(MemoryControlQuery(workspace_id="workspace-a"))[0].verification is (
            MemoryVerificationViewStatus.REQUESTED
        )
    finally:
        memory.close()
        user_model.close()

    reopened_memory = SQLiteMemoryStore(tmp_path / "memory.sqlite3", clock=lambda: now)
    reopened_user_model = UserModelStore(tmp_path / "user-model.sqlite3", clock=lambda: now)
    try:
        reopened = MemoryControlService(reopened_memory, reopened_user_model)
        assert reopened.learning_paused() is False
        assert len(reopened.verification_requests(reference)) == 1
    finally:
        reopened_memory.close()
        reopened_user_model.close()


def test_forget_category_and_application_facade(tmp_path: Path) -> None:
    now = datetime(2026, 8, 24, tzinfo=UTC)
    memory, user_model, control = _services(tmp_path, now)
    record = _user(now)
    user_model.create(record)
    try:
        assistant = JarvisAssistantService(
            ConversationService(FakeAIProvider(("ready",)), model="fake", context_limit=256),
            memory_control=control,
        )
        entries = assistant.inspect_memory(MemoryControlQuery(workspace_id="workspace-a"))
        assert entries[0].category == "communication"
        assert assistant.forget_memory_category("communication", workspace_id="workspace-a") == 1
        assert assistant.inspect_memory(MemoryControlQuery(workspace_id="workspace-a")) == ()
    finally:
        memory.close()
        user_model.close()


def test_control_rejects_malformed_inputs_and_covers_all_scopes(tmp_path: Path) -> None:
    now = datetime(2026, 8, 24, tzinfo=UTC)
    memory, user_model, control = _services(tmp_path, now)
    durable = _durable(now)
    episodic = MemoryRecord(
        memory_id=uuid4(),
        memory_type=MemoryType.EPISODIC,
        content="A completed task was recorded.",
        data='{"outcome":"done"}',
        created_at=now,
        provenance=MemoryProvenance(MemorySource.TASK, "task:123", now, True),
        confidence=None,
        retention=RetentionPolicy.THIRTY_DAYS,
        sensitivity=Sensitivity.PRIVATE,
        expires_at=RetentionPolicy.THIRTY_DAYS.expiry(now),
        updated_at=now,
    )
    inferred = _user(now)
    memory.put(durable)
    memory.put(episodic)
    user_model.create(inferred)
    durable_ref = MemoryControlReference(MemoryControlDomain.DURABLE_MEMORY, durable.memory_id)
    episodic_ref = MemoryControlReference(MemoryControlDomain.DURABLE_MEMORY, episodic.memory_id)
    user_ref = MemoryControlReference(MemoryControlDomain.USER_MODEL, inferred.record_id)
    try:
        with pytest.raises(ValueError):
            MemoryControlReference("bad", uuid4())  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            MemoryControlReference(MemoryControlDomain.USER_MODEL, "bad")  # type: ignore[arg-type]
        with pytest.raises(PermissionError):
            MemoryControlQuery(sensitivities=frozenset({Sensitivity.SECRET}))
        with pytest.raises(ValueError):
            MemoryControlQuery(sources=frozenset(str(index) for index in range(17)))
        with pytest.raises(ValueError):
            MemoryControlQuery(min_confidence=0.9, max_confidence=0.1)
        with pytest.raises(ValueError):
            MemoryControlQuery(recency_after=now, recency_before=now - timedelta(days=1))
        with pytest.raises(ValueError):
            MemoryControlQuery(include_inactive=1)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            MemoryControlQuery(limit=0)
        with pytest.raises(ValueError):
            MemoryControlQuery(sources=frozenset({""}))
        with pytest.raises(ValueError):
            MemoryControlQuery(sources=frozenset({"not-a-source"}))
        with pytest.raises(ValueError):
            MemoryCorrection("")
        with pytest.raises(ValueError):
            MemoryCorrection("valid", data=[])  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            MemoryCorrection("valid", confidence=2)
        with pytest.raises(ValueError):
            MemoryCorrection("valid", sensitivity="private")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            MemoryCorrection("valid", retention="one_year")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            MemoryCorrection("valid", evidence=())
        with pytest.raises(PermissionError):
            MemoryCorrection("valid", evidence=("token=secret-value",))
        with pytest.raises(PermissionError):
            MemoryCorrection("valid", source_reference="api_key=secret-value")
        with pytest.raises(ValueError):
            control.inspect(object())  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            control.correct(object(), MemoryCorrection("valid"))  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            control.correct(durable_ref, object())  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            control.change_retention(durable_ref, "one_year")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            control.pause_learning(1)  # type: ignore[arg-type]
        with pytest.raises(PermissionError):
            control.request_reverification(user_ref, reason="token=secret-value")

        assert len(control.inspect(MemoryControlQuery(min_confidence=0))) == 3
        assert len(control.inspect(MemoryControlQuery(min_confidence=0.1))) == 2
        assert control.change_retention(user_ref, RetentionPolicy.THIRTY_DAYS).retention is (
            RetentionPolicy.THIRTY_DAYS
        )
        durable_request = control.request_reverification(durable_ref)
        assert (
            control.verification_requests(durable_ref)[0].request_id == durable_request.request_id
        )
        assert control.mark_explicit(durable_ref).source == "user"
        with pytest.raises(PermissionError):
            control.correct(episodic_ref, MemoryCorrection("not allowed"))
        with pytest.raises(PermissionError):
            control.mark_explicit(episodic_ref)
        assert control.delete(user_ref) is True
        assert control.delete(user_ref) is False
        assert control.forget_category(MemoryType.LONG_TERM.value) >= 1
        with pytest.raises(PermissionError):
            MemoryControlEntry(
                durable_ref,
                None,
                "long_term",
                "belief",
                "why",
                "provenance",
                "user",
                0.5,
                now,
                now,
                None,
                MemoryVerificationViewStatus.NOT_VERIFIED,
                None,
                (),
                RetentionPolicy.ONE_YEAR,
                Sensitivity.SECRET,
                False,
                False,
            )
    finally:
        memory.close()
        user_model.close()
