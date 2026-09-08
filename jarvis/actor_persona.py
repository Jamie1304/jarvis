"""Trusted interaction provenance and the bounded presentation persona.

This module deliberately keeps two different concepts separate: an
``ActorContext`` is short-lived trusted session provenance, while a persona is
only presentation preference.  Neither is model- or memory-derived authority.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import cast
from uuid import UUID, uuid4

from jarvis.memory.models import RetentionPolicy, Sensitivity
from jarvis.permissions.models import ApprovalActorKind, ApprovalIdentity
from jarvis.user_model import (
    UserModelKind,
    UserModelOrigin,
    UserModelRecord,
    UserModelSource,
    UserModelStore,
)


class ActorContextSource(StrEnum):
    LOCAL_DESKTOP_SESSION = "local_desktop_session"
    AUTHENTICATED_APPLICATION_SESSION = "authenticated_application_session"
    SYSTEM_SERVICE = "system_service"


class ForbiddenActorSource(StrEnum):
    MODEL = "model"
    MEMORY_INFERENCE = "memory_inference"
    VOICE_RECOGNITION = "voice_recognition"
    FACE_RECOGNITION = "face_recognition"
    GESTURE = "gesture"
    FREE_TEXT_NAME = "free_text_name"
    LLM_GUESS = "llm_guess"


class ActorContextState(StrEnum):
    ACTIVE = "active"
    ENDED = "ended"


@dataclass(frozen=True, slots=True)
class ActorContext:
    context_id: UUID
    session_id: UUID
    principal_id: str
    source: ActorContextSource
    created_at: datetime
    expires_at: datetime | None = None
    display_label: str | None = None
    state: ActorContextState = ActorContextState.ACTIVE

    def is_active(self, now: datetime | None = None) -> bool:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        return self.state is ActorContextState.ACTIVE and (
            self.expires_at is None or current < self.expires_at
        )

    def require_active(self, now: datetime | None = None) -> None:
        if not self.is_active(now):
            raise PermissionError("Actor context is stale or ended")


class ActorContextService:
    """Application-owned factory; no untrusted input can mint a context."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._contexts: dict[UUID, ActorContext] = {}

    def create_trusted(
        self,
        *,
        session_id: UUID,
        principal_id: str,
        source: ActorContextSource,
        display_label: str | None = None,
        ttl_seconds: int | None = None,
    ) -> ActorContext:
        if (
            not isinstance(session_id, UUID)
            or not isinstance(principal_id, str)
            or not principal_id
        ):
            raise ValueError("Trusted actor context requires typed session provenance")
        if not isinstance(source, ActorContextSource):
            raise ValueError("Actor context source must be trusted application provenance")
        if ttl_seconds is not None and (type(ttl_seconds) is not int or ttl_seconds <= 0):
            raise ValueError("Actor context lifetime is invalid")
        now = self._clock().astimezone(UTC)
        context = ActorContext(
            uuid4(),
            session_id,
            principal_id,
            source,
            now,
            now + timedelta(seconds=ttl_seconds) if ttl_seconds is not None else None,
            display_label,
        )
        self._contexts[context.context_id] = context
        return context

    def end(self, context: ActorContext) -> None:
        current = self._contexts.get(context.context_id)
        if current is not context:
            raise PermissionError("Actor context does not belong to this application")
        self._contexts[context.context_id] = replace(current, state=ActorContextState.ENDED)

    def require_active(self, context: ActorContext) -> ActorContext:
        current = self._contexts.get(context.context_id)
        if current is not context:
            raise PermissionError("Actor context is unknown or belongs to another session")
        current.require_active(self._clock())
        return current

    def approval_identity(self, context: ActorContext) -> ApprovalIdentity:
        self.require_active(context)
        return ApprovalIdentity(context.principal_id, ApprovalActorKind.TRUSTED_USER)


@dataclass(frozen=True, slots=True)
class PersonaProfile:
    formality: int = 2
    verbosity: int = 2
    directness: int = 2
    technical_depth: int = 2
    humor_level: int = 0
    initiative: int = 1
    uncertainty_detail: int = 2
    response_length: int = 2

    def __post_init__(self) -> None:
        values = (
            self.formality,
            self.verbosity,
            self.directness,
            self.technical_depth,
            self.humor_level,
            self.initiative,
            self.uncertainty_detail,
            self.response_length,
        )
        if any(type(value) is not int or not 0 <= value <= 4 for value in values):
            raise ValueError("Persona values must be integers from 0 through 4")

    @classmethod
    def defaults(cls) -> PersonaProfile:
        return cls()

    def as_dict(self) -> dict[str, int]:
        return {name: int(getattr(self, name)) for name in self.__dataclass_fields__}

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> PersonaProfile:
        names = set(cls.__dataclass_fields__)
        if set(value) != names:
            raise ValueError("Persona schema is unknown or incomplete")
        return cls(**{name: cast(int, value[name]) for name in names})


class PersonaKernel:
    """Bounded persona projection backed by the existing user-model store."""

    _KEY = "persona.profile"
    _CATEGORY = "presentation"

    def __init__(
        self, store: UserModelStore, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))

    def get(self) -> PersonaProfile:
        records = self._store.list(include_global=True, include_inferred=True)
        record = next((item for item in records if item.key == self._KEY and item.active), None)
        if record is None:
            return PersonaProfile.defaults()
        try:
            if not isinstance(record.value, Mapping):
                raise ValueError("Stored persona value is not an object")
            return PersonaProfile.from_mapping(record.value)
        except (TypeError, ValueError) as error:
            raise ValueError("Stored persona schema is invalid") from error

    def update(self, **updates: object) -> PersonaProfile:
        current = self.get()
        profile = PersonaProfile.from_mapping({**current.as_dict(), **updates})
        records = self._store.list(include_global=True, include_inferred=True)
        record = next((item for item in records if item.key == self._KEY and item.active), None)
        now = self._clock().astimezone(UTC)
        if record is None:
            self._store.create(
                UserModelRecord(
                    uuid4(),
                    None,
                    self._KEY,
                    UserModelKind.PREFERENCE,
                    self._CATEGORY,
                    profile.as_dict(),
                    UserModelSource.USER,
                    "persona-settings",
                    1.0,
                    now,
                    now,
                    now,
                    Sensitivity.PRIVATE,
                    RetentionPolicy.UNTIL_DELETED,
                    UserModelOrigin.EXPLICIT,
                )
            )
        else:
            self._store.correct(
                record.record_id, value=profile.as_dict(), source_reference="persona-settings"
            )
        return profile

    def reset(self) -> PersonaProfile:
        records = self._store.list(include_global=True, include_inferred=True)
        record = next((item for item in records if item.key == self._KEY and item.active), None)
        if record is not None:
            self._store.delete(record.record_id, reason="persona reset to safe defaults")
        return PersonaProfile.defaults()


__all__ = [
    "ActorContext",
    "ActorContextService",
    "ActorContextSource",
    "ActorContextState",
    "ForbiddenActorSource",
    "PersonaKernel",
    "PersonaProfile",
]
