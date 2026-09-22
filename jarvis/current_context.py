"""Bounded, rebuildable composition of the application's current state."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from jarvis.actor_persona import ActorContext, ActorContextService, PersonaKernel, PersonaProfile
from jarvis.conversation.service import ConversationService
from jarvis.human_adaptation import HumanAdaptationService
from jarvis.planning.models import PlanningTaskStatus
from jarvis.presence import PresenceSnapshot, PresenceState
from jarvis.task_controller import TaskController


class CurrentContextError(ValueError):
    """A current-context reference or projection value is malformed."""


class ProviderReadiness(StrEnum):
    """Provider state that can be stated without performing a network probe."""

    NOT_PROBED = "not_probed"


@dataclass(frozen=True, slots=True)
class CurrentActorProjection:
    """Trusted actor provenance, kept separate from presentation persona."""

    context_id: UUID
    session_id: UUID
    source: str
    active: bool


@dataclass(frozen=True, slots=True)
class CurrentProviderProjection:
    """Configured provider identity; readiness is absent until an owner probes it."""

    provider_id: str | None
    model_id: str | None
    available: bool | None
    readiness: ProviderReadiness | None


@dataclass(frozen=True, slots=True)
class CurrentStewardshipProjection:
    """Small bounded stewardship state safe for current-context projection."""

    storage_pressure: str = "unknown"
    critical_disk: bool | None = None
    acquisition_active: bool | None = None
    task_waiting_for_resource: bool = False
    maintenance_deferred: bool = False
    security_state: str = "unknown"
    model_retirement_pending: bool = False

    def __post_init__(self) -> None:
        values = (
            self.storage_pressure,
            self.security_state,
        )
        if any(type(value) is not str or not value or len(value) > 64 for value in values):
            raise CurrentContextError("Current stewardship state is malformed")
        if self.critical_disk not in {None, True, False}:
            raise CurrentContextError("Current critical-disk state is malformed")
        if self.acquisition_active not in {None, True, False}:
            raise CurrentContextError("Current acquisition state is malformed")
        if type(self.task_waiting_for_resource) is not bool:
            raise CurrentContextError("Current waiting-resource state is malformed")
        if type(self.maintenance_deferred) is not bool:
            raise CurrentContextError("Current maintenance state is malformed")
        if type(self.model_retirement_pending) is not bool:
            raise CurrentContextError("Current model-retirement state is malformed")


@dataclass(frozen=True, slots=True)
class CurrentContextModelProjection:
    """Safe descriptive fields suitable for future model-context assembly."""

    actor_source: str | None
    persona: PersonaProfile
    conversation_id: UUID | None
    conversation_session_id: UUID | None
    task_id: UUID | None
    task_status: PlanningTaskStatus | None
    presence: PresenceState | None
    runtime_state: str
    safe_mode: bool
    provider_id: str | None
    model_id: str | None
    interface_language: str = "en"
    conversation_language: str = "en"
    locale: str = "en-US"
    personalization_mode: str = "explicit_only"
    learning_paused: bool = True
    stewardship: CurrentStewardshipProjection = field(default_factory=CurrentStewardshipProjection)


@dataclass(frozen=True, slots=True)
class CurrentContextSnapshot:
    """Read-only current state assembled from canonical application owners."""

    revision: int
    captured_at: datetime
    actor: CurrentActorProjection | None
    persona: PersonaProfile
    active_conversation_id: UUID | None
    conversation_session_id: UUID | None
    active_task_id: UUID | None
    active_task_status: PlanningTaskStatus | None
    presence: PresenceSnapshot | None
    runtime_state: str
    safe_mode: bool
    provider: CurrentProviderProjection
    provenance: tuple[tuple[str, str], ...]
    interface_language: str = "en"
    conversation_language: str = "en"
    locale: str = "en-US"
    personalization_mode: str = "explicit_only"
    learning_paused: bool = True
    stewardship: CurrentStewardshipProjection = field(default_factory=CurrentStewardshipProjection)

    def __post_init__(self) -> None:
        if type(self.revision) is not int or self.revision < 0:
            raise CurrentContextError("Current-context revision is malformed")
        if self.captured_at.tzinfo is None:
            raise CurrentContextError("Current-context timestamp must be timezone-aware")
        if not isinstance(self.persona, PersonaProfile):
            raise CurrentContextError("Current-context persona is malformed")
        if type(self.runtime_state) is not str or not self.runtime_state:
            raise CurrentContextError("Current-context runtime state is malformed")
        if type(self.safe_mode) is not bool:
            raise CurrentContextError("Current-context safe-mode state is malformed")
        if not isinstance(self.stewardship, CurrentStewardshipProjection):
            raise CurrentContextError("Current-context stewardship state is malformed")

    def model_projection(self) -> CurrentContextModelProjection:
        """Return only bounded descriptive state; no authority or private data."""

        return CurrentContextModelProjection(
            self.actor.source if self.actor is not None else None,
            self.persona,
            self.active_conversation_id,
            self.conversation_session_id,
            self.active_task_id,
            self.active_task_status,
            self.presence.state if self.presence is not None else None,
            self.runtime_state,
            self.safe_mode,
            self.provider.provider_id,
            self.provider.model_id,
            self.interface_language,
            self.conversation_language,
            self.locale,
            self.personalization_mode,
            self.learning_paused,
            self.stewardship,
        )

    @classmethod
    def safe_mode_snapshot(cls, runtime_state: str, *, revision: int = 0) -> CurrentContextSnapshot:
        """Build a truthful projection when normal runtime services are unavailable."""

        return cls(
            revision,
            datetime.now(UTC),
            None,
            PersonaProfile.defaults(),
            None,
            None,
            None,
            None,
            None,
            runtime_state,
            True,
            CurrentProviderProjection(None, None, None, None),
            (
                ("actor", "ActorContextService; unavailable in Safe Mode"),
                ("persona", "PersonaKernel defaults; no persistent read performed"),
                ("runtime", "ApplicationRuntime"),
                ("provider", "not available in Safe Mode"),
            ),
            "en",
            "en",
            "en-US",
            "explicit_only",
            True,
        )


class CurrentContextService:
    """Runtime-owned projection; it stores only bounded active references."""

    def __init__(
        self,
        *,
        actor_context_service: ActorContextService,
        actor_context: ActorContext,
        persona_kernel: PersonaKernel,
        conversation: ConversationService,
        task_controller: TaskController,
        presence: Callable[[], PresenceSnapshot],
        runtime_state: str,
        safe_mode: bool,
        provider_id: str | None,
        model_id: str | None,
        human_adaptation: HumanAdaptationService | None = None,
        stewardship: Callable[[], CurrentStewardshipProjection] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._actor_context_service = actor_context_service
        self._actor_context = actor_context
        self._persona = persona_kernel
        self._conversation = conversation
        self._tasks = task_controller
        self._presence = presence
        self._runtime_state = runtime_state
        self._safe_mode = safe_mode
        self._provider_id = provider_id
        self._model_id = model_id
        self._human_adaptation = human_adaptation
        self._stewardship = stewardship
        self._clock = clock or (lambda: datetime.now(UTC))
        self._active_conversation_id: UUID | None = None
        self._active_task_id: UUID | None = None
        self._revision = 0

    def select_conversation(self, conversation_id: UUID) -> None:
        if not isinstance(conversation_id, UUID) or not self._conversation.has_conversation(
            conversation_id
        ):
            raise CurrentContextError("Conversation reference is not owned by ConversationService")
        self._active_conversation_id = conversation_id
        self._revision += 1

    def select_task(self, task_id: UUID) -> None:
        if not isinstance(task_id, UUID) or self._tasks.get_task(task_id) is None:
            raise CurrentContextError("Task reference is not owned by TaskController")
        self._active_task_id = task_id
        self._revision += 1

    def clear_active_references(self) -> None:
        if self._active_conversation_id is not None or self._active_task_id is not None:
            self._active_conversation_id = None
            self._active_task_id = None
            self._revision += 1

    def snapshot(self) -> CurrentContextSnapshot:
        self._reconcile_references()
        conversation_id = self._active_conversation_id
        task_id = self._active_task_id
        task = self._tasks.get_task(task_id) if task_id is not None else None
        actor = self._actor_projection()
        presence = self._presence()
        if self._human_adaptation is None:
            preferences = None
            personalization = None
        else:
            preferences = self._human_adaptation.language_preferences()
            personalization = self._human_adaptation.personalization_settings()
        return CurrentContextSnapshot(
            self._revision,
            self._clock().astimezone(UTC),
            actor,
            self._persona.get(),
            conversation_id,
            self._conversation.session_id(conversation_id) if conversation_id is not None else None,
            task_id,
            task.status if task is not None else None,
            presence,
            self._runtime_state,
            self._safe_mode,
            CurrentProviderProjection(
                self._provider_id,
                self._model_id,
                None,
                ProviderReadiness.NOT_PROBED if self._provider_id is not None else None,
            ),
            (
                ("actor", "ActorContextService"),
                ("persona", "PersonaKernel / UserModelStore"),
                ("conversation", "ConversationService"),
                ("conversation_session", "ConversationService -> AgentSessionStore"),
                ("task", "TaskController / PlanningEngine"),
                ("presence", "PresenceProjection"),
                ("runtime", "ApplicationRuntime"),
                ("provider", "Runtime configuration; readiness not probed by snapshot"),
            ),
            str(preferences.interface_language) if preferences else "en",
            str(self._human_adaptation.resolve_language().conversation.language)
            if self._human_adaptation
            else "en",
            preferences.locale if preferences else "en-US",
            str(personalization["mode"]) if personalization else "explicit_only",
            True
            if self._safe_mode
            else (bool(personalization["learning_paused"]) if personalization else True),
            self._stewardship()
            if self._stewardship is not None
            else CurrentStewardshipProjection(),
        )

    def _actor_projection(self) -> CurrentActorProjection | None:
        try:
            active = self._actor_context_service.require_active(self._actor_context).is_active()
        except PermissionError:
            active = False
        return CurrentActorProjection(
            self._actor_context.context_id,
            self._actor_context.session_id,
            self._actor_context.source.value,
            active,
        )

    def _reconcile_references(self) -> None:
        changed = False
        if self._active_conversation_id is not None and not self._conversation.has_conversation(
            self._active_conversation_id
        ):
            self._active_conversation_id = None
            changed = True
        if self._active_task_id is not None and self._tasks.get_task(self._active_task_id) is None:
            self._active_task_id = None
            changed = True
        if changed:
            self._revision += 1


__all__ = [
    "CurrentActorProjection",
    "CurrentContextError",
    "CurrentContextModelProjection",
    "CurrentContextService",
    "CurrentContextSnapshot",
    "CurrentStewardshipProjection",
    "CurrentProviderProjection",
    "ProviderReadiness",
]
