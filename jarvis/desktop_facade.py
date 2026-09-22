"""Application-owned, secret-safe projections for the optional desktop client."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from jarvis.actor_persona import PersonaProfile
from jarvis.ai.model_intelligence import ModelIntelligencePage, ModelIntelligenceProjection
from jarvis.ai.providers.registry import ProviderRegistry
from jarvis.application import JarvisAssistantService
from jarvis.attention import (
    AttentionItem,
    InterruptionClass,
)
from jarvis.control_center import ControlCenterSection
from jarvis.core.environment_settings import (
    EnvironmentSettingDescriptor,
    EnvironmentSettingsService,
)
from jarvis.core.errors import ServiceUnavailableError
from jarvis.current_context import CurrentContextSnapshot
from jarvis.human_adaptation import LanguagePreferences, LanguageTag, load_default_localizer
from jarvis.memory.control import MemoryControlReference, MemoryCorrection
from jarvis.memory.episodes import Episode
from jarvis.memory.models import RetentionPolicy
from jarvis.permissions import (
    ApprovalChoice,
    DesktopApprovalHandoff,
    TrustedDesktopApprovalSurface,
)
from jarvis.system_stewardship import StewardshipObservation, SystemStewardshipCoordinator
from jarvis.trace import TraceEvent, TraceEventType

if TYPE_CHECKING:
    from jarvis.runtime import ApplicationRuntime


@dataclass(frozen=True, slots=True)
class DesktopRow:
    """One bounded operational row for a desktop page."""

    identifier: str
    title: str
    status: str
    detail: str
    reference: MemoryControlReference | None = None


@dataclass(frozen=True, slots=True)
class DesktopRuntimeView:
    state: str
    version: str
    safe_mode: bool
    error: str | None
    provider: str | None
    model: str | None
    stt: str
    tts: str


@dataclass(frozen=True, slots=True)
class DesktopActorView:
    """Truthful session provenance; it never presents inferred identity."""

    session_id: UUID
    source: str
    label: str | None
    active: bool


@dataclass(frozen=True, slots=True)
class DesktopPersonaView:
    profile: PersonaProfile


@dataclass(frozen=True, slots=True)
class DesktopAttentionItemView:
    """Secret-safe presentation of one unresolved authoritative Attention item."""

    item_id: UUID
    interruption_class: str | None
    decision: str
    delivery_state: str
    reason_code: str | None
    summary: str
    created_at: datetime
    expires_at: datetime | None
    requires_user_action: bool
    related_task_id: UUID | None
    actor_context_id: UUID | None
    workspace: str


@dataclass(frozen=True, slots=True)
class DesktopAttentionView:
    """Bounded application-owned Attention detail and summary."""

    state: str
    unresolved_count: int
    highest_interruption_class: str | None
    highest_actionable_item_id: UUID | None
    items: tuple[DesktopAttentionItemView, ...]


@dataclass(frozen=True, slots=True)
class DesktopEpisodeView:
    """Read-only, bounded presentation of a durable episodic experience."""

    episode_id: UUID
    task_id: UUID
    category: str
    started_at: datetime | None
    ended_at: datetime
    outcome: str
    verification: str
    continuity: str
    action_summary: tuple[str, ...]
    evidence_references: tuple[str, ...]
    semantic_event_ids: tuple[UUID, ...]
    semantic_pattern_ids: tuple[UUID, ...]
    sensitivity: str
    provenance: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DesktopActivityItemView:
    """One bounded factual activity item suitable for operator display."""

    identifier: str
    category: str
    status: str
    occurred_at: datetime
    summary: str
    task_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class DesktopActivityView:
    state: str
    items: tuple[DesktopActivityItemView, ...]


@dataclass(frozen=True, slots=True)
class DesktopOverviewView:
    """Truthful bounded home projection assembled from the runtime owners."""

    runtime: DesktopRuntimeView
    actor: DesktopActorView | None
    context: CurrentContextSnapshot
    attention: DesktopAttentionView
    episodes: tuple[DesktopEpisodeView, ...]
    activity: DesktopActivityView


@dataclass(frozen=True, slots=True)
class DesktopStewardshipView:
    """Bounded system-health projection; it never presents mutation authority."""

    lifecycle: str
    observation_id: UUID
    fingerprint: str
    security: str
    startup: str
    storage_pressure: tuple[tuple[str, str], ...]
    detected_bytes: int
    safe_candidate_bytes: int
    duplicate_groups: int
    model_count: int
    model_error: str | None
    security_findings: tuple[tuple[str, str, str, str], ...]
    startup_entries: tuple[tuple[str, bool, str, str], ...]
    updates: tuple[tuple[str, str, str, str, str], ...]
    acquisition_records: tuple[tuple[str, str, str, str], ...]
    acquisition_requests: tuple[tuple[str, str, str, str, str, str, str, str, str, str], ...]
    cleanup_candidates: tuple[tuple[str, int, str, str, bool], ...]
    models: tuple[tuple[str, bool, str, str], ...]
    model_analysis: tuple[tuple[str, str, str, str], ...]


class DesktopApplicationFacade:
    """Desktop boundary over the canonical runtime; the frontend never sees a container."""

    def __init__(self, runtime: ApplicationRuntime) -> None:
        self._runtime = runtime
        self._settings = EnvironmentSettingsService(
            app_data_dir=(runtime.container.paths.root if runtime.container is not None else None)
        )
        self._localizer = load_default_localizer()
        self._assistant: JarvisAssistantService | None = None
        if runtime.container is not None:
            from jarvis.bootstrap import create_assistant_from_runtime

            self._assistant = create_assistant_from_runtime(runtime)

    @property
    def safe_mode(self) -> bool:
        return self._runtime.container is None

    def runtime_view(self) -> DesktopRuntimeView:
        container = self._runtime.container
        if container is None:
            return DesktopRuntimeView(
                self._runtime.status.value,
                "1.0.0",
                True,
                self._runtime.error,
                None,
                None,
                "unavailable",
                "unavailable",
            )
        return DesktopRuntimeView(
            self._runtime.status.value,
            container.settings.version,
            False,
            None,
            container.settings.ai_provider,
            container.settings.ai_model,
            "ready" if container.stt is not None else "disabled",
            "ready" if container.tts is not None and container.tts.enabled else "disabled",
        )

    def model_intelligence_view(self) -> ModelIntelligencePage:
        """Expose real provider/model state without exposing runtime internals to Qt."""

        container = self._runtime.container
        if container is None:
            return ModelIntelligenceProjection(ProviderRegistry()).page()
        router = container.provider_router
        return ModelIntelligenceProjection(router.registry, router.policy_engine).page()

    def settings_descriptors(self) -> tuple[EnvironmentSettingDescriptor, ...]:
        return (
            self._assistant.settings_descriptors()
            if self._assistant
            else self._settings.descriptors()
        )

    def save_settings(self, updates: dict[str, object]) -> tuple[EnvironmentSettingDescriptor, ...]:
        return (
            self._assistant.save_settings(updates)
            if self._assistant
            else self._settings.save(updates)
        )

    def language_preferences(self) -> dict[str, object]:
        """Return typed language state through the application service boundary."""

        if self._assistant is None:
            return {
                "interface_language": "en",
                "locale": "en-US",
                "conversation_language": None,
                "conversation_mode": "auto",
                "fallback_language": "en",
                "stt_language": None,
                "tts_language": None,
                "tts_voice": None,
            }
        return self._assistant.language_preferences()

    def save_language_preferences(self, updates: dict[str, object]) -> dict[str, object]:
        """Persist language preferences without exposing SQLite to Qt."""

        assistant = self._require_assistant()
        current = assistant.human_adaptation.language_preferences().as_dict()
        current.update(updates)
        return assistant.human_adaptation.set_language_preferences(
            LanguagePreferences.from_dict(current)
        ).as_dict()

    def personalization(self) -> dict[str, object]:
        """Return inspectable bounded adaptation state for the settings surface."""

        if self._assistant is None:
            return {
                "personalization": {
                    "mode": "explicit_only",
                    "adaptive_persona": "fixed",
                    "style_fidelity": "balanced",
                    "routine_learning": False,
                    "behavioral_learning": False,
                    "observation_scope": "jarvis_only",
                    "learning_paused": True,
                    "adaptive_frozen": True,
                },
                "pinned_traits": (),
                "adaptive_persona": {},
                "expression": (),
                "routines": (),
                "history": (),
            }
        return self._assistant.personalization()

    def save_personalization(self, updates: dict[str, object]) -> dict[str, object]:
        assistant = self._require_assistant()
        return assistant.human_adaptation.configure_personalization(**updates)

    def pause_learning(self, paused: bool) -> dict[str, object]:
        return self._require_assistant().human_adaptation.pause_learning(paused)

    def freeze_adaptive_persona(self, frozen: bool) -> dict[str, object]:
        return self._require_assistant().human_adaptation.freeze_adaptive_persona(frozen)

    def reset_adaptations(self) -> dict[str, object]:
        assistant = self._require_assistant()
        assistant.human_adaptation.reset_adaptations()
        return assistant.personalization()

    def reset_learning(self) -> dict[str, object]:
        assistant = self._require_assistant()
        assistant.human_adaptation.reset_learning()
        return assistant.personalization()

    def pin_persona_trait(self, field: str, value: int) -> tuple[str, ...]:
        return self._require_assistant().human_adaptation.pin_persona_trait(field, value)

    def unpin_persona_trait(self, field: str) -> tuple[str, ...]:
        return self._require_assistant().human_adaptation.unpin_persona_trait(field)

    def actor_context(self) -> DesktopActorView:
        context = self._require_container().actor_context
        return DesktopActorView(
            context.session_id, context.source.value, context.display_label, context.is_active()
        )

    def current_context(self) -> CurrentContextSnapshot:
        """Return a bounded read-only projection of canonical current state."""

        container = self._runtime.container
        if container is None:
            return CurrentContextSnapshot.safe_mode_snapshot(
                self._runtime.status.value,
            )
        return container.current_context.snapshot()

    def persona(self) -> DesktopPersonaView:
        return DesktopPersonaView(self._require_container().persona_kernel.get())

    def update_persona(self, updates: dict[str, object]) -> DesktopPersonaView:
        container = self._require_container()
        profile = container.persona_kernel.update(**updates)
        container.human_adaptation.mark_explicit_persona_update(updates)
        return DesktopPersonaView(profile)

    def reset_persona(self) -> DesktopPersonaView:
        return DesktopPersonaView(self._require_container().persona_kernel.reset())

    def reset_setting_to_default(self, name: str) -> tuple[EnvironmentSettingDescriptor, ...]:
        return self._settings.reset_to_default(name)

    def create_conversation(self) -> UUID:
        profile = self._require_container().persona_kernel.get()
        conversation_id = self._require_assistant().create_conversation(
            profile.presentation_guidance()
        )
        self._require_container().current_context.select_conversation(conversation_id)
        return conversation_id

    def select_conversation(self, conversation_id: UUID) -> None:
        self._require_container().current_context.select_conversation(conversation_id)

    def cancel(self, conversation_id: UUID) -> None:
        self._require_assistant().cancel(conversation_id)

    async def stream_text(self, conversation_id: UUID, text: str) -> Any:
        self._require_container().current_context.select_conversation(conversation_id)
        async for event in self._require_assistant().stream_text(conversation_id, text):
            yield event

    async def ollama_status(self, *, ensure_running: bool = False) -> Any:
        return await self._require_assistant().ollama_status(ensure_running=ensure_running)

    def attention_view(self) -> DesktopAttentionView:
        """Project durable Attention without acknowledging or mutating delivery."""

        container = self._runtime.container
        if container is None:
            return DesktopAttentionView("unavailable", 0, None, None, ())
        views = tuple(
            self._attention_item_view(item)
            for item in container.attention_store.list_items()
            if not item.resolved
        )
        ordered = tuple(
            sorted(
                views,
                key=lambda item: (
                    self._interruption_rank(item.interruption_class),
                    item.requires_user_action,
                    item.created_at,
                ),
                reverse=True,
            )
        )
        highest_actionable = next(
            (item.item_id for item in ordered if item.requires_user_action), None
        )
        highest_class = ordered[0].interruption_class if ordered else None
        return DesktopAttentionView(
            "ready" if ordered else "empty",
            len(ordered),
            highest_class,
            highest_actionable,
            ordered,
        )

    def episode_views(self) -> tuple[DesktopEpisodeView, ...]:
        """Return recent durable Episodes through the existing memory owner."""

        container = self._runtime.container
        if container is None:
            return ()
        episodes = container.episodic_memory.list_episodes()
        return tuple(
            self._episode_view(episode)
            for episode in sorted(episodes, key=lambda item: item.ended_at, reverse=True)[:32]
        )

    def activity_view(self) -> DesktopActivityView:
        """Project bounded task, Attention, Episode, and Trace facts for Activity."""

        container = self._runtime.container
        if container is None:
            return DesktopActivityView("unavailable", ())
        items: list[DesktopActivityItemView] = []
        for event in container.trace_service.recent_events():
            items.append(self._trace_activity(event))
        for item in container.attention_store.list_items():
            entry = container.attention_policy.entry_for(item.item_id)
            decision = entry.decision.value if entry is not None else "unknown"
            delivery = item.delivery_state.value
            class_name = item.interruption_class.value if item.interruption_class else "generic"
            reason = item.interruption_reason_code or "not supplied by source"
            items.append(
                DesktopActivityItemView(
                    f"attention:{item.item_id}",
                    "attention",
                    decision,
                    item.created_at,
                    (
                        f"{item.summary} · class={class_name}; decision={decision}; "
                        f"delivery={delivery}; reason={reason}"
                    ),
                    item.related_task_id,
                )
            )
        for episode in self.episode_views():
            items.append(
                DesktopActivityItemView(
                    f"episode:{episode.episode_id}",
                    "episode",
                    episode.verification,
                    episode.ended_at,
                    (
                        f"Episode recorded · outcome={episode.outcome}; "
                        f"continuity={episode.continuity}"
                    ),
                    episode.task_id,
                )
            )
        ordered = tuple(
            sorted(items, key=lambda item: (item.occurred_at, item.identifier), reverse=True)[:80]
        )
        return DesktopActivityView("ready" if ordered else "empty", ordered)

    def overview_view(self) -> DesktopOverviewView:
        """Assemble the bounded home view from existing application projections."""

        runtime = self.runtime_view()
        context = self.current_context()
        actor = self.actor_context() if not runtime.safe_mode else None
        return DesktopOverviewView(
            runtime,
            actor,
            context,
            self.attention_view(),
            self.episode_views()[:5],
            self.activity_view(),
        )

    async def refresh_rows(self, page: str) -> tuple[DesktopRow, ...]:
        if page == "overview":
            return self._overview_rows(self.overview_view())
        if page == "attention":
            return self._attention_rows(self.attention_view())
        if page == "episodes":
            container = self._runtime.container
            if container is None:
                return (
                    DesktopRow(
                        "episodes-unavailable",
                        "Episodes",
                        "UNAVAILABLE",
                        "Episodes are unavailable in Safe Mode",
                    ),
                )
            return self._episode_rows(self.episode_views())
        if page == "activity":
            return self._activity_rows(self.activity_view())
        assistant = self._require_assistant()
        if page == "tasks":
            return tuple(
                DesktopRow(
                    str(task.task_id),
                    task.goal,
                    task.status.value,
                    task.error.message if task.error is not None else "No failure reported",
                )
                for task in assistant.list_tasks()
            )
        if page == "memory":
            return tuple(
                DesktopRow(
                    str(entry.reference.record_id),
                    entry.belief,
                    entry.verification.value,
                    (
                        f"Category: {entry.category}; Source: {entry.source}; "
                        "Confidence: "
                        f"{entry.confidence if entry.confidence is not None else 'n/a'}; "
                        f"Sensitivity: {entry.sensitivity.value}; "
                        f"Retention: {entry.retention.value}; "
                        f"Updated: {entry.updated_at.isoformat()}"
                    ),
                    entry.reference,
                )
                for entry in assistant.inspect_memory()
                if entry.category != "episodic"
            )
        if page == "permissions":
            return await self._permission_rows()
        if page == "system-health":
            return self._stewardship_rows(await self.system_stewardship_view())
        sections = {
            "capabilities": ControlCenterSection.CAPABILITIES,
            "tools": ControlCenterSection.TOOLS,
            "automations": ControlCenterSection.AUTOMATIONS,
            "permissions": ControlCenterSection.PERMISSIONS,
        }
        if page not in sections:
            raise ValueError("Desktop page is unknown")
        snapshot = await assistant.refresh_control_center(sections[page])
        section = snapshot.section(sections[page])
        return tuple(
            DesktopRow(
                item.item_id,
                item.label,
                item.status.value,
                self._control_center_detail(item.detail, item.metadata, item.actions),
            )
            for item in section.items
        )

    async def system_stewardship_view(self) -> DesktopStewardshipView:
        """Refresh the canonical stewardship projection for the System Health page."""

        container = self._require_container()
        coordinator = container.system_stewardship
        if not isinstance(coordinator, SystemStewardshipCoordinator):
            raise ServiceUnavailableError("System stewardship is unavailable")
        observation = await coordinator.observe()
        return self._stewardship_view(observation)

    async def run_task(self, task_id: UUID) -> DesktopRow:
        self._require_container().current_context.select_task(task_id)
        task = await self._require_assistant().run_task(task_id)
        return DesktopRow(
            str(task.task_id),
            task.goal,
            task.status.value,
            self._task_detail(task),
        )

    async def create_task(self, conversation_id: UUID, goal: str) -> DesktopRow:
        task = await self._require_assistant().create_task(conversation_id, goal)
        self._require_container().current_context.select_task(task.task_id)
        return DesktopRow(str(task.task_id), task.goal, task.status.value, "Task created")

    async def submit_goal(self, conversation_id: UUID, goal: str) -> DesktopRow:
        schedule = await self._require_assistant().submit_goal(conversation_id, goal)
        return DesktopRow(
            str(schedule.goal_id),
            goal,
            schedule.status.value,
            "Goal submitted through GoalSupervisor and the canonical planning runner",
        )

    async def cancel_task(self, task_id: UUID) -> DesktopRow:
        self._require_container().current_context.select_task(task_id)
        task = await self._require_assistant().cancel_task(task_id)
        return DesktopRow(str(task.task_id), task.goal, task.status.value, "Cancellation requested")

    def correct_memory(self, reference: MemoryControlReference, belief: str) -> DesktopRow:
        entry = self._require_assistant().correct_memory(reference, MemoryCorrection(belief))
        return self._memory_row(entry)

    def delete_memory(self, reference: MemoryControlReference) -> bool:
        return self._require_assistant().delete_memory(reference)

    def forget_memory_category(self, category: str) -> int:
        return self._require_assistant().forget_memory_category(category)

    def change_memory_retention(
        self, reference: MemoryControlReference, retention: RetentionPolicy
    ) -> DesktopRow:
        entry = self._require_assistant().change_memory_retention(reference, retention)
        return self._memory_row(entry)

    def pause_memory_learning(self, paused: bool) -> bool:
        return self._require_assistant().pause_memory_learning(paused)

    def mark_memory_explicit(self, reference: MemoryControlReference) -> DesktopRow:
        return self._memory_row(self._require_assistant().mark_memory_explicit(reference))

    def request_memory_reverification(self, reference: MemoryControlReference) -> str:
        request = self._require_assistant().request_memory_reverification(reference)
        return str(request.request_id)

    async def decide_permission(self, request_id: UUID, choice: ApprovalChoice) -> bool:
        """Submit a one-time decision through the trusted desktop approval path."""

        container = self._require_container()
        request = await container.permission_broker.get_approval(request_id)
        if request is None:
            raise ValueError("Permission request no longer exists")
        handoff = DesktopApprovalHandoff.create(request)
        result = await TrustedDesktopApprovalSurface().decide(
            handoff,
            request,
            choice=choice,
            authenticator=container.desktop_approval_authenticator,
            identity=container.actor_context_service.approval_identity(container.actor_context),
            broker=container.permission_broker,
        )
        return result.accepted

    async def check_tool_health(self, tool_id: str) -> DesktopRow:
        """Run the registry's read-only health probe; tool execution remains brokered."""

        container = self._require_container()
        results = await container.tool_registry.health_check(tool_id)
        if len(results) != 1:
            raise ValueError("Tool health probe returned an unexpected result")
        identifier, health = results[0]
        record = container.tool_registry.inspect(identifier)
        return DesktopRow(
            identifier,
            record.manifest.name,
            health.status.value,
            health.detail,
        )

    def remove_automation(self, automation_id: UUID) -> bool:
        """Remove a selected durable automation through its owning service."""

        return bool(self._require_container().automation_service.unregister(automation_id))

    async def start_recording(self) -> None:
        await self._require_assistant().start_recording()

    async def stop_recording(self) -> str:
        return (await self._require_assistant().stop_recording()).text

    async def stop_speaking(self) -> None:
        await self._require_assistant().stop_speaking()

    async def aclose(self) -> None:
        await self._runtime.aclose()

    @staticmethod
    def _stewardship_view(observation: StewardshipObservation) -> DesktopStewardshipView:
        return DesktopStewardshipView(
            observation.lifecycle.value,
            observation.observation_id,
            observation.fingerprint,
            observation.system.security.overall.value,
            observation.system.startup.overall.value,
            tuple((volume_id, state.value) for volume_id, state in observation.storage.pressure),
            observation.storage.detected_bytes,
            observation.storage.safe_candidate_bytes,
            len(observation.storage.duplicate_groups),
            len(observation.models),
            observation.model_error,
            tuple(
                (item.provider, item.target, item.state.value, item.evidence_ref)
                for item in observation.system.security.findings
            ),
            tuple(
                (item.entry_id, item.enabled, item.state.value, item.detail)
                for item in observation.system.startup.entries
            ),
            tuple(
                (
                    item.application_id,
                    item.current_version,
                    item.candidate_version or "unknown",
                    item.state.value,
                    item.provider,
                )
                for item in observation.system.updates
            ),
            tuple(
                (
                    item.resource_id,
                    item.state.value,
                    item.target_location or "unknown",
                    str(item.size_bytes) if item.size_bytes is not None else "unknown",
                )
                for item in observation.acquisition_records
            ),
            tuple(
                (
                    request.resource_id,
                    request.purpose,
                    request.required_for or "unknown",
                    request.source or "unknown",
                    str(request.download_size_bytes or request.installed_size_bytes or "unknown"),
                    request.target_location or "unknown",
                    request.security_risk.value,
                    (
                        "administrator approval"
                        if request.administrator_required
                        else "broker authority"
                    ),
                    next(
                        (
                            record.state.value
                            for record in observation.acquisition_records
                            if record.request_fingerprint == request.fingerprint
                        ),
                        "planned",
                    ),
                    request.verification_plan or "unknown",
                )
                for request in observation.acquisition_requests
            ),
            tuple(
                (
                    item.path.name,
                    item.size_bytes,
                    item.classification.category.value,
                    item.state.value,
                    item.eligible,
                )
                for item in observation.storage.cleanup_candidates
            ),
            tuple(
                (
                    item.identity.storage_key,
                    item.available,
                    ", ".join(sorted(item.capability_dimensions)) or "unknown",
                    str(item.actual_router_use)
                    if item.actual_router_use is not None
                    else "unknown",
                )
                for item in observation.models
            ),
            tuple(
                (
                    item.candidate.identity.storage_key,
                    item.classification.value,
                    ", ".join(sorted(item.unique_dimensions)) or "none",
                    item.reason,
                )
                for item in observation.model_analysis
            ),
        )

    def _stewardship_rows(self, view: DesktopStewardshipView) -> tuple[DesktopRow, ...]:
        language = LanguageTag(self.current_context().interface_language)

        def t(message_id: str, fallback: str, **params: object) -> str:
            translated = self._localizer.translate(message_id, language, **params)
            return fallback if translated.startswith("[") else translated

        pressure = "; ".join(f"{volume}: {state}" for volume, state in view.storage_pressure)
        rows = [
            DesktopRow(
                "stewardship-lifecycle",
                t("stewardship.observation", "Stewardship observation"),
                view.lifecycle.upper(),
                t(
                    "stewardship.observation_detail",
                    f"Observation: {view.observation_id}; fingerprint: {view.fingerprint}",
                    observation_id=str(view.observation_id),
                    fingerprint=view.fingerprint,
                ),
            ),
            DesktopRow(
                "stewardship-security",
                t("stewardship.security", "Security"),
                view.security.upper(),
                t("stewardship.provider_projection", "Trusted provider projection"),
            ),
            DesktopRow(
                "stewardship-startup",
                t("stewardship.startup", "Startup"),
                view.startup.upper(),
                t("stewardship.startup_detail", "Trusted startup observation"),
            ),
            DesktopRow(
                "stewardship-storage",
                t("stewardship.storage", "Storage"),
                "OBSERVED",
                t(
                    "stewardship.storage_detail",
                    f"Pressure: {pressure or 'UNKNOWN'}; detected={view.detected_bytes}; "
                    f"safe candidate={view.safe_candidate_bytes}; "
                    f"duplicates={view.duplicate_groups}",
                    pressure=pressure or "UNKNOWN",
                    detected=view.detected_bytes,
                    safe_candidate=view.safe_candidate_bytes,
                    duplicates=view.duplicate_groups,
                ),
            ),
            DesktopRow(
                "stewardship-models",
                t("stewardship.models", "Model portfolio"),
                "OBSERVED" if view.model_error is None else "UNKNOWN",
                t(
                    "stewardship.models_detail",
                    f"Measured inventory entries: {view.model_count}"
                    + (f"; {view.model_error}" if view.model_error else ""),
                    count=view.model_count,
                    error=view.model_error or "none",
                ),
            ),
        ]
        rows.extend(
            DesktopRow(
                f"stewardship-security-{index}",
                t("stewardship.security_evidence", "Security evidence"),
                state.upper(),
                t(
                    "stewardship.security_evidence_detail",
                    f"Provider: {provider}; target: {target}; evidence: {evidence}",
                    provider=provider,
                    target=target,
                    evidence=evidence,
                ),
            )
            for index, (provider, target, state, evidence) in enumerate(view.security_findings)
        )
        rows.extend(
            DesktopRow(
                f"stewardship-startup-{index}",
                t("stewardship.startup_evidence", "Startup evidence"),
                state.upper(),
                t(
                    "stewardship.startup_evidence_detail",
                    f"Entry: {entry}; enabled={enabled}; detail: {detail}",
                    entry=entry,
                    enabled=enabled,
                    detail=detail,
                ),
            )
            for index, (entry, enabled, state, detail) in enumerate(view.startup_entries)
        )
        rows.extend(
            DesktopRow(
                f"stewardship-update-{index}",
                t("stewardship.update", "Update evidence"),
                state.upper(),
                t(
                    "stewardship.update_detail",
                    f"{application}: {current} -> {candidate}; provider={provider}",
                    application=application,
                    current=current,
                    candidate=candidate,
                    provider=provider,
                ),
            )
            for index, (application, current, candidate, state, provider) in enumerate(view.updates)
        )
        rows.extend(
            DesktopRow(
                f"stewardship-acquisition-{index}",
                t("stewardship.acquisition", "Acquisition evidence"),
                state.upper(),
                t(
                    "stewardship.acquisition_detail",
                    f"Resource: {resource}; target={target}; size={size}",
                    resource=resource,
                    target=target,
                    size=size,
                ),
            )
            for index, (resource, state, target, size) in enumerate(view.acquisition_records)
        )
        rows.extend(
            DesktopRow(
                f"stewardship-acquisition-request-{index}",
                t("stewardship.acquisition_request", "Acquisition request"),
                status.upper(),
                t(
                    "stewardship.acquisition_request_detail",
                    (
                        f"{resource}: purpose={purpose}; required-for={required_for}; "
                        f"source={source}; size={size}; target={target}; risk={risk}; "
                        f"authority={authority}; verification={verification}"
                    ),
                    resource=resource,
                    purpose=purpose,
                    required_for=required_for,
                    source=source,
                    size=size,
                    target=target,
                    risk=risk,
                    authority=authority,
                    status=status,
                    verification=verification,
                ),
            )
            for index, (
                resource,
                purpose,
                required_for,
                source,
                size,
                target,
                risk,
                authority,
                status,
                verification,
            ) in enumerate(view.acquisition_requests)
        )
        rows.extend(
            DesktopRow(
                f"stewardship-cleanup-{index}",
                t("stewardship.cleanup", "Cleanup candidate"),
                state.upper(),
                t(
                    "stewardship.cleanup_detail",
                    f"{name}: category={category}; bytes={size}; eligible={eligible}",
                    name=name,
                    category=category,
                    size=size,
                    state=state,
                    eligible=eligible,
                ),
            )
            for index, (name, size, category, state, eligible) in enumerate(view.cleanup_candidates)
        )
        rows.extend(
            DesktopRow(
                f"stewardship-model-{index}",
                t("stewardship.model", "Model evidence"),
                "AVAILABLE" if available else "UNAVAILABLE",
                t(
                    "stewardship.model_detail",
                    f"{identity}: dimensions={dimensions}; router use={router_use}",
                    identity=identity,
                    dimensions=dimensions,
                    router_use=router_use,
                ),
            )
            for index, (identity, available, dimensions, router_use) in enumerate(view.models)
        )
        rows.extend(
            DesktopRow(
                f"stewardship-model-analysis-{index}",
                t("stewardship.model_analysis", "Model analysis"),
                classification.upper(),
                t(
                    "stewardship.model_analysis_detail",
                    f"Candidate: {candidate}; classification={classification}; "
                    f"unique={unique}; reason={reason}",
                    candidate=candidate,
                    classification=classification,
                    unique=unique,
                    reason=reason,
                ),
            )
            for index, (candidate, classification, unique, reason) in enumerate(view.model_analysis)
        )
        return tuple(rows)

    @staticmethod
    def _interruption_rank(value: str | None) -> int:
        if value is None:
            return -1
        return {
            InterruptionClass.SILENT.value: 0,
            InterruptionClass.QUEUE.value: 1,
            InterruptionClass.NORMAL.value: 2,
            InterruptionClass.IMPORTANT.value: 3,
            InterruptionClass.URGENT.value: 4,
        }.get(value, -1)

    def _attention_item_view(self, item: AttentionItem) -> DesktopAttentionItemView:
        container = self._require_container()
        entry = container.attention_policy.entry_for(item.item_id)
        return DesktopAttentionItemView(
            item.item_id,
            item.interruption_class.value if item.interruption_class is not None else None,
            entry.decision.value if entry is not None else "unknown",
            item.delivery_state.value,
            item.interruption_reason_code,
            item.summary,
            item.created_at,
            item.expires_at,
            item.requires_user_action,
            item.related_task_id,
            item.actor_context_id,
            item.workspace,
        )

    @staticmethod
    def _episode_view(episode: Episode) -> DesktopEpisodeView:
        return DesktopEpisodeView(
            episode.episode_id,
            episode.task_id,
            episode.goal_category,
            episode.started_at,
            episode.ended_at,
            episode.terminal_outcome.value,
            episode.verification.value,
            episode.continuity.value,
            tuple(
                f"{action.tool_id}: {action.action} ({action.outcome})"
                for action in episode.actions
            ),
            episode.evidence_references,
            episode.semantic_event_ids,
            episode.semantic_pattern_ids,
            episode.sensitivity.value,
            episode.provenance,
        )

    @staticmethod
    def _trace_activity(event: TraceEvent) -> DesktopActivityItemView:
        summary = event.summary
        if event.event_type is TraceEventType.ATTENTION and isinstance(event.result, Mapping):
            result = event.result
            interruption_class = result.get("interruption_class")
            reason = result.get("reason_code")
            if result.get("reevaluation_reason") == "context_reevaluation":
                summary = (
                    "Attention context reevaluated · "
                    f"decision {result.get('prior_attention_decision', 'unknown')} → "
                    f"{result.get('new_attention_decision', 'unknown')}"
                )
            else:
                summary = (
                    f"Attention decision recorded · class={interruption_class or 'unknown'}; "
                    f"reason={reason or 'unknown'}; "
                    f"decision={result.get('attention_decision', 'unknown')}; "
                    f"delivery={result.get('delivery_state', 'unknown')}"
                )
        return DesktopActivityItemView(
            f"trace:{event.event_id}",
            event.event_type.value,
            event.event_type.value,
            event.occurred_at,
            summary,
            event.task_id,
        )

    @staticmethod
    def _attention_rows(view: DesktopAttentionView) -> tuple[DesktopRow, ...]:
        if view.state == "unavailable":
            return (
                DesktopRow(
                    "attention-unavailable",
                    "Attention",
                    "UNAVAILABLE",
                    "Attention is unavailable in Safe Mode.",
                ),
            )
        if not view.items:
            return (
                DesktopRow(
                    "attention-empty",
                    "No unresolved attention",
                    "EMPTY",
                    "No unresolved Attention items are waiting for review.",
                ),
            )
        return tuple(
            DesktopRow(
                str(item.item_id),
                item.summary,
                (item.interruption_class or "UNCLASSIFIED").upper(),
                (
                    f"Decision: {item.decision}; Delivery: {item.delivery_state}; "
                    f"Reason: {item.reason_code or 'not supplied by source'}; "
                    f"Created: {item.created_at.isoformat()}"
                    + (
                        f"; Expires: {item.expires_at.isoformat()}"
                        if item.expires_at is not None
                        else ""
                    )
                    + (
                        f"; Requires user action; Task: {item.related_task_id}"
                        if item.requires_user_action and item.related_task_id is not None
                        else "; Requires user action"
                        if item.requires_user_action
                        else ""
                    )
                ),
            )
            for item in view.items
        )

    @staticmethod
    def _episode_rows(episodes: tuple[DesktopEpisodeView, ...]) -> tuple[DesktopRow, ...]:
        if not episodes:
            return (
                DesktopRow(
                    "episodes-empty",
                    "No relevant episodes yet",
                    "EMPTY",
                    "JARVIS will record verified meaningful experiences as they occur.",
                ),
            )
        return tuple(
            DesktopRow(
                str(episode.episode_id),
                f"Episode · {episode.category}",
                f"{episode.outcome.upper()} / {episode.verification.upper()}",
                (
                    f"Task: {episode.task_id}; Ended: {episode.ended_at.isoformat()}; "
                    f"Continuity: {episode.continuity}; Sensitivity: {episode.sensitivity}; "
                    f"Actions: {', '.join(episode.action_summary) or 'No actions recorded'}; "
                    "Evidence refs: "
                    f"{', '.join(episode.evidence_references) or 'No evidence references'}; "
                    f"Semantic events: {len(episode.semantic_event_ids)}; "
                    f"Patterns: {len(episode.semantic_pattern_ids)}; "
                    f"Provenance: {', '.join(episode.provenance)}"
                ),
            )
            for episode in episodes
        )

    @staticmethod
    def _activity_rows(view: DesktopActivityView) -> tuple[DesktopRow, ...]:
        if view.state == "unavailable":
            return (
                DesktopRow(
                    "activity-unavailable",
                    "Activity",
                    "UNAVAILABLE",
                    "Factual activity is unavailable in Safe Mode.",
                ),
            )
        if not view.items:
            return (
                DesktopRow(
                    "activity-empty",
                    "No recent activity",
                    "EMPTY",
                    "Verified task, Attention, Episode, and runtime facts will appear here.",
                ),
            )
        return tuple(
            DesktopRow(
                item.identifier,
                (
                    "Trace · "
                    if item.identifier.startswith("trace:")
                    else "Current "
                    if item.identifier.startswith("attention:")
                    else ""
                )
                + item.category.replace("_", " ").title(),
                item.status.upper(),
                f"{item.occurred_at.isoformat()} · {item.summary}",
            )
            for item in view.items
        )

    def _overview_rows(self, view: DesktopOverviewView) -> tuple[DesktopRow, ...]:
        runtime = view.runtime
        rows = [
            DesktopRow(
                "runtime",
                "Runtime",
                runtime.state.upper(),
                (
                    f"Mode: {'Safe Mode' if runtime.safe_mode else 'Normal'}; "
                    f"Provider: {runtime.provider or 'not configured'}; "
                    f"Model: {runtime.model or 'not configured'}; "
                    f"STT: {runtime.stt}; TTS: {runtime.tts}"
                    + (f"; Error: {runtime.error}" if runtime.error else "")
                ),
            ),
            DesktopRow(
                "actor",
                "ActorContext",
                "UNAVAILABLE" if view.actor is None else "ACTIVE" if view.actor.active else "ENDED",
                (
                    "ActorContext is unavailable in Safe Mode."
                    if view.actor is None
                    else f"Source: {view.actor.source}; Label: {view.actor.label or 'unlabeled'}; "
                    f"Session: {view.actor.session_id}"
                ),
            ),
            DesktopRow(
                "context",
                "Current context",
                "SAFE_MODE" if view.context.safe_mode else "LIVE",
                self._context_detail(view.context),
            ),
        ]
        attention = view.attention
        if attention.state == "unavailable":
            rows.append(
                DesktopRow(
                    "attention",
                    "Attention",
                    "UNAVAILABLE",
                    "Attention is unavailable in Safe Mode.",
                )
            )
        elif not attention.items:
            rows.append(
                DesktopRow(
                    "attention",
                    "Attention",
                    "EMPTY",
                    "No unresolved Attention items are waiting for review.",
                )
            )
        else:
            rows.append(
                DesktopRow(
                    "attention",
                    "Attention",
                    "WAITING",
                    (
                        f"Unresolved: {attention.unresolved_count}; highest class: "
                        f"{attention.highest_interruption_class or 'unclassified'}; "
                        f"highest actionable: "
                        f"{attention.highest_actionable_item_id or 'no actionable item'}"
                    ),
                )
            )
            rows.extend(self._attention_rows(attention)[:8])
        if runtime.safe_mode:
            rows.append(
                DesktopRow(
                    "episodes",
                    "Episodes",
                    "UNAVAILABLE",
                    "Episodes are unavailable in Safe Mode.",
                )
            )
        else:
            rows.extend(self._episode_rows(view.episodes)[:5])
        return tuple(rows)

    @staticmethod
    def _context_detail(context: CurrentContextSnapshot) -> str:
        conversation = (
            str(context.active_conversation_id)
            if context.active_conversation_id is not None
            else "no active conversation"
        )
        task = (
            f"{context.active_task_id} ({context.active_task_status.value})"
            if context.active_task_id is not None and context.active_task_status is not None
            else "no active task"
        )
        presence = context.presence.state.value if context.presence is not None else "unknown"
        readiness = (
            context.provider.readiness.value
            if context.provider.readiness is not None
            else "unknown"
        )
        return (
            f"Conversation: {conversation}; Task: {task}; Presence: {presence}; "
            f"Provider readiness: {readiness}; Runtime: {context.runtime_state}"
        )

    @staticmethod
    def _memory_row(entry: Any) -> DesktopRow:
        return DesktopRow(
            str(entry.reference.record_id),
            entry.belief,
            entry.verification.value,
            (
                f"Category: {entry.category}; Source: {entry.source}; "
                "Confidence: "
                f"{entry.confidence if entry.confidence is not None else 'n/a'}; "
                f"Sensitivity: {entry.sensitivity.value}; "
                f"Retention: {entry.retention.value}; Updated: {entry.updated_at.isoformat()}"
            ),
            entry.reference,
        )

    def _task_detail(self, task: Any) -> str:
        if task.error is not None:
            if task.status.value == "waiting_for_resource":
                language = LanguageTag(self.current_context().interface_language)
                translated = self._localizer.translate(
                    "task.waiting_for_resource",
                    language,
                    reason=task.error.message,
                )
                if not translated.startswith("["):
                    return translated
            return f"Task ended with {task.error.failure_kind.value}: {task.error.message}"
        if task.status.value == "completed":
            return "Task completed; terminal outcome is available to the Episode projection."
        return f"Task state is {task.status.value}; no verified completion is claimed."

    @staticmethod
    def _control_center_detail(
        detail: str,
        metadata: tuple[tuple[str, str], ...],
        actions: tuple[Any, ...],
    ) -> str:
        parts = [detail] if detail else []
        if metadata:
            parts.append("Metadata: " + "; ".join(f"{key}={value}" for key, value in metadata))
        if actions:
            parts.append(
                "Available through application: " + ", ".join(action.label for action in actions)
            )
        return "\n".join(parts) or "No additional detail is available."

    async def _permission_rows(self) -> tuple[DesktopRow, ...]:
        container = self._require_container()
        rows: list[DesktopRow] = []
        for request in await container.permission_broker.pending_approvals():
            prompt = self._require_assistant().render_permission_prompt(request)
            rows.append(
                DesktopRow(
                    str(request.request_id),
                    prompt.desktop_short,
                    request.status.value,
                    f"{prompt.desktop_scope}\n{prompt.desktop_details}",
                )
            )
        return tuple(rows)

    def _require_container(self) -> Any:
        container = self._runtime.container
        if container is None:
            raise ServiceUnavailableError("Normal desktop actions are unavailable in Safe Mode")
        return container

    def _require_assistant(self) -> JarvisAssistantService:
        if self._assistant is None:
            raise ServiceUnavailableError("Normal desktop actions are unavailable in Safe Mode")
        return self._assistant
