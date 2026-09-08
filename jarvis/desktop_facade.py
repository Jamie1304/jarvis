"""Application-owned, secret-safe projections for the optional desktop client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from uuid import UUID

from jarvis.actor_persona import PersonaProfile
from jarvis.application import JarvisAssistantService
from jarvis.control_center import ControlCenterSection
from jarvis.core.environment_settings import (
    EnvironmentSettingDescriptor,
    EnvironmentSettingsService,
)
from jarvis.core.errors import ServiceUnavailableError
from jarvis.current_context import CurrentContextSnapshot
from jarvis.memory.control import MemoryControlReference, MemoryCorrection
from jarvis.memory.models import RetentionPolicy
from jarvis.permissions import (
    ApprovalChoice,
    DesktopApprovalHandoff,
    TrustedDesktopApprovalSurface,
)

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


class DesktopApplicationFacade:
    """Desktop boundary over the canonical runtime; the frontend never sees a container."""

    def __init__(self, runtime: ApplicationRuntime) -> None:
        self._runtime = runtime
        self._settings = EnvironmentSettingsService(
            app_data_dir=(runtime.container.paths.root if runtime.container is not None else None)
        )
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
        return DesktopPersonaView(self._require_container().persona_kernel.update(**updates))

    def reset_persona(self) -> DesktopPersonaView:
        return DesktopPersonaView(self._require_container().persona_kernel.reset())

    def reset_setting_to_default(self, name: str) -> tuple[EnvironmentSettingDescriptor, ...]:
        return self._settings.reset_to_default(name)

    def create_conversation(self) -> UUID:
        conversation_id = self._require_assistant().create_conversation()
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

    async def refresh_rows(self, page: str) -> tuple[DesktopRow, ...]:
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
            )
        if page == "permissions":
            return await self._permission_rows()
        sections = {
            "capabilities": ControlCenterSection.CAPABILITIES,
            "tools": ControlCenterSection.TOOLS,
            "automations": ControlCenterSection.AUTOMATIONS,
            "permissions": ControlCenterSection.PERMISSIONS,
            "activity": ControlCenterSection.AUDIT,
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

    async def run_task(self, task_id: UUID) -> DesktopRow:
        self._require_container().current_context.select_task(task_id)
        task = await self._require_assistant().run_task(task_id)
        return DesktopRow(
            str(task.task_id), task.goal, task.status.value, "Task execution completed"
        )

    async def create_task(self, conversation_id: UUID, goal: str) -> DesktopRow:
        task = await self._require_assistant().create_task(conversation_id, goal)
        self._require_container().current_context.select_task(task.task_id)
        return DesktopRow(str(task.task_id), task.goal, task.status.value, "Task created")

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
