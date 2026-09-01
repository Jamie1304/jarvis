"""Process-local typed conversation orchestration."""

import threading
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from jarvis.ai.models import ChatMessage, GenerationRequest, MessageRole, ProviderHealth
from jarvis.ai.providers.base import AIProvider
from jarvis.ai.sessions import AgentSessionStore, AgentSessionType
from jarvis.core.errors import ConversationCancelledError


@dataclass(frozen=True, slots=True)
class ConversationUpdate:
    """A UI-safe incremental assistant response update."""

    conversation_id: UUID
    message_id: UUID
    content: str
    done: bool


class ConversationService:
    """Own process-local history and stream provider-neutral assistant responses."""

    def __init__(
        self,
        provider: AIProvider,
        *,
        model: str,
        context_limit: int,
        session_store: AgentSessionStore | None = None,
        session_type: AgentSessionType = AgentSessionType.INTERACTIVE,
        provider_id: str = "default",
    ) -> None:
        self._provider = provider
        self._model = model
        self._context_limit = context_limit
        self._messages: dict[UUID, list[ChatMessage]] = {}
        self._cancellations: dict[UUID, threading.Event] = {}
        self._generations: dict[UUID, int] = {}
        self._session_store = session_store
        self._session_type = session_type
        self._provider_id = provider_id
        self._sessions: dict[UUID, UUID] = {}

    def create_conversation(self, system_prompt: str | None = None) -> UUID:
        """Create a conversation, optionally seeded with a system instruction."""

        conversation_id = uuid4()
        self._messages[conversation_id] = []
        if self._session_store is not None:
            session = self._session_store.create(
                self._session_type,
                self._provider_id,
                self._model,
                context_metadata=(("conversation_id", str(conversation_id)),),
            )
            self._sessions[conversation_id] = session.session_id
        if system_prompt:
            self._messages[conversation_id].append(
                self._message(conversation_id, MessageRole.SYSTEM, system_prompt)
            )
        return conversation_id

    def history(self, conversation_id: UUID) -> tuple[ChatMessage, ...]:
        """Return immutable process-local history for UI rendering."""

        return tuple(self._messages.get(conversation_id, []))

    def cancel(self, conversation_id: UUID) -> None:
        """Request cancellation from any thread, including the desktop UI thread."""

        cancellation = self._cancellations.get(conversation_id)
        if cancellation is not None:
            cancellation.set()
        self._generations[conversation_id] = self._generations.get(conversation_id, 0) + 1
        session_id = self._sessions.get(conversation_id)
        if session_id is not None and self._session_store is not None:
            self._session_store.mark_synchronized(session_id, False)

    def session_id(self, conversation_id: UUID) -> UUID | None:
        """Return the bound execution session, if session persistence is enabled."""

        return self._sessions.get(conversation_id)

    async def provider_health(self) -> ProviderHealth:
        """Expose provider connectivity without leaking its concrete implementation."""

        return await self._provider.health_check()

    async def aclose(self) -> None:
        """Release the configured provider's resources."""

        await self._provider.aclose()

    async def stream_reply(
        self, conversation_id: UUID, user_content: str
    ) -> AsyncIterator[ConversationUpdate]:
        """Store a user message then yield and retain one assistant response."""

        messages = self._messages.setdefault(conversation_id, [])
        session_id = self._ensure_session(conversation_id)
        self._generations[conversation_id] = self._generations.get(conversation_id, 0) + 1
        generation = self._generations[conversation_id]
        previous = self._cancellations.get(conversation_id)
        if previous is not None:
            previous.set()
            if session_id is not None and self._session_store is not None:
                self._session_store.mark_synchronized(session_id, False)
        messages.append(self._message(conversation_id, MessageRole.USER, user_content))
        cancellation = threading.Event()
        self._cancellations[conversation_id] = cancellation
        assistant_id = uuid4()
        content = ""
        request = GenerationRequest(
            messages=self._within_context(messages),
            model=self._model,
            context_limit=self._context_limit,
        )
        try:
            async for chunk in self._provider.stream(request):
                self._raise_if_cancelled(
                    cancellation, conversation_id, generation, self._generations
                )
                content += chunk.content
                yield ConversationUpdate(
                    conversation_id=conversation_id,
                    message_id=assistant_id,
                    content=chunk.content,
                    done=chunk.done,
                )
            self._raise_if_cancelled(cancellation, conversation_id, generation, self._generations)
            if session_id is not None and self._session_store is not None:
                self._session_store.mark_synchronized(session_id, True)
                self._session_store.record_usage(session_id, max(1, len(content) // 4))
        finally:
            if self._cancellations.get(conversation_id) is cancellation:
                self._cancellations.pop(conversation_id, None)
        if generation == self._generations.get(conversation_id):
            messages.append(
                ChatMessage(
                    id=assistant_id,
                    conversation_id=conversation_id,
                    role=MessageRole.ASSISTANT,
                    content=content,
                    created_at=datetime.now(UTC),
                )
            )

    def _ensure_session(self, conversation_id: UUID) -> UUID | None:
        if self._session_store is None:
            return None
        session_id = self._sessions.get(conversation_id)
        if session_id is None:
            session = self._session_store.create(
                self._session_type,
                self._provider_id,
                self._model,
                context_metadata=(("conversation_id", str(conversation_id)),),
            )
            self._sessions[conversation_id] = session.session_id
            return session.session_id
        current = self._session_store.get(session_id)
        if current is None or current.archived or not current.synchronized:
            replacement = (
                self._session_store.rebuild(session_id)
                if current
                else self._session_store.create(self._session_type, self._provider_id, self._model)
            )
            self._sessions[conversation_id] = replacement.session_id
            return replacement.session_id
        return session_id

    def _within_context(self, messages: list[ChatMessage]) -> tuple[ChatMessage, ...]:
        """Bound request size conservatively until tokenization becomes provider-aware."""

        retained: list[ChatMessage] = []
        character_budget = self._context_limit * 4
        used = 0
        for message in reversed(messages):
            size = len(message.content)
            if retained and used + size > character_budget:
                break
            retained.append(message)
            used += size
        return tuple(reversed(retained))

    @staticmethod
    def _message(conversation_id: UUID, role: MessageRole, content: str) -> ChatMessage:
        return ChatMessage(
            id=uuid4(),
            conversation_id=conversation_id,
            role=role,
            content=content,
            created_at=datetime.now(UTC),
        )

    @staticmethod
    def _raise_if_cancelled(
        cancellation: threading.Event,
        conversation_id: UUID,
        generation: int,
        generations: dict[UUID, int],
    ) -> None:
        if cancellation.is_set() or generation != generations.get(conversation_id):
            raise ConversationCancelledError("Assistant response was cancelled")
