"""Process-local typed conversation orchestration."""

import threading
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from jarvis.ai.models import ChatMessage, GenerationRequest, MessageRole, ProviderHealth
from jarvis.ai.providers.base import AIProvider
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

    def __init__(self, provider: AIProvider, *, model: str, context_limit: int) -> None:
        self._provider = provider
        self._model = model
        self._context_limit = context_limit
        self._messages: dict[UUID, list[ChatMessage]] = {}
        self._cancellations: dict[UUID, threading.Event] = {}

    def create_conversation(self, system_prompt: str | None = None) -> UUID:
        """Create a conversation, optionally seeded with a system instruction."""

        conversation_id = uuid4()
        self._messages[conversation_id] = []
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
                self._raise_if_cancelled(cancellation)
                content += chunk.content
                yield ConversationUpdate(
                    conversation_id=conversation_id,
                    message_id=assistant_id,
                    content=chunk.content,
                    done=chunk.done,
                )
            self._raise_if_cancelled(cancellation)
        finally:
            self._cancellations.pop(conversation_id, None)
        messages.append(
            ChatMessage(
                id=assistant_id,
                conversation_id=conversation_id,
                role=MessageRole.ASSISTANT,
                content=content,
                created_at=datetime.now(UTC),
            )
        )

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
    def _raise_if_cancelled(cancellation: threading.Event) -> None:
        if cancellation.is_set():
            raise ConversationCancelledError("Assistant response was cancelled")
