"""Provider-neutral conversational model types."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class MessageRole(StrEnum):
    """Roles accepted by conversational model providers."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


@dataclass(frozen=True, slots=True)
class ChatMessage:
    """A single conversation message independent of any AI provider SDK."""

    id: UUID
    conversation_id: UUID
    role: MessageRole
    content: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class GenerationRequest:
    """A normalized request sent to an AI provider."""

    messages: tuple[ChatMessage, ...]
    model: str
    context_limit: int


@dataclass(frozen=True, slots=True)
class GenerationResult:
    """A complete generated assistant response."""

    content: str
    model: str


@dataclass(frozen=True, slots=True)
class GenerationChunk:
    """An incremental part of a streamed assistant response."""

    content: str
    done: bool = False


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    """Provider connectivity state safe to expose to the UI."""

    available: bool
    detail: str


@dataclass(frozen=True, slots=True)
class ModelInfo:
    """Provider-neutral description of the selected model."""

    provider: str
    model: str
    context_limit: int
