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


class ModelRole(StrEnum):
    GENERAL = "general"
    REASONING = "reasoning"
    CODING = "coding"
    TOOL_USE = "tool_use"
    VISION = "vision"
    EMBEDDING = "embedding"
    RERANKING = "reranking"
    STT = "stt"
    TTS = "tts"
    IMAGE_GENERATION = "image_generation"


class EvidenceKind(StrEnum):
    PUBLISHED = "published"
    COMMUNITY = "community"
    MEASURED_ON_THIS_MACHINE = "measured_on_this_machine"


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """Provenance for hardware/model facts; measured data is explicitly scoped."""

    kind: EvidenceKind
    source: str
    detail: str
    captured_at: datetime | None = None
    machine_scope: str | None = None
    metrics: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EvidenceKind):
            raise ValueError("Evidence kind is invalid")
        for name, value, limit in (
            ("Evidence source", self.source, 256),
            ("Evidence detail", self.detail, 2_000),
        ):
            if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
                raise ValueError(f"{name} is invalid")
        if self.captured_at is not None and self.captured_at.tzinfo is None:
            raise ValueError("Evidence timestamp must be timezone-aware")
        if self.kind is EvidenceKind.MEASURED_ON_THIS_MACHINE:
            if self.captured_at is None or self.machine_scope != "this_machine":
                raise ValueError("Measured evidence must identify this machine and timestamp")
        elif self.machine_scope is not None:
            raise ValueError("Only measured evidence may identify a machine")
        if (
            type(self.metrics) is not tuple
            or len(self.metrics) > 64
            or any(
                type(key) is not str
                or type(value) is not str
                or not key.strip()
                or len(key) > 128
                or len(value) > 512
                or "\x00" in key
                or "\x00" in value
                for key, value in self.metrics
            )
        ):
            raise ValueError("Evidence metrics are invalid")


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
