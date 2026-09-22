"""Provider interface for local or future remote language models."""

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from jarvis.ai.models import (
    GenerationChunk,
    GenerationRequest,
    GenerationResult,
    ModelInfo,
    ProviderHealth,
)
from jarvis.ai.usability import ModelUsabilityEvidence


class IntelligenceProvider:
    """Provider-neutral root for every intelligence capability.

    The root deliberately has no ``generate`` requirement.  Generative
    providers implement :class:`AIProvider`; decision, embedding, and future
    providers can expose only the operation they actually support.
    """

    @property
    def intelligence_kinds(self) -> frozenset[str]:
        """Return the bounded kinds advertised by this adapter."""

        return frozenset()

    async def discover_models(self) -> object | None:  # noqa: B027
        """Return an adapter-owned model snapshot when discovery is supported."""

        return None

    async def aclose(self) -> None:  # noqa: B027
        """Release provider resources."""


class AIProvider(IntelligenceProvider, ABC):
    """A provider-neutral asynchronous conversational model contract."""

    @property
    def intelligence_kinds(self) -> frozenset[str]:
        return frozenset({"generative"})

    @abstractmethod
    async def generate(self, request: GenerationRequest) -> GenerationResult:
        """Generate one complete assistant response."""

    @abstractmethod
    def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        """Yield an assistant response incrementally."""

    @abstractmethod
    async def health_check(self) -> ProviderHealth:
        """Report provider connectivity without raising for normal unavailability."""

    @abstractmethod
    async def model_info(self) -> ModelInfo:
        """Return the selected model metadata."""

    async def aclose(self) -> None:  # noqa: B027
        """Release any provider resources."""

        await super().aclose()

    async def probe_usability(self) -> ModelUsabilityEvidence | None:  # noqa: B027
        """Return safe provider/model evidence when a native probe exists.

        Adapters may implement this read-only observation without making
        inference, billing, credential, or lifecycle changes.  ``None`` keeps
        the generic fallback at provider health plus unknown model/quota facts.
        """

        return None
