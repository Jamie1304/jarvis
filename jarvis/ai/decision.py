"""Provider-neutral decision routing with safe offline fallback."""

from __future__ import annotations

from dataclasses import dataclass

from jarvis.ai.models import PrivacyClassification, PrivacyContext
from jarvis.ai.providers.base import IntelligenceProvider
from jarvis.ai.providers.intelligence import (
    DecisionProvider,
    DecisionRequest,
    DecisionResult,
    IntelligenceKind,
    RemoteIntelligencePrivacyGateway,
)


@dataclass(frozen=True, slots=True)
class DecisionRouteCandidate:
    provider_id: str
    provider: DecisionProvider
    local: bool = False
    priority: int = 0

    def __post_init__(self) -> None:
        if not self.provider_id.strip() or not isinstance(self.provider, DecisionProvider):
            raise ValueError("Decision route candidate is invalid")
        if type(self.local) is not bool or type(self.priority) is not int:
            raise ValueError("Decision route candidate metadata is invalid")


@dataclass(frozen=True, slots=True)
class DecisionRouteResult:
    result: DecisionResult
    provider_id: str
    attempted_provider_ids: tuple[str, ...]
    used_offline_fallback: bool = False


class DecisionRoutingError(RuntimeError):
    """No independently eligible decision provider completed."""

    def __init__(self, message: str, attempted_provider_ids: tuple[str, ...]) -> None:
        super().__init__(message)
        self.attempted_provider_ids = attempted_provider_ids


class DecisionRouter:
    """Try eligible decision providers in deterministic order, never by vendor name."""

    def __init__(
        self,
        candidates: tuple[DecisionRouteCandidate, ...],
        *,
        privacy_gateway: RemoteIntelligencePrivacyGateway | None = None,
    ) -> None:
        if type(candidates) is not tuple or any(
            not isinstance(item, DecisionRouteCandidate) for item in candidates
        ):
            raise ValueError("Decision route candidates are invalid")
        self._candidates = tuple(
            sorted(candidates, key=lambda item: (item.priority, item.provider_id))
        )
        self._privacy_gateway = privacy_gateway

    async def decide(self, request: DecisionRequest) -> DecisionRouteResult:
        if not isinstance(request, DecisionRequest):
            raise ValueError("Decision request is invalid")
        attempted: list[str] = []
        for candidate in self._candidates:
            attempted.append(candidate.provider_id)
            try:
                outbound = request
                if not candidate.local:
                    if self._privacy_gateway is None:
                        raise PermissionError("Remote decision privacy gateway is unavailable")
                    payload = self._privacy_gateway.prepare(
                        IntelligenceKind.DECISION,
                        dict(request.inputs),
                        request.privacy_context,
                        correlation_id=request.correlation_id,
                    )
                    outbound = DecisionRequest(
                        request.task,
                        payload.fields,
                        request.task_class,
                        request.output_schema,
                        PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
                        request.correlation_id,
                    )
                result = await candidate.provider.decide(outbound)
                if self._privacy_gateway is not None and not candidate.local:
                    self._privacy_gateway.validate_inbound(result, request.privacy_context)
                return DecisionRouteResult(
                    result,
                    candidate.provider_id,
                    tuple(attempted),
                    candidate.local and len(attempted) > 1,
                )
            except (ConnectionError, PermissionError, TimeoutError, ValueError):
                continue
        raise DecisionRoutingError("No eligible decision provider completed", tuple(attempted))


def ensure_decision_provider(provider: IntelligenceProvider) -> DecisionProvider:
    """Validate a generic registry result at the decision boundary."""

    if not isinstance(provider, DecisionProvider):
        raise TypeError("Registered provider does not implement DecisionProvider")
    return provider
