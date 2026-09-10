"""Local-private boundary for provider-neutral text inference.

This module is deliberately deterministic.  A provider's name, endpoint, or
response never establishes locality; only trusted provider metadata does.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from jarvis.ai.models import (
    ChatMessage,
    GenerationChunk,
    GenerationRequest,
    GenerationResult,
    ModelInfo,
    PrivacyClassification,
    PrivacyContext,
    ProviderHealth,
)
from jarvis.ai.providers.base import AIProvider
from jarvis.ai.providers.registry import ProviderMetadata
from jarvis.core.errors import PrivacyBlockedError, RemoteOutputRejectedError

_MAX_ENVELOPE_TEXT: Final = 16_000
_MAX_REMOTE_OUTPUT: Final = 1_000_000
_EMAIL = re.compile(r"(?i)(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w.-])")
_PHONE = re.compile(r"(?<!\w)\+?[0-9][0-9 .()\-]{7,}[0-9](?!\w)")
_IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_SECRET = re.compile(
    r"(?ix)(?:\b(?:api[_-]?key|access[_-]?token|password|passwd|secret|private[_-]?key)\s*[:=]\s*\S+"
    r"|\bbearer\s+[a-z0-9._~+/=-]{12,}\b|\b(?:sk|ghp|glpat|xox[baprs])-[a-z0-9_-]{8,}\b"
    r"|\bAKIA[0-9A-Z]{16}\b)"
)


class PrivacyDecisionStatus(StrEnum):
    ALLOWED_REMOTE = "allowed_remote"
    BLOCKED_PRIVACY = "blocked_privacy"
    LOCAL_PASS_THROUGH = "local_pass_through"


class PrivacyReason(StrEnum):
    ALLOWED = "allowed"
    CLOUD_ROUTE_BLOCKED_PRIVACY = "CLOUD_ROUTE_BLOCKED_PRIVACY"
    UNKNOWN_PRIVACY = "unknown_privacy"
    SECRET_NEVER_MODEL_CONTEXT = "secret_never_model_context"
    MALFORMED_ENVELOPE = "malformed_privacy_envelope"
    REMOTE_OUTPUT_UNTRUSTED = "remote_output_untrusted"


@dataclass(frozen=True, slots=True)
class PrivacyDecision:
    status: PrivacyDecisionStatus
    reason: PrivacyReason
    redaction_count: int = 0


@dataclass(frozen=True, slots=True)
class CloudTaskEnvelope:
    """The bounded minimum context a remote text task may receive."""

    objective: str
    sanitized_input: str
    constraints: tuple[str, ...] = ()
    output_schema: str = "text"
    public_references: tuple[str, ...] = ()
    correlation_ref: str | None = None

    def __post_init__(self) -> None:
        if any(
            type(value) is not str
            or not value.strip()
            or len(value) > _MAX_ENVELOPE_TEXT
            or "\x00" in value
            for value in (self.objective, self.sanitized_input, self.output_schema)
        ):
            raise ValueError("Cloud envelope text is malformed or oversized")
        for name, values in (
            ("constraints", self.constraints),
            ("references", self.public_references),
        ):
            if (
                type(values) is not tuple
                or len(values) > 32
                or any(
                    type(value) is not str
                    or not value.strip()
                    or len(value) > 4_000
                    or "\x00" in value
                    for value in values
                )
            ):
                raise ValueError(f"Cloud envelope {name} are malformed")
        if self.correlation_ref is not None and (
            type(self.correlation_ref) is not str
            or not self.correlation_ref.strip()
            or len(self.correlation_ref) > 128
            or "\x00" in self.correlation_ref
        ):
            raise ValueError("Cloud envelope correlation reference is malformed")


@dataclass(frozen=True, slots=True)
class _Placeholder:
    token: str
    value: str


class PrivacyBoundary:
    """Prepare, validate, invoke, and locally recompose one provider call."""

    def __init__(self, provider_metadata: ProviderMetadata) -> None:
        self._metadata = provider_metadata
        self.last_decision: PrivacyDecision | None = None

    @property
    def explicitly_local(self) -> bool:
        return self._metadata.explicitly_local

    def prepare(
        self, request: GenerationRequest
    ) -> tuple[GenerationRequest, tuple[_Placeholder, ...]]:
        context = request.privacy_context
        if not isinstance(context, PrivacyContext):
            raise PrivacyBlockedError(PrivacyReason.MALFORMED_ENVELOPE.value)
        raw_values = tuple(dict.fromkeys(context.known_private_values))
        if self._has_secret(request, raw_values):
            self._block(PrivacyReason.SECRET_NEVER_MODEL_CONTEXT)
        if self.explicitly_local:
            self.last_decision = PrivacyDecision(
                PrivacyDecisionStatus.LOCAL_PASS_THROUGH, PrivacyReason.ALLOWED
            )
            return request, ()
        if context.classification is PrivacyClassification.UNKNOWN:
            self._block(PrivacyReason.UNKNOWN_PRIVACY)
        if context.classification in {
            PrivacyClassification.LOCAL_ONLY,
            PrivacyClassification.SECRET,
        }:
            self._block(PrivacyReason.CLOUD_ROUTE_BLOCKED_PRIVACY)
        if len(request.messages) > 128 or any(
            type(message.content) is not str
            or len(message.content) > _MAX_ENVELOPE_TEXT
            or "\x00" in message.content
            for message in request.messages
        ):
            self._block(PrivacyReason.MALFORMED_ENVELOPE)
        placeholders: list[_Placeholder] = []
        selected = self._selected_messages(request.messages, context.allowed_message_ids)
        messages: list[ChatMessage] = []
        for message in selected:
            content = self._sanitize(message.content, raw_values, placeholders)
            messages.append(
                ChatMessage(
                    message.id,
                    message.conversation_id,
                    message.role,
                    content,
                    message.created_at,
                )
            )
        outbound = GenerationRequest(
            tuple(messages),
            request.model,
            request.context_limit,
            PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        )
        self._validate_outbound(outbound, raw_values)
        self.last_decision = PrivacyDecision(
            PrivacyDecisionStatus.ALLOWED_REMOTE,
            PrivacyReason.ALLOWED,
            len(placeholders),
        )
        return outbound, tuple(placeholders)

    async def generate(self, provider: AIProvider, request: GenerationRequest) -> GenerationResult:
        outbound, placeholders = self.prepare(request)
        result = await provider.generate(outbound)
        return GenerationResult(self._inbound(result.content, placeholders, request), result.model)

    async def stream(
        self, provider: AIProvider, request: GenerationRequest
    ) -> AsyncIterator[GenerationChunk]:
        outbound, placeholders = self.prepare(request)
        async for chunk in provider.stream(outbound):
            yield GenerationChunk(self._inbound(chunk.content, placeholders, request), chunk.done)

    def envelope(self, request: GenerationRequest) -> CloudTaskEnvelope:
        outbound, _ = self.prepare(request)
        return CloudTaskEnvelope(
            objective="text-inference",
            sanitized_input="\n".join(message.content for message in outbound.messages),
        )

    def _selected_messages(
        self, messages: tuple[ChatMessage, ...], allowed: tuple[object, ...]
    ) -> tuple[ChatMessage, ...]:
        if not allowed:
            return messages
        allowed_set = set(allowed)
        return tuple(message for message in messages if message.id in allowed_set)

    def _sanitize(
        self, content: str, known_values: tuple[str, ...], placeholders: list[_Placeholder]
    ) -> str:
        result = content
        for value in sorted(known_values, key=len, reverse=True):
            if value not in result:
                continue
            token = self._token_for(value, placeholders)
            result = result.replace(value, token)
        result = _EMAIL.sub(lambda match: self._token_for(match.group(0), placeholders), result)
        result = _PHONE.sub(lambda match: self._token_for(match.group(0), placeholders), result)
        result = _IP.sub(lambda match: self._token_for(match.group(0), placeholders), result)
        return result

    @staticmethod
    def _token_for(value: str, placeholders: list[_Placeholder]) -> str:
        for item in placeholders:
            if item.value == value:
                return item.token
        kind = "EMAIL" if _EMAIL.fullmatch(value) else "PRIVATE"
        if " " in value and value[:1].isupper() and not any(char.isdigit() for char in value):
            kind = "PERSON"
        token = f"<{kind}_{sum(item.token.startswith(f'<{kind}_') for item in placeholders) + 1}>"
        placeholders.append(_Placeholder(token, value))
        return token

    def _validate_outbound(self, request: GenerationRequest, known_values: tuple[str, ...]) -> None:
        serialized = json.dumps(
            {
                "model": request.model,
                "messages": [
                    {"role": message.role.value, "content": message.content}
                    for message in request.messages
                ],
                "context_limit": request.context_limit,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        if len(serialized) > _MAX_ENVELOPE_TEXT * 8 or any(
            value in serialized for value in known_values
        ):
            self._block(PrivacyReason.CLOUD_ROUTE_BLOCKED_PRIVACY)
        if _SECRET.search(serialized):
            self._block(PrivacyReason.SECRET_NEVER_MODEL_CONTEXT)

    def _inbound(
        self, content: str, placeholders: tuple[_Placeholder, ...], request: GenerationRequest
    ) -> str:
        if not isinstance(content, str) or len(content) > _MAX_REMOTE_OUTPUT:
            raise RemoteOutputRejectedError(PrivacyReason.REMOTE_OUTPUT_UNTRUSTED.value)
        if any(item.value in content for item in placeholders) or _SECRET.search(content):
            raise RemoteOutputRejectedError(PrivacyReason.REMOTE_OUTPUT_UNTRUSTED.value)
        for item in placeholders:
            content = content.replace(item.token, item.value)
        return content

    def _has_secret(self, request: GenerationRequest, known_values: tuple[str, ...]) -> bool:
        text = "\n".join(message.content for message in request.messages)
        return bool(_SECRET.search(text)) or any(_SECRET.search(value) for value in known_values)

    def _block(self, reason: PrivacyReason) -> None:
        decision = PrivacyDecision(PrivacyDecisionStatus.BLOCKED_PRIVACY, reason)
        self.last_decision = decision
        raise PrivacyBlockedError(reason.value)


class PrivacyGuardedProvider(AIProvider):
    """Provider facade making the privacy boundary the only inference seam."""

    def __init__(self, provider: AIProvider, metadata: ProviderMetadata) -> None:
        self._provider = provider
        self._boundary = PrivacyBoundary(metadata)

    @property
    def boundary(self) -> PrivacyBoundary:
        return self._boundary

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        return await self._boundary.generate(self._provider, request)

    def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        return self._boundary.stream(self._provider, request)

    async def health_check(self) -> ProviderHealth:
        return await self._provider.health_check()

    async def model_info(self) -> ModelInfo:
        return await self._provider.model_info()

    async def aclose(self) -> None:
        await self._provider.aclose()
