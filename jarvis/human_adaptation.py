"""Language, localization, and bounded personal adaptation services.

This module is deliberately a presentation and learning layer.  It does not
own actor identity, permissions, execution, verification, or automation
authority.  Persistent values are bounded aggregates and typed preferences;
raw conversation, keystrokes, credentials, and hidden reasoning are never
stored here.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
import string
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Final, cast
from uuid import UUID, uuid4


class HumanAdaptationError(RuntimeError):
    """The adaptation store or a typed adaptation boundary is invalid."""


class HumanAdaptationMigrationError(HumanAdaptationError):
    """The adaptation database cannot be safely opened or migrated."""


class LanguageSupportState(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    MODEL_ONLY = "model_only"
    TEXT_ONLY = "text_only"
    VOICE_UNAVAILABLE = "voice_unavailable"
    UNSUPPORTED = "unsupported"


class LanguageResolutionSource(StrEnum):
    REQUESTED_OUTPUT = "requested_output"
    TASK_OVERRIDE = "task_override"
    CONVERSATION_OVERRIDE = "conversation_override"
    USER_PREFERENCE = "user_preference"
    APPLICATION_DEFAULT = "application_default"
    SAFE_FALLBACK = "safe_fallback"
    DETECTED = "detected"
    PROVIDER_METADATA = "provider_metadata"
    UNKNOWN = "unknown"


class LanguageDetectionProvenance(StrEnum):
    EXPLICIT = "explicit"
    LOCAL_DETECTOR = "local_detector"
    STT_PROVIDER = "stt_provider"
    MODEL_EVIDENCE = "model_evidence"
    UNKNOWN = "unknown"


class ConversationLanguageMode(StrEnum):
    AUTO = "auto"
    FIXED = "fixed"


class PersonalizationMode(StrEnum):
    OFF = "off"
    EXPLICIT_ONLY = "explicit_only"
    COMMUNICATION = "communication"
    CONTEXTUAL = "contextual"
    DEEP = "deep"


class AdaptivePersonaMode(StrEnum):
    FIXED = "fixed"
    ADAPTIVE = "adaptive"


class StyleFidelity(StrEnum):
    OFF = "off"
    LIGHT = "light"
    BALANCED = "balanced"
    HIGH = "high"
    MAXIMUM = "maximum"


class ObservationScope(StrEnum):
    JARVIS_ONLY = "jarvis_only"
    APP_SCOPED = "app_scoped"
    SYSTEM_WIDE = "system_wide"


class EvidenceClass(StrEnum):
    EXPLICIT = "explicit"
    COMMUNICATION = "communication"
    CONTEXTUAL = "contextual"
    CORRECTION = "correction"
    ROUTINE = "routine"


class AdaptationSource(StrEnum):
    USER = "user"
    LOCAL_AGGREGATE = "local_aggregate"
    SYSTEM_DEFAULT = "system_default"


class LanguageTag:
    """A normalized BCP-47-like language tag without vendor assumptions."""

    __slots__ = ("tag",)
    tag: str

    def __init__(self, tag: str) -> None:
        object.__setattr__(self, "tag", normalize_language_tag(tag))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("LanguageTag is immutable")

    def __repr__(self) -> str:
        return f"LanguageTag({self.tag!r})"

    def __str__(self) -> str:
        return self.tag

    def __hash__(self) -> int:
        return hash(self.tag)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, LanguageTag) and self.tag == other.tag

    @property
    def base(self) -> str:
        return self.tag.split("-", 1)[0]


def normalize_language_tag(value: str) -> str:
    if type(value) is not str:
        raise ValueError("Language tag must be text")
    raw = value.strip().replace("_", "-")
    if not raw or len(raw) > 35 or not re.fullmatch(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{2,8})*", raw):
        raise ValueError("Language tag is not a bounded standard identifier")
    parts = raw.split("-")
    normalized = [parts[0].lower()]
    for part in parts[1:]:
        normalized.append(part.upper() if len(part) in {2, 3} and part.isalpha() else part.title())
    return "-".join(normalized)


def normalize_locale(value: str) -> str:
    return normalize_language_tag(value)


@dataclass(frozen=True, slots=True)
class LanguageDetection:
    language: LanguageTag | None
    confidence: float
    provenance: LanguageDetectionProvenance
    evidence: str = ""

    def __post_init__(self) -> None:
        if self.language is not None and not isinstance(self.language, LanguageTag):
            raise ValueError("Detected language is malformed")
        if type(self.confidence) not in {int, float} or not math.isfinite(self.confidence):
            raise ValueError("Language confidence is malformed")
        if not 0 <= self.confidence <= 1:
            raise ValueError("Language confidence is outside its bounds")
        if not isinstance(self.provenance, LanguageDetectionProvenance):
            raise ValueError("Language provenance is malformed")
        if type(self.evidence) is not str or len(self.evidence) > 256 or "\x00" in self.evidence:
            raise ValueError("Language evidence is malformed")


@dataclass(frozen=True, slots=True)
class LanguagePreferences:
    interface_language: LanguageTag = field(default_factory=lambda: LanguageTag("en"))
    locale: str = "en-US"
    conversation_language: LanguageTag | None = None
    conversation_mode: ConversationLanguageMode = ConversationLanguageMode.AUTO
    fallback_language: LanguageTag = field(default_factory=lambda: LanguageTag("en"))
    stt_language: LanguageTag | None = None
    tts_language: LanguageTag | None = None
    tts_voice: str | None = None

    def __post_init__(self) -> None:
        for value in (self.interface_language, self.fallback_language):
            if not isinstance(value, LanguageTag):
                raise ValueError("Language preference is malformed")
        for optional_value in (
            self.conversation_language,
            self.stt_language,
            self.tts_language,
        ):
            if optional_value is not None and not isinstance(optional_value, LanguageTag):
                raise ValueError("Optional language preference is malformed")
        object.__setattr__(self, "locale", normalize_locale(self.locale))
        if not isinstance(self.conversation_mode, ConversationLanguageMode):
            raise ValueError("Conversation language mode is malformed")
        if self.conversation_mode is ConversationLanguageMode.AUTO and self.conversation_language:
            raise ValueError("AUTO conversation mode cannot carry a fixed language")
        if self.tts_voice is not None and (
            type(self.tts_voice) is not str
            or not self.tts_voice.strip()
            or len(self.tts_voice) > 256
        ):
            raise ValueError("TTS voice preference is malformed")

    def as_dict(self) -> dict[str, object]:
        return {
            "interface_language": str(self.interface_language),
            "locale": self.locale,
            "conversation_language": str(self.conversation_language)
            if self.conversation_language
            else None,
            "conversation_mode": self.conversation_mode.value,
            "fallback_language": str(self.fallback_language),
            "stt_language": str(self.stt_language) if self.stt_language else None,
            "tts_language": str(self.tts_language) if self.tts_language else None,
            "tts_voice": self.tts_voice,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> LanguagePreferences:
        def optional_language(name: str) -> LanguageTag | None:
            item = value.get(name)
            return LanguageTag(item) if isinstance(item, str) and item else None

        return cls(
            interface_language=LanguageTag(str(value.get("interface_language", "en"))),
            locale=str(value.get("locale", "en-US")),
            conversation_language=optional_language("conversation_language"),
            conversation_mode=ConversationLanguageMode(
                str(value.get("conversation_mode", ConversationLanguageMode.AUTO.value))
            ),
            fallback_language=LanguageTag(str(value.get("fallback_language", "en"))),
            stt_language=optional_language("stt_language"),
            tts_language=optional_language("tts_language"),
            tts_voice=(str(value["tts_voice"]) if value.get("tts_voice") else None),
        )


@dataclass(frozen=True, slots=True)
class LanguageOverrides:
    requested_output: LanguageTag | None = None
    task: LanguageTag | None = None
    conversation: LanguageTag | None = None
    content: LanguageTag | None = None
    stt: LanguageTag | None = None
    tts: LanguageTag | None = None

    def __post_init__(self) -> None:
        for value in (
            self.requested_output,
            self.task,
            self.conversation,
            self.content,
            self.stt,
            self.tts,
        ):
            if value is not None and not isinstance(value, LanguageTag):
                raise ValueError("Language override is malformed")


@dataclass(frozen=True, slots=True)
class ResolvedLanguage:
    language: LanguageTag
    source: LanguageResolutionSource
    confidence: float
    detection: LanguageDetection | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.language, LanguageTag) or not isinstance(
            self.source, LanguageResolutionSource
        ):
            raise ValueError("Resolved language is malformed")
        if not 0 <= self.confidence <= 1:
            raise ValueError("Resolved language confidence is malformed")


@dataclass(frozen=True, slots=True)
class LanguageContext:
    interface_language: LanguageTag
    conversation: ResolvedLanguage
    output: ResolvedLanguage
    content_language: LanguageTag | None
    locale: str
    stt_language: LanguageTag | None
    tts_language: LanguageTag | None
    detection: LanguageDetection | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.interface_language, LanguageTag):
            raise ValueError("Interface language is malformed")
        if not isinstance(self.conversation, ResolvedLanguage) or not isinstance(
            self.output, ResolvedLanguage
        ):
            raise ValueError("Language resolution is malformed")
        object.__setattr__(self, "locale", normalize_locale(self.locale))

    def prompt_projection(self) -> str:
        """Bounded presentation metadata; no authority or personal history."""

        parts = [
            f"conversation_language={self.conversation.language}",
            f"output_language={self.output.language}",
        ]
        if self.content_language is not None:
            parts.append(f"content_language={self.content_language}")
        return "Language presentation context only; " + ", ".join(parts) + "."


class LanguageContextResolver:
    """Resolve scoped language without mutating global preferences."""

    def __init__(self, *, application_default: LanguageTag | None = None) -> None:
        self._application_default = application_default or LanguageTag("en")

    def resolve(
        self,
        preferences: LanguagePreferences,
        overrides: LanguageOverrides | None = None,
        *,
        detected: LanguageDetection | None = None,
    ) -> LanguageContext:
        active_overrides = overrides or LanguageOverrides()
        conversation, conversation_source = self._conversation_language(
            preferences, active_overrides, detected
        )
        output, output_source = self._first(
            (
                (active_overrides.requested_output, LanguageResolutionSource.REQUESTED_OUTPUT),
                (active_overrides.task, LanguageResolutionSource.TASK_OVERRIDE),
                (active_overrides.conversation, LanguageResolutionSource.CONVERSATION_OVERRIDE),
                (conversation, conversation_source),
                (self._application_default, LanguageResolutionSource.APPLICATION_DEFAULT),
                (preferences.fallback_language, LanguageResolutionSource.SAFE_FALLBACK),
            )
        )
        assert conversation is not None and output is not None
        return LanguageContext(
            preferences.interface_language,
            ResolvedLanguage(
                conversation,
                conversation_source,
                1.0
                if conversation_source is not LanguageResolutionSource.DETECTED
                else (detected.confidence if detected else 0.0),
                detected,
            ),
            ResolvedLanguage(
                output,
                output_source,
                1.0
                if output_source is not LanguageResolutionSource.DETECTED
                else (detected.confidence if detected else 0.0),
                detected,
            ),
            active_overrides.content,
            preferences.locale,
            active_overrides.stt or preferences.stt_language,
            active_overrides.tts or preferences.tts_language,
            detected,
        )

    def _conversation_language(
        self,
        preferences: LanguagePreferences,
        overrides: LanguageOverrides,
        detected: LanguageDetection | None,
    ) -> tuple[LanguageTag, LanguageResolutionSource]:
        if overrides.conversation is not None:
            return overrides.conversation, LanguageResolutionSource.CONVERSATION_OVERRIDE
        if (
            preferences.conversation_mode is ConversationLanguageMode.FIXED
            and preferences.conversation_language
        ):
            return preferences.conversation_language, LanguageResolutionSource.USER_PREFERENCE
        if detected is not None and detected.language is not None and detected.confidence >= 0.75:
            return detected.language, LanguageResolutionSource.DETECTED
        return self._application_default, LanguageResolutionSource.APPLICATION_DEFAULT

    @staticmethod
    def _first(
        values: Sequence[tuple[LanguageTag | None, LanguageResolutionSource]],
    ) -> tuple[LanguageTag | None, LanguageResolutionSource]:
        for language, source in values:
            if language is not None:
                return language, source
        return None, LanguageResolutionSource.UNKNOWN


class DeterministicLanguageDetector:
    """Small local detector with explicit uncertainty for short text."""

    _WORDS: Final[dict[str, frozenset[str]]] = {
        "en": frozenset({"the", "and", "please", "write", "hello", "this", "with"}),
        "nl": frozenset({"de", "het", "en", "graag", "schrijf", "hallo", "met"}),
    }

    def detect(
        self,
        text: str,
        *,
        explicit: LanguageTag | None = None,
        provider_language: LanguageTag | None = None,
    ) -> LanguageDetection:
        if explicit is not None:
            return LanguageDetection(
                explicit, 1.0, LanguageDetectionProvenance.EXPLICIT, "explicit metadata"
            )
        if provider_language is not None:
            return LanguageDetection(
                provider_language,
                0.95,
                LanguageDetectionProvenance.STT_PROVIDER,
                "provider metadata",
            )
        words = {item.casefold() for item in re.findall(r"[A-Za-zÀ-ÿ]+", text) if item}
        if len(words) < 2:
            return LanguageDetection(
                None, 0.0, LanguageDetectionProvenance.UNKNOWN, "short or ambiguous text"
            )
        scores = {language: len(words & vocabulary) for language, vocabulary in self._WORDS.items()}
        ordered = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        if (
            not ordered
            or ordered[0][1] == 0
            or (len(ordered) > 1 and ordered[0][1] == ordered[1][1])
        ):
            return LanguageDetection(
                None, 0.0, LanguageDetectionProvenance.UNKNOWN, "no decisive local evidence"
            )
        confidence = min(0.99, 0.55 + ordered[0][1] / max(6, len(words)))
        return LanguageDetection(
            LanguageTag(ordered[0][0]),
            confidence,
            LanguageDetectionProvenance.LOCAL_DETECTOR,
            "bounded local word evidence",
        )


@dataclass(frozen=True, slots=True)
class LanguageCapability:
    language: LanguageTag
    state: LanguageSupportState
    text: bool = True
    model: bool = True
    stt: bool = False
    tts: bool = False
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.language, LanguageTag) or not isinstance(
            self.state, LanguageSupportState
        ):
            raise ValueError("Language capability is malformed")
        if any(type(value) is not bool for value in (self.text, self.model, self.stt, self.tts)):
            raise ValueError("Language capability flags are malformed")
        if len(self.evidence) > 8 or any(
            type(item) is not str or not item.strip() for item in self.evidence
        ):
            raise ValueError("Language capability evidence is malformed")

    @property
    def routing_capability(self) -> str:
        return f"language:{self.language.base}"


class LanguageCapabilityCatalog:
    """Provider-neutral language evidence; no language selects a vendor."""

    def __init__(self, capabilities: Sequence[LanguageCapability] | None = None) -> None:
        defaults = capabilities or (
            LanguageCapability(
                LanguageTag("en"), LanguageSupportState.TEXT_ONLY, evidence=("core text",)
            ),
            LanguageCapability(
                LanguageTag("nl"), LanguageSupportState.TEXT_ONLY, evidence=("core text",)
            ),
        )
        self._capabilities = {item.language.base: item for item in defaults}

    def get(self, language: LanguageTag | str) -> LanguageCapability:
        tag = language if isinstance(language, LanguageTag) else LanguageTag(language)
        return self._capabilities.get(
            tag.base,
            LanguageCapability(tag, LanguageSupportState.UNSUPPORTED, text=False, model=False),
        )

    def register(self, capability: LanguageCapability) -> None:
        self._capabilities[capability.language.base] = capability

    def all(self) -> tuple[LanguageCapability, ...]:
        return tuple(self._capabilities[key] for key in sorted(self._capabilities))


@dataclass(frozen=True, slots=True)
class VoiceLanguageCapability:
    provider_id: str
    modality: str
    languages: frozenset[LanguageTag]
    automatic_detection: bool = False
    physical_evidence: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.provider_id) is not str
            or not self.provider_id.strip()
            or len(self.provider_id) > 128
            or self.modality not in {"stt", "tts"}
            or type(self.languages) is not frozenset
            or any(not isinstance(item, LanguageTag) for item in self.languages)
            or type(self.automatic_detection) is not bool
            or type(self.physical_evidence) is not bool
        ):
            raise ValueError("Voice language capability is malformed")


class VoiceLanguageCatalog:
    """Truthful STT/TTS language metadata, independent of device success."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], VoiceLanguageCapability] = {}

    def register(self, capability: VoiceLanguageCapability) -> None:
        self._items[(capability.modality, capability.provider_id.casefold())] = capability

    def get(self, modality: str, provider_id: str) -> VoiceLanguageCapability | None:
        return self._items.get((modality, provider_id.casefold()))

    def supports(self, modality: str, provider_id: str, language: LanguageTag | str) -> bool:
        capability = self.get(modality, provider_id)
        tag = language if isinstance(language, LanguageTag) else LanguageTag(language)
        return capability is not None and tag.base in {item.base for item in capability.languages}


class Localizer:
    """Data-only message lookup with bounded, named interpolation."""

    def __init__(self, bundles: Mapping[str, Mapping[str, str]], *, fallback: str = "en") -> None:
        if not isinstance(bundles, Mapping) or not bundles:
            raise ValueError("Localization bundles are malformed")
        normalized: dict[str, dict[str, str]] = {}
        for key, value in bundles.items():
            if type(key) is not str or not isinstance(value, Mapping):
                raise ValueError("Localization bundle is malformed")
            language = normalize_language_tag(key).split("-", 1)[0]
            messages: dict[str, str] = {}
            for message_id, template in value.items():
                if type(message_id) is not str or not re.fullmatch(
                    r"[a-z0-9_.-]{1,128}", message_id
                ):
                    raise ValueError("Localization message ID is malformed")
                if type(template) is not str or len(template) > 4_096 or "\x00" in template:
                    raise ValueError("Localization template is malformed")
                try:
                    parsed = tuple(string.Formatter().parse(template))
                except (IndexError, ValueError) as error:
                    raise ValueError("Localization template is malformed") from error
                fields = {field for _, field, _, _ in parsed if field}
                if any(
                    conversion is not None
                    or format_spec
                    or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", field)
                    for _, field, format_spec, conversion in parsed
                    if field
                ):
                    raise ValueError("Localization template uses an unsafe field")
                if len(fields) > 16:
                    raise ValueError("Localization template has too many fields")
                messages[message_id] = template
            normalized[language] = messages
        self._bundles = normalized
        self._fallback = normalize_language_tag(fallback).split("-", 1)[0]
        if self._fallback not in self._bundles:
            raise ValueError("Localization fallback bundle is missing")

    def translate(self, message_id: str, language: LanguageTag | str, **params: object) -> str:
        if type(message_id) is not str or not re.fullmatch(r"[a-z0-9_.-]{1,128}", message_id):
            raise ValueError("Localization message ID is malformed")
        tag = language if isinstance(language, LanguageTag) else LanguageTag(language)
        template = self._bundles.get(tag.base, {}).get(message_id)
        template = template or self._bundles[self._fallback].get(message_id)
        if template is None:
            return f"[{message_id}]"
        fields = {field for _, field, _, _ in string.Formatter().parse(template) if field}
        if set(params) != fields:
            raise ValueError("Localization interpolation parameters do not match the resource")
        safe = {key: _display_value(value) for key, value in params.items()}
        rendered = template.format_map(safe)
        if len(rendered) > 4_096 or any(ord(char) < 32 for char in rendered):
            raise ValueError("Localized text is not safe display text")
        return rendered

    def available(self, language: LanguageTag | str) -> bool:
        tag = language if isinstance(language, LanguageTag) else LanguageTag(language)
        return tag.base in self._bundles


def load_default_localizer() -> Localizer:
    """Load the versioned English and Dutch data-only resource bundles."""

    root = Path(__file__).with_name("locales")
    bundles: dict[str, Mapping[str, str]] = {}
    for language in ("en", "nl"):
        value = json.loads((root / f"{language}.json").read_text(encoding="utf-8"))
        if not isinstance(value, Mapping) or any(
            type(key) is not str or type(item) is not str for key, item in value.items()
        ):
            raise HumanAdaptationError("Localization resource is malformed")
        bundles[language] = value
    return Localizer(bundles)


def _display_value(value: object) -> str:
    if isinstance(value, str | int | float | bool):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Localization parameter is not finite")
        text = str(value)
    elif isinstance(value, LanguageTag):
        text = str(value)
    else:
        raise TypeError("Localization parameters must be scalar display values")
    if len(text) > 512 or any(ord(char) < 32 for char in text):
        raise ValueError("Localization parameter is not safe display text")
    return text


@dataclass(frozen=True, slots=True)
class LocalizedCapabilityPresentation:
    capability_id: str
    name: str
    description: str
    language: LanguageTag


def localize_capability_metadata(
    capability_id: str,
    metadata: Mapping[str, object],
    language: LanguageTag | str,
) -> LocalizedCapabilityPresentation:
    """Render declarative capability metadata without service-specific branches."""

    tag = language if isinstance(language, LanguageTag) else LanguageTag(language)
    names = metadata.get("names", {})
    descriptions = metadata.get("descriptions", {})
    if not isinstance(names, Mapping) or not isinstance(descriptions, Mapping):
        raise ValueError("Capability localization metadata is malformed")
    name = names.get(str(tag), names.get(tag.base, metadata.get("name")))
    description = descriptions.get(
        str(tag), descriptions.get(tag.base, metadata.get("description"))
    )
    if not all(
        isinstance(item, str) and item.strip() for item in (capability_id, name, description)
    ):
        raise ValueError("Capability localization fields are malformed")
    return LocalizedCapabilityPresentation(capability_id, name, description, tag)


@dataclass(frozen=True, slots=True)
class LocalizedApprovalPresentation:
    """Localized text paired with the unchanged trusted approval identity."""

    language: LanguageTag
    short_text: str
    exact_text: str
    request_id: UUID | None
    argument_fingerprint: str | None
    action_fingerprint: str | None


def localize_approval_request(
    request: object,
    language: LanguageTag | str,
    *,
    localizer: Localizer | None = None,
) -> LocalizedApprovalPresentation:
    """Translate only trusted approval presentation; never rebuild the request."""

    from jarvis.permissions.presentation import TrustedActionNarrator

    tag = language if isinstance(language, LanguageTag) else LanguageTag(language)
    presentation = TrustedActionNarrator().narrate(request)
    translator = localizer or load_default_localizer()
    short = translator.translate(
        "permission.request",
        tag,
        permission=presentation.permission_requested.value,
        action=presentation.operation.action,
    )
    exact = f"{short} {presentation.exact_details}"
    return LocalizedApprovalPresentation(
        tag,
        short,
        exact,
        presentation.operation.approval_request_id,
        presentation.operation.argument_fingerprint,
        presentation.operation.action_fingerprint,
    )


@dataclass(frozen=True, slots=True)
class AdaptationHistoryEntry:
    field: str
    previous_value: object
    new_value: object
    occurred_at: datetime
    evidence_class: EvidenceClass
    confidence: float
    source: AdaptationSource
    corrected: bool = False

    def __post_init__(self) -> None:
        _bounded_key(self.field)
        _json_value(self.previous_value)
        _json_value(self.new_value)
        if self.occurred_at.tzinfo is None or not isinstance(self.evidence_class, EvidenceClass):
            raise ValueError("Adaptation history metadata is malformed")
        if (
            type(self.confidence) not in {int, float}
            or not math.isfinite(self.confidence)
            or not 0 <= self.confidence <= 1
            or not isinstance(self.source, AdaptationSource)
        ):
            raise ValueError("Adaptation history confidence/source is malformed")
        if type(self.corrected) is not bool:
            raise ValueError("Adaptation correction flag is malformed")


@dataclass(frozen=True, slots=True)
class ExpressionAttribute:
    name: str
    value: object
    confidence: float
    evidence_count: int
    provenance: str
    updated_at: datetime
    relationship: str | None = None

    def __post_init__(self) -> None:
        _bounded_key(self.name)
        _validate_expression_value(self.name, self.value)
        if (
            type(self.confidence) not in {int, float}
            or not math.isfinite(self.confidence)
            or not 0 <= self.confidence <= 1
            or type(self.evidence_count) is not int
            or not 0 <= self.evidence_count <= HumanAdaptationStore._MAX_COUNTER
        ):
            raise ValueError("Expression attribute confidence/count is malformed")
        if type(self.provenance) is not str or not self.provenance or len(self.provenance) > 256:
            raise ValueError("Expression provenance is malformed")
        if self.updated_at.tzinfo is None:
            raise ValueError("Expression timestamp must be timezone-aware")
        if self.relationship is not None:
            _relationship_key(self.relationship)


@dataclass(frozen=True, slots=True)
class RoutineCandidate:
    routine_id: UUID
    pattern: str
    proposed_action: str
    evidence_count: int
    confidence: float
    scope: ObservationScope
    contexts: tuple[str, ...]
    last_observed: datetime
    suggestion_only: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.routine_id, UUID):
            raise ValueError("Routine ID is malformed")
        for value, limit in ((self.pattern, 256), (self.proposed_action, 512)):
            if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
                raise ValueError("Routine candidate text is malformed")
        if self.evidence_count < 1 or not 0 <= self.confidence <= 1:
            raise ValueError("Routine candidate confidence/count is malformed")
        if not isinstance(self.scope, ObservationScope) or self.last_observed.tzinfo is None:
            raise ValueError("Routine candidate metadata is malformed")
        if len(self.contexts) > 16 or any(
            type(item) is not str or len(item) > 128 for item in self.contexts
        ):
            raise ValueError("Routine candidate contexts are malformed")
        if self.suggestion_only is not True:
            raise ValueError("Routine candidates cannot become authority")


@dataclass(frozen=True, slots=True)
class BehavioralAggregateEvent:
    surface: str
    duration_seconds: int = 0
    correction_count: int = 0
    backspace_count: int = 0
    keystroke_count: int = 0
    navigation_category: str | None = None
    secure_input: bool = False
    scope: ObservationScope = ObservationScope.JARVIS_ONLY
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if type(self.surface) is not str or not re.fullmatch(r"[a-z0-9_.-]{1,128}", self.surface):
            raise ValueError("Behavioral event surface is malformed")
        for value in (
            self.duration_seconds,
            self.correction_count,
            self.backspace_count,
            self.keystroke_count,
        ):
            if type(value) is not int or not 0 <= value <= 1_000_000:
                raise ValueError("Behavioral aggregate is outside its bounds")
        if self.navigation_category is not None and (
            type(self.navigation_category) is not str or len(self.navigation_category) > 128
        ):
            raise ValueError("Behavioral navigation category is malformed")
        if not isinstance(self.secure_input, bool) or not isinstance(self.scope, ObservationScope):
            raise ValueError("Behavioral event policy metadata is malformed")
        if self.occurred_at.tzinfo is None:
            raise ValueError("Behavioral event timestamp must be timezone-aware")


class HumanAdaptationStore:
    """Versioned local store for preferences, aggregates, and inspection history."""

    CURRENT_SCHEMA = 1
    _MAX_COUNTER = 10_000
    _REQUIRED_TABLES = frozenset(
        {
            "schema_versions",
            "adaptation_state",
            "adaptation_history",
            "adaptation_evidence",
            "expression_attributes",
            "routine_candidates",
        }
    )

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._connection: sqlite3.Connection | None = None
        self._lock = RLock()
        self._transaction_depth = 0
        try:
            connection = sqlite3.connect(self._path, timeout=5.0, check_same_thread=False)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA foreign_keys = ON")
            self._connection = connection
            self._migrate()
        except Exception as error:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            raise HumanAdaptationMigrationError(
                "Human adaptation persistence is unavailable"
            ) from error

    @property
    def database_path(self) -> Path:
        return self._path

    def __enter__(self) -> HumanAdaptationStore:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
                self._transaction_depth = 0

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize and atomically group adaptation-store mutations."""

        with self._lock:
            connection = self._require()
            outermost = self._transaction_depth == 0
            self._transaction_depth += 1
            try:
                yield connection
                if outermost:
                    connection.commit()
            except Exception:
                if outermost:
                    connection.rollback()
                raise
            finally:
                self._transaction_depth -= 1

    def schema_version(self) -> int:
        with self._lock:
            connection = self._require()
            row = connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM schema_versions"
            ).fetchone()
            return int(row["version"] if row else 0)

    def get_state(self, key: str) -> object | None:
        _bounded_key(key)
        with self._lock:
            row = (
                self._require()
                .execute("SELECT value FROM adaptation_state WHERE key = ?", (key,))
                .fetchone()
            )
            return json.loads(row["value"]) if row else None

    def set_state(self, key: str, value: object) -> None:
        _bounded_key(key)
        encoded = json.dumps(_json_value(value), sort_keys=True, separators=(",", ":"))
        with self._lock:
            connection = self._require()
            connection.execute(
                "INSERT INTO adaptation_state(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, encoded),
            )
            self._commit()

    def delete_state(self, key: str) -> None:
        _bounded_key(key)
        with self._lock:
            self._require().execute("DELETE FROM adaptation_state WHERE key = ?", (key,))
            self._commit()

    def append_history(self, entry: AdaptationHistoryEntry) -> None:
        if not isinstance(entry, AdaptationHistoryEntry):
            raise ValueError("Adaptation history entry is malformed")
        with self._lock:
            self._require().execute(
                "INSERT INTO adaptation_history(field, previous_value, new_value, occurred_at, "
                "evidence_class, confidence, source, corrected) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.field,
                    json.dumps(entry.previous_value, sort_keys=True, separators=(",", ":")),
                    json.dumps(entry.new_value, sort_keys=True, separators=(",", ":")),
                    _iso(entry.occurred_at),
                    entry.evidence_class.value,
                    entry.confidence,
                    entry.source.value,
                    int(entry.corrected),
                ),
            )
            self._commit()

    def history(self, *, limit: int = 100) -> tuple[AdaptationHistoryEntry, ...]:
        if not 1 <= limit <= 1_000:
            raise ValueError("History limit is outside its bounds")
        with self._lock:
            rows = self._require().execute(
                "SELECT field, previous_value, new_value, occurred_at, evidence_class, "
                "confidence, source, corrected "
                "FROM adaptation_history ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            return tuple(
                AdaptationHistoryEntry(
                    row["field"],
                    json.loads(row["previous_value"]),
                    json.loads(row["new_value"]),
                    _parse_iso(row["occurred_at"]),
                    EvidenceClass(row["evidence_class"]),
                    float(row["confidence"]),
                    AdaptationSource(row["source"]),
                    bool(row["corrected"]),
                )
                for row in rows
            )

    def upsert_expression(self, attribute: ExpressionAttribute) -> None:
        if not isinstance(attribute, ExpressionAttribute):
            raise ValueError("Expression attribute is malformed")
        with self._lock:
            self._require().execute(
                "INSERT INTO expression_attributes(name, relationship, value, confidence, "
                "evidence_count, provenance, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(name, relationship) DO UPDATE SET value=excluded.value, "
                "confidence=excluded.confidence, evidence_count=excluded.evidence_count, "
                "provenance=excluded.provenance, updated_at=excluded.updated_at",
                (
                    attribute.name,
                    attribute.relationship or "",
                    json.dumps(attribute.value, sort_keys=True, separators=(",", ":")),
                    attribute.confidence,
                    attribute.evidence_count,
                    attribute.provenance,
                    _iso(attribute.updated_at),
                ),
            )
            self._commit()

    def expressions(self) -> tuple[ExpressionAttribute, ...]:
        with self._lock:
            rows = self._require().execute(
                "SELECT name, relationship, value, confidence, evidence_count, "
                "provenance, updated_at "
                "FROM expression_attributes ORDER BY name, relationship"
            )
            return tuple(
                ExpressionAttribute(
                    row["name"],
                    json.loads(row["value"]),
                    float(row["confidence"]),
                    int(row["evidence_count"]),
                    row["provenance"],
                    _parse_iso(row["updated_at"]),
                    row["relationship"] or None,
                )
                for row in rows
            )

    def upsert_routine(self, candidate: RoutineCandidate) -> None:
        if not isinstance(candidate, RoutineCandidate):
            raise ValueError("Routine candidate is malformed")
        with self._lock:
            self._require().execute(
                "INSERT INTO routine_candidates(routine_id, pattern, proposed_action, "
                "evidence_count, "
                "confidence, scope, contexts, last_observed) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(pattern) DO UPDATE SET routine_id=excluded.routine_id, "
                "proposed_action=excluded.proposed_action, evidence_count=excluded.evidence_count, "
                "confidence=excluded.confidence, scope=excluded.scope, contexts=excluded.contexts, "
                "last_observed=excluded.last_observed",
                (
                    str(candidate.routine_id),
                    candidate.pattern,
                    candidate.proposed_action,
                    candidate.evidence_count,
                    candidate.confidence,
                    candidate.scope.value,
                    json.dumps(candidate.contexts),
                    _iso(candidate.last_observed),
                ),
            )
            self._commit()

    def routines(self) -> tuple[RoutineCandidate, ...]:
        with self._lock:
            rows = self._require().execute(
                "SELECT routine_id, pattern, proposed_action, evidence_count, confidence, scope, "
                "contexts, last_observed "
                "FROM routine_candidates ORDER BY last_observed DESC"
            )
            return tuple(
                RoutineCandidate(
                    UUID(row["routine_id"]),
                    row["pattern"],
                    row["proposed_action"],
                    int(row["evidence_count"]),
                    float(row["confidence"]),
                    ObservationScope(row["scope"]),
                    tuple(json.loads(row["contexts"])),
                    _parse_iso(row["last_observed"]),
                )
                for row in rows
            )

    def clear_adaptations(self) -> None:
        with self.transaction() as connection:
            connection.execute("DELETE FROM adaptation_history")
            connection.execute("DELETE FROM adaptation_evidence")
            connection.execute(
                "DELETE FROM adaptation_state WHERE key IN "
                "('adaptive_persona', 'persona_pins', 'learning_counters')"
            )

    def clear_learning(self) -> None:
        with self.transaction() as connection:
            connection.execute("DELETE FROM expression_attributes")
            connection.execute("DELETE FROM routine_candidates")
            connection.execute("DELETE FROM adaptation_evidence")
            connection.execute(
                "DELETE FROM adaptation_state WHERE key IN "
                "('behavior_aggregates', 'learning_counters', 'routine_counters')"
            )

    def _require(self) -> sqlite3.Connection:
        if self._connection is None:
            raise HumanAdaptationError("Human adaptation store is closed")
        return self._connection

    def _commit(self) -> None:
        if self._transaction_depth == 0:
            self._require().commit()

    def _migrate(self) -> None:
        with self.transaction() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_versions("
                "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
            )
            row = connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM schema_versions"
            ).fetchone()
            current = int(row["version"] if row else 0)
            if current > self.CURRENT_SCHEMA:
                raise HumanAdaptationMigrationError(
                    "Human adaptation database uses a future schema"
                )
            if current == 0:
                connection.execute(
                    "CREATE TABLE adaptation_state(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE adaptation_history("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, field TEXT NOT NULL, "
                    "previous_value TEXT NOT NULL, new_value TEXT NOT NULL, "
                    "occurred_at TEXT NOT NULL, "
                    "evidence_class TEXT NOT NULL, confidence REAL NOT NULL, source TEXT NOT NULL, "
                    "corrected INTEGER NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE adaptation_evidence("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, field TEXT NOT NULL, "
                    "target_value INTEGER NOT NULL, confidence REAL NOT NULL, "
                    "evidence_class TEXT NOT NULL, source TEXT NOT NULL, occurred_at TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE expression_attributes("
                    "name TEXT NOT NULL, relationship TEXT NOT NULL DEFAULT '', "
                    "value TEXT NOT NULL, confidence REAL NOT NULL, "
                    "evidence_count INTEGER NOT NULL, provenance TEXT NOT NULL, "
                    "updated_at TEXT NOT NULL, PRIMARY KEY(name, relationship))"
                )
                connection.execute(
                    "CREATE TABLE routine_candidates("
                    "routine_id TEXT PRIMARY KEY, pattern TEXT UNIQUE NOT NULL, "
                    "proposed_action TEXT NOT NULL, evidence_count INTEGER NOT NULL, "
                    "confidence REAL NOT NULL, scope TEXT NOT NULL, "
                    "contexts TEXT NOT NULL, last_observed TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO schema_versions(version, name, applied_at) VALUES (?, ?, ?)",
                    (1, "initial human adaptation schema", _iso(datetime.now(UTC))),
                )
            else:
                version_name = connection.execute(
                    "SELECT name FROM schema_versions WHERE version = 1"
                ).fetchone()
                if (
                    version_name is None
                    or version_name["name"] != "initial human adaptation schema"
                ):
                    raise HumanAdaptationMigrationError(
                        "Human adaptation migration identity mismatch"
                    )
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                missing = self._REQUIRED_TABLES - tables
                if missing:
                    raise HumanAdaptationMigrationError(
                        f"Human adaptation schema is incomplete: {sorted(missing)!r}"
                    )


class HumanAdaptationService:
    """Application-owned facade joining language, explicit persona, and local learning."""

    _LANGUAGE_STATE = "language_preferences"
    _PERSONALIZATION_STATE = "personalization_settings"

    def __init__(
        self,
        store: HumanAdaptationStore,
        *,
        clock: Callable[[], datetime] | None = None,
        language_catalog: LanguageCapabilityCatalog | None = None,
        minimum_evidence: int = 3,
        confidence_threshold: float = 0.75,
        cooldown: timedelta = timedelta(hours=1),
        evidence_window: timedelta = timedelta(hours=24),
    ) -> None:
        if not isinstance(store, HumanAdaptationStore):
            raise TypeError("Human adaptation service requires its authoritative store")
        if (
            type(minimum_evidence) is not int
            or minimum_evidence < 2
            or type(confidence_threshold) not in {int, float}
            or not math.isfinite(confidence_threshold)
            or not 0 < confidence_threshold <= 1
            or not isinstance(cooldown, timedelta)
            or cooldown < timedelta(0)
            or not isinstance(evidence_window, timedelta)
            or evidence_window < timedelta(0)
        ):
            raise ValueError("Adaptation bounds are malformed")
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._catalog = language_catalog or LanguageCapabilityCatalog()
        self._resolver = LanguageContextResolver()
        self._detector = DeterministicLanguageDetector()
        self._minimum_evidence = minimum_evidence
        self._confidence_threshold = confidence_threshold
        self._cooldown = cooldown
        self._evidence_window = evidence_window

    @property
    def store(self) -> HumanAdaptationStore:
        return self._store

    def language_preferences(self) -> LanguagePreferences:
        value = self._store.get_state(self._LANGUAGE_STATE)
        return (
            LanguagePreferences.from_dict(value)
            if isinstance(value, Mapping)
            else LanguagePreferences()
        )

    def set_language_preferences(
        self, preferences: LanguagePreferences | None = None, **updates: object
    ) -> LanguagePreferences:
        current = preferences or self.language_preferences()
        if updates:
            data = current.as_dict()
            data.update(updates)
            current = LanguagePreferences.from_dict(data)
        if not isinstance(current, LanguagePreferences):
            raise TypeError("Language preferences are malformed")
        self._store.set_state(self._LANGUAGE_STATE, current.as_dict())
        return current

    def detect_language(
        self,
        text: str,
        *,
        explicit: LanguageTag | None = None,
        provider_language: LanguageTag | None = None,
    ) -> LanguageDetection:
        if type(text) is not str or not text.strip() or len(text) > 4_000:
            raise ValueError("Language detection text is malformed")
        return self._detector.detect(text, explicit=explicit, provider_language=provider_language)

    def resolve_language(
        self,
        overrides: LanguageOverrides | None = None,
        *,
        detected: LanguageDetection | None = None,
    ) -> LanguageContext:
        return self._resolver.resolve(self.language_preferences(), overrides, detected=detected)

    def capability(self, language: LanguageTag | str) -> LanguageCapability:
        return self._catalog.get(language)

    def personalization_settings(self) -> dict[str, object]:
        value = self._store.get_state(self._PERSONALIZATION_STATE)
        defaults: dict[str, object] = {
            "mode": PersonalizationMode.EXPLICIT_ONLY.value,
            "adaptive_persona": AdaptivePersonaMode.FIXED.value,
            "style_fidelity": StyleFidelity.BALANCED.value,
            "routine_learning": False,
            "behavioral_learning": False,
            "observation_scope": ObservationScope.JARVIS_ONLY.value,
            "learning_paused": False,
            "adaptive_frozen": False,
        }
        if isinstance(value, Mapping):
            defaults.update(value)
        self._validate_personalization(defaults)
        return defaults

    def configure_personalization(self, **updates: object) -> dict[str, object]:
        current = self.personalization_settings()
        current.update(updates)
        self._validate_personalization(current)
        self._store.set_state(self._PERSONALIZATION_STATE, current)
        return current

    def pause_learning(self, paused: bool = True) -> dict[str, object]:
        if type(paused) is not bool:
            raise ValueError("Learning pause state is malformed")
        return self.configure_personalization(learning_paused=paused)

    def freeze_adaptive_persona(self, frozen: bool = True) -> dict[str, object]:
        if type(frozen) is not bool:
            raise ValueError("Adaptive freeze state is malformed")
        return self.configure_personalization(adaptive_frozen=frozen)

    def pin_persona_trait(self, field: str, value: int) -> tuple[str, ...]:
        _persona_field(field)
        if type(value) is not int or not 0 <= value <= 4:
            raise ValueError("Persona trait value is malformed")
        with self._store.transaction():
            pins = set(self._pins())
            pins.add(field)
            adaptive = self._adaptive_persona()
            adaptive[field] = value
            self._store.set_state("persona_pins", sorted(pins))
            self._store.set_state("adaptive_persona", adaptive)
        return tuple(sorted(pins))

    def mark_explicit_persona_update(self, updates: Mapping[str, object]) -> tuple[str, ...]:
        """Record a trusted user correction so inference can never overwrite it."""

        if not isinstance(updates, Mapping):
            raise TypeError("Explicit persona updates must be a mapping")
        for trait, value in updates.items():
            _persona_field(trait)
            if type(value) is not int or not 0 <= value <= 4:
                raise ValueError("Explicit persona value is malformed")
        typed_updates = {trait: cast(int, value) for trait, value in updates.items()}
        with self._store.transaction():
            pins = set(self._pins())
            adaptive = self._adaptive_persona()
            now = self._now()
            for trait, value in typed_updates.items():
                previous = adaptive[trait]
                adaptive[trait] = int(value)
                pins.add(trait)
                if previous != value:
                    self._store.append_history(
                        AdaptationHistoryEntry(
                            trait,
                            previous,
                            value,
                            now,
                            EvidenceClass.CORRECTION,
                            1.0,
                            AdaptationSource.USER,
                            True,
                        )
                    )
            self._store.set_state("persona_pins", sorted(pins))
            self._store.set_state("adaptive_persona", adaptive)
        return tuple(sorted(pins))

    def unpin_persona_trait(self, field: str) -> tuple[str, ...]:
        _persona_field(field)
        pins = set(self._pins())
        pins.discard(field)
        self._store.set_state("persona_pins", sorted(pins))
        return tuple(sorted(pins))

    def pinned_persona_traits(self) -> tuple[str, ...]:
        return self._pins()

    def adaptive_persona(self) -> dict[str, int]:
        return {key: int(value) for key, value in self._adaptive_persona().items()}

    def effective_persona_projection(self, explicit_profile: Mapping[str, int]) -> dict[str, int]:
        if set(explicit_profile) != set(_PERSONA_FIELDS):
            raise ValueError("Persona profile fields are incomplete")
        result = {key: int(value) for key, value in explicit_profile.items()}
        adaptive = self._adaptive_persona()
        for key, value in adaptive.items():
            if key not in self._pins():
                result[key] = int(value)
        return result

    def record_persona_evidence(
        self,
        field: str,
        target_value: int,
        *,
        confidence: float,
        evidence_class: EvidenceClass = EvidenceClass.COMMUNICATION,
        provenance: str = "bounded local feedback",
        occurred_at: datetime | None = None,
    ) -> bool:
        _persona_field(field)
        if type(target_value) is not int or not 0 <= target_value <= 4:
            raise ValueError("Persona evidence value is malformed")
        if (
            type(confidence) not in {int, float}
            or not math.isfinite(confidence)
            or not 0 <= confidence <= 1
            or not isinstance(evidence_class, EvidenceClass)
            or type(provenance) is not str
            or not provenance.strip()
        ):
            raise ValueError("Persona evidence metadata is malformed")
        settings = self.personalization_settings()
        mode = PersonalizationMode(str(settings["mode"]))
        allowed: dict[PersonalizationMode, set[EvidenceClass]] = {
            PersonalizationMode.COMMUNICATION: {
                EvidenceClass.COMMUNICATION,
                EvidenceClass.CORRECTION,
            },
            PersonalizationMode.CONTEXTUAL: {
                EvidenceClass.COMMUNICATION,
                EvidenceClass.CORRECTION,
                EvidenceClass.CONTEXTUAL,
            },
            PersonalizationMode.DEEP: set(EvidenceClass),
        }
        if (
            mode not in allowed
            or evidence_class not in allowed[mode]
            or settings["learning_paused"]
            or settings["adaptive_frozen"]
        ):
            return False
        if (
            AdaptivePersonaMode(str(settings["adaptive_persona"]))
            is not AdaptivePersonaMode.ADAPTIVE
        ):
            return False
        if field in self._pins():
            return False
        key = f"{field}:{target_value}:{evidence_class.value}"
        now = self._now(occurred_at)
        with self._store.transaction():
            counters = self._store.get_state("learning_counters")
            data = dict(counters) if isinstance(counters, Mapping) else {}
            raw_item = data.get(key)
            item = dict(raw_item) if isinstance(raw_item, Mapping) else {}
            window_started = (
                _parse_iso(item["window_started"])
                if isinstance(item.get("window_started"), str)
                else None
            )
            if (
                window_started is None
                or now < window_started
                or now - window_started >= self._evidence_window
            ):
                count = 0
                previous_confidence = 0.0
                window_started = now
            else:
                count = _bounded_counter(item.get("count", 0))
                previous_confidence = _bounded_confidence(item.get("confidence", 0.0))
            count = min(HumanAdaptationStore._MAX_COUNTER, count + 1)
            average = (previous_confidence * (count - 1) + confidence) / count
            item = {
                "count": count,
                "confidence": average,
                "last_adapted": item.get("last_adapted"),
                "window_started": _iso(window_started),
            }
            data[key] = item
            if count < self._minimum_evidence or average < self._confidence_threshold:
                self._store.set_state("learning_counters", data)
                return False
            last = _parse_iso(item["last_adapted"]) if item.get("last_adapted") else None
            if last is not None and now - last < self._cooldown:
                self._store.set_state("learning_counters", data)
                return False
            adaptive = self._adaptive_persona()
            previous = int(adaptive.get(field, 2))
            if previous == target_value:
                item["count"] = 0
                item["confidence"] = 0.0
                self._store.set_state("learning_counters", data)
                return False
            next_value = previous + (1 if target_value > previous else -1)
            adaptive[field] = next_value
            item["last_adapted"] = _iso(now)
            item["count"] = 0
            item["confidence"] = 0.0
            self._store.set_state("adaptive_persona", adaptive)
            self._store.set_state("learning_counters", data)
            self._store.append_history(
                AdaptationHistoryEntry(
                    field,
                    previous,
                    next_value,
                    now,
                    evidence_class,
                    average,
                    AdaptationSource.LOCAL_AGGREGATE,
                )
            )
            return True

    def record_expression_feedback(
        self,
        name: str,
        value: object,
        *,
        confidence: float,
        provenance: str,
        relationship: str | None = None,
        secure_input: bool = False,
    ) -> ExpressionAttribute | None:
        _bounded_key(name)
        if (
            type(confidence) not in {int, float}
            or not math.isfinite(confidence)
            or not 0 <= confidence <= 1
            or type(provenance) is not str
            or not provenance.strip()
        ):
            raise ValueError("Expression evidence is malformed")
        if type(secure_input) is not bool:
            raise ValueError("Expression secure-input metadata is malformed")
        if secure_input:
            return None
        normalized_relationship = (
            _relationship_key(relationship) if relationship is not None else None
        )
        with self._store.transaction():
            settings = self.personalization_settings()
            if (
                PersonalizationMode(str(settings["mode"]))
                in {PersonalizationMode.OFF, PersonalizationMode.EXPLICIT_ONLY}
                or settings["learning_paused"]
            ):
                return None
            existing = next(
                (
                    item
                    for item in self._store.expressions()
                    if item.name == name and item.relationship == normalized_relationship
                ),
                None,
            )
            count = min(
                HumanAdaptationStore._MAX_COUNTER, (existing.evidence_count if existing else 0) + 1
            )
            average = (
                (existing.confidence * (count - 1) if existing else 0.0) + confidence
            ) / count
            attribute = ExpressionAttribute(
                name,
                value,
                min(1.0, average),
                count,
                provenance[:256],
                self._now(),
                normalized_relationship,
            )
            self._store.upsert_expression(attribute)
            return attribute

    def expression_profile(self) -> tuple[ExpressionAttribute, ...]:
        return self._store.expressions()

    def record_behavior_event(self, event: BehavioralAggregateEvent) -> bool:
        if not isinstance(event, BehavioralAggregateEvent):
            raise ValueError("Behavioral event is malformed")
        with self._store.transaction():
            settings = self.personalization_settings()
            if (
                PersonalizationMode(str(settings["mode"])) is not PersonalizationMode.DEEP
                or not settings["behavioral_learning"]
                or settings["learning_paused"]
                or event.secure_input
                or event.scope is ObservationScope.SYSTEM_WIDE
                or settings["observation_scope"] == ObservationScope.SYSTEM_WIDE.value
            ):
                return False
            aggregates = self._store.get_state("behavior_aggregates")
            data = dict(aggregates) if isinstance(aggregates, Mapping) else {}
            bucket = data.setdefault(
                event.surface,
                {
                    "events": 0,
                    "duration_seconds": 0,
                    "corrections": 0,
                    "backspaces": 0,
                    "keystrokes": 0,
                },
            )
            for key, amount in (
                ("events", 1),
                ("duration_seconds", event.duration_seconds),
                ("corrections", event.correction_count),
                ("backspaces", event.backspace_count),
                ("keystrokes", event.keystroke_count),
            ):
                bucket[key] = min(
                    HumanAdaptationStore._MAX_COUNTER, int(bucket.get(key, 0)) + amount
                )
            self._store.set_state("behavior_aggregates", data)
            return True

    def behavioral_aggregates(self) -> dict[str, object]:
        value = self._store.get_state("behavior_aggregates")
        return dict(value) if isinstance(value, Mapping) else {}

    def observe_routine(
        self,
        pattern: str,
        proposed_action: str,
        *,
        context: str = "jarvis",
        scope: ObservationScope = ObservationScope.JARVIS_ONLY,
    ) -> RoutineCandidate | None:
        if type(pattern) is not str or type(proposed_action) is not str:
            raise ValueError("Routine observation is malformed")
        if type(context) is not str or not context.strip() or len(context) > 128:
            raise ValueError("Routine context is malformed")
        with self._store.transaction():
            settings = self.personalization_settings()
            if (
                PersonalizationMode(str(settings["mode"]))
                not in {PersonalizationMode.CONTEXTUAL, PersonalizationMode.DEEP}
                or not settings["routine_learning"]
                or settings["learning_paused"]
                or scope is ObservationScope.SYSTEM_WIDE
            ):
                return None
            state = self._store.get_state("routine_counters")
            counters = dict(state) if isinstance(state, Mapping) else {}
            raw_item = counters.get(pattern)
            item = dict(raw_item) if isinstance(raw_item, Mapping) else {}
            item["count"] = min(
                HumanAdaptationStore._MAX_COUNTER, _bounded_counter(item.get("count", 0)) + 1
            )
            contexts = [
                item for item in item.get("contexts", []) if type(item) is str and len(item) <= 128
            ]
            if context not in contexts and len(contexts) < 16:
                contexts.append(context)
            item["contexts"] = contexts
            counters[pattern] = item
            self._store.set_state("routine_counters", counters)
            if item["count"] < self._minimum_evidence:
                return None
            candidate = RoutineCandidate(
                uuid4(),
                pattern,
                proposed_action,
                item["count"],
                min(0.99, item["count"] / 10),
                scope,
                tuple(contexts),
                self._now(),
            )
            self._store.upsert_routine(candidate)
            return candidate

    def routine_candidates(self) -> tuple[RoutineCandidate, ...]:
        return self._store.routines()

    def render_style(self, semantic_content: str, *, relationship: str | None = None) -> str:
        if (
            type(semantic_content) is not str
            or not semantic_content.strip()
            or len(semantic_content) > 8_000
            or "\x00" in semantic_content
        ):
            raise ValueError("Semantic content is malformed")
        fidelity = StyleFidelity(str(self.personalization_settings()["style_fidelity"]))
        if fidelity is StyleFidelity.OFF or fidelity is StyleFidelity.LIGHT:
            return semantic_content
        relationship_key = _relationship_key(relationship or "neutral")
        greeting = {
            "friend": "Hey",
            "colleague": "Hello",
            "business": "Dear colleague",
        }.get(relationship_key, "Hello")
        if fidelity is StyleFidelity.MAXIMUM:
            return f"{greeting},\n\n{semantic_content}\n\nBest regards."
        return f"{greeting}, {semantic_content}"

    def cloud_style_projection(self, *, relationship: str | None = None) -> dict[str, str]:
        """Only bounded abstract style guidance may cross the privacy boundary."""

        relationship_key = _relationship_key(relationship) if relationship is not None else None
        attributes = {
            item.name: str(item.value)
            for item in self.expression_profile()
            if item.relationship in {None, relationship_key}
        }
        result = {
            "tone": _style_value("tone", attributes.get("tone")),
            "length": _style_value("length", attributes.get("length")),
            "directness": _style_value("directness", attributes.get("directness")),
        }
        if relationship_key is not None:
            result["relationship"] = relationship_key
        return result

    def observation_status(self) -> dict[str, str]:
        scope = ObservationScope(str(self.personalization_settings()["observation_scope"]))
        return {
            "scope": scope.value,
            "system_wide": "unavailable"
            if scope is ObservationScope.SYSTEM_WIDE
            else "not_requested",
        }

    def reset_adaptations(self) -> None:
        self._store.clear_adaptations()

    def reset_learning(self) -> None:
        self._store.clear_learning()

    def inspect(self) -> dict[str, object]:
        return {
            "language": self.language_preferences().as_dict(),
            "personalization": self.personalization_settings(),
            "adaptive_persona": self.adaptive_persona(),
            "pinned_traits": self.pinned_persona_traits(),
            "expression": tuple(
                item.__dict__
                if hasattr(item, "__dict__")
                else {
                    "name": item.name,
                    "value": item.value,
                    "confidence": item.confidence,
                    "evidence_count": item.evidence_count,
                    "provenance": item.provenance,
                    "relationship": item.relationship,
                }
                for item in self.expression_profile()
            ),
            "routines": self.routine_candidates(),
            "history": self._store.history(),
            "observation": self.observation_status(),
        }

    @staticmethod
    def _validate_personalization(value: Mapping[str, object]) -> None:
        known = {
            "mode",
            "adaptive_persona",
            "style_fidelity",
            "routine_learning",
            "behavioral_learning",
            "observation_scope",
            "learning_paused",
            "adaptive_frozen",
        }
        unknown = set(value) - known
        if unknown:
            raise ValueError("Unknown personalization setting")
        PersonalizationMode(str(value["mode"]))
        AdaptivePersonaMode(str(value["adaptive_persona"]))
        StyleFidelity(str(value["style_fidelity"]))
        ObservationScope(str(value["observation_scope"]))
        for key in (
            "routine_learning",
            "behavioral_learning",
            "learning_paused",
            "adaptive_frozen",
        ):
            if type(value[key]) is not bool:
                raise ValueError(f"Personalization setting {key} is malformed")

    def _now(self, value: datetime | None = None) -> datetime:
        current = value if value is not None else self._clock()
        if not isinstance(current, datetime) or current.tzinfo is None:
            raise ValueError("Adaptation clock must return a timezone-aware timestamp")
        return current.astimezone(UTC)

    def _pins(self) -> tuple[str, ...]:
        value = self._store.get_state("persona_pins")
        return (
            tuple(sorted(item for item in value if isinstance(item, str)))
            if isinstance(value, list)
            else ()
        )

    def _adaptive_persona(self) -> dict[str, int]:
        value = self._store.get_state("adaptive_persona")
        if not isinstance(value, Mapping):
            return {key: 2 for key in _PERSONA_FIELDS}
        return {key: max(0, min(4, int(value.get(key, 2)))) for key in _PERSONA_FIELDS}


_PERSONA_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "formality",
        "verbosity",
        "directness",
        "technical_depth",
        "humor_level",
        "initiative",
        "uncertainty_detail",
        "response_length",
    }
)

_EXPRESSION_VALUES: Final[dict[str, frozenset[str]]] = {
    "tone": frozenset({"neutral", "formal", "informal", "friendly", "professional"}),
    "length": frozenset({"short", "balanced", "long", "concise", "detailed"}),
    "directness": frozenset({"indirect", "balanced", "direct"}),
    "greeting": frozenset({"none", "brief", "warm", "formal"}),
    "closing": frozenset({"none", "brief", "warm", "formal"}),
    "punctuation": frozenset({"minimal", "standard", "expressive"}),
    "capitalization": frozenset({"lower", "sentence", "title", "upper"}),
    "abbreviations": frozenset({"none", "rare", "common"}),
    "emoji": frozenset({"none", "rare", "some", "frequent"}),
    "vocabulary": frozenset({"simple", "mixed", "technical"}),
    "sentence_length": frozenset({"short", "balanced", "long"}),
    "technical_terms": frozenset({"none", "some", "many"}),
    "channel": frozenset({"desktop", "voice", "text", "api"}),
    "relationship_style": frozenset({"neutral", "friend", "colleague", "business"}),
}

_RELATIONSHIPS: Final[frozenset[str]] = frozenset({"neutral", "friend", "colleague", "business"})


def _validate_expression_value(name: str, value: object) -> None:
    if name in _EXPRESSION_VALUES:
        if type(value) is not str or value not in _EXPRESSION_VALUES[name]:
            raise ValueError("Expression value is not a bounded aggregate")
        return
    if type(value) is bool:
        return
    if type(value) is int and 0 <= value <= 1_000_000:
        return
    if type(value) is float and math.isfinite(value) and 0 <= value <= 1_000_000:
        return
    raise ValueError("Expression value is not a bounded aggregate")


def _style_value(name: str, value: str | None) -> str:
    allowed = _EXPRESSION_VALUES[name]
    return value if value in allowed else ("neutral" if name == "tone" else "balanced")


def _relationship_key(value: str) -> str:
    if type(value) is not str:
        raise ValueError("Relationship is malformed")
    normalized = value.casefold().strip()
    if normalized not in _RELATIONSHIPS:
        raise ValueError("Relationship is not an allowed bounded category")
    return normalized


def _persona_field(value: str) -> None:
    if type(value) is not str or value not in _PERSONA_FIELDS:
        raise ValueError("Unknown persona trait")


def _bounded_counter(value: object) -> int:
    if type(value) is not int or not 0 <= value <= HumanAdaptationStore._MAX_COUNTER:
        return 0
    return value


def _bounded_confidence(value: object) -> float:
    if type(value) is int:
        return float(value) if 0 <= value <= 1 else 0.0
    if type(value) is float:
        return value if math.isfinite(value) and 0 <= value <= 1 else 0.0
    return 0.0


def _bounded_key(value: str, *, limit: int = 128) -> None:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_.:-]{1," + str(limit) + r"}", value):
        raise ValueError("Bounded adaptation key is malformed")


def _json_value(value: object, *, depth: int = 0) -> object:
    if depth > 5 or value is None or isinstance(value, bool | int | str):
        if isinstance(value, str) and (
            len(value) > 512 or "\x00" in value or "transcript" in value.casefold()
        ):
            raise ValueError("Personal adaptation value is raw or oversized")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Personal adaptation value is non-finite")
        return value
    if isinstance(value, Mapping):
        if len(value) > 32:
            raise ValueError("Personal adaptation object is too large")
        return {str(key): _json_value(child, depth=depth + 1) for key, child in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        if len(value) > 32:
            raise ValueError("Personal adaptation array is too large")
        return [_json_value(child, depth=depth + 1) for child in value]
    raise ValueError("Personal adaptation value must be JSON data")


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("Timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat()


def _parse_iso(value: str | None) -> datetime:
    if not value:
        raise ValueError("Timestamp is missing")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def language_capability(language: LanguageTag | str) -> str:
    return LanguageCapabilityCatalog().get(language).routing_capability


__all__ = [
    "AdaptationHistoryEntry",
    "AdaptationSource",
    "AdaptivePersonaMode",
    "BehavioralAggregateEvent",
    "ConversationLanguageMode",
    "DeterministicLanguageDetector",
    "EvidenceClass",
    "ExpressionAttribute",
    "HumanAdaptationError",
    "HumanAdaptationMigrationError",
    "HumanAdaptationService",
    "HumanAdaptationStore",
    "LanguageCapability",
    "LanguageCapabilityCatalog",
    "LanguageContext",
    "LanguageContextResolver",
    "LanguageDetection",
    "LanguageDetectionProvenance",
    "LanguageOverrides",
    "LanguagePreferences",
    "LanguageResolutionSource",
    "LanguageSupportState",
    "LanguageTag",
    "Localizer",
    "LocalizedApprovalPresentation",
    "LocalizedCapabilityPresentation",
    "ObservationScope",
    "PersonalizationMode",
    "ResolvedLanguage",
    "RoutineCandidate",
    "StyleFidelity",
    "VoiceLanguageCapability",
    "VoiceLanguageCatalog",
    "language_capability",
    "localize_capability_metadata",
    "load_default_localizer",
    "localize_approval_request",
    "normalize_language_tag",
    "normalize_locale",
]
