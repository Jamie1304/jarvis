"""Generic dynamic control-center projections and trusted presentation profiles.

The control center is a read-only application projection.  It discovers current
metadata from explicitly registered application services; it does not execute a
tool, grant permission, activate a package, or become a domain store.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from jarvis.permissions.models import (
    ActionDescriptor,
    ApprovalRequest,
    Permission,
    PermissionRequest,
    validate_safe_display_text,
)
from jarvis.permissions.presentation import (
    ExactOperationRenderer,
    TrustedActionNarrator,
    TrustedPermissionPresentation,
)


class ControlCenterError(RuntimeError):
    """A control-center projection could not be used safely."""


class ControlCenterValidationError(ControlCenterError, ValueError):
    """Control-center metadata or registration is malformed."""


class OutputMedium(StrEnum):
    DESKTOP = "desktop"
    VOICE = "voice"
    NOTIFICATION = "notification"
    PRESENTATION = "presentation"
    COMPACT = "compact"


@dataclass(frozen=True, slots=True)
class OutputMediumProfile:
    """Presentation preferences that cannot change facts or authority."""

    medium: OutputMedium
    natural_short_sentences: bool = False
    allow_markdown: bool = True
    allow_tables: bool = True
    speakable_urls_numbers: bool = False
    max_length: int = 16_000

    def __post_init__(self) -> None:
        if not isinstance(self.medium, OutputMedium):
            raise ControlCenterValidationError("Output medium is malformed")
        if any(
            type(value) is not bool
            for value in (
                self.natural_short_sentences,
                self.allow_markdown,
                self.allow_tables,
                self.speakable_urls_numbers,
            )
        ):
            raise ControlCenterValidationError("Output medium flags are malformed")
        if type(self.max_length) is not int or not 1 <= self.max_length <= 64_000:
            raise ControlCenterValidationError("Output medium length is malformed")

    @classmethod
    def for_medium(cls, medium: OutputMedium) -> OutputMediumProfile:
        if not isinstance(medium, OutputMedium):
            raise ControlCenterValidationError("Output medium is malformed")
        if medium is OutputMedium.VOICE:
            return cls(medium, True, False, False, True, 8_000)
        if medium is OutputMedium.NOTIFICATION:
            return cls(medium, True, False, False, True, 1_000)
        if medium is OutputMedium.PRESENTATION:
            return cls(medium, False, True, True, False, 32_000)
        if medium is OutputMedium.COMPACT:
            return cls(medium, True, False, False, False, 4_000)
        return cls(medium)

    def format(self, text: str) -> str:
        """Format display text only; this never creates trusted metadata."""

        if type(text) is not str or "\x00" in text or len(text) > self.max_length:
            raise ControlCenterValidationError(
                "Output text is malformed or exceeds the medium bound"
            )
        formatted = text
        if not self.allow_markdown:
            formatted = re.sub(r"```(?:[A-Za-z0-9_.+-]+)?\s*|[`*_#]", "", formatted)
            formatted = re.sub(r"^\s*[-•]\s+", "", formatted, flags=re.MULTILINE)
        if self.natural_short_sentences:
            formatted = " ".join(formatted.split())
        if self.speakable_urls_numbers:
            formatted = re.sub(
                r"https?://[^\s]+",
                lambda match: _speakable_url(match.group(0)),
                formatted,
            )
        return formatted.strip() if self.natural_short_sentences else formatted


class OutputMediumProfileRegistry:
    """Replaceable channel profiles; selection does not alter runtime policy."""

    def __init__(self, profiles: Iterable[OutputMediumProfile] = ()) -> None:
        self._profiles: dict[OutputMedium, OutputMediumProfile] = {
            medium: OutputMediumProfile.for_medium(medium) for medium in OutputMedium
        }
        for profile in profiles:
            self.register(profile)

    def register(self, profile: OutputMediumProfile) -> None:
        if not isinstance(profile, OutputMediumProfile):
            raise ControlCenterValidationError("Output medium profile is malformed")
        self._profiles[profile.medium] = profile

    def get(self, medium: OutputMedium) -> OutputMediumProfile:
        if not isinstance(medium, OutputMedium):
            raise ControlCenterValidationError("Output medium is malformed")
        return self._profiles[medium]

    def profiles(self) -> tuple[OutputMediumProfile, ...]:
        return tuple(self._profiles[medium] for medium in OutputMedium)


class ControlCenterSection(StrEnum):
    SYSTEM = "system"
    CAPABILITIES = "capabilities"
    INTEGRATIONS = "integrations"
    TOOLS = "tools"
    SKILLS = "skills"
    AGENTS = "agents"
    MODELS = "models"
    PERMISSIONS = "permissions"
    MEMORY = "memory"
    KNOWLEDGE = "knowledge"
    GOALS = "goals"
    AUTOMATIONS = "automations"
    AUDIT = "audit"
    HEALTH = "health"
    RECOVERY = "recovery"


class ControlCenterStatus(StrEnum):
    AVAILABLE = "available"
    DEGRADED = "degraded"
    NOT_AVAILABLE = "not_available"


def _text(value: object, name: str, limit: int, *, allow_empty: bool = False) -> str:
    try:
        return validate_safe_display_text(
            value,
            field=name,
            max_length=limit,
            allow_empty=allow_empty,
        )
    except ValueError as error:
        raise ControlCenterValidationError(str(error)) from error


def _id(value: object, name: str) -> str:
    value = _text(value, name, 128)
    if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in value):
        raise ControlCenterValidationError(f"{name} is malformed")
    return value


@dataclass(frozen=True, slots=True)
class SemanticActionMetadata:
    """Trusted semantic action metadata, not a hard-coded voice command tree."""

    action_id: str
    label: str
    description: str
    application_operation: str
    required_permissions: tuple[Permission, ...] = ()
    parameters: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _id(self.action_id, "Semantic action ID")
        _text(self.label, "Semantic action label", 128)
        _text(self.description, "Semantic action description", 1_000)
        _id(self.application_operation, "Application operation")
        if any(not isinstance(permission, Permission) for permission in self.required_permissions):
            raise ControlCenterValidationError("Semantic action permissions are malformed")
        if len(self.parameters) > 32 or len(set(self.parameters)) != len(self.parameters):
            raise ControlCenterValidationError("Semantic action parameters are malformed")
        for parameter in self.parameters:
            _id(parameter, "Semantic action parameter")


@dataclass(frozen=True, slots=True)
class ControlCenterItem:
    item_id: str
    label: str
    status: ControlCenterStatus
    detail: str = ""
    actions: tuple[SemanticActionMetadata, ...] = ()
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _id(self.item_id, "Control-center item ID")
        _text(self.label, "Control-center item label", 256)
        if not isinstance(self.status, ControlCenterStatus):
            raise ControlCenterValidationError("Control-center item status is malformed")
        _text(self.detail, "Control-center item detail", 2_048, allow_empty=True)
        if any(not isinstance(action, SemanticActionMetadata) for action in self.actions):
            raise ControlCenterValidationError("Control-center actions are malformed")
        if len(self.metadata) > 64 or len({key for key, _ in self.metadata}) != len(self.metadata):
            raise ControlCenterValidationError("Control-center metadata is malformed")
        for key, value in self.metadata:
            _id(key, "Control-center metadata key")
            _text(value, "Control-center metadata value", 1_000, allow_empty=True)


@dataclass(frozen=True, slots=True)
class ControlCenterContribution:
    status: ControlCenterStatus
    items: tuple[ControlCenterItem, ...] = ()
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.status, ControlCenterStatus):
            raise ControlCenterValidationError("Control-center contribution status is malformed")
        if any(not isinstance(item, ControlCenterItem) for item in self.items):
            raise ControlCenterValidationError("Control-center contribution items are malformed")
        if len({item.item_id for item in self.items}) != len(self.items):
            raise ControlCenterValidationError("Control-center contribution IDs are not unique")
        _text(self.detail, "Control-center contribution detail", 2_048, allow_empty=True)


@dataclass(frozen=True, slots=True)
class ControlCenterSectionView:
    section: ControlCenterSection
    status: ControlCenterStatus
    items: tuple[ControlCenterItem, ...]
    detail: str


@dataclass(frozen=True, slots=True)
class ControlCenterSnapshot:
    revision: int
    refreshed_at: datetime
    sections: tuple[ControlCenterSectionView, ...]

    def __post_init__(self) -> None:
        if type(self.revision) is not int or self.revision < 0:
            raise ControlCenterValidationError("Control-center revision is malformed")
        if self.refreshed_at.tzinfo is None:
            raise ControlCenterValidationError("Control-center timestamp must be timezone-aware")
        if tuple(view.section for view in self.sections) != tuple(ControlCenterSection):
            raise ControlCenterValidationError("Control-center sections are incomplete")

    def section(self, section: ControlCenterSection) -> ControlCenterSectionView:
        if not isinstance(section, ControlCenterSection):
            raise ControlCenterValidationError("Control-center section is malformed")
        return self.sections[tuple(ControlCenterSection).index(section)]


ControlCenterProviderResult = ControlCenterContribution | Iterable[ControlCenterItem]
ControlCenterProvider = Callable[
    [], ControlCenterProviderResult | Awaitable[ControlCenterProviderResult]
]


class ControlCenterService:
    """Refreshable, read-only projection of explicitly registered services."""

    def __init__(self) -> None:
        self._providers: dict[ControlCenterSection, dict[str, ControlCenterProvider]] = {
            section: {} for section in ControlCenterSection
        }
        self._views: dict[ControlCenterSection, ControlCenterSectionView] = {
            section: ControlCenterSectionView(
                section, ControlCenterStatus.NOT_AVAILABLE, (), "No service is registered"
            )
            for section in ControlCenterSection
        }
        self._revision = 0

    def register(
        self,
        section: ControlCenterSection,
        source_id: str,
        provider: ControlCenterProvider,
    ) -> None:
        if not isinstance(section, ControlCenterSection) or not callable(provider):
            raise ControlCenterValidationError("Control-center source is malformed")
        source_id = _id(source_id, "Control-center source ID")
        if source_id in self._providers[section]:
            raise ControlCenterError("Control-center source is already registered")
        self._providers[section][source_id] = provider

    def unregister(self, section: ControlCenterSection, source_id: str) -> None:
        if not isinstance(section, ControlCenterSection):
            raise ControlCenterValidationError("Control-center section is malformed")
        self._providers[section].pop(_id(source_id, "Control-center source ID"), None)

    def sources(self, section: ControlCenterSection) -> tuple[str, ...]:
        if not isinstance(section, ControlCenterSection):
            raise ControlCenterValidationError("Control-center section is malformed")
        return tuple(sorted(self._providers[section]))

    def snapshot(self) -> ControlCenterSnapshot:
        return ControlCenterSnapshot(
            self._revision,
            datetime.now(UTC),
            tuple(self._views[section] for section in ControlCenterSection),
        )

    async def refresh(self, section: ControlCenterSection | None = None) -> ControlCenterSnapshot:
        if section is None:
            sections: tuple[ControlCenterSection, ...] = tuple(ControlCenterSection)
        else:
            if not isinstance(section, ControlCenterSection):
                raise ControlCenterValidationError("Control-center section is malformed")
            sections = (section,)
        for current in sections:
            self._views[current] = await self._refresh_section(current)
        self._revision += 1
        return self.snapshot()

    async def _refresh_section(self, section: ControlCenterSection) -> ControlCenterSectionView:
        providers = self._providers[section]
        if not providers:
            return ControlCenterSectionView(
                section, ControlCenterStatus.NOT_AVAILABLE, (), "No service is registered"
            )
        items: list[ControlCenterItem] = []
        failures = 0
        unavailable = 0
        for source_id in sorted(providers):
            try:
                result = providers[source_id]()
                if inspect.isawaitable(result):
                    result = await result
                contribution = (
                    result
                    if isinstance(result, ControlCenterContribution)
                    else ControlCenterContribution(
                        ControlCenterStatus.AVAILABLE, tuple(result), "available"
                    )
                )
                items.extend(contribution.items)
                if contribution.status is ControlCenterStatus.DEGRADED:
                    failures += 1
                elif contribution.status is ControlCenterStatus.NOT_AVAILABLE:
                    unavailable += 1
            except Exception:
                failures += 1
        if len({item.item_id for item in items}) != len(items):
            return ControlCenterSectionView(
                section,
                ControlCenterStatus.DEGRADED,
                (),
                "A projection source returned duplicate IDs",
            )
        status = (
            ControlCenterStatus.DEGRADED
            if failures
            else (
                ControlCenterStatus.NOT_AVAILABLE
                if unavailable == len(providers)
                else ControlCenterStatus.AVAILABLE
            )
        )
        return ControlCenterSectionView(
            section,
            status,
            tuple(sorted(items, key=lambda item: item.item_id)),
            (
                "One or more projection sources failed"
                if failures
                else ("No service is available" if unavailable else "available")
            ),
        )

    async def aclose(self) -> None:
        """Application-owned lifecycle hook; projections own no external resources."""


@dataclass(frozen=True, slots=True)
class TrustedPermissionPrompt:
    """Desktop and voice views derived from one immutable trusted presentation."""

    presentation: TrustedPermissionPresentation
    desktop_short: str
    desktop_impact: str
    desktop_scope: str
    desktop_details: str
    desktop_choices: tuple[str, str] = ("Allow once", "Deny")
    voice_prompt: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.presentation, TrustedPermissionPresentation):
            raise ControlCenterValidationError("Permission prompt presentation is malformed")
        for value, name in (
            (self.desktop_short, "Desktop permission narration"),
            (self.desktop_impact, "Desktop permission impact"),
            (self.desktop_scope, "Desktop permission scope"),
            (self.desktop_details, "Desktop permission details"),
            (self.voice_prompt, "Voice permission prompt"),
        ):
            _text(value, name, 16_000)
        if self.desktop_choices != ("Allow once", "Deny"):
            raise ControlCenterValidationError("Desktop permission choices are malformed")


class TrustedPermissionSurface:
    """Render trusted permission requests for local desktop and voice channels."""

    def __init__(
        self,
        narrator: TrustedActionNarrator | None = None,
        renderer: ExactOperationRenderer | None = None,
    ) -> None:
        self._narrator = narrator or TrustedActionNarrator()
        self._renderer = renderer or ExactOperationRenderer()

    def present(
        self,
        request: ApprovalRequest | PermissionRequest,
        operation: ActionDescriptor | None = None,
    ) -> TrustedPermissionPrompt:
        presentation = self._narrator.narrate(request, operation)
        return TrustedPermissionPrompt(
            presentation=presentation,
            desktop_short=self._renderer.render_short(presentation),
            desktop_impact=presentation.effect,
            desktop_scope=presentation.scope,
            desktop_details=self._renderer.render(presentation),
            voice_prompt=self._renderer.render_voice(presentation),
        )


def _speakable_url(value: str) -> str:
    suffix = "".join(" dot " if character == "." else character for character in value)
    return suffix.replace("https://", "https colon slash slash ").replace(
        "http://", "http colon slash slash "
    )


def unavailable_item(item_id: str, label: str, detail: str) -> ControlCenterItem:
    """Create explicit unavailable metadata for an optional service."""

    return ControlCenterItem(item_id, label, ControlCenterStatus.NOT_AVAILABLE, detail)


def static_provider(
    items: Iterable[ControlCenterItem],
) -> Callable[[], ControlCenterContribution]:
    """Adapt a trusted static projection to the refresh registry."""

    captured = tuple(items)

    def provide() -> ControlCenterContribution:
        return ControlCenterContribution(ControlCenterStatus.AVAILABLE, captured, "available")

    return provide
