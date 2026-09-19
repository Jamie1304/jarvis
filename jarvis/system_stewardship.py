"""Provider-neutral, read-only system stewardship health contracts.

The services in this module observe trusted provider boundaries and produce
typed plans.  They do not execute lifecycle, security, startup, or update
effects.  Effectful work remains owned by the existing application,
PermissionBroker, HostBridge, acquisition, and provisioning paths.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol

from jarvis.applications.manager import ApplicationManager
from jarvis.applications.models import (
    ApplicationHealthEvidence,
    ApplicationRecord,
    ApplicationStatus,
    InstallationCandidate,
    InstallationPlan,
)
from jarvis.applications.plans import InstallationPlanStore
from jarvis.applications.providers import (
    PackageProvider,
    WindowsRegistryInventoryProvider,
    WingetPackageProvider,
)
from jarvis.applications.runtime import WindowsApplicationRuntime
from jarvis.security.startup import (
    IntegrityEvidenceError,
    IntegrityEvidenceProvider,
    SourceCheckoutIntegrityEvidenceProvider,
)


class StewardshipError(ValueError):
    """A health observation or typed plan is malformed."""


class StaleStewardshipPlan(StewardshipError):
    """A plan no longer describes the current provider observation."""


class HealthState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    BROKEN = "broken"
    UPDATE_AVAILABLE = "update_available"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


class SecurityFindingState(StrEnum):
    HEALTHY = "healthy"
    THREAT_DETECTED = "threat_detected"
    INTEGRITY_FAILURE = "integrity_failure"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


class StartupEntryState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    BROKEN = "broken"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


class StartupEffectStatus(StrEnum):
    """Status of the separate startup mutation authority."""

    NOT_YET_TRUSTED = "STARTUP_EFFECT_PROVIDER_NOT_YET_TRUSTED"


class UpdateStage(StrEnum):
    DISCOVER = "discover"
    DOWNLOAD = "download"
    VERIFY = "verify"
    APPROVE = "approve"
    INSTALL = "install"
    VERIFY_RESULT = "verify_result"
    ROLLBACK = "rollback"
    UNKNOWN_OUTCOME = "unknown_outcome"


_MODEL_SOURCES: Final = frozenset({"model", "llm", "assistant", "chat", "ai"})


def _text(value: object, label: str, limit: int = 512) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > limit
        or any(ord(character) < 32 for character in value)
    ):
        raise StewardshipError(f"{label} is malformed")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise StewardshipError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _fingerprint(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class SecurityFinding:
    """Provider evidence with provenance; it is never a model judgement."""

    provider: str
    target: str
    observed_at: datetime
    state: SecurityFindingState
    result_id: str
    detail: str
    evidence_ref: str
    confidence: float | None = None

    def __post_init__(self) -> None:
        provider = _text(self.provider, "Security provider", 128).casefold()
        if provider in _MODEL_SOURCES:
            raise StewardshipError("Model-only security claims are not trusted evidence")
        _text(self.target, "Security target", 1_024)
        _timestamp(self.observed_at, "Security observation time")
        if not isinstance(self.state, SecurityFindingState):
            raise StewardshipError("Security finding state is malformed")
        _text(self.result_id, "Security result identity", 256)
        _text(self.detail, "Security finding detail", 2_048)
        _text(self.evidence_ref, "Security evidence reference", 1_024)
        if self.confidence is not None and (
            type(self.confidence) not in {int, float} or not 0 <= self.confidence <= 1
        ):
            raise StewardshipError("Security confidence is malformed")

    def is_stale(self, *, now: datetime, max_age: timedelta) -> bool:
        checked = _timestamp(now, "Security check time")
        if max_age <= timedelta(0):
            raise StewardshipError("Security evidence age bound is invalid")
        return checked - _timestamp(self.observed_at, "Security observation time") > max_age


class SecurityProvider(Protocol):
    async def observe(self) -> tuple[SecurityFinding, ...]:
        """Return findings produced by a trusted machine/provider boundary."""


class TrustedSecurityProvider(Protocol):
    """Explicit application-owned security provider registration boundary."""

    provider_id: str

    async def observe(self) -> tuple[SecurityFinding, ...]:
        """Return evidence from this explicitly composed provider."""


@dataclass(frozen=True, slots=True)
class SecurityHealthReport:
    findings: tuple[SecurityFinding, ...]
    overall: SecurityFindingState


class SecurityHealthService:
    """Observe security providers without making security claims itself."""

    def __init__(self, provider: SecurityProvider, *, clock: Callable[[], datetime] | None = None):
        self._provider = provider
        self._clock = clock or (lambda: datetime.now(UTC))

    async def observe(self) -> SecurityHealthReport:
        try:
            findings = await self._provider.observe()
            if not isinstance(findings, tuple) or any(
                not isinstance(item, SecurityFinding) for item in findings
            ):
                raise StewardshipError("Security provider returned malformed evidence")
            overall = self._overall(findings)
            return SecurityHealthReport(findings, overall)
        except Exception as error:
            finding = SecurityFinding(
                "security-provider",
                "host-security",
                self._clock(),
                SecurityFindingState.UNAVAILABLE,
                "provider-unavailable",
                f"security provider unavailable: {type(error).__name__}",
                "provider-status",
            )
            return SecurityHealthReport((finding,), SecurityFindingState.UNAVAILABLE)

    @staticmethod
    def _overall(findings: tuple[SecurityFinding, ...]) -> SecurityFindingState:
        if not findings:
            return SecurityFindingState.UNKNOWN
        if any(item.state is SecurityFindingState.THREAT_DETECTED for item in findings):
            return SecurityFindingState.THREAT_DETECTED
        if any(item.state is SecurityFindingState.INTEGRITY_FAILURE for item in findings):
            return SecurityFindingState.INTEGRITY_FAILURE
        if any(item.state is SecurityFindingState.UNAVAILABLE for item in findings):
            return SecurityFindingState.UNAVAILABLE
        if any(item.state is SecurityFindingState.UNKNOWN for item in findings):
            return SecurityFindingState.UNKNOWN
        return SecurityFindingState.HEALTHY


class IntegritySecurityProvider:
    """Project the existing trusted JARVIS integrity authority into health evidence."""

    provider_id = "jarvis-integrity"

    def __init__(
        self,
        integrity_evidence: IntegrityEvidenceProvider,
        *,
        target: str = "jarvis-distribution-integrity",
    ) -> None:
        if not isinstance(integrity_evidence, IntegrityEvidenceProvider):
            raise StewardshipError("Integrity security provider is not trusted")
        self._integrity_evidence = integrity_evidence
        self._target = _text(target, "Integrity security target", 256)

    async def observe(self) -> tuple[SecurityFinding, ...]:
        observed_at = datetime.now(UTC)
        try:
            await asyncio.to_thread(self._integrity_evidence.validate)
        except IntegrityEvidenceError:
            return (
                SecurityFinding(
                    self.provider_id,
                    self._target,
                    observed_at,
                    SecurityFindingState.INTEGRITY_FAILURE,
                    "jarvis-integrity-failed",
                    "trusted JARVIS integrity validation failed",
                    "trusted-integrity-validator",
                ),
            )
        except Exception as error:
            return (
                SecurityFinding(
                    self.provider_id,
                    self._target,
                    observed_at,
                    SecurityFindingState.UNAVAILABLE,
                    "jarvis-integrity-unavailable",
                    f"trusted JARVIS integrity provider unavailable: {type(error).__name__}",
                    "trusted-integrity-validator",
                ),
            )
        return (
            SecurityFinding(
                self.provider_id,
                self._target,
                observed_at,
                SecurityFindingState.HEALTHY,
                "jarvis-integrity-verified",
                "trusted JARVIS distribution integrity validation passed",
                "trusted-integrity-validator",
            ),
        )


class UnavailableSecurityProvider:
    """Explicitly preserve a security domain for which no trusted provider exists."""

    def __init__(self, provider_id: str, *, target: str) -> None:
        self.provider_id = _text(provider_id, "Unavailable security provider", 128)
        self._target = _text(target, "Unavailable security target", 256)

    async def observe(self) -> tuple[SecurityFinding, ...]:
        return (
            SecurityFinding(
                self.provider_id,
                self._target,
                datetime.now(UTC),
                SecurityFindingState.UNAVAILABLE,
                f"{self.provider_id}-unavailable",
                "no trusted provider is composed for this security domain",
                "provider-status",
            ),
        )


class TrustedSecurityProviderRegistry:
    """Aggregate only explicit trusted provider instances without hiding failures."""

    def __init__(self, providers: tuple[TrustedSecurityProvider, ...]) -> None:
        if not isinstance(providers, tuple) or not providers:
            raise StewardshipError("Trusted security provider registry is empty")
        identifiers: set[str] = set()
        for provider in providers:
            identifier = getattr(provider, "provider_id", None)
            if type(identifier) is not str or not identifier.strip():
                raise StewardshipError("Trusted security provider identity is malformed")
            if identifier.casefold() in _MODEL_SOURCES:
                raise StewardshipError("Model-only security providers are not trusted")
            if identifier.casefold() in identifiers:
                raise StewardshipError("Trusted security provider identity is duplicated")
            identifiers.add(identifier.casefold())
        self._providers = providers

    async def observe(self) -> tuple[SecurityFinding, ...]:
        findings: list[SecurityFinding] = []
        for provider in self._providers:
            try:
                result = await provider.observe()
                if not isinstance(result, tuple) or any(
                    not isinstance(item, SecurityFinding) for item in result
                ):
                    raise StewardshipError("Trusted security provider returned malformed evidence")
                findings.extend(result)
            except Exception as error:
                findings.append(
                    SecurityFinding(
                        provider.provider_id,
                        "security-provider",
                        datetime.now(UTC),
                        SecurityFindingState.UNAVAILABLE,
                        f"{provider.provider_id}-unavailable",
                        f"security provider unavailable: {type(error).__name__}",
                        "provider-status",
                    )
                )
        return tuple(findings)


@dataclass(frozen=True, slots=True)
class StartupEntryEvidence:
    entry_id: str
    owner: str | None
    provider: str
    enabled: bool
    target_command: str | None
    target_exists: bool | None
    observed_at: datetime
    state: StartupEntryState
    detail: str

    def __post_init__(self) -> None:
        _text(self.entry_id, "Startup entry identity", 256)
        if self.owner is not None:
            _text(self.owner, "Startup owner", 256)
        _text(self.provider, "Startup provider", 128)
        if type(self.enabled) is not bool:
            raise StewardshipError("Startup enabled state is malformed")
        if self.target_command is not None:
            _text(self.target_command, "Startup target", 2_048)
        if self.target_exists is not None and type(self.target_exists) is not bool:
            raise StewardshipError("Startup target state is malformed")
        _timestamp(self.observed_at, "Startup observation time")
        if not isinstance(self.state, StartupEntryState):
            raise StewardshipError("Startup entry state is malformed")
        _text(self.detail, "Startup evidence detail", 2_048)


class StartupProvider(Protocol):
    async def observe(self) -> tuple[StartupEntryEvidence, ...]:
        """Return bounded startup inventory evidence."""


class StartupProviderError(RuntimeError):
    """A bounded startup source could not produce safe evidence."""


class WindowsStartupProvider:
    """Read the finite documented Windows Run/RunOnce registry source set."""

    provider_id = "windows-startup-registry"
    TRUSTED_REGISTRY_SOURCES: Final = (
        ("current-user", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("current-user", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("machine", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("machine", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    )

    async def observe(self) -> tuple[StartupEntryEvidence, ...]:
        if sys.platform != "win32":
            raise StartupProviderError("Windows startup provider is unavailable on this host")
        return await asyncio.to_thread(self._observe_registry)

    @classmethod
    def _observe_registry(cls) -> tuple[StartupEntryEvidence, ...]:
        import winreg

        entries: list[StartupEntryEvidence] = []
        identities: set[str] = set()
        for scope, key_path in cls.TRUSTED_REGISTRY_SOURCES:
            hive = (
                winreg.HKEY_CURRENT_USER if scope == "current-user" else winreg.HKEY_LOCAL_MACHINE
            )
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise StartupProviderError(
                    "Windows startup registry source is unavailable"
                ) from error
            with key:
                index = 0
                while True:
                    try:
                        name, command, value_type = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    if (
                        type(name) is not str
                        or not name.strip()
                        or type(command) is not str
                        or not command.strip()
                        or value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ)
                    ):
                        raise StartupProviderError("Windows startup registry evidence is malformed")
                    entry_id = cls.entry_id(scope, key_path, name)
                    if entry_id in identities:
                        raise StartupProviderError("Windows startup entry identity is ambiguous")
                    identities.add(entry_id)
                    entries.append(
                        StartupEntryEvidence(
                            entry_id,
                            name,
                            cls.provider_id,
                            True,
                            command,
                            None,
                            datetime.now(UTC),
                            StartupEntryState.HEALTHY,
                            "read-only Windows startup registry observation",
                        )
                    )
        return tuple(sorted(entries, key=lambda item: item.entry_id))

    @staticmethod
    def entry_id(scope: str, key_path: str, value_name: str) -> str:
        _text(scope, "Windows startup scope", 64)
        _text(key_path, "Windows startup source", 256)
        _text(value_name, "Windows startup entry name", 256)
        digest = _fingerprint((scope, key_path.casefold(), value_name.casefold()))[:32]
        return f"startup:windows-registry:{scope}:{digest}"


@dataclass(frozen=True, slots=True)
class StartupHealthReport:
    entries: tuple[StartupEntryEvidence, ...]
    overall: HealthState


@dataclass(frozen=True, slots=True)
class StartupMutationPlan:
    """Exact reversible intent; applying it remains an external authority step."""

    entry_id: str
    provider: str
    previous_enabled: bool
    new_enabled: bool
    target_command: str | None
    planned_at: datetime
    expires_at: datetime
    fingerprint: str

    def __post_init__(self) -> None:
        _text(self.entry_id, "Startup plan entry identity", 256)
        if "*" in self.entry_id:
            raise StewardshipError("Wildcard startup plans are forbidden")
        _text(self.provider, "Startup plan provider", 128)
        if type(self.previous_enabled) is not bool or type(self.new_enabled) is not bool:
            raise StewardshipError("Startup plan state is malformed")
        if self.target_command is not None:
            _text(self.target_command, "Startup plan target", 2_048)
        planned = _timestamp(self.planned_at, "Startup plan time")
        expires = _timestamp(self.expires_at, "Startup plan expiry")
        if expires <= planned:
            raise StewardshipError("Startup plan expiry is invalid")
        if len(self.fingerprint) != 64 or any(
            c not in "0123456789abcdef" for c in self.fingerprint
        ):
            raise StewardshipError("Startup plan fingerprint is malformed")


class StartupHealthService:
    def __init__(self, provider: StartupProvider, *, clock: Callable[[], datetime] | None = None):
        self._provider = provider
        self._clock = clock or (lambda: datetime.now(UTC))

    async def observe(self) -> StartupHealthReport:
        try:
            entries = await self._provider.observe()
            if not isinstance(entries, tuple) or any(
                not isinstance(item, StartupEntryEvidence) for item in entries
            ):
                raise StewardshipError("Startup provider returned malformed evidence")
            overall = HealthState.HEALTHY
            if any(item.state is StartupEntryState.BROKEN for item in entries):
                overall = HealthState.BROKEN
            elif any(item.state is StartupEntryState.DEGRADED for item in entries):
                overall = HealthState.DEGRADED
            elif any(item.state is StartupEntryState.UNKNOWN for item in entries):
                overall = HealthState.UNKNOWN
            return StartupHealthReport(entries, overall)
        except Exception:
            return StartupHealthReport((), HealthState.UNAVAILABLE)

    async def plan_set_enabled(
        self, entry_id: str, enabled: bool, *, ttl: timedelta = timedelta(minutes=5)
    ) -> StartupMutationPlan:
        _text(entry_id, "Startup entry identity", 256)
        if "*" in entry_id:
            raise StewardshipError("Wildcard startup plans are forbidden")
        if type(enabled) is not bool or ttl <= timedelta(0):
            raise StewardshipError("Startup mutation request is malformed")
        report = await self.observe()
        matches = tuple(item for item in report.entries if item.entry_id == entry_id)
        if len(matches) != 1:
            raise StaleStewardshipPlan("Startup entry is missing or ambiguous")
        item = matches[0]
        planned = _timestamp(self._clock(), "Startup plan time")
        payload = (item.entry_id, item.provider, item.enabled, enabled, item.target_command)
        return StartupMutationPlan(
            item.entry_id,
            item.provider,
            item.enabled,
            enabled,
            item.target_command,
            planned,
            planned + ttl,
            _fingerprint(payload),
        )

    async def revalidate(self, plan: StartupMutationPlan) -> StartupEntryEvidence:
        report = await self.observe()
        matches = tuple(item for item in report.entries if item.entry_id == plan.entry_id)
        if len(matches) != 1:
            raise StaleStewardshipPlan("Startup plan target no longer exists uniquely")
        current = matches[0]
        if (
            current.provider != plan.provider
            or current.enabled != plan.previous_enabled
            or current.target_command != plan.target_command
        ):
            raise StaleStewardshipPlan("Startup entry changed after planning")
        return current

    @staticmethod
    def assert_receipt(plan: StartupMutationPlan, receipt_fingerprint: str) -> None:
        if receipt_fingerprint != plan.fingerprint:
            raise StewardshipError("Startup receipt does not match the exact plan")


@dataclass(frozen=True, slots=True)
class SoftwareHealthReport:
    applications: tuple[ApplicationHealthEvidence, ...]


class SoftwareHealthService:
    def __init__(self, manager: ApplicationManager) -> None:
        self._manager = manager

    async def observe(self) -> SoftwareHealthReport:
        return SoftwareHealthReport(await self._manager.health())


@dataclass(frozen=True, slots=True)
class UpdateEvidence:
    application_id: str
    application_name: str
    current_version: str
    candidate_version: str | None
    provider: str
    source: str | None
    state: HealthState
    detail: str
    observed_at: datetime
    candidate: InstallationCandidate | None = None

    def __post_init__(self) -> None:
        _text(self.application_id, "Update application identity", 256)
        _text(self.application_name, "Update application name", 256)
        _text(self.current_version, "Current application version", 128)
        _text(self.provider, "Update provider", 128)
        if self.source is not None:
            _text(self.source, "Update source", 128)
        if self.candidate_version is not None:
            _text(self.candidate_version, "Candidate application version", 128)
        if not isinstance(self.state, HealthState):
            raise StewardshipError("Update evidence state is malformed")
        _text(self.detail, "Update evidence detail", 2_048)
        _timestamp(self.observed_at, "Update observation time")
        if self.state is HealthState.UPDATE_AVAILABLE and self.candidate is None:
            raise StewardshipError("Available update requires a trusted candidate")


@dataclass(frozen=True, slots=True)
class UpdateCoordinationPlan:
    application_id: str
    current_version: str
    candidate: InstallationCandidate
    source: str
    created_at: datetime
    expires_at: datetime
    fingerprint: str
    stages: tuple[UpdateStage, ...] = (
        UpdateStage.DISCOVER,
        UpdateStage.DOWNLOAD,
        UpdateStage.VERIFY,
        UpdateStage.APPROVE,
        UpdateStage.INSTALL,
        UpdateStage.VERIFY_RESULT,
    )

    def __post_init__(self) -> None:
        _text(self.application_id, "Update plan application identity", 256)
        _text(self.current_version, "Update plan current version", 128)
        _text(self.source, "Update plan source", 128)
        _timestamp(self.created_at, "Update plan time")
        if _timestamp(self.expires_at, "Update plan expiry") <= self.created_at:
            raise StewardshipError("Update plan expiry is invalid")
        if not isinstance(self.candidate, InstallationCandidate):
            raise StewardshipError("Update plan candidate is malformed")
        if len(self.fingerprint) != 64 or any(
            c not in "0123456789abcdef" for c in self.fingerprint
        ):
            raise StewardshipError("Update plan fingerprint is malformed")


class UpdateCoordinator:
    """Coordinate trusted package-provider evidence without becoming an installer."""

    def __init__(
        self,
        manager: ApplicationManager,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(manager.package_provider, PackageProvider):
            raise StewardshipError("Update coordination requires a trusted package provider")
        self._manager = manager
        self._clock = clock or (lambda: datetime.now(UTC))

    async def observe(self) -> tuple[UpdateEvidence, ...]:
        try:
            records = await self._manager.inventory()
        except Exception as error:
            return (
                UpdateEvidence(
                    "application-inventory",
                    "Installed applications",
                    "unknown",
                    None,
                    type(self._manager.package_provider).__name__,
                    None,
                    HealthState.UNAVAILABLE,
                    f"application inventory unavailable: {type(error).__name__}",
                    _timestamp(self._clock(), "Update observation time"),
                ),
            )
        results: list[UpdateEvidence] = []
        for record in records:
            results.append(await self._observe_record(record))
        return tuple(results)

    async def plan(
        self, application_id: str, *, ttl: timedelta = timedelta(minutes=5)
    ) -> UpdateCoordinationPlan:
        if ttl <= timedelta(0):
            raise StewardshipError("Update plan lifetime is invalid")
        evidence = tuple(
            item for item in await self.observe() if item.application_id == application_id
        )
        if len(evidence) != 1 or evidence[0].state is not HealthState.UPDATE_AVAILABLE:
            raise StewardshipError("No trusted update is available")
        item = evidence[0]
        assert item.candidate is not None
        created = _timestamp(self._clock(), "Update plan time")
        return UpdateCoordinationPlan(
            item.application_id,
            item.current_version,
            item.candidate,
            item.source or item.provider,
            created,
            created + ttl,
            _fingerprint(
                (
                    item.application_id,
                    item.current_version,
                    item.candidate.package_id,
                    item.candidate.source,
                    item.candidate.version,
                )
            ),
        )

    async def plan_application_update(self, application_id: str) -> InstallationPlan:
        """Bridge one observed candidate to the existing immutable app plan boundary."""

        evidence = tuple(
            item for item in await self.observe() if item.application_id == application_id
        )
        if len(evidence) != 1 or evidence[0].state is not HealthState.UPDATE_AVAILABLE:
            raise StewardshipError("No trusted update is available")
        expected = evidence[0]
        assert expected.candidate is not None
        try:
            application_plan = await self._manager.plan_update(application_id)
        except Exception as error:
            raise StaleStewardshipPlan(
                "Application update evidence changed before planning"
            ) from error
        candidate = application_plan.candidate
        if (
            application_plan.current_version != expected.current_version
            or candidate != expected.candidate
        ):
            raise StaleStewardshipPlan("Application update candidate changed before planning")
        return application_plan

    async def revalidate(self, plan: UpdateCoordinationPlan) -> UpdateEvidence:
        matches = tuple(
            item for item in await self.observe() if item.application_id == plan.application_id
        )
        if len(matches) != 1 or matches[0].state is not HealthState.UPDATE_AVAILABLE:
            raise StaleStewardshipPlan("Update evidence is no longer available")
        current = matches[0]
        if current.current_version != plan.current_version or current.candidate != plan.candidate:
            raise StaleStewardshipPlan("Update candidate changed after planning")
        return current

    async def _observe_record(self, record: ApplicationRecord) -> UpdateEvidence:
        now = _timestamp(self._clock(), "Update observation time")
        provider = type(self._manager.package_provider).__name__
        if record.status is not ApplicationStatus.INSTALLED or record.version is None:
            return UpdateEvidence(
                record.application_id,
                record.name,
                record.version or "unknown",
                None,
                provider,
                None,
                HealthState.UNKNOWN,
                "installed identity is not valid for update discovery",
                now,
            )
        try:
            candidate = await self._manager.package_provider.find_update(record)
        except Exception as error:
            return UpdateEvidence(
                record.application_id,
                record.name,
                record.version,
                None,
                provider,
                None,
                HealthState.UNAVAILABLE,
                f"update provider unavailable: {type(error).__name__}",
                now,
            )
        if candidate is None:
            return UpdateEvidence(
                record.application_id,
                record.name,
                record.version,
                None,
                provider,
                None,
                HealthState.UNKNOWN,
                "trusted provider supplied no update metadata",
                now,
            )
        try:
            candidate.validate_for_trusted_display()
        except ValueError:
            return UpdateEvidence(
                record.application_id,
                record.name,
                record.version,
                None,
                provider,
                None,
                HealthState.UNKNOWN,
                "provider update metadata failed trusted validation",
                now,
            )
        if (
            candidate.source.casefold() in _MODEL_SOURCES
            or candidate.verification.application_name.casefold() != record.name.casefold()
            or candidate.verification.publisher is not None
            and candidate.verification.publisher.casefold() != (record.publisher or "").casefold()
            or not _is_newer(candidate.version, record.version)
        ):
            return UpdateEvidence(
                record.application_id,
                record.name,
                record.version,
                candidate.version,
                provider,
                candidate.source,
                HealthState.UNKNOWN,
                "candidate failed trusted identity, provenance, or version checks",
                now,
            )
        return UpdateEvidence(
            record.application_id,
            record.name,
            record.version,
            candidate.version,
            provider,
            candidate.source,
            HealthState.UPDATE_AVAILABLE,
            "trusted provider established a newer compatible candidate",
            now,
            candidate,
        )


@dataclass(frozen=True, slots=True)
class SystemHealthProjection:
    software: SoftwareHealthReport
    security: SecurityHealthReport
    startup: StartupHealthReport
    updates: tuple[UpdateEvidence, ...]


@dataclass(slots=True)
class SystemStewardshipComposition:
    """Normal application-owned composition for read-only system stewardship."""

    software: SoftwareHealthService
    security: SecurityHealthService
    startup: StartupHealthService
    updates: UpdateCoordinator
    startup_effect: StartupEffectStatus = StartupEffectStatus.NOT_YET_TRUSTED

    async def refresh(self) -> SystemHealthProjection:
        software, security, startup, updates = await asyncio.gather(
            self.software.observe(),
            self.security.observe(),
            self.startup.observe(),
            self.updates.observe(),
        )
        return SystemHealthProjection(software, security, startup, updates)

    async def plan_application_update(self, application_id: str) -> InstallationPlan:
        """Create an existing ApplicationManager plan; never execute an update."""

        return await self.updates.plan_application_update(application_id)


def create_system_stewardship_composition(
    manager: ApplicationManager,
    *,
    integrity_evidence: IntegrityEvidenceProvider | None = None,
    project_root: Path | None = None,
    startup_provider: StartupProvider | None = None,
    additional_security_providers: tuple[TrustedSecurityProvider, ...] = (),
    clock: Callable[[], datetime] | None = None,
) -> SystemStewardshipComposition:
    """Compose trusted provider instances without dynamic provider discovery."""

    evidence = integrity_evidence or SourceCheckoutIntegrityEvidenceProvider(
        project_root or Path(__file__).resolve().parents[1]
    )
    security_providers: tuple[TrustedSecurityProvider, ...] = (
        IntegritySecurityProvider(evidence),
        *additional_security_providers,
        UnavailableSecurityProvider(
            "host-wide-security",
            target="host-wide-security",
        ),
    )
    registry = TrustedSecurityProviderRegistry(security_providers)
    return SystemStewardshipComposition(
        SoftwareHealthService(manager),
        SecurityHealthService(registry, clock=clock),
        StartupHealthService(startup_provider or WindowsStartupProvider(), clock=clock),
        UpdateCoordinator(manager, clock=clock),
    )


def create_real_windows_system_stewardship(
    *,
    project_root: Path | None = None,
    integrity_evidence: IntegrityEvidenceProvider | None = None,
    candidates: tuple[InstallationCandidate, ...] = (),
) -> SystemStewardshipComposition:
    """Create the bounded real-host composition using explicit trusted owners."""

    manager = ApplicationManager(
        WindowsRegistryInventoryProvider(),
        WingetPackageProvider(candidates),
        WindowsApplicationRuntime(),
        InstallationPlanStore(),
    )
    return create_system_stewardship_composition(
        manager,
        integrity_evidence=integrity_evidence,
        project_root=project_root,
    )


def _version_tuple(value: str) -> tuple[int, ...] | None:
    raw = value.strip().removeprefix("v")
    parts = raw.split(".")
    if not parts or any(not part.isdecimal() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _is_newer(candidate: str, current: str) -> bool:
    candidate_parts = _version_tuple(candidate)
    current_parts = _version_tuple(current)
    if candidate_parts is None or current_parts is None:
        return False
    width = max(len(candidate_parts), len(current_parts))
    return candidate_parts + (0,) * (width - len(candidate_parts)) > current_parts + (0,) * (
        width - len(current_parts)
    )


__all__ = [
    "HealthState",
    "IntegritySecurityProvider",
    "SecurityFinding",
    "SecurityFindingState",
    "SecurityHealthReport",
    "SecurityHealthService",
    "SecurityProvider",
    "TrustedSecurityProvider",
    "TrustedSecurityProviderRegistry",
    "SoftwareHealthReport",
    "SoftwareHealthService",
    "StaleStewardshipPlan",
    "StartupEntryEvidence",
    "StartupEntryState",
    "StartupEffectStatus",
    "StartupHealthReport",
    "StartupHealthService",
    "StartupMutationPlan",
    "StartupProvider",
    "StartupProviderError",
    "StewardshipError",
    "SystemHealthProjection",
    "SystemStewardshipComposition",
    "UpdateCoordinationPlan",
    "UpdateCoordinator",
    "UpdateEvidence",
    "UpdateStage",
    "UnavailableSecurityProvider",
    "WindowsStartupProvider",
    "create_real_windows_system_stewardship",
    "create_system_stewardship_composition",
]
