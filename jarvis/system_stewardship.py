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
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol
from uuid import UUID, uuid4

from jarvis.acquisition import (
    AcquisitionArtifactRecord,
    AcquisitionBroker,
    AcquisitionPresentation,
    AcquisitionRequest,
    AcquisitionResult,
    AcquisitionResultStatus,
    build_acquisition_presentation,
)
from jarvis.ai.portfolio import (
    DominanceAnalysis,
    ModelPortfolioEvidence,
    ModelPortfolioOptimizer,
    RetirementPlan,
    RetirementProtection,
)
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
from jarvis.resources import ResourceGovernor, ResourceSnapshot
from jarvis.security.startup import (
    IntegrityEvidenceError,
    IntegrityEvidenceProvider,
    SourceCheckoutIntegrityEvidenceProvider,
)
from jarvis.storage import (
    CleanupCandidate,
    CleanupClassifier,
    DuplicateDetector,
    DuplicateGroup,
    FileClassification,
    FileClassifier,
    PlacementStatus,
    ResourcePlacementRequest,
    Reversibility,
    StorageDeferred,
    StorageForecast,
    StorageHistoryStore,
    StorageInventoryService,
    StoragePlanner,
    StoragePressureState,
    VolumeObservation,
    forecast_storage_pressure,
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
    SUPPORTED_FOR_EXACT_CURRENT_USER_RUN = "SUPPORTED_FOR_EXACT_CURRENT_USER_RUN"
    READ_ONLY = "READ_ONLY"
    UNAVAILABLE = "UNAVAILABLE"


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
    value_type: int | None = None

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
        if self.value_type is not None and (
            isinstance(self.value_type, bool) or not isinstance(self.value_type, int)
        ):
            raise StewardshipError("Startup registry value type is malformed")


class StartupProvider(Protocol):
    async def observe(self) -> tuple[StartupEntryEvidence, ...]:
        """Return bounded startup inventory evidence."""


class StartupProviderError(RuntimeError):
    """A bounded startup source could not produce safe evidence."""


class _StartupObservationBackend(Protocol):
    def read(self, scope: str, key_path: str) -> tuple[tuple[str, str, int], ...]: ...


class WindowsStartupProvider:
    """Read the finite documented Windows Run/RunOnce registry source set."""

    provider_id = "windows-startup-registry"
    TRUSTED_REGISTRY_SOURCES: Final = (
        ("current-user", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("current-user", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("machine", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("machine", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    )

    def __init__(self, backend: _StartupObservationBackend | None = None) -> None:
        self._backend = backend

    async def observe(self) -> tuple[StartupEntryEvidence, ...]:
        if sys.platform != "win32" and self._backend is None:
            raise StartupProviderError("Windows startup provider is unavailable on this host")
        if self._backend is not None:
            return await asyncio.to_thread(self._observe_backend, self._backend)
        return await asyncio.to_thread(self._observe_registry)

    @classmethod
    def _observe_backend(
        cls, backend: _StartupObservationBackend
    ) -> tuple[StartupEntryEvidence, ...]:
        entries: list[StartupEntryEvidence] = []
        identities: set[str] = set()
        for scope, key_path in cls.TRUSTED_REGISTRY_SOURCES:
            values = backend.read(scope, key_path)
            if not isinstance(values, tuple):
                raise StartupProviderError("Windows startup backend returned malformed values")
            for value in values:
                if type(value) is not tuple or len(value) != 3:
                    raise StartupProviderError("Windows startup backend value is malformed")
                name, command, value_type = value
                if (
                    type(name) is not str
                    or not name.strip()
                    or type(command) is not str
                    or not command.strip()
                    or value_type not in (1, 2)
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
                        value_type,
                    )
                )
        return tuple(sorted(entries, key=lambda item: item.entry_id))

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
                            value_type,
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
    operation: str = "disable"
    mutation_id: str | None = None
    value_type: int | None = None
    task_id: UUID | None = None

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
        if self.operation not in {"disable", "restore"}:
            raise StewardshipError("Startup plan operation is malformed")
        if self.mutation_id is not None:
            _text(self.mutation_id, "Startup mutation identity", 64)
        if self.value_type is not None and (
            isinstance(self.value_type, bool) or not isinstance(self.value_type, int)
        ):
            raise StewardshipError("Startup plan registry value type is malformed")
        if self.task_id is not None and not isinstance(self.task_id, UUID):
            raise StewardshipError("Startup plan task identity is malformed")


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
        payload = (
            item.entry_id,
            item.provider,
            item.enabled,
            enabled,
            item.target_command,
            item.value_type,
            "disable" if not enabled else "restore",
        )
        return StartupMutationPlan(
            item.entry_id,
            item.provider,
            item.enabled,
            enabled,
            item.target_command,
            planned,
            planned + ttl,
            _fingerprint(payload),
            "disable" if not enabled else "restore",
            None,
            item.value_type,
            uuid4(),
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
            or plan.value_type is not None
            and current.value_type != plan.value_type
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
    startup_effect: StartupEffectStatus = StartupEffectStatus.NOT_YET_TRUSTED


class StewardshipLifecycleState(StrEnum):
    """Application projection of the lifecycle without replacing effect states."""

    OBSERVED = "observed"
    CLASSIFIED = "classified"
    PLANNED = "planned"
    AWAITING_AUTHORITY = "awaiting_authority"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    FAILED = "failed"
    UNKNOWN_OUTCOME = "unknown_outcome"
    ROLLBACK_REQUIRED = "rollback_required"
    ROLLED_BACK = "rolled_back"


class StewardshipOperation(StrEnum):
    OBSERVE = "observe"
    ACQUISITION = "acquisition"
    MODEL_RETIREMENT = "model_retirement"
    STORAGE_RELOCATION = "storage_relocation"
    STORAGE_CLEANUP = "storage_cleanup"
    STARTUP_MUTATION = "startup_mutation"
    UPDATE = "update"


class StewardshipLifecycleRecorder(Protocol):
    """The existing secret-safe audit sink is the lifecycle journal."""

    def record_lifecycle(
        self, kind: str, *, task_id: UUID | None, detail: dict[str, str]
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class StorageStewardshipReport:
    """Truthful storage facts and proposals; no field implies execution."""

    volumes: tuple[VolumeObservation, ...]
    pressure: tuple[tuple[str, StoragePressureState], ...]
    forecasts: tuple[StorageForecast, ...]
    cleanup_candidates: tuple[CleanupCandidate, ...]
    duplicate_groups: tuple[DuplicateGroup, ...]
    detected_bytes: int
    safe_candidate_bytes: int
    protected_bytes: int
    scan_truncated: bool = False
    duplicate_scan_state: str = "not_requested"

    def __post_init__(self) -> None:
        if any(not isinstance(item, VolumeObservation) for item in self.volumes):
            raise StewardshipError("Storage report contains malformed volume evidence")
        if any(
            type(volume_id) is not str
            or not volume_id
            or not isinstance(state, StoragePressureState)
            for volume_id, state in self.pressure
        ):
            raise StewardshipError("Storage report pressure evidence is malformed")
        if any(not isinstance(item, StorageForecast) for item in self.forecasts):
            raise StewardshipError("Storage report forecast evidence is malformed")
        if any(not isinstance(item, CleanupCandidate) for item in self.cleanup_candidates):
            raise StewardshipError("Storage report cleanup evidence is malformed")
        if any(not isinstance(item, DuplicateGroup) for item in self.duplicate_groups):
            raise StewardshipError("Storage report duplicate evidence is malformed")
        if any(
            type(value) is not int or value < 0
            for value in (self.detected_bytes, self.safe_candidate_bytes, self.protected_bytes)
        ):
            raise StewardshipError("Storage report byte totals are malformed")
        _text(self.duplicate_scan_state, "Duplicate scan state", 128)


@dataclass(frozen=True, slots=True)
class CleanupStewardshipPlan:
    """A grouped, inert cleanup proposal that requires a trusted file effect."""

    candidates: tuple[CleanupCandidate, ...]
    detected_bytes: int
    safe_candidate_bytes: int
    recovery: str


@dataclass(frozen=True, slots=True)
class AcquisitionStewardshipPlan:
    request: AcquisitionRequest
    presentation: AcquisitionPresentation


@dataclass(frozen=True, slots=True)
class MissingResourceRequirement:
    """Trusted requirement evidence that can be converted into one formal request."""

    requirement_id: str
    source: str
    evidence_reference: str
    request: AcquisitionRequest
    observed_missing: bool = True
    task_id: UUID | None = None
    step_id: UUID | None = None
    attempt_id: UUID | None = None

    def __post_init__(self) -> None:
        _text(self.requirement_id, "Missing-resource requirement identity", 256)
        _text(self.source, "Missing-resource requirement source", 256)
        _text(self.evidence_reference, "Missing-resource evidence reference", 1_024)
        if not isinstance(self.request, AcquisitionRequest):
            raise StewardshipError("Missing-resource formal request is malformed")
        if type(self.observed_missing) is not bool or not self.observed_missing:
            raise StewardshipError("Missing-resource evidence must establish absence")
        for value, name in (
            (self.task_id, "Missing-resource task identity"),
            (self.step_id, "Missing-resource step identity"),
            (self.attempt_id, "Missing-resource attempt identity"),
        ):
            if value is not None and not isinstance(value, UUID):
                raise StewardshipError(f"{name} is malformed")


@dataclass(frozen=True, slots=True)
class StewardshipPlan:
    plan_id: UUID
    operation: StewardshipOperation
    lifecycle: StewardshipLifecycleState
    observation_fingerprint: str
    created_at: datetime
    expires_at: datetime
    reversibility: Reversibility
    payload: object
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.plan_id, UUID):
            raise StewardshipError("Stewardship plan identity is malformed")
        if not isinstance(self.operation, StewardshipOperation):
            raise StewardshipError("Stewardship plan operation is malformed")
        if self.lifecycle is not StewardshipLifecycleState.PLANNED:
            raise StewardshipError("Only planned stewardship records can be issued")
        if len(self.observation_fingerprint) != 64:
            raise StewardshipError("Stewardship plan observation binding is malformed")
        created = _timestamp(self.created_at, "Stewardship plan creation time")
        if _timestamp(self.expires_at, "Stewardship plan expiry") <= created:
            raise StewardshipError("Stewardship plan expiry is invalid")
        if not isinstance(self.reversibility, Reversibility):
            raise StewardshipError("Stewardship plan reversibility is malformed")
        _text(self.detail, "Stewardship plan detail", 2_000)


@dataclass(frozen=True, slots=True)
class StewardshipObservation:
    observation_id: UUID
    observed_at: datetime
    lifecycle: StewardshipLifecycleState
    system: SystemHealthProjection
    storage: StorageStewardshipReport
    resources: ResourceSnapshot | None
    models: tuple[ModelPortfolioEvidence, ...]
    model_analysis: tuple[DominanceAnalysis, ...]
    model_error: str | None
    fingerprint: str
    acquisition_records: tuple[AcquisitionArtifactRecord, ...] = ()
    acquisition_requests: tuple[AcquisitionRequest, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.observation_id, UUID):
            raise StewardshipError("Stewardship observation identity is malformed")
        _timestamp(self.observed_at, "Stewardship observation time")
        if self.lifecycle is not StewardshipLifecycleState.CLASSIFIED:
            raise StewardshipError("Stewardship observations must be classified")
        if not isinstance(self.system, SystemHealthProjection):
            raise StewardshipError("Stewardship system projection is malformed")
        if not isinstance(self.storage, StorageStewardshipReport):
            raise StewardshipError("Stewardship storage projection is malformed")
        if self.resources is not None and not isinstance(self.resources, ResourceSnapshot):
            raise StewardshipError("Stewardship resource projection is malformed")
        if any(not isinstance(item, ModelPortfolioEvidence) for item in self.models):
            raise StewardshipError("Stewardship model evidence is malformed")
        if any(not isinstance(item, DominanceAnalysis) for item in self.model_analysis):
            raise StewardshipError("Stewardship model analysis is malformed")
        if self.model_error is not None:
            _text(self.model_error, "Stewardship model error", 512)
        if len(self.fingerprint) != 64:
            raise StewardshipError("Stewardship observation fingerprint is malformed")
        if any(
            not isinstance(item, AcquisitionArtifactRecord) for item in self.acquisition_records
        ):
            raise StewardshipError("Stewardship acquisition evidence is malformed")
        if any(not isinstance(item, AcquisitionRequest) for item in self.acquisition_requests):
            raise StewardshipError("Stewardship acquisition requests are malformed")


@dataclass(frozen=True, slots=True)
class StewardshipRecoveryReport:
    startup: tuple[object, ...]
    storage: tuple[object, ...]
    acquisition_pending: tuple[object, ...]
    detail: str


class StartupMutationCapability(Protocol):
    async def plan_disable(self, entry_id: str) -> StartupMutationPlan: ...

    async def plan_restore(self, mutation_id: str) -> StartupMutationPlan: ...

    async def authorize(
        self, plan: StartupMutationPlan, *, user_id: str | None = None
    ) -> object: ...

    async def execute(self, plan: StartupMutationPlan, receipt: object) -> object: ...

    async def reconcile(self) -> tuple[object, ...]: ...


@dataclass(slots=True)
class SystemStewardshipComposition:
    """Normal application-owned composition for read-only system stewardship."""

    software: SoftwareHealthService
    security: SecurityHealthService
    startup: StartupHealthService
    updates: UpdateCoordinator
    startup_effect: StartupEffectStatus = StartupEffectStatus.NOT_YET_TRUSTED
    startup_mutation: StartupMutationCapability | None = None

    async def refresh(self) -> SystemHealthProjection:
        software, security, startup, updates = await asyncio.gather(
            self.software.observe(),
            self.security.observe(),
            self.startup.observe(),
            self.updates.observe(),
        )
        return SystemHealthProjection(software, security, startup, updates, self.startup_effect)

    async def plan_application_update(self, application_id: str) -> InstallationPlan:
        """Create an existing ApplicationManager plan; never execute an update."""

        return await self.updates.plan_application_update(application_id)

    async def plan_startup_disable(self, entry_id: str) -> StartupMutationPlan:
        if self.startup_mutation is None:
            raise StewardshipError("startup effect provider is not composed")
        return await self.startup_mutation.plan_disable(entry_id)

    async def plan_startup_restore(self, mutation_id: str) -> StartupMutationPlan:
        if self.startup_mutation is None:
            raise StewardshipError("startup effect provider is not composed")
        return await self.startup_mutation.plan_restore(mutation_id)

    async def authorize_startup(
        self, plan: StartupMutationPlan, *, user_id: str | None = None
    ) -> object:
        if self.startup_mutation is None:
            raise StewardshipError("startup effect provider is not composed")
        return await self.startup_mutation.authorize(plan, user_id=user_id)

    async def execute_startup(self, plan: StartupMutationPlan, receipt: object) -> object:
        if self.startup_mutation is None:
            raise StewardshipError("startup effect provider is not composed")
        return await self.startup_mutation.execute(plan, receipt)

    async def reconcile_startup(self) -> tuple[object, ...]:
        if self.startup_mutation is None:
            raise StewardshipError("startup effect provider is not composed")
        return await self.startup_mutation.reconcile()


class SystemStewardshipCoordinator:
    """Application-owned stewardship projection over existing trusted owners.

    This coordinator owns sequencing, stale-observation binding, and the
    operator-facing projection. It deliberately has no filesystem, package,
    model, registry, or startup mutation implementation of its own.
    """

    def __init__(
        self,
        system: SystemStewardshipComposition,
        *,
        storage_inventory: StorageInventoryService,
        storage_planner: StoragePlanner,
        resource_governor: ResourceGovernor | None = None,
        acquisition: AcquisitionBroker | None = None,
        portfolio: ModelPortfolioOptimizer | None = None,
        storage_history: StorageHistoryStore | None = None,
        file_steward: object | None = None,
        lifecycle_recorder: StewardshipLifecycleRecorder | None = None,
        cleanup_roots: Iterable[Path] = (),
        duplicate_roots: Iterable[Path] = (),
        jarvis_roots: Iterable[Path] = (),
        protected_roots: Iterable[Path] = (),
        classifier: Callable[[Path], FileClassification] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(system, SystemStewardshipComposition):
            raise StewardshipError("System stewardship composition is malformed")
        if not isinstance(storage_inventory, StorageInventoryService) or not isinstance(
            storage_planner, StoragePlanner
        ):
            raise StewardshipError("Storage stewardship owners are malformed")
        if resource_governor is not None and not isinstance(resource_governor, ResourceGovernor):
            raise StewardshipError("Resource governor is malformed")
        if acquisition is not None and not isinstance(acquisition, AcquisitionBroker):
            raise StewardshipError("Acquisition owner is malformed")
        if portfolio is not None and not isinstance(portfolio, ModelPortfolioOptimizer):
            raise StewardshipError("Model portfolio owner is malformed")
        self.system = system
        self.storage_inventory = storage_inventory
        self.storage_planner = storage_planner
        self.resource_governor = resource_governor
        self.acquisition = acquisition
        self.portfolio = portfolio
        self.storage_history = storage_history
        self.file_steward = file_steward
        self.lifecycle_recorder = lifecycle_recorder
        self._cleanup_roots = tuple(Path(item) for item in cleanup_roots)
        self._duplicate_roots = tuple(Path(item) for item in duplicate_roots)
        self._jarvis_roots = tuple(Path(item) for item in jarvis_roots)
        self._protected_roots = tuple(Path(item) for item in protected_roots)
        self._classifier = classifier
        self._clock = clock or (lambda: datetime.now(UTC))
        self._last: StewardshipObservation | None = None
        self._lifecycle_state: dict[StewardshipOperation, StewardshipLifecycleState] = {}
        self._acquisition_requests: dict[str, AcquisitionRequest] = {}

    @property
    def last_observation(self) -> StewardshipObservation | None:
        return self._last

    async def observe(
        self,
        *,
        task_classes: tuple[str, ...] = (),
        cleanup_roots: Iterable[Path] | None = None,
        duplicate_roots: Iterable[Path] | None = None,
    ) -> StewardshipObservation:
        """Observe all configured domains and classify without executing effects."""

        system_result = await self.system.refresh()
        storage_result = self._observe_storage(
            tuple(cleanup_roots) if cleanup_roots is not None else self._cleanup_roots,
            tuple(duplicate_roots) if duplicate_roots is not None else self._duplicate_roots,
        )
        models: tuple[ModelPortfolioEvidence, ...] = ()
        model_analysis: tuple[DominanceAnalysis, ...] = ()
        model_error: str | None = None
        if self.portfolio is not None:
            try:
                models = await self.portfolio.current_evidence(task_classes=task_classes)
                model_analysis = self.portfolio.analyze(models, task_classes=task_classes)
            except Exception as error:
                model_error = f"model portfolio unavailable: {type(error).__name__}"
        resources = self.resource_governor.snapshot() if self.resource_governor else None
        acquisition_records: tuple[AcquisitionArtifactRecord, ...] = ()
        if self.acquisition is not None:
            acquisition_records = tuple(self.acquisition.ledger.records())
        acquisition_requests = tuple(
            self._acquisition_requests[key] for key in sorted(self._acquisition_requests)
        )
        observed_at = _timestamp(self._clock(), "Stewardship clock")
        fingerprint = self._observation_fingerprint(
            system_result,
            storage_result,
            resources,
            models,
            acquisition_records,
            acquisition_requests,
        )
        observation = StewardshipObservation(
            uuid4(),
            observed_at,
            StewardshipLifecycleState.CLASSIFIED,
            system_result,
            storage_result,
            resources,
            models,
            model_analysis,
            model_error,
            fingerprint,
            acquisition_records,
            acquisition_requests,
        )
        self._last = observation
        self._record(
            StewardshipOperation.OBSERVE,
            StewardshipLifecycleState.CLASSIFIED,
            fingerprint,
            detail="trusted provider observations classified",
        )
        return observation

    def plan_cleanup(
        self, observation: StewardshipObservation, *, ttl: timedelta = timedelta(minutes=5)
    ) -> StewardshipPlan:
        self._validate_observation(observation)
        if ttl <= timedelta(0):
            raise StewardshipError("Cleanup plan lifetime is invalid")
        candidates = tuple(item for item in observation.storage.cleanup_candidates if item.eligible)
        payload = CleanupStewardshipPlan(
            candidates,
            observation.storage.detected_bytes,
            sum(item.expected_reclaimed_bytes for item in candidates),
            "trusted FileSteward recovery is required for any effect",
        )
        return self._plan(
            StewardshipOperation.STORAGE_CLEANUP,
            observation,
            payload,
            Reversibility.REVERSIBLE_WITH_BACKUP,
            ttl,
            "grouped cleanup proposal; no deletion authority granted",
        )

    def plan_relocation(
        self,
        observation: StewardshipObservation,
        request: ResourcePlacementRequest,
        *,
        ttl: timedelta = timedelta(minutes=5),
    ) -> StewardshipPlan:
        self._validate_observation(observation)
        if ttl <= timedelta(0):
            raise StewardshipError("Relocation plan lifetime is invalid")
        placement = self.storage_planner.plan(request, volumes=observation.storage.volumes)
        reversibility = (
            Reversibility.FULLY_REVERSIBLE
            if placement.status is PlacementStatus.ALREADY_SUITABLE
            else Reversibility.REVERSIBLE_WITH_BACKUP
        )
        return self._plan(
            StewardshipOperation.STORAGE_RELOCATION,
            observation,
            placement,
            reversibility,
            ttl,
            "bounded placement proposal; trusted file effect remains separate",
        )

    def plan_acquisition(
        self,
        observation: StewardshipObservation,
        request: AcquisitionRequest,
        *,
        ttl: timedelta = timedelta(minutes=5),
    ) -> StewardshipPlan:
        self._validate_observation(observation)
        if not isinstance(request, AcquisitionRequest):
            raise StewardshipError("Acquisition plan request is malformed")
        if ttl <= timedelta(0):
            raise StewardshipError("Acquisition plan lifetime is invalid")
        self.record_acquisition_request(request)
        payload = AcquisitionStewardshipPlan(request, build_acquisition_presentation(request))
        reversibility = (
            Reversibility.REINSTALL_REQUIRED
            if request.rollback_plan is None
            else Reversibility.REVERSIBLE_WITH_BACKUP
        )
        return self._plan(
            StewardshipOperation.ACQUISITION,
            observation,
            payload,
            reversibility,
            ttl,
            "formal acquisition request prepared; trusted broker authority remains required",
        )

    def record_acquisition_request(self, request: AcquisitionRequest) -> None:
        """Project a trusted task-originated request without granting effect authority."""

        if not isinstance(request, AcquisitionRequest):
            raise StewardshipError("Acquisition request is malformed")
        self._acquisition_requests[request.fingerprint] = request

    def prepare_missing_resource(
        self,
        observation: StewardshipObservation,
        requirement: MissingResourceRequirement,
        *,
        ttl: timedelta = timedelta(minutes=5),
    ) -> StewardshipPlan:
        """Convert trusted absence evidence into the existing acquisition contract."""

        if not isinstance(requirement, MissingResourceRequirement):
            raise StewardshipError("Missing-resource requirement is malformed")
        return self.plan_acquisition(observation, requirement.request, ttl=ttl)

    def plan_model_retirement(
        self,
        observation: StewardshipObservation,
        analysis: DominanceAnalysis,
        protection: RetirementProtection,
    ) -> RetirementPlan:
        self._validate_observation(observation)
        if self.portfolio is None:
            raise StewardshipError("Model portfolio owner is unavailable")
        plan = self.portfolio.propose_retirement(analysis, protection)
        self._record(
            StewardshipOperation.MODEL_RETIREMENT,
            StewardshipLifecycleState.PLANNED,
            observation.fingerprint,
            detail=f"retirement plan {plan.plan_id} created by portfolio authority",
        )
        return plan

    async def acquire(
        self,
        plan: StewardshipPlan,
        *,
        task_id: UUID | None = None,
        user_id: str | None = None,
    ) -> AcquisitionResult:
        if plan.operation is not StewardshipOperation.ACQUISITION:
            raise StewardshipError("Plan is not an acquisition plan")
        current = await self.assert_current(plan)
        if self.acquisition is None or not isinstance(plan.payload, AcquisitionStewardshipPlan):
            raise StewardshipError("Acquisition owner is unavailable")
        self._record(
            StewardshipOperation.ACQUISITION,
            StewardshipLifecycleState.AWAITING_AUTHORITY,
            current.fingerprint,
            detail="delegating formal request to the existing acquisition broker",
            task_id=task_id,
        )
        self._record(
            StewardshipOperation.ACQUISITION,
            StewardshipLifecycleState.EXECUTING,
            current.fingerprint,
            detail="acquisition broker execution began",
            task_id=task_id,
        )
        try:
            result = await self.acquisition.acquire(
                plan.payload.request, task_id=task_id, user_id=user_id
            )
        except Exception as error:
            state = (
                StewardshipLifecycleState.UNKNOWN_OUTCOME
                if type(error).__name__ in {"AcquisitionUnknownOutcome", "AcquisitionStaleTarget"}
                else StewardshipLifecycleState.FAILED
            )
            self._record(
                StewardshipOperation.ACQUISITION,
                state,
                current.fingerprint,
                detail=f"acquisition broker returned {type(error).__name__}",
                task_id=task_id,
            )
            raise
        terminal = (
            StewardshipLifecycleState.VERIFIED
            if result.status
            in {AcquisitionResultStatus.REGISTERED, AcquisitionResultStatus.DUPLICATE}
            else StewardshipLifecycleState.UNKNOWN_OUTCOME
            if result.status is AcquisitionResultStatus.UNKNOWN_OUTCOME
            else StewardshipLifecycleState.VERIFYING
        )
        self._record(
            StewardshipOperation.ACQUISITION,
            terminal,
            current.fingerprint,
            detail=f"acquisition result {result.status.value}",
            task_id=task_id,
        )
        return result

    async def assert_current(
        self, plan: StewardshipPlan, observation: StewardshipObservation | None = None
    ) -> StewardshipObservation:
        if not isinstance(plan, StewardshipPlan):
            raise StewardshipError("Stewardship plan is malformed")
        if _timestamp(self._clock(), "Stewardship clock") >= plan.expires_at:
            raise StaleStewardshipPlan("stewardship plan has expired")
        current = observation or await self.observe()
        if current.fingerprint != plan.observation_fingerprint:
            raise StaleStewardshipPlan("stewardship observation changed after planning")
        return current

    async def reconcile(self) -> StewardshipRecoveryReport:
        """Reconcile known uncertainty without retrying an uncertain effect."""

        startup: tuple[object, ...] = ()
        if self.system.startup_mutation is not None:
            startup = await self.system.reconcile_startup()
        storage: tuple[object, ...] = ()
        if self.file_steward is not None:
            reconcile_pending = getattr(self.file_steward, "reconcile_pending", None)
            if not callable(reconcile_pending):
                raise StewardshipError("File stewardship recovery owner is malformed")
            storage = tuple(reconcile_pending())
        pending: tuple[object, ...] = ()
        if self.acquisition is not None:
            pending = tuple(
                item
                for item in self.acquisition.ledger.records()
                if getattr(item.state, "value", "")
                in {"active", "verification_required", "placement_pending"}
            )
        report = StewardshipRecoveryReport(
            startup,
            storage,
            pending,
            "uncertain effect records remain pending until provider evidence closes them",
        )
        unresolved = pending or tuple(
            item
            for item in (*startup, *storage)
            if getattr(getattr(item, "state", None), "value", "")
            in {"unknown_outcome", "recovery_required", "pending"}
        )
        recovery_state = (
            StewardshipLifecycleState.UNKNOWN_OUTCOME
            if unresolved
            else StewardshipLifecycleState.VERIFIED
        )
        recovery_detail = "restart reconciliation completed with provider evidence"
        for operation in (
            StewardshipOperation.ACQUISITION,
            StewardshipOperation.STORAGE_CLEANUP,
            StewardshipOperation.STORAGE_RELOCATION,
            StewardshipOperation.STARTUP_MUTATION,
        ):
            if operation in self._lifecycle_state:
                self._record(
                    operation,
                    recovery_state,
                    self._last.fingerprint if self._last is not None else "0" * 64,
                    detail=recovery_detail,
                )
        self._record(
            StewardshipOperation.OBSERVE,
            recovery_state,
            self._last.fingerprint if self._last is not None else "0" * 64,
            detail=recovery_detail,
        )
        return report

    def _observe_storage(
        self, cleanup_roots: tuple[Path, ...], duplicate_roots: tuple[Path, ...]
    ) -> StorageStewardshipReport:
        volumes = tuple(self.storage_inventory.inspect())
        pressure = tuple(
            (item.volume_id, self.storage_inventory.pressure(item.volume_id)) for item in volumes
        )
        snapshots = self.storage_history.snapshots() if self.storage_history is not None else ()
        forecasts = tuple(forecast_storage_pressure(snapshots, item.volume_id) for item in volumes)
        default_classifier = FileClassifier(
            protected_roots=self._protected_roots,
            jarvis_roots=self._jarvis_roots,
        )
        classify = self._classifier or default_classifier.classify
        candidates: list[CleanupCandidate] = []
        truncated = False
        for path in self._bounded_files(cleanup_roots):
            if len(candidates) >= 10_000:
                truncated = True
                break
            try:
                candidates.append(CleanupClassifier().candidate(path, classify(path)))
            except (OSError, ValueError):
                continue
        duplicates: tuple[DuplicateGroup, ...] = ()
        duplicate_scan_state = "not_requested"
        if duplicate_roots:
            try:
                duplicates = DuplicateDetector(resource_governor=self.resource_governor).scan(
                    duplicate_roots, classifier=classify
                )
            except StorageDeferred:
                duplicate_scan_state = "deferred"
            else:
                duplicate_scan_state = "verified"
        return StorageStewardshipReport(
            volumes,
            pressure,
            forecasts,
            tuple(candidates),
            duplicates,
            sum(item.size_bytes for item in candidates),
            sum(item.expected_reclaimed_bytes for item in candidates if item.eligible),
            sum(item.size_bytes for item in candidates if item.state.value == "protected"),
            truncated,
            duplicate_scan_state,
        )

    @staticmethod
    def _bounded_files(roots: tuple[Path, ...]) -> Iterable[Path]:
        count = 0
        for root_value in roots:
            root = Path(root_value)
            if not root.is_dir() or root.is_symlink():
                continue
            try:
                paths = root.rglob("*")
                for path in paths:
                    if count >= 10_001:
                        return
                    if path.is_file() and not path.is_symlink():
                        count += 1
                        yield path
            except OSError:
                continue

    def _plan(
        self,
        operation: StewardshipOperation,
        observation: StewardshipObservation,
        payload: object,
        reversibility: Reversibility,
        ttl: timedelta,
        detail: str,
    ) -> StewardshipPlan:
        created = _timestamp(self._clock(), "Stewardship clock")
        plan = StewardshipPlan(
            uuid4(),
            operation,
            StewardshipLifecycleState.PLANNED,
            observation.fingerprint,
            created,
            created + ttl,
            reversibility,
            payload,
            detail,
        )
        self._record(operation, StewardshipLifecycleState.PLANNED, observation.fingerprint, detail)
        return plan

    def _validate_observation(self, observation: StewardshipObservation) -> None:
        if not isinstance(observation, StewardshipObservation):
            raise StewardshipError("Stewardship observation is malformed")
        if self._last is not None and observation.observation_id != self._last.observation_id:
            raise StaleStewardshipPlan("stewardship observation is not the current projection")

    def _record(
        self,
        operation: StewardshipOperation,
        state: StewardshipLifecycleState,
        fingerprint: str,
        detail: str,
        *,
        task_id: UUID | None = None,
    ) -> None:
        previous = self._lifecycle_state.get(operation)
        if (
            previous
            in {
                StewardshipLifecycleState.UNKNOWN_OUTCOME,
                StewardshipLifecycleState.FAILED,
            }
            and state is StewardshipLifecycleState.VERIFIED
            and "reconcil" not in detail.casefold()
        ):
            raise StewardshipError(
                f"{operation.value} cannot become verified without a new "
                "reconciliation evidence path"
            )
        if state is StewardshipLifecycleState.ROLLED_BACK and "rollback" not in detail.casefold():
            raise StewardshipError("rolled-back stewardship state lacks rollback evidence")
        self._lifecycle_state[operation] = state
        if self.lifecycle_recorder is None:
            return
        self.lifecycle_recorder.record_lifecycle(
            "system_stewardship",
            task_id=task_id,
            detail={
                "operation": operation.value,
                "state": state.value,
                "observation_fingerprint": fingerprint,
                "detail": detail,
            },
        )

    @staticmethod
    def _observation_fingerprint(
        system: SystemHealthProjection,
        storage: StorageStewardshipReport,
        resources: ResourceSnapshot | None,
        models: tuple[ModelPortfolioEvidence, ...],
        acquisition_records: tuple[AcquisitionArtifactRecord, ...] = (),
        acquisition_requests: tuple[AcquisitionRequest, ...] = (),
    ) -> str:
        # These projections are composed of immutable, typed evidence records.
        # Hashing their complete representations prevents a newly added provider
        # field from silently escaping stale-plan invalidation.
        return _fingerprint(
            {
                "system": repr(system),
                "storage": repr(storage),
                "resources": repr(resources),
                "models": repr(models),
                "acquisition_records": repr(acquisition_records),
                "acquisition_requests": repr(acquisition_requests),
            }
        )


def create_system_stewardship_composition(
    manager: ApplicationManager,
    *,
    integrity_evidence: IntegrityEvidenceProvider | None = None,
    project_root: Path | None = None,
    startup_provider: StartupProvider | None = None,
    additional_security_providers: tuple[TrustedSecurityProvider, ...] = (),
    clock: Callable[[], datetime] | None = None,
    startup_mutation: StartupMutationCapability | None = None,
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
        (
            StartupEffectStatus.SUPPORTED_FOR_EXACT_CURRENT_USER_RUN
            if startup_mutation is not None
            else StartupEffectStatus.NOT_YET_TRUSTED
        ),
        startup_mutation,
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
    "AcquisitionStewardshipPlan",
    "CleanupStewardshipPlan",
    "MissingResourceRequirement",
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
    "StewardshipLifecycleRecorder",
    "StewardshipLifecycleState",
    "StewardshipObservation",
    "StewardshipOperation",
    "StewardshipPlan",
    "StewardshipRecoveryReport",
    "StorageStewardshipReport",
    "SystemStewardshipCoordinator",
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
