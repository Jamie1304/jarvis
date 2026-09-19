"""Focused evidence and authority tests for R3C system stewardship."""

import asyncio
import sys
import types
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from jarvis.applications.manager import ApplicationManager
from jarvis.applications.models import (
    ApplicationRecord,
    ApplicationStatus,
    InstallationCandidate,
    InstallationVerification,
)
from jarvis.applications.plans import InstallationPlanStore
from jarvis.applications.providers import ApplicationInventoryProvider, PackageProvider
from jarvis.applications.runtime import ApplicationRuntime
from jarvis.computer.models import LaunchInfo
from jarvis.security.startup import IntegrityEvidenceError, IntegrityEvidenceProvider
from jarvis.system_stewardship import (
    HealthState,
    IntegritySecurityProvider,
    SecurityFinding,
    SecurityFindingState,
    SecurityHealthReport,
    SecurityHealthService,
    SecurityProvider,
    StaleStewardshipPlan,
    StartupEffectStatus,
    StartupEntryEvidence,
    StartupEntryState,
    StartupHealthReport,
    StartupHealthService,
    StartupProvider,
    StartupProviderError,
    StewardshipError,
    SystemHealthProjection,
    TrustedSecurityProviderRegistry,
    UpdateCoordinator,
    UpdateEvidence,
    WindowsStartupProvider,
    create_system_stewardship_composition,
)

NOW = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)


class SecurityFixture:
    def __init__(self, findings: tuple[SecurityFinding, ...] = ()) -> None:
        self.findings = findings

    async def observe(self) -> tuple[SecurityFinding, ...]:
        return self.findings


class FailingSecurity:
    async def observe(self) -> tuple[SecurityFinding, ...]:
        raise RuntimeError("provider offline")


class EmptySecurity:
    async def observe(self) -> tuple[SecurityFinding, ...]:
        return ()


class MalformedSecurity:
    async def observe(self) -> object:
        return [finding()]


class StartupFixture:
    def __init__(self, entries: tuple[StartupEntryEvidence, ...]) -> None:
        self.entries = entries

    async def observe(self) -> tuple[StartupEntryEvidence, ...]:
        return self.entries


class FailingStartup:
    async def observe(self) -> tuple[StartupEntryEvidence, ...]:
        raise RuntimeError("startup provider offline")


class MalformedStartup:
    async def observe(self) -> object:
        return [startup_entry()]


class IntegrityFixture(IntegrityEvidenceProvider):
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls = 0

    def validate(self) -> None:
        self.calls += 1
        if self.error is not None:
            raise self.error


class TrustedUnavailable:
    provider_id = "trusted-unavailable"

    async def observe(self) -> tuple[SecurityFinding, ...]:
        raise RuntimeError("offline")


class ModelProvider:
    provider_id = "model"

    async def observe(self) -> tuple[SecurityFinding, ...]:
        return ()


class FailingInventory(ApplicationInventoryProvider):
    async def enumerate_installed(self) -> tuple[ApplicationRecord, ...]:
        raise RuntimeError("inventory offline")


class InventoryFixture(ApplicationInventoryProvider):
    def __init__(self, records: tuple[ApplicationRecord, ...]) -> None:
        self.records = records

    async def enumerate_installed(self) -> tuple[ApplicationRecord, ...]:
        return self.records


class RuntimeFixture(ApplicationRuntime):
    async def can_launch(self, record: ApplicationRecord) -> bool:
        return record.status is ApplicationStatus.INSTALLED

    async def launch(self, record: ApplicationRecord) -> LaunchInfo:
        return LaunchInfo(record.application_id, 10)

    async def close(self, application_id: str, process_id: int) -> None:
        del application_id, process_id


class PackagesFixture(PackageProvider):
    def __init__(
        self,
        candidate: InstallationCandidate | None = None,
        *,
        error: Exception | None = None,
    ) -> None:
        self.candidate = candidate
        self.error = error
        self.update_calls = 0

    async def search(self, semantic_name: str) -> tuple[InstallationCandidate, ...]:
        del semantic_name
        return ()

    async def find_update(self, record: ApplicationRecord) -> InstallationCandidate | None:
        del record
        self.update_calls += 1
        if self.error is not None:
            raise self.error
        return self.candidate

    async def install(self, candidate: InstallationCandidate, cancellation: asyncio.Event) -> None:
        del candidate, cancellation

    async def update(self, candidate: InstallationCandidate, cancellation: asyncio.Event) -> None:
        del candidate, cancellation


class ChangingPackages(PackagesFixture):
    def __init__(self) -> None:
        super().__init__(candidate())
        self._calls = 0

    async def find_update(self, record: ApplicationRecord) -> InstallationCandidate | None:
        del record
        self._calls += 1
        return candidate() if self._calls == 1 else candidate("3.0.0")


class BadCandidate(InstallationCandidate):
    def __post_init__(self) -> None:
        pass

    def validate_for_trusted_display(self) -> None:
        raise ValueError("candidate is stale")


def finding(
    state: SecurityFindingState = SecurityFindingState.HEALTHY,
    *,
    observed_at: datetime = NOW,
) -> SecurityFinding:
    return SecurityFinding(
        "trusted-security-provider",
        "file:sample.exe",
        observed_at,
        state,
        "scan-1",
        "provider scan result",
        "local-provider-record:scan-1",
        0.95,
    )


def startup_entry(
    *, enabled: bool = True, target: str | None = "C:/safe/app.exe"
) -> StartupEntryEvidence:
    return StartupEntryEvidence(
        "startup:current-user:sample",
        "sample-app",
        "trusted-startup-provider",
        enabled,
        target,
        target is not None,
        NOW,
        StartupEntryState.HEALTHY if target is not None else StartupEntryState.BROKEN,
        "bounded provider observation",
    )


def record(version: str = "1.0.0") -> ApplicationRecord:
    return ApplicationRecord(
        "app:sample",
        "Sample App",
        version,
        "Sample Publisher",
        "C:/safe/app.exe",
        "trusted-inventory",
        ApplicationStatus.INSTALLED,
    )


def candidate(version: str = "2.0.0", source: str = "trusted-catalog") -> InstallationCandidate:
    return InstallationCandidate(
        "sample.app",
        source,
        "Sample App",
        "Sample Publisher",
        version,
        (),
        "provider-issued candidate",
        0.9,
        InstallationVerification("Sample App", "Sample Publisher", version),
    )


def app_manager(
    packages: PackagesFixture, records: tuple[ApplicationRecord, ...] = (record(),)
) -> ApplicationManager:
    return ApplicationManager(
        InventoryFixture(records), packages, RuntimeFixture(), InstallationPlanStore()
    )


@pytest.mark.asyncio
async def test_security_report_preserves_provider_threat_and_provenance() -> None:
    report = await SecurityHealthService(
        SecurityFixture((finding(), finding(SecurityFindingState.THREAT_DETECTED)))
    ).observe()
    assert report.overall is SecurityFindingState.THREAT_DETECTED
    assert report.findings[1].evidence_ref == "local-provider-record:scan-1"
    assert not report.findings[0].is_stale(
        now=NOW + timedelta(minutes=1), max_age=timedelta(hours=1)
    )


def test_security_rejects_model_claim_and_stale_bound_is_validated() -> None:
    with pytest.raises(StewardshipError, match="Model-only"):
        finding_provider = "model"
        SecurityFinding(
            finding_provider,
            "file:x",
            NOW,
            SecurityFindingState.HEALTHY,
            "claim",
            "clean",
            "model-output",
        )
    with pytest.raises(StewardshipError, match="age bound"):
        finding().is_stale(now=NOW, max_age=timedelta(0))
    assert finding(observed_at=NOW - timedelta(hours=2)).is_stale(
        now=NOW, max_age=timedelta(hours=1)
    )


@pytest.mark.asyncio
async def test_security_provider_failure_is_unavailable_not_clean() -> None:
    report = await SecurityHealthService(FailingSecurity(), clock=lambda: NOW).observe()
    assert report.overall is SecurityFindingState.UNAVAILABLE
    assert report.findings[0].state is SecurityFindingState.UNAVAILABLE


@pytest.mark.asyncio
async def test_security_overall_is_conservative_for_integrity_and_unknown_states() -> None:
    integrity = await SecurityHealthService(
        SecurityFixture((finding(SecurityFindingState.INTEGRITY_FAILURE),))
    ).observe()
    assert integrity.overall is SecurityFindingState.INTEGRITY_FAILURE
    unknown = await SecurityHealthService(
        SecurityFixture((finding(SecurityFindingState.UNKNOWN),))
    ).observe()
    assert unknown.overall is SecurityFindingState.UNKNOWN


def test_integrity_adapter_rejects_untrusted_authority_and_reports_generic_failure() -> None:
    with pytest.raises(StewardshipError, match="not trusted"):
        IntegritySecurityProvider(cast(Any, object()))


@pytest.mark.asyncio
async def test_integrity_adapter_keeps_unexpected_provider_failure_unavailable() -> None:
    result = await IntegritySecurityProvider(
        IntegrityFixture(RuntimeError("secret path"))
    ).observe()
    assert result[0].state is SecurityFindingState.UNAVAILABLE
    assert "secret path" not in result[0].detail


@pytest.mark.asyncio
async def test_startup_observation_and_exact_reversible_plan_are_read_only() -> None:
    provider = StartupFixture((startup_entry(),))
    service = StartupHealthService(provider, clock=lambda: NOW)
    report = await service.observe()
    assert report.overall is HealthState.HEALTHY
    plan = await service.plan_set_enabled("startup:current-user:sample", False)
    assert plan.previous_enabled is True
    assert plan.new_enabled is False
    assert plan.target_command == "C:/safe/app.exe"
    assert await service.revalidate(plan) == startup_entry()
    StartupHealthService.assert_receipt(plan, plan.fingerprint)
    restored = await service.plan_set_enabled("startup:current-user:sample", True)
    assert restored.new_enabled is True


@pytest.mark.asyncio
async def test_startup_stale_entry_and_receipt_mismatch_fail_closed() -> None:
    provider = StartupFixture((startup_entry(),))
    service = StartupHealthService(provider, clock=lambda: NOW)
    plan = await service.plan_set_enabled("startup:current-user:sample", False)
    provider.entries = (startup_entry(enabled=False),)
    with pytest.raises(StaleStewardshipPlan, match="changed"):
        await service.revalidate(plan)
    with pytest.raises(StewardshipError, match="receipt"):
        service.assert_receipt(plan, "0" * 64)
    with pytest.raises(StaleStewardshipPlan, match="missing"):
        await service.plan_set_enabled("startup:missing", False)


@pytest.mark.asyncio
async def test_startup_provider_failure_is_unavailable_and_wildcards_are_denied() -> None:
    report = await StartupHealthService(FailingStartup()).observe()
    assert report.overall is HealthState.UNAVAILABLE
    service = StartupHealthService(StartupFixture((startup_entry(),)), clock=lambda: NOW)
    with pytest.raises(StewardshipError, match="Wildcard"):
        await service.plan_set_enabled("startup:*", False)


def test_trusted_security_registry_rejects_empty_malformed_and_duplicate_registration() -> None:
    with pytest.raises(StewardshipError, match="empty"):
        TrustedSecurityProviderRegistry(cast(Any, ()))
    with pytest.raises(StewardshipError, match="identity"):
        TrustedSecurityProviderRegistry((cast(Any, object()),))
    with pytest.raises(StewardshipError, match="duplicated"):
        TrustedSecurityProviderRegistry((TrustedUnavailable(), TrustedUnavailable()))


@pytest.mark.asyncio
async def test_trusted_security_registry_quarantines_malformed_provider_result() -> None:
    class MalformedTrusted:
        provider_id = "trusted-malformed"

        async def observe(self) -> object:
            return [finding()]

    result = await TrustedSecurityProviderRegistry(cast(Any, (MalformedTrusted(),))).observe()
    assert result[0].state is SecurityFindingState.UNAVAILABLE


@pytest.mark.asyncio
async def test_update_observation_requires_trusted_newer_identity() -> None:
    packages = PackagesFixture(candidate())
    coordinator = UpdateCoordinator(app_manager(packages), clock=lambda: NOW)
    evidence = await coordinator.observe()
    assert evidence[0].state is HealthState.UPDATE_AVAILABLE
    plan = await coordinator.plan("app:sample")
    assert plan.candidate.version == "2.0.0"
    assert await coordinator.revalidate(plan) == evidence[0]
    assert plan.stages[0].value == "discover"
    assert plan.stages[-1].value == "verify_result"
    assert packages.update_calls == 3


@pytest.mark.asyncio
async def test_update_model_claim_identity_or_version_failure_is_unknown() -> None:
    for item in (candidate(source="model"), candidate(version="0.5.0")):
        evidence = await UpdateCoordinator(
            app_manager(PackagesFixture(item)), clock=lambda: NOW
        ).observe()
        assert evidence[0].state is HealthState.UNKNOWN
        assert evidence[0].candidate is None


@pytest.mark.asyncio
async def test_update_provider_unavailable_and_missing_metadata_stay_truthful() -> None:
    failed = await UpdateCoordinator(
        app_manager(PackagesFixture(error=RuntimeError("offline"))), clock=lambda: NOW
    ).observe()
    assert failed[0].state is HealthState.UNAVAILABLE
    missing = await UpdateCoordinator(app_manager(PackagesFixture()), clock=lambda: NOW).observe()
    assert missing[0].state is HealthState.UNKNOWN
    with pytest.raises(StewardshipError, match="No trusted update"):
        await UpdateCoordinator(app_manager(PackagesFixture()), clock=lambda: NOW).plan(
            "app:sample"
        )


@pytest.mark.asyncio
async def test_update_candidate_change_is_stale_and_invalid_inventory_is_unknown() -> None:
    packages = PackagesFixture(candidate())
    coordinator = UpdateCoordinator(app_manager(packages), clock=lambda: NOW)
    plan = await coordinator.plan("app:sample")
    packages.candidate = candidate("3.0.0")
    with pytest.raises(StaleStewardshipPlan, match="changed"):
        await coordinator.revalidate(plan)
    invalid = await UpdateCoordinator(
        app_manager(
            PackagesFixture(),
            (
                ApplicationRecord(
                    "app:broken", "Broken", None, None, None, "inventory", ApplicationStatus.BROKEN
                ),
            ),
        ),
        clock=lambda: NOW,
    ).observe()
    assert invalid[0].state is HealthState.UNKNOWN


@pytest.mark.asyncio
async def test_update_inventory_failure_is_unavailable_and_application_bridge_is_stale() -> None:
    failed_manager = ApplicationManager(
        FailingInventory(), PackagesFixture(), RuntimeFixture(), InstallationPlanStore()
    )
    unavailable = await UpdateCoordinator(failed_manager, clock=lambda: NOW).observe()
    assert unavailable[0].state is HealthState.UNAVAILABLE
    changing = ChangingPackages()
    with pytest.raises(StaleStewardshipPlan, match="changed"):
        await UpdateCoordinator(app_manager(changing), clock=lambda: NOW).plan_application_update(
            "app:sample"
        )
    with pytest.raises(StewardshipError, match="No trusted update"):
        await UpdateCoordinator(
            app_manager(PackagesFixture()), clock=lambda: NOW
        ).plan_application_update("app:sample")

    class FailsAfterObservation(PackagesFixture):
        def __init__(self) -> None:
            super().__init__(candidate())
            self._calls = 0

        async def find_update(self, record: ApplicationRecord) -> InstallationCandidate | None:
            del record
            self._calls += 1
            if self._calls == 1:
                return candidate()
            raise RuntimeError("provider changed")

    with pytest.raises(StaleStewardshipPlan, match="changed"):
        await UpdateCoordinator(
            app_manager(FailsAfterObservation()), clock=lambda: NOW
        ).plan_application_update("app:sample")

    revalidation_packages = PackagesFixture(candidate())
    coordinator = UpdateCoordinator(app_manager(revalidation_packages), clock=lambda: NOW)
    plan = await coordinator.plan("app:sample")
    assert plan.candidate.version == "2.0.0"
    revalidation_packages.candidate = None
    with pytest.raises(StaleStewardshipPlan, match="no longer"):
        await coordinator.revalidate(plan)


@pytest.mark.asyncio
async def test_software_health_uses_application_manager_read_only_boundary() -> None:
    from jarvis.system_stewardship import SoftwareHealthService

    report = await SoftwareHealthService(app_manager(PackagesFixture())).observe()
    assert report.applications[0].state.value == "healthy"


@pytest.mark.asyncio
async def test_security_empty_and_malformed_provider_evidence_are_not_clean() -> None:
    empty = await SecurityHealthService(EmptySecurity()).observe()
    assert empty.overall is SecurityFindingState.UNKNOWN
    malformed = await SecurityHealthService(cast(SecurityProvider, MalformedSecurity())).observe()
    assert malformed.overall is SecurityFindingState.UNAVAILABLE


def test_security_and_startup_record_validation_is_fail_closed() -> None:
    invalid_security = (
        {"target": ""},
        {"observed_at": NOW.replace(tzinfo=None)},
        {"state": cast(Any, "healthy")},
        {"confidence": 2.0},
    )
    for changes in invalid_security:
        values: dict[str, object] = {
            "provider": "provider",
            "target": "file:x",
            "observed_at": NOW,
            "state": SecurityFindingState.HEALTHY,
            "result_id": "result",
            "detail": "detail",
            "evidence_ref": "ref",
        }
        values.update(changes)
        with pytest.raises(StewardshipError):
            SecurityFinding(**cast(Any, values))
    with pytest.raises(StewardshipError):
        StartupEntryEvidence(
            "entry", "", "provider", True, "target", True, NOW, StartupEntryState.HEALTHY, "detail"
        )
    with pytest.raises(StewardshipError):
        StartupEntryEvidence(
            "entry",
            None,
            "provider",
            cast(Any, "yes"),
            "target",
            True,
            NOW,
            StartupEntryState.HEALTHY,
            "detail",
        )
    with pytest.raises(StewardshipError):
        StartupEntryEvidence(
            "entry",
            None,
            "provider",
            True,
            "target",
            cast(Any, "yes"),
            NOW,
            StartupEntryState.HEALTHY,
            "detail",
        )
    with pytest.raises(StewardshipError):
        StartupEntryEvidence(
            "entry", None, "provider", True, "target", True, NOW, cast(Any, "healthy"), "detail"
        )


@pytest.mark.asyncio
async def test_startup_state_projection_and_plan_validation_cover_unknown_paths() -> None:
    for state, expected in (
        (StartupEntryState.BROKEN, HealthState.BROKEN),
        (StartupEntryState.DEGRADED, HealthState.DEGRADED),
        (StartupEntryState.UNKNOWN, HealthState.UNKNOWN),
    ):
        report = await StartupHealthService(
            StartupFixture((replace(startup_entry(), state=state),))
        ).observe()
        assert report.overall is expected
    service = StartupHealthService(StartupFixture((startup_entry(),)), clock=lambda: NOW)
    plan = await service.plan_set_enabled("startup:current-user:sample", False)
    with pytest.raises(StewardshipError, match="malformed"):
        await service.plan_set_enabled("startup:current-user:sample", False, ttl=timedelta(0))
    with pytest.raises(StewardshipError, match="expiry"):
        replace(plan, expires_at=NOW)
    with pytest.raises(StewardshipError, match="state"):
        replace(plan, previous_enabled=cast(Any, "yes"))
    with pytest.raises(StewardshipError, match="fingerprint"):
        replace(plan, fingerprint="bad")
    malformed = await StartupHealthService(cast(StartupProvider, MalformedStartup())).observe()
    assert malformed.overall is HealthState.UNAVAILABLE


@pytest.mark.asyncio
async def test_update_validation_and_provider_identity_fail_closed() -> None:
    with pytest.raises(StewardshipError, match="trusted package provider"):
        UpdateCoordinator(
            cast(
                Any,
                ApplicationManager(
                    InventoryFixture((record(),)),
                    cast(Any, object()),
                    RuntimeFixture(),
                    InstallationPlanStore(),
                ),
            ),
            clock=lambda: NOW,
        )
    coordinator = UpdateCoordinator(app_manager(PackagesFixture(candidate())), clock=lambda: NOW)
    with pytest.raises(StewardshipError, match="lifetime"):
        await coordinator.plan("app:sample", ttl=timedelta(0))
    invalid_values = (
        {"state": cast(Any, "healthy")},
        {"observed_at": NOW.replace(tzinfo=None)},
        {"candidate_version": ""},
    )
    for changes in invalid_values:
        values: dict[str, object] = {
            "application_id": "app:sample",
            "application_name": "Sample App",
            "current_version": "1.0.0",
            "candidate_version": None,
            "provider": "provider",
            "source": None,
            "state": HealthState.UNKNOWN,
            "detail": "detail",
            "observed_at": NOW,
        }
        values.update(changes)
        with pytest.raises(StewardshipError):
            UpdateEvidence(**cast(Any, values))
    with pytest.raises(StewardshipError, match="candidate"):
        UpdateEvidence(
            "app:sample",
            "Sample App",
            "1.0.0",
            "2.0.0",
            "provider",
            "catalog",
            HealthState.UPDATE_AVAILABLE,
            "detail",
            NOW,
        )


@pytest.mark.asyncio
async def test_update_invalid_candidate_and_identity_paths_remain_unknown() -> None:
    bad = BadCandidate(
        "sample.app",
        "trusted-catalog",
        "Sample App",
        "Sample Publisher",
        "2.0.0",
        (),
        "provider-issued candidate",
        0.9,
        InstallationVerification("Sample App", "Sample Publisher", "2.0.0"),
    )
    invalid_metadata = await UpdateCoordinator(
        app_manager(PackagesFixture(bad)), clock=lambda: NOW
    ).observe()
    assert invalid_metadata[0].state is HealthState.UNKNOWN
    candidates = (
        replace(
            candidate(),
            verification=InstallationVerification("Other", "Sample Publisher", "2.0.0"),
        ),
        replace(
            candidate(),
            verification=InstallationVerification("Sample App", "Other Publisher", "2.0.0"),
        ),
        replace(candidate(), version="not-a-version"),
    )
    for item in candidates:
        result = await UpdateCoordinator(
            app_manager(PackagesFixture(item)), clock=lambda: NOW
        ).observe()
        assert result[0].state is HealthState.UNKNOWN
    plan = await UpdateCoordinator(
        app_manager(PackagesFixture(candidate())), clock=lambda: NOW
    ).plan("app:sample")
    with pytest.raises(StewardshipError, match="fingerprint"):
        replace(plan, fingerprint="bad")


def test_projection_is_read_only_typed_composition() -> None:
    from jarvis.system_stewardship import SoftwareHealthReport

    projection = SystemHealthProjection(
        software=SoftwareHealthReport(()),
        security=SecurityHealthReport((), SecurityFindingState.UNKNOWN),
        startup=StartupHealthReport((), HealthState.UNKNOWN),
        updates=(),
    )
    assert projection.updates == ()


@pytest.mark.asyncio
async def test_integrity_security_adapter_delegates_and_preserves_truthful_failure() -> None:
    passing = IntegrityFixture()
    healthy = await IntegritySecurityProvider(passing).observe()
    assert passing.calls == 1
    assert healthy[0].state is SecurityFindingState.HEALTHY
    assert healthy[0].target == "jarvis-distribution-integrity"
    assert healthy[0].provider == "jarvis-integrity"

    failed = await IntegritySecurityProvider(
        IntegrityFixture(IntegrityEvidenceError("record mismatch"))
    ).observe()
    assert failed[0].state is SecurityFindingState.INTEGRITY_FAILURE
    assert "record mismatch" not in failed[0].detail
    assert failed[0].target == "jarvis-distribution-integrity"


@pytest.mark.asyncio
async def test_trusted_security_registry_preserves_provider_failure_and_rejects_model() -> None:
    registry = TrustedSecurityProviderRegistry(
        (IntegritySecurityProvider(IntegrityFixture()), TrustedUnavailable())
    )
    findings = await registry.observe()
    assert [item.provider for item in findings] == ["jarvis-integrity", "trusted-unavailable"]
    assert findings[1].state is SecurityFindingState.UNAVAILABLE
    with pytest.raises(StewardshipError, match="Model-only"):
        TrustedSecurityProviderRegistry((ModelProvider(),))


def test_windows_startup_provider_uses_a_finite_stable_source_identity() -> None:
    assert len(WindowsStartupProvider.TRUSTED_REGISTRY_SOURCES) == 4
    first = WindowsStartupProvider.entry_id(
        "current-user", WindowsStartupProvider.TRUSTED_REGISTRY_SOURCES[0][1], "JARVIS"
    )
    second = WindowsStartupProvider.entry_id(
        "current-user", WindowsStartupProvider.TRUSTED_REGISTRY_SOURCES[0][1], "JARVIS"
    )
    different_source = WindowsStartupProvider.entry_id(
        "machine", WindowsStartupProvider.TRUSTED_REGISTRY_SOURCES[0][1], "JARVIS"
    )
    assert first == second
    assert first != different_source
    assert "JARVIS" not in first


@pytest.mark.asyncio
async def test_windows_startup_provider_reads_only_bounded_registry_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeKey:
        def __enter__(self) -> "FakeKey":
            return self

        def __exit__(self, *_: object) -> None:
            return None

    def enum_value(_key: FakeKey, index: int) -> tuple[str, str, int]:
        if index == 0:
            return "JARVIS", "do-not-execute", 1
        raise OSError("end")

    fake_winreg = types.SimpleNamespace(
        HKEY_CURRENT_USER=1,
        HKEY_LOCAL_MACHINE=2,
        KEY_READ=4,
        REG_SZ=1,
        REG_EXPAND_SZ=2,
        OpenKey=lambda *_args: FakeKey(),
        EnumValue=enum_value,
    )
    monkeypatch.setitem(sys.modules, "winreg", fake_winreg)
    monkeypatch.setattr(
        WindowsStartupProvider,
        "TRUSTED_REGISTRY_SOURCES",
        (WindowsStartupProvider.TRUSTED_REGISTRY_SOURCES[0],),
    )
    entries = await WindowsStartupProvider().observe()
    assert len(entries) == 1
    assert entries[0].target_command == "do-not-execute"
    assert entries[0].target_exists is None


def test_windows_startup_provider_rejects_malformed_and_ambiguous_registry_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeKey:
        def __enter__(self) -> "FakeKey":
            return self

        def __exit__(self, *_: object) -> None:
            return None

    fake_winreg = types.SimpleNamespace(
        HKEY_CURRENT_USER=1,
        HKEY_LOCAL_MACHINE=2,
        KEY_READ=4,
        REG_SZ=1,
        REG_EXPAND_SZ=2,
        OpenKey=lambda *_args: FakeKey(),
    )
    monkeypatch.setitem(sys.modules, "winreg", fake_winreg)
    monkeypatch.setattr(
        WindowsStartupProvider,
        "TRUSTED_REGISTRY_SOURCES",
        (WindowsStartupProvider.TRUSTED_REGISTRY_SOURCES[0],),
    )

    fake_winreg.EnumValue = lambda _key, _index: ("bad", 7, 1)
    with pytest.raises(StartupProviderError, match="malformed"):
        WindowsStartupProvider._observe_registry()

    def duplicate(_key: FakeKey, index: int) -> tuple[str, str, int]:
        if index < 2:
            return "same", "command", 1
        raise OSError("end")

    fake_winreg.EnumValue = duplicate
    with pytest.raises(StartupProviderError, match="ambiguous"):
        WindowsStartupProvider._observe_registry()

    fake_winreg.OpenKey = lambda *_args: (_ for _ in ()).throw(FileNotFoundError("missing"))
    assert WindowsStartupProvider._observe_registry() == ()
    fake_winreg.OpenKey = lambda *_args: (_ for _ in ()).throw(OSError("denied"))
    with pytest.raises(StartupProviderError, match="unavailable"):
        WindowsStartupProvider._observe_registry()


def test_real_composition_factory_uses_explicit_trusted_owners() -> None:
    from jarvis.system_stewardship import create_real_windows_system_stewardship

    composition = create_real_windows_system_stewardship(
        integrity_evidence=IntegrityFixture(),
    )
    assert composition.startup_effect is StartupEffectStatus.NOT_YET_TRUSTED


@pytest.mark.asyncio
async def test_composition_refresh_is_read_only_and_update_plan_uses_app_manager_boundary() -> None:
    packages = PackagesFixture(candidate())
    composition = create_system_stewardship_composition(
        app_manager(packages),
        integrity_evidence=IntegrityFixture(),
        startup_provider=StartupFixture((startup_entry(),)),
        clock=lambda: NOW,
    )
    projection = await composition.refresh()
    assert projection.software.applications[0].state.value == "healthy"
    assert projection.security.findings[0].provider == "jarvis-integrity"
    assert projection.security.findings[-1].state is SecurityFindingState.UNAVAILABLE
    assert projection.startup.entries[0].entry_id == "startup:current-user:sample"
    assert composition.startup_effect is StartupEffectStatus.NOT_YET_TRUSTED

    application_plan = await composition.plan_application_update("app:sample")
    assert application_plan.kind.value == "update"
    assert application_plan.candidate == candidate()
    assert packages.update_calls == 3


@pytest.mark.asyncio
async def test_startup_provider_unavailable_is_not_a_mutation_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = WindowsStartupProvider()
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(StartupProviderError, match="unavailable"):
        await provider.observe()
