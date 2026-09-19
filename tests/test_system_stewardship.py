"""Focused evidence and authority tests for R3C system stewardship."""

import asyncio
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
from jarvis.system_stewardship import (
    HealthState,
    SecurityFinding,
    SecurityFindingState,
    SecurityHealthReport,
    SecurityHealthService,
    SecurityProvider,
    StaleStewardshipPlan,
    StartupEntryEvidence,
    StartupEntryState,
    StartupHealthReport,
    StartupHealthService,
    StartupProvider,
    StewardshipError,
    SystemHealthProjection,
    UpdateCoordinator,
    UpdateEvidence,
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
