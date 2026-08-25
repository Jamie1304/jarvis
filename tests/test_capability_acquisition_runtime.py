from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

import pytest
from jarvis.capabilities import (
    CapabilityHealth,
    CapabilityLifecycle,
    CapabilityManifest,
    CapabilityRegistry,
    EffectClassification,
    EffectMetadata,
    EnvironmentGraph,
    Reversibility,
)
from jarvis.capability_acquisition import (
    AcquisitionScope,
    AcquisitionStage,
    CapabilityAcquisitionCoordinator,
    CapabilityAcquisitionServices,
    SolutionDiscovery,
    VerificationEvidenceProvider,
)
from jarvis.capability_factory import (
    AdoptionCandidates,
    CapabilityFactory,
    CapabilityFactoryResult,
    FactoryLifecycle,
    FactoryStrategy,
    GeneratedCapabilityPackage,
    SolutionOption,
    SolutionReport,
    WorkspaceContext,
)
from jarvis.discovery.models import (
    ArchitectureFit,
    CandidateProvenance,
    CapabilityGap,
    DiscoveryCandidate,
    DiscoveryEvidence,
    DiscoverySource,
    MaintenanceStatus,
    RecommendationClass,
    Testability,
)
from jarvis.discovery.providers import StaticCatalogDiscoveryProvider
from jarvis.discovery.service import (
    CandidateEvaluator,
    CapabilityDiscoveryService,
    CapabilityGapDetector,
)
from jarvis.effect_attestation import EffectAttestationStore
from jarvis.environment_discovery import EnvironmentDiscoveryService
from jarvis.goal_supervisor import (
    CapabilityAcquisitionRequest,
    GoalAnalysis,
    GoalIntent,
    GoalSupervisorValidationError,
)
from jarvis.integration_package import IntegrationPackage
from jarvis.package_activation import (
    ActivationHooks,
    ActivationRequest,
    CanaryExecution,
    CanaryLimits,
    PackageActivationService,
    ShadowExecution,
)
from jarvis.package_certification import (
    BuiltPackage,
    CertificationHooks,
    CertificationRecord,
    CertificationStage,
    CertificationStageResult,
    PackageCertifier,
)
from jarvis.package_reviewer import GeneratedPackageReviewer, PackageSourceFile
from jarvis.package_runtime import HotLoadManager, PreparedPackageRuntime
from jarvis.permissions.models import Risk
from jarvis.provisioning import (
    ProvisioningAuthorization,
    ProvisioningEngine,
    ProvisioningPlan,
    ProvisioningProvider,
    ProvisioningResult,
)
from jarvis.setup_conductor import InMemorySetupStore, SetupConductor, SetupHandler
from jarvis.tools.models import SemanticVersion, ToolHealthStatus, ToolPlatform
from jarvis.verification import EvidenceRecord, EvidenceType, VerificationEngine, VerificationLevel


class _Generator:
    async def generate(
        self,
        gap: CapabilityGap,
        solution: SolutionReport,
        workspace: WorkspaceContext,
        environment: EnvironmentGraph,
        preferences: Mapping[str, object],
        strategy: FactoryStrategy,
    ) -> GeneratedCapabilityPackage:
        del gap, solution, workspace, environment, preferences, strategy
        raise AssertionError("an existing capability must be reused before generation")


class _BuiltGenerator:
    def __init__(self, package: IntegrationPackage) -> None:
        self.package = package

    async def generate(
        self,
        gap: CapabilityGap,
        solution: SolutionReport,
        workspace: WorkspaceContext,
        environment: EnvironmentGraph,
        preferences: Mapping[str, object],
        strategy: FactoryStrategy,
    ) -> GeneratedCapabilityPackage:
        del gap, solution, workspace, environment, preferences, strategy
        return GeneratedCapabilityPackage(self.package, True, True, True, "random-fixture")


class _SourceProvider:
    def __init__(self, source: PackageSourceFile) -> None:
        self.source = source

    def sources(self, package: IntegrationPackage) -> tuple[PackageSourceFile, ...]:
        del package
        return (self.source,)


class _CertificationHooks:
    def __init__(self, source: PackageSourceFile) -> None:
        self.source = source

    def hooks(self, package: IntegrationPackage) -> CertificationHooks:
        def stage(name: CertificationStage) -> CertificationStageResult:
            if name is CertificationStage.AUTHORITY_DECISION:
                return CertificationStageResult(
                    True,
                    ("trusted fixture authority",),
                    "approval:random-fixture",
                    shadow_eligible=True,
                    canary_eligible=True,
                )
            return CertificationStageResult(True, (f"{name.value} passed",))

        return CertificationHooks(
            build=lambda item: BuiltPackage(item, (self.source,)),
            unit_tests=lambda item: stage(CertificationStage.UNIT_TESTS),
            sandbox_integration_test=lambda item: stage(
                CertificationStage.SANDBOX_INTEGRATION_TEST
            ),
            permission_diff=lambda item: stage(CertificationStage.PERMISSION_DIFF),
            authority_decision=lambda item: stage(CertificationStage.AUTHORITY_DECISION),
            install=lambda item: stage(CertificationStage.INSTALL),
            healthcheck=lambda item: stage(CertificationStage.HEALTHCHECK),
            verification=lambda item: stage(CertificationStage.VERIFICATION),
        )


class _ActivationRequest:
    def __init__(self, source: PackageSourceFile) -> None:
        self.source = source

    def request(
        self,
        package: IntegrationPackage,
        certification: CertificationRecord,
        source_files: tuple[PackageSourceFile, ...],
    ) -> ActivationRequest:
        del source_files
        return ActivationRequest(
            package,
            certification,
            (self.source,),
            CanaryLimits(
                "random-fixture", max_calls=1, max_effects=1, max_budget=10, max_wall_seconds=5.0
            ),
        )


class _Manifest:
    def __init__(self, capability_id: str) -> None:
        self.capability_id = capability_id

    def manifest(
        self, package: IntegrationPackage, request: CapabilityAcquisitionRequest
    ) -> CapabilityManifest:
        del package, request
        return _manifest(self.capability_id)


def _generated_coordinator(
    registry: CapabilityRegistry,
    package: IntegrationPackage,
    source: PackageSourceFile,
    activation: object,
) -> CapabilityAcquisitionCoordinator:
    setup = SetupConductor(
        {"fixture": cast(SetupHandler, object())},
        InMemorySetupStore(),
        cast(Callable[[ProvisioningPlan], Awaitable[ProvisioningResult]], object()),
    )
    hot_load = HotLoadManager(_RuntimeFactory(), _Surface())
    return CapabilityAcquisitionCoordinator(
        CapabilityAcquisitionServices(
            registry,
            CapabilityGapDetector(frozenset()),
            EnvironmentDiscoveryService(()),
            SolutionDiscovery(CapabilityDiscoveryService((), CandidateEvaluator())),
            CapabilityFactory(registry, setup, _BuiltGenerator(package)),
            GeneratedPackageReviewer(),
            PackageCertifier(),
            setup,
            ProvisioningEngine(
                cast(Mapping[str, ProvisioningProvider], {"fixture": object()}),
                cast(ProvisioningAuthorization, object()),
            ),
            cast(PackageActivationService, activation),
            hot_load,
            VerificationEngine(),
        ),
        scope_provider=_Scope(),
        source_provider=_SourceProvider(source),
        certification_hooks=_CertificationHooks(source),
        activation_requests=_ActivationRequest(source),
        manifest_provider=_Manifest(package.package_id),
        verification_evidence=_Evidence(),
    )


class _Scope:
    async def scope(self, intent: GoalIntent, gap: CapabilityGap) -> AcquisitionScope:
        del intent, gap
        return AcquisitionScope(WorkspaceContext("random-fixture"), EnvironmentGraph())


class _Evidence:
    async def collect(
        self, capability_id: str, original_goal: str, stage: AcquisitionStage
    ) -> tuple[EvidenceRecord, ...]:
        return (
            EvidenceRecord(
                EvidenceType.CUSTOM,
                f"trusted-fixture-health:{capability_id}:{stage.value}",
                datetime.now(UTC),
                timedelta(minutes=5),
                1.0,
                f"capability:{capability_id}",
                f"capability:{capability_id}",
                level=VerificationLevel.INTEGRATION_VERIFIED,
            ),
        )


class _RuntimeFactory:
    def prepare(self, package: object) -> PreparedPackageRuntime:
        raise AssertionError(f"activation is not used by reuse fixture: {package!r}")


class _Surface:
    def atomic_swap(self, package: object, runtime: PreparedPackageRuntime) -> None:
        del package, runtime

    def rollback(self, package: object, runtime: PreparedPackageRuntime | None) -> None:
        del package, runtime

    def remove(self, package: object, runtime: PreparedPackageRuntime) -> None:
        del package, runtime


def _disabled_shadow(*args: object, **kwargs: object) -> ShadowExecution:
    del args, kwargs
    raise AssertionError("activation is not used by reuse fixture")


def _disabled_canary(*args: object, **kwargs: object) -> CanaryExecution:
    del args, kwargs
    raise AssertionError("activation is not used by reuse fixture")


def _manifest(capability_id: str) -> CapabilityManifest:
    return CapabilityManifest(
        capability_id,
        "Random local capability",
        SemanticVersion(1, 0, 0),
        "trusted-fixture-owner",
        ("inspect",),
        {"input": "object"},
        {"output": "object"},
        (),
        Risk.LOW,
        frozenset({ToolPlatform.WINDOWS}),
        False,
        (),
        (),
        (),
        (),
        CapabilityHealth(ToolHealthStatus.AVAILABLE, "fixture health"),
        ("trusted fixture health",),
        (),
        ("synthetic fixture",),
        "fixture-hash",
        CapabilityLifecycle.ACTIVE,
        EffectMetadata(EffectClassification.OBSERVATION, Reversibility.READ_ONLY),
        confidence=1.0,
        last_verified=datetime.now(UTC),
    )


def _coordinator(registry: CapabilityRegistry) -> CapabilityAcquisitionCoordinator:
    setup = SetupConductor(
        {"fixture": cast(SetupHandler, object())},
        InMemorySetupStore(),
        cast(Callable[[ProvisioningPlan], Awaitable[ProvisioningResult]], object()),
    )
    hot_load = HotLoadManager(_RuntimeFactory(), _Surface())
    activation = PackageActivationService(
        hot_load,
        ActivationHooks(_disabled_shadow, _disabled_canary),
        attestation_store=EffectAttestationStore(),
    )
    return CapabilityAcquisitionCoordinator(
        CapabilityAcquisitionServices(
            registry,
            CapabilityGapDetector(frozenset()),
            EnvironmentDiscoveryService(()),
            SolutionDiscovery(CapabilityDiscoveryService((), CandidateEvaluator())),
            CapabilityFactory(registry, setup, _Generator()),
            GeneratedPackageReviewer(),
            PackageCertifier(),
            setup,
            ProvisioningEngine(
                cast(Mapping[str, ProvisioningProvider], {"fixture": object()}),
                cast(ProvisioningAuthorization, object()),
            ),
            activation,
            hot_load,
            VerificationEngine(),
        ),
        scope_provider=_Scope(),
        verification_evidence=_Evidence(),
    )


@pytest.mark.asyncio
async def test_production_coordinator_researches_then_reuses_random_existing_capability() -> None:
    capability_id = f"fixture-{uuid4().hex}"
    registry = CapabilityRegistry((_manifest(capability_id),))
    coordinator = _coordinator(registry)
    intent = GoalIntent(
        "Complete a random local capability goal", required_capabilities=(capability_id,)
    )
    gap = CapabilityGap(capability_id, intent.original_outcome, ("inspect",), (), Risk.LOW, ())

    research = await coordinator.research(intent, GoalAnalysis(gap))
    assert research.acquisition is not None
    report = await coordinator.acquire(
        CapabilityAcquisitionRequest(
            gap,
            SolutionReport(gap, ()),
            AdoptionCandidates(),
            WorkspaceContext("random-fixture"),
            EnvironmentGraph(),
            {},
            goal_id=intent.goal_id,
        )
    )

    assert report.active, report.detail
    assert report.capability_id == capability_id
    assert coordinator.last_run is not None
    assert coordinator.last_run.stage is AcquisitionStage.ACTIVE
    assert coordinator.last_run.original_goal == intent.original_outcome


@pytest.mark.asyncio
async def test_solution_discovery_converts_evidence_to_reuse_option() -> None:
    candidate = DiscoveryCandidate(
        "random capability",
        DiscoverySource.INTEGRATION_CATALOG,
        "random-candidate",
        CandidateProvenance(
            DiscoverySource.INTEGRATION_CATALOG,
            "fixture:random-candidate",
            datetime.now(UTC),
            (DiscoveryEvidence("fixture", "synthetic candidate"),),
            owner_verified=True,
        ),
        "fixture-owner",
        (),
        (),
        ArchitectureFit.COMPATIBLE,
        1.0,
        Testability.DETERMINISTIC,
        MaintenanceStatus.ACTIVE,
    )
    service = SolutionDiscovery(
        CapabilityDiscoveryService(
            (StaticCatalogDiscoveryProvider(DiscoverySource.INTEGRATION_CATALOG, (candidate,)),),
            CandidateEvaluator(),
        )
    )
    gap = CapabilityGap("random", "inspect random", (), (), Risk.LOW, ())
    result = await service.discover(gap, EnvironmentGraph())

    assert result.solution.options[0].strategy is FactoryStrategy.REUSE_API_LIBRARY_MCP_CLI
    assert result.solution.options[0].safe
    assert RecommendationClass.RECOMMENDED.value in result.evidence[0]


@pytest.mark.asyncio
async def test_coordinator_research_without_gap_is_advisory_only() -> None:
    coordinator = _coordinator(CapabilityRegistry())
    research = await coordinator.research(GoalIntent("No acquisition needed"), GoalAnalysis())
    assert research.acquisition is None
    assert research.evidence == ("no capability gap requires acquisition",)


def _acquisition_request(capability_id: str) -> CapabilityAcquisitionRequest:
    gap = CapabilityGap(capability_id, "inspect a random fixture", ("inspect",), (), Risk.LOW, ())
    return CapabilityAcquisitionRequest(
        gap,
        SolutionReport(gap, ()),
        AdoptionCandidates(),
        WorkspaceContext("random-fixture"),
        EnvironmentGraph(),
        {},
    )


class _ResultFactory:
    def __init__(self, result: CapabilityFactoryResult) -> None:
        self.result = result

    async def acquire(self, *args: object, **kwargs: object) -> CapabilityFactoryResult:
        del args, kwargs
        return self.result


class _EmptyEvidence:
    async def collect(
        self, capability_id: str, original_goal: str, stage: AcquisitionStage
    ) -> tuple[EvidenceRecord, ...]:
        del capability_id, original_goal, stage
        return ()


@pytest.mark.asyncio
async def test_coordinator_rejects_malformed_request_and_inactive_factory_result() -> None:
    coordinator = _coordinator(CapabilityRegistry())
    with pytest.raises(GoalSupervisorValidationError):
        await coordinator.acquire(cast(CapabilityAcquisitionRequest, object()))

    request = _acquisition_request(f"fixture-{uuid4().hex}")
    result = CapabilityFactoryResult(
        uuid4(), request.gap, FactoryLifecycle.READY_FOR_APPROVAL, None, None, reason="deferred"
    )
    coordinator._services = replace(
        coordinator._services, factory=cast(CapabilityFactory, _ResultFactory(result))
    )
    report = await coordinator.acquire(request)
    assert not report.active
    assert "did not produce an active package" in report.detail
    assert coordinator.last_run is not None
    assert coordinator.last_run.stage is AcquisitionStage.FAILED


@pytest.mark.asyncio
async def test_reused_capability_requires_independent_evidence_and_can_fail_verification() -> None:
    capability_id = f"fixture-{uuid4().hex}"
    request = _acquisition_request(capability_id)
    result = CapabilityFactoryResult(
        uuid4(),
        request.gap,
        FactoryLifecycle.ACTIVE,
        FactoryStrategy.REUSE_JARVIS,
        capability_id,
    )

    no_evidence = _coordinator(CapabilityRegistry())
    no_evidence._services = replace(
        no_evidence._services,
        factory=cast(CapabilityFactory, _ResultFactory(result)),
    )
    no_evidence._evidence = None
    report = await no_evidence.acquire(request)
    assert not report.active
    assert "no trusted verification collector" in report.detail

    failed = _coordinator(CapabilityRegistry())
    failed._services = replace(
        failed._services,
        factory=cast(CapabilityFactory, _ResultFactory(result)),
    )
    failed._evidence = cast(VerificationEvidenceProvider, _EmptyEvidence())
    report = await failed.acquire(request)
    assert not report.active
    assert "independently verified" in report.detail
    assert failed.last_run is not None
    assert failed.last_run.stage is AcquisitionStage.FAILED


@pytest.mark.asyncio
async def test_production_coordinator_builds_certifies_stages_and_verifies_random_fixture() -> None:
    from tests.test_package_activation import package as activation_package
    from tests.test_package_activation import setup as activation_setup

    package, source = activation_package((2, 0, 0))
    activation, _, _ = activation_setup()
    capability_id = f"fixture-{uuid4().hex}"
    registry = CapabilityRegistry()
    coordinator = _generated_coordinator(registry, package, source, activation)
    intent = GoalIntent(
        "Verify a random generated capability", required_capabilities=(capability_id,)
    )
    gap = CapabilityGap(capability_id, intent.original_outcome, ("inspect",), (), Risk.LOW, ())

    report = await coordinator.acquire(
        CapabilityAcquisitionRequest(
            gap,
            SolutionReport(
                gap,
                (SolutionOption("build-fixture", FactoryStrategy.GENERATE_ADAPTER, capability_id),),
            ),
            AdoptionCandidates(),
            WorkspaceContext("random-fixture"),
            EnvironmentGraph(),
            {},
            goal_id=intent.goal_id,
        )
    )

    assert report.active, report.detail
    assert report.capability_id == package.package_id
    assert coordinator.last_run is not None
    assert coordinator.last_run.stage is AcquisitionStage.ACTIVE
    assert coordinator.last_run.certification is not None
    assert coordinator.last_run.activation is not None
