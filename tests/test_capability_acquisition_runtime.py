from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
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
    AcquisitionRun,
    AcquisitionScope,
    AcquisitionStage,
    CapabilityAcquisitionCoordinator,
    CapabilityAcquisitionError,
    CapabilityAcquisitionServices,
    EnvironmentAdoptionCandidateProvider,
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
from jarvis.environment_discovery import (
    DiscoveryConfidence,
    DiscoveryMode,
    DiscoveryObservation,
    EnvironmentDiscoveryService,
    EnvironmentIdentity,
)
from jarvis.events import InMemoryEventBus
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
    ActivationState,
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
from jarvis.package_reviewer import GeneratedPackageReviewer, PackageSourceFile, ReviewDecision
from jarvis.package_runtime import HotLoadManager, PreparedPackageRuntime
from jarvis.permissions.models import Risk
from jarvis.provisioning import (
    ProvisioningAuthorization,
    ProvisioningEngine,
    ProvisioningPlan,
    ProvisioningProvider,
    ProvisioningResult,
)
from jarvis.setup_conductor import (
    InMemorySetupStore,
    SetupConductor,
    SetupHandler,
    SetupRun,
    SetupRunState,
    SetupStep,
)
from jarvis.tools.models import SemanticVersion, ToolHealthStatus, ToolPlatform
from jarvis.trace import TraceError, TraceService, TraceStore
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
    def __init__(self, source: PackageSourceFile, failed: CertificationStage | None = None) -> None:
        self.source = source
        self.failed = failed

    def hooks(self, package: IntegrationPackage) -> CertificationHooks:
        def stage(name: CertificationStage) -> CertificationStageResult:
            if name is self.failed:
                return CertificationStageResult(False, (f"synthetic {name.value} rejection",))
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
    certification_hooks: _CertificationHooks | None = None,
    trace: TraceService | None = None,
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
        certification_hooks=certification_hooks or _CertificationHooks(source),
        activation_requests=_ActivationRequest(source),
        manifest_provider=_Manifest(package.package_id),
        verification_evidence=_Evidence(),
        trace=trace,
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


def _coordinator(
    registry: CapabilityRegistry, trace: TraceService | None = None
) -> CapabilityAcquisitionCoordinator:
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
        trace=trace,
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
async def test_solution_discovery_rejects_candidates_and_falls_back_to_build() -> None:
    with pytest.raises(CapabilityAcquisitionError, match="Build setup step"):
        SolutionDiscovery(cast(Any, object()), build_setup_step=cast(Any, object()))

    class _RejectedDiscovery:
        async def recommend(self, gap: CapabilityGap) -> object:
            candidate = SimpleNamespace(identity="rejected", capability_provided="bad")
            evaluation = SimpleNamespace(
                candidate=candidate, classification=RecommendationClass.REJECTED
            )
            return SimpleNamespace(evaluated_candidates=(evaluation,))

    gap = CapabilityGap("missing", "inspect missing", (), (), Risk.LOW, ())
    result = await SolutionDiscovery(cast(Any, _RejectedDiscovery())).discover(
        gap, EnvironmentGraph()
    )
    assert result.solution.options[0].strategy is FactoryStrategy.GENERATE_ADAPTER
    assert result.solution.options[0].capability_id == "missing"
    assert "fallback:build" in result.evidence[-1]


def test_environment_adoption_candidates_skip_unusable_observations() -> None:
    now = datetime.now(UTC)
    runtime_identity = EnvironmentIdentity(
        "runtime", "runtime", (("executable", "C:/python.exe"), ("version", "3.12"))
    )
    runtime_observation = DiscoveryObservation(
        DiscoverySource.WINDOWS_LOCAL,
        now,
        runtime_identity,
        (("kind", "python-runtime"),),
        "runtime",
        "fixture",
        now,
        now,
        ("fixture",),
        DiscoveryConfidence(1.0, "fixture"),
    )
    no_location = SimpleNamespace(
        identity=EnvironmentIdentity("no-location", "device", (("version", "1"),)),
        observations=(runtime_observation,),
    )
    usable = SimpleNamespace(identity=runtime_identity, observations=(runtime_observation,))

    class _Discovery:
        def discover(self, mode: DiscoveryMode) -> tuple[object, ...]:
            assert mode is DiscoveryMode.READ_ONLY_LOCAL_DISCOVERY
            return (usable, no_location)

    provider = EnvironmentAdoptionCandidateProvider(cast(Any, _Discovery()))
    gap = CapabilityGap("python runtime", "use runtime", (), (), Risk.LOW, ())
    candidates = provider.for_gap(gap, EnvironmentGraph())
    assert len(candidates.candidates) == 1
    assert provider.for_setup(SetupStep("setup", "runtime"), cast(Any, SimpleNamespace()))
    skipped = provider.for_gap(
        CapabilityGap("camera", "observe camera", (), (), Risk.LOW, ()), EnvironmentGraph()
    )
    assert skipped.candidates == ()


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
async def test_prepare_preserves_typed_review_and_certification_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_package_activation import package as activation_package
    from tests.test_package_activation import setup as activation_setup

    package, source = activation_package((2, 0, 0))
    activation, _, _ = activation_setup()
    request = _acquisition_request(f"fixture-{uuid4().hex}")

    with pytest.raises(GoalSupervisorValidationError, match="preparation request"):
        await _generated_coordinator(CapabilityRegistry(), package, source, activation).prepare(
            cast(Any, object())
        )

    empty = _generated_coordinator(CapabilityRegistry(), package, source, activation)
    empty_result = CapabilityFactoryResult(
        uuid4(), request.solution.gap, FactoryLifecycle.READY_FOR_APPROVAL, None, None
    )
    empty._services = replace(  # noqa: SLF001
        empty._services, factory=cast(CapabilityFactory, _ResultFactory(empty_result))
    )
    report = await empty.prepare(request)
    assert not report.active
    assert "candidate" in report.detail.casefold()

    missing_sources = _generated_coordinator(CapabilityRegistry(), package, source, activation)
    built_result = CapabilityFactoryResult(
        uuid4(),
        request.solution.gap,
        FactoryLifecycle.READY_FOR_APPROVAL,
        FactoryStrategy.GENERATE_ADAPTER,
        request.gap.desired_capability,
        package=GeneratedCapabilityPackage(package, True, True, True, "fixture"),
    )
    missing_sources._services = replace(  # noqa: SLF001
        missing_sources._services, factory=cast(CapabilityFactory, _ResultFactory(built_result))
    )
    missing_sources._sources = None  # noqa: SLF001
    report = await missing_sources.prepare(request)
    assert "trusted package boundaries" in report.detail

    rejected = _generated_coordinator(CapabilityRegistry(), package, source, activation)
    rejected._services = replace(  # noqa: SLF001
        rejected._services, factory=cast(CapabilityFactory, _ResultFactory(built_result))
    )
    monkeypatch.setattr(
        rejected._services.package_reviewer,
        "review",
        cast(Any, lambda *args, **kwargs: SimpleNamespace(decision=ReviewDecision.REJECT)),
    )
    report = await rejected.prepare(request)
    assert "reviewer" in report.detail

    failed_certification = _generated_coordinator(
        CapabilityRegistry(),
        package,
        source,
        activation,
        certification_hooks=_CertificationHooks(source, failed=CertificationStage.UNIT_TESTS),
    )
    failed_certification._services = replace(  # noqa: SLF001
        failed_certification._services,
        factory=cast(CapabilityFactory, _ResultFactory(built_result)),
    )
    report = await failed_certification.prepare(request)
    assert not report.active
    assert "certification failed" in report.detail

    class _BrokenCertifier:
        def certify(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            raise RuntimeError("certifier unavailable")

    generic_prepare = _generated_coordinator(CapabilityRegistry(), package, source, activation)
    generic_prepare._services = replace(  # noqa: SLF001
        generic_prepare._services,
        factory=cast(CapabilityFactory, _ResultFactory(built_result)),
        package_certifier=cast(Any, _BrokenCertifier()),
    )
    report = await generic_prepare.prepare(request)
    assert "failed closed" in report.detail

    generic_acquire = _generated_coordinator(CapabilityRegistry(), package, source, activation)
    generic_acquire._services = replace(  # noqa: SLF001
        generic_acquire._services, package_certifier=cast(Any, _BrokenCertifier())
    )
    report = await generic_acquire.acquire(
        replace(
            request,
            solution=SolutionReport(
                request.gap,
                (
                    SolutionOption(
                        "build-fixture",
                        FactoryStrategy.GENERATE_ADAPTER,
                        request.gap.desired_capability,
                    ),
                ),
            ),
        )
    )
    assert "certification failed" in report.detail


@pytest.mark.asyncio
async def test_acquisition_setup_states_and_report_helpers_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_package_activation import package as activation_package
    from tests.test_package_activation import setup as activation_setup

    package, source = activation_package((2, 0, 0))
    activation, _, _ = activation_setup()
    request = _acquisition_request(f"fixture-{uuid4().hex}")
    setup_step = SetupStep("setup-fixture", "fixture")

    async def run_with_state(
        coordinator: CapabilityAcquisitionCoordinator, state: SetupRunState
    ) -> object:
        async def fake_run(*args: object) -> SetupRun:
            del args
            return SetupRun(uuid4(), "fixture", None, state)

        monkeypatch.setattr(coordinator, "_run_setup", fake_run)  # noqa: SLF001
        option = SolutionOption(
            "build-fixture",
            FactoryStrategy.GENERATE_ADAPTER,
            request.gap.desired_capability,
            requires_setup=True,
            setup_step=setup_step,
        )
        result = await coordinator.acquire(
            replace(request, solution=SolutionReport(request.gap, (option,)))
        )
        return result

    waiting = await run_with_state(
        _generated_coordinator(CapabilityRegistry(), package, source, activation),
        SetupRunState.WAITING_DECISIONS,
    )
    assert "decisions" in cast(Any, waiting).detail
    failed = await run_with_state(
        _generated_coordinator(CapabilityRegistry(), package, source, activation),
        SetupRunState.FAILED,
    )
    assert "did not complete" in cast(Any, failed).detail

    coordinator = _coordinator(CapabilityRegistry())
    factory_result = CapabilityFactoryResult(
        uuid4(), request.gap, FactoryLifecycle.READY_FOR_APPROVAL, None, None
    )
    waiting_report = coordinator._waiting_report(  # noqa: SLF001
        factory_result, "approval required"
    )
    assert waiting_report.stage == AcquisitionStage.WAITING_FOR_APPROVAL.value
    coordinator._update(stage=AcquisitionStage.FAILED)  # noqa: SLF001


@pytest.mark.asyncio
async def test_acquisition_activation_registration_and_verification_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_package_activation import package as activation_package
    from tests.test_package_activation import setup as activation_setup

    package, source = activation_package((2, 0, 0))
    request = _acquisition_request(f"fixture-{uuid4().hex}")
    option = SolutionOption(
        "build-fixture", FactoryStrategy.GENERATE_ADAPTER, request.gap.desired_capability
    )
    request = replace(request, solution=SolutionReport(request.gap, (option,)))

    class _StagedActivation:
        def __init__(self, promotion_state: ActivationState = ActivationState.ACTIVE) -> None:
            self.promotion_state = promotion_state
            self.quarantine_calls = 0

        def register_certified(self, request: object) -> None:
            del request

        def run_shadow(self, package_id: str, version: object) -> object:
            del package_id, version
            return SimpleNamespace(state=ActivationState.SHADOW)

        def run_canary(self, package_id: str, version: object) -> object:
            del package_id, version
            return SimpleNamespace(state=ActivationState.CANARY)

        def promote(self, package_id: str, version: object) -> object:
            del package_id, version
            return SimpleNamespace(state=self.promotion_state)

        def quarantine(self, package_id: str, version: object, reason: str) -> None:
            del package_id, version, reason
            self.quarantine_calls += 1
            raise RuntimeError("quarantine unavailable")

    def build() -> tuple[CapabilityAcquisitionCoordinator, _StagedActivation]:
        activation, _, _ = activation_setup()
        coordinator = _generated_coordinator(CapabilityRegistry(), package, source, activation)
        staged = _StagedActivation()
        coordinator._services = replace(  # noqa: SLF001
            coordinator._services, package_activation=cast(Any, staged)
        )
        return coordinator, staged

    not_active, _ = build()
    not_active._services = replace(  # noqa: SLF001
        not_active._services,
        package_activation=cast(Any, _StagedActivation(ActivationState.QUARANTINED)),
    )
    report = await not_active.acquire(request)
    assert "ACTIVE" in report.detail

    activation_error, _ = build()
    broken = cast(Any, activation_error._services.package_activation)  # noqa: SLF001
    broken.promote = lambda *args: (_ for _ in ()).throw(RuntimeError("promote failed"))
    report = await activation_error.acquire(request)
    assert "staged activation failed" in report.detail

    collision, _ = build()
    monkeypatch.setattr(collision._services.registry, "inspect", lambda _: object())  # noqa: SLF001
    report = await collision.acquire(request)
    assert "collided" in report.detail

    registration_error, _ = build()

    def fail_inspect(_: str) -> object:
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr(registration_error._services.registry, "inspect", fail_inspect)  # noqa: SLF001
    report = await registration_error.acquire(request)
    assert "registration failed" in report.detail

    no_evidence, _ = build()
    no_evidence._evidence = None  # noqa: SLF001
    report = await no_evidence.acquire(request)
    assert "verification collector" in report.detail

    quarantine, staged = build()
    quarantine._evidence = cast(VerificationEvidenceProvider, _EmptyEvidence())  # noqa: SLF001
    report = await quarantine.acquire(request)
    assert "verification failed" in report.detail
    assert staged.quarantine_calls == 1


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


@pytest.mark.asyncio
async def test_certification_failure_is_typed_and_leaves_no_activation_authority() -> None:
    from tests.test_package_activation import package as activation_package
    from tests.test_package_activation import setup as activation_setup

    package, source = activation_package((2, 0, 0))
    activation, _, _ = activation_setup()
    capability_id = f"fixture-{uuid4().hex}"
    registry = CapabilityRegistry()
    coordinator = _generated_coordinator(
        registry,
        package,
        source,
        activation,
        certification_hooks=_CertificationHooks(
            source, failed=CertificationStage.SANDBOX_INTEGRATION_TEST
        ),
    )
    intent = GoalIntent(
        "Reject a random generated capability before activation",
        required_capabilities=(capability_id,),
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

    assert not report.active
    assert "gate=SANDBOX_INTEGRATION_TEST" in report.detail
    assert "CERTIFICATION_SANDBOX_INTEGRATION_TEST_FAILED" in report.detail
    assert coordinator.last_run is not None
    assert coordinator.last_run.stage is AcquisitionStage.FAILED
    assert coordinator.last_run.activation is None
    assert coordinator.last_run.certification is None
    assert coordinator.last_run.package_hash == package.package_hash
    assert registry.manifests() == ()
    assert coordinator.flight_recorder is not None
    operations = [item.operation for item in coordinator.flight_recorder.records()]
    assert "certification_failed" in operations
    assert "post_cleanup_terminal" in operations
    from jarvis.acceptance.evidence import collect_qualification_failure

    failure_evidence = collect_qualification_failure(
        coordinator,
        qualification_run_id="failure-control",
        failure_stage="SANDBOX_INTEGRATION_TEST",
        typed_failure_code="CERTIFICATION_SANDBOX_INTEGRATION_TEST_FAILED",
    )
    assert failure_evidence.result == "EXECUTION_FAILURE"
    assert failure_evidence.active is False
    assert failure_evidence.activation_id is None
    assert failure_evidence.package_hash == package.package_hash


@pytest.mark.asyncio
async def test_acquisition_rejects_activation_and_verification_boundary_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_package_activation import package as activation_package
    from tests.test_package_activation import setup as activation_setup

    def build(
        *, activation_options: Mapping[str, object] | None = None
    ) -> tuple[
        CapabilityAcquisitionCoordinator,
        CapabilityAcquisitionRequest,
    ]:
        package, source = activation_package((2, 0, 0))
        activation, _, _ = activation_setup(**cast(Any, activation_options or {}))
        capability_id = f"fixture-{uuid4().hex}"
        coordinator = _generated_coordinator(CapabilityRegistry(), package, source, activation)
        request = _acquisition_request(capability_id)
        return coordinator, replace(
            request,
            solution=SolutionReport(
                request.solution.gap,
                (SolutionOption("build-fixture", FactoryStrategy.GENERATE_ADAPTER, capability_id),),
            ),
        )

    rejected, request = build()
    monkeypatch.setattr(
        rejected._services.package_reviewer,  # noqa: SLF001
        "review",
        lambda *args, **kwargs: SimpleNamespace(decision=ReviewDecision.REJECT),
    )
    report = await rejected.acquire(request)
    assert not report.active
    assert "package review did not pass" in report.detail

    missing_hooks, request = build()
    missing_hooks._certification_hooks = None  # noqa: SLF001
    report = await missing_hooks.acquire(request)
    assert not report.active
    assert "trusted certification hooks" in report.detail

    missing_activation, request = build()
    missing_activation._activation_requests = None  # noqa: SLF001
    report = await missing_activation.acquire(request)
    assert not report.active
    assert "activation request builder" in report.detail

    missing_manifest, request = build()
    missing_manifest._manifest_provider = None  # noqa: SLF001
    report = await missing_manifest.acquire(request)
    assert not report.active
    assert "capability manifest provider" in report.detail

    shadow_failure, request = build(activation_options={"shadow_malformed": True})
    report = await shadow_failure.acquire(request)
    assert not report.active
    assert "Shadow activation failed" in report.detail

    canary_failure, request = build(activation_options={"canary_malformed": True})
    report = await canary_failure.acquire(request)
    assert not report.active
    assert "Canary activation failed" in report.detail

    verification_failure, request = build()
    verification_failure._evidence = cast(VerificationEvidenceProvider, _EmptyEvidence())  # noqa: SLF001
    report = await verification_failure.acquire(request)
    assert not report.active
    assert "post-activation verification failed" in report.detail


def test_acquisition_constructor_rejects_malformed_trusted_boundaries() -> None:
    coordinator = _coordinator(CapabilityRegistry())
    services = coordinator._services  # noqa: SLF001
    for field in ("registry", "package_reviewer", "package_certifier", "verification"):
        malformed = replace(cast(Any, services), **cast(Any, {field: object()}))
        with pytest.raises(CapabilityAcquisitionError, match="malformed"):
            CapabilityAcquisitionCoordinator(malformed, scope_provider=_Scope())
    with pytest.raises(CapabilityAcquisitionError, match="security status"):
        CapabilityAcquisitionCoordinator(
            services,
            scope_provider=_Scope(),
            sandbox_security_status=cast(Any, object()),
        )
    with pytest.raises(CapabilityAcquisitionError, match="Trace service"):
        CapabilityAcquisitionCoordinator(
            services,
            scope_provider=_Scope(),
            trace=cast(TraceService, object()),
        )


@pytest.mark.asyncio
async def test_trace_projection_failure_preserves_unit_test_failure_and_package_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_package_activation import package as activation_package
    from tests.test_package_activation import setup as activation_setup

    package, source = activation_package((2, 0, 0))
    activation, _, _ = activation_setup()
    capability_id = f"fixture-{uuid4().hex}"
    trace_store = TraceStore(tmp_path / "trace.sqlite3")
    trace = TraceService(trace_store, InMemoryEventBus())

    def reject_projection(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise TraceError("Trace package hash is malformed")

    monkeypatch.setattr(TraceService, "record", reject_projection)
    coordinator = _generated_coordinator(
        CapabilityRegistry(),
        package,
        source,
        activation,
        certification_hooks=_CertificationHooks(source, failed=CertificationStage.UNIT_TESTS),
        trace=trace,
    )
    request = _acquisition_request(capability_id)
    request = replace(
        request,
        solution=SolutionReport(
            request.solution.gap,
            (SolutionOption("build-fixture", FactoryStrategy.GENERATE_ADAPTER, capability_id),),
        ),
    )

    report = await coordinator.acquire(request)

    assert not report.active
    assert "gate=UNIT_TESTS" in report.detail
    assert "CERTIFICATION_UNIT_TESTS_FAILED" in report.detail
    assert coordinator.last_run is not None
    assert coordinator.last_run.stage is AcquisitionStage.FAILED
    assert coordinator.last_run.package_hash == package.package_hash
    assert coordinator.last_run.certification is None
    assert coordinator.last_run.activation is None
    assert coordinator.flight_recorder is not None
    records = coordinator.flight_recorder.records()
    failure = next(item for item in records if item.operation == "certification_failed")
    projection = next(item for item in records if item.operation == "trace_record_failed")
    assert failure.resource_identity["package_hash"] == package.package_hash
    assert failure.stage == CertificationStage.UNIT_TESTS.value
    assert failure.error_class == "CertificationFailure"
    assert projection.error_class == "TraceError"
    assert projection.resource_identity["package_hash"] == package.package_hash
    assert "post_cleanup_terminal" in [item.operation for item in records]
    assert coordinator._services.registry.manifests() == ()  # noqa: SLF001

    trace_store.close()


def test_acquisition_trace_normalizes_invalid_optional_fields(tmp_path: Path) -> None:
    trace_store = TraceStore(tmp_path / "trace.sqlite3")
    trace = TraceService(trace_store, InMemoryEventBus())
    coordinator = _coordinator(CapabilityRegistry(), trace=trace)
    goal_id = uuid4()
    run = AcquisitionRun(
        uuid4(),
        goal_id,
        "bounded failure",
        "fixture-capability",
        AcquisitionStage.FAILED,
        package_id="fixture-package",
        package_version="1.0.0",
        package_hash="not-a-package-hash",
        adoption_attestation_reference="\x00not-safe",
        reason="\x00unbounded producer detail",
    )

    coordinator._record_trace(run)  # noqa: SLF001

    event = trace.get(goal_id=goal_id).events[0]
    assert event.package_hash is None
    assert event.result == {
        "stage": AcquisitionStage.FAILED.value,
        "run_id": str(run.run_id),
        "adoption_attestation_reference": None,
    }
    assert event.evidence == ()
    trace_store.close()
