"""Production-owned end-to-end capability acquisition composition.

This module is deliberately an orchestration boundary.  It does not execute a
second task engine, authorize effects, certify package code, or treat model
claims as verification.  Those responsibilities remain with the existing
PlanningEngine, PermissionBroker, PackageCertifier, PackageActivationService,
and VerificationEngine respectively.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from jarvis.capabilities import CapabilityManifest, CapabilityRegistry, EnvironmentGraph
from jarvis.capability_factory import (
    AdoptionCandidates,
    CapabilityFactory,
    CapabilityFactoryResult,
    FactoryLifecycle,
    FactoryStrategy,
    SolutionOption,
    SolutionReport,
    WorkspaceContext,
)
from jarvis.discovery.models import (
    ArchitectureFit,
    CapabilityGap,
    DiscoveryCandidate,
    RecommendationClass,
)
from jarvis.discovery.service import CapabilityDiscoveryService, CapabilityGapDetector
from jarvis.environment_discovery import DiscoveryMode, EnvironmentDiscoveryService
from jarvis.goal_supervisor import (
    CapabilityAcquisitionReport,
    CapabilityAcquisitionRequest,
    GoalAlternative,
    GoalAnalysis,
    GoalIntent,
    GoalResearch,
    GoalSupervisorValidationError,
    GoalUsage,
)
from jarvis.integration_package import IntegrationPackage
from jarvis.package_activation import (
    ActivationRecord,
    ActivationRequest,
    ActivationState,
    PackageActivationService,
)
from jarvis.package_certification import (
    CertificationHooks,
    CertificationRecord,
    CertificationRequest,
    PackageCertifier,
)
from jarvis.package_reviewer import (
    GeneratedPackageReviewer,
    PackageReviewPolicy,
    PackageReviewSurface,
    PackageSourceFile,
    ReviewDecision,
)
from jarvis.package_runtime import HotLoadManager
from jarvis.provisioning import ProvisioningEngine
from jarvis.setup_conductor import (
    SetupConductor,
    SetupContext,
    SetupRun,
    SetupRunState,
    SetupStep,
)
from jarvis.trace import TraceEventType, TraceService
from jarvis.verification import (
    EvidenceRecord,
    EvidenceType,
    VerificationEngine,
    VerificationLevel,
    VerificationPlan,
    VerificationResult,
)
from jarvis.windows_sandbox import SandboxSecurityStatus

_DEFAULT_REVIEW_SURFACE = PackageReviewSurface()
_DEFAULT_REVIEW_POLICY = PackageReviewPolicy()


class CapabilityAcquisitionError(RuntimeError):
    """A capability acquisition run stopped safely at a named boundary."""


class AcquisitionStage(StrEnum):
    GAP_DETECTED = "gap_detected"
    DISCOVERING = "discovering"
    ADOPTING = "adopting"
    REUSING = "reusing"
    RESEARCHING = "researching"
    BUILDING = "building"
    REVIEWING = "reviewing"
    SANDBOX_TESTING = "sandbox_testing"
    CERTIFYING = "certifying"
    SETUP = "setup"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    WAITING_FOR_CREDENTIALS = "waiting_for_credentials"
    SHADOW = "shadow"
    CANARY = "canary"
    ACTIVE = "active"
    VERIFYING = "verifying"
    FAILED = "failed"
    RECOVERING = "recovering"
    QUARANTINED = "quarantined"


@dataclass(frozen=True, slots=True)
class AcquisitionScope:
    """Trusted application scope forwarded to factory/setup services."""

    workspace: WorkspaceContext
    environment: EnvironmentGraph
    preferences: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SolutionDiscoveryResult:
    solution: SolutionReport
    adoption_candidates: AdoptionCandidates
    evidence: tuple[str, ...] = ()


class SolutionDiscoveryProvider(Protocol):
    async def discover(
        self, gap: CapabilityGap, environment: EnvironmentGraph
    ) -> SolutionDiscoveryResult: ...  # pragma: no cover


class ScopeProvider(Protocol):
    async def scope(
        self,
        intent: GoalIntent,
        gap: CapabilityGap,
    ) -> AcquisitionScope: ...  # pragma: no cover


class PackageSourceProvider(Protocol):
    def sources(
        self,
        package: IntegrationPackage,
    ) -> tuple[PackageSourceFile, ...]: ...  # pragma: no cover


class CertificationHookProvider(Protocol):
    def hooks(self, package: IntegrationPackage) -> CertificationHooks: ...  # pragma: no cover


class ActivationRequestProvider(Protocol):
    def request(
        self,
        package: IntegrationPackage,
        certification: CertificationRecord,
        source_files: tuple[PackageSourceFile, ...],
    ) -> ActivationRequest: ...  # pragma: no cover


class CapabilityManifestProvider(Protocol):
    def manifest(
        self,
        package: IntegrationPackage,
        request: CapabilityAcquisitionRequest,
    ) -> CapabilityManifest: ...  # pragma: no cover


class VerificationEvidenceProvider(Protocol):
    async def collect(
        self,
        capability_id: str,
        original_goal: str,
        stage: AcquisitionStage,
    ) -> Sequence[EvidenceRecord]: ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class AcquisitionRun:
    """Human-readable coordinator state; durable goal intent remains GoalSupervisor-owned."""

    run_id: UUID
    goal_id: UUID
    original_goal: str
    capability_id: str | None
    stage: AcquisitionStage
    strategy: FactoryStrategy | None = None
    package_id: str | None = None
    package_version: str | None = None
    package_hash: str | None = None
    certification: CertificationRecord | None = None
    activation: ActivationRecord | None = None
    setup: SetupRun | None = None
    adoption_attestation_reference: str | None = None
    verification: VerificationResult | None = None
    evidence: tuple[str, ...] = ()
    reason: str = ""
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class SolutionDiscovery:
    """Convert evidence-only discovery recommendations into factory options."""

    def __init__(
        self,
        discovery: CapabilityDiscoveryService,
        *,
        adoption_provider: Callable[[CapabilityGap, EnvironmentGraph], AdoptionCandidates]
        | None = None,
        setup_step_provider: Callable[[DiscoveryCandidate], SetupStep | None] | None = None,
        build_setup_step: SetupStep | None = None,
    ) -> None:
        self._discovery = discovery
        self._adoption_provider = adoption_provider or (
            lambda _gap, _environment: AdoptionCandidates()
        )
        self._setup_step_provider = setup_step_provider or (lambda _candidate: None)
        if build_setup_step is not None and not isinstance(build_setup_step, SetupStep):
            raise CapabilityAcquisitionError("Build setup step is malformed")
        self._build_setup_step = build_setup_step

    async def discover(
        self, gap: CapabilityGap, environment: EnvironmentGraph
    ) -> SolutionDiscoveryResult:
        recommendation = await self._discovery.recommend(gap)
        options: list[SolutionOption] = []
        evidence: list[str] = []
        for evaluation in recommendation.evaluated_candidates:
            candidate = evaluation.candidate
            evidence.append(f"candidate:{candidate.identity}:{evaluation.classification.value}")
            if evaluation.classification is RecommendationClass.REJECTED:
                continue
            step = self._setup_step_provider(candidate)
            options.append(
                SolutionOption(
                    option_id=f"reuse.{_safe_id(candidate.identity)}",
                    strategy=FactoryStrategy.REUSE_API_LIBRARY_MCP_CLI,
                    capability_id=_safe_id(candidate.capability_provided),
                    compatible=candidate.architecture_fit is not ArchitectureFit.INCOMPATIBLE,
                    safe=evaluation.classification
                    in {RecommendationClass.RECOMMENDED, RecommendationClass.CAUTION},
                    requires_setup=step is not None,
                    setup_step=step,
                    evidence=(candidate.provenance.reference,),
                )
            )
        if not any(option.compatible and option.safe for option in options):
            options.append(
                SolutionOption(
                    option_id=f"build.{_safe_id(gap.desired_capability)}",
                    strategy=FactoryStrategy.GENERATE_ADAPTER,
                    capability_id=_safe_id(gap.desired_capability),
                    evidence=("no safe reusable candidate was discovered",),
                    requires_setup=self._build_setup_step is not None,
                    setup_step=self._build_setup_step,
                )
            )
            evidence.append("fallback:build only after discovery found no safe reusable option")
        return SolutionDiscoveryResult(
            SolutionReport(gap, tuple(options), discovery_complete=True),
            self._adoption_provider(gap, environment),
            tuple(evidence),
        )


@dataclass(frozen=True, slots=True)
class CapabilityAcquisitionServices:
    """The single service graph owned by the application composition root."""

    registry: CapabilityRegistry
    gap_detector: CapabilityGapDetector
    environment_discovery: EnvironmentDiscoveryService
    solution_discovery: SolutionDiscoveryProvider
    factory: CapabilityFactory
    package_reviewer: GeneratedPackageReviewer
    package_certifier: PackageCertifier
    setup_conductor: SetupConductor
    provisioning_engine: ProvisioningEngine
    package_activation: PackageActivationService
    hot_load: HotLoadManager
    verification: VerificationEngine


class CapabilityAcquisitionCoordinator:
    """One production-owned coordinator above existing acquisition subsystems."""

    def __init__(
        self,
        services: CapabilityAcquisitionServices,
        *,
        scope_provider: ScopeProvider,
        source_provider: PackageSourceProvider | None = None,
        certification_hooks: CertificationHookProvider | None = None,
        activation_requests: ActivationRequestProvider | None = None,
        manifest_provider: CapabilityManifestProvider | None = None,
        verification_evidence: VerificationEvidenceProvider | None = None,
        sandbox_security_status: SandboxSecurityStatus | None = None,
        trace: TraceService | None = None,
        review_surface: PackageReviewSurface = _DEFAULT_REVIEW_SURFACE,
        review_policy: PackageReviewPolicy = _DEFAULT_REVIEW_POLICY,
    ) -> None:
        if not isinstance(services.registry, CapabilityRegistry):
            raise CapabilityAcquisitionError("Capability registry is malformed")
        if not isinstance(services.package_reviewer, GeneratedPackageReviewer):
            raise CapabilityAcquisitionError("Package reviewer is malformed")
        if not isinstance(services.package_certifier, PackageCertifier):
            raise CapabilityAcquisitionError("Package certifier is malformed")
        if not isinstance(services.verification, VerificationEngine):
            raise CapabilityAcquisitionError("Verification engine is malformed")
        self._services = services
        self._scope = scope_provider
        self._sources = source_provider
        self._certification_hooks = certification_hooks
        self._activation_requests = activation_requests
        self._manifest_provider = manifest_provider
        self._evidence = verification_evidence
        if sandbox_security_status is not None and not isinstance(
            sandbox_security_status, SandboxSecurityStatus
        ):
            raise CapabilityAcquisitionError("Sandbox security status is malformed")
        self._sandbox_security_status = sandbox_security_status
        if trace is not None and type(trace) is not TraceService:
            raise CapabilityAcquisitionError("Trace service is malformed")
        self._trace = trace
        self._review_surface = review_surface
        self._review_policy = review_policy
        self._last_run: AcquisitionRun | None = None

    @property
    def last_run(self) -> AcquisitionRun | None:
        return self._last_run

    async def research(
        self,
        intent: GoalIntent,
        analysis: GoalAnalysis,
        alternative: GoalAlternative | None = None,
    ) -> GoalResearch:
        """GoalSupervisor researcher: discovery only, with no install or authority."""

        del alternative
        gap = analysis.capability_gap
        if gap is None:
            return GoalResearch(evidence=("no capability gap requires acquisition",))
        scope = await self._scope.scope(intent, gap)
        self._services.environment_discovery.discover(DiscoveryMode.READ_ONLY_LOCAL_DISCOVERY)
        discovered = await self._services.solution_discovery.discover(gap, scope.environment)
        request = CapabilityAcquisitionRequest(
            gap,
            discovered.solution,
            discovered.adoption_candidates,
            scope.workspace,
            scope.environment,
            scope.preferences,
            goal_id=intent.goal_id,
        )
        return GoalResearch(
            acquisition=request,
            usage=GoalUsage(),
            evidence=("read-only environment discovery completed", *discovered.evidence),
        )

    async def acquire(self, request: CapabilityAcquisitionRequest) -> CapabilityAcquisitionReport:
        """GoalSupervisor acquirer: delegate each lifecycle stage to its owner."""

        if not isinstance(request, CapabilityAcquisitionRequest):
            raise GoalSupervisorValidationError("Capability acquisition request is malformed")
        result = await self._services.factory.acquire(
            request.gap,
            request.solution,
            request.adoption_candidates,
            request.workspace,
            request.environment,
            request.preferences,
        )
        self._last_run = AcquisitionRun(
            result.run_id,
            request.goal_id or UUID(int=0),
            request.gap.current_task,
            result.capability_id,
            self._factory_stage(result),
            result.strategy,
            result.package.package.package_id if result.package is not None else None,
            (str(result.package.package.version) if result.package is not None else None),
            result.package.package.package_hash if result.package is not None else None,
            setup=result.setup_run,
            adoption_attestation_reference=result.adoption_attestation_reference,
            reason=result.reason,
            evidence=(result.reason,),
        )
        self._record_trace(self._last_run)
        if result.lifecycle is FactoryLifecycle.ACTIVE and result.capability_id is not None:
            return await self._verify_reused(request, result)
        if result.package is None:
            return self._inactive_report(
                result, "capability factory did not produce an active package"
            )
        return await self._certify_and_activate(request, result)

    async def prepare(self, request: CapabilityAcquisitionRequest) -> CapabilityAcquisitionReport:
        """Build and certify a candidate without registering or activating it.

        Opportunity preparation uses this path.  It deliberately stops before
        ``PackageActivationService`` and therefore cannot create authority.
        The package content itself is owned by the production package store so
        an accepted opportunity can resume from the same reviewed candidate.
        """

        if not isinstance(request, CapabilityAcquisitionRequest):
            raise GoalSupervisorValidationError("Capability preparation request is malformed")
        result = await self._services.factory.acquire(
            request.gap,
            request.solution,
            request.adoption_candidates,
            request.workspace,
            request.environment,
            request.preferences,
        )
        self._last_run = AcquisitionRun(
            result.run_id,
            request.goal_id or UUID(int=0),
            request.gap.current_task,
            result.capability_id,
            self._factory_stage(result),
            result.strategy,
            result.package.package.package_id if result.package is not None else None,
            str(result.package.package.version) if result.package is not None else None,
            result.package.package.package_hash if result.package is not None else None,
            setup=result.setup_run,
            reason=result.reason,
            evidence=(result.reason,),
        )
        self._record_trace(self._last_run)
        if result.package is None:
            return CapabilityAcquisitionReport(
                False,
                result.capability_id,
                evidence=(result.reason or "no candidate was generated",),
                detail=result.reason or "No inactive capability candidate is available",
            )
        if self._sources is None or self._certification_hooks is None:
            return CapabilityAcquisitionReport(
                False,
                result.capability_id,
                evidence=("trusted preparation boundaries are unavailable",),
                detail=(
                    "Capability preparation remains inactive because trusted package "
                    "boundaries are unavailable"
                ),
            )
        package = result.package.package
        source_files = self._sources.sources(package)
        review = self._services.package_reviewer.review(
            package,
            source_files=source_files,
            surface=self._review_surface,
            policy=self._review_policy,
        )
        if review.decision in {ReviewDecision.REJECT, ReviewDecision.MANUAL_REVIEW_REQUIRED}:
            return CapabilityAcquisitionReport(
                False,
                result.capability_id,
                evidence=("package preparation review failed",),
                detail="Capability preparation was rejected by the trusted package reviewer",
            )
        try:
            certification = self._services.package_certifier.certify(
                CertificationRequest(
                    package,
                    f"preparation:{package.package_id}",
                    ("local-runtime",),
                    (request.gap.current_task,),
                    review_surface=self._review_surface,
                    review_policy=self._review_policy,
                    sandbox_security_status=self._sandbox_security_status,
                ),
                self._certification_hooks.hooks(package),
            )
        except Exception as error:
            return CapabilityAcquisitionReport(
                False,
                package.package_id,
                evidence=("package preparation certification failed",),
                detail=(
                    f"Capability preparation failed closed at certification: {type(error).__name__}"
                ),
            )
        self._update(
            stage=AcquisitionStage.CERTIFYING,
            certification=certification,
            reason="candidate certified for later trusted activation; no authority granted",
        )
        return CapabilityAcquisitionReport(
            False,
            package.package_id,
            evidence=(
                "package reviewed",
                "sandbox tested",
                "certified for later activation",
                "activation intentionally not attempted",
            ),
            detail="Capability candidate was prepared and certified without activation",
        )

    async def _verify_reused(
        self, request: CapabilityAcquisitionRequest, result: CapabilityFactoryResult
    ) -> CapabilityAcquisitionReport:
        if self._evidence is None:
            return self._inactive_report(
                result, "reused capability has no trusted verification collector"
            )
        verification = await self._verify(
            result.capability_id or "", request.gap.current_task, AcquisitionStage.VERIFYING
        )
        if verification.passed:
            self._update(stage=AcquisitionStage.ACTIVE, verification=verification)
            return CapabilityAcquisitionReport(
                True,
                result.capability_id,
                evidence=("existing capability reused", "verification complete"),
                detail="existing safe capability reused and independently verified",
            )
        self._update(
            stage=AcquisitionStage.FAILED,
            verification=verification,
            reason="reused capability verification failed",
        )
        return CapabilityAcquisitionReport(
            False,
            evidence=("existing capability verification failed",),
            detail="existing capability was not independently verified",
        )

    async def _certify_and_activate(
        self,
        request: CapabilityAcquisitionRequest,
        factory_result: CapabilityFactoryResult,
    ) -> CapabilityAcquisitionReport:
        generated = factory_result.package
        assert generated is not None
        package = generated.package
        self._update(stage=AcquisitionStage.REVIEWING, package_id=package.package_id)
        source_files = self._sources.sources(package) if self._sources is not None else ()
        review = self._services.package_reviewer.review(
            package,
            source_files=source_files,
            surface=self._review_surface,
            policy=self._review_policy,
        )
        if review.decision in {ReviewDecision.REJECT, ReviewDecision.MANUAL_REVIEW_REQUIRED}:
            return self._failed_report(factory_result, "package review did not pass")
        if self._certification_hooks is None:
            return self._failed_report(
                factory_result, "trusted certification hooks are unavailable"
            )
        self._update(stage=AcquisitionStage.SANDBOX_TESTING)
        self._update(stage=AcquisitionStage.CERTIFYING)
        try:
            certification = self._services.package_certifier.certify(
                CertificationRequest(
                    package,
                    f"capability:{package.package_id}",
                    ("local-runtime",),
                    (request.gap.current_task,),
                    review_surface=self._review_surface,
                    review_policy=self._review_policy,
                    sandbox_security_status=self._sandbox_security_status,
                ),
                self._certification_hooks.hooks(package),
            )
        except Exception as error:
            return self._failed_report(
                factory_result, f"package certification failed: {type(error).__name__}"
            )
        self._update(certification=certification)
        option = next(
            (
                item
                for item in request.solution.options
                if item.option_id == factory_result.selected_option_id
            ),
            None,
        )
        if option is not None and option.setup_step is not None:
            self._update(stage=AcquisitionStage.SETUP)
            setup = await self._run_setup(request, option.setup_step, factory_result.run_id)
            self._update(setup=setup)
            if setup.state is SetupRunState.WAITING_DECISIONS:
                return self._waiting_report(factory_result, "setup requires trusted user decisions")
            if setup.state is not SetupRunState.COMPLETED:
                return self._failed_report(factory_result, "setup/provisioning did not complete")
        if self._activation_requests is None:
            return self._failed_report(
                factory_result, "trusted activation request builder is unavailable"
            )
        if self._manifest_provider is None:
            return self._failed_report(
                factory_result, "capability manifest provider is unavailable"
            )
        # The manifest is prepared before Shadow/Canary so the trusted hot-load
        # surface can atomically refresh the registry projection.  Registration
        # still happens only after ACTIVE; persisting this inactive metadata is
        # not an authority grant.
        manifest = self._manifest_provider.manifest(package, request)
        self._update(stage=AcquisitionStage.SHADOW)
        try:
            activation_request = self._activation_requests.request(
                package, certification, source_files
            )
            self._services.package_activation.register_certified(activation_request)
            shadow = self._services.package_activation.run_shadow(
                package.package_id, package.version
            )
            if shadow.state is not ActivationState.SHADOW:
                return self._failed_report(factory_result, "Shadow activation failed")
            self._update(stage=AcquisitionStage.CANARY, activation=shadow)
            canary = self._services.package_activation.run_canary(
                package.package_id, package.version
            )
            if canary.state is not ActivationState.CANARY:
                return self._failed_report(factory_result, "Canary activation failed")
            self._update(stage=AcquisitionStage.CANARY, activation=canary)
            active = self._services.package_activation.promote(package.package_id, package.version)
            if active.state is not ActivationState.ACTIVE:
                return self._failed_report(factory_result, "Activation did not reach ACTIVE")
            self._update(stage=AcquisitionStage.ACTIVE, activation=active)
        except Exception as error:
            return self._failed_report(
                factory_result, f"staged activation failed: {type(error).__name__}: {error}"
            )
        try:
            try:
                existing = self._services.registry.inspect(manifest.capability_id)
            except KeyError:
                self._services.registry.register(manifest)
            else:
                if existing != manifest:
                    return self._failed_report(
                        factory_result, "active capability registration collided"
                    )
        except Exception:
            return self._failed_report(factory_result, "active capability registration failed")
        self._update(stage=AcquisitionStage.VERIFYING, activation=active)
        if self._evidence is None:
            return self._failed_report(
                factory_result, "trusted verification collector is unavailable"
            )
        verification = await self._verify(
            manifest.capability_id, request.gap.current_task, AcquisitionStage.VERIFYING
        )
        if not verification.passed:
            try:
                self._services.package_activation.quarantine(
                    package.package_id, package.version, "post-activation verification failed"
                )
            except Exception:
                pass
            self._update(stage=AcquisitionStage.QUARANTINED, verification=verification)
            return self._failed_report(factory_result, "post-activation verification failed")
        self._update(stage=AcquisitionStage.ACTIVE, verification=verification, activation=active)
        return CapabilityAcquisitionReport(
            True,
            manifest.capability_id,
            evidence=(
                "package reviewed",
                "certified",
                "Shadow passed",
                "Canary passed",
                "verified",
            ),
            detail="capability reached ACTIVE and passed trusted verification",
        )

    async def _run_setup(
        self, request: CapabilityAcquisitionRequest, step: SetupStep, run_id: UUID
    ) -> SetupRun:
        context = SetupContext(
            request.workspace.configuration,
            request.preferences,
            request.workspace.credential_refs,
            request.workspace.workspace_id,
        )
        return await self._services.setup_conductor.run(
            request.gap.desired_capability.replace(" ", "_")[:128],
            (step,),
            context,
            run_id=run_id,
        )

    async def _verify(
        self, capability_id: str, original_goal: str, stage: AcquisitionStage
    ) -> VerificationResult:
        assert self._evidence is not None
        records = tuple(await self._evidence.collect(capability_id, original_goal, stage))
        plan = VerificationPlan(
            original_goal,
            (f"capability:{capability_id}",),
            allowed_evidence_types=frozenset(EvidenceType),
            required_level=VerificationLevel.INTEGRATION_VERIFIED,
            independent_observation_required=True,
            ask_user_when_unobservable=False,
        )
        return self._services.verification.evaluate(plan, records)

    def _inactive_report(
        self, result: CapabilityFactoryResult, reason: str
    ) -> CapabilityAcquisitionReport:
        self._update(stage=AcquisitionStage.FAILED, reason=reason)
        return CapabilityAcquisitionReport(False, evidence=(reason,), detail=reason)

    def _waiting_report(
        self, result: CapabilityFactoryResult, reason: str
    ) -> CapabilityAcquisitionReport:
        self._update(stage=AcquisitionStage.WAITING_FOR_APPROVAL, reason=reason)
        return CapabilityAcquisitionReport(False, evidence=(reason,), detail=reason)

    def _failed_report(
        self, result: CapabilityFactoryResult, reason: str
    ) -> CapabilityAcquisitionReport:
        self._update(stage=AcquisitionStage.FAILED, reason=reason)
        return CapabilityAcquisitionReport(False, evidence=(reason,), detail=reason)

    def _update(
        self,
        *,
        stage: AcquisitionStage | None = None,
        package_id: str | None = None,
        certification: CertificationRecord | None = None,
        activation: ActivationRecord | None = None,
        setup: SetupRun | None = None,
        verification: VerificationResult | None = None,
        reason: str | None = None,
    ) -> None:
        if self._last_run is None:
            return
        current = self._last_run
        if stage is not None:
            current = replace(current, stage=stage)
        if package_id is not None:
            current = replace(current, package_id=package_id)
        if certification is not None:
            current = replace(current, certification=certification)
        if activation is not None:
            current = replace(current, activation=activation)
        if setup is not None:
            current = replace(current, setup=setup)
        if verification is not None:
            current = replace(current, verification=verification)
        if reason is not None:
            current = replace(current, reason=reason)
        self._last_run = replace(current, updated_at=datetime.now(UTC))
        self._record_trace(self._last_run)

    def _record_trace(self, run: AcquisitionRun) -> None:
        if self._trace is None:
            return
        self._trace.record(
            TraceEventType.CAPABILITY_ACQUISITION,
            "Capability acquisition stage recorded",
            goal_id=run.goal_id,
            correlation_id=run.goal_id,
            integration_id=run.package_id or run.capability_id,
            package_version=run.package_version,
            package_hash=run.package_hash,
            result={
                "stage": run.stage.value,
                "run_id": str(run.run_id),
                "adoption_attestation_reference": run.adoption_attestation_reference,
            },
            evidence=(run.reason,) if run.reason else (),
            effect_attestation_ids=(
                run.activation.attestation_ids if run.activation is not None else ()
            ),
        )

    @staticmethod
    def _factory_stage(result: CapabilityFactoryResult) -> AcquisitionStage:
        return {
            FactoryLifecycle.ACTIVE: AcquisitionStage.ACTIVE,
            FactoryLifecycle.READY_FOR_APPROVAL: AcquisitionStage.WAITING_FOR_APPROVAL,
            FactoryLifecycle.ADOPTING: AcquisitionStage.ADOPTING,
            FactoryLifecycle.PROVISIONING: AcquisitionStage.SETUP,
            FactoryLifecycle.SANDBOX_TESTING: AcquisitionStage.SANDBOX_TESTING,
            FactoryLifecycle.STATIC_CHECKING: AcquisitionStage.REVIEWING,
        }.get(result.lifecycle, AcquisitionStage.FAILED)


def _safe_id(value: str) -> str:
    compact = "".join(character if character.isalnum() else "_" for character in value.casefold())
    return compact.strip("_")[:96] or "capability"


__all__ = [
    "AcquisitionRun",
    "AcquisitionScope",
    "AcquisitionStage",
    "CapabilityAcquisitionCoordinator",
    "CapabilityAcquisitionError",
    "CapabilityAcquisitionServices",
    "CapabilityManifestProvider",
    "CertificationHookProvider",
    "PackageSourceProvider",
    "ScopeProvider",
    "SolutionDiscovery",
    "SolutionDiscoveryProvider",
    "SolutionDiscoveryResult",
    "VerificationEvidenceProvider",
]
