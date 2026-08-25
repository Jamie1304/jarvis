"""Central, provider-neutral capability acquisition and lifecycle coordination."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4

from jarvis.adoption import AdoptionOutcome
from jarvis.capabilities import (
    CapabilityLifecycle,
    CapabilityManifest,
    CapabilityRegistry,
    EnvironmentGraph,
)
from jarvis.discovery.models import CapabilityGap
from jarvis.integration_package import IntegrationPackage, PackageLifecycle
from jarvis.package_reviewer import PackageSourceFile
from jarvis.resources import (
    ReservationReleaseReason,
    ResourceBudget,
    ResourceDecision,
    ResourceDecisionStatus,
    ResourceGovernor,
    ResourcePriority,
)
from jarvis.setup_conductor import (
    AdoptionCandidate as SetupAdoptionCandidate,
)
from jarvis.setup_conductor import (
    AdoptionChoice,
    SetupConductor,
    SetupContext,
    SetupRun,
    SetupRunState,
    SetupStep,
)


class CapabilityFactoryError(RuntimeError):
    """Capability acquisition cannot proceed safely."""


class CapabilityFactoryValidationError(CapabilityFactoryError, ValueError):
    """Factory input or generated package metadata is malformed."""


class FactoryStrategy(StrEnum):
    REUSE_JARVIS = "reuse_jarvis"
    ADOPT_MACHINE = "adopt_machine"
    REUSE_API_LIBRARY_MCP_CLI = "reuse_api_library_mcp_cli"
    PROVISION_SUPPORT = "provision_support"
    GENERATE_ADAPTER = "generate_adapter"
    GENERATE_MCP_SERVER = "generate_mcp_server"


class FactoryLifecycle(StrEnum):
    GAP_DETECTED = "gap_detected"
    DISCOVERING = "discovering"
    ADOPTING = "adopting"
    RESEARCHING = "researching"
    DESIGNING = "designing"
    GENERATING = "generating"
    STATIC_CHECKING = "static_checking"
    SANDBOX_TESTING = "sandbox_testing"
    SECURITY_CHECKING = "security_checking"
    READY_FOR_APPROVAL = "ready_for_approval"
    PROVISIONING = "provisioning"
    CERTIFIED = "certified"
    SHADOW = "shadow"
    CANARY = "canary"
    ACTIVE = "active"
    DEGRADED = "degraded"
    QUARANTINED = "quarantined"
    DECLINED = "declined"
    ARCHIVED = "archived"
    UPDATING = "updating"
    ROLLING_BACK = "rolling_back"


@dataclass(frozen=True, slots=True)
class WorkspaceContext:
    """Scoped setup context; preferences and references do not grant authority."""

    workspace_id: str
    configuration: Mapping[str, object] = field(default_factory=dict)
    credential_refs: tuple[str, ...] = ()
    capability_scope: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _identifier(self.workspace_id, "Workspace ID")
        _safe_json(self.configuration)
        if type(self.credential_refs) is not tuple or any(
            not _text(value, "Credential reference", 256) for value in self.credential_refs
        ):
            raise CapabilityFactoryValidationError("Workspace credential references are malformed")
        if type(self.capability_scope) is not frozenset or any(
            not _identifier(value, "Workspace capability") for value in self.capability_scope
        ):
            raise CapabilityFactoryValidationError("Workspace capability scope is malformed")


@dataclass(frozen=True, slots=True)
class SolutionOption:
    option_id: str
    strategy: FactoryStrategy
    capability_id: str
    compatible: bool = True
    safe: bool = True
    requires_setup: bool = False
    setup_step: SetupStep | None = None
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.option_id, "Solution option ID")
        _identifier(self.capability_id, "Solution capability ID")
        if not isinstance(self.strategy, FactoryStrategy):
            raise CapabilityFactoryValidationError("Solution strategy is malformed")
        if type(self.compatible) is not bool or type(self.safe) is not bool:
            raise CapabilityFactoryValidationError("Solution compatibility flags are malformed")
        if type(self.requires_setup) is not bool or (
            self.requires_setup and self.setup_step is None
        ):
            raise CapabilityFactoryValidationError("Solution setup contract is malformed")
        _labels(self.evidence, "Solution evidence")


@dataclass(frozen=True, slots=True)
class SolutionReport:
    gap: CapabilityGap
    options: tuple[SolutionOption, ...] = ()
    discovery_complete: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.gap, CapabilityGap) or type(self.options) is not tuple:
            raise CapabilityFactoryValidationError("Solution report is malformed")
        if any(type(option) is not SolutionOption for option in self.options):
            raise CapabilityFactoryValidationError("Solution options are malformed")
        if type(self.discovery_complete) is not bool:
            raise CapabilityFactoryValidationError("Solution discovery status is malformed")


@dataclass(frozen=True, slots=True)
class AdoptionCandidate:
    """A machine capability plus the setup contract used to adopt it."""

    candidate: SetupAdoptionCandidate
    setup_step: SetupStep
    safe: bool = True

    def __post_init__(self) -> None:
        if (
            type(self.candidate) is not SetupAdoptionCandidate
            or type(self.setup_step) is not SetupStep
        ):
            raise CapabilityFactoryValidationError("Adoption candidate is malformed")
        if type(self.safe) is not bool:
            raise CapabilityFactoryValidationError("Adoption safety flag is malformed")


@dataclass(frozen=True, slots=True)
class AdoptionCandidates:
    candidates: tuple[AdoptionCandidate, ...] = ()

    def __post_init__(self) -> None:
        if type(self.candidates) is not tuple or any(
            type(candidate) is not AdoptionCandidate for candidate in self.candidates
        ):
            raise CapabilityFactoryValidationError("Adoption candidates are malformed")
        ids = tuple(candidate.candidate.candidate_id for candidate in self.candidates)
        if len(set(ids)) != len(ids):
            raise CapabilityFactoryValidationError("Adoption candidate IDs must be unique")


@dataclass(frozen=True, slots=True)
class GeneratedCapabilityPackage:
    """Data-only generated package proposal; it is never active by construction."""

    package: IntegrationPackage
    static_checked: bool
    sandbox_tested: bool
    security_checked: bool
    generated_by: str
    source_files: tuple[PackageSourceFile, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.package, IntegrationPackage):
            raise CapabilityFactoryValidationError("Generated package is malformed")
        if self.package.lifecycle not in {PackageLifecycle.DISCOVERED, PackageLifecycle.VALIDATED}:
            raise CapabilityFactoryValidationError("Generated package lifecycle is not inactive")
        if not all(
            type(value) is bool
            for value in (self.static_checked, self.sandbox_tested, self.security_checked)
        ):
            raise CapabilityFactoryValidationError("Generated package checks are malformed")
        _text(self.generated_by, "Generator provenance", 512)
        if type(self.source_files) is not tuple or any(
            not isinstance(value, PackageSourceFile) for value in self.source_files
        ):
            raise CapabilityFactoryValidationError(
                "Generated package source snapshots are malformed"
            )


class CapabilityGenerator(Protocol):
    async def generate(
        self,
        gap: CapabilityGap,
        solution: SolutionReport,
        workspace: WorkspaceContext,
        environment: EnvironmentGraph,
        preferences: Mapping[str, object],
        strategy: FactoryStrategy,
    ) -> GeneratedCapabilityPackage: ...


@dataclass(frozen=True, slots=True)
class CapabilityFactoryResult:
    run_id: UUID
    gap: CapabilityGap
    lifecycle: FactoryLifecycle
    strategy: FactoryStrategy | None
    capability_id: str | None
    selected_option_id: str | None = None
    adopted_candidate_id: str | None = None
    package: GeneratedCapabilityPackage | None = None
    setup_run: SetupRun | None = None
    trace: tuple[FactoryLifecycle, ...] = ()
    reason: str = ""
    resource_decision: ResourceDecision | None = None
    adoption_attestation_reference: str | None = None


class CapabilityFactory:
    """Apply DISCOVER -> ADOPT -> REUSE -> BUILD exactly once per acquisition."""

    def __init__(
        self,
        registry: CapabilityRegistry,
        setup_conductor: SetupConductor,
        generator: CapabilityGenerator,
        *,
        clock: Callable[[], datetime] | None = None,
        resource_governor: ResourceGovernor | None = None,
    ) -> None:
        if not isinstance(registry, CapabilityRegistry):
            raise CapabilityFactoryValidationError("Capability registry is malformed")
        self._registry = registry
        self._setup = setup_conductor
        self._generator = generator
        self._clock = clock or (lambda: datetime.now(UTC))
        self._resource_governor = resource_governor

    async def acquire(
        self,
        gap: CapabilityGap,
        solution: SolutionReport,
        adoption_candidates: AdoptionCandidates,
        workspace: WorkspaceContext,
        environment: EnvironmentGraph,
        preferences: Mapping[str, object],
        *,
        run_id: UUID | None = None,
    ) -> CapabilityFactoryResult:
        self._validate_inputs(
            gap, solution, adoption_candidates, workspace, environment, preferences
        )
        run_id = run_id or uuid4()
        reservation_id = None
        resource_decision = None
        governor = self._resource_governor
        if governor is not None:
            resource_decision = governor.reserve(
                "capability-factory",
                ResourcePriority.USER_REQUESTED,
                ResourceBudget(concurrency=1, duration_seconds=900),
            )
            if not resource_decision.allowed:
                lifecycle = (
                    FactoryLifecycle.DISCOVERING
                    if resource_decision.status is ResourceDecisionStatus.DEFER
                    else FactoryLifecycle.DECLINED
                )
                return CapabilityFactoryResult(
                    run_id,
                    gap,
                    lifecycle,
                    None,
                    None,
                    trace=(FactoryLifecycle.GAP_DETECTED, FactoryLifecycle.DISCOVERING),
                    reason=resource_decision.reason,
                    resource_decision=resource_decision,
                )
            reservation_id = resource_decision.reservation_id
        try:
            result = await self._acquire(
                gap,
                solution,
                adoption_candidates,
                workspace,
                environment,
                preferences,
                run_id=run_id,
            )
            if resource_decision is not None:
                result = replace(result, resource_decision=resource_decision)
            return result
        except BaseException:
            if reservation_id is not None and governor is not None:
                governor.release(reservation_id, ReservationReleaseReason.CRASH)
            raise
        else:
            if reservation_id is not None and governor is not None:
                governor.release(reservation_id, ReservationReleaseReason.COMPLETE)

    async def _acquire(
        self,
        gap: CapabilityGap,
        solution: SolutionReport,
        adoption_candidates: AdoptionCandidates,
        workspace: WorkspaceContext,
        environment: EnvironmentGraph,
        preferences: Mapping[str, object],
        *,
        run_id: UUID,
    ) -> CapabilityFactoryResult:
        self._validate_inputs(
            gap, solution, adoption_candidates, workspace, environment, preferences
        )
        trace = [FactoryLifecycle.GAP_DETECTED, FactoryLifecycle.DISCOVERING]
        existing = self._reuse_jarvis(gap, workspace)
        if existing is not None:
            trace.append(FactoryLifecycle.ACTIVE)
            return self._result(
                run_id,
                gap,
                FactoryLifecycle.ACTIVE,
                FactoryStrategy.REUSE_JARVIS,
                existing.capability_id,
                trace,
                "existing JARVIS capability reused",
            )
        trace.append(FactoryLifecycle.ADOPTING)
        declined_adoption = self._declined_adoption(adoption_candidates, preferences)
        if declined_adoption is not None:
            trace.append(FactoryLifecycle.DECLINED)
            return self._result(
                run_id,
                gap,
                FactoryLifecycle.DECLINED,
                FactoryStrategy.ADOPT_MACHINE,
                None,
                trace,
                "machine capability adoption declined",
                adopted=declined_adoption.candidate.candidate_id,
            )
        adoption = self._choose_adoption(adoption_candidates, preferences)
        if adoption is not None:
            setup = await self._run_setup(gap, adoption.setup_step, workspace, preferences, run_id)
            adopted_step = next(
                (
                    item
                    for item in setup.steps
                    if item.state.value == "adopted"
                    and item.candidate_id == adoption.candidate.candidate_id
                    and item.adoption_attestation is not None
                ),
                None,
            )
            if setup.state is SetupRunState.COMPLETED and adopted_step is not None:
                trace.extend((FactoryLifecycle.CERTIFIED, FactoryLifecycle.ACTIVE))
                return self._result(
                    run_id,
                    gap,
                    FactoryLifecycle.ACTIVE,
                    FactoryStrategy.ADOPT_MACHINE,
                    adoption.candidate.component_id,
                    trace,
                    "compatible machine capability adopted",
                    adopted=adoption.candidate.candidate_id,
                    setup=setup,
                    adoption_attestation_reference=(
                        "adoption-attestation:" + adopted_step.adoption_attestation.attestation_id
                        if adopted_step.adoption_attestation is not None
                        else None
                    ),
                )
            return self._result(
                run_id,
                gap,
                FactoryLifecycle.ADOPTING,
                FactoryStrategy.ADOPT_MACHINE,
                None,
                trace,
                "adoption setup is incomplete",
                adopted=adoption.candidate.candidate_id,
                setup=setup,
            )
        revalidation = next(
            (
                candidate
                for candidate in adoption_candidates.candidates
                if candidate.safe
                and candidate.candidate.compatible
                and self._choice_for(candidate.candidate.candidate_id, preferences)
                is not AdoptionChoice.IGNORE
            ),
            None,
        )
        if revalidation is not None:
            return self._result(
                run_id,
                gap,
                FactoryLifecycle.ADOPTING,
                FactoryStrategy.ADOPT_MACHINE,
                None,
                trace,
                "existing capability requires trusted identity/provenance revalidation",
                adopted=revalidation.candidate.candidate_id,
            )
        trace.append(FactoryLifecycle.RESEARCHING)
        reuse = self._choose_option(
            solution,
            (FactoryStrategy.REUSE_API_LIBRARY_MCP_CLI, FactoryStrategy.PROVISION_SUPPORT),
        )
        if reuse is not None:
            if reuse.requires_setup and reuse.setup_step is not None:
                setup = await self._run_setup(gap, reuse.setup_step, workspace, preferences, run_id)
                if setup.state is not SetupRunState.COMPLETED:
                    return self._result(
                        run_id,
                        gap,
                        FactoryLifecycle.PROVISIONING,
                        reuse.strategy,
                        reuse.capability_id,
                        trace,
                        "reuse setup is incomplete",
                        option=reuse.option_id,
                        setup=setup,
                    )
                trace.append(FactoryLifecycle.PROVISIONING)
                trace.extend((FactoryLifecycle.CERTIFIED, FactoryLifecycle.ACTIVE))
                return self._result(
                    run_id,
                    gap,
                    FactoryLifecycle.ACTIVE,
                    reuse.strategy,
                    reuse.capability_id,
                    trace,
                    "existing external capability configured",
                    option=reuse.option_id,
                    setup=setup,
                )
            trace.extend((FactoryLifecycle.CERTIFIED, FactoryLifecycle.ACTIVE))
            return self._result(
                run_id,
                gap,
                FactoryLifecycle.ACTIVE,
                reuse.strategy,
                reuse.capability_id,
                trace,
                "external capability reused",
                option=reuse.option_id,
            )
        build = self._choose_option(
            solution, (FactoryStrategy.GENERATE_ADAPTER, FactoryStrategy.GENERATE_MCP_SERVER)
        )
        if build is None:
            trace.append(FactoryLifecycle.DECLINED)
            return self._result(
                run_id,
                gap,
                FactoryLifecycle.DECLINED,
                None,
                None,
                trace,
                "no compatible acquisition strategy",
            )
        assert build is not None
        trace.extend((FactoryLifecycle.DESIGNING, FactoryLifecycle.GENERATING))
        package = await self._generator.generate(
            gap, solution, workspace, environment, preferences, build.strategy
        )
        if not package.static_checked:
            return self._result(
                run_id,
                gap,
                FactoryLifecycle.STATIC_CHECKING,
                build.strategy,
                package.package.package_id,
                trace + [FactoryLifecycle.STATIC_CHECKING],
                "generated package requires static checks",
                option=build.option_id,
                package=package,
            )
        trace.append(FactoryLifecycle.STATIC_CHECKING)
        if not package.sandbox_tested:
            return self._result(
                run_id,
                gap,
                FactoryLifecycle.SANDBOX_TESTING,
                build.strategy,
                package.package.package_id,
                trace + [FactoryLifecycle.SANDBOX_TESTING],
                "generated package requires sandbox tests",
                option=build.option_id,
                package=package,
            )
        trace.append(FactoryLifecycle.SANDBOX_TESTING)
        if not package.security_checked:
            return self._result(
                run_id,
                gap,
                FactoryLifecycle.SECURITY_CHECKING,
                build.strategy,
                package.package.package_id,
                trace + [FactoryLifecycle.SECURITY_CHECKING],
                "generated package requires security checks",
                option=build.option_id,
                package=package,
            )
        trace.extend((FactoryLifecycle.SECURITY_CHECKING, FactoryLifecycle.READY_FOR_APPROVAL))
        return self._result(
            run_id,
            gap,
            FactoryLifecycle.READY_FOR_APPROVAL,
            build.strategy,
            package.package.package_id,
            trace,
            "generated package is inactive and ready for trusted review",
            option=build.option_id,
            package=package,
        )

    async def _run_setup(
        self,
        gap: CapabilityGap,
        step: SetupStep,
        workspace: WorkspaceContext,
        preferences: Mapping[str, object],
        run_id: UUID,
    ) -> SetupRun:
        context = SetupContext(
            workspace.configuration, preferences, workspace.credential_refs, workspace.workspace_id
        )
        return await self._setup.run(
            gap.desired_capability.replace(" ", "_")[:128], (step,), context, run_id=run_id
        )

    def _reuse_jarvis(
        self, gap: CapabilityGap, workspace: WorkspaceContext
    ) -> CapabilityManifest | None:
        del workspace
        desired = gap.desired_capability.casefold()
        for manifest in self._registry.manifests():
            if manifest.lifecycle is CapabilityLifecycle.ACTIVE and (
                desired in manifest.name.casefold() or desired in manifest.capability_id.casefold()
            ):
                return manifest
        return None

    @staticmethod
    def _declined_adoption(
        candidates: AdoptionCandidates, preferences: Mapping[str, object]
    ) -> AdoptionCandidate | None:
        return next(
            (
                candidate
                for candidate in candidates.candidates
                if CapabilityFactory._choice_for(candidate.candidate.candidate_id, preferences)
                is AdoptionChoice.IGNORE
            ),
            None,
        )

    @staticmethod
    def _choose_adoption(
        candidates: AdoptionCandidates, preferences: Mapping[str, object]
    ) -> AdoptionCandidate | None:
        for candidate in candidates.candidates:
            choice = CapabilityFactory._choice_for(candidate.candidate.candidate_id, preferences)
            if (
                candidate.safe
                and candidate.candidate.compatible
                and choice
                in {
                    None,
                    AdoptionChoice.USE_IN_PLACE,
                    AdoptionChoice.IMPORT_COPY,
                    AdoptionChoice.RECONFIGURE,
                }
                and (
                    candidate.candidate.adoption_attestation is not None
                    or choice is AdoptionChoice.USE_IN_PLACE
                )
            ):
                if (
                    candidate.candidate.adoption_attestation is not None
                    and candidate.candidate.adoption_attestation.policy_outcome
                    not in {
                        AdoptionOutcome.ADOPT_VERIFIED,
                        AdoptionOutcome.ADOPT_WITH_RESTRICTIONS,
                    }
                ):
                    continue
                return candidate
        return None

    @staticmethod
    def _choose_option(
        solution: SolutionReport, strategies: tuple[FactoryStrategy, ...]
    ) -> SolutionOption | None:
        options: list[SolutionOption] = [
            option
            for option in solution.options
            if option.strategy in strategies and option.compatible and option.safe
        ]
        if not options:
            return None
        return min(
            options,
            key=lambda option: (
                strategies.index(option.strategy) if option.strategy in strategies else 99,
                option.option_id,
            ),
        )

    @staticmethod
    def _choice_for(candidate_id: str, preferences: Mapping[str, object]) -> AdoptionChoice | None:
        value = preferences.get(f"adoption.{candidate_id}")
        if value is None:
            return None
        if not isinstance(value, str):
            raise CapabilityFactoryValidationError("Adoption preference is malformed")
        try:
            return AdoptionChoice(value)
        except ValueError as error:
            raise CapabilityFactoryValidationError("Adoption preference is unknown") from error

    @staticmethod
    def _validate_inputs(
        gap: CapabilityGap,
        solution: SolutionReport,
        adoption: AdoptionCandidates,
        workspace: WorkspaceContext,
        environment: EnvironmentGraph,
        preferences: Mapping[str, object],
    ) -> None:
        if (
            solution.gap != gap
            or not isinstance(adoption, AdoptionCandidates)
            or not isinstance(workspace, WorkspaceContext)
            or not isinstance(environment, EnvironmentGraph)
        ):
            raise CapabilityFactoryValidationError("Factory inputs are inconsistent")
        _safe_json(preferences)

    def _result(
        self,
        run_id: UUID,
        gap: CapabilityGap,
        lifecycle: FactoryLifecycle,
        strategy: FactoryStrategy | None,
        capability_id: str | None,
        trace: list[FactoryLifecycle],
        reason: str,
        *,
        option: str | None = None,
        adopted: str | None = None,
        package: GeneratedCapabilityPackage | None = None,
        setup: SetupRun | None = None,
        adoption_attestation_reference: str | None = None,
    ) -> CapabilityFactoryResult:
        return CapabilityFactoryResult(
            run_id,
            gap,
            lifecycle,
            strategy,
            capability_id,
            option,
            adopted,
            package,
            setup,
            tuple(trace),
            reason,
            adoption_attestation_reference=adoption_attestation_reference,
        )


def _text(value: object, field_name: str, limit: int = 512) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > limit
        or any(ord(char) < 32 for char in value)
    ):
        raise CapabilityFactoryValidationError(f"{field_name} is malformed")
    return value


def _identifier(value: object, field_name: str) -> str:
    value = _text(value, field_name, 128)
    if any(char not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for char in value):
        raise CapabilityFactoryValidationError(f"{field_name} is malformed")
    return value


def _labels(values: tuple[str, ...], field_name: str) -> None:
    if any(not _text(value, field_name) for value in values):
        raise CapabilityFactoryValidationError(f"{field_name} are malformed")


def _safe_json(value: object, *, depth: int = 0) -> object:
    if depth > 12:
        raise CapabilityFactoryValidationError("Factory metadata is too deeply nested")
    if (
        value is None
        or type(value) is bool
        or type(value) is int
        or type(value) is float
        or type(value) is str
    ):
        return value
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            key_text = _identifier(key, "Factory metadata key")
            if key_text.casefold() in {
                "secret",
                "password",
                "token",
                "private_key",
                "credential_value",
            }:
                raise CapabilityFactoryValidationError(
                    "Factory metadata cannot contain raw secrets"
                )
            result[key_text] = _safe_json(item, depth=depth + 1)
        return result
    if isinstance(value, tuple | list):
        return [_safe_json(item, depth=depth + 1) for item in value]
    raise CapabilityFactoryValidationError("Factory metadata must be JSON")


__all__ = [
    "AdoptionCandidate",
    "AdoptionCandidates",
    "CapabilityFactory",
    "CapabilityFactoryError",
    "CapabilityFactoryResult",
    "CapabilityFactoryValidationError",
    "FactoryLifecycle",
    "FactoryStrategy",
    "GeneratedCapabilityPackage",
    "SolutionOption",
    "SolutionReport",
    "WorkspaceContext",
]
