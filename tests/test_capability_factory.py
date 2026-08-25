from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
from uuid import uuid4

import pytest
from jarvis.adoption import AdoptionPolicy
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
from jarvis.capability_factory import (
    AdoptionCandidate,
    AdoptionCandidates,
    CapabilityFactory,
    CapabilityFactoryValidationError,
    FactoryLifecycle,
    FactoryStrategy,
    GeneratedCapabilityPackage,
    SolutionOption,
    SolutionReport,
    WorkspaceContext,
)
from jarvis.discovery.models import CapabilityGap
from jarvis.integration_package import (
    IntegrationPackage,
    PackageBoundary,
    PackageEntry,
    PackageLayout,
    PackageLifecycle,
    PackageProvenance,
)
from jarvis.permissions.models import Risk
from jarvis.provisioning import ProvisioningPlan, ProvisioningPlanState, ProvisioningResult
from jarvis.setup_conductor import (
    AdoptionCandidate as SetupAdoptionCandidate,
)
from jarvis.setup_conductor import (
    InMemorySetupStore,
    SetupConductor,
    SetupContext,
    SetupDecision,
    SetupInspection,
    SetupStep,
)
from jarvis.tools.models import SemanticVersion, ToolHealthStatus, ToolPlatform

from tests.adoption_fixtures import adoption_candidate


class SetupFixture:
    def __init__(
        self, *, completed: bool = True, candidate: SetupAdoptionCandidate | None = None
    ) -> None:
        self.completed = completed
        self.candidate = candidate

    async def inspect(self, step: SetupStep, context: SetupContext) -> SetupInspection:
        del step, context
        return SetupInspection(
            completed=self.completed,
            candidates=(self.candidate,) if self.candidate is not None else (),
        )

    async def prepare(
        self, step: SetupStep, context: SetupContext, decision: SetupDecision | None
    ) -> ProvisioningPlan | None:
        del step, context, decision
        return None

    async def configure(self, step: SetupStep, context: SetupContext) -> None:
        del step, context

    async def verify(self, step: SetupStep, context: SetupContext) -> bool:
        del step, context
        return self.completed

    async def first_start(self, step: SetupStep, context: SetupContext) -> bool:
        del step, context
        return True


class Generator:
    def __init__(self, package: GeneratedCapabilityPackage) -> None:
        self.package = package
        self.calls = 0

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
        self.calls += 1
        return self.package


def gap(name: str = "unknown capability") -> CapabilityGap:
    return CapabilityGap(name, "test task", ("missing action",), (), Risk.LOW, ())


def package() -> IntegrationPackage:
    digest = sha256(b"generated").hexdigest()
    provenance = PackageProvenance("jarvis.generator", "test-revision", "internal")
    return IntegrationPackage(
        "generated.capability",
        SemanticVersion(1, 0, 0),
        PackageLayout(),
        (
            PackageEntry(
                "manifest", "code/manifest.json", PackageBoundary.PACKAGE_CODE, digest, provenance
            ),
        ),
        lifecycle=PackageLifecycle.VALIDATED,
        provenance=provenance,
    )


def factory(
    generator: Generator,
    registry: CapabilityRegistry | None = None,
    *,
    setup_completed: bool = True,
    setup_candidate: SetupAdoptionCandidate | None = None,
    adoption_policy: AdoptionPolicy | None = None,
) -> CapabilityFactory:
    setup = SetupConductor(
        {"runtime": SetupFixture(completed=setup_completed, candidate=setup_candidate)},
        InMemorySetupStore(),
        lambda plan: _provision(plan),
        adoption_policy=adoption_policy,
    )
    return CapabilityFactory(registry or CapabilityRegistry(), setup, generator)


async def _provision(plan: ProvisioningPlan) -> ProvisioningResult:
    return ProvisioningResult(plan.plan_id, ProvisioningPlanState.VERIFIED, (), "verified")


def generated(
    *, static: bool = True, sandbox: bool = True, security: bool = True
) -> GeneratedCapabilityPackage:
    return GeneratedCapabilityPackage(package(), static, sandbox, security, "trusted-test-builder")


@pytest.mark.asyncio
async def test_acquisition_order_reuses_active_jarvis_capability_before_build() -> None:
    manifest = CapabilityManifest(
        "unknown.capability",
        "Unknown Capability",
        SemanticVersion(1, 0, 0),
        "jarvis.core",
        ("use",),
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
        CapabilityHealth(ToolHealthStatus.AVAILABLE, "ok"),
        ("deterministic",),
        (),
        ("core",),
        "hash",
        CapabilityLifecycle.ACTIVE,
        EffectMetadata(EffectClassification.OBSERVATION, Reversibility.READ_ONLY),
    )
    generator = Generator(generated())
    result = await factory(generator, CapabilityRegistry((manifest,))).acquire(
        gap(),
        SolutionReport(
            gap(), (SolutionOption("build", FactoryStrategy.GENERATE_ADAPTER, "generated"),)
        ),
        AdoptionCandidates(),
        WorkspaceContext("random-workspace"),
        EnvironmentGraph(),
        {},
    )
    assert result.strategy is FactoryStrategy.REUSE_JARVIS
    assert result.lifecycle is FactoryLifecycle.ACTIVE
    assert generator.calls == 0


@pytest.mark.asyncio
async def test_adoption_precedes_external_reuse_and_uses_setup_conductor() -> None:
    setup_candidate, adoption_policy = adoption_candidate("machine", location="unknown:/runtime")
    adoption = AdoptionCandidate(setup_candidate, SetupStep("adopt", "runtime"))
    generator = Generator(generated())
    current_gap = gap()
    result = await factory(
        generator,
        setup_candidate=setup_candidate,
        adoption_policy=adoption_policy,
    ).acquire(
        current_gap,
        SolutionReport(
            current_gap, (SolutionOption("api", FactoryStrategy.REUSE_API_LIBRARY_MCP_CLI, "api"),)
        ),
        AdoptionCandidates((adoption,)),
        WorkspaceContext("workspace-" + uuid4().hex[:8], {"mode": "local"}),
        EnvironmentGraph(),
        {},
    )
    assert result.strategy is FactoryStrategy.ADOPT_MACHINE
    assert result.lifecycle is FactoryLifecycle.ACTIVE
    assert result.setup_run is not None
    assert generator.calls == 0


@pytest.mark.asyncio
async def test_declined_adoption_is_inactive_and_does_not_build() -> None:
    adoption = AdoptionCandidate(
        SetupAdoptionCandidate("machine", "runtime", "unknown:/runtime"),
        SetupStep("adopt", "runtime"),
    )
    generator = Generator(generated())
    current_gap = gap()
    result = await factory(generator).acquire(
        current_gap,
        SolutionReport(
            current_gap, (SolutionOption("api", FactoryStrategy.REUSE_API_LIBRARY_MCP_CLI, "api"),)
        ),
        AdoptionCandidates((adoption,)),
        WorkspaceContext("workspace"),
        EnvironmentGraph(),
        {"adoption.machine": "ignore"},
    )
    assert result.lifecycle is FactoryLifecycle.DECLINED
    assert result.package is None
    assert generator.calls == 0


@pytest.mark.asyncio
async def test_external_reuse_precedes_generation_and_can_require_setup() -> None:
    current_gap = gap()
    option = SolutionOption(
        "api",
        FactoryStrategy.REUSE_API_LIBRARY_MCP_CLI,
        "api.capability",
        True,
        True,
        True,
        SetupStep("configure", "runtime"),
    )
    generator = Generator(generated())
    result = await factory(generator).acquire(
        current_gap,
        SolutionReport(
            current_gap,
            (SolutionOption("generated", FactoryStrategy.GENERATE_ADAPTER, "generated"), option),
        ),
        AdoptionCandidates(),
        WorkspaceContext("workspace"),
        EnvironmentGraph(),
        {},
    )
    assert result.strategy is FactoryStrategy.REUSE_API_LIBRARY_MCP_CLI
    assert result.lifecycle is FactoryLifecycle.ACTIVE
    assert generator.calls == 0


@pytest.mark.asyncio
async def test_generated_package_stops_ready_for_approval_and_never_registers_active() -> None:
    current_gap = gap("new capability")
    generator = Generator(generated())
    registry = CapabilityRegistry()
    result = await factory(generator, registry).acquire(
        current_gap,
        SolutionReport(
            current_gap, (SolutionOption("mcp", FactoryStrategy.GENERATE_MCP_SERVER, "generated"),)
        ),
        AdoptionCandidates(),
        WorkspaceContext("unknown-workspace"),
        EnvironmentGraph(),
        {},
    )
    assert result.lifecycle is FactoryLifecycle.READY_FOR_APPROVAL
    assert result.package is not None
    assert result.package.package.lifecycle is PackageLifecycle.VALIDATED
    assert registry.manifests() == ()
    assert FactoryLifecycle.SECURITY_CHECKING in result.trace


@pytest.mark.asyncio
async def test_incomplete_generated_checks_remain_inactive() -> None:
    current_gap = gap("checked later")
    generator = Generator(generated(security=False))
    result = await factory(generator).acquire(
        current_gap,
        SolutionReport(
            current_gap, (SolutionOption("adapter", FactoryStrategy.GENERATE_ADAPTER, "generated"),)
        ),
        AdoptionCandidates(),
        WorkspaceContext("workspace"),
        EnvironmentGraph(),
        {},
    )
    assert result.lifecycle is FactoryLifecycle.SECURITY_CHECKING
    assert result.package is not None


@pytest.mark.asyncio
async def test_static_and_sandbox_checks_stop_before_later_stages() -> None:
    current_gap = gap("checked in order")
    for proposal, expected in (
        (generated(static=False), FactoryLifecycle.STATIC_CHECKING),
        (generated(sandbox=False), FactoryLifecycle.SANDBOX_TESTING),
    ):
        result = await factory(Generator(proposal)).acquire(
            current_gap,
            SolutionReport(
                current_gap,
                (SolutionOption("adapter", FactoryStrategy.GENERATE_ADAPTER, "generated"),),
            ),
            AdoptionCandidates(),
            WorkspaceContext("workspace"),
            EnvironmentGraph(),
            {},
        )
        assert result.lifecycle is expected


@pytest.mark.asyncio
async def test_incomplete_adoption_and_reuse_setup_do_not_become_active() -> None:
    adoption = AdoptionCandidate(
        SetupAdoptionCandidate("machine", "runtime", "unknown:/runtime"),
        SetupStep("adopt", "runtime"),
    )
    current_gap = gap("incomplete setup")
    result = await factory(Generator(generated()), setup_completed=False).acquire(
        current_gap,
        SolutionReport(current_gap, ()),
        AdoptionCandidates((adoption,)),
        WorkspaceContext("workspace"),
        EnvironmentGraph(),
        {},
    )
    assert result.lifecycle is FactoryLifecycle.ADOPTING
    assert result.setup_run is None
    reuse = SolutionOption(
        "api",
        FactoryStrategy.REUSE_API_LIBRARY_MCP_CLI,
        "api.capability",
        requires_setup=True,
        setup_step=SetupStep("configure", "runtime"),
    )
    result = await factory(Generator(generated()), setup_completed=False).acquire(
        current_gap,
        SolutionReport(current_gap, (reuse,)),
        AdoptionCandidates(),
        WorkspaceContext("workspace"),
        EnvironmentGraph(),
        {},
    )
    assert result.lifecycle is FactoryLifecycle.PROVISIONING


@pytest.mark.asyncio
async def test_external_reuse_without_setup_is_active() -> None:
    current_gap = gap("simple reuse")
    result = await factory(Generator(generated())).acquire(
        current_gap,
        SolutionReport(
            current_gap,
            (SolutionOption("cli", FactoryStrategy.REUSE_API_LIBRARY_MCP_CLI, "cli.capability"),),
        ),
        AdoptionCandidates(),
        WorkspaceContext("workspace"),
        EnvironmentGraph(),
        {},
    )
    assert result.lifecycle is FactoryLifecycle.ACTIVE
    assert result.strategy is FactoryStrategy.REUSE_API_LIBRARY_MCP_CLI


@pytest.mark.asyncio
async def test_unsafe_or_incompatible_options_are_declined() -> None:
    current_gap = gap("no safe solution")
    result = await factory(Generator(generated())).acquire(
        current_gap,
        SolutionReport(
            current_gap,
            (
                SolutionOption(
                    "unsafe", FactoryStrategy.REUSE_API_LIBRARY_MCP_CLI, "unsafe", safe=False
                ),
                SolutionOption(
                    "wrong", FactoryStrategy.GENERATE_ADAPTER, "wrong", compatible=False
                ),
            ),
        ),
        AdoptionCandidates(),
        WorkspaceContext("workspace"),
        EnvironmentGraph(),
        {},
    )
    assert result.lifecycle is FactoryLifecycle.DECLINED


def test_factory_contract_rejects_malformed_metadata() -> None:
    with pytest.raises(CapabilityFactoryValidationError):
        WorkspaceContext("workspace", credential_refs=["not-tuple"])  # type: ignore[arg-type]
    with pytest.raises(CapabilityFactoryValidationError):
        WorkspaceContext("workspace", capability_scope={"bad scope"})  # type: ignore[arg-type]
    with pytest.raises(CapabilityFactoryValidationError):
        SolutionOption("option", "bad", "capability")  # type: ignore[arg-type]
    with pytest.raises(CapabilityFactoryValidationError):
        SolutionOption(
            "option", FactoryStrategy.GENERATE_ADAPTER, "capability", requires_setup=True
        )
    with pytest.raises(CapabilityFactoryValidationError):
        SolutionOption("option", FactoryStrategy.GENERATE_ADAPTER, "capability", compatible=1)  # type: ignore[arg-type]
    with pytest.raises(CapabilityFactoryValidationError):
        SolutionReport(gap(), (object(),))  # type: ignore[arg-type]
    with pytest.raises(CapabilityFactoryValidationError):
        SolutionReport(gap(), (), discovery_complete=1)  # type: ignore[arg-type]
    with pytest.raises(CapabilityFactoryValidationError):
        AdoptionCandidate(object(), SetupStep("setup", "runtime"))  # type: ignore[arg-type]
    with pytest.raises(CapabilityFactoryValidationError):
        GeneratedCapabilityPackage(object(), True, True, True, "generator")  # type: ignore[arg-type]
    with pytest.raises(CapabilityFactoryValidationError):
        _ = WorkspaceContext("workspace", {"nested": {"password": "raw"}})


def test_factory_rejects_malformed_preferences() -> None:
    candidate = AdoptionCandidate(
        SetupAdoptionCandidate("machine", "runtime", "unknown:/runtime"),
        SetupStep("adopt", "runtime"),
    )
    with pytest.raises(CapabilityFactoryValidationError):
        CapabilityFactory._choice_for("machine", {"adoption.machine": 1})
    with pytest.raises(CapabilityFactoryValidationError):
        CapabilityFactory._choice_for("machine", {"adoption.machine": "unknown"})
    assert candidate.candidate.candidate_id == "machine"


@pytest.mark.asyncio
async def test_factory_rejects_unknown_system_metadata_and_mismatched_reports() -> None:
    generator = Generator(generated())
    current_gap = gap()
    candidate = AdoptionCandidate(
        SetupAdoptionCandidate("machine", "runtime", "unknown:/runtime"),
        SetupStep("adopt", "runtime"),
    )
    with pytest.raises(CapabilityFactoryValidationError):
        WorkspaceContext("workspace", {"password": "raw"})
    with pytest.raises(CapabilityFactoryValidationError):
        AdoptionCandidates((candidate, candidate))  # duplicate identity is not silently merged
    with pytest.raises(CapabilityFactoryValidationError):
        await factory(generator).acquire(
            current_gap,
            SolutionReport(gap("other"), ()),
            AdoptionCandidates(),
            WorkspaceContext("workspace"),
            EnvironmentGraph(),
            {},
        )
