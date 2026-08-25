from __future__ import annotations

import asyncio
import json
from collections.abc import Coroutine
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TypeVar, cast
from uuid import uuid4

import pytest
from jarvis.agent_runtime import (
    AgentLoop,
    AgentLoopResult,
    AgentTerminationReason,
    AgentUsage,
)
from jarvis.ai.providers.registry import ProviderRegistry
from jarvis.ai.routing import ProviderRouter
from jarvis.capabilities import CapabilityLifecycle, CapabilityRegistry, EnvironmentGraph
from jarvis.capability_acquisition import AcquisitionStage, CapabilityAcquisitionCoordinator
from jarvis.capability_factory import (
    AdoptionCandidates,
    FactoryStrategy,
    GeneratedCapabilityPackage,
    SolutionReport,
    WorkspaceContext,
)
from jarvis.capability_health import CapabilityHealthService
from jarvis.capability_lifecycle import LifecycleMetadata, StoredLifecycleRecord
from jarvis.capability_opportunities import (
    CapabilityOpportunity,
    OpportunityDecision,
    OpportunityEvidence,
    OpportunityEvidenceSource,
    OpportunityPreparationState,
    OpportunityStatus,
)
from jarvis.discovery.models import CapabilityGap
from jarvis.effect_attestation import EffectAttestationStore
from jarvis.environment_discovery import DiscoveryMode
from jarvis.goal_supervisor import CapabilityAcquisitionRequest, GoalResearch
from jarvis.integration_package import IntegrationPackage
from jarvis.package_activation import (
    ActivationRecord,
    ActivationState,
    ActivationTransition,
    CanaryLimits,
)
from jarvis.package_certification import (
    CertificationRecord,
    CertificationStage,
    CertificationStageEvidence,
    package_fingerprints,
)
from jarvis.package_reviewer import PackageSourceFile
from jarvis.package_runtime import HotLoadError, PackageRuntimeHealth, PreparedPackageRuntime
from jarvis.permissions.models import Permission, Risk
from jarvis.production_capability import (
    AgentRuntimeCapabilityGenerator,
    CapabilityGenerationProvider,
    CapabilityLifecycleRestorer,
    ProductionActivationBoundary,
    ProductionCapabilityError,
    ProductionCertificationProvider,
    ProductionLocalCandidateProvider,
    ProductionLocalDiscoveryProvider,
    ProductionOpportunityPreparation,
    ProductionPackageRegistrationSurface,
    ProductionPackageRuntime,
    ProductionPackageRuntimeFactory,
    ProductionPackageStore,
    ProductionProvisioningProvider,
    ProductionSandboxRunner,
    ProductionSetupHandler,
    ProductionVerificationEvidence,
    _AgentLoopGenerationProvider,
    _build_generic_package,
    _GenerationSpec,
    _manifest_from_payload,
    _package_digest,
    _package_from_payload,
    _package_payload,
    _parse_generation_spec,
    _safe_identifier,
)
from jarvis.provisioning import ProvisioningAction
from jarvis.resources import ResourceGovernor, SystemResourceTelemetry
from jarvis.setup_conductor import SetupContext, SetupStep
from jarvis.verification import VerificationEngine
from jarvis.windows_sandbox import SandboxSecurityStatus, WindowsContainmentMode

_Result = TypeVar("_Result")


@pytest.mark.asyncio
async def test_generation_waits_for_missing_routable_provider(tmp_path: Path) -> None:
    gap = CapabilityGap("synthetic", "perform synthetic work", ("synthetic",), (), Risk.LOW, ())
    generator = AgentRuntimeCapabilityGenerator(
        cast(AgentLoop, object()),
        ProductionPackageStore(tmp_path / "packages"),
        provider=cast(CapabilityGenerationProvider, object()),
        router=ProviderRouter(ProviderRegistry()),
        provider_id="missing-provider",
        model_id="missing-model",
    )

    with pytest.raises(ProductionCapabilityError, match="WAITING_FOR_MODEL_PROVIDER"):
        await generator.generate(
            gap,
            SolutionReport(gap),
            WorkspaceContext("synthetic-workspace"),
            EnvironmentGraph(),
            {},
            FactoryStrategy.GENERATE_ADAPTER,
        )


def test_package_store_rejects_path_and_hash_traversal(tmp_path: Path) -> None:
    store = ProductionPackageStore(tmp_path / "packages")

    with pytest.raises(ProductionCapabilityError):
        store.load("generated.synthetic", "../../outside", "a" * 64)
    with pytest.raises(ProductionCapabilityError):
        store.load("generated.synthetic", "1.0.0", "../outside")


def _gap(desired: str = "synthetic-capability") -> CapabilityGap:
    return CapabilityGap(
        desired,
        f"perform bounded work for {desired}",
        (desired,),
        (),
        Risk.LOW,
        (),
    )


class _StaticProposal:
    def __init__(self, raw: str) -> None:
        self.raw = raw

    async def propose(
        self,
        prompt: str,
        *,
        gap: CapabilityGap,
        solution: SolutionReport,
        workspace: WorkspaceContext,
        environment: EnvironmentGraph,
        strategy: FactoryStrategy,
    ) -> str:
        del prompt, gap, solution, workspace, environment, strategy
        return self.raw


async def _generated(
    tmp_path: Path,
    *,
    desired: str = "synthetic-capability",
    source: str | None = None,
) -> tuple[ProductionPackageStore, GeneratedCapabilityPackage, CapabilityGap]:
    gap = _gap(desired)
    payload: dict[str, object] = {
        "name": "Synthetic capability",
        "description": "Bounded synthetic package",
    }
    if source is not None:
        payload["source"] = source
    store = ProductionPackageStore(tmp_path / "packages")
    generator = AgentRuntimeCapabilityGenerator(
        cast(AgentLoop, object()),
        store,
        provider=_StaticProposal(json.dumps(payload)),
    )
    generated = await generator.generate(
        gap,
        SolutionReport(gap),
        WorkspaceContext("synthetic-workspace"),
        EnvironmentGraph(),
        {},
        FactoryStrategy.GENERATE_ADAPTER,
    )
    return store, generated, gap


def _request(gap: CapabilityGap) -> CapabilityAcquisitionRequest:
    return CapabilityAcquisitionRequest(
        gap,
        SolutionReport(gap),
        AdoptionCandidates(),
        WorkspaceContext("synthetic-workspace"),
        EnvironmentGraph(),
        {},
    )


def _status(*, isolated: bool = True) -> SandboxSecurityStatus:
    return SandboxSecurityStatus(
        WindowsContainmentMode.APPCONTAINER if isolated else WindowsContainmentMode.JOB_OBJECT_ONLY,
        isolated,
        isolated,
        isolated,
        3 if isolated else 0,
        isolated,
        isolated,
        isolated,
        "synthetic sandbox status",
        appcontainer_profile="synthetic-profile" if isolated else None,
        runtime_root="C:/synthetic-runtime" if isolated else None,
    )


class _FakeSandboxProcess:
    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        self.security_status = _status()
        self.closed = False

    async def start(self) -> None:
        return None

    async def request(self, kind: str, payload: dict[str, object]) -> dict[str, object]:
        return {"status": "observed", "kind": kind, "payload": payload}

    async def close(self) -> None:
        self.closed = True


class _UnsafeSandboxProcess(_FakeSandboxProcess):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.security_status = _status(isolated=False)


class _FakeSandboxRunner:
    def __init__(self, status: SandboxSecurityStatus | None = None) -> None:
        self._status = status or _status()

    def status(self) -> SandboxSecurityStatus:
        return self._status

    def probe(self, package: IntegrationPackage) -> SandboxSecurityStatus:
        del package
        return self._status

    def available_status(self) -> SandboxSecurityStatus:
        return self._status

    def _execute(
        self, package: IntegrationPackage, kind: str, payload: dict[str, object]
    ) -> tuple[SandboxSecurityStatus, dict[str, object]]:
        del package, payload
        return self._status, {"status": "observed", "kind": kind}


class _RestoreLifecycleStore:
    def __init__(self, stored: StoredLifecycleRecord) -> None:
        self.stored = stored

    def list(self) -> tuple[StoredLifecycleRecord, ...]:
        return (self.stored,)

    def load(self, integration_id: str, version: str) -> StoredLifecycleRecord | None:
        if (
            self.stored.record.package_id == integration_id
            and str(self.stored.record.version) == version
        ):
            return self.stored
        return None

    def save(
        self,
        record: ActivationRecord,
        *,
        expected_revision: int,
        **_: object,
    ) -> StoredLifecycleRecord:
        assert expected_revision == self.stored.revision
        self.stored = StoredLifecycleRecord(
            record,
            self.stored.revision + 1,
            "STABLE",
            None,
            self.stored.metadata,
        )
        return self.stored


class _RestoreActivation:
    def __init__(self, record: ActivationRecord) -> None:
        self.record = record
        self.requests: list[object] = []

    def restore(self, request: object) -> ActivationRecord:
        self.requests.append(request)
        return self.record


def _restore_record(
    package: IntegrationPackage,
    certification: CertificationRecord,
    state: ActivationState,
) -> ActivationRecord:
    now = datetime.now(UTC)
    return ActivationRecord(
        f"restore-{state.value.lower()}",
        package.package_id,
        package.version,
        package.package_hash,
        certification,
        state,
        (),
        (),
        (),
        (),
        "restored",
        (),
        (ActivationTransition(None, state, "synthetic durable state", now),),
        now,
        now,
        sandbox_security_mode="appcontainer",
    )


def _restore_certification(
    package: IntegrationPackage, source_files: tuple[PackageSourceFile, ...]
) -> CertificationRecord:
    source_hash, dependency_hash, manifest_hash = package_fingerprints(package, source_files)
    now = datetime.now(UTC)
    stage = CertificationStageEvidence(CertificationStage.CERTIFIED, True, ("trusted",), now)
    return CertificationRecord(
        package.package_id,
        package.version,
        package.package_hash,
        source_hash,
        dependency_hash,
        manifest_hash,
        (),
        (),
        package.permissions,
        None,
        ("windows",),
        ("healthy",),
        ("verified",),
        "restore-point:synthetic",
        True,
        True,
        ("baseline:synthetic",),
        (stage,),
        now,
    )


def _stored_restore_record(
    package: IntegrationPackage,
    certification: CertificationRecord,
    state: ActivationState,
    *,
    metadata: LifecycleMetadata | None = None,
) -> StoredLifecycleRecord:
    return StoredLifecycleRecord(
        _restore_record(package, certification, state),
        1,
        "STABLE",
        None,
        metadata
        or LifecycleMetadata(
            configuration_version=str(package.version),
            behavior_baseline_reference=("baseline:synthetic",),
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state",
    [
        ActivationState.ACTIVE,
        ActivationState.DEGRADED,
        ActivationState.SHADOW,
        ActivationState.CANARY,
    ],
)
async def test_lifecycle_restorer_rehydrates_only_safe_projections(
    tmp_path: Path, state: ActivationState
) -> None:
    store, generated, gap = await _generated(tmp_path)
    package = generated.package
    manifest = store.manifest(package, _request(gap))
    certification = _restore_certification(package, store.source_files(package))
    lifecycle = _RestoreLifecycleStore(_stored_restore_record(package, certification, state))
    activation = _RestoreActivation(lifecycle.stored.record)
    registry = CapabilityRegistry()
    health = CapabilityHealthService()
    restorer = CapabilityLifecycleRestorer(
        cast(Any, lifecycle),
        store,
        cast(Any, _FakeSandboxRunner()),
        cast(Any, activation),
        registry,
        health=health,
    )

    result = restorer.restore_all()[0]

    assert result.restored
    assert result.resulting_state is state
    assert len(activation.requests) == 1
    assert health.baseline(package.package_id).package_version == str(package.version)
    if state is ActivationState.ACTIVE:
        assert registry.inspect(manifest.capability_id).lifecycle is CapabilityLifecycle.ACTIVE
    elif state is ActivationState.DEGRADED:
        assert registry.inspect(manifest.capability_id).lifecycle is CapabilityLifecycle.DEGRADED
    else:
        with pytest.raises(KeyError):
            registry.inspect(manifest.capability_id)


@pytest.mark.asyncio
async def test_lifecycle_restorer_quarantines_missing_package_or_isolation(
    tmp_path: Path,
) -> None:
    store, generated, gap = await _generated(tmp_path)
    package = generated.package
    store.manifest(package, _request(gap))
    certification = _restore_certification(package, store.source_files(package))

    source_path = store.package_directory(package) / "code" / "entrypoint.py"
    source_path.unlink()
    missing_lifecycle = _RestoreLifecycleStore(
        _stored_restore_record(package, certification, ActivationState.ACTIVE)
    )
    missing = CapabilityLifecycleRestorer(
        cast(Any, missing_lifecycle),
        store,
        cast(Any, _FakeSandboxRunner()),
        cast(Any, _RestoreActivation(missing_lifecycle.stored.record)),
        CapabilityRegistry(),
    ).restore_all()[0]
    assert missing.resulting_state is ActivationState.QUARANTINED
    assert missing_lifecycle.stored.record.state is ActivationState.QUARANTINED

    intact_store, intact_generated, intact_gap = await _generated(tmp_path / "intact")
    intact_package = intact_generated.package
    intact_store.manifest(intact_package, _request(intact_gap))
    intact_certification = _restore_certification(
        intact_package, intact_store.source_files(intact_package)
    )
    isolation_lifecycle = _RestoreLifecycleStore(
        _stored_restore_record(intact_package, intact_certification, ActivationState.ACTIVE)
    )
    isolation = CapabilityLifecycleRestorer(
        cast(Any, isolation_lifecycle),
        intact_store,
        cast(Any, _FakeSandboxRunner(_status(isolated=False))),
        cast(Any, _RestoreActivation(isolation_lifecycle.stored.record)),
        CapabilityRegistry(),
    ).restore_all()[0]
    assert isolation.resulting_state is ActivationState.QUARANTINED


@pytest.mark.asyncio
async def test_lifecycle_restorer_revalidates_adoption_and_preserves_terminal_state(
    tmp_path: Path,
) -> None:
    store, generated, gap = await _generated(tmp_path)
    package = generated.package
    store.manifest(package, _request(gap))
    certification = _restore_certification(package, store.source_files(package))
    adoption = _RestoreLifecycleStore(
        _stored_restore_record(
            package,
            certification,
            ActivationState.ACTIVE,
            metadata=LifecycleMetadata(
                provenance_reference=("adoption-attestation:synthetic",),
                configuration_version=str(package.version),
            ),
        )
    )
    rejected = CapabilityLifecycleRestorer(
        cast(Any, adoption),
        store,
        cast(Any, _FakeSandboxRunner()),
        cast(Any, _RestoreActivation(adoption.stored.record)),
        CapabilityRegistry(),
    ).restore_all()[0]
    assert rejected.resulting_state is ActivationState.QUARANTINED

    terminal = _RestoreLifecycleStore(
        _stored_restore_record(package, certification, ActivationState.QUARANTINED)
    )
    result = CapabilityLifecycleRestorer(
        cast(Any, terminal),
        store,
        cast(Any, _FakeSandboxRunner()),
        cast(Any, _RestoreActivation(terminal.stored.record)),
        CapabilityRegistry(),
    ).restore_all()[0]
    assert not result.restored
    assert result.resulting_state is ActivationState.QUARANTINED


@pytest.mark.asyncio
async def test_production_generation_persists_package_and_manifest(tmp_path: Path) -> None:
    store, generated, gap = await _generated(tmp_path)
    package = generated.package
    assert package.package_hash == _package_digest(package)
    assert store.source_files(package)

    # Re-saving the exact immutable candidate is idempotent; changed content is not.
    store.save_candidate(generated, gap=gap)
    reopened = ProductionPackageStore(store.root)
    loaded = reopened.load(package.package_id, str(package.version))
    assert loaded.package_hash == package.package_hash
    assert reopened.source_files(loaded) == store.source_files(package)

    manifest = reopened.manifest(loaded, _request(gap))
    assert manifest.lifecycle is CapabilityLifecycle.ACTIVE
    restored_store = ProductionPackageStore(store.root)
    restored_manifest = restored_store.load_manifest(loaded)
    assert restored_manifest.content_hash == package.package_hash
    assert restored_store.package_directory(loaded).is_dir()


@pytest.mark.asyncio
async def test_package_manifest_identity_tampering_fails_closed(tmp_path: Path) -> None:
    store, generated, gap = await _generated(tmp_path)
    package = generated.package
    store.manifest(package, _request(gap))
    manifest_path = store.package_directory(package) / "capability-manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["capability_id"] = "generated.attacker"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    reopened = ProductionPackageStore(store.root)
    with pytest.raises(ProductionCapabilityError, match="identity"):
        reopened.load_manifest(package)


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "not-json",
        "[]",
        '{"name": 1}',
        '{"description": ""}',
        '{"name": "ok", "description": 1}',
        '{"name": "ok", "description": "ok", "source": 1}',
    ],
)
def test_model_generation_spec_rejects_malformed_output(raw: object) -> None:
    with pytest.raises(ProductionCapabilityError):
        _parse_generation_spec(cast(str, raw))


def test_generation_spec_and_identifiers_are_bounded() -> None:
    parsed = _parse_generation_spec('{"name":" Name ","description":" Description "}')
    assert parsed == _GenerationSpec("Name", "Description", None)
    assert _safe_identifier("A capability / with spaces") == "a-capability-with-spaces"
    assert _safe_identifier("!!!") == "capability"


@pytest.mark.asyncio
async def test_agent_loop_generation_boundary_rejects_untrusted_termination() -> None:
    class _Loop:
        context_limit = 4_096

        def __init__(self, result: AgentLoopResult) -> None:
            self.result = result

        async def run(self, *args: object, **kwargs: object) -> AgentLoopResult:
            del args, kwargs
            return self.result

    gap = _gap()

    async def call(provider: _AgentLoopGenerationProvider) -> str:
        return await provider.propose(
            "bounded prompt",
            gap=gap,
            solution=SolutionReport(gap),
            workspace=WorkspaceContext("synthetic-workspace"),
            environment=EnvironmentGraph(),
            strategy=FactoryStrategy.GENERATE_ADAPTER,
        )

    stopped = _AgentLoopGenerationProvider(
        cast(AgentLoop, _Loop(AgentLoopResult(AgentTerminationReason.TIMEOUT, AgentUsage(), ())))
    )
    with pytest.raises(ProductionCapabilityError, match="inference stopped"):
        await call(stopped)
    empty = _AgentLoopGenerationProvider(
        cast(
            AgentLoop,
            _Loop(
                AgentLoopResult(
                    AgentTerminationReason.COMPLETED,
                    AgentUsage(),
                    (),
                    proposed_result=None,
                )
            ),
        )
    )
    with pytest.raises(ProductionCapabilityError, match="no proposal"):
        await call(empty)
    complete = _AgentLoopGenerationProvider(
        cast(
            AgentLoop,
            _Loop(
                AgentLoopResult(
                    AgentTerminationReason.COMPLETED,
                    AgentUsage(),
                    (),
                    proposed_result='{"name":"safe"}',
                )
            ),
        )
    )
    assert await call(complete) == '{"name":"safe"}'


def test_package_serialization_rejects_malformed_metadata(tmp_path: Path) -> None:
    with pytest.raises(ProductionCapabilityError, match="provenance"):
        _package_payload(cast(IntegrationPackage, SimpleNamespace(provenance=None)))
    with pytest.raises(ProductionCapabilityError, match="manifest"):
        _manifest_from_payload({})


@pytest.mark.asyncio
async def test_package_store_rejects_inconsistent_or_tampered_content(tmp_path: Path) -> None:
    store = ProductionPackageStore(tmp_path / "packages")
    gap = _gap()
    package = _build_generic_package(gap, _GenerationSpec("name", "description", None))
    source = PackageSourceFile("code/entrypoint.py", "not the package source")
    generated = GeneratedCapabilityPackage(package, True, True, True, "test", (source,))
    with pytest.raises(ProductionCapabilityError, match="source hash"):
        store.save_candidate(generated, gap=gap)

    valid_store, valid_generated, valid_gap = await _generated(tmp_path / "valid")
    valid_package = valid_generated.package
    metadata = valid_store.package_directory(valid_package) / "package.json"
    metadata.write_text("{}", encoding="utf-8")
    with pytest.raises(ProductionCapabilityError, match="metadata"):
        valid_store.save_candidate(valid_generated, gap=valid_gap)

    # A second immutable package with the same identity/version is rejected.
    metadata.write_text(json.dumps(_package_payload(valid_package)), encoding="utf-8")
    source_path = valid_store.package_directory(valid_package) / "code" / "entrypoint.py"
    original_source = source_path.read_text(encoding="utf-8")
    source_path.write_text(original_source + "\n", encoding="utf-8")
    with pytest.raises(ProductionCapabilityError, match="source has changed"):
        valid_store.save_candidate(valid_generated, gap=valid_gap)
    source_path.write_text(original_source, encoding="utf-8")


@pytest.mark.asyncio
async def test_package_store_load_and_path_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ProductionCapabilityError):
        ProductionPackageStore(Path("relative-package-root"))
    store, generated, _ = await _generated(tmp_path)
    package = generated.package
    with pytest.raises(ProductionCapabilityError, match="hash-addressed"):
        store.package_directory(replace(package, package_hash=""))
    with pytest.raises(ProductionCapabilityError, match="escaped"):
        store._validate_directory_chain(tmp_path)  # noqa: SLF001
    with pytest.raises(ProductionCapabilityError, match="unsafe"):
        store._safe_child(store.package_directory(package), "../escape")  # noqa: SLF001
    with pytest.raises(ProductionCapabilityError, match="escaped"):
        store._safe_child(store.package_directory(package), r"..\..\escape")  # noqa: SLF001
    with pytest.raises(ProductionCapabilityError, match="unsupported"):
        _package_from_payload({"schema": 99})


@pytest.mark.asyncio
async def test_production_runtime_uses_fake_native_process_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, generated, _ = await _generated(tmp_path)
    package = generated.package
    monkeypatch.setattr("jarvis.production_capability.SandboxProcess", _FakeSandboxProcess)
    governor = ResourceGovernor(SystemResourceTelemetry())
    runtime = ProductionPackageRuntime(package, store, tmp_path / "sandboxes", governor)
    assert runtime.health_check() == PackageRuntimeHealth(
        True, "package contents are present and hash-verified"
    )
    runtime.restore_state({"checkpoint": "one"})
    assert runtime.export_state() == {"checkpoint": "one"}
    with pytest.raises(HotLoadError):
        runtime.restore_state({1: "invalid"})  # type: ignore[dict-item]
    with pytest.raises(ProductionCapabilityError, match="malformed"):
        await runtime.request("", {})
    result = await runtime.request("inspect", {"value": "bounded"})
    assert result["status"] == "observed"
    assert runtime.invoke("inspect", {})["kind"] == "inspect"
    runtime._active_requests = 1  # noqa: SLF001
    with pytest.raises(HotLoadError):
        runtime.drain()
    runtime._active_requests = 0  # noqa: SLF001
    assert (
        ProductionPackageRuntimeFactory(store, tmp_path / "sandboxes", governor)
        .prepare(package)
        .health_check()
        .healthy
    )

    empty_store = ProductionPackageStore(tmp_path / "empty-packages")
    with pytest.raises(HotLoadError):
        ProductionPackageRuntimeFactory(empty_store, tmp_path / "sandboxes", governor).prepare(
            package
        )


@pytest.mark.asyncio
async def test_production_sandbox_runner_and_registration_are_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, generated, gap = await _generated(tmp_path)
    package = generated.package
    monkeypatch.setattr("jarvis.production_capability.SandboxProcess", _FakeSandboxProcess)
    governor = ResourceGovernor(SystemResourceTelemetry())
    runner = ProductionSandboxRunner(store, tmp_path / "sandboxes", governor)
    assert runner.available_status() is not None
    assert runner.probe(package).executable_isolation
    assert runner.status() is not None

    monkeypatch.setattr("jarvis.production_capability.SandboxProcess", _UnsafeSandboxProcess)
    with pytest.raises(ProductionCapabilityError, match="isolation"):
        ProductionSandboxRunner(store, tmp_path / "unsafe", governor).probe(package)
    monkeypatch.setattr("jarvis.production_capability.SandboxProcess", _FakeSandboxProcess)

    request = _request(gap)
    manifest = store.manifest(package, request)
    registry = CapabilityRegistry()
    surface = ProductionPackageRegistrationSurface(registry, store)
    runtime = cast(PreparedPackageRuntime, object())
    surface.atomic_swap(package, runtime)
    surface.atomic_swap(package, runtime)
    surface.remove(package, runtime)
    with pytest.raises(KeyError):
        registry.inspect(manifest.capability_id)
    registry.register(replace(manifest, name="different"))
    with pytest.raises(HotLoadError):
        surface.atomic_swap(package, runtime)
    surface.rollback(package, None)


def test_production_discovery_and_bounded_setup_contracts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = ProductionLocalDiscoveryProvider()
    monkeypatch.setattr("jarvis.production_capability.sys.platform", "linux")
    assert provider.discover(DiscoveryMode.PASSIVE_DISCOVERY) == ()
    monkeypatch.setattr("jarvis.production_capability.sys.platform", "win32")
    observations = provider.discover(DiscoveryMode.READ_ONLY_LOCAL_DISCOVERY)
    assert observations and observations[0].confidence.score == 0.75
    candidate_provider = ProductionLocalCandidateProvider(lambda: observations)
    assert _run_async(candidate_provider.discover(_gap("ordinary-capability"))) == ()
    runtime_candidates = _run_async(candidate_provider.discover(_gap("local-runtime")))
    assert runtime_candidates

    provisioning = ProductionProvisioningProvider()
    action = cast(ProvisioningAction, object())
    assert not _run_async(provisioning.inspect(action)).satisfied
    assert _run_async(provisioning.apply(action, asyncio.Event())).outcome.value == (
        "pre_effect_failure"
    )
    assert _run_async(provisioning.rollback(action, asyncio.Event())).outcome.value == (
        "pre_effect_failure"
    )
    assert not _run_async(provisioning.health_check(action))

    setup = ProductionSetupHandler()
    step = SetupStep("synthetic-step", "generic")
    context = SetupContext(workspace="synthetic-workspace")
    inspection = _run_async(setup.inspect(step, context))
    assert "typed" in inspection.detail
    assert _run_async(setup.prepare(step, context, None)) is None
    _run_async(setup.configure(step, context))
    assert _run_async(setup.verify(step, context))
    assert _run_async(setup.first_start(step, context))


def _run_async(coro: Coroutine[Any, Any, _Result]) -> _Result:
    return asyncio.run(coro)


@pytest.mark.asyncio
async def test_production_certification_and_trusted_activation_hooks(tmp_path: Path) -> None:
    store, generated, gap = await _generated(tmp_path)
    package = generated.package
    sandbox = _FakeSandboxRunner()
    certifier = ProductionCertificationProvider(
        store, cast(ProductionSandboxRunner, sandbox), VerificationEngine()
    )
    hooks = certifier.hooks(package)
    assert hooks.build(package).source_files
    assert hooks.unit_tests(package).passed
    assert hooks.sandbox_integration_test(package).passed
    assert hooks.permission_diff(package).passed
    authority = hooks.authority_decision(package)
    assert authority.passed and authority.shadow_eligible and authority.canary_eligible
    assert hooks.install(package).passed
    assert hooks.healthcheck(package).passed
    assert hooks.verification(package).passed
    with_permissions = replace(
        package,
        permissions=(Permission.FILESYSTEM_READ,),
    )
    assert not hooks.authority_decision(with_permissions).passed
    manifest = certifier.manifest(package, _request(gap))
    assert manifest.content_hash == package.package_hash

    attestations = EffectAttestationStore(tmp_path / "attestations.sqlite3")
    boundary = ProductionActivationBoundary(
        store, cast(ProductionSandboxRunner, sandbox), attestations, VerificationEngine()
    )
    activation_hooks = boundary.hooks(attestations)
    shadow_observer = attestations.observer(
        package.package_id, str(package.version), package.package_hash, "SHADOW", "shadow-run"
    )
    shadow = activation_hooks.shadow(package, shadow_observer)
    assert shadow.attestation is not None
    assert shadow.attestation.zero_trusted_dispatch
    canary_observer = attestations.observer(
        package.package_id, str(package.version), package.package_hash, "CANARY", "canary-run"
    )
    canary = activation_hooks.canary(
        package,
        CanaryLimits("synthetic"),
        canary_observer,
    )
    assert canary.passed
    assert canary.attestation is not None
    attestation = canary.attestation
    assert attestation.dispatched_count == 1
    verify_canary = activation_hooks.verify_canary
    assert verify_canary is not None
    assert verify_canary(package, attestation).passed
    attestations.close()


@pytest.mark.asyncio
async def test_production_verification_evidence_and_opportunity_boundaries(
    tmp_path: Path,
) -> None:
    store, generated, gap = await _generated(tmp_path)
    package = generated.package
    request = _request(gap)
    manifest = store.manifest(package, request)
    registry = CapabilityRegistry((manifest,))
    evidence = ProductionVerificationEvidence(registry, object(), store)
    assert (
        await evidence.collect(
            manifest.capability_id,
            "goal",
            AcquisitionStage.RESEARCHING,
        )
        == ()
    )
    assert (
        await evidence.collect(
            "missing",
            "goal",
            AcquisitionStage.VERIFYING,
        )
        == ()
    )
    collected = await evidence.collect(
        manifest.capability_id,
        "goal",
        AcquisitionStage.VERIFYING,
    )
    assert collected and collected[0].source == "trusted.package.runtime"

    adopted_registry = CapabilityRegistry((replace(manifest, integration_owner="adopted.runtime"),))
    adopted_evidence = ProductionVerificationEvidence(adopted_registry, object(), store)
    adopted = await adopted_evidence.collect(
        manifest.capability_id,
        "goal",
        AcquisitionStage.VERIFYING,
    )
    assert adopted and adopted[0].source == "trusted.capability.registry"
    stopped_registry = CapabilityRegistry(
        (replace(manifest, lifecycle=CapabilityLifecycle.STOPPED),)
    )
    assert (
        await ProductionVerificationEvidence(stopped_registry, object(), store).collect(
            manifest.capability_id,
            "goal",
            __import__(
                "jarvis.capability_acquisition", fromlist=["AcquisitionStage"]
            ).AcquisitionStage.VERIFYING,
        )
        == ()
    )

    opportunity = CapabilityOpportunity(
        uuid4(),
        "synthetic need",
        ("evidence-1",),
        (
            OpportunityEvidence(
                OpportunityEvidenceSource.REPEATED_WORKFLOW,
                "evidence-1",
                "verified synthetic observation",
                0.9,
                datetime.now(UTC),
                True,
            ),
        ),
        0.9,
        "bounded benefit",
        "none",
        "small",
        ("trusted approval",),
        "synthetic-workspace",
        datetime.now(UTC),
        datetime.now(UTC),
        status=OpportunityStatus.DETECTED,
        preparation_state=OpportunityPreparationState.NOT_STARTED,
        decision=OpportunityDecision.PREPARE,
    )

    class _ResearchOnlyCoordinator:
        async def research(self, intent: object, analysis: object) -> GoalResearch:
            del intent, analysis
            return GoalResearch()

    coordinator = cast(CapabilityAcquisitionCoordinator, _ResearchOnlyCoordinator())
    with pytest.raises(ProductionCapabilityError):
        await ProductionOpportunityPreparation(coordinator).prepare(
            cast(CapabilityOpportunity, object())
        )
    prepared = await ProductionOpportunityPreparation(coordinator).prepare(opportunity)
    assert prepared.state is OpportunityPreparationState.READY
    assert "unavailable" in prepared.prepared_summary
