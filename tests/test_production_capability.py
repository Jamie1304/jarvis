from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Coroutine, Mapping
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
from jarvis.capabilities import (
    CapabilityActionSpec,
    CapabilityError,
    CapabilityLifecycle,
    CapabilityRegistry,
    EffectClassification,
    EffectMetadata,
    EnvironmentGraph,
    Reversibility,
    action_schema_dict,
    validate_action_schema,
)
from jarvis.capability_acquisition import AcquisitionStage, CapabilityAcquisitionCoordinator
from jarvis.capability_factory import (
    AdoptionCandidates,
    FactoryStrategy,
    GeneratedCapabilityPackage,
    SolutionReport,
    WorkspaceContext,
)
from jarvis.capability_health import CapabilityHealthService
from jarvis.capability_lifecycle import (
    LifecycleMetadata,
    SQLiteCapabilityLifecycleStore,
    StoredLifecycleRecord,
)
from jarvis.capability_opportunities import (
    CapabilityOpportunity,
    OpportunityDecision,
    OpportunityEvidence,
    OpportunityEvidenceSource,
    OpportunityPreparationState,
    OpportunityStatus,
)
from jarvis.core.errors import CapabilityUnavailableError, DuplicateToolError, ToolRegistrationError
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
    CertificationFailure,
    CertificationRecord,
    CertificationRequest,
    CertificationStage,
    CertificationStageEvidence,
    PackageCertifier,
    package_fingerprints,
)
from jarvis.package_reviewer import PackageSourceFile
from jarvis.package_runtime import HotLoadError, PackageRuntimeHealth, PreparedPackageRuntime
from jarvis.permissions.models import Permission, Risk
from jarvis.planning.validation import PlanProposal
from jarvis.production_capability import (
    AgentRuntimeCapabilityGenerator,
    CapabilityGenerationProvider,
    CapabilityLifecycleRestorer,
    CertificationFunctionalCase,
    PackageCertificationPlan,
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
    _action_spec_from_payload,
    _action_spec_payload,
    _AgentLoopGenerationProvider,
    _build_generic_package,
    _certification_fixture,
    _effect_from_payload,
    _GenerationSpec,
    _generic_worker_source,
    _manifest_for,
    _manifest_from_payload,
    _manifest_payload,
    _package_digest,
    _package_from_payload,
    _package_payload,
    _parse_generation_spec,
    _run_in_new_thread,
    _safe_identifier,
    _sandbox_python_executable,
    build_package_certification_plan,
)
from jarvis.provisioning import ProvisioningAction
from jarvis.resources import ResourceGovernor, SystemResourceTelemetry
from jarvis.sandbox import SandboxLimits
from jarvis.setup_conductor import SetupContext, SetupStep
from jarvis.tools.base import Tool
from jarvis.tools.harness import ToolHarness
from jarvis.tools.models import (
    SemanticVersion,
    ToolCaller,
    ToolEffectDisposition,
    ToolExecutionContext,
    ToolResultStatus,
)
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


def _action_spec(
    *,
    action_id: str = "transform",
    effect: EffectMetadata | None = None,
    permissions: tuple[Permission, ...] = (),
    target_scope: tuple[str, ...] = (),
    input_schema: Mapping[str, object] | None = None,
    output_schema: Mapping[str, object] | None = None,
    idempotent: bool = True,
    retryable: bool = False,
    package_hash: str = "a" * 64,
) -> CapabilityActionSpec:
    return CapabilityActionSpec(
        capability_id="synthetic-capability",
        package_id="generated.synthetic",
        package_version=SemanticVersion(1, 0, 0),
        package_hash=package_hash,
        action_id=action_id,
        semantic_name="Transform synthetic input",
        description="A bounded synthetic action",
        input_schema=input_schema
        or {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
            "additionalProperties": False,
        },
        output_schema=output_schema
        or {
            "type": "object",
            "properties": {"result": {"type": "string"}},
            "required": ["result"],
            "additionalProperties": False,
        },
        effect=effect or EffectMetadata(EffectClassification.OBSERVATION, Reversibility.READ_ONLY),
        required_permissions=permissions,
        target_scope=target_scope,
        idempotent=idempotent,
        retryable=retryable,
        verification=("adapter_output_schema", "action_completed"),
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


class _CapturingSandboxProcess(_FakeSandboxProcess):
    limits: list[SandboxLimits] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.limits.append(cast(SandboxLimits, kwargs["limits"]))
        super().__init__(*args, **kwargs)


class _FakeSandboxRunner:
    def __init__(self, status: SandboxSecurityStatus | None = None) -> None:
        self._status = status or _status()
        self.calls: list[str] = []

    def status(self) -> SandboxSecurityStatus:
        return self._status

    def probe(self, package: IntegrationPackage) -> SandboxSecurityStatus:
        del package
        return self._status

    def available_status(self) -> SandboxSecurityStatus:
        return self._status

    def execute(
        self, package: IntegrationPackage, action_id: str, payload: Mapping[str, object]
    ) -> tuple[SandboxSecurityStatus, dict[str, object]]:
        del payload
        self.calls.append(action_id)
        if action_id == "health":
            return self._status, {"status": "healthy", "capability": package.package_id}
        if action_id == "observe":
            return self._status, {
                "status": "observed",
                "capability": package.package_id,
                "label": "observed",
            }
        return self._status, {"status": action_id}

    def _execute(
        self, package: IntegrationPackage, kind: str, payload: dict[str, object]
    ) -> tuple[SandboxSecurityStatus, dict[str, object]]:
        return self.execute(package, kind, payload)


class _WrongSemanticSandboxRunner(_FakeSandboxRunner):
    def execute(
        self, package: IntegrationPackage, action_id: str, payload: Mapping[str, object]
    ) -> tuple[SandboxSecurityStatus, dict[str, object]]:
        status, response = super().execute(package, action_id, payload)
        if action_id == "observe":
            response["label"] = "wrong-semantic-result"
        return status, response


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


def _valid_generation_action_payload() -> dict[str, object]:
    return {
        "name": "Synthetic semantic action",
        "description": "A bounded action contract for a randomized local fixture",
        "actions": [
            {
                "action_id": "transform",
                "semantic_name": "Transform a value",
                "description": "Return a bounded transformed value",
                "input_schema": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                    "additionalProperties": False,
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"result": {"type": "string"}},
                    "required": ["result"],
                    "additionalProperties": False,
                },
                "effect": {
                    "classification": "observation",
                    "reversibility": "read_only",
                    "preview_supported": False,
                    "produced_artifacts": ["synthetic-result"],
                    "emitted_events": ["synthetic.completed"],
                },
                "permissions": [],
                "target_scope": [],
                "idempotent": True,
                "retryable": True,
                "verification": ["adapter_output_schema", "action_completed"],
            }
        ],
    }


def test_generation_action_contract_round_trips_as_a_typed_package() -> None:
    raw = json.dumps(_valid_generation_action_payload())
    spec = _parse_generation_spec(raw)
    assert len(spec.actions) == 1
    package = _build_generic_package(_gap("random-semantic-capability"), spec)
    assert package.tools == ("inspect", "transform")
    assert package.action_specs[0].package_hash == package.package_hash
    assert "ACTION_IDS" in _generic_worker_source(
        package.package_id, spec.name, package.action_specs
    )

    restored = _package_from_payload(_package_payload(package))
    assert restored == package
    manifest = _manifest_for(package, _request(_gap("random-semantic-capability")))
    assert _manifest_from_payload(_manifest_payload(manifest)) == manifest


@pytest.mark.parametrize(
    "case",
    [
        "actions_not_list",
        "duplicate_action",
        "item_not_object",
        "bad_identity",
        "bad_schema",
        "scalar_schema",
        "bad_effect_shape",
        "bad_effect_metadata",
        "bad_effect_value",
        "permissions_not_list",
        "unknown_permission",
        "bad_scope",
        "retry_mismatch",
        "bad_compensation",
        "too_many_scope_labels",
    ],
)
def test_generation_action_parser_rejects_malformed_declarations(case: str) -> None:
    payload = _valid_generation_action_payload()
    action = cast(dict[str, object], cast(list[object], payload["actions"])[0])
    if case == "actions_not_list":
        payload["actions"] = {}
    elif case == "duplicate_action":
        payload["actions"] = [action, dict(action)]
    elif case == "item_not_object":
        payload["actions"] = [None]
    elif case == "bad_identity":
        action["action_id"] = "inspect"
    elif case == "bad_schema":
        action["input_schema"] = {"type": "object", "unknown": True}
    elif case == "scalar_schema":
        action["output_schema"] = {"type": "string"}
    elif case == "bad_effect_shape":
        action["effect"] = []
    elif case == "bad_effect_metadata":
        cast(dict[str, object], action["effect"])["produced_artifacts"] = "artifact"
    elif case == "bad_effect_value":
        cast(dict[str, object], action["effect"])["classification"] = "not-an-effect"
    elif case == "permissions_not_list":
        action["permissions"] = "filesystem_write"
    elif case == "unknown_permission":
        action["permissions"] = ["not-a-permission"]
    elif case == "bad_scope":
        action["target_scope"] = [1]
    elif case == "retry_mismatch":
        action["retryable"] = True
        action["idempotent"] = False
    elif case == "bad_compensation":
        action["compensation"] = 1
    else:
        action["target_scope"] = ["scope"] * 33

    with pytest.raises(ProductionCapabilityError):
        _parse_generation_spec(json.dumps(payload))


@pytest.mark.parametrize(
    "schema",
    [
        None,
        [],
        {"type": "unsupported"},
        {"type": 1},
        {"type": "string", "unknown": True},
        {"type": "string", "description": ""},
        {"type": "string", "minLength": "one"},
        {"type": "string", "minimum": float("inf")},
        {"type": "object", "properties": []},
        {"type": "object", "properties": {"": {"type": "string"}}},
        {"type": "object", "properties": {"value": "bad"}},
        {"type": "object", "properties": {"value": {"type": "string"}}, "required": "value"},
        {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value", "value"],
        },
        {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["missing"],
        },
        {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "additionalProperties": True,
        },
        {"type": "string", "properties": {}},
        {"type": "array"},
        {"type": "array", "items": []},
        {"type": "string", "items": {"type": "string"}},
    ],
)
def test_generated_action_schema_rejects_malformed_or_executable_shapes(
    schema: object,
) -> None:
    with pytest.raises(CapabilityError):
        validate_action_schema(schema)

    deeply_nested: object = {"type": "string"}
    for _ in range(6):
        deeply_nested = {"type": "array", "items": deeply_nested}
    with pytest.raises(CapabilityError):
        validate_action_schema(deeply_nested)


def test_generated_action_contract_normalizes_nested_types_and_rejects_unsafe_metadata() -> None:
    complex_schema: Mapping[str, object] = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "count": {"type": "integer"},
            "ratio": {"type": "number"},
            "enabled": {"type": "boolean"},
            "items": {"type": "array", "items": {"type": "string"}},
            "nested": {
                "type": "object",
                "properties": {"flag": {"type": "boolean"}},
                "required": ["flag"],
                "additionalProperties": False,
            },
        },
        "required": ["name", "count", "ratio", "enabled", "items", "nested"],
        "additionalProperties": False,
    }
    spec = _action_spec(input_schema=complex_schema)
    assert action_schema_dict(spec.input_schema) == complex_schema
    detached = action_schema_dict(spec.input_schema)
    detached["properties"] = {}
    assert spec.input_schema["properties"] != {}

    with pytest.raises(CapabilityError):
        replace(spec, package_version=cast(Any, object()))
    with pytest.raises(CapabilityError):
        replace(spec, package_hash="not-a-hash")
    with pytest.raises(CapabilityError):
        replace(spec, action_id="inspect")
    with pytest.raises(CapabilityError):
        replace(spec, semantic_name="")
    with pytest.raises(CapabilityError):
        replace(spec, effect=cast(Any, object()))
    with pytest.raises(CapabilityError):
        replace(
            spec, required_permissions=(Permission.NETWORK_REQUEST, Permission.FILESYSTEM_WRITE)
        )
    with pytest.raises(CapabilityError):
        replace(
            spec,
            effect=EffectMetadata(EffectClassification.EXTERNAL_EFFECT, Reversibility.REVERSIBLE),
        )
    with pytest.raises(CapabilityError):
        replace(spec, retryable=True, idempotent=False)
    with pytest.raises(CapabilityError):
        replace(spec, idempotent=cast(Any, 1))
    with pytest.raises(CapabilityError):
        replace(spec, verification=("",))
    with pytest.raises(CapabilityError):
        replace(spec, compensation="")

    with pytest.raises(CapabilityError):
        EffectMetadata(cast(Any, object()), Reversibility.READ_ONLY)
    with pytest.raises(CapabilityError):
        EffectMetadata(EffectClassification.OBSERVATION, cast(Any, object()))
    with pytest.raises(CapabilityError):
        EffectMetadata(EffectClassification.OBSERVATION, Reversibility.READ_ONLY, cast(Any, 1))
    with pytest.raises(CapabilityError):
        EffectMetadata(
            EffectClassification.OBSERVATION,
            Reversibility.READ_ONLY,
            produced_artifacts=cast(Any, ["artifact"]),
        )


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
    with pytest.raises(ProductionCapabilityError, match="undeclared"):
        await runtime.request("not-declared", {})
    with pytest.raises(ProductionCapabilityError, match="schema"):
        await runtime.request("observe", {})
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
async def test_production_runtime_keeps_bounded_request_timeout_aligned_with_tool_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, generated, _ = await _generated(tmp_path)
    _CapturingSandboxProcess.limits.clear()
    monkeypatch.setattr("jarvis.production_capability.SandboxProcess", _CapturingSandboxProcess)
    runtime = ProductionPackageRuntime(
        generated.package,
        store,
        tmp_path / "sandboxes",
        ResourceGovernor(SystemResourceTelemetry()),
    )

    await runtime.request("inspect", {})

    assert _CapturingSandboxProcess.limits
    assert _CapturingSandboxProcess.limits[-1].timeout_seconds == 60.0


@pytest.mark.asyncio
async def test_generated_action_adapter_is_a_typed_tool_boundary(tmp_path: Path) -> None:
    _, generated, _ = await _generated(tmp_path)
    package = generated.package
    spec = package.action_specs[0]
    calls: list[tuple[str, str, Mapping[str, object]]] = []

    def invoke(
        package_id: str, action_id: str, payload: Mapping[str, object]
    ) -> Mapping[str, object]:
        calls.append((package_id, action_id, payload))
        return {"status": "observed", "capability": package_id, "label": "synthetic"}

    from jarvis.generated_capability import GeneratedCapabilityToolAdapter

    adapter = GeneratedCapabilityToolAdapter(spec, invoke)
    result = await ToolHarness().invoke(adapter, {"value": "bounded"})

    assert result.status is ToolResultStatus.SUCCESS
    assert result.output is not None
    assert calls == [(package.package_id, spec.action_id, {"value": "bounded"})]
    assert any(item.kind == "generated_action" for item in result.evidence)


@pytest.mark.asyncio
async def test_generated_action_adapter_validates_nested_io_and_effect_metadata() -> None:
    complex_input: Mapping[str, object] = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "count": {"type": "integer"},
            "ratio": {"type": "number"},
            "enabled": {"type": "boolean"},
            "items": {"type": "array", "items": {"type": "string"}},
            "nested": {
                "type": "object",
                "properties": {"flag": {"type": "boolean"}},
                "required": ["flag"],
                "additionalProperties": False,
            },
        },
        "required": ["name", "count", "ratio", "enabled", "items", "nested"],
        "additionalProperties": False,
    }
    spec = _action_spec(input_schema=complex_input)
    valid_input: Mapping[str, object] = {
        "name": "synthetic",
        "count": 2,
        "ratio": 1.5,
        "enabled": True,
        "items": ["one", "two"],
        "nested": {"flag": False},
    }

    async def invoke(
        package_id: str, action_id: str, payload: Mapping[str, object]
    ) -> Mapping[str, object]:
        assert package_id == spec.package_id
        assert action_id == spec.action_id
        assert payload["count"] == 2
        return {"result": "validated"}

    from jarvis.generated_capability import (
        GeneratedCapabilityError,
        GeneratedCapabilityToolAdapter,
        action_input_model,
        action_output_model,
        validate_action_input,
    )

    adapter = GeneratedCapabilityToolAdapter(spec, invoke)
    result = await ToolHarness().invoke(adapter, valid_input)
    assert result.status is ToolResultStatus.SUCCESS
    assert result.output is not None and result.output.result == "validated"  # type: ignore[attr-defined]
    validated = action_input_model(spec).model_validate(dict(valid_input), strict=True)
    assert validate_action_input(spec, valid_input).model_dump() == validated.model_dump()
    assert action_output_model(spec).model_validate({"result": "ok"}, strict=True)

    with pytest.raises(GeneratedCapabilityError):
        action_input_model(cast(Any, object()))
    with pytest.raises(GeneratedCapabilityError):
        action_output_model(cast(Any, object()))
    with pytest.raises(GeneratedCapabilityError):
        validate_action_input(spec, cast(Any, []))
    with pytest.raises(GeneratedCapabilityError):
        validate_action_input(spec, {"name": "wrong"})
    invalid_input = await ToolHarness().invoke(adapter, {**valid_input, "extra": True})
    assert invalid_input.status is ToolResultStatus.VALIDATION_ERROR

    bad_output = GeneratedCapabilityToolAdapter(
        spec,
        cast(Any, lambda *_args: {"result": 1}),
    )
    bad_result = await ToolHarness().invoke(bad_output, valid_input)
    assert bad_result.status is ToolResultStatus.INTERNAL_FAILURE
    assert bad_result.effect_disposition is ToolEffectDisposition.NO_EFFECT

    non_object = GeneratedCapabilityToolAdapter(
        spec,
        cast(Any, lambda *_args: "not an object"),
    )
    non_object_result = await ToolHarness().invoke(non_object, valid_input)
    assert non_object_result.status is ToolResultStatus.INTERNAL_FAILURE

    effect = EffectMetadata(
        EffectClassification.EXTERNAL_EFFECT,
        Reversibility.COMPENSATABLE,
        preview_supported=True,
        compensation="restore synthetic state",
    )
    effectful_spec = _action_spec(
        action_id="effectful",
        effect=effect,
        permissions=(
            Permission.APPLICATION_LAUNCH,
            Permission.COMPUTER_INPUT,
            Permission.FILESYSTEM_WRITE,
            Permission.NETWORK_REQUEST,
        ),
        target_scope=("C:\\synthetic-root", "synthetic.example.test"),
    )
    context = ToolExecutionContext(
        uuid4(), uuid4(), ToolCaller.TEST, asyncio.Event(), logging.getLogger("test.generated")
    )
    effectful_adapter = GeneratedCapabilityToolAdapter(
        effectful_spec,
        cast(Any, lambda *_args: (_ for _ in ()).throw(RuntimeError("hidden fixture failure"))),
    )
    descriptor = effectful_adapter._describe_action(  # noqa: SLF001
        context,
        effectful_adapter.input_model.model_validate({"value": "bounded"}, strict=True),
    )
    scopes = {item.permission: item.scope for item in descriptor.permissions}
    assert scopes[Permission.FILESYSTEM_WRITE].paths == (
        "C:\\synthetic-root",
        "synthetic.example.test",
    )
    assert scopes[Permission.NETWORK_REQUEST].hosts == (
        "C:\\synthetic-root",
        "synthetic.example.test",
    )
    assert scopes[Permission.APPLICATION_LAUNCH].applications == (
        "C:\\synthetic-root",
        "synthetic.example.test",
    )
    assert descriptor.risk is Risk.HIGH
    effect_result = await effectful_adapter._execute_authorized(  # noqa: SLF001
        context,
        effectful_adapter.input_model.model_validate({"value": "bounded"}, strict=True),
    )
    assert effect_result.status is ToolResultStatus.UNKNOWN_OUTCOME
    assert effect_result.effect_disposition is ToolEffectDisposition.UNKNOWN

    successful_effectful_adapter = GeneratedCapabilityToolAdapter(
        effectful_spec,
        cast(Any, lambda *_args: {"result": "package-reported completion"}),
    )
    successful_effect_result = await successful_effectful_adapter._execute_authorized(  # noqa: SLF001
        context,
        successful_effectful_adapter.input_model.model_validate({"value": "bounded"}, strict=True),
    )
    assert successful_effect_result.status is ToolResultStatus.UNKNOWN_OUTCOME
    assert successful_effect_result.output is None
    assert successful_effect_result.effect_disposition is ToolEffectDisposition.UNKNOWN

    critical_spec = _action_spec(
        action_id="destructive",
        effect=EffectMetadata(EffectClassification.DESTRUCTIVE, Reversibility.IRREVERSIBLE),
        permissions=(Permission.FILESYSTEM_WRITE,),
    )
    critical_adapter = GeneratedCapabilityToolAdapter(critical_spec, invoke)
    critical_descriptor = critical_adapter._describe_action(  # noqa: SLF001
        context,
        critical_adapter.input_model.model_validate({"value": "bounded"}, strict=True),
    )
    assert critical_descriptor.risk is Risk.CRITICAL

    with pytest.raises(GeneratedCapabilityError):
        GeneratedCapabilityToolAdapter(cast(Any, object()), invoke)
    with pytest.raises(GeneratedCapabilityError):
        GeneratedCapabilityToolAdapter(spec, cast(Any, object()))


def test_generated_action_model_and_risk_boundaries_fail_closed() -> None:
    from jarvis.generated_capability import GeneratedCapabilityError, _model_for_schema, _risk_for

    malformed_schemas: tuple[Mapping[str, object], ...] = (
        {"type": "array", "items": []},
        {"type": "object", "properties": []},
        {"type": "object", "properties": {"value": "bad"}},
        {"type": "unsupported"},
    )
    for schema in malformed_schemas:
        with pytest.raises(GeneratedCapabilityError, match="Generated"):
            _model_for_schema("Malformed", schema)
    with pytest.raises(GeneratedCapabilityError, match="object"):
        _model_for_schema("Scalar", {"type": "string"})
    with pytest.raises(GeneratedCapabilityError, match="root"):
        _model_for_schema("Root", {"type": "object", "properties": []})
    with pytest.raises(GeneratedCapabilityError, match="property"):
        _model_for_schema("Root", {"type": "object", "properties": {"value": "bad"}})

    local = SimpleNamespace(
        effect=EffectMetadata(EffectClassification.LOCAL_MUTATION, Reversibility.REVERSIBLE),
        required_permissions=(),
    )
    assert _risk_for(cast(CapabilityActionSpec, local)) is Risk.MEDIUM
    action = _action_spec()
    with pytest.raises(CapabilityError, match="objects"):
        replace(action, input_schema={"type": "string"})


@pytest.mark.asyncio
async def test_capability_and_environment_contracts_reject_invalid_trust_metadata(
    tmp_path: Path,
) -> None:
    from jarvis.capabilities import (
        CapabilityHealth,
        EnvironmentEdge,
        EnvironmentNode,
        EnvironmentNodeKind,
    )
    from jarvis.tools.models import ToolHealthStatus

    _, generated, gap = await _generated(tmp_path)
    manifest = _manifest_for(generated.package, _request(gap))
    naive = datetime.now()
    # Construct each invalid value under its assertion so a rejected fixture
    # cannot be confused with a failure while building the test inputs.
    invalid_manifest_kwargs: tuple[dict[str, object], ...] = (
        {"actions": ()},
        {"input_schema": {}},
        {"permissions": (cast(Any, object()),)},
        {"permissions": (Permission.FILESYSTEM_READ, Permission.FILESYSTEM_READ)},
        {"supported_platforms": frozenset()},
        {"supported_platforms": frozenset({cast(Any, object())})},
        {"confidence": 2.0},
        {"content_hash": ""},
        {"last_verified": naive},
        {"network_domains": ("synthetic.example.test",)},
        {"credential_references": ("token=secret",)},
    )
    for kwargs in invalid_manifest_kwargs:
        with pytest.raises(CapabilityError):
            replace(manifest, **cast(Any, kwargs))
    with pytest.raises(CapabilityError):
        CapabilityHealth(cast(Any, object()), "invalid")
    with pytest.raises(CapabilityError):
        CapabilityHealth(ToolHealthStatus.AVAILABLE, "invalid", naive)

    with pytest.raises(CapabilityError):
        EnvironmentNode("node", cast(Any, object()), "label")
    with pytest.raises(CapabilityError):
        EnvironmentNode(
            "node-secret",
            EnvironmentNodeKind.APPLICATION,
            "label",
            account_ref="api_key=secret",
        )
    with pytest.raises(CapabilityError):
        EnvironmentNode("node-confidence", EnvironmentNodeKind.APPLICATION, "label", confidence=2.0)
    with pytest.raises(CapabilityError):
        EnvironmentNode(
            "node-time",
            EnvironmentNodeKind.APPLICATION,
            "label",
            last_verified=naive,
        )
    with pytest.raises(CapabilityError):
        EnvironmentEdge("source", "target", "relation", confidence=2.0)
    with pytest.raises(CapabilityError):
        EnvironmentEdge("source", "target", "relation", last_verified=naive)

    graph = EnvironmentGraph()
    source = EnvironmentNode("source", EnvironmentNodeKind.APPLICATION, "source")
    target = EnvironmentNode("target", EnvironmentNodeKind.SERVICE, "target")
    graph.add_node(source)
    graph.add_node(target)
    with pytest.raises(CapabilityError):
        graph.add_node(source)
    with pytest.raises(CapabilityError):
        graph.add_edge(EnvironmentEdge("missing", "target", "uses"))
    graph.add_edge(EnvironmentEdge("source", "target", "uses"))
    assert graph.related("source") == (target,)
    graph.remove_node("target")
    assert graph.edges() == ()
    with pytest.raises(KeyError):
        graph.remove_node("target")
    with pytest.raises(KeyError):
        graph.related("target")


@pytest.mark.asyncio
async def test_persisted_generated_action_metadata_rejects_tampering(tmp_path: Path) -> None:
    _, generated, _ = await _generated(tmp_path)
    package = generated.package
    spec = package.action_specs[0]
    serialized = _action_spec_payload(spec)
    assert (
        _action_spec_from_payload(
            serialized, package.package_id, package.version, package.package_hash
        )
        == spec
    )
    assert _effect_from_payload(serialized["effect"]) == spec.effect

    malformed: list[object] = [None]
    for field, value in (
        ("package_id", "other-package"),
        ("package_version", "9.9.9"),
        ("package_hash", "b" * 64),
        ("required_permissions", "not-a-list"),
        ("target_scope", "not-a-list"),
        ("verification", "not-a-list"),
        ("input_schema", []),
        ("output_schema", []),
        ("idempotent", 1),
        ("retryable", 1),
        ("compensation", 1),
    ):
        candidate = dict(serialized)
        candidate[field] = value
        malformed.append(candidate)
    missing_effect = dict(serialized)
    del missing_effect["effect"]
    malformed.append(missing_effect)
    bad_permission = dict(serialized)
    bad_permission["required_permissions"] = ["unknown-permission"]
    malformed.append(bad_permission)
    for malformed_candidate in malformed:
        with pytest.raises(ProductionCapabilityError):
            _action_spec_from_payload(
                malformed_candidate, package.package_id, package.version, package.package_hash
            )

    effect_cases: tuple[object, ...] = (
        None,
        {"classification": "observation", "reversibility": "read_only", "preview_supported": 1},
        {
            "classification": "observation",
            "reversibility": "read_only",
            "produced_artifacts": "not-a-list",
        },
        {"classification": "not-an-effect", "reversibility": "read_only"},
        {"reversibility": "read_only"},
    )
    for effect_candidate in effect_cases:
        with pytest.raises(ProductionCapabilityError):
            _effect_from_payload(effect_candidate)


@pytest.mark.asyncio
async def test_manifest_storage_round_trip_and_invalid_persisted_values(
    tmp_path: Path,
) -> None:
    store, generated, gap = await _generated(tmp_path)
    package = generated.package
    request = _request(gap)
    manifest = store.manifest(package, request)
    assert store.manifest(package, request) is manifest
    certification = _restore_certification(package, store.source_files(package))
    assert (
        store.activation_request(
            package,
            certification,
            store.source_files(package),
            None,
        ).package
        == package
    )

    payload = _manifest_payload(manifest)
    invalid: list[dict[str, object]] = []
    for field, value in (
        ("supported_platforms", "not-a-list"),
        ("health", []),
        ("input_schema", []),
        ("output_schema", []),
        ("network_required", 1),
        ("last_verified", "not-a-timestamp"),
    ):
        candidate = json.loads(json.dumps(payload))
        candidate[field] = value
        invalid.append(candidate)
    for candidate in invalid:
        with pytest.raises(ProductionCapabilityError):
            _manifest_from_payload(candidate)

    no_actions = replace(package, action_specs=())
    no_action_manifest = _manifest_for(no_actions, request)
    assert no_action_manifest.actions == ("inspect",)
    assert no_action_manifest.effect.classification is EffectClassification.OBSERVATION
    external_package = replace(
        package,
        permissions=(Permission.NETWORK_REQUEST,),
        action_specs=(
            replace(
                package.action_specs[0],
                effect=EffectMetadata(
                    EffectClassification.EXTERNAL_EFFECT, Reversibility.REVERSIBLE
                ),
                required_permissions=(Permission.NETWORK_REQUEST,),
            ),
        ),
    )
    assert _manifest_for(external_package, request).risk is Risk.HIGH
    destructive_package = replace(
        package,
        permissions=(Permission.FILESYSTEM_WRITE,),
        action_specs=(
            replace(
                package.action_specs[0],
                effect=EffectMetadata(EffectClassification.DESTRUCTIVE, Reversibility.IRREVERSIBLE),
                required_permissions=(Permission.FILESYSTEM_WRITE,),
            ),
        ),
    )
    assert _manifest_for(destructive_package, request).risk is Risk.CRITICAL


@pytest.mark.asyncio
async def test_package_store_rechecks_immutable_metadata_and_timestamp_shapes(
    tmp_path: Path,
) -> None:
    store, generated, gap = await _generated(tmp_path)
    package = generated.package
    assert store.root == (tmp_path / "packages").resolve()
    reopened = ProductionPackageStore(store.root)
    assert reopened.load(package.package_id, str(package.version), package.package_hash) == package
    with pytest.raises(ProductionCapabilityError):
        reopened.load(package.package_id, "1", package.package_hash)
    with pytest.raises(ProductionCapabilityError):
        reopened.load(package.package_id, str(package.version), "B" * 64)

    changed_spec = replace(package.action_specs[0], semantic_name="different semantic name")
    changed = replace(package, action_specs=(changed_spec,))
    changed_generated = GeneratedCapabilityPackage(
        changed,
        static_checked=True,
        sandbox_tested=True,
        security_checked=True,
        generated_by="synthetic-test",
        source_files=store.source_files(package),
    )
    with pytest.raises(ProductionCapabilityError, match="metadata hash"):
        store.save_candidate(changed_generated, gap=gap)

    manifest = store.manifest(package, _request(gap))
    payload = _manifest_payload(manifest)
    for health_value in (
        {"status": "available", "detail": "healthy", "checked_at": 1},
        {"status": "available", "detail": "healthy", "checked_at": "not-iso"},
        {"status": "available", "detail": "healthy", "checked_at": "2026-01-01T00:00:00"},
    ):
        candidate = json.loads(json.dumps(payload))
        candidate["health"] = health_value
        with pytest.raises(ProductionCapabilityError):
            _manifest_from_payload(candidate)
    for field, value in (
        ("actions", "not-a-list"),
        ("permissions", ["not-a-permission"]),
        ("confidence", float("nan")),
    ):
        candidate = json.loads(json.dumps(payload, allow_nan=True))
        candidate[field] = value
        with pytest.raises(ProductionCapabilityError):
            _manifest_from_payload(candidate)


@pytest.mark.asyncio
async def test_integration_package_action_and_data_boundaries_fail_closed(tmp_path: Path) -> None:
    from jarvis.integration_package import (
        DiagnosticProbe,
        PackageAsset,
        PackageBoundary,
        PackageContractError,
        PackageOperationPolicy,
        SafeRepairAction,
        SecretSchema,
    )

    _, generated, _ = await _generated(tmp_path)
    package = generated.package
    spec = package.action_specs[0]
    cases: tuple[Callable[[], object], ...] = (
        lambda: replace(package, tools=("",)),
        lambda: replace(
            package,
            permissions=(Permission.NETWORK_REQUEST, Permission.FILESYSTEM_READ),
        ),
        lambda: replace(package, entries=(package.entries[0], package.entries[0])),
        lambda: replace(package, action_specs=(cast(Any, object()),)),
        lambda: replace(package, action_specs=(spec, spec)),
        lambda: replace(package, action_specs=(replace(spec, package_id="other-package"),)),
        lambda: replace(
            package,
            action_specs=(replace(spec, required_permissions=(Permission.FILESYSTEM_WRITE,)),),
        ),
    )
    for make_invalid in cases:
        with pytest.raises(PackageContractError):
            make_invalid()

    with pytest.raises(PackageContractError):
        SecretSchema("secret", "description", vault_reference_only=False)
    with pytest.raises(PackageContractError):
        DiagnosticProbe("probe", "description", safe_read_only=False)
    with pytest.raises(PackageContractError):
        SafeRepairAction("repair", "description", requires_approval=False)
    with pytest.raises(PackageContractError):
        PackageAsset("asset")
    with pytest.raises(PackageContractError):
        PackageAsset("asset", artifact_ref="C:/not-an-artifact-ref")
    with pytest.raises(PackageContractError):
        PackageOperationPolicy(preserve_user_config=False)
    with pytest.raises(PackageContractError):
        replace(package.entries[0], boundary=PackageBoundary.USER_CONFIG)


@pytest.mark.asyncio
async def test_generated_registration_requires_active_durable_lifecycle_and_planner_uses_adapter(
    tmp_path: Path,
) -> None:
    from jarvis.generated_capability import (
        GeneratedActionPlanPlanner,
        GeneratedCapabilityError,
        GeneratedCapabilityToolAdapter,
        GeneratedCapabilityToolRegistrar,
    )
    from jarvis.goal_supervisor import GoalIntent
    from jarvis.tools.registry import ToolRegistry

    store, generated, gap = await _generated(tmp_path)
    package = generated.package
    certification = _restore_certification(package, store.source_files(package))
    lifecycle = SQLiteCapabilityLifecycleStore(tmp_path / "lifecycle.sqlite3")
    lifecycle.create(_restore_record(package, certification, ActivationState.CERTIFIED))
    registry = ToolRegistry()
    registry.seal()

    def invoke(
        package_id: str, action_id: str, payload: Mapping[str, object]
    ) -> Mapping[str, object]:
        del action_id, payload
        return {"status": "observed", "capability": package_id, "label": "synthetic"}

    adapter = GeneratedCapabilityToolAdapter(package.action_specs[0], invoke)
    with pytest.raises(ToolRegistrationError, match="activation registration port"):
        registry.register(adapter)
    unsealed_registry = ToolRegistry()
    with pytest.raises(ToolRegistrationError, match="sealed startup registry"):
        unsealed_registry._trusted_application_registration_port().activate(  # noqa: SLF001
            package.package_id,
            package.version,
            package.package_hash,
            certification,
            (adapter,),
        )
    with pytest.raises(GeneratedCapabilityError, match="malformed"):
        GeneratedCapabilityToolRegistrar(cast(Any, object()), lifecycle, invoke)
    with pytest.raises(GeneratedCapabilityError, match="malformed"):
        GeneratedCapabilityToolRegistrar(
            registry._trusted_application_registration_port(), cast(Any, object()), invoke
        )  # noqa: SLF001
    with pytest.raises(GeneratedCapabilityError, match="malformed"):
        GeneratedCapabilityToolRegistrar(
            registry._trusted_application_registration_port(), lifecycle, cast(Any, object())
        )  # noqa: SLF001
    registrar = GeneratedCapabilityToolRegistrar(
        registry._trusted_application_registration_port(),  # noqa: SLF001
        lifecycle,
        invoke,
    )
    with pytest.raises(GeneratedCapabilityError, match="malformed"):
        registrar.activate(cast(Any, object()), certification)
    with pytest.raises(GeneratedCapabilityError, match="bound package hash"):
        GeneratedCapabilityToolAdapter(_action_spec(package_hash=""), invoke)
    with pytest.raises(GeneratedCapabilityError, match="ACTIVE"):
        registrar.activate(package, certification)
    lifecycle.save(
        _restore_record(package, certification, ActivationState.SHADOW), expected_revision=1
    )
    lifecycle.save(
        _restore_record(package, certification, ActivationState.CANARY), expected_revision=2
    )
    active = _restore_record(package, certification, ActivationState.ACTIVE)
    lifecycle.save(active, expected_revision=3)
    stale_certification = replace(certification, package_hash="b" * 64)
    with pytest.raises(GeneratedCapabilityError, match="stale"):
        registrar.activate(package, stale_certification)
    empty_package = replace(package, action_specs=())
    with pytest.raises(GeneratedCapabilityError, match="no semantic"):
        registrar.activate(empty_package, certification)
    registrar.activate(package, certification)
    assert registry.find_by_capability(gap.desired_capability)
    registrar.deactivate(package.package_id)
    assert registry.find_by_capability(gap.desired_capability) == ()

    other_store, other_generated, _ = await _generated(tmp_path / "other", desired="other")
    other_package = other_generated.package
    other_certification = _restore_certification(
        other_package, other_store.source_files(other_package)
    )
    lifecycle.create(_restore_record(other_package, other_certification, ActivationState.CERTIFIED))
    with pytest.raises(GeneratedCapabilityError, match="ACTIVE"):
        registrar.activate(other_package, other_certification)
    lifecycle.close()

    planner = GeneratedActionPlanPlanner(
        SimpleNamespace(
            find_by_capability=lambda _capability: (SimpleNamespace(tool=adapter, usable=True),)
        )
    )
    valid_intent = GoalIntent(
        "observe randomized input",
        required_capabilities=(gap.desired_capability,),
        metadata={
            "generated_action_input": {"value": "bounded"},
            "generated_expected_output": "observed",
        },
    )
    proposal = planner.proposal_for(valid_intent)
    assert isinstance(proposal, PlanProposal)
    assert proposal.steps[0].tool_id == adapter.manifest.tool_id
    assert planner.proposal_for(object()) is None
    assert planner.proposal_for(GoalIntent("no capability")) is None
    assert (
        planner.proposal_for(
            replace(valid_intent, metadata={"generated_action_input": {"value": "bounded"}})
        )
        is None
    )
    assert (
        planner.proposal_for(
            replace(
                valid_intent,
                metadata={
                    "generated_action_input": {"value": "bounded"},
                    "generated_expected_output": 1,
                },
            )
        )
        is None
    )
    assert GeneratedActionPlanPlanner(object()).proposal_for(valid_intent) is None
    assert (
        GeneratedActionPlanPlanner(
            SimpleNamespace(find_by_capability=lambda _capability: ())
        ).proposal_for(valid_intent)
        is None
    )
    assert (
        GeneratedActionPlanPlanner(
            SimpleNamespace(
                find_by_capability=lambda _capability: (
                    SimpleNamespace(tool=object(), usable=True),
                )
            )
        ).proposal_for(valid_intent)
        is None
    )
    assert (
        GeneratedActionPlanPlanner(
            SimpleNamespace(
                find_by_capability=lambda _capability: (
                    SimpleNamespace(tool=adapter, usable=False),
                )
            )
        ).proposal_for(valid_intent)
        is None
    )
    assert (
        planner.proposal_for(
            replace(
                valid_intent,
                metadata={
                    "generated_action_input": {"value": 1},
                    "generated_expected_output": "observed",
                },
            )
        )
        is None
    )


@pytest.mark.asyncio
async def test_generated_registry_identity_and_atomic_swap_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from jarvis.generated_capability import GeneratedCapabilityToolAdapter
    from jarvis.tools.registry import ToolRegistry

    _, generated, _ = await _generated(tmp_path)
    package = generated.package
    certification = _restore_certification(package, ())
    registry = ToolRegistry()
    registry.seal()
    port = registry._trusted_application_registration_port()  # noqa: SLF001

    def invoke(
        package_id: str, action_id: str, payload: Mapping[str, object]
    ) -> Mapping[str, object]:
        del action_id, payload
        return {"status": "observed", "capability": package_id, "label": "synthetic"}

    adapter = GeneratedCapabilityToolAdapter(package.action_specs[0], invoke)
    with pytest.raises(ToolRegistrationError, match="authority"):
        registry._activate_generated(  # noqa: SLF001
            object(),
            package.package_id,
            package.version,
            package.package_hash,
            certification,
            (adapter,),
        )
    with pytest.raises(ToolRegistrationError, match="identity"):
        port.activate("", package.version, package.package_hash, certification, (adapter,))
    with pytest.raises(ToolRegistrationError, match="identity"):
        port.activate(package.package_id, package.version, "b" * 64, certification, (adapter,))
    with pytest.raises(ToolRegistrationError, match="semantic"):
        port.activate(package.package_id, package.version, package.package_hash, certification, ())
    with pytest.raises(ToolRegistrationError, match="adapter"):
        port.activate(
            package.package_id,
            package.version,
            package.package_hash,
            certification,
            (cast(Any, object()),),
        )
    mismatched = GeneratedCapabilityToolAdapter(_action_spec(package_hash="b" * 64), invoke)
    with pytest.raises(ToolRegistrationError, match="identity"):
        port.activate(
            package.package_id,
            package.version,
            package.package_hash,
            certification,
            (mismatched,),
        )
    with pytest.raises(DuplicateToolError, match="unique"):
        port.activate(
            package.package_id,
            package.version,
            package.package_hash,
            certification,
            (adapter, adapter),
        )

    failed_registry = ToolRegistry()
    failed_registry.register_factory(adapter.manifest.tool_id, lambda: cast(Any, object()))
    failed_registry.seal()
    with pytest.raises(DuplicateToolError, match="failed registration"):
        failed_registry._trusted_application_registration_port().activate(  # noqa: SLF001
            package.package_id,
            package.version,
            package.package_hash,
            certification,
            (adapter,),
        )

    calls = 0
    broker = registry.permission_broker
    original_register = broker._register_tool_for_trusted_application  # noqa: SLF001

    def fail_once(
        authority: object,
        tool_id: str,
        tool: Tool[Any, Any],
        permissions: frozenset[Permission],
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ValueError("synthetic registration failure")
        original_register(authority, tool_id, tool, permissions)

    port.activate(
        package.package_id,
        package.version,
        package.package_hash,
        certification,
        (adapter,),
    )
    second = GeneratedCapabilityToolAdapter(
        replace(package.action_specs[0], action_id="second-action"), invoke
    )
    monkeypatch.setattr(broker, "_register_tool_for_trusted_application", fail_once)
    with pytest.raises(ToolRegistrationError, match="swap failed"):
        port.activate(
            package.package_id,
            package.version,
            package.package_hash,
            certification,
            (second,),
        )
    assert registry.get(adapter.manifest.tool_id) is adapter
    with pytest.raises(CapabilityUnavailableError):
        registry.get(second.manifest.tool_id)


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
async def test_production_certification_executes_actions_and_rejects_wrong_semantics(
    tmp_path: Path,
) -> None:
    store, generated, _ = await _generated(tmp_path)
    sandbox = _WrongSemanticSandboxRunner()
    provider = ProductionCertificationProvider(
        store, cast(ProductionSandboxRunner, sandbox), VerificationEngine()
    )
    hooks = provider.hooks(generated.package)

    result = hooks.unit_tests(generated.package)
    assert not result.passed
    assert "independent semantic oracle mismatch" in result.evidence[0]
    assert "observe" in sandbox.calls
    assert provider.plan(generated.package).package_hash == generated.package.package_hash
    with pytest.raises(CertificationFailure) as failure:
        PackageCertifier().certify(
            CertificationRequest(
                generated.package,
                "rollback:synthetic",
                ("local-runtime",),
                ("synthetic outcome",),
            ),
            hooks,
        )
    assert failure.value.stage is CertificationStage.UNIT_TESTS


def test_package_certification_plan_requires_application_oracle_for_custom_actions() -> None:
    base = _build_generic_package(
        _gap(),
        _GenerationSpec("Synthetic", "Synthetic package", None, ()),
    )
    spec = replace(
        _action_spec(action_id="custom"),
        package_id=base.package_id,
        package_version=base.version,
        package_hash=base.package_hash,
    )
    package = replace(base, action_specs=(spec,))
    plan = PackageCertificationPlan(
        package.package_id,
        str(package.version),
        package.package_hash,
        (CertificationFunctionalCase("custom-case", "custom", {"value": "x"}),),
    )
    assert plan.semantic_oracle is None
    built = build_package_certification_plan(package)
    with pytest.raises(ProductionCapabilityError, match="No application-owned semantic oracle"):
        assert built.semantic_oracle is not None
        built.semantic_oracle(spec, {"value": "x"})


@pytest.mark.asyncio
async def test_production_verification_evidence_and_opportunity_boundaries(
    tmp_path: Path,
) -> None:
    store, generated, gap = await _generated(tmp_path)
    package = generated.package
    request = _request(gap)
    manifest = store.manifest(package, request)
    registry = CapabilityRegistry((manifest,))
    evidence = ProductionVerificationEvidence(
        registry,
        object(),
        store,
        sandbox=cast(ProductionSandboxRunner, _FakeSandboxRunner()),
    )
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
    assert collected and collected[0].source.startswith("trusted.package.semantic:")
    assert "goal=" in collected[0].source

    adopted_registry = CapabilityRegistry((replace(manifest, integration_owner="adopted.runtime"),))
    adopted_evidence = ProductionVerificationEvidence(adopted_registry, object(), store)
    adopted = await adopted_evidence.collect(
        manifest.capability_id,
        "goal",
        AcquisitionStage.VERIFYING,
    )
    assert adopted and adopted[0].source.startswith("trusted.capability.registry:")
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


@pytest.mark.asyncio
async def test_production_runtime_helpers_and_verification_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production composition helpers reject malformed or contradictory boundary data."""

    assert _certification_fixture({"enum": ["fixed"]}, key="value") == "fixed"
    assert _certification_fixture(
        {
            "type": "object",
            "properties": {
                "capability": {"type": "string"},
                "count": {"type": "integer"},
                "enabled": {"type": "boolean"},
                "items": {"type": "array"},
            },
            "required": ["capability", "count", "enabled", "items", "missing"],
        },
        key="input",
        package_id="generated.synthetic",
    ) == {
        "capability": "generated.synthetic",
        "count": 0,
        "enabled": False,
        "items": [],
    }
    assert _certification_fixture({"type": "string"}, key="salt") == "certification-salt"
    assert _certification_fixture({"type": "number"}, key="value") == 0.0
    for schema in (
        {"type": "object", "properties": [], "required": []},
        {"type": "object", "properties": {}, "required": "not-a-list"},
        {"type": "null"},
    ):
        with pytest.raises(ProductionCapabilityError):
            _certification_fixture(schema, key="input")

    async def _thread_value() -> str:
        return "trusted result"

    async def _thread_failure() -> str:
        raise RuntimeError("synthetic thread failure")

    assert _run_in_new_thread(_thread_value()) == "trusted result"
    with pytest.raises(RuntimeError, match="synthetic thread failure"):
        _run_in_new_thread(_thread_failure())
    assert _sandbox_python_executable().is_file()

    store, generated, gap = await _generated(tmp_path)
    package = generated.package
    runtime = ProductionPackageRuntime(
        package,
        store,
        tmp_path / "sandboxes",
        ResourceGovernor(SystemResourceTelemetry()),
    )
    assert runtime.health_check().healthy
    runtime.restore_state({"bounded": "state"})
    assert runtime.export_state() == {"bounded": "state"}
    with pytest.raises(HotLoadError, match="state is malformed"):
        runtime.restore_state(cast(Mapping[str, object], {1: "not-a-string-key"}))
    runtime._active_requests = 1  # noqa: SLF001 - verifies the owned runtime drain guard.
    with pytest.raises(HotLoadError, match="active requests"):
        runtime.drain()
    runtime._active_requests = 0  # noqa: SLF001
    with pytest.raises(ProductionCapabilityError, match="request is malformed"):
        await runtime.request(cast(str, ""), {})
    with pytest.raises(ProductionCapabilityError, match="undeclared"):
        await runtime.request("missing-action", {})

    def _request_blocking(kind: str, payload: Mapping[str, object]) -> dict[str, object]:
        return {"kind": kind, "payload": dict(payload)}

    monkeypatch.setattr(runtime, "_request_blocking", _request_blocking)
    assert await runtime.request("health", {"probe": "bounded"}) == {
        "kind": "health",
        "payload": {"probe": "bounded"},
    }
    entrypoint = store.package_directory(package) / "code" / "entrypoint.py"
    entrypoint.unlink()
    assert not runtime.health_check().healthy
    with pytest.raises(HotLoadError):
        ProductionPackageRuntimeFactory(
            store,
            tmp_path / "sandboxes",
            ResourceGovernor(SystemResourceTelemetry()),
        ).prepare(package)

    intact_store, intact_generated, intact_gap = await _generated(tmp_path / "intact")
    manifest = intact_store.manifest(intact_generated.package, _request(intact_gap))
    registry = CapabilityRegistry((manifest,))
    assert (
        await ProductionVerificationEvidence(
            registry,
            object(),
            intact_store,
            sandbox=None,
        ).collect(manifest.capability_id, "goal", AcquisitionStage.VERIFYING)
        == ()
    )
    assert (
        await ProductionVerificationEvidence(
            registry,
            object(),
            intact_store,
            sandbox=cast(ProductionSandboxRunner, _FakeSandboxRunner()),
        ).collect(manifest.capability_id, "", AcquisitionStage.VERIFYING)
        == ()
    )


def test_lifecycle_restorer_certified_state_and_binding_fail_closed(tmp_path: Path) -> None:
    """A durable CERTIFIED row is staged, and malformed health binding is rejected."""

    store, generated, gap = asyncio.run(_generated(tmp_path))
    package = generated.package
    store.manifest(package, _request(gap))
    certification = _restore_certification(package, store.source_files(package))
    lifecycle = _RestoreLifecycleStore(
        _stored_restore_record(package, certification, ActivationState.CERTIFIED)
    )
    restorer = CapabilityLifecycleRestorer(
        cast(Any, lifecycle),
        store,
        cast(Any, _FakeSandboxRunner()),
        cast(Any, _RestoreActivation(lifecycle.stored.record)),
        CapabilityRegistry(),
    )
    result = restorer.restore_all()
    assert not result[0].restored
    assert result[0].resulting_state is ActivationState.CERTIFIED
    with pytest.raises(ProductionCapabilityError, match="health service is malformed"):
        restorer.bind_health(cast(CapabilityHealthService, object()))
