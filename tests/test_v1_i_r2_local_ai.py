"""Deterministic V1-I-R2 model intelligence and local-AI acceptance tests."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

import httpx
import pytest
from jarvis.ai.knowledge import (
    CookbookObservation,
    CookbookOutcome,
    EvidenceSufficiency,
    ModelKnowledgeService,
    ModelKnowledgeStore,
    VerifierAgreement,
    identity_for,
)
from jarvis.ai.local_ai import (
    AcquisitionStatus,
    LocalAIControlPlane,
    LocalAISetupMode,
    LocalAISetupStatus,
    LocalAIUserPolicy,
)
from jarvis.ai.model_manager import (
    LocalModelManager,
    LocalModelSpec,
    ModelArtifact,
    ModelLifecycleError,
    ModelLifecycleState,
)
from jarvis.ai.models import (
    ChatMessage,
    GenerationRequest,
    MessageRole,
    ModelRole,
    PrivacyClassification,
    PrivacyContext,
)
from jarvis.ai.providers.ollama_runtime import (
    OllamaModelAdapter,
    OllamaRuntimeManager,
)
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderDefinition,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.ai.routing import (
    InferenceDispatcher,
    ProviderRouter,
    RouteBenchmark,
    RouteCandidate,
    RouteDecision,
    RouteRequest,
    RouteStatus,
    RoutingPolicy,
)
from jarvis.capability_health import HealthStatus
from jarvis.component_doctor import ComponentProblem, DiagnosticOwner, RoutedRepairResearch
from jarvis.hardware import (
    FitStatus,
    HardwareInventoryService,
    HardwareReading,
    ModelCombinationRequest,
    ModelInventory,
    ModelPlanner,
)
from jarvis.resources import (
    ResourceGovernor,
    ResourcePolicy,
    ResourcePriority,
    ResourceSnapshot,
)

from tests.fakes import FakeAIProvider
from tests.test_hardware import _hardware

_SETUP_EVIDENCE = "test_local_ai_setup_selects_dynamic_models_and_preserves_identity_across_reload"
_POLICY_EVIDENCE = (
    "test_local_ai_policy_controls_acquisition_and_resource_pressure_unloads_only_idle"
)
_SWITCH_EVIDENCE = "test_routing_switching_cost_prefers_warm_or_materially_better_models"
_CALIBRATION_EVIDENCE = "test_calibration_requires_independent_verification_and_updates_cookbook"
_COOKBOOK_EVIDENCE = (
    "test_task_specific_cookbook_evidence_prefers_better_route_without_global_replacement"
)
_FAILURE_EVIDENCE = (
    "tests.test_p3c_adaptive_routing::test_dispatcher_reroutes_bounded_failure_before_stream_output"
)
_EXTERNAL_EVIDENCE = (
    "tests.test_ollama_runtime::test_reachable_ollama_is_adopted_without_a_second_launch"
)
_FALLBACK_EVIDENCE = (
    "tests.test_p3c_adaptive_routing::test_timeout_reroutes_but_cancellation_does_not"
)
_NO_CLOUD_EVIDENCE = "tests.test_v1_h_burn_in::test_v1_h_no_cloud_route_never_calls_remote_provider"
_KNOWLEDGE_EVIDENCE = (
    "tests.test_model_knowledge::test_measurements_remain_separate_latest_bounded_and_restart_safe"
)


V1_I_R2_DETERMINISTIC_MATRIX: tuple[dict[str, str], ...] = (
    {
        "case": "initial_local_provider_adoption",
        "evidence": _SETUP_EVIDENCE,
    },
    {
        "case": "initial_hardware_aware_portfolio",
        "evidence": _SETUP_EVIDENCE,
    },
    {
        "case": "constrained_hardware",
        "evidence": "test_constrained_hardware_chooses_a_realistic_multi_role_portfolio",
    },
    {
        "case": "acquisition_allowed",
        "evidence": _POLICY_EVIDENCE,
    },
    {
        "case": "acquisition_blocked_by_policy",
        "evidence": _POLICY_EVIDENCE,
    },
    {
        "case": "acquisition_deferred_by_resources",
        "evidence": "test_background_calibration_and_acquisition_defer_under_system_pressure",
    },
    {
        "case": "lifecycle_load",
        "evidence": _SETUP_EVIDENCE,
    },
    {
        "case": "warm_reuse",
        "evidence": _SETUP_EVIDENCE,
    },
    {
        "case": "idle_unload",
        "evidence": _SETUP_EVIDENCE,
    },
    {
        "case": "reload",
        "evidence": _SETUP_EVIDENCE,
    },
    {
        "case": "selected_model_equals_actual_model",
        "evidence": _SETUP_EVIDENCE,
    },
    {
        "case": "pointless_switch_avoided",
        "evidence": _SWITCH_EVIDENCE,
    },
    {
        "case": "material_switch_performed",
        "evidence": _SWITCH_EVIDENCE,
    },
    {
        "case": "candidate_discovery_without_name_branch",
        "evidence": "test_ollama_adapter_reports_provider_truth_and_measures_real_api_calls",
    },
    {
        "case": "candidate_calibration",
        "evidence": "test_calibration_requires_independent_verification_and_updates_cookbook",
    },
    {
        "case": "better_candidate_promoted_for_task",
        "evidence": _COOKBOOK_EVIDENCE,
    },
    {
        "case": "worse_newer_candidate_not_promoted",
        "evidence": _CALIBRATION_EVIDENCE,
    },
    {
        "case": "failure_specific_rerouting",
        "evidence": _FAILURE_EVIDENCE,
    },
    {
        "case": "strong_model_bounded_repair_research",
        "evidence": "test_strong_repair_research_uses_same_untrusted_candidate_boundary",
    },
    {
        "case": "strong_model_remains_untrusted",
        "evidence": "test_strong_repair_research_uses_same_untrusted_candidate_boundary",
    },
    {
        "case": "provider_owned_recovery",
        "evidence": "test_owned_ollama_recovery_terminates_only_owned_process",
    },
    {
        "case": "external_provider_not_killed",
        "evidence": _EXTERNAL_EVIDENCE,
    },
    {
        "case": "local_provider_failure_fallback",
        "evidence": _FALLBACK_EVIDENCE,
    },
    {
        "case": "local_only_never_cloud_fallback",
        "evidence": _NO_CLOUD_EVIDENCE,
    },
    {
        "case": "pressure_unloads_safe_idle_candidate",
        "evidence": "test_background_calibration_and_acquisition_defer_under_system_pressure",
    },
    {
        "case": "pressure_selects_smaller_route",
        "evidence": "test_resource_pressure_selects_smaller_sufficient_route",
    },
    {
        "case": "active_model_not_evicted",
        "evidence": _POLICY_EVIDENCE,
    },
    {
        "case": "restart_rediscovery",
        "evidence": _SETUP_EVIDENCE,
    },
    {
        "case": "cookbook_measurement_survives_restart",
        "evidence": _KNOWLEDGE_EVIDENCE,
    },
    {
        "case": "no_completed_inference_replay",
        "evidence": _SETUP_EVIDENCE,
    },
)


class _OllamaHarness:
    """Small typed HTTP harness matching only the provider APIs used by tests."""

    def __init__(self) -> None:
        self.models: dict[str, dict[str, object]] = {
            "llama3.2:3b": {
                "digest": "sha256:llama32",
                "size": 2_019_393_189,
                "capabilities": ["completion", "tools"],
                "details": {
                    "family": "llama",
                    "parameter_size": "3.2B",
                    "quantization_level": "Q4_K_M",
                    "context_length": 131_072,
                },
            },
            "qwen3.5:9b": {
                "digest": "sha256:qwen35",
                "size": 6_594_474_711,
                "capabilities": ["vision", "completion", "tools", "thinking"],
                "details": {
                    "family": "qwen35",
                    "parameter_size": "9.7B",
                    "quantization_level": "Q4_K_M",
                    "context_length": 262_144,
                },
            },
        }
        self.running: set[str] = set()
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        payload: dict[str, object] = {}
        if request.content:
            decoded = json.loads(request.content.decode("utf-8"))
            if isinstance(decoded, dict):
                payload = decoded
        self.calls.append((request.method, request.url.path, payload))
        if request.method == "GET" and request.url.path == "/api/tags":
            return httpx.Response(
                200,
                json={
                    "models": [
                        {"name": model_id, **metadata} for model_id, metadata in self.models.items()
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/api/ps":
            return httpx.Response(
                200,
                json={"models": [{"model": model_id} for model_id in sorted(self.running)]},
            )
        if request.method == "POST" and request.url.path == "/api/pull":
            model_id = payload.get("model")
            if type(model_id) is not str or not model_id.strip():
                return httpx.Response(400, json={"error": "invalid model"})
            self.models.setdefault(
                model_id,
                {
                    "digest": "sha256:downloaded",
                    "size": 100,
                    "capabilities": ["completion"],
                    "details": {
                        "family": "downloaded",
                        "parameter_size": "1B",
                        "quantization_level": "Q4",
                        "context_length": 4_096,
                    },
                },
            )
            return httpx.Response(200, json={"status": "success"})
        if request.method == "POST" and request.url.path == "/api/generate":
            model_id = payload.get("model")
            if type(model_id) is not str:
                return httpx.Response(400, json={"error": "invalid model"})
            if payload.get("keep_alive") == 0:
                self.running.discard(model_id)
            else:
                self.running.add(model_id)
            return httpx.Response(
                200,
                json={
                    "response": "JARVIS_CALIBRATION_OK",
                    "eval_count": 16,
                    "eval_duration": 1_000_000,
                },
            )
        return httpx.Response(404, json={"error": "not found"})


class _FixedTelemetry:
    def __init__(self, snapshot: ResourceSnapshot) -> None:
        self.current = snapshot

    def snapshot(self) -> ResourceSnapshot:
        return self.current


class _FixedProbe:
    def __init__(self) -> None:
        self.profile = _hardware(ram=16 * 1024**3, disk=32 * 1024**3, concurrency=4)

    def read(self) -> HardwareReading:
        return self.profile.reading


@dataclass
class _LocalBundle:
    harness: _OllamaHarness
    client: httpx.AsyncClient
    runtime: OllamaRuntimeManager
    adapter: OllamaModelAdapter
    registry: ProviderRegistry
    knowledge: ModelKnowledgeService
    manager: LocalModelManager
    control: LocalAIControlPlane
    router: ProviderRouter
    dispatcher: InferenceDispatcher
    resources: ResourceGovernor


def _resource_snapshot(*, disk: int = 32 * 1024**3) -> ResourceSnapshot:
    return ResourceSnapshot(
        datetime(2026, 1, 1, tzinfo=UTC),
        cpu_utilization=0.1,
        cpu_cores=8,
        ram_total_bytes=16 * 1024**3,
        ram_available_bytes=12 * 1024**3,
        gpu_vram_total_bytes=8 * 1024**3,
        gpu_vram_available_bytes=6 * 1024**3,
        disk_free_bytes=disk,
        on_ac_power=True,
        battery_level=0.9,
        user_idle_seconds=1.0,
        user_active=True,
        heavy_foreground_workload=False,
    )


async def _bundle(
    tmp_path: Path,
    *,
    policy: LocalAIUserPolicy | None = None,
    disk: int = 32 * 1024**3,
    response: str = "OK",
) -> _LocalBundle:
    harness = _OllamaHarness()
    client = httpx.AsyncClient(transport=httpx.MockTransport(harness.handler))
    runtime = OllamaRuntimeManager(
        endpoint="http://127.0.0.1:11434",
        model="qwen3.5:9b",
        autostart=False,
        executable=None,
        start_timeout_seconds=0.2,
        stop_owned_on_exit=False,
        client=client,
    )
    adapter = OllamaModelAdapter(runtime, client=client)
    specs = await adapter.discover()
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                adapter.provider_metadata,
                lambda _configuration: FakeAIProvider((response,)),
                tuple(item.metadata for item in specs),
            ),
        )
    )
    knowledge = ModelKnowledgeService(ModelKnowledgeStore(tmp_path / "knowledge.sqlite3"))
    knowledge.store.register_provider(adapter.provider_metadata)
    manager = LocalModelManager(
        tmp_path / "models",
        knowledge=knowledge,
        provider_id="ollama",
        provider_adapter=adapter,
    )
    hardware = HardwareInventoryService(_FixedProbe())
    resources = ResourceGovernor(
        _FixedTelemetry(_resource_snapshot(disk=disk)),
        policy=ResourcePolicy(low_disk_bytes=1_000),
    )
    planner = ModelPlanner(manager.inventory)
    control = LocalAIControlPlane(
        registry,
        manager,
        hardware,
        planner,
        resources,
        knowledge,
        provider_id="ollama",
        policy=policy,
    )
    router = ProviderRouter(
        registry,
        resources,
        knowledge,
        hardware_profile=hardware.inspect(),
    )
    dispatcher = InferenceDispatcher(router, registry, lifecycle=control)
    control.bind_dispatcher(dispatcher)
    return _LocalBundle(
        harness,
        client,
        runtime,
        adapter,
        registry,
        knowledge,
        manager,
        control,
        router,
        dispatcher,
        resources,
    )


async def _close_bundle(bundle: _LocalBundle) -> None:
    await bundle.dispatcher.aclose()
    await bundle.manager.aclose()
    bundle.knowledge.close()
    await bundle.client.aclose()


@pytest.mark.asyncio
async def test_ollama_adapter_reports_provider_truth_and_measures_real_api_calls() -> None:
    harness = _OllamaHarness()
    client = httpx.AsyncClient(transport=httpx.MockTransport(harness.handler))
    runtime = OllamaRuntimeManager(
        endpoint="http://127.0.0.1:11434",
        model="qwen3.5:9b",
        autostart=False,
        executable=None,
        start_timeout_seconds=0.2,
        stop_owned_on_exit=False,
        client=client,
    )
    adapter = OllamaModelAdapter(runtime, client=client)
    try:
        specs = await adapter.discover()
        assert {item.model_id for item in specs} == {"llama3.2:3b", "qwen3.5:9b"}
        qwen = next(item for item in specs if item.model_id == "qwen3.5:9b")
        assert qwen.provider_managed and qwen.installed and not qwen.loaded
        assert qwen.artifact is not None and qwen.artifact.sha256 is None
        assert qwen.provider_digest == "sha256:qwen35"
        assert ModelRole.REASONING in qwen.metadata.roles
        assert ModelRole.TOOL_USE in qwen.metadata.roles
        assert "reasoning" in qwen.metadata.capabilities
        assert qwen.metadata.evidence[0].kind.value == "provider_reported"
        assert await adapter.verify(qwen)

        await adapter.acquire(qwen)
        handle = await adapter.load(qwen)
        health = await adapter.health(qwen.model_id, handle)
        measurement = await adapter.benchmark(qwen.model_id, handle)
        assert health.available
        assert measurement.model_id == qwen.model_id
        assert measurement.storage_bytes == qwen.metadata.storage_bytes
        assert measurement.throughput == 16_000.0
        await adapter.unload(qwen.model_id, handle)
        assert qwen.model_id not in harness.running
        assert any(path == "/api/pull" for _, path, _ in harness.calls)
        assert any(path == "/api/generate" for _, path, _ in harness.calls)
    finally:
        await adapter.aclose()
        await client.aclose()


@pytest.mark.asyncio
async def test_local_ai_setup_selects_dynamic_models_and_preserves_identity_across_reload(
    tmp_path: Path,
) -> None:
    bundle = await _bundle(
        tmp_path,
        policy=LocalAIUserPolicy(
            provider_pin="ollama",
            model_pin="qwen3.5:9b",
            routing_policy=RoutingPolicy.LOCAL_ONLY,
        ),
    )
    try:
        setup_results = [
            await bundle.control.setup(mode, roles=(ModelRole.GENERAL, ModelRole.REASONING))
            for mode in LocalAISetupMode
        ]
        setup = setup_results[1]
        assert tuple(item.mode for item in setup_results) == tuple(LocalAISetupMode)
        assert all(item.status is LocalAISetupStatus.READY for item in setup_results)
        assert setup.status is LocalAISetupStatus.READY
        assert setup.selected_model_id == "qwen3.5:9b"
        assert set(setup.discovered_models) == {"llama3.2:3b", "qwen3.5:9b"}
        assert setup.portfolio
        assert bundle.control.status().provider_ownership == "external"

        intent = bundle.control.apply_policy_to_step(
            RouteRequest(
                task="repair research",
                profile="repair",
                role=ModelRole.REASONING,
                policy=RoutingPolicy.LOCAL_ONLY,
                required_capabilities=frozenset({"reasoning"}),
                task_class="repair_research",
                responsibility="bounded research",
                privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
            )
        )
        assert intent.pinned_provider_id == "ollama"
        assert intent.pinned_model_id == "qwen3.5:9b"
        decision = bundle.dispatcher.route(intent)
        assert decision.status is RouteStatus.SELECTED
        assert decision.primary is not None
        assert decision.primary.model_id == "qwen3.5:9b"
        message = ChatMessage(
            uuid4(),
            uuid4(),
            MessageRole.USER,
            "Return a bounded local research result.",
            datetime.now(UTC),
        )
        result = await bundle.dispatcher.generate(
            GenerationRequest(
                (message,),
                "wrong-configured-model",
                8_192,
                PrivacyContext(PrivacyClassification.LOCAL_ONLY),
            ),
            intent,
            decision=decision,
        )
        assert result.result.model == "qwen3.5:9b"
        assert bundle.manager.inspect("qwen3.5:9b").state is ModelLifecycleState.IDLE
        assert bundle.manager.has_runtime_handle("qwen3.5:9b")
        load_calls_before_reuse = sum(
            path == "/api/generate" and payload.get("prompt") == ""
            for _, path, payload in bundle.harness.calls
        )
        reused = await bundle.dispatcher.generate(
            GenerationRequest(
                (message,),
                "wrong-configured-model",
                8_192,
                PrivacyContext(PrivacyClassification.LOCAL_ONLY),
            ),
            intent,
            decision=decision,
        )
        assert reused.result.model == "qwen3.5:9b"
        load_calls_after_reuse = sum(
            path == "/api/generate" and payload.get("prompt") == ""
            for _, path, payload in bundle.harness.calls
        )
        assert load_calls_after_reuse == load_calls_before_reuse
        assert any(
            path == "/api/generate" and payload.get("model") == "qwen3.5:9b"
            for _, path, payload in bundle.harness.calls
        )

        unloaded = await bundle.manager.unload_idle()
        assert unloaded == ("qwen3.5:9b",)
        assert bundle.manager.inspect("qwen3.5:9b").state is ModelLifecycleState.AVAILABLE
        reloaded = await bundle.manager.load("qwen3.5:9b")
        assert reloaded.state is ModelLifecycleState.WARM
        assert bundle.manager.has_runtime_handle("qwen3.5:9b")
        await bundle.manager.unload("qwen3.5:9b")
        bundle.harness.running.add("qwen3.5:9b")
        restarted = LocalModelManager(
            tmp_path / "restart-models",
            provider_id="ollama",
            provider_adapter=bundle.adapter,
        )
        records = await restarted.discover()
        assert restarted.inspect("qwen3.5:9b").state is ModelLifecycleState.WARM
        assert not restarted.has_runtime_handle("qwen3.5:9b")
        assert len(records) == 2
        calls_before_rediscovery = len(bundle.harness.calls)
        await restarted.aclose()
        bundle.harness.models.pop("llama3.2:3b")
        rediscovered = await bundle.control.discover()
        assert len(bundle.harness.calls) > calls_before_rediscovery
        assert not any(
            path == "/api/generate"
            for _, path, _ in bundle.harness.calls[calls_before_rediscovery:]
        )
        assert tuple(item.spec.model_id for item in rediscovered) == ("qwen3.5:9b",)
        assert bundle.manager.inspect("llama3.2:3b").state is ModelLifecycleState.UNAVAILABLE
        assert bundle.registry.definition("ollama").models == (
            bundle.manager.inspect("qwen3.5:9b").spec.metadata,
        )
    finally:
        await _close_bundle(bundle)


@pytest.mark.asyncio
async def test_local_ai_policy_controls_acquisition_and_resource_pressure_unloads_only_idle(
    tmp_path: Path,
) -> None:
    bundle = await _bundle(tmp_path)
    try:
        await bundle.control.setup()
        metadata = ModelMetadata(
            model_id="download:candidate",
            context_limit=4_096,
            roles=frozenset({ModelRole.GENERAL}),
            modalities=frozenset({"text"}),
            storage_bytes=100,
            compatibility=frozenset(),
        )
        pending = LocalModelSpec(
            "download:candidate",
            metadata,
            ModelArtifact("ollama://download:candidate", None, 100, provider_managed=True),
            provider_managed=True,
            installed=False,
            provider_digest=None,
        )
        bundle.manager.register(pending)
        blocked = bundle.control.acquisition_decision("download:candidate")
        assert blocked.status is AcquisitionStatus.BLOCKED_BY_POLICY

        allowed = LocalAIControlPlane(
            bundle.registry,
            bundle.manager,
            bundle.control.hardware,
            ModelPlanner(bundle.manager.inventory),
            bundle.resources,
            bundle.knowledge,
            provider_id="ollama",
            policy=LocalAIUserPolicy(auto_download_allowed=True, maximum_model_disk_bytes=200),
        )
        decision = allowed.acquisition_decision("download:candidate")
        assert decision.status is AcquisitionStatus.ALLOWED
        acquired = await allowed.acquire("download:candidate")
        assert acquired.status is AcquisitionStatus.ALREADY_AVAILABLE
        assert bundle.manager.inspect("download:candidate").spec.installed

        too_large = LocalAIControlPlane(
            bundle.registry,
            bundle.manager,
            bundle.control.hardware,
            ModelPlanner(bundle.manager.inventory),
            bundle.resources,
            bundle.knowledge,
            provider_id="ollama",
            policy=LocalAIUserPolicy(auto_download_allowed=True, maximum_model_disk_bytes=50),
        )
        assert (
            too_large.acquisition_decision("download:candidate").status
            is AcquisitionStatus.ALREADY_AVAILABLE
        )

        selected = next(
            item for item in bundle.control.status().models if item.spec.model_id == "qwen3.5:9b"
        )
        del selected
        qwen_spec = bundle.manager.inspect("qwen3.5:9b").spec
        await bundle.manager.load("qwen3.5:9b")
        await bundle.manager.load("llama3.2:3b")
        bundle.manager.mark_in_use("llama3.2:3b")
        unloaded = await bundle.manager.unload_idle()
        assert unloaded == ("qwen3.5:9b",)
        assert bundle.manager.inspect("llama3.2:3b").state is ModelLifecycleState.IN_USE
        assert qwen_spec.model_id == "qwen3.5:9b"
        with pytest.raises(ModelLifecycleError, match="never auto-removed"):
            await bundle.manager.remove("qwen3.5:9b")
    finally:
        await _close_bundle(bundle)


@pytest.mark.asyncio
async def test_calibration_requires_independent_verification_and_updates_cookbook(
    tmp_path: Path,
) -> None:
    bundle = await _bundle(tmp_path)
    try:
        await bundle.control.setup(roles=(ModelRole.GENERAL, ModelRole.REASONING))
        successful = await bundle.control.calibrate(
            "qwen3.5:9b",
            "repair_research",
            samples=3,
            verify=lambda content: content == "OK",
        )
        assert successful == (True, True, True)
        identity = identity_for("ollama", bundle.manager.inspect("qwen3.5:9b").spec.metadata)
        summary = bundle.knowledge.cookbook_summary(identity, task_class="repair_research")
        assert summary.evidence_sufficiency is EvidenceSufficiency.SUFFICIENT
        assert summary.verified_success_count == 3
        assert summary.unknown_outcome_count == 0

        failed = await bundle.control.calibrate(
            "llama3.2:3b",
            "worse_new_model",
            samples=1,
            verify=lambda _content: False,
        )
        assert failed == (False,)
        candidates = await bundle.control.candidates(
            role=ModelRole.REASONING, task_class="repair_research"
        )
        assert candidates[0].spec.model_id == "qwen3.5:9b"
        assert candidates[0].relevance > candidates[-1].relevance
    finally:
        await _close_bundle(bundle)


@pytest.mark.asyncio
async def test_task_specific_cookbook_evidence_prefers_better_route_without_global_replacement(
    tmp_path: Path,
) -> None:
    bundle = await _bundle(tmp_path)
    try:
        await bundle.control.setup(roles=(ModelRole.GENERAL, ModelRole.REASONING))
        now = datetime.now(UTC)
        qwen = bundle.manager.inspect("qwen3.5:9b").spec.metadata
        llama = bundle.manager.inspect("llama3.2:3b").spec.metadata
        for index in range(3):
            bundle.knowledge.record_cookbook(
                CookbookObservation(
                    identity_for("ollama", qwen),
                    "coding",
                    CookbookOutcome.VERIFIED_SUCCESS,
                    now,
                    operation_class="coding",
                    role=ModelRole.GENERAL,
                    locality=ProviderLocality.LOCAL,
                    machine_scope="this_machine",
                    verified=True,
                    verifier_agreement=VerifierAgreement.DETERMINISTIC_VERIFICATION,
                    observation_id=f"qwen-coding-{index}",
                )
            )
            bundle.knowledge.record_cookbook(
                CookbookObservation(
                    identity_for("ollama", llama),
                    "coding",
                    CookbookOutcome.FAILURE,
                    now,
                    operation_class="coding",
                    role=ModelRole.GENERAL,
                    locality=ProviderLocality.LOCAL,
                    machine_scope="this_machine",
                    verified=False,
                    observation_id=f"llama-coding-{index}",
                )
            )

        coding = bundle.router.route(
            RouteRequest(
                task="coding step",
                profile="task-graph-step-coding",
                role=ModelRole.GENERAL,
                policy=RoutingPolicy.PREFER_LOCAL,
                task_class="coding",
                minimum_expected_reliability=0.5,
                privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
            )
        )
        assert coding.primary is not None and coding.primary.model_id == "qwen3.5:9b"
        general = bundle.router.route(
            RouteRequest(
                task="general step",
                profile="task-graph-step-general",
                role=ModelRole.GENERAL,
                policy=RoutingPolicy.PREFER_LOCAL,
                task_class="general",
                privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
            )
        )
        assert general.primary is not None and general.primary.model_id == "llama3.2:3b"
    finally:
        await _close_bundle(bundle)


@pytest.mark.asyncio
async def test_task_graph_steps_keep_independent_typed_routes(tmp_path: Path) -> None:
    bundle = await _bundle(tmp_path)
    try:
        await bundle.control.setup(roles=(ModelRole.GENERAL, ModelRole.REASONING))
        general = bundle.router.route(
            RouteRequest(
                task="one higher-level task",
                profile="same-task-graph",
                role=ModelRole.GENERAL,
                policy=RoutingPolicy.PREFER_LOCAL,
                task_class="summarize",
                privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
            )
        )
        reasoning = bundle.router.route(
            RouteRequest(
                task="one higher-level task",
                profile="same-task-graph",
                role=ModelRole.REASONING,
                policy=RoutingPolicy.PREFER_LOCAL,
                task_class="repair_research",
                required_capabilities=frozenset({"reasoning"}),
                privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
            )
        )
        assert general.primary is not None and reasoning.primary is not None
        assert general.primary.model_id == "llama3.2:3b"
        assert reasoning.primary.model_id == "qwen3.5:9b"
        assert general.primary.model_id != reasoning.primary.model_id
    finally:
        await _close_bundle(bundle)


def test_cheaper_sufficient_route_wins_over_available_stronger_route() -> None:
    provider = ProviderMetadata("local", "Local", "fixture", local_only=True)
    cheap = ModelMetadata(
        "cheap-sufficient",
        4_096,
        roles=frozenset({ModelRole.GENERAL}),
        input_cost_per_million=0.1,
        output_cost_per_million=0.1,
        quality_score=0.8,
        modalities=frozenset({"text"}),
    )
    strong = ModelMetadata(
        "strong-expensive",
        4_096,
        roles=frozenset({ModelRole.GENERAL}),
        input_cost_per_million=5.0,
        output_cost_per_million=5.0,
        quality_score=0.99,
        modalities=frozenset({"text"}),
    )
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                provider,
                lambda _configuration: FakeAIProvider(),
                (strong, cheap),
            ),
        )
    )
    decision = ProviderRouter(registry).route(
        RouteRequest(
            task="cheap sufficient step",
            profile="cost-aware-step",
            role=ModelRole.GENERAL,
            policy=RoutingPolicy.LOWEST_COST,
        )
    )
    assert decision.primary is not None and decision.primary.model_id == "cheap-sufficient"


@pytest.mark.asyncio
async def test_strong_repair_research_uses_same_untrusted_candidate_boundary(
    tmp_path: Path,
) -> None:
    response = '{"action_id":"restart-component","description":"Restart the bounded component"}'
    bundle = await _bundle(tmp_path, response=response)
    try:
        await bundle.control.setup(roles=(ModelRole.GENERAL, ModelRole.REASONING))
        research = RoutedRepairResearch(bundle.dispatcher)
        candidate = await research(
            ComponentProblem(
                "repair.component",
                "bounded component is unavailable",
                DiagnosticOwner.CORE,
                failure_code="component.unavailable",
                health_status=HealthStatus.UNAVAILABLE,
                source="trusted-health-probe",
                evidence=("trusted probe observed unavailable",),
            )
        )
        assert candidate is not None
        assert candidate.source == "model"
        assert candidate.trusted is False
        assert candidate.validated is False
        assert any(
            path == "/api/generate" and payload.get("model") == "qwen3.5:9b"
            for _, path, payload in bundle.harness.calls
        )
    finally:
        await _close_bundle(bundle)


@pytest.mark.asyncio
async def test_background_calibration_and_acquisition_defer_under_system_pressure(
    tmp_path: Path,
) -> None:
    bundle = await _bundle(tmp_path / "calibration", disk=50)
    try:
        await bundle.control.setup()
        before = len(bundle.harness.calls)
        assert (
            await bundle.control.calibrate(
                "qwen3.5:9b", "background-benchmark", samples=3, verify=lambda _value: True
            )
            == ()
        )
        assert not any(path == "/api/generate" for _, path, _ in bundle.harness.calls[before:])

        pending = LocalModelSpec(
            "download:pressure",
            ModelMetadata(
                "download:pressure",
                4_096,
                roles=frozenset({ModelRole.GENERAL}),
                storage_bytes=100,
                modalities=frozenset({"text"}),
            ),
            ModelArtifact("ollama://download:pressure", None, 100, provider_managed=True),
            provider_managed=True,
        )
        bundle.manager.register(pending)
        policy_control = LocalAIControlPlane(
            bundle.registry,
            bundle.manager,
            bundle.control.hardware,
            ModelPlanner(bundle.manager.inventory),
            bundle.resources,
            bundle.knowledge,
            provider_id="ollama",
            policy=LocalAIUserPolicy(auto_download_allowed=True),
        )
        deferred = policy_control.acquisition_decision("download:pressure")
        assert deferred.status is AcquisitionStatus.DEFERRED_BY_RESOURCES
    finally:
        await _close_bundle(bundle)


def test_constrained_hardware_chooses_a_realistic_multi_role_portfolio() -> None:
    inventory = ModelInventory(
        (
            ModelMetadata(
                "small-general",
                4_096,
                roles=frozenset({ModelRole.GENERAL, ModelRole.REASONING}),
                storage_bytes=1,
                ram_bytes=1,
                vram_bytes=0,
                modalities=frozenset({"text"}),
                compatibility=frozenset({"windows"}),
            ),
            ModelMetadata(
                "heavy-general",
                8_192,
                roles=frozenset({ModelRole.GENERAL}),
                storage_bytes=1,
                ram_bytes=8,
                vram_bytes=0,
                modalities=frozenset({"text"}),
                compatibility=frozenset({"windows"}),
            ),
        )
    )
    planned = ModelPlanner(inventory).plan(
        ModelCombinationRequest((ModelRole.GENERAL,), max_concurrency=1),
        _hardware(ram=2, disk=10, concurrency=2, vram=0),
    )
    assert planned.status is FitStatus.COMPATIBLE
    assert planned.assignments == ((ModelRole.GENERAL, "small-general"),)


def test_resource_pressure_selects_smaller_sufficient_route() -> None:
    provider = ProviderMetadata("local", "Local", "fixture", local_only=True)
    small = ModelMetadata(
        "small-route",
        4_096,
        roles=frozenset({ModelRole.GENERAL}),
        ram_bytes=1,
        modalities=frozenset({"text"}),
    )
    large = ModelMetadata(
        "large-route",
        4_096,
        roles=frozenset({ModelRole.GENERAL}),
        ram_bytes=8,
        modalities=frozenset({"text"}),
    )
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                provider,
                lambda _configuration: FakeAIProvider(),
                (large, small),
            ),
        )
    )
    resources = ResourceGovernor(
        _FixedTelemetry(
            ResourceSnapshot(
                datetime.now(UTC),
                cpu_utilization=0.95,
                ram_total_bytes=10,
                ram_available_bytes=1,
                disk_free_bytes=100,
            )
        )
    )
    decision = ProviderRouter(registry, resources).route(
        RouteRequest(
            task="interactive",
            profile="pressure",
            role=ModelRole.GENERAL,
            concurrency=2,
            resource_state=_hardware(ram=16, disk=100, concurrency=4, vram=0),
            policy=RoutingPolicy.PREFER_LOCAL,
        )
    )
    assert decision.status is RouteStatus.SELECTED
    assert decision.primary is not None and decision.primary.model_id == "small-route"


def test_routing_switching_cost_prefers_warm_or_materially_better_models() -> None:
    local = ProviderMetadata(
        "local", "Local", "fixture", local_only=True, locality=ProviderLocality.LOCAL
    )
    current = ModelMetadata(
        "current-model",
        8_192,
        frozenset({"chat"}),
        frozenset({ModelRole.GENERAL}),
        quality_score=0.80,
        modalities=frozenset({"text"}),
    )
    candidate = ModelMetadata(
        "new-model",
        8_192,
        frozenset({"chat"}),
        frozenset({ModelRole.GENERAL}),
        quality_score=0.82,
        modalities=frozenset({"text"}),
    )
    better = ModelMetadata(
        "better-model",
        8_192,
        frozenset({"chat"}),
        frozenset({ModelRole.GENERAL}),
        quality_score=0.99,
        modalities=frozenset({"text"}),
    )
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                local,
                lambda _configuration: FakeAIProvider(),
                (current, candidate, better),
            ),
        )
    )
    router = ProviderRouter(registry)
    current_identity = identity_for("local", current)
    benchmarks = (
        RouteBenchmark("local", "current-model", datetime.now(UTC), load_latency_ms=1),
        RouteBenchmark("local", "new-model", datetime.now(UTC), load_latency_ms=100),
        RouteBenchmark("local", "better-model", datetime.now(UTC), load_latency_ms=100),
    )
    worse = router.route(
        RouteRequest(
            task="switch",
            profile="switch",
            policy=RoutingPolicy.QUALITY_FIRST,
            current_identity=current_identity,
            current_quality=0.80,
            switching_cost_budget_ms=20.0,
            minimum_quality_gain_to_switch=0.05,
            benchmarks=benchmarks,
            excluded_identities=(identity_for("local", better),),
        )
    )
    assert worse.status is RouteStatus.SELECTED
    assert worse.primary is not None and worse.primary.model_id == "current-model"
    material = router.route(
        RouteRequest(
            task="switch",
            profile="switch",
            policy=RoutingPolicy.QUALITY_FIRST,
            current_identity=current_identity,
            current_quality=0.80,
            switching_cost_budget_ms=20.0,
            minimum_quality_gain_to_switch=0.05,
            preferred_model_id="better-model",
            benchmarks=benchmarks,
        )
    )
    assert material.primary is not None and material.primary.model_id == "better-model"


@pytest.mark.asyncio
async def test_owned_ollama_recovery_terminates_only_owned_process() -> None:
    launches: list[list[str]] = []
    requests = 0

    class Process:
        def __init__(self) -> None:
            self.terminated = False

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, _timeout: float) -> None:
            return None

    processes: list[Process] = []

    def launcher(arguments: list[str]) -> Process:
        launches.append(arguments)
        process = Process()
        processes.append(process)
        return process

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            raise httpx.ConnectError("offline", request=request)
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "qwen3.5:9b"}]})
        return httpx.Response(200, json={"models": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    manager = OllamaRuntimeManager(
        endpoint="http://127.0.0.1:11434",
        model="qwen3.5:9b",
        autostart=True,
        executable=Path(__file__),
        start_timeout_seconds=0.2,
        stop_owned_on_exit=True,
        client=client,
        launcher=launcher,
    )
    try:
        started = await manager.ensure_running()
        assert started.ownership.value == "jarvis"
        assert len(launches) == 1
        recovered = await manager.recover()
        assert recovered.server.value == "running"
        assert processes[0].terminated
        assert recovered.ownership.value == "external"
    finally:
        await manager.aclose()
        await client.aclose()


def test_local_ai_policy_and_route_validation_is_fail_closed() -> None:
    with pytest.raises(ValueError, match="provider pin"):
        LocalAIUserPolicy(provider_pin=cast(str, "\x00"))
    with pytest.raises(ValueError, match="auto-download"):
        LocalAIUserPolicy(auto_download_allowed=cast(bool, 1))
    with pytest.raises(ValueError, match="disk budget"):
        LocalAIUserPolicy(maximum_model_disk_bytes=cast(int, -1))
    with pytest.raises(ValueError, match="idle-unload"):
        LocalAIUserPolicy(idle_unload_seconds=-1)


@pytest.mark.asyncio
async def test_local_ai_setup_failure_and_acquisition_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider_failure = await _bundle(tmp_path / "provider-failure")
    try:

        async def fail_provider() -> object:
            raise RuntimeError("provider offline")

        monkeypatch.setattr(provider_failure.manager, "ensure_provider", fail_provider)
        result = await provider_failure.control.setup()
        assert result.status is LocalAISetupStatus.UNAVAILABLE
        assert result.reasons == ("provider unavailable: RuntimeError",)
    finally:
        await _close_bundle(provider_failure)

    discovery_failure = await _bundle(tmp_path / "discovery-failure")
    try:

        async def fail_discovery() -> object:
            raise RuntimeError("catalog offline")

        monkeypatch.setattr(discovery_failure.manager, "discover", fail_discovery)
        result = await discovery_failure.control.setup()
        assert result.status is LocalAISetupStatus.UNAVAILABLE
        assert result.reasons == ("model discovery failed: RuntimeError",)
    finally:
        await _close_bundle(discovery_failure)

    empty_provider = await _bundle(tmp_path / "empty-provider")
    try:

        async def empty_discovery() -> tuple[object, ...]:
            return ()

        monkeypatch.setattr(empty_provider.manager, "discover", empty_discovery)
        result = await empty_provider.control.setup()
        assert result.status is LocalAISetupStatus.UNAVAILABLE
        assert result.reasons == ("provider reported no installed models",)
    finally:
        await _close_bundle(empty_provider)

    pinned_missing = await _bundle(
        tmp_path / "pinned-missing",
        policy=LocalAIUserPolicy(model_pin="model-that-is-not-installed"),
    )
    try:
        assert pinned_missing.control.policy.model_pin == "model-that-is-not-installed"
        assert pinned_missing.control.manager is pinned_missing.manager
        assert pinned_missing.control.hardware is pinned_missing.control.hardware
        with pytest.raises(ValueError, match="dispatcher"):
            pinned_missing.control.bind_dispatcher(cast(InferenceDispatcher, object()))
        result = await pinned_missing.control.setup()
        assert result.status is LocalAISetupStatus.UNKNOWN
        assert result.selected_model_id is None

        intent = pinned_missing.control.apply_policy_to_step(
            RouteRequest(
                task="explicit step",
                profile="explicit",
                policy=RoutingPolicy.BALANCED,
                pinned_provider_id="explicit-provider",
                pinned_model_id="explicit-model",
            )
        )
        assert intent.pinned_provider_id == "explicit-provider"
        assert intent.pinned_model_id == "explicit-model"
        assert intent.policy is RoutingPolicy.PREFER_LOCAL
        with pytest.raises(ValueError, match="route intent"):
            pinned_missing.control.apply_policy_to_step(cast(RouteRequest, object()))
        with pytest.raises(ValueError, match="setup mode"):
            await pinned_missing.control.setup(cast(LocalAISetupMode, "invalid"))
        with pytest.raises(ValueError, match="setup roles"):
            await pinned_missing.control.setup(roles=())

        candidates = await pinned_missing.control.candidates(
            role=ModelRole.VISION, task_class="unseen-task"
        )
        llama = next(item for item in candidates if item.spec.model_id == "llama3.2:3b")
        assert llama.reasons == ("role mismatch",)
    finally:
        await _close_bundle(pinned_missing)

    limits = await _bundle(tmp_path / "limits")
    try:
        for model_id, size in (("download:budget", 100), ("download:unknown", None)):
            limits.manager.register(
                LocalModelSpec(
                    model_id,
                    ModelMetadata(
                        model_id,
                        4_096,
                        roles=frozenset({ModelRole.GENERAL}),
                        modalities=frozenset({"text"}),
                        storage_bytes=size,
                    ),
                    ModelArtifact(
                        f"ollama://{model_id}",
                        None,
                        size,
                        provider_managed=True,
                    ),
                    provider_managed=True,
                )
            )
        limited = LocalAIControlPlane(
            limits.registry,
            limits.manager,
            limits.control.hardware,
            ModelPlanner(limits.manager.inventory),
            limits.resources,
            limits.knowledge,
            provider_id="ollama",
            policy=LocalAIUserPolicy(auto_download_allowed=True, maximum_model_disk_bytes=50),
        )
        assert (
            limited.acquisition_decision("download:budget").status
            is AcquisitionStatus.BLOCKED_BY_POLICY
        )
        assert limited.acquisition_decision("download:unknown").status is AcquisitionStatus.UNKNOWN
    finally:
        await _close_bundle(limits)


@pytest.mark.asyncio
async def test_local_ai_calibration_validation_and_provider_failure_are_recorded(
    tmp_path: Path,
) -> None:
    bundle = await _bundle(tmp_path)
    try:
        await bundle.control.setup()
        verifier = cast(Callable[[str], bool], object())
        with pytest.raises(ValueError, match="task class"):
            await bundle.control.calibrate("qwen3.5:9b", "", verify=lambda _value: True)
        with pytest.raises(ValueError, match="sample count"):
            await bundle.control.calibrate(
                "qwen3.5:9b", "invalid", samples=0, verify=lambda _value: True
            )
        with pytest.raises(ValueError, match="verifier"):
            await bundle.control.calibrate("qwen3.5:9b", "invalid", verify=verifier)
        with pytest.raises(ValueError, match="resource priority"):
            await bundle.control.calibrate(
                "qwen3.5:9b",
                "invalid",
                verify=lambda _value: True,
                priority=cast(ResourcePriority, "invalid"),
            )

        bundle.control._dispatcher = None
        with pytest.raises(ModelLifecycleError, match="dispatcher"):
            await bundle.control.calibrate("qwen3.5:9b", "no-dispatcher", verify=lambda _: True)

        class FailingDispatcher:
            async def generate(
                self,
                request: GenerationRequest,
                intent: RouteRequest,
                *,
                decision: RouteDecision | None = None,
            ) -> object:
                del request, intent, decision
                raise RuntimeError("bounded provider failure")

        failed = await bundle.control.calibrate(
            "qwen3.5:9b",
            "provider-failure",
            samples=1,
            verify=lambda _value: True,
            dispatcher=FailingDispatcher(),
        )
        assert failed == (False,)

        async def async_verifier(content: str) -> bool:
            return content == "OK"

        successful = await bundle.control.calibrate(
            "llama3.2:3b",
            "async-verifier",
            samples=1,
            verify=async_verifier,
            dispatcher=bundle.dispatcher,
        )
        assert successful == (True,)
    finally:
        await _close_bundle(bundle)


@pytest.mark.asyncio
async def test_provider_manager_health_benchmark_and_no_adapter_paths(tmp_path: Path) -> None:
    bundle = await _bundle(tmp_path / "provider-manager")
    try:
        assert await bundle.manager.ensure_provider() is not None
        await bundle.manager.discover()
        assert await bundle.manager.verify("qwen3.5:9b")
        health = await bundle.manager.health("qwen3.5:9b")
        assert health.available
        with pytest.raises(ModelLifecycleError, match="marked in use"):
            bundle.manager.mark_in_use("qwen3.5:9b")
        assert bundle.manager.mark_idle("qwen3.5:9b").state is ModelLifecycleState.HEALTHY
        with pytest.raises(ModelLifecycleError, match="loaded provider model"):
            await bundle.manager.benchmark("qwen3.5:9b")
        await bundle.manager.download("qwen3.5:9b")
        await bundle.manager.install("qwen3.5:9b")
        await bundle.manager.load("qwen3.5:9b")
        measurement = await bundle.manager.benchmark("qwen3.5:9b")
        assert measurement.model_id == "qwen3.5:9b"
        assert await bundle.manager.recover_provider() is not None
        await bundle.manager.unload("qwen3.5:9b")
    finally:
        await _close_bundle(bundle)

    bare = LocalModelManager(tmp_path / "bare")
    assert await bare.ensure_provider() is None
    assert await bare.recover_provider() is None
    spec = LocalModelSpec(
        "bare-model",
        ModelMetadata("bare-model", 4_096, modalities=frozenset({"text"})),
        ModelArtifact("fixture://bare-model", "a" * 64, 1),
    )
    bare.register(spec)
    discovered = await bare.discover()
    assert discovered[0].spec.model_id == "bare-model"
    await bare.aclose()


@pytest.mark.asyncio
async def test_local_ai_prepare_rejects_unsafe_candidates_and_recovers_provider(
    tmp_path: Path,
) -> None:
    bundle = await _bundle(tmp_path)
    try:
        await bundle.control.setup()
        provider = bundle.registry.definition("ollama").metadata
        qwen = bundle.manager.inspect("qwen3.5:9b").spec.metadata
        with pytest.raises(ModelLifecycleError, match="candidate is malformed"):
            await bundle.control.prepare_for_inference(cast(RouteCandidate, object()))
        with pytest.raises(ModelLifecycleError, match="non-local provider"):
            await bundle.control.prepare_for_inference(
                RouteCandidate("other", "qwen3.5:9b", provider, qwen, True)
            )
        with pytest.raises(KeyError, match="Unknown local model"):
            await bundle.control.prepare_for_inference(
                RouteCandidate("ollama", "missing-model", provider, qwen, True)
            )

        pending_id = "pending:prepare"
        pending_metadata = ModelMetadata(
            pending_id,
            4_096,
            roles=frozenset({ModelRole.GENERAL}),
            storage_bytes=100,
            modalities=frozenset({"text"}),
        )
        bundle.manager.register(
            LocalModelSpec(
                pending_id,
                pending_metadata,
                ModelArtifact("ollama://pending:prepare", None, 100, provider_managed=True),
                provider_managed=True,
            )
        )
        with pytest.raises(ModelLifecycleError, match="automatic model acquisition"):
            await bundle.control.prepare_for_inference(
                RouteCandidate("ollama", pending_id, provider, pending_metadata, True)
            )

        large_id = "incompatible:prepare"
        large_metadata = ModelMetadata(
            large_id,
            4_096,
            roles=frozenset({ModelRole.GENERAL}),
            ram_bytes=64 * 1024**3,
            modalities=frozenset({"text"}),
        )
        bundle.manager.register(
            LocalModelSpec(
                large_id,
                large_metadata,
                ModelArtifact("ollama://incompatible:prepare", None, 1, provider_managed=True),
                provider_managed=True,
                installed=True,
            )
        )
        with pytest.raises(ModelLifecycleError, match="hardware fit is incompatible"):
            await bundle.control.prepare_for_inference(
                RouteCandidate("ollama", large_id, provider, large_metadata, True)
            )

        assert not await bundle.control.recover_provider("other")
        assert await bundle.control.recover_provider("ollama")
    finally:
        await _close_bundle(bundle)


def test_provider_model_contract_edges_are_rejected() -> None:
    with pytest.raises(ModelLifecycleError, match="Provider model hash"):
        ModelArtifact("ollama://bad", "not-a-sha", None, provider_managed=True)
    with pytest.raises(ModelLifecycleError, match="Provider model size"):
        ModelArtifact("ollama://bad", None, -1, provider_managed=True)
    metadata = ModelMetadata("contract-model", 4_096, modalities=frozenset({"text"}))
    provider_artifact = ModelArtifact("ollama://contract-model", None, None, provider_managed=True)
    with pytest.raises(ModelLifecycleError, match="provider artifacts"):
        LocalModelSpec(
            "contract-model",
            metadata,
            ModelArtifact("fixture://contract-model", "c" * 64, 1),
            provider_managed=True,
        )
    with pytest.raises(ModelLifecycleError, match="provider state"):
        LocalModelSpec(
            "contract-model",
            metadata,
            provider_artifact,
            provider_managed=True,
            installed=cast(bool, 1),
        )
    with pytest.raises(ModelLifecycleError, match="loaded model"):
        LocalModelSpec(
            "contract-model",
            metadata,
            provider_artifact,
            provider_managed=True,
            loaded=True,
        )


@pytest.mark.asyncio
async def test_local_ai_candidate_projection_and_recovery_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = await _bundle(tmp_path)
    try:
        await bundle.control.setup()

        def missing_summary(*args: object, **kwargs: object) -> object:
            del args, kwargs
            raise KeyError("no cookbook entry")

        monkeypatch.setattr(bundle.knowledge, "cookbook_summary", missing_summary)
        candidates = await bundle.control.candidates(task_class="unmeasured")
        assert candidates
        assert (
            bundle.control._selected_model(bundle.manager.records(), ("llama3.2:3b",)) is not None
        )

        async def recovery_failure() -> object:
            raise RuntimeError("recovery unavailable")

        monkeypatch.setattr(bundle.manager, "recover_provider", recovery_failure)
        assert not await bundle.control.recover_provider("ollama")
        bundle.manager._provider_adapter = None
        assert bundle.control.status().provider_ownership == "unknown"
    finally:
        await _close_bundle(bundle)


@pytest.mark.asyncio
async def test_ollama_adapter_rejects_malformed_and_transport_truth(tmp_path: Path) -> None:
    import jarvis.ai.providers.ollama_runtime as ollama_runtime_module
    from jarvis.core.errors import ProviderError, ProviderTimeoutError, ProviderUnavailableError

    assert ollama_runtime_module.OllamaRuntimeManager._models(
        {"models": [{"name": "valid"}, {}, "invalid", {"model": "second"}, {"name": "\x00"}]}
    ) == ("valid", "second")
    assert ollama_runtime_module._bounded_model_text("") is None
    assert ollama_runtime_module._positive_int(0) is None
    assert ollama_runtime_module._nonnegative_int(-1) is None
    assert ollama_runtime_module._capabilities("not-a-list") == set()

    with pytest.raises(ValueError, match="runtime manager"):
        OllamaModelAdapter(cast(OllamaRuntimeManager, object()))

    def malformed_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": "malformed"})
        return httpx.Response(500, json={"error": "broken"})

    malformed_client = httpx.AsyncClient(transport=httpx.MockTransport(malformed_handler))
    malformed_runtime = OllamaRuntimeManager(
        endpoint="http://127.0.0.1:11434",
        model="qwen3.5:9b",
        autostart=False,
        executable=None,
        start_timeout_seconds=0.2,
        stop_owned_on_exit=False,
        client=malformed_client,
    )
    malformed_adapter = OllamaModelAdapter(malformed_runtime, client=malformed_client)
    try:
        status = await malformed_runtime.status()
        assert status.server.value == "running"
        with pytest.raises(ProviderError, match="catalog is malformed"):
            await malformed_adapter.discover()
    finally:
        await malformed_adapter.aclose()
        await malformed_client.aclose()

    harness = _OllamaHarness()
    good_client = httpx.AsyncClient(transport=httpx.MockTransport(harness.handler))
    runtime = OllamaRuntimeManager(
        endpoint="http://127.0.0.1:11434",
        model="qwen3.5:9b",
        autostart=False,
        executable=None,
        start_timeout_seconds=0.2,
        stop_owned_on_exit=False,
        client=good_client,
    )
    adapter = OllamaModelAdapter(runtime, client=good_client)
    try:
        qwen = next(item for item in await adapter.discover() if item.model_id == "qwen3.5:9b")
        file_spec = LocalModelSpec(
            "file-model",
            ModelMetadata("file-model", 4_096, modalities=frozenset({"text"})),
            ModelArtifact("fixture://file-model", "b" * 64, 1),
        )
        with pytest.raises(ProviderError, match="file-managed"):
            await adapter.acquire(file_spec)
        with pytest.raises(ProviderError, match="handle"):
            await adapter.benchmark(qwen.model_id, object())
        harness.models.pop(qwen.model_id)
        assert not await adapter.verify(qwen)
        harness.models["qwen3.5:9b"] = {
            "digest": "sha256:qwen35",
            "size": 6_594_474_711,
            "capabilities": ["vision", "completion", "tools", "thinking"],
            "details": {
                "family": "qwen35",
                "parameter_size": "9.7B",
                "quantization_level": "Q4_K_M",
                "context_length": 262_144,
            },
        }
        assert await adapter.verify(replace(qwen, provider_digest=None))
    finally:
        await adapter.aclose()
        await good_client.aclose()

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    stable_client = httpx.AsyncClient(transport=httpx.MockTransport(harness.handler))
    stable_runtime = OllamaRuntimeManager(
        endpoint="http://127.0.0.1:11434",
        model="qwen3.5:9b",
        autostart=False,
        executable=None,
        start_timeout_seconds=0.2,
        stop_owned_on_exit=False,
        client=stable_client,
    )

    def server_error_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "server error"})

    error_client = httpx.AsyncClient(transport=httpx.MockTransport(server_error_handler))
    error_adapter = OllamaModelAdapter(stable_runtime, client=error_client)
    try:
        with pytest.raises(ProviderError, match="HTTP 500"):
            await error_adapter.load(qwen)
    finally:
        await error_adapter.aclose()
        await error_client.aclose()

    def malformed_json_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not-json")

    malformed_json_client = httpx.AsyncClient(transport=httpx.MockTransport(malformed_json_handler))
    malformed_json_adapter = OllamaModelAdapter(stable_runtime, client=malformed_json_client)
    try:
        with pytest.raises(ProviderError, match="malformed JSON"):
            await malformed_json_adapter.discover()
    finally:
        await malformed_json_adapter.aclose()
        await malformed_json_client.aclose()

    timeout_client = httpx.AsyncClient(transport=httpx.MockTransport(timeout_handler))
    timeout_adapter = OllamaModelAdapter(stable_runtime, client=timeout_client)
    try:
        with pytest.raises(ProviderTimeoutError):
            await timeout_adapter.discover()
        with pytest.raises(ProviderTimeoutError):
            await timeout_adapter.load(qwen)
    finally:
        await timeout_adapter.aclose()
        await timeout_client.aclose()

    def connect_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    connect_client = httpx.AsyncClient(transport=httpx.MockTransport(connect_handler))
    connect_adapter = OllamaModelAdapter(stable_runtime, client=connect_client)
    try:
        with pytest.raises(ProviderUnavailableError):
            await connect_adapter.discover()
        with pytest.raises(ProviderUnavailableError):
            await connect_adapter.load(qwen)
    finally:
        await connect_adapter.aclose()
        await connect_client.aclose()
        await stable_client.aclose()


def test_v1_i_r2_deterministic_matrix_is_machine_readable_and_complete() -> None:
    case_ids = tuple(item["case"] for item in V1_I_R2_DETERMINISTIC_MATRIX)
    assert len(case_ids) >= 30
    assert len(set(case_ids)) == len(case_ids)
    assert all(item["evidence"] for item in V1_I_R2_DETERMINISTIC_MATRIX)
