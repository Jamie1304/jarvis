"""Provider-neutral local-AI setup, lifecycle, and evidence orchestration.

The control plane deliberately owns policy and lifecycle decisions while provider
adapters own only typed provider operations.  Model metadata and model output are
descriptive inputs; neither can grant trust or execution authority.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import uuid4

from jarvis.ai.knowledge import (
    CookbookObservation,
    CookbookOutcome,
    EvidenceSufficiency,
    ModelKnowledgeService,
    VerifierAgreement,
    identity_for,
)
from jarvis.ai.model_manager import (
    LocalModelManager,
    LocalModelRecord,
    LocalModelSpec,
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
from jarvis.ai.providers.registry import ProviderLocality, ProviderRegistry
from jarvis.ai.routing import (
    InferenceDispatcher,
    RouteCandidate,
    RouteDecision,
    RouteRequest,
    RouteStatus,
    RoutingPolicy,
)
from jarvis.hardware import (
    FitStatus,
    HardwareInventoryService,
    HardwareProfile,
    ModelCombinationRequest,
    ModelPlanner,
)
from jarvis.resources import (
    ResourceBudget,
    ResourceDecisionStatus,
    ResourceGovernor,
    ResourcePriority,
)


class LocalAISetupMode(StrEnum):
    JARVIS_MANAGED_LOCAL_AI = "jarvis_managed_local_ai"
    USE_EXISTING_LOCAL_PROVIDER = "use_existing_local_provider"
    MANUAL_CONFIGURATION = "manual_configuration"


class LocalAISetupStatus(StrEnum):
    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class AcquisitionStatus(StrEnum):
    ALREADY_AVAILABLE = "already_available"
    ALLOWED = "allowed"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    DEFERRED_BY_RESOURCES = "deferred_by_resources"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class LocalAIUserPolicy:
    """Typed backend policy for local model setup and lifecycle."""

    routing_policy: RoutingPolicy = RoutingPolicy.PREFER_LOCAL
    provider_pin: str | None = None
    model_pin: str | None = None
    auto_download_allowed: bool = False
    maximum_model_disk_bytes: int | None = None
    model_never_auto_remove: bool = True
    provider_auto_start: bool = True
    keep_warm: bool = True
    idle_unload_seconds: float | None = 300.0

    def __post_init__(self) -> None:
        if not isinstance(self.routing_policy, RoutingPolicy):
            raise ValueError("Local-AI routing policy is invalid")
        for pin_name, pin_value in (
            ("provider pin", self.provider_pin),
            ("model pin", self.model_pin),
        ):
            if pin_value is not None and (
                type(pin_value) is not str or not pin_value.strip() or "\x00" in pin_value
            ):
                raise ValueError(f"Local-AI {pin_name} is invalid")
        for policy_name, policy_value in (
            ("auto-download", self.auto_download_allowed),
            ("never-remove", self.model_never_auto_remove),
            ("provider auto-start", self.provider_auto_start),
            ("keep-warm", self.keep_warm),
        ):
            if type(policy_value) is not bool:
                raise ValueError(f"Local-AI {policy_name} policy is invalid")
        if self.maximum_model_disk_bytes is not None and (
            type(self.maximum_model_disk_bytes) is not int or self.maximum_model_disk_bytes < 0
        ):
            raise ValueError("Local-AI disk budget is invalid")
        if self.idle_unload_seconds is not None and (
            type(self.idle_unload_seconds) not in {int, float} or self.idle_unload_seconds < 0
        ):
            raise ValueError("Local-AI idle-unload policy is invalid")


@dataclass(frozen=True, slots=True)
class ModelAcquisitionDecision:
    model_id: str
    status: AcquisitionStatus
    reason: str
    requested_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class LocalModelCandidate:
    spec: LocalModelSpec
    fit: FitStatus
    relevance: float
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LocalAISetupResult:
    mode: LocalAISetupMode
    status: LocalAISetupStatus
    hardware: HardwareProfile
    provider_id: str
    discovered_models: tuple[str, ...]
    selected_model_id: str | None
    portfolio: tuple[str, ...]
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LocalAIStatus:
    provider_id: str
    provider_ownership: str
    hardware: HardwareProfile
    models: tuple[LocalModelRecord, ...]
    setup_mode: LocalAISetupMode | None
    status: LocalAISetupStatus


class _CalibrationDispatcher(Protocol):
    async def generate(
        self,
        request: GenerationRequest,
        intent: RouteRequest,
        *,
        decision: RouteDecision | None = None,
    ) -> object: ...


VerificationCallback = Callable[[str], bool | Awaitable[bool]]


class LocalAIControlPlane:
    """One authoritative provider-neutral local model control plane."""

    def __init__(
        self,
        registry: ProviderRegistry,
        manager: LocalModelManager,
        hardware: HardwareInventoryService,
        planner: ModelPlanner,
        resource_governor: ResourceGovernor,
        knowledge: ModelKnowledgeService,
        *,
        provider_id: str,
        policy: LocalAIUserPolicy | None = None,
    ) -> None:
        if not isinstance(registry, ProviderRegistry):
            raise ValueError("Local-AI provider registry is invalid")
        if not isinstance(manager, LocalModelManager):
            raise ValueError("Local-AI model manager is invalid")
        if not isinstance(hardware, HardwareInventoryService):
            raise ValueError("Local-AI hardware inventory is invalid")
        if not isinstance(planner, ModelPlanner):
            raise ValueError("Local-AI model planner is invalid")
        if not isinstance(resource_governor, ResourceGovernor):
            raise ValueError("Local-AI resource governor is invalid")
        if not isinstance(knowledge, ModelKnowledgeService):
            raise ValueError("Local-AI model knowledge is invalid")
        if type(provider_id) is not str or not provider_id.strip():
            raise ValueError("Local-AI provider identity is invalid")
        self._registry = registry
        self._manager = manager
        self._hardware = hardware
        self._planner = planner
        self._resources = resource_governor
        self._knowledge = knowledge
        self._provider_id = provider_id
        self._policy = policy or LocalAIUserPolicy()
        self._setup_mode: LocalAISetupMode | None = None
        self._status = LocalAISetupStatus.UNKNOWN
        self._dispatcher: _CalibrationDispatcher | None = None
        self._last_hardware: HardwareProfile | None = None

    @property
    def policy(self) -> LocalAIUserPolicy:
        return self._policy

    @property
    def manager(self) -> LocalModelManager:
        return self._manager

    @property
    def hardware(self) -> HardwareInventoryService:
        return self._hardware

    def bind_dispatcher(self, dispatcher: InferenceDispatcher) -> None:
        if not isinstance(dispatcher, InferenceDispatcher):
            raise ValueError("Local-AI dispatcher is invalid")
        self._dispatcher = dispatcher

    def apply_policy_to_step(self, intent: RouteRequest) -> RouteRequest:
        """Apply user policy to one typed cognitive step.

        Pins are carried by the step request itself.  The control plane never
        mutates a process-wide router default, so independent steps in one
        task graph remain independently routable.
        """

        if not isinstance(intent, RouteRequest):
            raise ValueError("Local-AI route intent is invalid")
        return replace(
            intent,
            policy=(
                self._policy.routing_policy
                if intent.policy is RoutingPolicy.BALANCED
                else intent.policy
            ),
            pinned_provider_id=intent.pinned_provider_id or self._policy.provider_pin,
            pinned_model_id=intent.pinned_model_id or self._policy.model_pin,
        )

    async def setup(
        self,
        mode: LocalAISetupMode = LocalAISetupMode.USE_EXISTING_LOCAL_PROVIDER,
        *,
        roles: tuple[ModelRole, ...] = (ModelRole.GENERAL,),
    ) -> LocalAISetupResult:
        if not isinstance(mode, LocalAISetupMode):
            raise ValueError("Local-AI setup mode is invalid")
        if (
            type(roles) is not tuple
            or not roles
            or any(not isinstance(role, ModelRole) for role in roles)
        ):
            raise ValueError("Local-AI setup roles are invalid")
        profile = self._hardware.inspect()
        self._last_hardware = profile
        self._setup_mode = mode
        reasons: list[str] = []
        try:
            # The adapter decides whether an unavailable provider may be
            # started.  Calling the typed ensure/adopt seam even when
            # auto-start is disabled still lets an already-running external
            # provider be observed and adopted without giving JARVIS process
            # ownership.
            await self._manager.ensure_provider()
            self._knowledge.observe_provider_health(
                self._registry.definition(self._provider_id).metadata,
                True,
                observed_at=datetime.now(UTC),
                source="local_ai_provider_setup",
                detail="Typed local provider setup completed",
            )
        except Exception as error:
            self._status = LocalAISetupStatus.UNAVAILABLE
            return LocalAISetupResult(
                mode,
                self._status,
                profile,
                self._provider_id,
                (),
                None,
                (),
                (f"provider unavailable: {type(error).__name__}",),
            )
        try:
            records = await self._manager.discover()
        except Exception as error:
            self._status = LocalAISetupStatus.UNAVAILABLE
            return LocalAISetupResult(
                mode,
                self._status,
                profile,
                self._provider_id,
                (),
                None,
                (),
                (f"model discovery failed: {type(error).__name__}",),
            )
        self._refresh_registry(records)
        if not records:
            self._status = LocalAISetupStatus.UNAVAILABLE
            return LocalAISetupResult(
                mode,
                self._status,
                profile,
                self._provider_id,
                (),
                None,
                (),
                ("provider reported no installed models",),
            )
        portfolio = self._planner.plan(ModelCombinationRequest(roles, max_concurrency=1), profile)
        portfolio_ids = tuple(model_id for _, model_id in portfolio.assignments if model_id)
        if portfolio.status is FitStatus.UNKNOWN:
            reasons.extend(portfolio.reasons)
        elif portfolio.status is FitStatus.INCOMPATIBLE:
            reasons.extend(portfolio.reasons)
        selected = self._selected_model(records, portfolio_ids)
        if selected is None:
            self._status = (
                LocalAISetupStatus.UNKNOWN
                if portfolio.status is FitStatus.UNKNOWN
                else LocalAISetupStatus.DEGRADED
            )
            return LocalAISetupResult(
                mode,
                self._status,
                profile,
                self._provider_id,
                tuple(item.spec.model_id for item in records),
                None,
                portfolio_ids,
                tuple(dict.fromkeys(reasons or ["no measured-compatible local model"])),
            )
        fit = self._manager.check_compatibility(selected.spec.model_id, profile)
        if fit is FitStatus.UNKNOWN:
            reasons.append("selected model capacity is unknown")
        elif fit is FitStatus.INCOMPATIBLE:
            reasons.append("selected model does not fit measured hardware")
        self._status = (
            LocalAISetupStatus.READY
            if fit is FitStatus.COMPATIBLE
            else LocalAISetupStatus.UNKNOWN
            if fit is FitStatus.UNKNOWN
            else LocalAISetupStatus.DEGRADED
        )
        return LocalAISetupResult(
            mode,
            self._status,
            profile,
            self._provider_id,
            tuple(item.spec.model_id for item in records),
            selected.spec.model_id,
            portfolio_ids or (selected.spec.model_id,),
            tuple(dict.fromkeys(reasons)),
        )

    async def discover(self) -> tuple[LocalModelRecord, ...]:
        records = await self._manager.discover()
        self._refresh_registry(records)
        return records

    async def candidates(
        self, *, role: ModelRole = ModelRole.GENERAL, task_class: str = "general"
    ) -> tuple[LocalModelCandidate, ...]:
        records = await self.discover()
        profile = self._last_hardware or self._hardware.inspect()
        candidates: list[LocalModelCandidate] = []
        for record in records:
            fit = self._manager.check_compatibility(record.spec.model_id, profile)
            model = record.spec.metadata
            relevance = 1.0 if not model.roles or role in model.roles else 0.0
            try:
                summary = self._knowledge.cookbook_summary(
                    identity_for(self._provider_id, model), task_class=task_class
                )
                if summary.evidence_sufficiency is EvidenceSufficiency.SUFFICIENT:
                    relevance += summary.verified_success_rate or 0.0
            except KeyError:
                pass
            candidates.append(
                LocalModelCandidate(
                    record.spec,
                    fit,
                    relevance,
                    tuple(("role mismatch",) if relevance == 0.0 else ()),
                )
            )
        return tuple(sorted(candidates, key=lambda item: (-item.relevance, item.spec.model_id)))

    def acquisition_decision(self, model_id: str) -> ModelAcquisitionDecision:
        record = self._manager.inspect(model_id)
        size = record.spec.metadata.storage_bytes
        if record.spec.installed or record.state in {
            ModelLifecycleState.AVAILABLE,
            ModelLifecycleState.WARM,
            ModelLifecycleState.HEALTHY,
            ModelLifecycleState.IDLE,
            ModelLifecycleState.IN_USE,
        }:
            return ModelAcquisitionDecision(
                model_id,
                AcquisitionStatus.ALREADY_AVAILABLE,
                "provider reports model available",
                size,
            )
        if not self._policy.auto_download_allowed:
            return ModelAcquisitionDecision(
                model_id,
                AcquisitionStatus.BLOCKED_BY_POLICY,
                "automatic model acquisition is disabled by user policy",
                size,
            )
        if (
            size is not None
            and self._policy.maximum_model_disk_bytes is not None
            and size > self._policy.maximum_model_disk_bytes
        ):
            return ModelAcquisitionDecision(
                model_id, AcquisitionStatus.BLOCKED_BY_POLICY, "model exceeds disk budget", size
            )
        if size is None:
            return ModelAcquisitionDecision(
                model_id,
                AcquisitionStatus.UNKNOWN,
                "model size is unknown; acquisition is conservative",
                None,
            )
        profile = self._last_hardware or self._hardware.inspect()
        if profile.reading.disk_free_bytes is None:
            return ModelAcquisitionDecision(
                model_id,
                AcquisitionStatus.DEFERRED_BY_RESOURCES,
                "free disk capacity is unmeasured",
                size,
            )
        decision = self._resources.decide(
            f"local-model-acquisition.{model_id}",
            ResourcePriority.USER_REQUESTED,
            ResourceBudget(disk_bytes=size, duration_seconds=600),
        )
        if decision.status not in {ResourceDecisionStatus.ALLOW, ResourceDecisionStatus.REDUCE}:
            return ModelAcquisitionDecision(
                model_id,
                AcquisitionStatus.DEFERRED_BY_RESOURCES,
                decision.reason,
                size,
            )
        return ModelAcquisitionDecision(model_id, AcquisitionStatus.ALLOWED, decision.reason, size)

    async def acquire(self, model_id: str) -> ModelAcquisitionDecision:
        decision = self.acquisition_decision(model_id)
        if decision.status is not AcquisitionStatus.ALLOWED:
            return decision
        await self._manager.download(model_id)
        await self._manager.install(model_id)
        return ModelAcquisitionDecision(
            model_id,
            AcquisitionStatus.ALREADY_AVAILABLE,
            "model acquired and provider-verified",
            decision.requested_bytes,
        )

    async def prepare_for_inference(
        self, candidate: RouteCandidate, intent: RouteRequest | None = None
    ) -> LocalModelRecord:
        if not isinstance(candidate, RouteCandidate):
            raise ModelLifecycleError("Inference lifecycle candidate is malformed")
        if candidate.provider_id.casefold() != self._provider_id.casefold():
            raise ModelLifecycleError("Local lifecycle received a non-local provider")
        try:
            record = self._manager.inspect(candidate.model_id)
        except KeyError:
            await self.discover()
            record = self._manager.inspect(candidate.model_id)
        if not record.spec.installed and record.state not in {
            ModelLifecycleState.AVAILABLE,
            ModelLifecycleState.WARM,
            ModelLifecycleState.HEALTHY,
            ModelLifecycleState.IDLE,
            ModelLifecycleState.IN_USE,
        }:
            acquisition = await self.acquire(candidate.model_id)
            if acquisition.status not in {
                AcquisitionStatus.ALLOWED,
                AcquisitionStatus.ALREADY_AVAILABLE,
            }:
                raise ModelLifecycleError(acquisition.reason)
            record = self._manager.inspect(candidate.model_id)
        profile = self._last_hardware or self._hardware.inspect()
        fit = self._manager.check_compatibility(candidate.model_id, profile)
        if fit is not FitStatus.COMPATIBLE:
            raise ModelLifecycleError("local model hardware fit is " + fit.value)
        model = record.spec.metadata
        priority = intent.priority if intent is not None else ResourcePriority.USER_REQUESTED
        decision = self._resources.decide(
            f"local-model.{candidate.model_id}",
            priority,
            ResourceBudget(
                ram_bytes=model.ram_bytes,
                vram_bytes=model.vram_bytes,
                disk_bytes=None,
                concurrency=intent.concurrency if intent is not None else 1,
                duration_seconds=120,
            ),
        )
        if decision.status not in {ResourceDecisionStatus.ALLOW, ResourceDecisionStatus.REDUCE}:
            raise ModelLifecycleError(decision.reason)
        if decision.unload_cold_models:
            await self._manager.unload_idle(
                exclude=(candidate.model_id,), preserve=(candidate.model_id,)
            )
        if record.state not in {
            ModelLifecycleState.WARM,
            ModelLifecycleState.LOADED,
            ModelLifecycleState.HEALTHY,
            ModelLifecycleState.IDLE,
            ModelLifecycleState.IN_USE,
        } or not self._manager.has_runtime_handle(candidate.model_id):
            record = await self._manager.load(candidate.model_id)
        return record

    def begin_inference(self, candidate: RouteCandidate) -> None:
        self._manager.mark_in_use(candidate.model_id)

    def end_inference(self, candidate: RouteCandidate) -> None:
        self._manager.mark_idle(candidate.model_id)

    async def recover_provider(self, provider_id: str) -> bool:
        if provider_id.casefold() != self._provider_id.casefold():
            return False
        try:
            await self._manager.recover_provider()
            await self.discover()
            return True
        except Exception:
            return False

    async def calibrate(
        self,
        model_id: str,
        task_class: str,
        *,
        samples: int = 3,
        verify: VerificationCallback,
        priority: ResourcePriority = ResourcePriority.BACKGROUND,
        dispatcher: _CalibrationDispatcher | None = None,
    ) -> tuple[bool, ...]:
        if type(task_class) is not str or not task_class.strip() or len(task_class) > 128:
            raise ValueError("Calibration task class is invalid")
        if type(samples) is not int or not 1 <= samples <= 8:
            raise ValueError("Calibration sample count is invalid")
        if not callable(verify):
            raise ValueError("Calibration verifier is invalid")
        if not isinstance(priority, ResourcePriority):
            raise ValueError("Calibration resource priority is invalid")
        selected_dispatcher = dispatcher or self._dispatcher
        if selected_dispatcher is None:
            raise ModelLifecycleError("Calibration dispatcher is not configured")
        record = self._manager.inspect(model_id)
        admission = self._resources.decide(
            f"local-model-calibration.{model_id}",
            priority,
            ResourceBudget(
                ram_bytes=record.spec.metadata.ram_bytes,
                vram_bytes=record.spec.metadata.vram_bytes,
                concurrency=1,
                duration_seconds=120,
            ),
        )
        if admission.status not in {ResourceDecisionStatus.ALLOW, ResourceDecisionStatus.REDUCE}:
            return ()
        results: list[bool] = []
        for index in range(samples):
            candidate = RouteCandidate(
                self._provider_id,
                model_id,
                self._registry.definition(self._provider_id).metadata,
                record.spec.metadata,
                True,
            )
            await self.prepare_for_inference(candidate)
            message = ChatMessage(
                uuid4(),
                uuid4(),
                MessageRole.USER,
                "Return exactly JARVIS_CALIBRATION_OK.",
                datetime.now(UTC),
            )
            request = GenerationRequest(
                (message,),
                model_id,
                record.spec.metadata.context_limit,
                PrivacyContext(PrivacyClassification.LOCAL_ONLY),
            )
            intent = RouteRequest(
                task="bounded local model calibration",
                profile="model_calibration",
                role=ModelRole.GENERAL,
                policy=RoutingPolicy.LOCAL_ONLY,
                preferred_provider_id=self._provider_id,
                preferred_model_id=model_id,
                task_class=task_class,
                responsibility="calibration",
                priority=priority,
                privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
            )
            try:
                dispatched = await selected_dispatcher.generate(
                    request,
                    intent,
                    decision=RouteDecision(RouteStatus.SELECTED, candidate),
                )
                result = getattr(getattr(dispatched, "result", None), "content", None)
                valid = type(result) is str and bool(await _maybe_await(verify(result)))
                self._knowledge.record_cookbook(
                    CookbookObservation(
                        identity_for(self._provider_id, record.spec.metadata),
                        task_class,
                        CookbookOutcome.VERIFIED_SUCCESS if valid else CookbookOutcome.FAILURE,
                        datetime.now(UTC),
                        operation_class="calibration",
                        role=ModelRole.GENERAL,
                        locality=ProviderLocality.LOCAL,
                        machine_scope="this_machine",
                        verified=valid,
                        verifier_agreement=(
                            VerifierAgreement.DETERMINISTIC_VERIFICATION
                            if valid
                            else VerifierAgreement.UNKNOWN
                        ),
                        observation_id=f"calibration-{model_id}-{task_class}-{index}",
                    )
                )
                results.append(valid)
            except Exception:
                self._knowledge.record_cookbook(
                    CookbookObservation(
                        identity_for(self._provider_id, record.spec.metadata),
                        task_class,
                        CookbookOutcome.FAILURE,
                        datetime.now(UTC),
                        operation_class="calibration",
                        role=ModelRole.GENERAL,
                        locality=ProviderLocality.LOCAL,
                        machine_scope="this_machine",
                        verified=False,
                        observation_id=f"calibration-{model_id}-{task_class}-{index}",
                    )
                )
                results.append(False)
        return tuple(results)

    def status(self) -> LocalAIStatus:
        ownership = "unknown"
        adapter = getattr(self._manager, "_provider_adapter", None)
        runtime = getattr(adapter, "_runtime", None)
        if runtime is not None:
            ownership = runtime.ownership.value
        return LocalAIStatus(
            self._provider_id,
            ownership,
            self._last_hardware or self._hardware.inspect(),
            self._manager.records(),
            self._setup_mode,
            self._status,
        )

    def _refresh_registry(self, records: Sequence[LocalModelRecord]) -> None:
        models = tuple(record.spec.metadata for record in records)
        self._registry.replace_models(self._provider_id, models)
        self._knowledge.refresh_registry(
            self._registry,
            observed_at=datetime.now(UTC),
            source="local_ai_provider_discovery",
        )

    def _selected_model(
        self, records: Sequence[LocalModelRecord], portfolio_ids: Sequence[str]
    ) -> LocalModelRecord | None:
        if self._policy.model_pin is not None:
            return next(
                (item for item in records if item.spec.model_id == self._policy.model_pin), None
            )
        for model_id in portfolio_ids:
            found = next((item for item in records if item.spec.model_id == model_id), None)
            if found is not None:
                return found
        return next(iter(records), None)


async def _maybe_await(value: bool | Awaitable[bool]) -> bool:
    result = await value if isinstance(value, Awaitable) else value
    return type(result) is bool and result


__all__ = [
    "AcquisitionStatus",
    "LocalAIControlPlane",
    "LocalAISetupMode",
    "LocalAISetupResult",
    "LocalAISetupStatus",
    "LocalAIStatus",
    "LocalAIUserPolicy",
    "LocalModelCandidate",
    "ModelAcquisitionDecision",
]
