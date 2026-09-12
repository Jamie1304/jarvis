"""Hierarchical diagnostics and repair orchestration.

Package declarations are metadata only.  A trusted composition root must bind
their probe and repair IDs to application-owned callbacks.  The doctor never
executes generated package code directly, grants permission, or treats model
research as certification.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, cast
from uuid import UUID, uuid4

from jarvis.ai.models import (
    ChatMessage,
    GenerationRequest,
    MessageRole,
    ModelRole,
    PrivacyClassification,
    PrivacyContext,
)
from jarvis.ai.routing import InferenceDispatcher, RouteRequest, RoutingPolicy
from jarvis.capability_health import (
    CapabilityHealthService,
    HealthStatus,
    RepairOutcome,
    RepairResult,
    RepairStage,
)
from jarvis.integration_package import (
    DiagnosticFailureSignature,
    DiagnosticProbe,
    DiagnosticsContract,
    IntegrationPackage,
    SafeRepairAction,
)
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ActionDescriptor,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
)
from jarvis.repair_state import (
    RepairAttemptRecord,
    RepairCase,
    RepairCaseStatus,
    RepairStoreError,
    SQLiteRepairStore,
    repair_case_key,
)
from jarvis.trace import ExecutionTrace, TraceEvent, TraceEventType
from jarvis.verification import VerificationResult

# These names are the canonical doctor vocabulary while preserving the
# validated package contract that predates this orchestrator.
FailureSignature = DiagnosticFailureSignature
RepairAction = SafeRepairAction


class ComponentDoctorError(RuntimeError):
    """A diagnostic registration or orchestration contract is invalid."""


class ComponentDoctorSecurityError(ComponentDoctorError, ValueError):
    """A probe, repair, fallback, or research result crosses a trust boundary."""


class DiagnosticOwner(StrEnum):
    CORE = "core"
    PROVIDER = "provider"
    SANDBOX = "sandbox"
    PROVISIONING = "provisioning"
    CAPABILITY = "capability"


TroubleshootingOwner = DiagnosticOwner
ComponentOwner = DiagnosticOwner


class DoctorStatus(StrEnum):
    REPAIRED = "repaired"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    PERMISSION_REQUIRED = "permission_required"
    RESEARCH_REQUIRED = "research_required"
    FAILED = "failed"
    QUARANTINED = "quarantined"
    NO_ACTION = "no_action"


class RepairAttemptState(StrEnum):
    PROPOSED = "proposed"
    PERMISSION_REQUIRED = "permission_required"
    APPLYING = "applying"
    VERIFICATION_PENDING = "verification_pending"
    VERIFIED = "verified"
    FAILED = "failed"
    UNKNOWN_OUTCOME = "unknown_outcome"
    SKIPPED = "skipped"


class RepairEffectOutcome(StrEnum):
    PRE_EFFECT_FAILURE = "pre_effect_failure"
    SAFE_TO_RETRY = "safe_to_retry"
    EFFECT_CONFIRMED = "effect_confirmed"
    UNKNOWN_OUTCOME = "unknown_outcome"


_MAX_ITEMS = 64
_MAX_ATTEMPTS = 3
_UNSAFE_MARKERS = (
    "bypass",
    "disable permission",
    "disable policy",
    "disable security",
    "grant authority",
    "export secret",
    "vault master",
)


def _text(value: object, name: str, limit: int = 2_000) -> str:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise ComponentDoctorError(f"{name} is malformed")
    return value.strip()


def _labels(values: Iterable[str], name: str, limit: int = _MAX_ITEMS) -> tuple[str, ...]:
    result = tuple(_text(value, name, 512) for value in values)
    if len(result) > limit or len(set(result)) != len(result):
        raise ComponentDoctorError(f"{name} are malformed")
    return result


def _time(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ComponentDoctorError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class ComponentProblem:
    component_id: str
    summary: str
    owner: DiagnosticOwner
    failure_code: str | None = None
    health_status: HealthStatus = HealthStatus.UNKNOWN
    source: str = "application"
    trusted: bool = True
    evidence: tuple[str, ...] = ()
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    component_version: str | None = None
    failure_observation_id: str | None = None

    def __post_init__(self) -> None:
        _text(self.component_id, "Component ID", 256)
        _text(self.summary, "Problem summary")
        if not isinstance(self.owner, DiagnosticOwner):
            raise ComponentDoctorError("Problem owner is malformed")
        if self.failure_code is not None:
            _text(self.failure_code, "Failure code", 256)
        if self.component_version is not None:
            _text(self.component_version, "Component version", 256)
        if self.failure_observation_id is not None:
            _text(self.failure_observation_id, "Failure observation ID", 256)
        if not isinstance(self.health_status, HealthStatus):
            raise ComponentDoctorError("Problem health status is malformed")
        source = _text(self.source, "Problem source", 256).casefold()
        object.__setattr__(self, "source", source)
        if type(self.trusted) is not bool:
            raise ComponentDoctorError("Problem trust flag is malformed")
        if self.trusted and source in {"model", "llm", "prompt", "external", "event"}:
            raise ComponentDoctorSecurityError("Untrusted content cannot authorize diagnosis")
        _labels(self.evidence, "Problem evidence")
        object.__setattr__(self, "occurred_at", _time(self.occurred_at, "Problem timestamp"))


@dataclass(frozen=True, slots=True)
class DiagnosticProbeResult:
    probe_id: str
    passed: bool
    detail: str
    evidence: tuple[str, ...] = ()
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _text(self.probe_id, "Probe ID", 128)
        if type(self.passed) is not bool:
            raise ComponentDoctorError("Probe result is malformed")
        _text(self.detail, "Probe detail")
        _labels(self.evidence, "Probe evidence")
        object.__setattr__(self, "checked_at", _time(self.checked_at, "Probe timestamp"))


@dataclass(frozen=True, slots=True)
class RepairExecution:
    outcome: RepairEffectOutcome
    verified: bool
    detail: str
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, RepairEffectOutcome) or type(self.verified) is not bool:
            raise ComponentDoctorError("Repair execution is malformed")
        _text(self.detail, "Repair execution detail")
        _labels(self.evidence, "Repair evidence")
        if self.outcome is RepairEffectOutcome.EFFECT_CONFIRMED and not self.verified:
            raise ComponentDoctorError("Confirmed repair must include verification")


@dataclass(frozen=True, slots=True)
class FallbackOption:
    option_id: str
    description: str
    preserves_privacy: bool = True
    preserves_security: bool = True
    requires_approval: bool = False

    def __post_init__(self) -> None:
        _text(self.option_id, "Fallback option ID", 128)
        _text(self.description, "Fallback description")
        if any(
            type(value) is not bool
            for value in (self.preserves_privacy, self.preserves_security, self.requires_approval)
        ):
            raise ComponentDoctorError("Fallback option flags are malformed")
        if not self.preserves_privacy or not self.preserves_security:
            raise ComponentDoctorSecurityError("Fallback cannot weaken privacy or security")


@dataclass(frozen=True, slots=True)
class RepairCandidate:
    candidate_id: str
    description: str
    action_id: str
    source: str
    trusted: bool = False
    sandbox_verified: bool = False
    security_reviewed: bool = False
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.candidate_id, "Repair candidate ID", 128)
        _text(self.description, "Repair candidate description")
        _text(self.action_id, "Repair candidate action ID", 128)
        source = _text(self.source, "Repair candidate source", 256).casefold()
        object.__setattr__(self, "source", source)
        if any(
            type(value) is not bool
            for value in (self.trusted, self.sandbox_verified, self.security_reviewed)
        ):
            raise ComponentDoctorError("Repair candidate trust flags are malformed")
        if self.trusted and source in {"model", "llm", "prompt", "external"}:
            raise ComponentDoctorSecurityError("Model research cannot self-certify repair")
        _labels(self.evidence, "Repair candidate evidence")

    @property
    def validated(self) -> bool:
        return self.trusted and self.sandbox_verified and self.security_reviewed


@dataclass(frozen=True, slots=True)
class RepairPlaybook:
    playbook_id: str
    component_id: str
    owner: DiagnosticOwner
    failure_signatures: tuple[FailureSignature, ...] = ()
    probes: tuple[DiagnosticProbe, ...] = ()
    actions: tuple[RepairAction, ...] = ()
    fallback_strategy: tuple[str, ...] = ()
    expected_repair_verification: tuple[str, ...] = ()
    package_id: str | None = None

    def __post_init__(self) -> None:
        _text(self.playbook_id, "Repair playbook ID", 128)
        _text(self.component_id, "Playbook component ID", 256)
        if not isinstance(self.owner, DiagnosticOwner):
            raise ComponentDoctorError("Playbook owner is malformed")
        if len(self.failure_signatures) > _MAX_ITEMS or any(
            not isinstance(item, FailureSignature) for item in self.failure_signatures
        ):
            raise ComponentDoctorError("Playbook failure signatures are malformed")
        if len(self.probes) > _MAX_ITEMS or any(
            not isinstance(item, DiagnosticProbe) for item in self.probes
        ):
            raise ComponentDoctorError("Playbook probes are malformed")
        if len(self.actions) > _MAX_ITEMS or any(
            not isinstance(item, RepairAction) for item in self.actions
        ):
            raise ComponentDoctorError("Playbook repair actions are malformed")
        if len({item.probe_id for item in self.probes}) != len(self.probes):
            raise ComponentDoctorError("Playbook probe IDs must be unique")
        if len({item.action_id for item in self.actions}) != len(self.actions):
            raise ComponentDoctorError("Playbook action IDs must be unique")
        _labels(self.fallback_strategy, "Playbook fallback strategy")
        _labels(self.expected_repair_verification, "Playbook verification")
        if self.package_id is not None:
            _text(self.package_id, "Playbook package ID", 128)

    @classmethod
    def from_package(cls, package: IntegrationPackage) -> RepairPlaybook:
        if not isinstance(package, IntegrationPackage):
            raise ComponentDoctorError("Integration package is malformed")
        contract: DiagnosticsContract = package.diagnostics
        return cls(
            f"{package.package_id}.diagnostics",
            package.package_id,
            DiagnosticOwner.CAPABILITY,
            contract.known_failure_signatures,
            contract.probes,
            contract.safe_repairs,
            contract.fallback_strategy or contract.fallback_hints,
            contract.expected_repair_verification,
            package.package_id,
        )

    @property
    def signatures(self) -> tuple[FailureSignature, ...]:
        return self.failure_signatures


@dataclass(frozen=True, slots=True)
class RepairAttempt:
    attempt_id: UUID
    component_id: str
    action_id: str
    number: int
    state: RepairAttemptState
    outcome: RepairEffectOutcome | None
    detail: str
    verification: tuple[str, ...] = ()
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_id, UUID):
            raise ComponentDoctorError("Repair attempt ID is malformed")
        _text(self.component_id, "Attempt component ID", 256)
        _text(self.action_id, "Attempt action ID", 128)
        if type(self.number) is not int or not 1 <= self.number <= _MAX_ATTEMPTS:
            raise ComponentDoctorError("Repair attempt number is malformed")
        if not isinstance(self.state, RepairAttemptState):
            raise ComponentDoctorError("Repair attempt state is malformed")
        if self.outcome is not None and not isinstance(self.outcome, RepairEffectOutcome):
            raise ComponentDoctorError("Repair attempt outcome is malformed")
        _text(self.detail, "Repair attempt detail")
        _labels(self.verification, "Repair attempt verification")
        object.__setattr__(self, "started_at", _time(self.started_at, "Attempt start"))
        if self.finished_at is not None:
            object.__setattr__(self, "finished_at", _time(self.finished_at, "Attempt finish"))


@dataclass(frozen=True, slots=True)
class DoctorResult:
    problem: ComponentProblem
    status: DoctorStatus
    owner: DiagnosticOwner
    signature: FailureSignature | None
    probes: tuple[DiagnosticProbeResult, ...]
    attempts: tuple[RepairAttempt, ...]
    fallback_id: str | None
    research: RepairCandidate | None
    detail: str
    case_id: UUID | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.problem, ComponentProblem)
            or not isinstance(self.status, DoctorStatus)
            or not isinstance(self.owner, DiagnosticOwner)
        ):
            raise ComponentDoctorError("Doctor result is malformed")
        if self.signature is not None and not isinstance(self.signature, FailureSignature):
            raise ComponentDoctorError("Doctor signature is malformed")
        if len(self.probes) > _MAX_ITEMS or any(
            not isinstance(item, DiagnosticProbeResult) for item in self.probes
        ):
            raise ComponentDoctorError("Doctor probe results are malformed")
        if len(self.attempts) > _MAX_ATTEMPTS or any(
            not isinstance(item, RepairAttempt) for item in self.attempts
        ):
            raise ComponentDoctorError("Doctor repair attempts are malformed")
        if self.fallback_id is not None:
            _text(self.fallback_id, "Doctor fallback ID", 128)
        if self.research is not None and not isinstance(self.research, RepairCandidate):
            raise ComponentDoctorError("Doctor research result is malformed")
        _text(self.detail, "Doctor result detail")
        if self.case_id is not None and not isinstance(self.case_id, UUID):
            raise ComponentDoctorError("Doctor case ID is malformed")


ProbeCallback = Callable[
    [ComponentProblem], DiagnosticProbeResult | Awaitable[DiagnosticProbeResult]
]
RepairCallback = Callable[
    [ComponentProblem, RepairAction], RepairExecution | Awaitable[RepairExecution]
]
FallbackCallback = Callable[[ComponentProblem], RepairExecution | Awaitable[RepairExecution]]
ResearchCallback = Callable[
    [ComponentProblem], RepairCandidate | None | Awaitable[RepairCandidate | None]
]
AuthorizationCallback = Callable[[ComponentProblem, RepairAction], bool | Awaitable[bool]]
RepairAuthorizationCallback = Callable[
    [ComponentProblem, RepairAction, UUID], bool | Awaitable[bool]
]
RepairObservationCallback = Callable[[RepairCase], object | Awaitable[object]]
IndependentVerificationCallback = Callable[
    [ComponentProblem, RepairAction, RepairExecution],
    VerificationResult | bool | str | Awaitable[VerificationResult | bool | str],
]


class RoutedRepairResearch:
    """Optional P3C research adapter; its output is always untrusted."""

    def __init__(self, dispatcher: InferenceDispatcher) -> None:
        if not isinstance(dispatcher, InferenceDispatcher):
            raise ComponentDoctorError("Inference dispatcher is malformed")
        self._dispatcher = dispatcher

    async def __call__(self, problem: ComponentProblem) -> RepairCandidate | None:
        request = RouteRequest(
            task="bounded repair candidate research",
            profile="repair_research",
            role=ModelRole.REASONING,
            classification=PrivacyClassification.LOCAL_ONLY.value,
            policy=RoutingPolicy.LOCAL_ONLY,
            allow_no_llm=True,
            task_class="repair_research",
            responsibility="repair_research",
        )
        message = ChatMessage(
            uuid4(),
            uuid4(),
            # This is a bounded research message, not conversation memory.
            # Only trusted failure identity is included.
            MessageRole.USER,
            json.dumps(
                {
                    "component": problem.component_id,
                    "failure_code": problem.failure_code,
                    "owner": problem.owner.value,
                },
                sort_keys=True,
            ),
            datetime.now(UTC),
        )
        try:
            dispatched = await self._dispatcher.generate(
                GenerationRequest(
                    (message,), "", 1, PrivacyContext(PrivacyClassification.LOCAL_ONLY)
                ),
                request,
            )
            value = json.loads(dispatched.result.content)
            if not isinstance(value, dict) or type(value.get("action_id")) is not str:
                return None
            description = value.get("description", "Model-suggested repair candidate")
            if type(description) is not str:
                return None
            return RepairCandidate(
                f"research-{uuid4().hex}", description[:2_000], value["action_id"], "model"
            )
        except Exception:
            return None


class BrokeredRepairAuthorizer:
    """Application-owned repair authority adapter backed by PermissionBroker."""

    def __init__(self, broker: PermissionBroker, *, user_id: str | None) -> None:
        if not isinstance(broker, PermissionBroker) or not isinstance(user_id, str) or not user_id:
            raise ComponentDoctorError("Repair broker authority context is malformed")
        self._broker = broker
        self._user_id = user_id
        self._identity = object()
        self._declared = frozenset({Permission.REPAIR_EXECUTE})
        broker.register_tool("repair.authority", self._identity, self._declared)

    async def __call__(
        self, problem: ComponentProblem, action: RepairAction, case_id: UUID
    ) -> bool:
        if not isinstance(problem, ComponentProblem) or not isinstance(action, RepairAction):
            return False
        arguments = {
            "case_id": str(case_id),
            "component_id": problem.component_id,
            "failure_code": problem.failure_code or "<none>",
            "component_version": problem.component_version or "<none>",
            "action_id": action.action_id,
            "required_permissions": ",".join(item.value for item in action.required_permissions),
        }
        descriptor = ActionDescriptor(
            "repair.execute",
            tuple(
                # The values are trusted, bounded repair facts, not model text.
                SafeArgument(name, value)
                for name, value in sorted(arguments.items())
            ),
            Risk.HIGH,
            (PermissionRequest(Permission.REPAIR_EXECUTE, PermissionScope(task_id=case_id)),),
        )
        result = await self._broker.authorize(
            tool_id="repair.authority",
            tool_identity=self._identity,
            declared_permissions=self._declared,
            task_id=case_id,
            user_id=self._user_id,
            descriptor=descriptor,
            normalized_arguments=arguments,
        )
        return result.authorized


class ComponentDoctor:
    """Route failures to their owner and isolate repair failures."""

    def __init__(
        self,
        health: CapabilityHealthService,
        *,
        research: ResearchCallback | None = None,
        authorize: AuthorizationCallback | None = None,
        trace: ExecutionTrace | None = None,
        clock: Callable[[], datetime] | None = None,
        max_attempts: int = 2,
        repair_store: SQLiteRepairStore | None = None,
        verifier: IndependentVerificationCallback | None = None,
        repair_authorizer: RepairAuthorizationCallback | None = None,
        repair_observer: RepairObservationCallback | None = None,
    ) -> None:
        if not isinstance(health, CapabilityHealthService):
            raise ComponentDoctorError("Capability health service is malformed")
        if type(max_attempts) is not int or not 1 <= max_attempts <= _MAX_ATTEMPTS:
            raise ComponentDoctorError("Doctor attempt bound is malformed")
        self._health = health
        self._research = research
        self._authorize = authorize
        self._trace = trace or health.trace
        self._clock = clock or (lambda: datetime.now(UTC))
        self._max_attempts = max_attempts
        if repair_store is not None and not isinstance(repair_store, SQLiteRepairStore):
            raise ComponentDoctorError("Repair store is malformed")
        if verifier is not None and not callable(verifier):
            raise ComponentDoctorError("Independent verifier is malformed")
        if repair_authorizer is not None and not callable(repair_authorizer):
            raise ComponentDoctorError("Repair authorizer is malformed")
        if repair_observer is not None and not callable(repair_observer):
            raise ComponentDoctorError("Repair observer is malformed")
        self._repair_store = repair_store
        self._verifier = verifier
        self._repair_authorizer = repair_authorizer
        self._repair_observer = repair_observer
        self._playbooks: dict[str, RepairPlaybook] = {}
        self._probes: dict[tuple[str, str], ProbeCallback] = {}
        self._actions: dict[tuple[str, str], RepairCallback] = {}
        self._fallbacks: dict[tuple[str, str], tuple[FallbackOption, FallbackCallback]] = {}
        self._verifiers: dict[tuple[str, str], IndependentVerificationCallback] = {}

    @property
    def repair_store(self) -> SQLiteRepairStore | None:
        return self._repair_store

    def register_verifier(
        self, component_id: str, action_id: str, callback: IndependentVerificationCallback
    ) -> None:
        """Bind a trusted application-owned post-effect observation."""

        self._playbook(component_id)
        self._declared_action(self._playbook(component_id), action_id)
        if not callable(callback):
            raise ComponentDoctorError("Independent verifier is malformed")
        key = (component_id, action_id)
        if key in self._verifiers:
            raise ComponentDoctorError("Independent verifier is already bound")
        self._verifiers[key] = callback

    register_post_repair_verifier = register_verifier

    def register_playbook(self, playbook: RepairPlaybook) -> None:
        if not isinstance(playbook, RepairPlaybook):
            raise ComponentDoctorError("Repair playbook is malformed")
        if playbook.component_id in self._playbooks:
            raise ComponentDoctorError("Component already has a repair playbook")
        self._playbooks[playbook.component_id] = playbook

    def register_package(self, package: IntegrationPackage) -> RepairPlaybook:
        playbook = RepairPlaybook.from_package(package)
        self.register_playbook(playbook)
        return playbook

    def register_probe(
        self,
        component_id: str,
        probe_id: str,
        callback: ProbeCallback,
        *,
        owner: DiagnosticOwner | None = None,
    ) -> None:
        playbook = self._playbook(component_id)
        probe = self._declared_probe(playbook, probe_id)
        if owner is not None and owner is not playbook.owner:
            raise ComponentDoctorSecurityError("Probe owner does not own the component")
        if not probe.safe_read_only or not callable(callback):
            raise ComponentDoctorSecurityError("Diagnostic probe is not read-only or callable")
        key = (playbook.component_id, probe_id)
        if key in self._probes:
            raise ComponentDoctorError("Diagnostic probe is already bound")
        self._probes[key] = callback

    def register_action(
        self,
        component_id: str,
        action_id: str,
        callback: RepairCallback,
        *,
        owner: DiagnosticOwner | None = None,
    ) -> None:
        playbook = self._playbook(component_id)
        action = self._declared_action(playbook, action_id)
        if owner is not None and owner is not playbook.owner:
            raise ComponentDoctorSecurityError("Repair owner does not own the component")
        if not callable(callback) or not action.requires_approval:
            raise ComponentDoctorSecurityError("Repair action cannot bypass approval")
        description = action.description.casefold()
        if any(marker in description for marker in _UNSAFE_MARKERS):
            raise ComponentDoctorSecurityError("Repair action attempts to weaken security")
        key = (playbook.component_id, action_id)
        if key in self._actions:
            raise ComponentDoctorError("Repair action is already bound")
        self._actions[key] = callback

    bind_repair_action = register_action

    def register_fallback(
        self,
        component_id: str,
        option: FallbackOption,
        callback: FallbackCallback,
        *,
        owner: DiagnosticOwner | None = None,
    ) -> None:
        playbook = self._playbook(component_id)
        if not isinstance(option, FallbackOption) or not callable(callback):
            raise ComponentDoctorError("Fallback binding is malformed")
        if option.option_id not in playbook.fallback_strategy:
            raise ComponentDoctorError("Fallback is not declared by the playbook")
        if owner is not None and owner is not playbook.owner:
            raise ComponentDoctorSecurityError("Fallback owner does not own the component")
        key = (component_id, option.option_id)
        if key in self._fallbacks:
            raise ComponentDoctorError("Fallback is already bound")
        self._fallbacks[key] = (option, callback)

    def owner_for(self, component_id: str) -> DiagnosticOwner:
        return self._playbook(component_id).owner

    def playbooks(self) -> tuple[RepairPlaybook, ...]:
        return tuple(self._playbooks.values())

    async def run(self, problem: ComponentProblem) -> DoctorResult:
        """Diagnose and safely repair one component without escaping its owner."""

        if not isinstance(problem, ComponentProblem):
            raise ComponentDoctorError("Component problem is malformed")
        case: RepairCase | None = None
        if self._repair_store is not None:
            try:
                case, created = self._repair_store.open_case(
                    component_id=problem.component_id,
                    owner=problem.owner.value,
                    failure_code=problem.failure_code,
                    component_version=problem.component_version,
                    attempt_budget=self._max_attempts,
                    now=self._now(),
                    failure_observation_id=problem.failure_observation_id,
                )
            except RepairStoreError as error:
                raise ComponentDoctorError("Repair persistence is unavailable") from error
            if not created and case.status not in {
                RepairCaseStatus.PERMISSION_REQUIRED,
                RepairCaseStatus.DIAGNOSIS_PENDING,
                RepairCaseStatus.AUTHORITY_PENDING,
                RepairCaseStatus.VERIFICATION_PENDING,
            }:
                return self._result_for_existing_case(problem, case)
        playbook = self._playbooks.get(problem.component_id)
        if playbook is None:
            await self._safe_health(
                problem, HealthStatus.DEGRADED, "No component playbook is registered"
            )
            research_candidate = await self._research_for(problem)
            return self._result(
                problem,
                DoctorStatus.RESEARCH_REQUIRED,
                problem.owner,
                None,
                (),
                (),
                None,
                research_candidate,
                "No known owner playbook; research is required",
                case_id=None if case is None else case.case_id,
            )
        if playbook.owner is not problem.owner:
            raise ComponentDoctorSecurityError("Problem owner does not own the component")

        if case is not None and case.status is RepairCaseStatus.VERIFICATION_PENDING:
            return await self._resume_verification(problem, playbook, case)

        signature = self._match_signature(playbook, problem)
        probe_results = await self._run_probes(playbook, problem)
        if case is not None:
            case = self._case_update(
                case,
                latest_diagnosis=(signature.signature if signature is not None else "unknown"),
            )
        action = self._known_action(playbook, signature)
        candidate: RepairCandidate | None = None
        if action is None:
            candidate = await self._research_for(problem)
            if candidate is None:
                return await self._degrade_or_fallback(
                    problem,
                    playbook,
                    signature,
                    probe_results,
                    (),
                    "Failure is not covered by a verified repair playbook",
                    case=case,
                )
            if not candidate.validated:
                await self._safe_health(
                    problem,
                    HealthStatus.DEGRADED,
                    "Research candidate requires trusted sandbox review",
                )
                return self._result(
                    problem,
                    DoctorStatus.RESEARCH_REQUIRED,
                    playbook.owner,
                    signature,
                    probe_results,
                    (),
                    None,
                    candidate,
                    "Research produced an unverified repair candidate",
                    case_id=None if case is None else case.case_id,
                )
            action = self._declared_action(playbook, candidate.action_id)

        attempts: list[RepairAttempt] = []
        callback = self._actions.get((playbook.component_id, action.action_id))
        if callback is None:
            return await self._degrade_or_fallback(
                problem,
                playbook,
                signature,
                probe_results,
                attempts,
                "Repair is declared but has no trusted application binding",
                candidate,
                case=case,
            )
        if action.requires_approval and not await self._authorized(problem, action, case):
            if case is not None:
                case = self._case_update(
                    case,
                    status=RepairCaseStatus.PERMISSION_REQUIRED,
                    selected_action=action.action_id,
                    terminal_reason="Fresh exact approval is required",
                )
            attempt = self._attempt(
                problem,
                action,
                1,
                RepairAttemptState.PERMISSION_REQUIRED,
                None,
                "Fresh trusted approval is required before repair",
            )
            attempts.append(attempt)
            if case is not None:
                assert self._repair_store is not None
                self._repair_store.save_attempt(
                    RepairAttemptRecord(
                        case.case_id,
                        max(1, case.attempt_count),
                        RepairAttemptState.PERMISSION_REQUIRED.value,
                        None,
                        attempt.detail,
                        attempt.started_at,
                        self._now(),
                    )
                )
            return self._result(
                problem,
                DoctorStatus.PERMISSION_REQUIRED,
                playbook.owner,
                signature,
                probe_results,
                attempts,
                None,
                candidate,
                "Repair remains paused pending exact permission approval",
                case_id=None if case is None else case.case_id,
            )

        for number in range(1, self._max_attempts + 1):
            if case is not None:
                case = self._case_update(
                    case,
                    status=RepairCaseStatus.EFFECT_IN_PROGRESS,
                    attempt_count=number,
                    selected_action=action.action_id,
                )
                assert self._repair_store is not None
                self._repair_store.save_attempt(
                    RepairAttemptRecord(
                        case.case_id,
                        number,
                        RepairAttemptState.APPLYING.value,
                        None,
                        "Effect execution started; no trusted terminal receipt exists",
                        self._now(),
                    )
                )
            try:
                raw_execution = await self._invoke(callback, problem, action)
                if not isinstance(raw_execution, RepairExecution):
                    raise ComponentDoctorError("Repair callback returned malformed result")
                execution = raw_execution
            except Exception:
                execution = RepairExecution(
                    RepairEffectOutcome.UNKNOWN_OUTCOME,
                    False,
                    "Repair callback failed after effect execution began",
                )
            state = (
                RepairAttemptState.UNKNOWN_OUTCOME
                if execution.outcome is RepairEffectOutcome.UNKNOWN_OUTCOME
                else RepairAttemptState.VERIFICATION_PENDING
                if execution.outcome is RepairEffectOutcome.EFFECT_CONFIRMED
                else RepairAttemptState.FAILED
            )
            attempts.append(
                self._attempt(
                    problem,
                    action,
                    number,
                    state,
                    execution.outcome,
                    execution.detail,
                    execution.evidence,
                )
            )
            verification_reference: str | None = None
            if execution.outcome is RepairEffectOutcome.EFFECT_CONFIRMED:
                if case is not None:
                    case = self._case_update(
                        case,
                        status=RepairCaseStatus.VERIFICATION_PENDING,
                        effect_outcome=execution.outcome.value,
                        selected_action=action.action_id,
                    )
                    assert self._repair_store is not None
                    self._repair_store.save_attempt(
                        RepairAttemptRecord(
                            case.case_id,
                            number,
                            RepairAttemptState.VERIFICATION_PENDING.value,
                            execution.outcome.value,
                            execution.detail,
                            attempts[-1].started_at,
                            self._now(),
                        )
                    )
                independently_verified, verification_reference = await self._verify_after_repair(
                    problem,
                    action,
                    execution,
                    probe_results,
                    playbook,
                    durable=case is not None and self._repair_authorizer is not None,
                )
                if independently_verified:
                    state = RepairAttemptState.VERIFIED
                    attempts[-1] = self._attempt(
                        problem,
                        action,
                        number,
                        state,
                        execution.outcome,
                        execution.detail,
                        execution.evidence,
                    )
                else:
                    state = RepairAttemptState.FAILED
                    attempts[-1] = self._attempt(
                        problem,
                        action,
                        number,
                        state,
                        execution.outcome,
                        "Independent post-repair verification failed",
                        execution.evidence,
                    )
            if case is not None:
                assert self._repair_store is not None
                self._repair_store.save_attempt(
                    RepairAttemptRecord(
                        case.case_id,
                        number,
                        state.value,
                        execution.outcome.value,
                        execution.detail,
                        attempts[-1].started_at,
                        self._now(),
                        verification_reference,
                    )
                )
            if state is RepairAttemptState.VERIFIED:
                if case is not None:
                    case = self._case_update(
                        case,
                        status=RepairCaseStatus.VERIFIED_REPAIRED,
                        effect_outcome=execution.outcome.value,
                        verification_reference=verification_reference or "trusted-probe",
                        terminal_reason="Independent post-repair verification passed",
                    )
                    case = await self._observe_terminal(case)
                await self._safe_health(problem, HealthStatus.HEALTHY, "Repair verified")
                return self._result(
                    problem,
                    DoctorStatus.REPAIRED,
                    playbook.owner,
                    signature,
                    probe_results,
                    attempts,
                    None,
                    candidate,
                    execution.detail,
                    case_id=None if case is None else case.case_id,
                )
            if state is RepairAttemptState.UNKNOWN_OUTCOME:
                if case is not None:
                    case = self._case_update(
                        case,
                        status=RepairCaseStatus.QUARANTINED,
                        effect_outcome=execution.outcome.value,
                        terminal_reason="Trusted terminal effect outcome is unknown",
                    )
                    case = await self._observe_terminal(case)
                await self._safe_health(
                    problem, HealthStatus.QUARANTINED, "Repair outcome is unknown"
                )
                return self._result(
                    problem,
                    DoctorStatus.QUARANTINED,
                    playbook.owner,
                    signature,
                    probe_results,
                    attempts,
                    None,
                    candidate,
                    "Unknown repair outcome is not replayed",
                    case_id=None if case is None else case.case_id,
                )
            if execution.outcome not in {
                RepairEffectOutcome.PRE_EFFECT_FAILURE,
                RepairEffectOutcome.SAFE_TO_RETRY,
            }:
                break

        result = await self._degrade_or_fallback(
            problem,
            playbook,
            signature,
            probe_results,
            attempts,
            "Repair did not verify successfully",
            candidate,
            case=case,
        )
        return result

    diagnose = run

    async def _run_probes(
        self, playbook: RepairPlaybook, problem: ComponentProblem
    ) -> tuple[DiagnosticProbeResult, ...]:
        results: list[DiagnosticProbeResult] = []
        for probe in playbook.probes:
            callback = self._probes.get((playbook.component_id, probe.probe_id))
            if callback is None:
                continue
            try:
                result = await self._invoke(callback, problem)
                if not isinstance(result, DiagnosticProbeResult):
                    raise ComponentDoctorError("Probe callback returned malformed result")
            except Exception:
                result = DiagnosticProbeResult(probe.probe_id, False, "Diagnostic probe failed")
            results.append(result)
        return tuple(results)

    async def _verify_after_repair(
        self,
        problem: ComponentProblem,
        action: RepairAction,
        execution: RepairExecution,
        _initial_probes: tuple[DiagnosticProbeResult, ...],
        playbook: RepairPlaybook,
        *,
        durable: bool = False,
    ) -> tuple[bool, str | None]:
        verifier = self._verifiers.get((problem.component_id, action.action_id), self._verifier)
        if verifier is not None:
            try:
                result = await self._invoke(verifier, problem, action, execution)
            except Exception:
                return False, "independent-verification-error"
            if isinstance(result, VerificationResult):
                passed = (
                    result.passed
                    and not result.contradictions
                    and not result.stale_evidence
                    and not result.rejected_model_claims
                )
                return passed, f"verification:{result.disposition.value}"
            if type(result) is bool and not durable:
                return result, "independent-verifier"
            if type(result) is str and result.strip() and not durable:
                return True, result.strip()[:256]
            return False, "independent-verification-malformed"

        # Compatibility for the pre-F doctor contract: a read-only probe is
        # trusted observation, but a passing pre-effect probe is not allowed to
        # rescue a failed observation.  New composed repairs bind an explicit
        # verifier (or rerun a previously failing probe) and receive a durable
        # verification reference.
        refreshed = await self._run_probes(playbook, problem)
        return bool(refreshed) and all(item.passed for item in refreshed), "fresh-probe"

    async def _resume_verification(
        self, problem: ComponentProblem, playbook: RepairPlaybook, case: RepairCase
    ) -> DoctorResult:
        """Complete durable verification after restart without replaying effects."""

        if case.selected_action is None:
            case = self._case_update(
                case,
                status=RepairCaseStatus.QUARANTINED,
                effect_outcome=RepairEffectOutcome.UNKNOWN_OUTCOME.value,
                terminal_reason="Verification-pending case has no selected action",
            )
            case = await self._observe_terminal(case)
            return self._result_for_existing_case(problem, case)
        action = self._declared_action(playbook, case.selected_action)
        execution = RepairExecution(
            RepairEffectOutcome.EFFECT_CONFIRMED,
            True,
            "Resuming durable verification after restart",
        )
        passed, reference = await self._verify_after_repair(
            problem, action, execution, (), playbook, durable=True
        )
        number = max(1, case.attempt_count)
        state = RepairAttemptState.VERIFIED if passed else RepairAttemptState.FAILED
        attempt = self._attempt(
            problem,
            action,
            number,
            state,
            execution.outcome,
            "Durable post-repair verification passed"
            if passed
            else "Durable post-repair verification failed",
        )
        if self._repair_store is not None:
            self._repair_store.save_attempt(
                RepairAttemptRecord(
                    case.case_id,
                    number,
                    state.value,
                    execution.outcome.value,
                    attempt.detail,
                    attempt.started_at,
                    self._now(),
                    reference,
                )
            )
        if passed:
            case = self._case_update(
                case,
                status=RepairCaseStatus.VERIFIED_REPAIRED,
                effect_outcome=execution.outcome.value,
                verification_reference=reference or "fresh-probe",
                terminal_reason="Independent post-repair verification passed after restart",
            )
            case = await self._observe_terminal(case)
            await self._safe_health(problem, HealthStatus.HEALTHY, "Repair verified after restart")
            status, detail = DoctorStatus.REPAIRED, attempt.detail
        else:
            case = self._case_update(
                case,
                status=RepairCaseStatus.FAILED,
                effect_outcome=execution.outcome.value,
                verification_reference=reference,
                terminal_reason="Independent post-repair verification failed after restart",
            )
            case = await self._observe_terminal(case)
            detail = case.terminal_reason or "Repair verification failed"
            await self._safe_health(problem, HealthStatus.UNAVAILABLE, detail)
            status = DoctorStatus.FAILED
        return self._result(
            problem,
            status,
            playbook.owner,
            None,
            (),
            (attempt,),
            None,
            None,
            detail,
            case_id=case.case_id,
        )

    def _case_update(self, case: RepairCase, **changes: object) -> RepairCase:
        if self._repair_store is None:
            return case
        updated = cast(
            RepairCase,
            replace(cast(Any, case), **changes, updated_at=self._now()),
        )
        return self._repair_store.save_case(updated)

    def _result_for_existing_case(
        self, problem: ComponentProblem, case: RepairCase
    ) -> DoctorResult:
        status = {
            RepairCaseStatus.VERIFIED_REPAIRED: DoctorStatus.REPAIRED,
            RepairCaseStatus.DEGRADED_FALLBACK: DoctorStatus.DEGRADED,
            RepairCaseStatus.QUARANTINED: DoctorStatus.QUARANTINED,
            RepairCaseStatus.PERMISSION_REQUIRED: DoctorStatus.PERMISSION_REQUIRED,
            RepairCaseStatus.FAILED: DoctorStatus.FAILED,
        }.get(case.status, DoctorStatus.QUARANTINED)
        owner = next(
            (
                playbook.owner
                for playbook in self._playbooks.values()
                if playbook.component_id == problem.component_id
            ),
            problem.owner,
        )
        return self._result(
            problem,
            status,
            owner,
            None,
            (),
            (),
            None,
            None,
            case.terminal_reason or "An active or quarantined repair case already exists",
            case_id=case.case_id,
        )

    def close(self) -> None:
        if self._repair_store is not None:
            self._repair_store.close()

    def repair_from_health(
        self,
        capability_id: str,
        _provider: object,
        authorize: Callable[[RepairAction], bool] | None,
    ) -> RepairResult:
        """Synchronous compatibility adapter into this canonical doctor.

        The health service supplies observations; it does not execute its old
        provider contract after this adapter is bound by the composition root.
        """

        report = self._health.drift(capability_id)
        if report is None or not report.findings:
            raise ComponentDoctorError("No drift evidence is available for repair")
        owner = self.owner_for(capability_id)
        problem = ComponentProblem(
            capability_id,
            f"Trusted behavior drift: {report.classification.value}",
            owner,
            failure_code=report.classification.value,
            health_status=self._health.health(capability_id).status,
            source="health",
            trusted=True,
            evidence=tuple(finding.detail for finding in report.findings[:8]),
            occurred_at=report.observation.observed_at,
            failure_observation_id=str(report.findings[0].finding_id),
        )

        def approved(item: ComponentProblem, action: RepairAction) -> bool:
            return authorize(action) if authorize is not None else False

        previous = self._authorize
        self._authorize = approved
        try:
            try:
                result = asyncio.get_running_loop()
            except RuntimeError:
                result = None
            if result is not None and result.is_running():
                raise ComponentDoctorError(
                    "Synchronous health repair cannot run inside an event loop"
                )
            doctor_result = asyncio.run(self.run(problem))
        finally:
            self._authorize = previous
        if doctor_result.status is DoctorStatus.REPAIRED:
            outcome, stage = RepairOutcome.COMPLETED, RepairStage.COMPLETED
        elif doctor_result.status is DoctorStatus.PERMISSION_REQUIRED:
            outcome, stage = RepairOutcome.AUTHORITY_REQUIRED, RepairStage.AUTHORITY
        else:
            outcome, stage = RepairOutcome.FAILED, RepairStage.FAILED
        return RepairResult(
            uuid4(),
            capability_id,
            outcome,
            stage,
            (RepairStage.DETECT, RepairStage.EVIDENCE, RepairStage.DIAGNOSE, stage),
            doctor_result.detail,
            self._health.health(capability_id),
        )

    async def _research_for(self, problem: ComponentProblem) -> RepairCandidate | None:
        if self._research is None or not problem.trusted:
            return None
        try:
            candidate = await self._invoke(self._research, problem)
        except Exception:
            return None
        if candidate is not None and not isinstance(candidate, RepairCandidate):
            return None
        return candidate

    async def _degrade_or_fallback(
        self,
        problem: ComponentProblem,
        playbook: RepairPlaybook,
        signature: FailureSignature | None,
        probes: tuple[DiagnosticProbeResult, ...],
        attempts: tuple[RepairAttempt, ...] | list[RepairAttempt],
        detail: str,
        candidate: RepairCandidate | None = None,
        case: RepairCase | None = None,
    ) -> DoctorResult:
        attempts = list(attempts)
        for fallback_id in playbook.fallback_strategy:
            binding = self._fallbacks.get((problem.component_id, fallback_id))
            if binding is None:
                continue
            option, callback = binding
            if option.requires_approval and not await self._authorized_fallback(
                problem, option, case
            ):
                if case is not None:
                    case = self._case_update(
                        case,
                        status=RepairCaseStatus.PERMISSION_REQUIRED,
                        fallback=option.option_id,
                        terminal_reason="Fallback requires fresh exact approval",
                    )
                return self._result(
                    problem,
                    DoctorStatus.PERMISSION_REQUIRED,
                    playbook.owner,
                    signature,
                    probes,
                    tuple(attempts),
                    None,
                    candidate,
                    "Fallback requires fresh trusted approval",
                    case_id=None if case is None else case.case_id,
                )
            number = 1 if case is None else min(3, max(1, case.attempt_count + 1))
            if case is not None:
                case = self._case_update(
                    case,
                    status=RepairCaseStatus.EFFECT_IN_PROGRESS,
                    attempt_count=number,
                    selected_action=option.option_id,
                    fallback=option.option_id,
                )
                assert self._repair_store is not None
                self._repair_store.save_attempt(
                    RepairAttemptRecord(
                        case.case_id,
                        number,
                        RepairAttemptState.APPLYING.value,
                        None,
                        "Fallback execution started; no trusted terminal receipt exists",
                        self._now(),
                    )
                )
            try:
                raw_execution = await self._invoke(callback, problem)
                if not isinstance(raw_execution, RepairExecution):
                    raise ComponentDoctorError("Fallback callback returned malformed result")
                execution = raw_execution
            except Exception:
                execution = RepairExecution(
                    RepairEffectOutcome.UNKNOWN_OUTCOME,
                    False,
                    "Fallback callback failed after effect execution began",
                )
            state = (
                RepairAttemptState.VERIFIED
                if execution.outcome is RepairEffectOutcome.EFFECT_CONFIRMED and execution.verified
                else RepairAttemptState.UNKNOWN_OUTCOME
                if execution.outcome is RepairEffectOutcome.UNKNOWN_OUTCOME
                else RepairAttemptState.FAILED
            )
            fallback_attempt = self._attempt(
                problem,
                RepairAction(option.option_id, option.description),
                number,
                state,
                execution.outcome,
                execution.detail,
                execution.evidence,
            )
            if case is not None:
                assert self._repair_store is not None
                self._repair_store.save_attempt(
                    RepairAttemptRecord(
                        case.case_id,
                        number,
                        state.value,
                        execution.outcome.value,
                        execution.detail,
                        fallback_attempt.started_at,
                        self._now(),
                    )
                )
            attempts.append(fallback_attempt)
            if state is RepairAttemptState.UNKNOWN_OUTCOME:
                if case is not None:
                    case = self._case_update(
                        case,
                        status=RepairCaseStatus.QUARANTINED,
                        effect_outcome=execution.outcome.value,
                        terminal_reason="Fallback effect outcome is unknown",
                    )
                    case = await self._observe_terminal(case)
                await self._safe_health(
                    problem,
                    HealthStatus.QUARANTINED,
                    "Fallback outcome is unknown",
                )
                return self._result(
                    problem,
                    DoctorStatus.QUARANTINED,
                    playbook.owner,
                    signature,
                    probes,
                    tuple(attempts),
                    None,
                    candidate,
                    "Unknown fallback outcome is not replayed",
                    case_id=None if case is None else case.case_id,
                )
            if state is RepairAttemptState.VERIFIED:
                if case is not None:
                    case = self._case_update(
                        case,
                        status=RepairCaseStatus.DEGRADED_FALLBACK,
                        effect_outcome=execution.outcome.value,
                        verification_reference=f"fallback:{option.option_id}",
                        fallback=option.option_id,
                        terminal_reason="Safe fallback applied",
                    )
                    case = await self._observe_terminal(case)
                await self._safe_health(problem, HealthStatus.DEGRADED, option.description)
                return self._result(
                    problem,
                    DoctorStatus.DEGRADED,
                    playbook.owner,
                    signature,
                    probes,
                    tuple(attempts),
                    option.option_id,
                    candidate,
                    f"Degraded to safe fallback: {option.description}",
                    case_id=None if case is None else case.case_id,
                )
            # A pre-effect failure is safe to abandon, but the same fallback
            # callback is never replayed after an ambiguous or malformed result.
            if execution.outcome not in {
                RepairEffectOutcome.PRE_EFFECT_FAILURE,
                RepairEffectOutcome.SAFE_TO_RETRY,
            }:
                break
        if case is not None:
            case = self._case_update(
                case,
                status=RepairCaseStatus.FAILED,
                terminal_reason=detail,
            )
            case = await self._observe_terminal(case)
        await self._safe_health(problem, HealthStatus.UNAVAILABLE, detail)
        return self._result(
            problem,
            DoctorStatus.FAILED,
            playbook.owner,
            signature,
            probes,
            tuple(attempts),
            None,
            candidate,
            detail,
            case_id=None if case is None else case.case_id,
        )

    async def _authorized(
        self, problem: ComponentProblem, action: RepairAction, case: RepairCase | None = None
    ) -> bool:
        if self._repair_authorizer is not None:
            if case is None:
                return False
            try:
                result = await self._invoke(self._repair_authorizer, problem, action, case.case_id)
            except Exception:
                return False
            return type(result) is bool and result
        if self._authorize is None:
            return False
        try:
            result = await self._invoke(self._authorize, problem, action)
        except Exception:
            return False
        return type(result) is bool and result

    async def _authorized_fallback(
        self, problem: ComponentProblem, option: FallbackOption, case: RepairCase | None = None
    ) -> bool:
        if self._authorize is None and self._repair_authorizer is None:
            return False
        synthetic = RepairAction(option.option_id, option.description)
        return await self._authorized(problem, synthetic, case)

    async def _observe_terminal(self, case: RepairCase) -> RepairCase:
        if self._repair_observer is not None and case.status in {
            RepairCaseStatus.VERIFIED_REPAIRED,
            RepairCaseStatus.DEGRADED_FALLBACK,
            RepairCaseStatus.FAILED,
            RepairCaseStatus.QUARANTINED,
        }:
            try:
                await self._invoke(self._repair_observer, case)
            except Exception:
                pass
        return case

    async def _safe_health(
        self, problem: ComponentProblem, status: HealthStatus, detail: str
    ) -> None:
        try:
            self._health.record_status(
                problem.component_id,
                status,
                detail,
                evidence=problem.evidence,
            )
        except Exception:
            # Diagnostics must not turn a component crash into an assistant crash.
            return

    async def _invoke(self, callback: Callable[..., object], *args: object) -> object:
        result = callback(*args)
        if inspect.isawaitable(result):
            return await result
        return result

    def _attempt(
        self,
        problem: ComponentProblem,
        action: RepairAction,
        number: int,
        state: RepairAttemptState,
        outcome: RepairEffectOutcome | None,
        detail: str,
        verification: tuple[str, ...] = (),
    ) -> RepairAttempt:
        now = self._now()
        attempt = RepairAttempt(
            uuid4(),
            problem.component_id,
            action.action_id,
            number,
            state,
            outcome,
            detail,
            verification,
            now,
            now,
        )
        self._trace.append(
            TraceEvent(
                trace_id=self._trace.trace_id,
                event_type=TraceEventType.REPAIR,
                source="component_doctor",
                summary=f"Repair {action.action_id}: {state.value}",
                occurred_at=now,
                result={
                    "component": problem.component_id,
                    "outcome": outcome.value if outcome else None,
                },
            )
        )
        return attempt

    def _result(
        self,
        problem: ComponentProblem,
        status: DoctorStatus,
        owner: DiagnosticOwner,
        signature: FailureSignature | None,
        probes: tuple[DiagnosticProbeResult, ...],
        attempts: Iterable[RepairAttempt],
        fallback_id: str | None,
        research: RepairCandidate | None,
        detail: str,
        *,
        case_id: UUID | None = None,
    ) -> DoctorResult:
        result = DoctorResult(
            problem,
            status,
            owner,
            signature,
            probes,
            tuple(attempts),
            fallback_id,
            research,
            detail,
            case_id,
        )
        self._trace.append(
            TraceEvent(
                trace_id=self._trace.trace_id,
                event_type=TraceEventType.DIAGNOSTIC,
                source="component_doctor",
                summary=f"Diagnostic {problem.component_id}: {status.value}",
                occurred_at=self._now(),
                result={"owner": owner.value, "status": status.value, "fallback": fallback_id},
            )
        )
        return result

    def _playbook(self, component_id: str) -> RepairPlaybook:
        component_id = _text(component_id, "Component ID", 256)
        try:
            return self._playbooks[component_id]
        except KeyError as error:
            raise ComponentDoctorError("Component has no repair playbook") from error

    @staticmethod
    def _declared_probe(playbook: RepairPlaybook, probe_id: str) -> DiagnosticProbe:
        for probe in playbook.probes:
            if probe.probe_id == probe_id:
                return probe
        raise ComponentDoctorError("Probe is not declared by the component owner")

    @staticmethod
    def _declared_action(playbook: RepairPlaybook, action_id: str) -> RepairAction:
        for action in playbook.actions:
            if action.action_id == action_id:
                return action
        raise ComponentDoctorError("Repair action is not declared by the component owner")

    @staticmethod
    def _match_signature(
        playbook: RepairPlaybook, problem: ComponentProblem
    ) -> FailureSignature | None:
        haystack = " ".join((problem.failure_code or "", problem.summary)).casefold()
        for signature in playbook.failure_signatures:
            if signature.signature.casefold() in haystack:
                return signature
        return None

    @staticmethod
    def _known_action(
        playbook: RepairPlaybook, signature: FailureSignature | None
    ) -> RepairAction | None:
        return playbook.actions[0] if signature is not None and playbook.actions else None

    def _now(self) -> datetime:
        return _time(self._clock(), "Doctor clock")

    async def aclose(self) -> None:
        """No external resources are owned; reserved for composition-root symmetry."""


__all__ = [
    "ComponentDoctor",
    "BrokeredRepairAuthorizer",
    "ComponentDoctorError",
    "ComponentDoctorSecurityError",
    "ComponentOwner",
    "ComponentProblem",
    "DiagnosticOwner",
    "DiagnosticProbe",
    "DiagnosticProbeResult",
    "DoctorResult",
    "DoctorStatus",
    "FailureSignature",
    "FallbackOption",
    "RepairAction",
    "RepairAttempt",
    "RepairAttemptState",
    "RepairCandidate",
    "RepairEffectOutcome",
    "RepairExecution",
    "RepairPlaybook",
    "RepairAttemptRecord",
    "RepairCase",
    "RepairCaseStatus",
    "RepairStoreError",
    "SQLiteRepairStore",
    "RoutedRepairResearch",
    "TroubleshootingOwner",
    "repair_case_key",
]
