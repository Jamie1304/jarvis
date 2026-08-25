"""Canonical production composition root for one bounded JARVIS runtime."""

from __future__ import annotations

import asyncio
import inspect
import re
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx

from jarvis.adoption import (
    AdoptionIdentityInspector,
    AdoptionPolicy,
    LocalDependencyProvenanceProvider,
    WindowsFileIdentityProvider,
    WindowsSignerVerifier,
)
from jarvis.agent_runtime import AgentLoop
from jarvis.ai.model_manager import LocalModelManager
from jarvis.ai.providers.base import AIProvider
from jarvis.ai.routing import ProviderRouter
from jarvis.ai.sessions import AgentSessionStore
from jarvis.artifacts import ArtifactStore
from jarvis.attention import AttentionItem, AttentionPolicy, AttentionPriority, SQLiteAttentionStore
from jarvis.automations import AutomationService, AutomationStoreError, SQLiteAutomationStore
from jarvis.backup import BackupService
from jarvis.bootstrap import create_provider_registry
from jarvis.browser import BrowserAdapter, BrowserSemanticBridge
from jarvis.browser_broker import (
    BrowserBrokerAdapter,
    BrowserCapabilityStatus,
    BrowserCapabilityUnavailable,
)
from jarvis.capabilities import CapabilityManifest, CapabilityRegistry, EnvironmentGraph
from jarvis.capability_acquisition import (
    AcquisitionScope,
    AcquisitionStage,
    ActivationRequestProvider,
    CapabilityAcquisitionCoordinator,
    CapabilityAcquisitionError,
    CapabilityAcquisitionServices,
    CapabilityManifestProvider,
    CertificationHookProvider,
    PackageSourceProvider,
    SolutionDiscovery,
    VerificationEvidenceProvider,
)
from jarvis.capability_factory import (
    CapabilityFactory,
    CapabilityGenerator,
    FactoryStrategy,
    GeneratedCapabilityPackage,
    SolutionReport,
    WorkspaceContext,
)
from jarvis.capability_health import AttentionNotice, CapabilityHealthService, HealthStatus
from jarvis.capability_lifecycle import (
    SQLiteCapabilityLifecycleStore,
    StoredLifecycleRecord,
)
from jarvis.capability_opportunities import (
    CapabilityOpportunity,
    CapabilityOpportunityEngine,
    OpportunityPreparationResult,
    OpportunityPreparationState,
    SQLiteOpportunityStore,
)
from jarvis.component_doctor import ComponentDoctor
from jarvis.control_center import (
    ControlCenterContribution,
    ControlCenterItem,
    ControlCenterSection,
    ControlCenterService,
    ControlCenterStatus,
    SemanticActionMetadata,
    static_provider,
)
from jarvis.conversation.service import ConversationService
from jarvis.core.config import Settings, get_settings
from jarvis.core.errors import ConfigurationError
from jarvis.core.logging import configure_logging
from jarvis.credentials import (
    CredentialBroker,
    CredentialVault,
    SecretBackend,
    TestOnlyInMemorySecretBackend,
    WindowsCredentialManagerBackend,
)
from jarvis.desktop_shell import (
    LaunchProfileRegistry,
    StartupWarmupRegistry,
    TestDriveRegistry,
    TestDriveStatus,
    TestDriveStep,
    TestDriveStepResult,
    WarmupComponent,
)
from jarvis.discovery.models import CapabilityGap
from jarvis.discovery.providers import InternalToolCatalogProvider
from jarvis.discovery.service import (
    CandidateEvaluator,
    CapabilityDiscoveryService,
    CapabilityGapDetector,
)
from jarvis.effect_attestation import EffectAttestationStore, TrustedEffectObserver
from jarvis.effects import (
    CompensationObservationProvider,
    CompensationService,
    CompensationStateProvider,
    CompensationStore,
)
from jarvis.environment_discovery import (
    EnvironmentDiscoveryProvider,
    EnvironmentDiscoveryService,
)
from jarvis.events import EventBus, InMemoryEventBus
from jarvis.goal_supervisor import (
    GoalAnalysis,
    GoalIntent,
    GoalSupervisor,
    GoalSupervisorStore,
    PlanningGoalTaskRunner,
    RegistryGoalAnalyzer,
)
from jarvis.integration_package import IntegrationPackage
from jarvis.knowledge import KnowledgeLibrary, KnowledgeLibraryMigrationError
from jarvis.knowledge.store import KnowledgeStore
from jarvis.mcp.manager import MCPExtensionManager
from jarvis.memory.control import MemoryControlService
from jarvis.memory.services import (
    ConversationContextService,
    EpisodicMemoryService,
    LongTermMemoryService,
    MemoryConsistencyService,
    MemoryRetrievalService,
    ProjectSystemMemory,
)
from jarvis.memory.store import MemoryMigrationError, SQLiteMemoryStore
from jarvis.multi_agent.registry import AgentRegistry
from jarvis.package_activation import (
    ActivationHooks,
    ActivationRequest,
    ActivationState,
    CanaryExecution,
    CanaryLimits,
    PackageActivationService,
    ShadowExecution,
)
from jarvis.package_certification import PackageCertifier
from jarvis.package_reviewer import GeneratedPackageReviewer
from jarvis.package_runtime import (
    HotLoadError,
    HotLoadManager,
    PackageRegistrationSurface,
    PackageRuntimeFactory,
    PreparedPackageRuntime,
)
from jarvis.permissions import (
    AuditStoreError,
    PermissionBroker,
    PolicyEngine,
    SQLiteAuditSink,
)
from jarvis.permissions.models import Permission, Risk
from jarvis.planning.engine import (
    BrokeredPlanningStepExecutor,
    CompletionCriteriaVerifier,
    EvidencePlanningStepVerifier,
    PlanAdvisor,
    PlanningEngine,
    task_state_for_status,
)
from jarvis.planning.models import ReplanEvidence
from jarvis.planning.store import PlanningStoreError, SQLitePlanningStore
from jarvis.planning.validation import PlanValidator
from jarvis.presence import PresenceProjection
from jarvis.presentation import PresentationSurface
from jarvis.provisioning import (
    BrokerProvisioningAuthorizer,
    ProvisioningApplyResult,
    ProvisioningAuthorization,
    ProvisioningEffectOutcome,
    ProvisioningEngine,
    ProvisioningError,
    ProvisioningObservation,
    ProvisioningProvider,
    SQLiteProvisioningStore,
)
from jarvis.recovery import (
    RecoveryCoordinator,
    RecoveryError,
    RecoveryEvidence,
    RecoveryPhase,
    RecoveryStore,
    TrustedRecoveryAuthority,
    compute_application_build_hash,
)
from jarvis.resources import ResourceGovernor, SystemResourceTelemetry
from jarvis.sandbox_proxies import HostProxy, HostProxyAudit, HostProxyManifest
from jarvis.security import (
    SECURITY_POLICY_VERSION,
    SecurityViolation,
    SecurityViolationCode,
    StartupSecurityConfiguration,
    StartupSecurityReport,
    StartupSecurityValidator,
)
from jarvis.setup_conductor import (
    DecisionCollector,
    SetupConductor,
    SetupHandler,
    SetupInspection,
    SQLiteSetupStore,
)
from jarvis.skills import SkillRegistry
from jarvis.state import ApplicationStateMachine, SQLiteStateStore, StateStoreError
from jarvis.task_controller import PlanningTaskController, TaskController
from jarvis.testing.golden import GoldenWorkflowError, GoldenWorkflowService, GoldenWorkflowStore
from jarvis.tools.base import Tool
from jarvis.tools.calculator import CalculatorTool
from jarvis.tools.local_time import LocalTimeTool
from jarvis.tools.registry import ToolRegistry
from jarvis.tools.weather import UnavailableWeatherTool
from jarvis.trace import TraceError, TraceService, TraceStore
from jarvis.ui_simulation import UISimulationHarness
from jarvis.update_preview import ControlledSelfUpdate
from jarvis.user_model import UserModelMigrationError, UserModelStore
from jarvis.verification import EvidenceRecord, VerificationEngine
from jarvis.windows_sandbox import SandboxSecurityStatus
from jarvis.workflows import (
    ProcedureBank,
    ProcedureEvidenceAuthority,
    SQLiteWorkflowProcedureStore,
    WorkflowProcedureStoreError,
    WorkflowTemplateRegistry,
)


class _UnavailableCapabilityGenerator:
    """Safe default: generation needs an explicitly configured trusted service."""

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
        raise CapabilityAcquisitionError("Capability generation is not configured")


class _OpportunityResearchPreparation:
    """Safe default preparation: discovery/research only, never activation."""

    def __init__(self, coordinator: CapabilityAcquisitionCoordinator) -> None:
        self._coordinator = coordinator

    async def prepare(self, opportunity: CapabilityOpportunity) -> OpportunityPreparationResult:
        gap = CapabilityGap(
            opportunity.semantic_need,
            opportunity.semantic_need,
            (opportunity.semantic_need,),
            (),
            Risk.MEDIUM,
            (),
        )
        research = await self._coordinator.research(
            GoalIntent(
                opportunity.semantic_need,
                required_capabilities=(opportunity.semantic_need,),
                metadata={"opportunity_id": str(opportunity.opportunity_id)},
            ),
            GoalAnalysis(gap),
        )
        return OpportunityPreparationResult(
            OpportunityPreparationState.READY,
            "Read-only capability research and discovery completed",
            opportunity.likely_required_authority,
            tuple(research.evidence),
        )


class _UnavailableProvisioningProvider:
    async def inspect(self, action: object) -> ProvisioningObservation:
        del action
        return ProvisioningObservation(False, evidence="No provisioning provider is configured")

    async def apply(self, action: object, cancellation: asyncio.Event) -> ProvisioningApplyResult:
        del action, cancellation
        return ProvisioningApplyResult(
            ProvisioningEffectOutcome.PRE_EFFECT_FAILURE,
            detail="No provisioning provider is configured",
        )

    async def rollback(
        self, action: object, cancellation: asyncio.Event
    ) -> ProvisioningApplyResult:
        del action, cancellation
        return ProvisioningApplyResult(
            ProvisioningEffectOutcome.PRE_EFFECT_FAILURE,
            detail="No provisioning provider is configured",
        )

    async def health_check(self, action: object) -> bool:
        del action
        return False


class _UnavailableSetupHandler:
    async def inspect(self, step: object, context: object) -> SetupInspection:
        del step, context
        return SetupInspection(detail="No setup handler is configured")

    async def prepare(self, step: object, context: object, decision: object) -> None:
        del step, context, decision
        return None

    async def configure(self, step: object, context: object) -> None:
        del step, context

    async def verify(self, step: object, context: object) -> bool:
        del step, context
        return False

    async def first_start(self, step: object, context: object) -> bool:
        del step, context
        return False


class _UnavailablePackageRuntimeFactory:
    def prepare(self, package: IntegrationPackage) -> PreparedPackageRuntime:
        del package
        raise HotLoadError("Package runtime is not configured")


class _UnavailablePackageRegistrationSurface:
    def atomic_swap(self, package: IntegrationPackage, runtime: PreparedPackageRuntime) -> None:
        del package, runtime
        raise HotLoadError("Package registration is not configured")

    def rollback(self, package: IntegrationPackage, runtime: PreparedPackageRuntime | None) -> None:
        del package, runtime

    def remove(self, package: IntegrationPackage, runtime: PreparedPackageRuntime) -> None:
        del package, runtime


class RuntimeStatus(StrEnum):
    STARTING = "starting"
    READY = "ready"
    ERROR = "error"
    SAFE_MODE = "safe_mode"
    STOPPED = "stopped"


class RuntimeServiceAvailability(StrEnum):
    """Application-visible health for optional runtime capabilities."""

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class RuntimeServiceStatus:
    """Bounded health view; it never grants capability or permission."""

    service_id: str
    availability: RuntimeServiceAvailability
    detail: str


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    root: Path
    state_database: Path
    planning_database: Path
    memory_database: Path
    user_model_database: Path
    knowledge_library_database: Path
    automation_database: Path
    trace_database: Path
    golden_workflow_database: Path
    workflow_procedure_database: Path
    sessions_database: Path
    goal_supervisor_database: Path
    setup_database: Path
    provisioning_database: Path
    effect_attestation_database: Path
    compensation_database: Path
    capability_lifecycle_database: Path
    opportunity_database: Path
    attention_database: Path
    credential_database: Path
    audit_database: Path
    artifacts: Path
    logs: Path
    config: Path
    cache: Path
    temporary: Path
    models: Path
    recovery: Path
    backups: Path

    @classmethod
    def from_root(cls, root: Path) -> RuntimePaths:
        base = root.expanduser().resolve()
        return cls(
            base,
            base / "state.sqlite3",
            base / "planning.sqlite3",
            base / "memory.sqlite3",
            base / "user-model.sqlite3",
            base / "knowledge-library.sqlite3",
            base / "automations.sqlite3",
            base / "trace.sqlite3",
            base / "golden-workflows.sqlite3",
            base / "workflow-procedures.sqlite3",
            base / "sessions.sqlite3",
            base / "goals.sqlite3",
            base / "setup.sqlite3",
            base / "provisioning.sqlite3",
            base / "effect-attestations.sqlite3",
            base / "compensation.sqlite3",
            base / "capability-lifecycle.sqlite3",
            base / "opportunities.sqlite3",
            base / "attention.sqlite3",
            base / "credentials.sqlite3",
            base / "audit.sqlite3",
            base / "artifacts",
            base / "logs",
            base / "config",
            base / "cache",
            base / "tmp",
            base / "models",
            base / "recovery",
            base / "backups",
        )

    def ensure_directories(self) -> None:
        self.validate_storage_layout()
        for path in (
            self.root,
            self.logs,
            self.config,
            self.cache,
            self.temporary,
            self.models,
            self.recovery,
            self.backups,
            self.artifacts,
        ):
            path.mkdir(parents=True, exist_ok=True)
        self.validate_storage_layout()

    def validate_storage_layout(self) -> None:
        """Reject links, aliases, hard-linked DBs, and child escapes before I/O."""

        canonical_root = self.root.resolve(strict=False)
        if canonical_root != self.root or self.root.is_symlink() or self.root.is_junction():
            raise OSError("Application-data root identity is unsafe")
        directories = (
            self.root,
            self.logs,
            self.config,
            self.cache,
            self.temporary,
            self.models,
            self.recovery,
            self.backups,
        )
        databases = (
            self.state_database,
            self.planning_database,
            self.memory_database,
            self.user_model_database,
            self.knowledge_library_database,
            self.automation_database,
            self.trace_database,
            self.golden_workflow_database,
            self.workflow_procedure_database,
            self.sessions_database,
            self.goal_supervisor_database,
            self.setup_database,
            self.provisioning_database,
            self.effect_attestation_database,
            self.compensation_database,
            self.capability_lifecycle_database,
            self.opportunity_database,
            self.attention_database,
            self.credential_database,
            self.audit_database,
            self.artifacts / "artifacts.sqlite3",
        )
        sidecars = tuple(
            database.with_name(f"{database.name}{suffix}")
            for database in databases
            for suffix in ("-journal", "-shm", "-wal")
        )
        database_files = (*databases, *sidecars)
        for path in (*directories, *database_files):
            if path.is_symlink() or path.is_junction():
                raise OSError("Application-data child uses a reparse point")
            resolved = path.resolve(strict=False)
            try:
                resolved.relative_to(canonical_root)
            except ValueError as error:
                raise OSError("Application-data child escaped its root") from error
            if resolved != path:
                raise OSError("Application-data child identity is ambiguous")
        for path in directories:
            if path.exists() and not path.is_dir():
                raise OSError("Application-data directory path is not a directory")
        for path in database_files:
            if path.exists():
                if not path.is_file() or path.stat().st_nlink > 1:
                    raise OSError("Application database path is not a private regular file")


class SafeBuiltinPlanAdvisor(PlanAdvisor):
    """A deliberately narrow local planner for safe arithmetic defaults.

    It is not a general language-model planner. Unsupported goals fail visibly
    until a separately configured trusted planning provider is introduced.
    """

    _CALCULATE = re.compile(r"^calculate\s+(.+)$", re.IGNORECASE)
    _PERCENT = re.compile(r"^\s*(\d+(?:\.\d+)?)%\s+of\s+(\d+(?:\.\d+)?)\s*$", re.IGNORECASE)

    async def propose(
        self, goal: str, assumptions: tuple[str, ...], constraints: tuple[str, ...]
    ) -> object:
        match = self._CALCULATE.fullmatch(" ".join(goal.split()))
        if match is None:
            raise ValueError("safe builtin planner supports only explicit calculation goals")
        expression = match.group(1)
        percentage = self._PERCENT.fullmatch(expression)
        if percentage is None:
            raise ValueError("safe builtin planner supports only percentage calculations")
        result = Decimal(percentage.group(1)) * Decimal(percentage.group(2)) / Decimal("100")
        normalized_result = format(result.normalize(), "f")
        result_text = (
            normalized_result.rstrip("0").rstrip(".")
            if "." in normalized_result
            else normalized_result
        )
        return {
            "goal": goal,
            "assumptions": list(assumptions),
            "constraints": list(constraints),
            "required_capabilities": ["calculation"],
            "required_permissions": [],
            "completion_criteria": [f"result={result_text}"],
            "steps": [
                {
                    "key": "calculate",
                    "tool_id": "calculator",
                    "capability": "calculation",
                    "input": {"expression": expression},
                    "dependencies": [],
                    "required_permissions": [],
                    "expected_output": "result",
                    "verification_rule": "evidence_contains_all",
                    "expected_evidence": [f"result={result_text}"],
                    "expensive_action": False,
                    "max_retries": 0,
                }
            ],
        }

    async def replan(self, evidence: ReplanEvidence) -> object:
        raise ValueError(f"safe builtin planner cannot replan ({evidence.error.code})")


@dataclass(frozen=True, slots=True)
class RuntimeTestFixture:
    """Trusted deterministic seams used only by the local ``test`` environment.

    The fixture is consumed by :meth:`ApplicationRuntime.create`; it does not
    construct a parallel runtime.  The composition root still owns the
    PermissionBroker, lifecycle store, activation service, registries, and
    coordinator.  Production/local environments reject this seam.
    """

    capability_generator: CapabilityGenerator
    package_runtime_factory: PackageRuntimeFactory
    package_registration_surface: PackageRegistrationSurface
    activation_hooks: Callable[[EffectAttestationStore], ActivationHooks]
    source_provider: PackageSourceProvider
    certification_hooks: CertificationHookProvider
    activation_requests: ActivationRequestProvider
    manifest_provider: CapabilityManifestProvider
    verification_evidence: VerificationEvidenceProvider
    setup_handlers: Mapping[str, SetupHandler] | None = None
    setup_decision_collector: DecisionCollector | None = None
    provisioning_providers: Mapping[str, ProvisioningProvider] | None = None
    provisioning_authorization: ProvisioningAuthorization | None = None
    discovery_providers: tuple[EnvironmentDiscoveryProvider, ...] = ()
    lifecycle_restore: (
        Callable[[StoredLifecycleRecord], tuple[ActivationRequest, CapabilityManifest]] | None
    ) = None
    sandbox_security_status: SandboxSecurityStatus | None = None
    recovery_key_backend: SecretBackend | None = None
    permission_policy: PolicyEngine | None = None
    additional_tools: tuple[Tool[Any, Any], ...] = ()
    compensation_observation_provider: CompensationObservationProvider | None = None
    compensation_state_provider: CompensationStateProvider | None = None


# This backend is reachable only through the explicit ``test`` environment.
# It keeps deterministic restart tests independent of the host credential
# manager while production/local composition always selects the Windows-backed
# implementation below.
_TEST_RECOVERY_BACKEND = TestOnlyInMemorySecretBackend()


@dataclass(frozen=True, slots=True)
class RuntimeContainer:
    """One owner for every enabled service instance and its shutdown lifecycle."""

    settings: Settings
    paths: RuntimePaths
    ai_provider: AIProvider
    resource_governor: ResourceGovernor
    provider_router: ProviderRouter
    model_manager: LocalModelManager
    conversation: ConversationService
    event_bus: EventBus
    state_store: SQLiteStateStore
    state_machine: ApplicationStateMachine
    policy_engine: PolicyEngine
    audit_sink: SQLiteAuditSink
    artifact_store: ArtifactStore
    mcp_manager: MCPExtensionManager
    permission_broker: PermissionBroker
    sandbox_tool_bindings: Mapping[str, tuple[str, object]]
    tool_registry: ToolRegistry
    planning_store: SQLitePlanningStore
    planning_engine: PlanningEngine
    task_controller: TaskController
    memory_store: SQLiteMemoryStore
    user_model_store: UserModelStore
    session_store: AgentSessionStore
    conversation_memory: ConversationContextService
    long_term_memory: LongTermMemoryService
    episodic_memory: EpisodicMemoryService
    memory_consistency: MemoryConsistencyService
    memory_control: MemoryControlService
    memory_retrieval: MemoryRetrievalService
    knowledge_library: KnowledgeLibrary
    knowledge: KnowledgeStore
    system_memory: ProjectSystemMemory
    automation_store: SQLiteAutomationStore
    trace_store: TraceStore
    trace_service: TraceService
    golden_workflow_store: GoldenWorkflowStore
    golden_workflows: GoldenWorkflowService
    workflow_procedure_store: SQLiteWorkflowProcedureStore
    procedure_evidence_authority: ProcedureEvidenceAuthority
    procedure_bank: ProcedureBank
    automation_service: AutomationService
    capability_health: CapabilityHealthService
    component_doctor: ComponentDoctor
    environment_discovery: EnvironmentDiscoveryService
    presence_projection: PresenceProjection
    presentation_surface: PresentationSurface
    compensation_service: CompensationService
    workflow_templates: WorkflowTemplateRegistry
    discovery: CapabilityGapDetector
    capability_gap_detector: CapabilityGapDetector
    candidate_evaluator: CandidateEvaluator
    goal_supervisor_store: GoalSupervisorStore
    goal_supervisor: GoalSupervisor
    solution_discovery: SolutionDiscovery
    capability_factory: CapabilityFactory
    package_reviewer: GeneratedPackageReviewer
    package_certifier: PackageCertifier
    setup_store: SQLiteSetupStore
    setup_conductor: SetupConductor
    adoption_policy: AdoptionPolicy
    provisioning_engine: ProvisioningEngine
    provisioning_store: SQLiteProvisioningStore
    effect_attestation_store: EffectAttestationStore
    capability_lifecycle_store: SQLiteCapabilityLifecycleStore
    opportunity_store: SQLiteOpportunityStore
    opportunity_engine: CapabilityOpportunityEngine
    attention_store: SQLiteAttentionStore
    attention_policy: AttentionPolicy
    package_activation: PackageActivationService
    hot_load: HotLoadManager
    verification_engine: VerificationEngine
    capability_acquisition: CapabilityAcquisitionCoordinator
    backup: BackupService
    recovery: RecoveryStore
    trusted_recovery_authority: TrustedRecoveryAuthority
    controlled_self_update: ControlledSelfUpdate
    credential_vault: CredentialVault
    credential_broker: CredentialBroker
    agent_loop: AgentLoop
    launch_profiles: LaunchProfileRegistry = field(default_factory=LaunchProfileRegistry)
    test_drive: TestDriveRegistry = field(default_factory=TestDriveRegistry)
    startup_warmup: StartupWarmupRegistry = field(default_factory=StartupWarmupRegistry)
    capability_registry: CapabilityRegistry = field(default_factory=CapabilityRegistry)
    skill_registry: SkillRegistry = field(default_factory=SkillRegistry)
    agent_registry: AgentRegistry = field(default_factory=AgentRegistry)
    control_center: ControlCenterService = field(default_factory=ControlCenterService)
    computer: object | None = None
    vision: object | None = None
    browser: BrowserSemanticBridge | None = None
    browser_status: BrowserCapabilityStatus = BrowserCapabilityStatus.UNAVAILABLE
    camera: object | None = None
    application_manager: object | None = None
    voice: object | None = None
    multi_agent: object | None = None
    improvement: object | None = None
    automation_start_task: asyncio.Task[None] | None = None
    presence_start_task: asyncio.Task[None] | None = None
    trace_start_task: asyncio.Task[None] | None = None
    _close_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def service_status(self, service_id: str) -> RuntimeServiceStatus:
        """Return an application-owned availability view for optional services.

        Availability is deliberately separate from authority: an unavailable
        optional capability is never replaced with an uncontrolled fallback.
        """

        if type(service_id) is not str or not service_id.strip():
            raise ValueError("Service ID is malformed")
        if service_id == "voice":
            if self.voice is None:
                return RuntimeServiceStatus(
                    service_id,
                    RuntimeServiceAvailability.UNAVAILABLE,
                    "voice providers are not configured",
                )
            return RuntimeServiceStatus(
                service_id, RuntimeServiceAvailability.AVAILABLE, "voice runtime configured"
            )
        if service_id == "camera":
            if self.camera is None:
                return RuntimeServiceStatus(
                    service_id,
                    RuntimeServiceAvailability.UNAVAILABLE,
                    "camera providers are not configured",
                )
            return RuntimeServiceStatus(
                service_id, RuntimeServiceAvailability.AVAILABLE, "camera runtime configured"
            )
        if service_id == "browser":
            availability = RuntimeServiceAvailability(self.browser_status.value)
            detail = (
                "browser broker configured"
                if self.browser is not None
                else "no supported trusted browser backend"
            )
            return RuntimeServiceStatus(service_id, availability, detail)
        if service_id == "environment_discovery":
            return RuntimeServiceStatus(
                service_id,
                RuntimeServiceAvailability.DEGRADED,
                (
                    "observation service is owned by the runtime; "
                    "no discovery providers are configured"
                ),
            )
        if service_id == "presentation":
            return RuntimeServiceStatus(
                service_id,
                RuntimeServiceAvailability.AVAILABLE,
                "typed presentation surface is configured; physical renderer is optional",
            )
        if service_id == "ui_simulation":
            return RuntimeServiceStatus(
                service_id,
                RuntimeServiceAvailability.AVAILABLE,
                "package-scoped simulation is available through certification services",
            )
        raise KeyError(f"Unknown runtime service: {service_id}")

    def create_host_proxy(
        self,
        manifest: HostProxyManifest,
        *,
        audit: HostProxyAudit | None = None,
        http_client: httpx.AsyncClient | None = None,
        resolver: Callable[[str], Sequence[str]] | None = None,
        forbidden_roots: Sequence[Path] = (),
        effect_observer: TrustedEffectObserver | None = None,
    ) -> HostProxy:
        """Create the only application-owned sandbox host-proxy entry point."""

        return HostProxy(
            manifest,
            self.permission_broker,
            credential_broker=self.credential_broker,
            audit=audit,
            http_client=http_client,
            resolver=resolver,
            forbidden_roots=forbidden_roots,
            effect_observer=effect_observer,
            tool_bindings=self.sandbox_tool_bindings,
        )

    def service_statuses(self) -> tuple[RuntimeServiceStatus, ...]:
        return tuple(
            self.service_status(service_id)
            for service_id in (
                "voice",
                "camera",
                "browser",
                "environment_discovery",
                "presentation",
                "ui_simulation",
            )
        )

    def create_ui_simulation_harness(
        self, package: IntegrationPackage, *, workspace_id: str
    ) -> UISimulationHarness:
        """Create a package-scoped simulator bound to this runtime's ArtifactStore."""

        return UISimulationHarness(
            package,
            artifact_store=self.artifact_store,
            workspace_id=workspace_id,
        )

    async def aclose(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            object.__setattr__(self, "_closed", True)
            if self.automation_start_task is not None:
                self.automation_start_task.cancel()
                await asyncio.gather(self.automation_start_task, return_exceptions=True)
            if self.presence_start_task is not None:
                self.presence_start_task.cancel()
                await asyncio.gather(self.presence_start_task, return_exceptions=True)
            if self.trace_start_task is not None:
                self.trace_start_task.cancel()
                await asyncio.gather(self.trace_start_task, return_exceptions=True)
            resources = (
                self.trace_service,
                self.automation_service,
                self.component_doctor,
                self.capability_health,
                self.presence_projection,
                self.event_bus,
                self.startup_warmup,
                self.control_center,
                self.conversation,
                self.model_manager,
                self.session_store,
                self.goal_supervisor_store,
                self.setup_store,
                self.provisioning_store,
                self.effect_attestation_store,
                self.compensation_service,
                self.capability_lifecycle_store,
                self.opportunity_store,
                self.attention_store,
                self.planning_store,
                self.memory_store,
                self.user_model_store,
                self.knowledge_library,
                self.trace_store,
                self.golden_workflow_store,
                self.workflow_procedure_store,
                self.automation_store,
                self.state_store,
                self.audit_sink,
                self.artifact_store,
                self.mcp_manager,
                self.voice,
                self.camera,
                self.application_manager,
                self.computer,
                self.vision,
                self.browser,
                self.credential_vault,
                self.multi_agent,
                self.improvement,
            )
            closed: set[int] = set()
            first_error: BaseException | None = None
            for resource in resources:
                if resource is None or id(resource) in closed:
                    continue
                closed.add(id(resource))
                try:
                    close = getattr(resource, "aclose", None) or getattr(resource, "close", None)
                    if callable(close):
                        result = close()
                        if inspect.isawaitable(result):
                            await result
                except BaseException as error:
                    if isinstance(error, asyncio.CancelledError):
                        raise
                    if first_error is None:
                        first_error = error
            if first_error is not None:
                raise first_error


class ApplicationRuntime:
    """Deterministic startup/readiness/shutdown owner; no legacy execution path."""

    def __init__(
        self,
        container: RuntimeContainer | None,
        *,
        status: RuntimeStatus = RuntimeStatus.STARTING,
        error: str | None = None,
        security_report: StartupSecurityReport | None = None,
    ) -> None:
        self._container = container
        self._status = status
        self._error = error
        self._security_report = security_report
        self._close_lock = asyncio.Lock()
        self._closed = False

    @property
    def container(self) -> RuntimeContainer | None:
        return self._container

    @property
    def status(self) -> RuntimeStatus:
        return self._status

    @property
    def error(self) -> str | None:
        return self._error

    @property
    def security_report(self) -> StartupSecurityReport | None:
        return self._security_report

    @classmethod
    def create_from_environment(
        cls,
        *,
        project_root: Path | None = None,
        browser_backend: BrowserAdapter | None = None,
        credential_vault: CredentialVault | None = None,
    ) -> ApplicationRuntime:
        """Load explicit process settings and map malformed input to safe mode."""

        try:
            settings = get_settings()
        except Exception:
            report = StartupSecurityReport(
                SECURITY_POLICY_VERSION,
                (
                    SecurityViolation(
                        SecurityViolationCode.CONFIGURATION_INVALID,
                        "Process configuration did not match the trusted schema",
                    ),
                ),
            )
            return cls(
                None,
                status=RuntimeStatus.SAFE_MODE,
                error="security policy rejected startup: configuration_invalid",
                security_report=report,
            )
        return cls.create(
            settings,
            project_root=project_root,
            browser_backend=browser_backend,
            credential_vault=credential_vault,
        )

    @classmethod
    def create(
        cls,
        settings: Settings,
        *,
        project_root: Path | None = None,
        browser_backend: BrowserAdapter | None = None,
        credential_vault: CredentialVault | None = None,
        test_fixture: RuntimeTestFixture | None = None,
    ) -> ApplicationRuntime:
        if test_fixture is not None and settings.environment != "test":
            return cls(
                None,
                status=RuntimeStatus.SAFE_MODE,
                error="deterministic runtime fixtures require the test environment",
            )
        trusted_project_root = project_root or Path(__file__).resolve().parents[1]
        startup_config = StartupSecurityConfiguration(
            policy_version=settings.security_policy_version,
            app_data_dir=settings.app_data_dir,
            project_root=trusted_project_root,
            ai_provider=settings.ai_provider,
            ai_endpoint=settings.ai_endpoint,
            computer_enabled=settings.computer_enabled,
            camera_enabled=settings.camera_enabled,
            application_management_enabled=settings.application_management_enabled,
            package_installation_enabled=settings.package_installation_enabled,
            voice_enabled=settings.voice_enabled,
            stt_enabled=settings.stt_enabled,
            tts_enabled=settings.tts_enabled,
            multi_agent_enabled=settings.multi_agent_enabled,
            improvement_enabled=settings.improvement_enabled,
            remote_approval_enabled=settings.remote_approval_enabled,
            autonomous_scheduling_enabled=settings.autonomous_scheduling_enabled,
        )
        startup_validator = StartupSecurityValidator()
        security_report = startup_validator.validate(startup_config)
        if not security_report.valid:
            reason = security_report.violations[0].code.value
            return cls(
                None,
                status=RuntimeStatus.SAFE_MODE,
                error=f"security policy rejected startup: {reason}",
                security_report=security_report,
            )
        resolved_app_data_dir = security_report.resolved_app_data_dir
        resolved_project_root = security_report.resolved_project_root
        if resolved_app_data_dir is None or resolved_project_root is None:
            return cls(
                None,
                status=RuntimeStatus.SAFE_MODE,
                error="security policy rejected startup: app_data_path_unsafe",
                security_report=cls._path_failure_report(security_report),
            )
        state_store: SQLiteStateStore | None = None
        audit: SQLiteAuditSink | None = None
        planning_store: SQLitePlanningStore | None = None
        memory_store: SQLiteMemoryStore | None = None
        user_model_store: UserModelStore | None = None
        knowledge_library: KnowledgeLibrary | None = None
        automation_store: SQLiteAutomationStore | None = None
        trace_store: TraceStore | None = None
        golden_workflow_store: GoldenWorkflowStore | None = None
        workflow_procedure_store: SQLiteWorkflowProcedureStore | None = None
        backup: BackupService | None = None
        automation_service: AutomationService | None = None
        recovery: RecoveryStore | None = None
        recovery_authority: TrustedRecoveryAuthority | None = None
        artifact_store: ArtifactStore | None = None
        recovery_coordinator: RecoveryCoordinator | None = None
        browser_service: BrowserSemanticBridge | None = None
        capability_lifecycle_store: SQLiteCapabilityLifecycleStore | None = None
        provisioning_store: SQLiteProvisioningStore | None = None
        opportunity_store: SQLiteOpportunityStore | None = None
        attention_store: SQLiteAttentionStore | None = None
        presence_projection: PresenceProjection | None = None
        presence_start_task: asyncio.Task[None] | None = None
        application_hash: str | None = None
        transaction_id = str(uuid4())
        try:
            paths = RuntimePaths.from_root(resolved_app_data_dir)
            if paths.root != resolved_app_data_dir:
                raise OSError("Application-data identity changed after security validation")
            paths.ensure_directories()
            final_report = startup_validator.validate(startup_config)
            final_app_data_dir = final_report.resolved_app_data_dir
            final_project_root = final_report.resolved_project_root
            if (
                not final_report.valid
                or final_app_data_dir is None
                or final_project_root is None
                or final_app_data_dir != paths.root
                or final_project_root != resolved_project_root
            ):
                raise OSError("Application-data identity changed during directory creation")
            security_report = final_report
            resolved_project_root = final_project_root
        except (OSError, RuntimeError) as error:
            return cls(
                None,
                status=RuntimeStatus.SAFE_MODE,
                error=f"trusted runtime path unavailable: {type(error).__name__}",
                security_report=cls._path_failure_report(security_report),
            )
        try:
            paths.validate_storage_layout()
            configure_logging(settings.log_level)
            # The application hash covers the trusted JARVIS package loaded by
            # this process, not an optional user/project knowledge root.
            application_hash = compute_application_build_hash(Path(__file__).resolve().parents[1])
            backup = BackupService(paths.backups)
            if settings.environment == "test":
                recovery_backend = (
                    test_fixture.recovery_key_backend
                    if test_fixture is not None and test_fixture.recovery_key_backend is not None
                    else _TEST_RECOVERY_BACKEND
                )
            else:
                recovery_backend = WindowsCredentialManagerBackend()
            recovery_authority = TrustedRecoveryAuthority(
                backup.installation_id,
                recovery_backend,
            )
            recovery_authority.initialize(
                allow_create=not (paths.recovery / "last-known-good.json").exists()
            )
            recovery = RecoveryStore(
                paths.recovery,
                trusted_authority=recovery_authority,
            )
            recovery_coordinator = RecoveryCoordinator(recovery)
            recovery_coordinator.begin_start(
                transaction_id,
                candidate_build=settings.version,
            )
            if recovery_coordinator.safe_mode:
                return cls(
                    None,
                    status=RuntimeStatus.SAFE_MODE,
                    error="recovery crash-loop guard entered safe mode",
                    security_report=security_report,
                )
            events = InMemoryEventBus()
            paths.validate_storage_layout()
            credential_vault = credential_vault or CredentialVault(
                paths.credential_database,
                event_bus=events,
            )
            credential_broker = CredentialBroker(credential_vault)
            paths.validate_storage_layout()
            state_store = SQLiteStateStore(paths.state_database)
            paths.validate_storage_layout()
            state_machine = ApplicationStateMachine(state_store, event_bus=events)
            paths.validate_storage_layout()
            audit = SQLiteAuditSink(paths.audit_database)
            paths.validate_storage_layout()
            policy = (
                test_fixture.permission_policy
                if test_fixture is not None and test_fixture.permission_policy is not None
                else PolicyEngine()
            )
            broker = PermissionBroker(
                policy,
                audit_sink=audit,
                event_bus=events,
            )
            sandbox_network_identity = object()
            broker.register_tool(
                "sandbox.network.request",
                sandbox_network_identity,
                frozenset({Permission.NETWORK_REQUEST}),
            )
            sandbox_tool_bindings = {
                "network.request": ("sandbox.network.request", sandbox_network_identity)
            }
            registry = ToolRegistry(
                (CalculatorTool(), LocalTimeTool(), UnavailableWeatherTool()),
                permission_broker=broker,
            )
            if test_fixture is not None:
                for additional_tool in test_fixture.additional_tools:
                    registry.register(additional_tool)
            if browser_backend is not None:
                try:
                    browser_broker = BrowserBrokerAdapter(
                        browser_backend,
                        registry,
                        vault=credential_vault,
                    )
                    browser_service = BrowserSemanticBridge(
                        browser_broker,
                        permission_gate=browser_broker,
                        event_bus=events,
                    )
                except BrowserCapabilityUnavailable:
                    browser_service = None
            mcp_manager = MCPExtensionManager(registry)
            paths.validate_storage_layout()
            planning_store = SQLitePlanningStore(paths.planning_database)
            paths.validate_storage_layout()
            validator = PlanValidator(registry, max_steps=settings.agent_max_steps)
            engine = PlanningEngine(
                store=planning_store,
                advisor=SafeBuiltinPlanAdvisor(),
                validator=validator,
                executor=BrokeredPlanningStepExecutor(registry, event_bus=events),
                step_verifier=EvidencePlanningStepVerifier(),
                goal_verifier=CompletionCriteriaVerifier(),
                state_machine=state_machine,
                event_bus=events,
                lifecycle_audit=audit,
                approval_invalidator=broker.invalidate_task_approvals,
            )
            engine.reconcile_after_restart()
            for task in engine.list_tasks():
                state_machine.reconcile_projection(
                    task.task_id,
                    task_state_for_status(task.status),
                    reason="reconciled from authoritative planning store",
                )
            paths.validate_storage_layout()
            memory_store = SQLiteMemoryStore(paths.memory_database)
            user_model_store = UserModelStore(paths.user_model_database)
            knowledge_library = KnowledgeLibrary(paths.knowledge_library_database)
            assert knowledge_library is not None
            session_store = AgentSessionStore(paths.sessions_database)
            paths.validate_storage_layout()
            artifact_store = ArtifactStore(paths.artifacts, event_bus=events)
            paths.validate_storage_layout()
            presentation_surface = PresentationSurface(
                "desktop",
                artifact_store=artifact_store,
            )
            root = resolved_project_root
            knowledge = KnowledgeStore.load(root / "knowledge" / "generated" / "project-index.json")
            provider_registry = create_provider_registry(
                model_id=settings.ai_model, context_limit=settings.ai_context_limit
            )
            try:
                provider = provider_registry.create(
                    settings.ai_provider,
                    {
                        "model": settings.ai_model,
                        "endpoint": settings.ai_endpoint,
                        "timeout_seconds": settings.ai_timeout_seconds,
                        "context_limit": settings.ai_context_limit,
                    },
                )
            except KeyError as error:
                raise ConfigurationError(
                    f"Unsupported AI provider: {settings.ai_provider}"
                ) from error
            resource_governor = ResourceGovernor(SystemResourceTelemetry())
            provider_router = ProviderRouter(provider_registry, resource_governor)
            model_manager = LocalModelManager(paths.models)
            conversation_memory = ConversationContextService()
            system_memory = ProjectSystemMemory(knowledge, root)
            capability_registry = CapabilityRegistry()
            skill_registry = SkillRegistry()
            agent_registry = AgentRegistry()
            memory_consistency = MemoryConsistencyService(memory_store)
            memory_control = MemoryControlService(
                memory_store,
                user_model_store,
                consistency=memory_consistency,
            )
            control_center = ControlCenterService()
            task_controller = PlanningTaskController(engine, broker)
            capability_gap_detector = CapabilityGapDetector(frozenset({"calculator", "local_time"}))
            environment_discovery = EnvironmentDiscoveryService(
                test_fixture.discovery_providers if test_fixture is not None else ()
            )
            solution_discovery = SolutionDiscovery(
                CapabilityDiscoveryService(
                    (InternalToolCatalogProvider(registry),), CandidateEvaluator()
                )
            )
            setup_store = SQLiteSetupStore(paths.setup_database)
            provisioning_store = SQLiteProvisioningStore(paths.provisioning_database)
            provisioning_engine = ProvisioningEngine(
                test_fixture.provisioning_providers
                if test_fixture is not None and test_fixture.provisioning_providers is not None
                else {"unconfigured": _UnavailableProvisioningProvider()},
                test_fixture.provisioning_authorization
                if test_fixture is not None and test_fixture.provisioning_authorization is not None
                else BrokerProvisioningAuthorizer(broker),
                store=provisioning_store,
            )
            # Seal the tool/permission registration boundary only after every
            # trusted built-in broker identity has been registered.
            registry.seal()
            adoption_inspector = AdoptionIdentityInspector(
                WindowsFileIdentityProvider(),
                WindowsSignerVerifier(),
                LocalDependencyProvenanceProvider(),
            )
            adoption_policy = AdoptionPolicy(adoption_inspector)
            setup_conductor = SetupConductor(
                test_fixture.setup_handlers
                if test_fixture is not None and test_fixture.setup_handlers is not None
                else {"unconfigured": _UnavailableSetupHandler()},
                setup_store,
                provisioning_engine.run,
                decision_collector=(
                    test_fixture.setup_decision_collector if test_fixture is not None else None
                ),
                adoption_policy=adoption_policy,
            )
            capability_factory = CapabilityFactory(
                capability_registry,
                setup_conductor,
                test_fixture.capability_generator
                if test_fixture is not None
                else _UnavailableCapabilityGenerator(),
                resource_governor=resource_governor,
            )
            capability_lifecycle_store = SQLiteCapabilityLifecycleStore(
                paths.capability_lifecycle_database
            )
            hot_load = HotLoadManager(
                test_fixture.package_runtime_factory
                if test_fixture is not None
                else _UnavailablePackageRuntimeFactory(),
                test_fixture.package_registration_surface
                if test_fixture is not None
                else _UnavailablePackageRegistrationSurface(),
                lifecycle_store=capability_lifecycle_store,
            )
            effect_attestation_store = EffectAttestationStore(
                paths.effect_attestation_database,
                event_bus=events,
            )
            paths.validate_storage_layout()
            trace_store = TraceStore(paths.trace_database)
            trace_service = TraceService(trace_store, events)

            if test_fixture is not None:
                activation_hooks = test_fixture.activation_hooks(effect_attestation_store)
            else:

                def unavailable_shadow(
                    package: IntegrationPackage, observer: TrustedEffectObserver
                ) -> ShadowExecution:
                    del package, observer
                    raise CapabilityAcquisitionError("Shadow activation is not configured")

                def unavailable_canary(
                    package: IntegrationPackage,
                    limits: CanaryLimits,
                    observer: TrustedEffectObserver,
                ) -> CanaryExecution:
                    del package, limits, observer
                    raise CapabilityAcquisitionError("Canary activation is not configured")

                activation_hooks = ActivationHooks(unavailable_shadow, unavailable_canary)

            package_activation = PackageActivationService(
                hot_load,
                activation_hooks,
                attestation_store=effect_attestation_store,
                lifecycle_store=capability_lifecycle_store,
                require_executable_isolation=True,
            )
            if test_fixture is not None and test_fixture.lifecycle_restore is not None:
                for stored in capability_lifecycle_store.list():
                    if stored.record.state not in {
                        ActivationState.ACTIVE,
                        ActivationState.DEGRADED,
                        ActivationState.SHADOW,
                        ActivationState.CANARY,
                    }:
                        continue
                    restore_request, restored_manifest = test_fixture.lifecycle_restore(stored)
                    restored = package_activation.restore(restore_request)
                    if restored.package_hash != stored.record.package_hash:
                        raise CapabilityAcquisitionError(
                            "Restored lifecycle package hash does not match durable state"
                        )
                    if restored.state in {ActivationState.ACTIVE, ActivationState.DEGRADED}:
                        capability_registry.register(restored_manifest)
            verification_engine = VerificationEngine()
            compensation_store = CompensationStore(paths.compensation_database)
            compensation_service = CompensationService(
                engine,
                registry,
                verification_engine,
                compensation_store,
                observation_provider=(
                    test_fixture.compensation_observation_provider
                    if test_fixture is not None
                    else None
                ),
                state_provider=(
                    test_fixture.compensation_state_provider if test_fixture is not None else None
                ),
                trace=trace_service,
            )
            package_reviewer = GeneratedPackageReviewer()
            package_certifier = PackageCertifier(
                package_reviewer,
                require_executable_isolation=True,
            )

            class _DefaultScopeProvider:
                async def scope(self, _intent: GoalIntent, _gap: CapabilityGap) -> AcquisitionScope:
                    return AcquisitionScope(WorkspaceContext("default"), EnvironmentGraph())

            class _NoVerificationEvidence:
                async def collect(
                    self,
                    capability_id: str,
                    original_goal: str,
                    stage: AcquisitionStage,
                ) -> Sequence[EvidenceRecord]:
                    del capability_id, original_goal, stage
                    return ()

            capability_acquisition = CapabilityAcquisitionCoordinator(
                CapabilityAcquisitionServices(
                    registry=capability_registry,
                    gap_detector=capability_gap_detector,
                    environment_discovery=environment_discovery,
                    solution_discovery=solution_discovery,
                    factory=capability_factory,
                    package_reviewer=package_reviewer,
                    package_certifier=package_certifier,
                    setup_conductor=setup_conductor,
                    provisioning_engine=provisioning_engine,
                    package_activation=package_activation,
                    hot_load=hot_load,
                    verification=verification_engine,
                ),
                scope_provider=_DefaultScopeProvider(),
                source_provider=(
                    test_fixture.source_provider if test_fixture is not None else None
                ),
                certification_hooks=(
                    test_fixture.certification_hooks if test_fixture is not None else None
                ),
                activation_requests=(
                    test_fixture.activation_requests if test_fixture is not None else None
                ),
                manifest_provider=(
                    test_fixture.manifest_provider if test_fixture is not None else None
                ),
                verification_evidence=(
                    test_fixture.verification_evidence
                    if test_fixture is not None
                    else _NoVerificationEvidence()
                ),
                sandbox_security_status=(
                    test_fixture.sandbox_security_status if test_fixture is not None else None
                ),
                trace=trace_service,
            )
            opportunity_store = SQLiteOpportunityStore(paths.opportunity_database)
            opportunity_engine = CapabilityOpportunityEngine(
                opportunity_store,
                capability_acquisition,
                preparation=_OpportunityResearchPreparation(capability_acquisition),
            )
            attention_store = SQLiteAttentionStore(paths.attention_database)
            attention_policy = AttentionPolicy(attention_store)
            goal_supervisor_store = GoalSupervisorStore(paths.goal_supervisor_database)
            goal_supervisor = GoalSupervisor(
                registry=capability_registry,
                store=goal_supervisor_store,
                analyzer=RegistryGoalAnalyzer(),
                researcher=capability_acquisition,
                acquirer=capability_acquisition,
                runner=PlanningGoalTaskRunner(task_controller),
                trace=trace_service,
            )
            workflow_procedure_store = SQLiteWorkflowProcedureStore(
                paths.workflow_procedure_database
            )
            procedure_evidence_authority = ProcedureEvidenceAuthority(
                planning_store,
                trace_store,
            )
            procedure_bank = ProcedureBank(
                store=workflow_procedure_store,
                evidence_authority=procedure_evidence_authority,
            )
            workflow_templates = WorkflowTemplateRegistry(store=workflow_procedure_store)
            paths.validate_storage_layout()
            automation_store = SQLiteAutomationStore(paths.automation_database)
            golden_workflow_store = GoldenWorkflowStore(paths.golden_workflow_database)
            golden_workflows = GoldenWorkflowService(golden_workflow_store)
            automation_service = AutomationService(
                automation_store,
                events,
                task_controller,
                workflow_registry=workflow_templates,
                trace_store=trace_store,
            )

            def health_attention_sink(notice: AttentionNotice) -> None:
                severity = getattr(notice.severity, "value", str(notice.severity))
                priority = {
                    "security_drift": AttentionPriority.SECURITY_CRITICAL,
                    "quarantined": AttentionPriority.SECURITY_CRITICAL,
                    "material_drift": AttentionPriority.URGENT,
                    "unavailable": AttentionPriority.HIGH,
                    "degraded": AttentionPriority.HIGH,
                    "low_risk_drift": AttentionPriority.LOW,
                }.get(severity, AttentionPriority.NORMAL)
                attention_policy.enqueue(
                    AttentionItem(
                        uuid4(),
                        "capability.health",
                        "default",
                        priority,
                        notice.created_at,
                        dedupe_key=f"capability-health:{notice.capability_id}:{severity}",
                        summary=notice.summary,
                    )
                )

            capability_health = CapabilityHealthService(
                event_bus=events,
                trace=trace_service.get(correlation_id=UUID(int=0)),
                attention_sink=health_attention_sink,
            )
            component_doctor = ComponentDoctor(capability_health)
            presence_projection = PresenceProjection(events)
            try:
                presence_start_task = asyncio.get_running_loop().create_task(
                    presence_projection.start()
                )
                trace_start_task = asyncio.get_running_loop().create_task(trace_service.start())
            except RuntimeError:
                # Synchronous callers can start the projection through the
                # application service once an event loop is available.
                presence_start_task = None
                trace_start_task = None

            def tool_projection() -> tuple[ControlCenterItem, ...]:
                items: list[ControlCenterItem] = []
                for manifest in registry.manifests():
                    record = registry.inspect(manifest.tool_id)
                    status = (
                        ControlCenterStatus.AVAILABLE
                        if record.usable
                        else ControlCenterStatus.DEGRADED
                    )
                    action = SemanticActionMetadata(
                        f"tool.{manifest.tool_id}.invoke",
                        f"Use {manifest.name}",
                        "Submit through the brokered application task service",
                        "task.submit",
                        tuple(sorted(manifest.declared_permissions, key=lambda item: item.value)),
                        tuple(sorted(record.tool.input_model.model_fields)),
                    )
                    items.append(
                        ControlCenterItem(
                            manifest.tool_id,
                            manifest.name,
                            status,
                            record.health.detail,
                            (action,),
                            (
                                ("version", str(manifest.version)),
                                ("health", record.health.status.value),
                            ),
                        )
                    )
                return tuple(items)

            def capability_projection() -> tuple[ControlCenterItem, ...]:
                items = [
                    ControlCenterItem(
                        manifest.capability_id,
                        manifest.name,
                        (
                            ControlCenterStatus.AVAILABLE
                            if manifest.health.status.value == "available"
                            else ControlCenterStatus.DEGRADED
                        ),
                        manifest.health.detail,
                        (
                            SemanticActionMetadata(
                                f"capability.{manifest.capability_id}.inspect",
                                f"Inspect {manifest.name}",
                                "Inspect capability metadata through the application service",
                                "capability.inspect",
                            ),
                        ),
                        (("version", str(manifest.version)),),
                    )
                    for manifest in capability_registry.manifests()
                ]
                for manifest in registry.manifests():
                    record = registry.inspect(manifest.tool_id)
                    status = (
                        ControlCenterStatus.AVAILABLE
                        if record.usable
                        else ControlCenterStatus.DEGRADED
                    )
                    for index, capability in enumerate(sorted(manifest.capabilities)):
                        items.append(
                            ControlCenterItem(
                                f"tool-capability.{manifest.tool_id}.{index}",
                                manifest.name,
                                status,
                                f"Executable capability tag: {capability}",
                                (
                                    SemanticActionMetadata(
                                        f"tool.{manifest.tool_id}.invoke",
                                        f"Use {manifest.name}",
                                        "Submit through the brokered application task service",
                                        "task.submit",
                                        tuple(
                                            sorted(
                                                manifest.declared_permissions,
                                                key=lambda item: item.value,
                                            )
                                        ),
                                        tuple(sorted(record.tool.input_model.model_fields)),
                                    ),
                                ),
                                (("capability", capability), ("tool_id", manifest.tool_id)),
                            )
                        )
                return tuple(items)

            def skill_projection() -> tuple[ControlCenterItem, ...]:
                return tuple(
                    ControlCenterItem(
                        manifest.skill_id,
                        manifest.skill_id,
                        ControlCenterStatus.AVAILABLE,
                        "Skill is registered and scope-checked at use",
                        (
                            SemanticActionMetadata(
                                f"skill.{manifest.skill_id}.inspect",
                                f"Inspect {manifest.skill_id}",
                                "Inspect skill metadata through the application service",
                                "skill.inspect",
                            ),
                        ),
                    )
                    for manifest in skill_registry.manifests()
                )

            def agent_projection() -> tuple[ControlCenterItem, ...]:
                return tuple(
                    ControlCenterItem(
                        contract.agent_id,
                        contract.agent_id,
                        (
                            ControlCenterStatus.AVAILABLE
                            if contract.available
                            else ControlCenterStatus.DEGRADED
                        ),
                        "Delegated worker; execution remains application-owned",
                        (
                            SemanticActionMetadata(
                                f"agent.{contract.agent_id}.inspect",
                                f"Inspect {contract.agent_id}",
                                "Inspect agent contract through the application service",
                                "agent.inspect",
                            ),
                        ),
                    )
                    for contract in agent_registry.list_contracts()
                )

            def integration_projection() -> tuple[ControlCenterItem, ...]:
                return tuple(
                    ControlCenterItem(
                        status.extension_id,
                        status.extension_id,
                        (
                            ControlCenterStatus.AVAILABLE
                            if status.state.value == "healthy"
                            else ControlCenterStatus.DEGRADED
                        ),
                        status.detail,
                        (
                            SemanticActionMetadata(
                                f"integration.{status.extension_id}.inspect",
                                f"Inspect {status.extension_id}",
                                "Inspect integration status through the application service",
                                "integration.inspect",
                            ),
                        ),
                    )
                    for status in mcp_manager.statuses()
                )

            async def permission_projection() -> tuple[ControlCenterItem, ...]:
                pending = await broker.pending_approvals()
                return tuple(
                    ControlCenterItem(
                        f"request.{request.request_id}",
                        "Pending permission request",
                        ControlCenterStatus.AVAILABLE,
                        request.permission.value,
                        (
                            SemanticActionMetadata(
                                f"permission.{request.request_id}.present",
                                "Review permission request",
                                "Render the trusted permission object for a local channel",
                                "permission.present",
                                (request.permission,),
                            ),
                        ),
                        (("request_id", str(request.request_id)),),
                    )
                    for request in pending
                )

            async def health_projection() -> tuple[ControlCenterItem, ...]:
                health = await provider.health_check()
                return (
                    ControlCenterItem(
                        "default-provider",
                        "Configured model provider",
                        (
                            ControlCenterStatus.AVAILABLE
                            if health.available
                            else ControlCenterStatus.DEGRADED
                        ),
                        health.detail,
                    ),
                )

            def capability_health_projection() -> tuple[ControlCenterItem, ...]:
                return tuple(
                    ControlCenterItem(
                        report.capability_id,
                        f"Capability health: {report.capability_id}",
                        (
                            ControlCenterStatus.AVAILABLE
                            if report.status is HealthStatus.HEALTHY
                            else ControlCenterStatus.DEGRADED
                        ),
                        report.detail,
                        metadata=(
                            ("health", report.status.value),
                            ("checked_at", report.checked_at.isoformat()),
                        ),
                    )
                    for report in capability_health.reports()
                )

            def audit_projection() -> tuple[ControlCenterItem, ...]:
                return (
                    ControlCenterItem(
                        "audit-store",
                        "Audit store",
                        ControlCenterStatus.AVAILABLE,
                        "Trusted audit records are application-owned",
                        metadata=(("lifecycle_record_count", str(len(audit.lifecycle_entries()))),),
                    ),
                )

            def memory_projection() -> tuple[ControlCenterItem, ...]:
                return (
                    ControlCenterItem(
                        "memory-store",
                        "Memory controls",
                        ControlCenterStatus.AVAILABLE,
                        "Inspect and change memory through the trusted application service",
                        metadata=(
                            ("learning_paused", str(memory_control.learning_paused()).lower()),
                            ("vault_secrets", "never exposed"),
                        ),
                    ),
                )

            control_center.register(
                ControlCenterSection.SYSTEM,
                "runtime",
                lambda: (
                    ControlCenterItem(
                        "runtime",
                        "JARVIS runtime",
                        ControlCenterStatus.AVAILABLE,
                        "Composition root is active",
                    ),
                    ControlCenterItem(
                        "settings",
                        "Runtime settings",
                        ControlCenterStatus.AVAILABLE,
                        "Settings are application-owned; secrets remain in the Vault",
                        (
                            SemanticActionMetadata(
                                "settings.inspect",
                                "Inspect settings",
                                "Inspect non-secret settings through the application service",
                                "settings.inspect",
                            ),
                        ),
                    ),
                ),
            )
            control_center.register(
                ControlCenterSection.CAPABILITIES, "registry", capability_projection
            )
            control_center.register(ControlCenterSection.TOOLS, "registry", tool_projection)
            control_center.register(ControlCenterSection.SKILLS, "registry", skill_projection)
            control_center.register(ControlCenterSection.AGENTS, "registry", agent_projection)
            control_center.register(
                ControlCenterSection.INTEGRATIONS, "mcp", integration_projection
            )
            control_center.register(
                ControlCenterSection.MODELS,
                "configured",
                lambda: (
                    ControlCenterItem(
                        "configured-model",
                        "Configured model",
                        ControlCenterStatus.AVAILABLE,
                        "Model selection remains provider-owned",
                        metadata=(("provider", settings.ai_provider), ("model", settings.ai_model)),
                    ),
                ),
            )
            control_center.register(
                ControlCenterSection.PERMISSIONS, "broker", permission_projection
            )
            control_center.register(
                ControlCenterSection.MEMORY,
                "store",
                memory_projection,
            )
            control_center.register(
                ControlCenterSection.KNOWLEDGE,
                "store",
                lambda: (
                    ControlCenterItem(
                        "project-knowledge-store",
                        "Project knowledge index",
                        ControlCenterStatus.AVAILABLE,
                        "Generated project knowledge is read as bounded context",
                        metadata=(("item_count", str(len(knowledge.snapshot.items))),),
                    ),
                    ControlCenterItem(
                        "personal-knowledge-library",
                        "Personal knowledge library",
                        ControlCenterStatus.AVAILABLE,
                        "Only explicitly approved sources are indexed",
                        metadata=(
                            ("document_count", str(len(knowledge_library.list_documents()))),
                            ("source_count", str(len(knowledge_library.list_sources()))),
                        ),
                    ),
                ),
            )
            control_center.register(
                ControlCenterSection.GOALS,
                "planning",
                lambda: tuple(
                    ControlCenterItem(
                        f"task.{task.task_id}",
                        "Planning task",
                        ControlCenterStatus.AVAILABLE,
                        task.status.value,
                    )
                    for task in engine.list_tasks()
                ),
            )
            control_center.register(
                ControlCenterSection.AUTOMATIONS,
                "automation.service",
                lambda: ControlCenterContribution(
                    ControlCenterStatus.AVAILABLE,
                    tuple(
                        ControlCenterItem(
                            str(definition.automation_id),
                            definition.name,
                            (
                                ControlCenterStatus.AVAILABLE
                                if definition.enabled
                                else ControlCenterStatus.DEGRADED
                            ),
                            "Durable event trigger and PlanningEngine dispatch",
                        )
                        for definition in automation_service.definitions()
                    ),
                    "Generic automations are disabled by default until registered",
                ),
            )
            control_center.register(ControlCenterSection.AUDIT, "store", audit_projection)
            control_center.register(ControlCenterSection.HEALTH, "provider", health_projection)
            control_center.register(
                ControlCenterSection.HEALTH,
                "capability-health",
                capability_health_projection,
            )
            control_center.register(
                ControlCenterSection.RECOVERY,
                "store",
                static_provider(
                    (
                        ControlCenterItem(
                            "recovery-store",
                            "Recovery store",
                            ControlCenterStatus.AVAILABLE,
                            "Snapshots and Safe Mode remain trusted runtime services",
                        ),
                    )
                ),
            )

            async def test_provider() -> TestDriveStepResult:
                health = await provider.health_check()
                return TestDriveStepResult(
                    TestDriveStatus.PASS if health.available else TestDriveStatus.FAIL,
                    health.detail,
                )

            async def test_persistence() -> TestDriveStepResult:
                engine.list_tasks()
                return TestDriveStepResult(TestDriveStatus.PASS, "authoritative stores responded")

            async def warmup_provider() -> None:
                await provider.health_check()

            test_drive = TestDriveRegistry()
            test_drive.register(
                TestDriveStep("system-health", "System health", test_persistence, required=True)
            )
            test_drive.register(
                TestDriveStep(
                    "model-provider", "Configured model/provider", test_provider, required=True
                )
            )
            startup_warmup = StartupWarmupRegistry(resource_governor)
            startup_warmup.register(WarmupComponent("default-model", warmup_provider))
            try:
                automation_start_task = asyncio.create_task(automation_service.start())
            except RuntimeError:
                automation_start_task = None
            assert backup is not None
            container = RuntimeContainer(
                settings=settings,
                paths=paths,
                ai_provider=provider,
                resource_governor=resource_governor,
                provider_router=provider_router,
                model_manager=model_manager,
                conversation=ConversationService(
                    provider,
                    model=settings.ai_model,
                    context_limit=settings.ai_context_limit,
                    session_store=session_store,
                    provider_id=settings.ai_provider,
                ),
                event_bus=events,
                state_store=state_store,
                state_machine=state_machine,
                policy_engine=policy,
                audit_sink=audit,
                artifact_store=artifact_store,
                mcp_manager=mcp_manager,
                permission_broker=broker,
                sandbox_tool_bindings=sandbox_tool_bindings,
                tool_registry=registry,
                planning_store=planning_store,
                planning_engine=engine,
                task_controller=task_controller,
                memory_store=memory_store,
                user_model_store=user_model_store,
                session_store=session_store,
                conversation_memory=conversation_memory,
                long_term_memory=LongTermMemoryService(memory_store),
                episodic_memory=EpisodicMemoryService(memory_store),
                memory_consistency=memory_consistency,
                memory_control=memory_control,
                memory_retrieval=MemoryRetrievalService(
                    memory_store, conversation_memory, system_memory
                ),
                knowledge_library=knowledge_library,
                knowledge=knowledge,
                system_memory=system_memory,
                automation_store=automation_store,
                trace_store=trace_store,
                trace_service=trace_service,
                golden_workflow_store=golden_workflow_store,
                golden_workflows=golden_workflows,
                workflow_procedure_store=workflow_procedure_store,
                procedure_evidence_authority=procedure_evidence_authority,
                procedure_bank=procedure_bank,
                automation_service=automation_service,
                capability_health=capability_health,
                component_doctor=component_doctor,
                environment_discovery=environment_discovery,
                presence_projection=presence_projection,
                presentation_surface=presentation_surface,
                compensation_service=compensation_service,
                workflow_templates=workflow_templates,
                discovery=capability_gap_detector,
                capability_gap_detector=capability_gap_detector,
                candidate_evaluator=CandidateEvaluator(),
                goal_supervisor_store=goal_supervisor_store,
                goal_supervisor=goal_supervisor,
                solution_discovery=solution_discovery,
                capability_factory=capability_factory,
                package_reviewer=package_reviewer,
                package_certifier=package_certifier,
                setup_store=setup_store,
                setup_conductor=setup_conductor,
                adoption_policy=adoption_policy,
                provisioning_engine=provisioning_engine,
                provisioning_store=provisioning_store,
                effect_attestation_store=effect_attestation_store,
                capability_lifecycle_store=capability_lifecycle_store,
                opportunity_store=opportunity_store,
                opportunity_engine=opportunity_engine,
                attention_store=attention_store,
                attention_policy=attention_policy,
                package_activation=package_activation,
                hot_load=hot_load,
                verification_engine=verification_engine,
                capability_acquisition=capability_acquisition,
                backup=backup,
                recovery=recovery,
                trusted_recovery_authority=recovery_authority,
                controlled_self_update=ControlledSelfUpdate(),
                agent_loop=AgentLoop(
                    provider,
                    registry,
                    model=settings.ai_model,
                    context_limit=settings.ai_context_limit,
                ),
                launch_profiles=LaunchProfileRegistry(),
                test_drive=test_drive,
                startup_warmup=startup_warmup,
                capability_registry=capability_registry,
                skill_registry=skill_registry,
                agent_registry=agent_registry,
                control_center=control_center,
                browser=browser_service,
                browser_status=(
                    BrowserCapabilityStatus.AVAILABLE
                    if browser_service is not None
                    else BrowserCapabilityStatus.UNAVAILABLE
                ),
                credential_vault=credential_vault,
                credential_broker=credential_broker,
                automation_start_task=automation_start_task,
                presence_start_task=presence_start_task,
                trace_start_task=trace_start_task,
            )
            snapshot = recovery.create_snapshot(
                transaction_id=transaction_id,
                app_revision=settings.version,
                application_hash=application_hash,
                configuration={
                    "environment": settings.environment,
                    "ai_provider": settings.ai_provider,
                    "security_policy_version": settings.security_policy_version,
                },
                database_schema={
                    "state": "validated",
                    "planning": "validated",
                    "memory": "validated",
                    "user_model": "validated",
                    "knowledge_library": "validated",
                    "automations": "validated",
                    "trace": "validated",
                    "golden_workflows": "validated",
                    "workflow_procedures": "validated",
                    "audit": "validated",
                    "capability_lifecycle": "validated",
                    "provisioning": "validated",
                    "credentials_metadata": "validated",
                    "artifacts": "validated",
                },
                integration_versions={},
                generated_package_state={"activation": "disabled"},
            )
            recovery.commit_start(transaction_id, snapshot.snapshot_id)
        except (
            AuditStoreError,
            AutomationStoreError,
            PlanningStoreError,
            MemoryMigrationError,
            KnowledgeLibraryMigrationError,
            UserModelMigrationError,
            StateStoreError,
            TraceError,
            GoldenWorkflowError,
            WorkflowProcedureStoreError,
            ProvisioningError,
            sqlite3.DatabaseError,
        ) as error:
            if recovery is not None:
                try:
                    recovery.mark_failed(
                        transaction_id,
                        failed_phase=RecoveryPhase.START,
                        detail=f"startup failure: {type(error).__name__}",
                    )
                except RecoveryError:
                    recovery.record(
                        RecoveryEvidence(
                            transaction_id,
                            RecoveryPhase.FAIL,
                            "startup_failure",
                            type(error).__name__,
                            None,
                            datetime.now(UTC).isoformat(),
                        )
                    )
            cls._close_partial_stores(
                artifact_store,
                automation_service,
                trace_store,
                golden_workflow_store,
                workflow_procedure_store,
                capability_lifecycle_store,
                provisioning_store,
                opportunity_store,
                attention_store,
                credential_vault,
                automation_store,
                memory_store,
                user_model_store,
                knowledge_library,
                planning_store,
                audit,
                state_store,
            )
            return cls(
                None,
                status=RuntimeStatus.SAFE_MODE,
                error=f"persistence unavailable: {type(error).__name__}",
                security_report=security_report,
            )
        except Exception as error:
            if recovery is not None:
                try:
                    recovery.mark_failed(
                        transaction_id,
                        failed_phase=RecoveryPhase.START,
                        detail=f"startup failure: {type(error).__name__}",
                    )
                except RecoveryError:
                    recovery.record(
                        RecoveryEvidence(
                            transaction_id,
                            RecoveryPhase.FAIL,
                            "startup_failure",
                            type(error).__name__,
                            None,
                            datetime.now(UTC).isoformat(),
                        )
                    )
            cls._close_partial_stores(
                artifact_store,
                automation_service,
                trace_store,
                golden_workflow_store,
                workflow_procedure_store,
                capability_lifecycle_store,
                provisioning_store,
                opportunity_store,
                attention_store,
                credential_vault,
                automation_store,
                memory_store,
                user_model_store,
                knowledge_library,
                planning_store,
                audit,
                state_store,
            )
            return cls(
                None,
                status=RuntimeStatus.ERROR,
                error=f"startup failed: {type(error).__name__}",
                security_report=security_report,
            )
        return cls(
            container,
            status=RuntimeStatus.READY,
            security_report=security_report,
        )

    @staticmethod
    def _path_failure_report(report: StartupSecurityReport) -> StartupSecurityReport:
        if any(
            violation.code is SecurityViolationCode.APP_DATA_PATH_UNSAFE
            for violation in report.violations
        ):
            return report
        return StartupSecurityReport(
            report.policy_version,
            (
                *report.violations,
                SecurityViolation(
                    SecurityViolationCode.APP_DATA_PATH_UNSAFE,
                    "The trusted runtime path could not be resolved safely",
                ),
            ),
            None,
            report.resolved_project_root,
        )

    @staticmethod
    def _close_partial_stores(*stores: object | None) -> None:
        """Best-effort cleanup after startup fails before a container owns resources."""

        for store in stores:
            close = getattr(store, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    continue

    async def aclose(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            self._closed = True
            container = self._container
            self._container = None
            if container is not None:
                await container.aclose()
            self._status = RuntimeStatus.STOPPED
