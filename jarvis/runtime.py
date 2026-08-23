"""Canonical production composition root for one bounded JARVIS runtime."""

from __future__ import annotations

import asyncio
import inspect
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from jarvis.agent_runtime import AgentLoop
from jarvis.ai.providers.base import AIProvider
from jarvis.ai.sessions import AgentSessionStore
from jarvis.artifacts import ArtifactStore
from jarvis.bootstrap import create_ai_provider
from jarvis.capabilities import CapabilityRegistry
from jarvis.control_center import (
    ControlCenterContribution,
    ControlCenterItem,
    ControlCenterSection,
    ControlCenterService,
    ControlCenterStatus,
    SemanticActionMetadata,
    static_provider,
    unavailable_item,
)
from jarvis.conversation.service import ConversationService
from jarvis.core.config import Settings, get_settings
from jarvis.core.logging import configure_logging
from jarvis.desktop_shell import (
    LaunchProfileRegistry,
    StartupWarmupRegistry,
    TestDriveRegistry,
    TestDriveStatus,
    TestDriveStep,
    TestDriveStepResult,
    WarmupComponent,
)
from jarvis.discovery.service import CandidateEvaluator, CapabilityGapDetector
from jarvis.events import EventBus, InMemoryEventBus
from jarvis.knowledge.store import KnowledgeStore
from jarvis.mcp.manager import MCPExtensionManager
from jarvis.memory.services import (
    ConversationContextService,
    EpisodicMemoryService,
    LongTermMemoryService,
    MemoryRetrievalService,
    ProjectSystemMemory,
)
from jarvis.memory.store import MemoryMigrationError, SQLiteMemoryStore
from jarvis.multi_agent.registry import AgentRegistry
from jarvis.permissions import (
    AuditStoreError,
    PermissionBroker,
    PolicyEngine,
    SQLiteAuditSink,
)
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
from jarvis.recovery import RecoveryEvidence, RecoveryPhase, RecoveryStore
from jarvis.security import (
    SECURITY_POLICY_VERSION,
    SecurityViolation,
    SecurityViolationCode,
    StartupSecurityConfiguration,
    StartupSecurityReport,
    StartupSecurityValidator,
)
from jarvis.skills import SkillRegistry
from jarvis.state import ApplicationStateMachine, SQLiteStateStore, StateStoreError
from jarvis.task_controller import PlanningTaskController, TaskController
from jarvis.tools.calculator import CalculatorTool
from jarvis.tools.local_time import LocalTimeTool
from jarvis.tools.registry import ToolRegistry
from jarvis.tools.weather import UnavailableWeatherTool


class RuntimeStatus(StrEnum):
    STARTING = "starting"
    READY = "ready"
    ERROR = "error"
    SAFE_MODE = "safe_mode"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    root: Path
    state_database: Path
    planning_database: Path
    memory_database: Path
    sessions_database: Path
    audit_database: Path
    artifacts: Path
    logs: Path
    config: Path
    cache: Path
    temporary: Path
    models: Path
    recovery: Path

    @classmethod
    def from_root(cls, root: Path) -> RuntimePaths:
        base = root.expanduser().resolve()
        return cls(
            base,
            base / "state.sqlite3",
            base / "planning.sqlite3",
            base / "memory.sqlite3",
            base / "sessions.sqlite3",
            base / "audit.sqlite3",
            base / "artifacts",
            base / "logs",
            base / "config",
            base / "cache",
            base / "tmp",
            base / "models",
            base / "recovery",
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
        )
        databases = (
            self.state_database,
            self.planning_database,
            self.memory_database,
            self.sessions_database,
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
class RuntimeContainer:
    """One owner for every enabled service instance and its shutdown lifecycle."""

    settings: Settings
    paths: RuntimePaths
    ai_provider: AIProvider
    conversation: ConversationService
    event_bus: EventBus
    state_store: SQLiteStateStore
    state_machine: ApplicationStateMachine
    policy_engine: PolicyEngine
    audit_sink: SQLiteAuditSink
    artifact_store: ArtifactStore
    mcp_manager: MCPExtensionManager
    permission_broker: PermissionBroker
    tool_registry: ToolRegistry
    planning_store: SQLitePlanningStore
    planning_engine: PlanningEngine
    task_controller: TaskController
    memory_store: SQLiteMemoryStore
    session_store: AgentSessionStore
    conversation_memory: ConversationContextService
    long_term_memory: LongTermMemoryService
    episodic_memory: EpisodicMemoryService
    memory_retrieval: MemoryRetrievalService
    knowledge: KnowledgeStore
    system_memory: ProjectSystemMemory
    discovery: CapabilityGapDetector
    candidate_evaluator: CandidateEvaluator
    recovery: RecoveryStore
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
    camera: object | None = None
    application_manager: object | None = None
    voice: object | None = None
    multi_agent: object | None = None
    improvement: object | None = None
    _close_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    async def aclose(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            object.__setattr__(self, "_closed", True)
            resources = (
                self.event_bus,
                self.startup_warmup,
                self.control_center,
                self.conversation,
                self.session_store,
                self.planning_store,
                self.memory_store,
                self.state_store,
                self.audit_sink,
                self.artifact_store,
                self.mcp_manager,
                self.voice,
                self.camera,
                self.application_manager,
                self.computer,
                self.vision,
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
    def create_from_environment(cls, *, project_root: Path | None = None) -> ApplicationRuntime:
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
        return cls.create(settings, project_root=project_root)

    @classmethod
    def create(cls, settings: Settings, *, project_root: Path | None = None) -> ApplicationRuntime:
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
        recovery: RecoveryStore | None = None
        artifact_store: ArtifactStore | None = None
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
            recovery = RecoveryStore(paths.recovery)
            recovery.begin_start(transaction_id)
            events = InMemoryEventBus()
            paths.validate_storage_layout()
            state_store = SQLiteStateStore(paths.state_database)
            paths.validate_storage_layout()
            state_machine = ApplicationStateMachine(state_store, event_bus=events)
            paths.validate_storage_layout()
            audit = SQLiteAuditSink(paths.audit_database)
            paths.validate_storage_layout()
            policy = PolicyEngine()
            broker = PermissionBroker(
                policy,
                audit_sink=audit,
                event_bus=events,
            )
            registry = ToolRegistry(
                (CalculatorTool(), LocalTimeTool(), UnavailableWeatherTool()),
                permission_broker=broker,
            )
            mcp_manager = MCPExtensionManager(registry)
            registry.seal()
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
            session_store = AgentSessionStore(paths.sessions_database)
            paths.validate_storage_layout()
            artifact_store = ArtifactStore(paths.artifacts, event_bus=events)
            paths.validate_storage_layout()
            root = resolved_project_root
            knowledge = KnowledgeStore.load(root / "knowledge" / "generated" / "project-index.json")
            provider = create_ai_provider(settings)
            conversation_memory = ConversationContextService()
            system_memory = ProjectSystemMemory(knowledge, root)
            capability_registry = CapabilityRegistry()
            skill_registry = SkillRegistry()
            agent_registry = AgentRegistry()
            control_center = ControlCenterService()

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
                lambda: (
                    ControlCenterItem(
                        "memory-store",
                        "Memory store",
                        ControlCenterStatus.AVAILABLE,
                        "Memory remains scoped by its authoritative store",
                    ),
                ),
            )
            control_center.register(
                ControlCenterSection.KNOWLEDGE,
                "store",
                lambda: (
                    ControlCenterItem(
                        "knowledge-store",
                        "Knowledge library",
                        ControlCenterStatus.AVAILABLE,
                        "Generated knowledge is read as bounded context",
                        metadata=(("item_count", str(len(knowledge.snapshot.items))),),
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
                "scheduler",
                lambda: ControlCenterContribution(
                    ControlCenterStatus.NOT_AVAILABLE,
                    (
                        unavailable_item(
                            "scheduler",
                            "Automation scheduler",
                            "No production scheduler is enabled",
                        ),
                    ),
                    "No production scheduler is enabled",
                ),
            )
            control_center.register(ControlCenterSection.AUDIT, "store", audit_projection)
            control_center.register(ControlCenterSection.HEALTH, "provider", health_projection)
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
            startup_warmup = StartupWarmupRegistry()
            startup_warmup.register(WarmupComponent("default-model", warmup_provider))
            container = RuntimeContainer(
                settings=settings,
                paths=paths,
                ai_provider=provider,
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
                tool_registry=registry,
                planning_store=planning_store,
                planning_engine=engine,
                task_controller=PlanningTaskController(engine, broker),
                memory_store=memory_store,
                session_store=session_store,
                conversation_memory=conversation_memory,
                long_term_memory=LongTermMemoryService(memory_store),
                episodic_memory=EpisodicMemoryService(memory_store),
                memory_retrieval=MemoryRetrievalService(
                    memory_store, conversation_memory, system_memory
                ),
                knowledge=knowledge,
                system_memory=system_memory,
                discovery=CapabilityGapDetector(frozenset({"calculator", "local_time"})),
                candidate_evaluator=CandidateEvaluator(),
                recovery=recovery,
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
            )
            snapshot = recovery.create_snapshot(
                transaction_id=transaction_id,
                app_revision=settings.version,
                configuration={
                    "environment": settings.environment,
                    "ai_provider": settings.ai_provider,
                    "security_policy_version": settings.security_policy_version,
                },
                database_schema={
                    "state": "validated",
                    "planning": "validated",
                    "memory": "validated",
                    "audit": "validated",
                    "artifacts": "validated",
                },
                integration_versions={},
                generated_package_state={"activation": "disabled"},
            )
            recovery.commit_start(transaction_id, snapshot.snapshot_id)
        except (
            AuditStoreError,
            PlanningStoreError,
            MemoryMigrationError,
            StateStoreError,
            sqlite3.DatabaseError,
        ) as error:
            if recovery is not None:
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
                artifact_store, memory_store, planning_store, audit, state_store
            )
            return cls(
                None,
                status=RuntimeStatus.SAFE_MODE,
                error=f"persistence unavailable: {type(error).__name__}",
                security_report=security_report,
            )
        except Exception as error:
            if recovery is not None:
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
                artifact_store, memory_store, planning_store, audit, state_store
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
