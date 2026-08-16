"""Canonical production composition root for one bounded JARVIS runtime."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from pathlib import Path

from jarvis.ai.providers.base import AIProvider
from jarvis.bootstrap import create_ai_provider
from jarvis.conversation.service import ConversationService
from jarvis.core.config import Settings
from jarvis.core.logging import configure_logging
from jarvis.discovery.service import CandidateEvaluator, CapabilityGapDetector
from jarvis.events import EventBus, InMemoryEventBus
from jarvis.knowledge.store import KnowledgeStore
from jarvis.memory.services import (
    ConversationContextService,
    EpisodicMemoryService,
    LongTermMemoryService,
    MemoryRetrievalService,
    ProjectSystemMemory,
)
from jarvis.memory.store import SQLiteMemoryStore
from jarvis.permissions import PermissionBroker, PolicyEngine, SQLiteAuditSink
from jarvis.planning.engine import (
    BrokeredPlanningStepExecutor,
    CompletionCriteriaVerifier,
    EvidencePlanningStepVerifier,
    PlanAdvisor,
    PlanningEngine,
)
from jarvis.planning.models import ReplanEvidence
from jarvis.planning.store import SQLitePlanningStore
from jarvis.planning.validation import PlanValidator
from jarvis.state import ApplicationStateMachine, SQLiteStateStore
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
    audit_database: Path
    logs: Path
    config: Path
    cache: Path
    temporary: Path
    models: Path

    @classmethod
    def from_root(cls, root: Path) -> RuntimePaths:
        base = root.expanduser().resolve()
        return cls(
            base,
            base / "state.sqlite3",
            base / "planning.sqlite3",
            base / "memory.sqlite3",
            base / "audit.sqlite3",
            base / "logs",
            base / "config",
            base / "cache",
            base / "tmp",
            base / "models",
        )

    def ensure_directories(self) -> None:
        for path in (self.root, self.logs, self.config, self.cache, self.temporary, self.models):
            path.mkdir(parents=True, exist_ok=True)


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


@dataclass(slots=True)
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
    permission_broker: PermissionBroker
    tool_registry: ToolRegistry
    planning_store: SQLitePlanningStore
    planning_engine: PlanningEngine
    task_controller: TaskController
    memory_store: SQLiteMemoryStore
    conversation_memory: ConversationContextService
    long_term_memory: LongTermMemoryService
    episodic_memory: EpisodicMemoryService
    memory_retrieval: MemoryRetrievalService
    knowledge: KnowledgeStore
    system_memory: ProjectSystemMemory
    discovery: CapabilityGapDetector
    candidate_evaluator: CandidateEvaluator
    computer: object | None = None
    vision: object | None = None
    camera: object | None = None
    application_manager: object | None = None
    voice: object | None = None
    multi_agent: object | None = None
    improvement: object | None = None

    async def aclose(self) -> None:
        await self.event_bus.close()
        await self.conversation.aclose()
        self.planning_store.close()
        self.memory_store.close()
        self.state_store.close()
        self.audit_sink.close()


class ApplicationRuntime:
    """Deterministic startup/readiness/shutdown owner; no legacy execution path."""

    def __init__(
        self, container: RuntimeContainer | None, *, status: RuntimeStatus = RuntimeStatus.STARTING
    ) -> None:
        self.container = container
        self.status = status
        self.error: str | None = None

    @classmethod
    def create(cls, settings: Settings, *, project_root: Path | None = None) -> ApplicationRuntime:
        paths = RuntimePaths.from_root(settings.app_data_dir)
        try:
            paths.ensure_directories()
            configure_logging(settings.log_level)
            events = InMemoryEventBus()
            state_store = SQLiteStateStore(paths.state_database)
            state_machine = ApplicationStateMachine(state_store, event_bus=events)
            audit = SQLiteAuditSink(paths.audit_database)
            policy = PolicyEngine()
            broker = PermissionBroker(policy, audit_sink=audit, event_bus=events)
            registry = ToolRegistry(
                (CalculatorTool(), LocalTimeTool(), UnavailableWeatherTool()),
                permission_broker=broker,
            )
            planning_store = SQLitePlanningStore(paths.planning_database)
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
            )
            memory_store = SQLiteMemoryStore(paths.memory_database)
            root = project_root or Path(__file__).resolve().parents[1]
            knowledge = KnowledgeStore.load(root / "knowledge" / "generated" / "project-index.json")
            provider = create_ai_provider(settings)
            conversation_memory = ConversationContextService()
            system_memory = ProjectSystemMemory(knowledge, root)
            container = RuntimeContainer(
                settings=settings,
                paths=paths,
                ai_provider=provider,
                conversation=ConversationService(
                    provider, model=settings.ai_model, context_limit=settings.ai_context_limit
                ),
                event_bus=events,
                state_store=state_store,
                state_machine=state_machine,
                policy_engine=policy,
                audit_sink=audit,
                permission_broker=broker,
                tool_registry=registry,
                planning_store=planning_store,
                planning_engine=engine,
                task_controller=PlanningTaskController(engine, broker),
                memory_store=memory_store,
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
            )
        except Exception as error:
            runtime = cls.__new__(cls)
            runtime.container = None
            runtime.status = RuntimeStatus.ERROR
            runtime.error = f"startup failed: {type(error).__name__}"
            return runtime
        return cls(container, status=RuntimeStatus.READY)

    async def aclose(self) -> None:
        if self.status is RuntimeStatus.STOPPED:
            return
        if self.container is not None:
            await self.container.aclose()
        self.status = RuntimeStatus.STOPPED
