"""Evidence-driven local-model portfolio stewardship.

The portfolio layer is a knowledge and lifecycle coordinator.  Availability
continues to come from ``LocalModelManager`` and routing continues to come from
``ProviderRouter``; this module only compares evidence and stages a separately
authorized removal effect.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID, uuid4

from jarvis.ai.knowledge import (
    CookbookSummary,
    EvidenceSufficiency,
    ModelIdentity,
    ModelKnowledgeService,
    ModelMeasurementView,
    identity_for,
)
from jarvis.ai.model_manager import (
    LocalModelManager,
    LocalModelRecord,
    ModelLifecycleError,
    ModelLifecycleState,
    ModelRemovalUnknownOutcome,
    ModelRemovalVerificationError,
)
from jarvis.ai.providers.registry import ModelMetadata, ProviderRegistry
from jarvis.ai.usability import (
    ModelUsabilityEvidence,
    ModelUsabilityStatus,
    UsabilityValidationError,
)
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ActionDescriptor,
    AuthorizationReceipt,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
)
from jarvis.resources import ResourceGovernor

PortfolioError = UsabilityValidationError
"""A portfolio comparison or retirement transition is unsafe."""


class InsufficientPortfolioEvidence(PortfolioError):
    """The available evidence does not support a destructive conclusion."""


class StaleRetirementPlan(PortfolioError):
    """Reality changed after a retirement plan was prepared."""


class RemovalUnknownOutcome(PortfolioError):
    """A provider removal lacks trusted terminal evidence."""


class RemovalVerificationError(PortfolioError):
    """Physical removal happened or was attempted but verification is incomplete."""


class DominanceClassification(StrEnum):
    REDUNDANT_CANDIDATE = "redundant_candidate"
    SPECIALIST = "specialist"
    NOT_REDUNDANT = "not_redundant"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class RetirementState(StrEnum):
    ACTIVE = "active"
    UNDER_REVIEW = "under_review"
    ROUTING_DISABLED = "routing_disabled"
    RETIREMENT_CANDIDATE = "retirement_candidate"
    RETENTION_WINDOW = "retention_window"
    REMOVAL_APPROVED = "removal_approved"
    REMOVED = "removed"
    REGISTRY_VERIFIED = "registry_verified"


class RemovalEffectOutcome(StrEnum):
    PRE_EFFECT_FAILURE = "pre_effect_failure"
    EFFECT_CONFIRMED = "effect_confirmed"
    UNKNOWN_OUTCOME = "unknown_outcome"


def _text(value: object, name: str, limit: int, *, allow_empty: bool = False) -> str:
    if (
        type(value) is not str
        or (not allow_empty and not value.strip())
        or len(value) > limit
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise PortfolioError(f"{name} is malformed")
    return value


def _optional_text(value: object, name: str, limit: int) -> str | None:
    if value is None:
        return None
    return _text(value, name, limit)


def _optional_nonnegative(value: object, name: str) -> None:
    if value is not None and type(value) not in {int, float}:
        raise PortfolioError(f"{name} is malformed")
    if value is not None and float(cast(int | float, value)) < 0:
        raise PortfolioError(f"{name} is malformed")


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise PortfolioError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class ModelPortfolioEvidence:
    """One model's current availability and measured/verified utility facts."""

    identity: ModelIdentity
    metadata: ModelMetadata
    available: bool
    provider_digest: str | None = None
    physical_size_bytes: int | None = None
    task_summaries: tuple[CookbookSummary, ...] = ()
    measurement: ModelMeasurementView | None = None
    actual_router_use: int | None = None
    privacy_eligible: bool | None = None
    stability: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ModelIdentity) or not isinstance(
            self.metadata, ModelMetadata
        ):
            raise PortfolioError("Portfolio identity or metadata is malformed")
        if self.identity.model_id != self.metadata.model_id or type(self.available) is not bool:
            raise PortfolioError("Portfolio identity or availability is malformed")
        _text(self.provider_digest, "Provider digest", 512) if self.provider_digest else None
        for value, name in (
            (self.physical_size_bytes, "Physical size"),
            (self.actual_router_use, "Router usage"),
        ):
            if value is not None and (type(value) is not int or value < 0):
                raise PortfolioError(f"{name} is malformed")
        if type(self.task_summaries) is not tuple or any(
            not isinstance(item, CookbookSummary) for item in self.task_summaries
        ):
            raise PortfolioError("Portfolio task evidence is malformed")
        if self.measurement is not None and not isinstance(self.measurement, ModelMeasurementView):
            raise PortfolioError("Portfolio measurement is malformed")
        if self.privacy_eligible is not None and type(self.privacy_eligible) is not bool:
            raise PortfolioError("Portfolio privacy evidence is malformed")
        _optional_nonnegative(self.stability, "Portfolio stability")
        if self.stability is not None and self.stability > 1:
            raise PortfolioError("Portfolio stability must be between zero and one")

    @property
    def capability_dimensions(self) -> frozenset[str]:
        return frozenset(
            {
                *self.metadata.capabilities,
                *(role.value for role in self.metadata.roles),
                *self.metadata.modalities,
            }
        )

    @property
    def same_physical_identity_key(self) -> tuple[str, str | None]:
        return (self.identity.provider_id, self.provider_digest)

    def summary_for(self, task_class: str) -> CookbookSummary | None:
        return next((item for item in self.task_summaries if item.task_class == task_class), None)


def _summary_is_sufficient(item: ModelPortfolioEvidence, task_class: str) -> bool:
    summary = item.summary_for(task_class)
    return summary is not None and summary.evidence_sufficiency is EvidenceSufficiency.SUFFICIENT


@dataclass(frozen=True, slots=True)
class DominanceAnalysis:
    candidate: ModelPortfolioEvidence
    replacement: ModelPortfolioEvidence | None
    classification: DominanceClassification
    reason: str
    comparable_task_classes: tuple[str, ...] = ()
    unique_dimensions: frozenset[str] = frozenset()
    candidate_utility: float | None = None
    replacement_utility: float | None = None
    physical_alias: bool = False

    def __post_init__(self) -> None:
        _text(self.reason, "Dominance reason", 2_000)
        if not isinstance(self.classification, DominanceClassification):
            raise PortfolioError("Dominance classification is malformed")
        if self.replacement is not None and not isinstance(
            self.replacement, ModelPortfolioEvidence
        ):
            raise PortfolioError("Dominance replacement is malformed")
        if type(self.comparable_task_classes) is not tuple or any(
            type(item) is not str for item in self.comparable_task_classes
        ):
            raise PortfolioError("Dominance task evidence is malformed")
        if type(self.unique_dimensions) is not frozenset:
            raise PortfolioError("Dominance dimensions are malformed")
        for value, name in (
            (self.candidate_utility, "Candidate utility"),
            (self.replacement_utility, "Replacement utility"),
        ):
            _optional_nonnegative(value, name)
        if type(self.physical_alias) is not bool:
            raise PortfolioError("Physical alias evidence is malformed")


@dataclass(frozen=True, slots=True)
class RetirementProtection:
    user_pinned: bool = False
    sole_local_fallback: bool = False
    in_use: bool = False
    required_by_capability: bool = False
    required_by_lkg: bool = False
    privacy_route: bool = False
    never_delete: bool = False
    active_task_dependency: bool = False
    specialist: bool = False
    reacquisition_known: bool | None = None

    def __post_init__(self) -> None:
        values = (
            self.user_pinned,
            self.sole_local_fallback,
            self.in_use,
            self.required_by_capability,
            self.required_by_lkg,
            self.privacy_route,
            self.never_delete,
            self.active_task_dependency,
            self.specialist,
        )
        if any(type(value) is not bool for value in values):
            raise PortfolioError("Retirement protection flags are malformed")
        if self.reacquisition_known is not None and type(self.reacquisition_known) is not bool:
            raise PortfolioError("Reacquisition evidence is malformed")

    @property
    def reasons(self) -> tuple[str, ...]:
        values = (
            (self.user_pinned, "user pinned"),
            (self.sole_local_fallback, "sole local fallback"),
            (self.in_use, "model is in use"),
            (self.required_by_capability, "required by a capability"),
            (self.required_by_lkg, "required by recovery or LKG"),
            (self.privacy_route, "only privacy-eligible route"),
            (self.never_delete, "NEVER_DELETE policy"),
            (self.active_task_dependency, "active task dependency"),
            (self.specialist, "verified specialist capability"),
            (self.reacquisition_known is not True, "reacquisition is not verified"),
        )
        return tuple(reason for active, reason in values if active)

    @property
    def removal_eligible(self) -> bool:
        return not self.reasons

    def as_dict(self) -> dict[str, bool | None]:
        return {
            "user_pinned": self.user_pinned,
            "sole_local_fallback": self.sole_local_fallback,
            "in_use": self.in_use,
            "required_by_capability": self.required_by_capability,
            "required_by_lkg": self.required_by_lkg,
            "privacy_route": self.privacy_route,
            "never_delete": self.never_delete,
            "active_task_dependency": self.active_task_dependency,
            "specialist": self.specialist,
            "reacquisition_known": self.reacquisition_known,
        }

    @classmethod
    def from_dict(cls, value: object) -> RetirementProtection:
        if not isinstance(value, dict):
            raise PortfolioError("Retirement protection evidence is malformed")
        fields = {
            name: value.get(name, default)
            for name, default in (
                ("user_pinned", False),
                ("sole_local_fallback", False),
                ("in_use", False),
                ("required_by_capability", False),
                ("required_by_lkg", False),
                ("privacy_route", False),
                ("never_delete", False),
                ("active_task_dependency", False),
                ("specialist", False),
                ("reacquisition_known", None),
            )
        }
        return cls(**fields)


@dataclass(frozen=True, slots=True)
class RetirementPlan:
    plan_id: UUID
    model: ModelIdentity
    replacement: ModelIdentity
    expected_provider_digest: str | None
    expected_state: ModelLifecycleState
    state: RetirementState
    created_at: datetime
    retention_until: datetime | None
    analysis_fingerprint: str
    detail: str
    protection: RetirementProtection = field(default_factory=RetirementProtection)
    approval_task_id: UUID | None = None
    approval_user_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.plan_id, UUID) or not isinstance(self.model, ModelIdentity):
            raise PortfolioError("Retirement plan identity is malformed")
        if not isinstance(self.replacement, ModelIdentity) or not isinstance(
            self.expected_state, ModelLifecycleState
        ):
            raise PortfolioError("Retirement plan model state is malformed")
        if not isinstance(self.protection, RetirementProtection):
            raise PortfolioError("Retirement plan protection is malformed")
        if self.approval_task_id is not None and not isinstance(self.approval_task_id, UUID):
            raise PortfolioError("Retirement approval task is malformed")
        _optional_text(self.approval_user_id, "Retirement approval user", 256)
        if not isinstance(self.state, RetirementState):
            raise PortfolioError("Retirement plan lifecycle state is malformed")
        created = _timestamp(self.created_at, "Retirement plan creation time")
        if (
            self.retention_until is not None
            and _timestamp(self.retention_until, "Retention expiry") <= created
        ):
            raise PortfolioError("Retention window must be in the future")
        _text(self.analysis_fingerprint, "Retirement analysis fingerprint", 128)
        _text(self.detail, "Retirement plan detail", 2_000)

    @property
    def fingerprint(self) -> str:
        return json.dumps(
            {
                "plan_id": str(self.plan_id),
                "model": self.model.storage_key,
                "replacement": self.replacement.storage_key,
                "digest": self.expected_provider_digest,
                "state": self.expected_state.value,
                "analysis": self.analysis_fingerprint,
                "protection": self.protection.as_dict(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )


class RetirementStore(Protocol):
    def get(self, plan_id: UUID) -> RetirementPlan | None: ...

    def put(self, plan: RetirementPlan) -> RetirementPlan: ...

    def history(self, plan_id: UUID) -> tuple[RetirementPlan, ...]: ...

    def active_plans(self) -> tuple[RetirementPlan, ...]: ...

    def close(self) -> None: ...


class InMemoryRetirementStore:
    def __init__(self) -> None:
        self._plans: dict[UUID, RetirementPlan] = {}
        self._history: dict[UUID, list[RetirementPlan]] = {}

    def get(self, plan_id: UUID) -> RetirementPlan | None:
        return self._plans.get(plan_id)

    def put(self, plan: RetirementPlan) -> RetirementPlan:
        if not isinstance(plan, RetirementPlan):
            raise PortfolioError("Retirement record is malformed")
        self._plans[plan.plan_id] = plan
        self._history.setdefault(plan.plan_id, []).append(plan)
        return plan

    def history(self, plan_id: UUID) -> tuple[RetirementPlan, ...]:
        return tuple(self._history.get(plan_id, ()))

    def active_plans(self) -> tuple[RetirementPlan, ...]:
        return tuple(self._plans.values())

    def close(self) -> None:
        return None


class SQLiteRetirementStore:
    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise PortfolioError("Retirement store path is malformed")
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, timeout=5.0, check_same_thread=False)
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS model_retirement_history (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                plan_id TEXT NOT NULL,
                model_json TEXT NOT NULL,
                replacement_json TEXT NOT NULL,
                expected_digest TEXT,
                expected_state TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                retention_until TEXT,
                analysis_fingerprint TEXT NOT NULL,
                detail TEXT NOT NULL,
                protection_json TEXT NOT NULL DEFAULT '{}',
                approval_task_id TEXT,
                approval_user_id TEXT
            )"""
        )
        columns = {
            str(row[1])
            for row in self._connection.execute(
                "PRAGMA table_info(model_retirement_history)"
            ).fetchall()
        }
        if "protection_json" not in columns:
            self._connection.execute(
                "ALTER TABLE model_retirement_history "
                "ADD COLUMN protection_json TEXT NOT NULL DEFAULT '{}'"
            )
        if "approval_task_id" not in columns:
            self._connection.execute(
                "ALTER TABLE model_retirement_history ADD COLUMN approval_task_id TEXT"
            )
        if "approval_user_id" not in columns:
            self._connection.execute(
                "ALTER TABLE model_retirement_history ADD COLUMN approval_user_id TEXT"
            )
        self._connection.commit()

    def get(self, plan_id: UUID) -> RetirementPlan | None:
        row = self._connection.execute(
            "SELECT * FROM model_retirement_history WHERE plan_id=? ORDER BY sequence DESC LIMIT 1",
            (str(plan_id),),
        ).fetchone()
        return None if row is None else self._from_row(row)

    def put(self, plan: RetirementPlan) -> RetirementPlan:
        if not isinstance(plan, RetirementPlan):
            raise PortfolioError("Retirement record is malformed")
        self._connection.execute(
            """INSERT INTO model_retirement_history
            (plan_id, model_json, replacement_json, expected_digest, expected_state, state,
             created_at, retention_until, analysis_fingerprint, detail, protection_json,
             approval_task_id, approval_user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(plan.plan_id),
                plan.model.storage_key,
                plan.replacement.storage_key,
                plan.expected_provider_digest,
                plan.expected_state.value,
                plan.state.value,
                plan.created_at.isoformat(),
                plan.retention_until.isoformat() if plan.retention_until else None,
                plan.analysis_fingerprint,
                plan.detail,
                json.dumps(plan.protection.as_dict(), sort_keys=True, separators=(",", ":")),
                str(plan.approval_task_id) if plan.approval_task_id is not None else None,
                plan.approval_user_id,
            ),
        )
        self._connection.commit()
        return plan

    def history(self, plan_id: UUID) -> tuple[RetirementPlan, ...]:
        rows = self._connection.execute(
            "SELECT * FROM model_retirement_history WHERE plan_id=? ORDER BY sequence",
            (str(plan_id),),
        ).fetchall()
        return tuple(self._from_row(row) for row in rows)

    def active_plans(self) -> tuple[RetirementPlan, ...]:
        rows = self._connection.execute(
            """
            SELECT history.*
            FROM model_retirement_history AS history
            JOIN (
                SELECT plan_id, MAX(sequence) AS sequence
                FROM model_retirement_history
                GROUP BY plan_id
            ) AS latest ON latest.sequence = history.sequence
            ORDER BY history.plan_id
            """
        ).fetchall()
        return tuple(self._from_row(row) for row in rows)

    def close(self) -> None:
        self._connection.close()

    @staticmethod
    def _identity(value: str) -> ModelIdentity:
        provider, model, version, quantization, runtime = json.loads(value)
        return ModelIdentity(provider, model, version, quantization, runtime)

    @classmethod
    def _from_row(cls, row: tuple[object, ...]) -> RetirementPlan:
        protection = RetirementProtection()
        if len(row) > 11 and row[11]:
            try:
                protection = RetirementProtection.from_dict(json.loads(str(row[11])))
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                raise PortfolioError("Retirement protection record is malformed") from error
        return RetirementPlan(
            UUID(str(row[1])),
            cls._identity(str(row[2])),
            cls._identity(str(row[3])),
            str(row[4]) if row[4] is not None else None,
            ModelLifecycleState(str(row[5])),
            RetirementState(str(row[6])),
            datetime.fromisoformat(str(row[7])),
            datetime.fromisoformat(str(row[8])) if row[8] else None,
            str(row[9]),
            str(row[10]),
            protection,
            UUID(str(row[12])) if len(row) > 12 and row[12] else None,
            str(row[13]) if len(row) > 13 and row[13] is not None else None,
        )


class ModelRemovalAuthorization(Protocol):
    async def authorize(
        self, plan: RetirementPlan, *, task_id: UUID, user_id: str | None
    ) -> object: ...

    async def begin(self, receipt: object) -> None: ...

    async def finish(self, receipt: object, outcome: RemovalEffectOutcome) -> None: ...


class BrokerModelRemovalAuthorizer:
    """Bind retirement removal to the existing PermissionBroker."""

    def __init__(self, broker: PermissionBroker) -> None:
        if not isinstance(broker, PermissionBroker):
            raise PortfolioError("Permission broker is malformed")
        self._broker = broker
        self._identity = object()
        broker.register_tool(
            "model.retirement.remove", self._identity, frozenset({Permission.MODEL_REMOVE})
        )

    async def authorize(
        self, plan: RetirementPlan, *, task_id: UUID, user_id: str | None
    ) -> object:
        descriptor = ActionDescriptor(
            "model.retirement.remove",
            (
                SafeArgument("model", plan.model.provider_model),
                SafeArgument("provider", plan.model.provider_id),
                SafeArgument("digest", plan.expected_provider_digest or "UNKNOWN"),
                SafeArgument("expected_state", plan.expected_state.value),
                SafeArgument("replacement", plan.replacement.provider_model),
                SafeArgument("plan", plan.analysis_fingerprint[:16]),
            ),
            Risk.CRITICAL,
            (
                PermissionRequest(
                    Permission.MODEL_REMOVE,
                    PermissionScope(tool_id="model.retirement.remove", task_id=task_id),
                ),
            ),
        )
        result = await self._broker.authorize(
            tool_id="model.retirement.remove",
            tool_identity=self._identity,
            declared_permissions=frozenset({Permission.MODEL_REMOVE}),
            task_id=task_id,
            user_id=user_id,
            descriptor=descriptor,
            normalized_arguments={
                "plan_id": str(plan.plan_id),
                "task_id": str(task_id),
                "provider": plan.model.provider_id,
                "model": plan.model.storage_key,
                "provider_digest": plan.expected_provider_digest,
                "expected_state": plan.expected_state.value,
                "replacement": plan.replacement.storage_key,
            },
        )
        if not result.authorized or result.receipt is None:
            if result.approval_requests:
                raise PortfolioError("retirement removal approval is required")
            raise PortfolioError(result.reason.value)
        return result.receipt

    async def begin(self, receipt: object) -> None:
        if type(receipt) is not AuthorizationReceipt:
            raise PortfolioError("retirement receipt is malformed")
        reason = await self._broker.begin_execution(receipt)
        if reason is not None:
            raise PortfolioError(reason.value)

    async def finish(self, receipt: object, outcome: RemovalEffectOutcome) -> None:
        if type(receipt) is not AuthorizationReceipt:
            raise PortfolioError("retirement receipt is malformed")
        await self._broker.record_execution_outcome(receipt, outcome.value)


@dataclass(frozen=True, slots=True)
class RemovalVerification:
    plan: RetirementPlan
    provider_absent: bool
    registry_updated: bool
    router_excludes_model: bool
    fallback_healthy: bool
    capability_health: bool
    broken_dependencies: int
    storage_before_bytes: int | None
    storage_after_bytes: int | None
    history_preserved: bool
    storage_delta_verified: bool = True

    @property
    def registry_verified(self) -> bool:
        return (
            self.provider_absent
            and self.registry_updated
            and self.router_excludes_model
            and self.fallback_healthy
            and self.capability_health
            and self.broken_dependencies == 0
            and self.history_preserved
            and self.storage_delta_verified
        )


class ModelPortfolioOptimizer:
    """Compare measured utility and stage safe, durable retirement."""

    def __init__(
        self,
        manager: LocalModelManager,
        knowledge: ModelKnowledgeService,
        registry: ProviderRegistry,
        *,
        provider_id: str,
        retirement_store: RetirementStore,
        removal_authorization: ModelRemovalAuthorization | None = None,
        resource_governor: ResourceGovernor | None = None,
        clock: Callable[[], datetime] | None = None,
        router_integrity: Callable[[ModelIdentity], bool] | None = None,
        capability_health: Callable[[ModelIdentity], bool] | None = None,
        dependency_references: Callable[[ModelIdentity], tuple[str, ...]] | None = None,
        storage_measurement: Callable[[ModelIdentity], int | None] | None = None,
        replacement_usability: Callable[[ModelIdentity], ModelUsabilityEvidence] | None = None,
    ) -> None:
        if (
            not isinstance(manager, LocalModelManager)
            or not isinstance(knowledge, ModelKnowledgeService)
            or not isinstance(registry, ProviderRegistry)
        ):
            raise PortfolioError("Portfolio dependencies are malformed")
        _text(provider_id, "Portfolio provider", 256)
        if not callable(getattr(retirement_store, "put", None)):
            raise PortfolioError("Retirement store is malformed")
        self._manager = manager
        self._knowledge = knowledge
        self._registry = registry
        self._provider_id = provider_id
        self._store = retirement_store
        self._removal_authorization = removal_authorization
        self._resource_governor = resource_governor
        self._clock = clock or (lambda: datetime.now(UTC))
        self._router_integrity = router_integrity
        self._capability_health = capability_health
        self._dependency_references = dependency_references
        self._storage_measurement = storage_measurement
        self._replacement_usability = replacement_usability
        self._receipts: dict[UUID, object] = {}
        self._routing_disabled: set[ModelIdentity] = set()

    async def current_evidence(
        self,
        *,
        task_classes: tuple[str, ...] = (),
        router_usage: Mapping[str, int] | None = None,
    ) -> tuple[ModelPortfolioEvidence, ...]:
        records = await self._manager.discover()
        self._restore_persisted_routing_state()
        self._refresh_registry()
        return tuple(
            self.evidence_for(record, task_classes=task_classes, router_usage=router_usage)
            for record in records
        )

    def evidence_for(
        self,
        record: LocalModelRecord,
        *,
        task_classes: tuple[str, ...] = (),
        router_usage: Mapping[str, int] | None = None,
    ) -> ModelPortfolioEvidence:
        if not isinstance(record, LocalModelRecord):
            raise PortfolioError("Model record is malformed")
        identity = identity_for(self._provider_id, record.spec.metadata)
        summaries = tuple(
            self._knowledge.cookbook_summary(identity, task_class=task_class)
            for task_class in task_classes
        )
        measurement = self._knowledge.latest_measurement(identity)
        usage = None
        if router_usage is not None:
            usage = router_usage.get(identity.storage_key)
            if usage is None:
                usage = router_usage.get(identity.provider_model)
            if usage is None:
                usage = router_usage.get(record.spec.model_id)
        provider = self._registry.definition(self._provider_id).metadata
        return ModelPortfolioEvidence(
            identity,
            record.spec.metadata,
            record.state not in {ModelLifecycleState.UNAVAILABLE, ModelLifecycleState.REMOVED},
            record.spec.provider_digest,
            record.spec.metadata.storage_bytes,
            summaries,
            measurement,
            usage,
            provider.explicitly_local,
            None,
        )

    def analyze(
        self,
        candidates: tuple[ModelPortfolioEvidence, ...],
        *,
        task_classes: tuple[str, ...] = (),
    ) -> tuple[DominanceAnalysis, ...]:
        if type(candidates) is not tuple or any(
            not isinstance(item, ModelPortfolioEvidence) for item in candidates
        ):
            raise PortfolioError("Portfolio candidates are malformed")
        results: list[DominanceAnalysis] = []
        for candidate in candidates:
            alternatives = [
                item
                for item in candidates
                if item.identity != candidate.identity and item.available
            ]
            if not candidate.available:
                results.append(
                    DominanceAnalysis(
                        candidate,
                        None,
                        DominanceClassification.NOT_REDUNDANT,
                        "model is currently unavailable; no removal conclusion",
                    )
                )
                continue
            chosen: tuple[ModelPortfolioEvidence, float, float, tuple[str, ...]] | None = None
            specialist: DominanceAnalysis | None = None
            alias_replacement: ModelPortfolioEvidence | None = None
            for replacement in alternatives:
                if (
                    candidate.provider_digest is not None
                    and replacement.provider_digest == candidate.provider_digest
                    and candidate.identity.provider_id == replacement.identity.provider_id
                ):
                    alias_replacement = replacement
                    continue
                unique = self._unique_dimensions(candidate, replacement)
                if candidate.privacy_eligible is True and replacement.privacy_eligible is not True:
                    unique = frozenset((*unique, "privacy"))
                comparable = tuple(
                    task_class
                    for task_class in task_classes
                    if candidate.summary_for(task_class) is not None
                    and replacement.summary_for(task_class) is not None
                )
                if unique:
                    specialist = DominanceAnalysis(
                        candidate,
                        replacement,
                        DominanceClassification.SPECIALIST,
                        "replacement lacks a relevant verified capability dimension",
                        comparable,
                        frozenset(unique),
                    )
                    continue
                if not comparable or not self._sufficient(candidate, replacement, comparable):
                    continue
                candidate_score = self._utility(candidate, comparable)
                replacement_score = self._utility(replacement, comparable)
                if replacement_score + 1e-9 < candidate_score:
                    continue
                if replacement_score < candidate_score and not self._resource_better(
                    replacement, candidate
                ):
                    continue
                if chosen is None or replacement_score > chosen[2]:
                    chosen = (replacement, candidate_score, replacement_score, comparable)
            if specialist is not None:
                results.append(specialist)
            elif alias_replacement is not None and chosen is None:
                results.append(
                    DominanceAnalysis(
                        candidate,
                        alias_replacement,
                        DominanceClassification.NOT_REDUNDANT,
                        (
                            "same provider digest indicates an alias, not independently "
                            "reclaimable storage"
                        ),
                        physical_alias=True,
                    )
                )
            elif chosen is None:
                results.append(
                    DominanceAnalysis(
                        candidate,
                        None,
                        DominanceClassification.INSUFFICIENT_EVIDENCE,
                        "no available route has sufficient equivalent verified evidence",
                    )
                )
            else:
                replacement, candidate_score, replacement_score, comparable = chosen
                results.append(
                    DominanceAnalysis(
                        candidate,
                        replacement,
                        DominanceClassification.REDUNDANT_CANDIDATE,
                        (
                            "replacement covers the compared responsibilities with equivalent "
                            "or better evidence"
                        ),
                        comparable,
                        candidate_utility=candidate_score,
                        replacement_utility=replacement_score,
                    )
                )
        return tuple(results)

    @staticmethod
    def minimal_portfolio(
        candidates: tuple[ModelPortfolioEvidence, ...], task_classes: tuple[str, ...]
    ) -> tuple[ModelIdentity, ...]:
        if not task_classes:
            return tuple(item.identity for item in candidates if item.available)
        remaining = set(task_classes)
        selected: list[ModelPortfolioEvidence] = []
        available = [item for item in candidates if item.available]
        while remaining:
            ranked = sorted(
                available,
                key=lambda item: (
                    -sum(_summary_is_sufficient(item, task) for task in remaining),
                    item.identity.storage_key,
                ),
            )
            if not ranked or not any(_summary_is_sufficient(ranked[0], task) for task in remaining):
                break
            selected.append(ranked[0])
            available.remove(ranked[0])
            remaining = {task for task in remaining if not _summary_is_sufficient(ranked[0], task)}
        return tuple(item.identity for item in selected)

    def propose_retirement(
        self,
        analysis: DominanceAnalysis,
        protection: RetirementProtection,
        *,
        retention_seconds: int = 86_400,
    ) -> RetirementPlan:
        if not isinstance(analysis, DominanceAnalysis) or not isinstance(
            protection, RetirementProtection
        ):
            raise PortfolioError("Retirement proposal inputs are malformed")
        if analysis.classification is not DominanceClassification.REDUNDANT_CANDIDATE:
            raise InsufficientPortfolioEvidence(
                "only an evidence-backed redundant candidate may enter review"
            )
        if not protection.removal_eligible:
            raise PortfolioError("protected model cannot enter destructive retirement")
        if type(retention_seconds) is not int or not 0 < retention_seconds <= 31_536_000:
            raise PortfolioError("retention window is outside the bounded range")
        assert analysis.replacement is not None
        now = _timestamp(self._clock(), "Portfolio clock")
        plan = RetirementPlan(
            uuid4(),
            analysis.candidate.identity,
            analysis.replacement.identity,
            analysis.candidate.provider_digest,
            ModelLifecycleState.AVAILABLE,
            RetirementState.ACTIVE,
            now,
            now + timedelta(seconds=retention_seconds),
            _analysis_fingerprint(analysis),
            "evidence-backed retirement plan created; no removal authority granted",
            protection,
        )
        return self._store.put(plan)

    def transition(self, plan_id: UUID, target: RetirementState) -> RetirementPlan:
        plan = self._require_plan(plan_id)
        if not isinstance(target, RetirementState):
            raise PortfolioError("Retirement target is malformed")
        allowed = {
            RetirementState.ACTIVE: {RetirementState.UNDER_REVIEW},
            RetirementState.UNDER_REVIEW: {RetirementState.ROUTING_DISABLED},
            RetirementState.ROUTING_DISABLED: {RetirementState.RETIREMENT_CANDIDATE},
            RetirementState.RETIREMENT_CANDIDATE: {RetirementState.RETENTION_WINDOW},
        }
        if target not in allowed.get(plan.state, set()):
            raise PortfolioError(
                f"invalid retirement transition {plan.state.value}->{target.value}"
            )
        updated = replace(plan, state=target, detail=f"transitioned to {target.value}")
        if target is RetirementState.ROUTING_DISABLED:
            self._routing_disabled.add(plan.model)
            self._refresh_registry()
        return self._store.put(updated)

    def re_enable(self, plan_id: UUID) -> RetirementPlan:
        """Re-enable a candidate while no destructive approval has been consumed."""

        plan = self._require_plan(plan_id)
        if plan.state not in {
            RetirementState.ROUTING_DISABLED,
            RetirementState.RETIREMENT_CANDIDATE,
            RetirementState.RETENTION_WINDOW,
        }:
            raise PortfolioError("only a pre-approval retirement plan can be re-enabled")
        self._routing_disabled.discard(plan.model)
        self._refresh_registry()
        return self._store.put(
            replace(plan, state=RetirementState.ACTIVE, detail="retirement plan re-enabled")
        )

    async def approve_removal(
        self, plan_id: UUID, *, task_id: UUID, user_id: str | None = None
    ) -> RetirementPlan:
        plan = self._require_plan(plan_id)
        if plan.state is not RetirementState.RETENTION_WINDOW:
            raise PortfolioError("removal approval requires the retention-window state")
        if plan.retention_until is not None and plan.retention_until > _timestamp(
            self._clock(), "Portfolio clock"
        ):
            raise PortfolioError("retention window has not elapsed")
        if self._removal_authorization is None:
            raise PortfolioError("no trusted model-removal authority is configured")
        receipt = await self._removal_authorization.authorize(
            plan, task_id=task_id, user_id=user_id
        )
        await self._removal_authorization.begin(receipt)
        self._receipts[plan.plan_id] = receipt
        updated = replace(
            plan,
            state=RetirementState.REMOVAL_APPROVED,
            detail="trusted removal authority consumed",
            approval_task_id=task_id,
            approval_user_id=user_id,
        )
        return self._store.put(updated)

    async def remove(self, plan_id: UUID) -> RemovalVerification:
        plan = self._require_plan(plan_id)
        if plan.state is not RetirementState.REMOVAL_APPROVED:
            raise PortfolioError("model removal requires a trusted approved plan")
        if plan_id not in self._receipts:
            raise PortfolioError("model removal has no fresh trusted effect receipt")
        if plan.model.provider_id != self._provider_id:
            await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
            raise StaleRetirementPlan("retirement provider identity changed")
        if not plan.protection.removal_eligible:
            await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
            raise StaleRetirementPlan("retirement protection changed before removal")
        if plan.model not in self._routing_disabled:
            await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
            raise StaleRetirementPlan("model routing was not disabled before removal")
        current = await self._manager.discover()
        record = next(
            (
                item
                for item in current
                if identity_for(self._provider_id, item.spec.metadata) == plan.model
            ),
            None,
        )
        if record is None or record.spec.provider_digest != plan.expected_provider_digest:
            await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
            raise StaleRetirementPlan("model identity or provider digest changed")
        if record.state is not plan.expected_state:
            await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
            raise StaleRetirementPlan("model lifecycle state changed before removal")
        if record.state is ModelLifecycleState.IN_USE or self._manager.has_runtime_handle(
            plan.model.model_id
        ):
            await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
            raise StaleRetirementPlan("model became active before removal")
        if self._router_integrity is not None and not self._router_integrity(plan.model):
            await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
            raise StaleRetirementPlan("removed model remains eligible for routing")
        if self._dependency_references is not None:
            references = self._dependency_references(plan.model)
            if references:
                await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
                raise StaleRetirementPlan("active dependency references the model")
        replacement = next(
            (
                item
                for item in current
                if identity_for(self._provider_id, item.spec.metadata) == plan.replacement
            ),
            None,
        )
        if replacement is None or replacement.state in {
            ModelLifecycleState.UNAVAILABLE,
            ModelLifecycleState.REMOVED,
        }:
            await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
            raise StaleRetirementPlan("replacement is not healthy at the effect boundary")
        try:
            replacement_health = await self._manager.health(plan.replacement.model_id)
        except (KeyError, ModelLifecycleError) as error:
            await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
            raise StaleRetirementPlan(
                "replacement health is unknown at the effect boundary"
            ) from error
        if not replacement_health.available:
            await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
            raise StaleRetirementPlan("replacement is unhealthy at the effect boundary")
        if not self._is_replacement_usable(plan.replacement):
            await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
            raise StaleRetirementPlan(
                "replacement request usability is not proven; availability is insufficient"
            )
        if self._capability_health is not None and not self._capability_health(plan.replacement):
            await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
            raise StaleRetirementPlan("replacement capability health is not proven")
        before = self._measure_storage(plan.model, record.spec.metadata.storage_bytes)
        try:
            await self._manager.remove_provider_model(
                plan.model.model_id,
                expected_provider_digest=plan.expected_provider_digest,
            )
        except ModelRemovalUnknownOutcome as error:
            await self._finish(plan, RemovalEffectOutcome.UNKNOWN_OUTCOME)
            raise RemovalUnknownOutcome(
                "provider removal outcome is ambiguous; reconcile before retry"
            ) from error
        except ModelRemovalVerificationError as error:
            await self._finish(plan, RemovalEffectOutcome.UNKNOWN_OUTCOME)
            raise RemovalVerificationError(
                "provider still exposes the model after the removal effect"
            ) from error
        except ModelLifecycleError:
            await self._finish(plan, RemovalEffectOutcome.PRE_EFFECT_FAILURE)
            raise
        except Exception as error:
            await self._finish(plan, RemovalEffectOutcome.UNKNOWN_OUTCOME)
            raise RemovalUnknownOutcome("provider removal outcome is ambiguous") from error
        await self._manager.discover()
        self._refresh_registry()
        remaining = await self._manager.discover()
        absent = not any(
            item.spec.model_id == plan.model.model_id
            and item.state is not ModelLifecycleState.REMOVED
            for item in remaining
        )
        registry_updated = all(
            model.model_id != plan.model.model_id
            for model in self._registry.definition(self._provider_id).models
        )
        router_excludes = (
            self._router_integrity(plan.model)
            if self._router_integrity is not None
            else registry_updated
        )
        try:
            replacement_health = await self._manager.health(plan.replacement.model_id)
            fallback_healthy = replacement_health.available and self._is_replacement_usable(
                plan.replacement
            )
        except (KeyError, ModelLifecycleError):
            fallback_healthy = False
        capability_ok = (
            True if self._capability_health is None else self._capability_health(plan.replacement)
        )
        broken = (
            len(self._dependency_references(plan.model))
            if self._dependency_references is not None
            else 0
        )
        after = self._measure_storage(plan.model, 0 if absent else before)
        storage_delta_verified = before is None or (after is not None and after <= before)
        history_preserved = self._history_preserved(plan.model)
        verification = RemovalVerification(
            replace(plan, state=RetirementState.REMOVED, detail="provider removal completed"),
            absent,
            registry_updated,
            router_excludes,
            fallback_healthy,
            capability_ok,
            broken,
            before,
            after,
            history_preserved,
            storage_delta_verified,
        )
        if not verification.registry_verified:
            await self._finish(plan, RemovalEffectOutcome.EFFECT_CONFIRMED)
            self._store.put(verification.plan)
            raise RemovalVerificationError("post-removal verification did not close")
        verified = replace(
            verification.plan,
            state=RetirementState.REGISTRY_VERIFIED,
            detail="provider, registry, router, fallback, capability, and history verified",
        )
        self._store.put(verified)
        await self._finish(plan, RemovalEffectOutcome.EFFECT_CONFIRMED)
        return replace(verification, plan=verified)

    async def reconcile_removal(self, plan_id: UUID) -> RetirementPlan:
        plan = self._require_plan(plan_id)
        current = await self._manager.discover()
        present = any(
            item.spec.model_id == plan.model.model_id
            and item.spec.provider_digest == plan.expected_provider_digest
            for item in current
        )
        if present:
            return self._store.put(replace(plan, detail="reconciled: provider still exposes model"))
        self._refresh_registry()
        registry_updated = all(
            model.model_id != plan.model.model_id
            for model in self._registry.definition(self._provider_id).models
        )
        router_excludes = (
            self._router_integrity(plan.model)
            if self._router_integrity is not None
            else registry_updated
        )
        try:
            replacement_health = await self._manager.health(plan.replacement.model_id)
            fallback_healthy = replacement_health.available and self._is_replacement_usable(
                plan.replacement
            )
        except (KeyError, ModelLifecycleError):
            fallback_healthy = False
        capability_ok = (
            True if self._capability_health is None else self._capability_health(plan.replacement)
        )
        broken = (
            len(self._dependency_references(plan.model))
            if self._dependency_references is not None
            else 0
        )
        removed = replace(
            plan,
            state=RetirementState.REMOVED,
            detail="reconciled: provider no longer exposes model",
        )
        verification = RemovalVerification(
            removed,
            True,
            registry_updated,
            router_excludes,
            fallback_healthy,
            capability_ok,
            broken,
            None,
            None,
            self._history_preserved(plan.model),
            True,
        )
        if not verification.registry_verified:
            self._store.put(removed)
            raise RemovalVerificationError("reconciled removal still has unresolved verification")
        return self._store.put(
            replace(
                removed,
                state=RetirementState.REGISTRY_VERIFIED,
                detail="reconciled provider removal and post-removal state",
            )
        )

    def inspect_plan(self, plan_id: UUID) -> RetirementPlan:
        return self._require_plan(plan_id)

    def history(self, plan_id: UUID) -> tuple[RetirementPlan, ...]:
        return self._store.history(plan_id)

    async def aclose(self) -> None:
        close = getattr(self._store, "close", None)
        if callable(close):
            close()

    def _require_plan(self, plan_id: UUID) -> RetirementPlan:
        if not isinstance(plan_id, UUID):
            raise PortfolioError("Retirement plan ID is malformed")
        plan = self._store.get(plan_id)
        if plan is None:
            raise KeyError("Unknown retirement plan")
        return plan

    def _refresh_registry(self) -> None:
        models = tuple(
            record.spec.metadata
            for record in self._manager.records()
            if record.state not in {ModelLifecycleState.REMOVED, ModelLifecycleState.UNAVAILABLE}
            and identity_for(self._provider_id, record.spec.metadata) not in self._routing_disabled
        )
        self._registry.replace_models(self._provider_id, models)

    def _restore_persisted_routing_state(self) -> None:
        active_plans = getattr(self._store, "active_plans", None)
        if not callable(active_plans):
            return
        for plan in active_plans():
            if plan.state in {
                RetirementState.ROUTING_DISABLED,
                RetirementState.RETIREMENT_CANDIDATE,
                RetirementState.RETENTION_WINDOW,
                RetirementState.REMOVAL_APPROVED,
            }:
                self._routing_disabled.add(plan.model)

    def _measure_storage(self, identity: ModelIdentity, fallback: int | None) -> int | None:
        value = self._storage_measurement(identity) if self._storage_measurement else fallback
        if value is not None and (type(value) is not int or value < 0):
            raise PortfolioError("storage measurement is malformed")
        return value

    def _is_replacement_usable(self, identity: ModelIdentity) -> bool:
        if self._replacement_usability is None:
            return False
        try:
            evidence = self._replacement_usability(identity)
        except Exception:
            return False
        return isinstance(evidence, ModelUsabilityEvidence) and evidence.proven_usable_at(
            self._clock()
        )

    def _history_preserved(self, identity: ModelIdentity) -> bool:
        try:
            self._knowledge.inspect_model(identity)
            return True
        except KeyError:
            return False

    async def _finish(self, plan: RetirementPlan, outcome: RemovalEffectOutcome) -> None:
        receipt = self._receipts.pop(plan.plan_id, None)
        if receipt is not None and self._removal_authorization is not None:
            await self._removal_authorization.finish(receipt, outcome)

    @staticmethod
    def _unique_dimensions(
        candidate: ModelPortfolioEvidence, replacement: ModelPortfolioEvidence
    ) -> frozenset[str]:
        unique = set(candidate.capability_dimensions - replacement.capability_dimensions)
        if candidate.metadata.context_limit > replacement.metadata.context_limit:
            unique.add("context_capacity")
        unique.update(candidate.metadata.compatibility - replacement.metadata.compatibility)
        return frozenset(unique)

    @staticmethod
    def _sufficient(
        candidate: ModelPortfolioEvidence,
        replacement: ModelPortfolioEvidence,
        task_classes: tuple[str, ...],
    ) -> bool:
        for task_class in task_classes:
            left = candidate.summary_for(task_class)
            right = replacement.summary_for(task_class)
            if left is None or right is None:
                return False
            if (
                left.evidence_sufficiency is not EvidenceSufficiency.SUFFICIENT
                or right.evidence_sufficiency is not EvidenceSufficiency.SUFFICIENT
            ):
                return False
        return True

    @staticmethod
    def _utility(item: ModelPortfolioEvidence, task_classes: tuple[str, ...]) -> float:
        values: list[float] = []
        for task_class in task_classes:
            summary = item.summary_for(task_class)
            if summary is None:
                continue
            for value in (
                summary.verified_success_rate,
                summary.structured_output_reliability,
                summary.tool_reliability,
            ):
                if value is not None:
                    values.append(value)
        if item.measurement is not None:
            if item.measurement.throughput is not None:
                values.append(min(item.measurement.throughput / 100.0, 1.0))
            if item.measurement.load_seconds is not None:
                values.append(1.0 / (1.0 + item.measurement.load_seconds))
        if item.metadata.quality_score is not None:
            values.append(min(item.metadata.quality_score, 1.0))
        if item.metadata.latency_ms is not None:
            values.append(1.0 / (1.0 + item.metadata.latency_ms / 1_000.0))
        if item.stability is not None:
            values.append(item.stability)
        return sum(values) / len(values) if values else 0.0

    @staticmethod
    def _resource_better(
        replacement: ModelPortfolioEvidence, candidate: ModelPortfolioEvidence
    ) -> bool:
        left = replacement.measurement
        right = candidate.measurement
        if left is None or right is None:
            return False
        if left.storage_bytes is not None and right.storage_bytes is not None:
            return left.storage_bytes <= right.storage_bytes
        return False


def _analysis_fingerprint(analysis: DominanceAnalysis) -> str:
    payload = {
        "candidate": analysis.candidate.identity.storage_key,
        "replacement": analysis.replacement.identity.storage_key if analysis.replacement else None,
        "classification": analysis.classification.value,
        "tasks": analysis.comparable_task_classes,
        "unique": sorted(analysis.unique_dimensions),
        "candidate_utility": analysis.candidate_utility,
        "replacement_utility": analysis.replacement_utility,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


__all__ = [
    "BrokerModelRemovalAuthorizer",
    "DominanceAnalysis",
    "DominanceClassification",
    "InMemoryRetirementStore",
    "InsufficientPortfolioEvidence",
    "PortfolioError",
    "ModelPortfolioEvidence",
    "ModelPortfolioOptimizer",
    "ModelUsabilityEvidence",
    "ModelUsabilityStatus",
    "ModelRemovalAuthorization",
    "RemovalEffectOutcome",
    "RemovalUnknownOutcome",
    "RemovalVerification",
    "RemovalVerificationError",
    "RetirementPlan",
    "RetirementProtection",
    "RetirementState",
    "SQLiteRetirementStore",
    "StaleRetirementPlan",
]
