"""Durable user policy, bounded budgets, approval binding, and learned state."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from jarvis.ai.knowledge import ModelIdentity
from jarvis.ai.providers.intelligence import (
    CostEvidence,
    LearnedModelState,
    ModelPolicy,
    ProviderPolicy,
    UsageReceipt,
)
from jarvis.ai.providers.registry import ModelLifecycle, ModelMetadata


def _text(value: object, name: str, limit: int) -> str:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError(f"{name} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class BulkPolicyRule:
    """A safe declarative predicate; arbitrary user expressions are forbidden."""

    rule_id: str
    policy: ModelPolicy
    provider_id: str | None = None
    family: str | None = None
    max_cost_per_million: float | None = None
    lifecycle: ModelLifecycle | None = None
    unverified_only: bool = False

    def __post_init__(self) -> None:
        _text(self.rule_id, "Bulk policy ID", 128)
        if not isinstance(self.policy, ModelPolicy):
            raise ValueError("Bulk policy value is invalid")
        for name, value in (("provider", self.provider_id), ("family", self.family)):
            if value is not None:
                _text(value, f"Bulk policy {name}", 256)
        if self.max_cost_per_million is not None and (
            type(self.max_cost_per_million) not in {int, float} or self.max_cost_per_million < 0
        ):
            raise ValueError("Bulk policy cost is invalid")
        if self.lifecycle is not None and not isinstance(self.lifecycle, ModelLifecycle):
            raise ValueError("Bulk policy lifecycle is invalid")
        if type(self.unverified_only) is not bool:
            raise ValueError("Bulk policy unverified flag is invalid")

    def matches(
        self,
        identity: ModelIdentity,
        metadata: ModelMetadata,
        cost: CostEvidence | None = None,
        *,
        unverified: bool = True,
    ) -> bool:
        if self.provider_id is not None and identity.provider_id != self.provider_id.casefold():
            return False
        if self.family is not None and metadata.family.casefold() != self.family.casefold():
            return False
        if (
            self.lifecycle is not None
            and getattr(metadata, "lifecycle", ModelLifecycle.UNKNOWN) is not self.lifecycle
        ):
            return False
        if self.max_cost_per_million is not None:
            total = None if cost is None else cost.total_per_million
            if total is None or total <= self.max_cost_per_million:
                return False
        return not self.unverified_only or unverified


@dataclass(frozen=True, slots=True)
class GuardedApproval:
    """A short-lived approval bound to the exact route and intended scope."""

    actor_id: str
    task_id: str
    route_key: str
    purpose: str
    estimated_cost: float | None
    scope: str
    expires_at: datetime
    allow_once: bool = True

    def __post_init__(self) -> None:
        for value, name, limit in (
            (self.actor_id, "approval actor", 256),
            (self.task_id, "approval task", 256),
            (self.route_key, "approval route", 1_024),
            (self.purpose, "approval purpose", 1_000),
            (self.scope, "approval scope", 256),
        ):
            _text(value, name, limit)
        if self.estimated_cost is not None and self.estimated_cost < 0:
            raise ValueError("Approval cost is invalid")
        if self.expires_at.tzinfo is None or type(self.allow_once) is not bool:
            raise ValueError("Approval expiry or mode is invalid")

    def permits(
        self,
        *,
        actor_id: str,
        task_id: str,
        route_key: str,
        purpose: str,
        estimated_cost: float | None,
        scope: str,
        now: datetime | None = None,
    ) -> bool:
        current = now or datetime.now(UTC)
        if current.tzinfo is None or current >= self.expires_at:
            return False
        if (actor_id, task_id, route_key, purpose, scope) != (
            self.actor_id,
            self.task_id,
            self.route_key,
            self.purpose,
            self.scope,
        ):
            return False
        return self.estimated_cost is None or (
            estimated_cost is not None and estimated_cost <= self.estimated_cost
        )


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    policy: ModelPolicy
    allowed: bool
    requires_approval: bool = False
    reason: str = ""


class PolicyStore:
    """Small SQLite-backed policy owner; no credentials or prompt data are stored."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path
        self._lock = threading.RLock()
        self._provider: dict[str, ProviderPolicy] = {}
        self._model: dict[str, ModelPolicy] = {}
        self._bulk: dict[str, BulkPolicyRule] = {}
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._initialize()
            self._load()

    def _connect(self) -> sqlite3.Connection:
        assert self._path is not None
        return sqlite3.connect(self._path)

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS provider_policy (
                    provider_id TEXT PRIMARY KEY, policy TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS model_policy (
                    route_key TEXT PRIMARY KEY, policy TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS bulk_policy (
                    rule_id TEXT PRIMARY KEY, rule_json TEXT NOT NULL
                );
                """
            )

    def _load(self) -> None:
        assert self._path is not None
        with self._lock, self._connect() as connection:
            self._provider = {
                str(row[0]): ProviderPolicy(str(row[1]))
                for row in connection.execute("SELECT provider_id, policy FROM provider_policy")
            }
            self._model = {
                str(row[0]): ModelPolicy(str(row[1]))
                for row in connection.execute("SELECT route_key, policy FROM model_policy")
            }
            for row in connection.execute("SELECT rule_id, rule_json FROM bulk_policy"):
                self._bulk[str(row[0])] = self._rule_from_json(json.loads(str(row[1])))

    def set_provider_policy(self, provider_id: str, policy: ProviderPolicy) -> None:
        provider_id = _text(provider_id, "Provider ID", 256).casefold()
        if not isinstance(policy, ProviderPolicy):
            raise ValueError("Provider policy is invalid")
        self._provider[provider_id] = policy
        if self._path is not None:
            with self._lock, self._connect() as connection:
                connection.execute(
                    "INSERT OR REPLACE INTO provider_policy VALUES (?, ?)",
                    (provider_id, policy.value),
                )

    def provider_policy(self, provider_id: str) -> ProviderPolicy:
        return self._provider.get(provider_id.casefold(), ProviderPolicy.ENABLED)

    def set_model_policy(self, identity: ModelIdentity, policy: ModelPolicy) -> None:
        if not isinstance(identity, ModelIdentity) or not isinstance(policy, ModelPolicy):
            raise ValueError("Model policy input is invalid")
        self._model[identity.storage_key] = policy
        if self._path is not None:
            with self._lock, self._connect() as connection:
                connection.execute(
                    "INSERT OR REPLACE INTO model_policy VALUES (?, ?)",
                    (identity.storage_key, policy.value),
                )

    def model_policy(self, identity: ModelIdentity) -> ModelPolicy | None:
        return self._model.get(identity.storage_key)

    def set_bulk_policy(self, rule: BulkPolicyRule) -> None:
        if not isinstance(rule, BulkPolicyRule):
            raise ValueError("Bulk policy rule is invalid")
        self._bulk[rule.rule_id] = rule
        if self._path is not None:
            with self._lock, self._connect() as connection:
                connection.execute(
                    "INSERT OR REPLACE INTO bulk_policy VALUES (?, ?)",
                    (rule.rule_id, json.dumps(self._rule_json(rule), sort_keys=True)),
                )

    def bulk_policies(self) -> tuple[BulkPolicyRule, ...]:
        return tuple(self._bulk[key] for key in sorted(self._bulk))

    @staticmethod
    def _rule_json(rule: BulkPolicyRule) -> dict[str, object]:
        return {
            "rule_id": rule.rule_id,
            "policy": rule.policy.value,
            "provider_id": rule.provider_id,
            "family": rule.family,
            "max_cost_per_million": rule.max_cost_per_million,
            "lifecycle": rule.lifecycle.value if rule.lifecycle else None,
            "unverified_only": rule.unverified_only,
        }

    @staticmethod
    def _rule_from_json(value: dict[str, Any]) -> BulkPolicyRule:
        return BulkPolicyRule(
            str(value["rule_id"]),
            ModelPolicy(str(value["policy"])),
            value.get("provider_id"),
            value.get("family"),
            value.get("max_cost_per_million"),
            None if value.get("lifecycle") is None else ModelLifecycle(str(value["lifecycle"])),
            bool(value.get("unverified_only", False)),
        )


_POLICY_RANK = {
    ModelPolicy.AUTO_ALLOWED: 0,
    ModelPolicy.GUARDED: 1,
    ModelPolicy.MANUAL_ONLY: 2,
    ModelPolicy.BLOCKED: 3,
}


class PolicyEngine:
    """Resolve provider, model, and bulk user policy before optimization."""

    def __init__(self, store: PolicyStore) -> None:
        self.store = store

    def effective_policy(
        self,
        identity: ModelIdentity,
        metadata: ModelMetadata,
        *,
        cost: CostEvidence | None = None,
        unverified: bool = True,
    ) -> ModelPolicy:
        provider = self.store.provider_policy(identity.provider_id)
        values = [
            ModelPolicy.BLOCKED
            if provider is ProviderPolicy.BLOCKED
            else ModelPolicy.MANUAL_ONLY
            if provider is ProviderPolicy.ROUTING_DISABLED
            else ModelPolicy.AUTO_ALLOWED
        ]
        values.append(self.store.model_policy(identity) or ModelPolicy.AUTO_ALLOWED)
        values.extend(
            rule.policy
            for rule in self.store.bulk_policies()
            if rule.matches(identity, metadata, cost, unverified=unverified)
        )
        return max(values, key=_POLICY_RANK.__getitem__)

    def evaluate(
        self,
        identity: ModelIdentity,
        metadata: ModelMetadata,
        *,
        explicit_selection: bool = False,
        approval: GuardedApproval | None = None,
        actor_id: str = "system",
        task_id: str = "task",
        purpose: str = "inference",
        scope: str = "inference",
        estimated_cost: float | None = None,
        cost: CostEvidence | None = None,
        unverified: bool = True,
        now: datetime | None = None,
    ) -> PolicyDecision:
        policy = self.effective_policy(identity, metadata, cost=cost, unverified=unverified)
        if getattr(metadata, "lifecycle", ModelLifecycle.UNKNOWN) is ModelLifecycle.RETIRED:
            return PolicyDecision(policy, False, reason="retired model route")
        if policy is ModelPolicy.BLOCKED:
            return PolicyDecision(policy, False, reason="user policy blocks route")
        if policy is ModelPolicy.MANUAL_ONLY and not explicit_selection:
            return PolicyDecision(
                policy, False, reason="manual-only route requires explicit selection"
            )
        if policy is ModelPolicy.GUARDED:
            route_key = identity.storage_key
            permitted = approval is not None and approval.permits(
                actor_id=actor_id,
                task_id=task_id,
                route_key=route_key,
                purpose=purpose,
                estimated_cost=estimated_cost,
                scope=scope,
                now=now,
            )
            if not permitted:
                return PolicyDecision(policy, False, True, "guarded route requires bound approval")
        return PolicyDecision(policy, True, reason="policy gates passed")


@dataclass(frozen=True, slots=True)
class BudgetPolicy:
    max_request_cost: float | None = None
    max_task_cost: float | None = None
    daily_cloud_budget: float | None = None
    weekly_cloud_budget: float | None = None
    monthly_cloud_budget: float | None = None
    approval_threshold: float | None = None

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items() if hasattr(self, "__dict__") else ():
            if value is not None and (type(value) not in {int, float} or value < 0):
                raise ValueError(f"Budget {name} is invalid")


class BudgetLedger:
    """Local-only budget accounting with separate estimates and receipts."""

    def __init__(self, policy: BudgetPolicy) -> None:
        self.policy = policy
        self._receipts: list[UsageReceipt] = []

    def record(self, receipt: UsageReceipt) -> None:
        if not isinstance(receipt, UsageReceipt):
            raise ValueError("Usage receipt is invalid")
        self._receipts.append(receipt)

    def actual_total(
        self, *, since: datetime | None = None, route_prefix: str | None = None
    ) -> float:
        return sum(
            item.actual_cost or 0.0
            for item in self._receipts
            if (since is None or item.observed_at >= since)
            and (route_prefix is None or item.route_key.startswith(route_prefix))
        )

    def estimated_allowed(
        self, estimated_cost: float | None, *, now: datetime | None = None
    ) -> bool:
        if estimated_cost is None:
            return False
        if (
            self.policy.max_request_cost is not None
            and estimated_cost > self.policy.max_request_cost
        ):
            return False
        current = now or datetime.now(UTC)
        day = current - timedelta(days=1)
        week = current - timedelta(days=7)
        month = current - timedelta(days=31)
        return not (
            self.policy.daily_cloud_budget is not None
            and self.actual_total(since=day) + estimated_cost > self.policy.daily_cloud_budget
            or self.policy.weekly_cloud_budget is not None
            and self.actual_total(since=week) + estimated_cost > self.policy.weekly_cloud_budget
            or self.policy.monthly_cloud_budget is not None
            and self.actual_total(since=month) + estimated_cost > self.policy.monthly_cloud_budget
        )


@dataclass(frozen=True, slots=True)
class LearnedRouteState:
    identity: ModelIdentity
    state: LearnedModelState = LearnedModelState.UNVERIFIED
    task_class: str | None = None
    failure_count: int = 0
    success_count: int = 0
    reason: str = ""


class TaskQuarantine:
    """Prefer narrow task-family quarantine over global model exclusion."""

    def __init__(self, threshold: int = 3) -> None:
        if type(threshold) is not int or threshold < 1:
            raise ValueError("Quarantine threshold is invalid")
        self._threshold = threshold
        self._failures: dict[tuple[str, str], int] = {}
        self._successes: dict[tuple[str, str], int] = {}

    def record_failure(
        self, identity: ModelIdentity, task_class: str, reason: str = ""
    ) -> LearnedRouteState:
        key = (identity.storage_key, _text(task_class, "Task class", 128))
        self._failures[key] = self._failures.get(key, 0) + 1
        count = self._failures[key]
        state = (
            LearnedModelState.TASK_QUARANTINED
            if count >= self._threshold
            else LearnedModelState.DEPRIORITIZED
        )
        return LearnedRouteState(
            identity, state, task_class, count, self._successes.get(key, 0), reason
        )

    def record_success(self, identity: ModelIdentity, task_class: str) -> LearnedRouteState:
        key = (identity.storage_key, _text(task_class, "Task class", 128))
        self._successes[key] = self._successes.get(key, 0) + 1
        return LearnedRouteState(
            identity,
            LearnedModelState.NORMAL,
            task_class,
            self._failures.get(key, 0),
            self._successes[key],
        )

    def is_quarantined(self, identity: ModelIdentity, task_class: str) -> bool:
        return self._failures.get((identity.storage_key, task_class), 0) >= self._threshold
