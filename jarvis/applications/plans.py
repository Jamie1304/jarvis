"""Ephemeral immutable installation plans; a package search is not execution authority."""

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from jarvis.applications.models import (
    InstallationCandidate,
    InstallationPlan,
    InstallationPlanError,
    InstallationPlanKind,
)


class InstallationPlanStore:
    """Create expiring, single-use plans owned solely by trusted application code."""

    def __init__(self, *, ttl_seconds: int = 300) -> None:
        if ttl_seconds <= 0:
            raise ValueError("Installation plan TTL must be positive")
        self._ttl_seconds = ttl_seconds
        self._plans: dict[UUID, InstallationPlan] = {}
        self._lock = asyncio.Lock()

    async def create(
        self,
        kind: InstallationPlanKind,
        candidate: InstallationCandidate,
        *,
        current_version: str | None = None,
    ) -> InstallationPlan:
        now = datetime.now(UTC)
        plan = InstallationPlan(
            plan_id=uuid4(),
            kind=kind,
            candidate=candidate,
            current_version=current_version,
            created_at=now,
            expires_at=now + timedelta(seconds=self._ttl_seconds),
        )
        async with self._lock:
            self._purge(now)
            self._plans[plan.plan_id] = plan
        return plan

    def peek(self, plan_id: UUID) -> InstallationPlan | None:
        """Return current immutable plan evidence for a synchronous tool descriptor."""

        plan = self._plans.get(plan_id)
        if plan is None or plan.expires_at <= datetime.now(UTC):
            return None
        return plan

    async def consume(self, plan_id: UUID) -> InstallationPlan:
        """Atomically take a plan before the provider can mutate the host."""

        now = datetime.now(UTC)
        async with self._lock:
            self._purge(now)
            try:
                return self._plans.pop(plan_id)
            except KeyError as error:
                raise InstallationPlanError("Installation plan is unavailable") from error

    def _purge(self, now: datetime) -> None:
        expired = [key for key, plan in self._plans.items() if plan.expires_at <= now]
        for key in expired:
            del self._plans[key]
