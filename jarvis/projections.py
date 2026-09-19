"""Bounded application projection-update notifications."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID


class ProjectionKind(StrEnum):
    """Durable projections that can invalidate the desktop product view."""

    EPISODE = "episode"
    TRACE = "trace"


@dataclass(frozen=True, slots=True)
class ProjectionUpdate:
    """Factual update emitted after one bounded projection is persisted."""

    kind: ProjectionKind
    record_id: UUID
    task_id: UUID | None
    correlation_id: UUID | None


ProjectionObserver = Callable[[ProjectionUpdate], None]


__all__ = ["ProjectionKind", "ProjectionObserver", "ProjectionUpdate"]
