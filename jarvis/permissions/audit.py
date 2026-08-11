"""Secret-safe append-only audit sink interfaces."""

import asyncio
from abc import ABC, abstractmethod

from jarvis.permissions.models import AuditRecord


class AuditSink(ABC):
    """Destination for broker-generated records, never raw tool arguments."""

    @abstractmethod
    async def append(self, record: AuditRecord) -> None:
        """Append one immutable audit event."""


class InMemoryAuditSink(AuditSink):
    """Deterministic process-local sink for tests and local composition."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._lock = asyncio.Lock()

    async def append(self, record: AuditRecord) -> None:
        async with self._lock:
            self._records.append(record)

    async def records(self) -> tuple[AuditRecord, ...]:
        async with self._lock:
            return tuple(self._records)
