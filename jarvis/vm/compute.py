"""Trusted host-side model compute boundary; guests receive results, not authority."""

from typing import Protocol
from uuid import UUID


class ModelInferenceBroker(Protocol):
    async def infer(self, task_id: UUID, prompt: str, *, max_output: int = 4096) -> str: ...
