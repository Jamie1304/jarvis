"""Non-blocking, best-effort voice capability warmup."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WarmupResult:
    name: str
    ready: bool
    detail: str


class VoiceWarmup:
    """Warm optional local providers without blocking desktop startup."""

    def __init__(self, checks: tuple[tuple[str, Callable[[], Awaitable[None]]], ...]) -> None:
        self._checks = checks
        self._task: asyncio.Task[tuple[WarmupResult, ...]] | None = None

    def start(self) -> asyncio.Task[tuple[WarmupResult, ...]]:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())
        return self._task

    async def aclose(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)

    async def _run(self) -> tuple[WarmupResult, ...]:
        results: list[WarmupResult] = []
        for name, check in self._checks:
            try:
                await check()
            except Exception as error:
                results.append(WarmupResult(name, False, type(error).__name__))
            else:
                results.append(WarmupResult(name, True, "ready"))
        return tuple(results)
