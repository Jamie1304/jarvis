"""Bounded in-process event delivery with failure isolation."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import replace
from threading import Lock
from typing import Protocol
from uuid import UUID

from jarvis.events.models import EventEnvelope, EventPayload

EventHandler = Callable[[EventEnvelope[EventPayload]], Awaitable[None]]


class EventBus(Protocol):
    async def publish(self, event: EventEnvelope[EventPayload]) -> bool: ...
    def publish_nowait(self, event: EventEnvelope[EventPayload]) -> bool: ...
    async def subscribe(self, handler: EventHandler) -> str: ...
    async def unsubscribe(self, subscription_id: str) -> None: ...
    async def close(self) -> None: ...


class EventBusMetrics(Protocol):
    def record(self, name: str, value: int = 1) -> None: ...


class InMemoryEventBus:
    """A bounded bus; one slow subscriber cannot block publishers or peers."""

    def __init__(
        self,
        *,
        queue_size: int = 128,
        max_events_per_correlation: int = 256,
        logger: logging.Logger | None = None,
        metrics: EventBusMetrics | None = None,
    ) -> None:
        if queue_size < 1:
            raise ValueError("queue_size must be positive")
        if max_events_per_correlation < 1:
            raise ValueError("max_events_per_correlation must be positive")
        self._queue_size = queue_size
        self._max_events_per_correlation = max_events_per_correlation
        self._logger = logger or logging.getLogger("jarvis.events")
        self._metrics = metrics
        self._subscribers: dict[
            str, tuple[asyncio.Queue[EventEnvelope[EventPayload]], EventHandler, asyncio.Task[None]]
        ] = {}
        self._closed = False
        self._counter = 0
        self._lock = asyncio.Lock()
        self._sync_lock = Lock()
        self._chain_counts: dict[UUID, int] = {}

    async def publish(self, event: EventEnvelope[EventPayload]) -> bool:
        if self._closed:
            return False
        with self._sync_lock:
            count = self._chain_counts.get(event.correlation_id, 0) + 1
            if count > self._max_events_per_correlation:
                self._metric("events.feedback_blocked")
                return False
            self._chain_counts[event.correlation_id] = count
            self._counter += 1
            numbered = replace(event, sequence=self._counter)
        async with self._lock:
            if self._closed:
                return False
            delivered = False
            for queue, _handler, _task in tuple(self._subscribers.values()):
                if queue.full():
                    # Drop oldest observation; authorization/state stores remain separate.
                    queue.get_nowait()
                    self._metric("events.dropped")
                queue.put_nowait(numbered)
                delivered = True
            self._metric("events.published")
            return delivered

    def publish_nowait(self, event: EventEnvelope[EventPayload]) -> bool:
        """Schedule publication for synchronous state/adaptor boundaries."""
        if self._closed:
            return False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return False
        loop.create_task(self.publish(event))
        return True

    async def subscribe(self, handler: EventHandler) -> str:
        if self._closed:
            raise RuntimeError("event bus is closed")
        if not callable(handler):
            raise TypeError("handler must be callable")
        subscription_id = str(UUID(int=self._counter + len(self._subscribers) + 1))
        queue: asyncio.Queue[EventEnvelope[EventPayload]] = asyncio.Queue(self._queue_size)
        task = asyncio.create_task(self._consume(subscription_id, queue, handler))
        async with self._lock:
            if self._closed:
                task.cancel()
                raise RuntimeError("event bus is closed")
            self._subscribers[subscription_id] = (queue, handler, task)
        return subscription_id

    async def unsubscribe(self, subscription_id: str) -> None:
        async with self._lock:
            item = self._subscribers.pop(subscription_id, None)
        if item is not None:
            item[2].cancel()
            await asyncio.gather(item[2], return_exceptions=True)

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            items = tuple(self._subscribers.values())
            self._subscribers.clear()
        for _queue, _handler, task in items:
            task.cancel()
        if items:
            await asyncio.gather(*(item[2] for item in items), return_exceptions=True)

    async def _consume(
        self,
        subscription_id: str,
        queue: asyncio.Queue[EventEnvelope[EventPayload]],
        handler: EventHandler,
    ) -> None:
        try:
            while True:
                event = await queue.get()
                try:
                    await handler(event)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self._metric("events.subscriber_failures")
                    self._logger.exception("event subscriber failed: %s", subscription_id)
        except asyncio.CancelledError:
            return

    def _metric(self, name: str) -> None:
        if self._metrics is not None:
            self._metrics.record(name)
