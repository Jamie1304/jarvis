"""Single-owner runtime bridge for the optional Qt desktop client."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from jarvis.application import AssistantEvent
from jarvis.projections import ProjectionObserver, ProjectionUpdate
from jarvis.runtime import ApplicationRuntime


@dataclass(frozen=True, slots=True)
class DesktopBackendStartup:
    """Result of starting the desktop's application owner."""

    ready: bool
    error: str | None = None


class DesktopBackendHost:
    """Own one canonical runtime and event loop outside the Qt main thread."""

    def __init__(
        self,
        runtime_factory: Callable[[], ApplicationRuntime],
        assistant_factory: Callable[[ApplicationRuntime], Any],
    ) -> None:
        self._runtime_factory = runtime_factory
        self._assistant_factory = assistant_factory
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._runtime: ApplicationRuntime | None = None
        self._assistant: Any | None = None
        self._started = threading.Event()
        self._stopped = threading.Event()
        self._startup = DesktopBackendStartup(False, "Desktop backend has not started")
        self._lock = threading.Lock()
        self._projection_listeners: list[ProjectionObserver] = []
        self._closing = False

    @property
    def startup(self) -> DesktopBackendStartup:
        return self._startup

    def start(self, *, timeout: float = 30.0) -> DesktopBackendStartup:
        """Start the backend owner once and wait for runtime composition."""

        with self._lock:
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run, name="jarvis-desktop-backend", daemon=True
                )
                self._thread.start()
        if not self._started.wait(timeout):
            return DesktopBackendStartup(False, "Desktop backend startup timed out")
        return self._startup

    def submit(self, operation: Callable[[Any], Any]) -> Future[Any]:
        """Execute a synchronous service operation on the owner event loop."""

        async def run() -> Any:
            return operation(self._require_assistant())

        return self._submit(run())

    def add_projection_listener(self, listener: ProjectionObserver) -> None:
        """Forward persisted runtime projections to an application surface."""

        if not callable(listener):
            raise TypeError("projection listener must be callable")
        with self._lock:
            if not self._closing and listener not in self._projection_listeners:
                self._projection_listeners.append(listener)

    def remove_projection_listener(self, listener: ProjectionObserver) -> None:
        with self._lock:
            if listener in self._projection_listeners:
                self._projection_listeners.remove(listener)

    def submit_async(self, operation: Callable[[Any], Any]) -> Future[Any]:
        """Execute an awaitable service operation on the owner event loop."""

        async def run() -> Any:
            result = operation(self._require_assistant())
            return await result

        return self._submit(run())

    def stream_text(
        self,
        conversation_id: UUID,
        text: str,
        *,
        on_event: Callable[[AssistantEvent], None],
    ) -> Future[None]:
        """Stream one response entirely on the runtime-owner event loop."""

        async def run() -> None:
            async for event in self._require_assistant().stream_text(conversation_id, text):
                on_event(event)

        return self._submit(run())

    def cancel(self, conversation_id: UUID) -> Future[Any]:
        return self.submit(lambda assistant: assistant.cancel(conversation_id))

    def close(self, *, timeout: float = 15.0) -> None:
        """Close runtime resources on their owning loop and join its thread."""

        with self._lock:
            self._closing = True
        loop = self._loop
        thread = self._thread
        if loop is None or thread is None or loop.is_closed():
            return

        async def shutdown() -> None:
            if self._runtime is not None:
                await self._runtime.aclose()
            elif self._assistant is not None:
                await self._assistant.aclose()

        try:
            future = asyncio.run_coroutine_threadsafe(shutdown(), loop)
            future.result(timeout)
        except RuntimeError:
            if not loop.is_closed():
                raise
        finally:
            with self._lock:
                self._projection_listeners.clear()
            if not loop.is_closed():
                loop.call_soon_threadsafe(loop.stop)
            if thread.is_alive():
                thread.join(timeout)

    def _submit(self, coroutine: Any) -> Future[Any]:
        loop = self._loop
        if loop is None or not self._startup.ready:
            raise RuntimeError(self._startup.error or "Desktop backend is unavailable")
        return asyncio.run_coroutine_threadsafe(coroutine, loop)

    def _require_assistant(self) -> Any:
        if self._assistant is None:
            raise RuntimeError("Desktop backend is unavailable")
        return self._assistant

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            self._runtime = self._runtime_factory()
            add_observer = getattr(self._runtime, "add_projection_observer", None)
            if callable(add_observer):
                add_observer(self._forward_projection)
            start_services = getattr(self._runtime, "start_background_services", None)
            if callable(start_services):
                start_services(loop)
            self._assistant = self._assistant_factory(self._runtime)
            self._startup = DesktopBackendStartup(True)
        except Exception as error:
            self._startup = DesktopBackendStartup(False, str(error))
        finally:
            self._started.set()
        if self._startup.ready:
            loop.run_forever()
        loop.close()
        self._stopped.set()

    def _forward_projection(self, update: ProjectionUpdate) -> None:
        with self._lock:
            if self._closing:
                return
            listeners = tuple(self._projection_listeners)
        for listener in listeners:
            try:
                listener(update)
            except Exception:
                # A closed or failed UI surface cannot affect runtime projections.
                continue
