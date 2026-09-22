"""Health-only HTTP API backed by canonical Trusted Core startup."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse

from jarvis import __version__
from jarvis.core.config import Settings
from jarvis.core.health import HealthService
from jarvis.runtime import ApplicationRuntime, RuntimeStatus


def create_app(
    settings: Settings | None = None,
    *,
    project_root: Path | None = None,
) -> FastAPI:
    """Create a health surface whose readiness follows the canonical runtime."""

    health_service = HealthService(__version__)
    runtime: ApplicationRuntime | None = None

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        nonlocal runtime
        try:
            runtime = (
                ApplicationRuntime.create(settings, project_root=project_root)
                if settings is not None
                else ApplicationRuntime.create_from_environment(project_root=project_root)
            )
            if runtime.status is RuntimeStatus.READY:
                health_service.mark_started()
            else:
                health_service.mark_unavailable(runtime.status.value)
        except Exception:
            # Configuration parsing itself occurs before ApplicationRuntime can
            # produce a report. Keep the health response redacted and fail closed.
            health_service.mark_unavailable("safe_mode")
        try:
            yield
        finally:
            if runtime is not None:
                await runtime.aclose()

    application = FastAPI(
        title="JARVIS",
        version=health_service.status().version,
        lifespan=lifespan,
    )

    @application.get("/health")
    async def health() -> Response:
        status = health_service.status()
        status_code = 200 if status.startup_complete else 503
        return JSONResponse(status_code=status_code, content=asdict(status))

    @application.get("/version")
    async def version() -> dict[str, str]:
        return {"version": health_service.status().version}

    return application


app = create_app()
