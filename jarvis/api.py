"""Minimal health-only HTTP API."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict

from fastapi import FastAPI

from jarvis import __version__
from jarvis.core.config import get_settings
from jarvis.core.health import HealthService
from jarvis.core.logging import configure_logging

settings = get_settings()
configure_logging(settings.log_level)
health_service = HealthService(settings.version or __version__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    health_service.mark_started()
    yield


app = FastAPI(title="JARVIS", version=health_service.status().version, lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, object]:
    return asdict(health_service.status())


@app.get("/version")
async def version() -> dict[str, str]:
    return {"version": health_service.status().version}
