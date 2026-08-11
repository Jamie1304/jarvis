"""Health and startup state service."""

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class HealthStatus:
    status: str
    version: str
    startup_complete: bool


class HealthService:
    """Minimal internal service used by the health API and future service checks."""

    def __init__(self, version: str) -> None:
        self._version = version
        self._startup_complete = False

    def mark_started(self) -> None:
        self._startup_complete = True

    def status(self) -> HealthStatus:
        return HealthStatus(
            status="ok" if self._startup_complete else "starting",
            version=self._version,
            startup_complete=self._startup_complete,
        )
