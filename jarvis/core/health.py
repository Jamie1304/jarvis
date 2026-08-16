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
        self._unavailable_status: str | None = None

    def mark_started(self) -> None:
        self._startup_complete = True
        self._unavailable_status = None

    def mark_unavailable(self, status: str) -> None:
        """Expose a bounded fail-closed startup state to health consumers."""

        if status not in {"error", "safe_mode"}:
            raise ValueError("Unavailable health status must be error or safe_mode")
        self._startup_complete = False
        self._unavailable_status = status

    def status(self) -> HealthStatus:
        return HealthStatus(
            status=(self._unavailable_status or ("ok" if self._startup_complete else "starting")),
            version=self._version,
            startup_complete=self._startup_complete,
        )
