"""Explicit application-specific configuration extension point; no generic editor."""

from abc import ABC, abstractmethod
from collections.abc import Mapping

from jarvis.applications.models import ApplicationManagerError, ApplicationRecord


class ApplicationConfigurationAdapter(ABC):
    """One reviewed adapter for one application and its documented safe settings API."""

    @property
    @abstractmethod
    def application_id(self) -> str:
        """Return the exact stable application identifier this adapter supports."""

    @abstractmethod
    async def configure(self, record: ApplicationRecord, settings: Mapping[str, object]) -> None:
        """Validate and apply only the adapter's explicit documented setting set."""


class ConfigurationRegistry:
    """Trusted composition registry; unknown apps have no configuration capability."""

    def __init__(self, adapters: tuple[ApplicationConfigurationAdapter, ...] = ()) -> None:
        self._adapters = {adapter.application_id: adapter for adapter in adapters}
        if len(self._adapters) != len(adapters):
            raise ValueError("Configuration adapters must use unique application identifiers")

    def for_application(self, application_id: str) -> ApplicationConfigurationAdapter:
        try:
            return self._adapters[application_id]
        except KeyError as error:
            raise ApplicationManagerError(
                "No reviewed configuration adapter exists for this application"
            ) from error
