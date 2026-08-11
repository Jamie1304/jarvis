"""Deterministic registry for explicitly trusted JARVIS tools."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from jarvis.core.errors import (
    CapabilityUnavailableError,
    DuplicateToolError,
    ToolRegistrationError,
)
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    ToolHealth,
    ToolHealthStatus,
    ToolManifest,
    ToolPlatform,
    ToolRegistrationStatus,
)


@dataclass(frozen=True, slots=True)
class ToolRecord:
    """Inspectable registry record; no application container is exposed."""

    tool: Tool[Any, Any]
    manifest: ToolManifest
    registration_status: ToolRegistrationStatus
    health: ToolHealth

    @property
    def registered(self) -> bool:
        return True

    @property
    def enabled(self) -> bool:
        return self.manifest.enabled

    @property
    def healthy(self) -> bool:
        return self.health.status is ToolHealthStatus.AVAILABLE

    @property
    def usable(self) -> bool:
        return (
            self.registration_status is ToolRegistrationStatus.REGISTERED
            and self.enabled
            and self.healthy
        )


@dataclass(frozen=True, slots=True)
class InitializationFailure:
    """A trusted factory failure retained for diagnostics and snapshots."""

    tool_id: str
    detail: str


ToolFactory = Callable[[], Tool[Any, Any]]


class ToolRegistry:
    """Resolve only explicitly registered tools; never scan or import directories."""

    def __init__(self, tools: tuple[Tool[Any, Any], ...] = ()) -> None:
        self._records: dict[str, ToolRecord] = {}
        self._initialization_failures: dict[str, InitializationFailure] = {}
        for tool in tools:
            self.register(tool)

    def register(self, tool: Tool[Any, Any]) -> ToolRecord:
        """Register a tool without replacing any existing implementation."""

        try:
            manifest = tool.manifest
            self._validate_manifest(manifest)
        except Exception as error:
            raise ToolRegistrationError(
                f"Tool initialization or manifest validation failed: {error}"
            ) from error
        tool_id = manifest.tool_id
        if tool_id in self._records or tool_id in self._initialization_failures:
            raise DuplicateToolError(f"Tool ID is already registered: {tool_id}")
        status = manifest.status
        detail = "Registered; health has not been actively probed"
        if not manifest.enabled:
            status = ToolRegistrationStatus.DISABLED
            detail = "Tool is disabled by its manifest"
        elif not self._supports_current_platform(manifest):
            status = ToolRegistrationStatus.UNSUPPORTED_PLATFORM
            detail = "Tool does not support the current platform"
        record = ToolRecord(
            tool=tool,
            manifest=manifest,
            registration_status=status,
            health=ToolHealth(
                ToolHealthStatus.AVAILABLE
                if status is ToolRegistrationStatus.REGISTERED
                else ToolHealthStatus.UNAVAILABLE,
                detail,
            ),
        )
        self._records[tool_id] = record
        return record

    def register_factory(self, tool_id: str, factory: ToolFactory) -> None:
        """Instantiate one explicitly configured trusted provider.

        Factory failures are retained and surfaced in diagnostics; they are never
        silently treated as a missing capability.
        """

        if tool_id in self._records or tool_id in self._initialization_failures:
            raise DuplicateToolError(f"Tool ID is already registered: {tool_id}")
        try:
            tool = factory()
            if tool.manifest.tool_id != tool_id:
                raise ToolRegistrationError(
                    f"Factory ID {tool_id!r} does not match manifest ID {tool.manifest.tool_id!r}"
                )
            self.register(tool)
        except Exception as error:
            self._initialization_failures[tool_id] = InitializationFailure(
                tool_id=tool_id,
                detail=str(error),
            )

    def unregister(self, tool_id: str) -> bool:
        """Remove an explicitly registered tool and report whether it existed."""

        return self._records.pop(tool_id, None) is not None

    def get(self, tool_id: str) -> Tool[Any, Any]:
        """Return a registered tool, even when it is currently unusable."""

        try:
            return self._records[tool_id].tool
        except KeyError as error:
            raise CapabilityUnavailableError(f"Capability is unavailable: {tool_id}") from error

    def inspect(self, tool_id: str) -> ToolRecord:
        """Return metadata and state for one registered tool."""

        try:
            return self._records[tool_id]
        except KeyError as error:
            raise CapabilityUnavailableError(f"Capability is unavailable: {tool_id}") from error

    def find_by_capability(self, capability: str) -> tuple[ToolRecord, ...]:
        """Find implementations in deterministic version/ID order."""

        matches = [
            record
            for record in self._records.values()
            if capability in record.manifest.capabilities or capability == record.manifest.tool_id
        ]
        return tuple(
            sorted(
                matches,
                key=lambda record: (
                    -record.manifest.version.major,
                    -record.manifest.version.minor,
                    -record.manifest.version.patch,
                    record.manifest.implementation_id or record.manifest.tool_id,
                ),
            )
        )

    def list_available(self) -> tuple[ToolRecord, ...]:
        return tuple(record for record in self._records.values() if record.usable)

    def list_unavailable(self) -> tuple[ToolRecord, ...]:
        return tuple(record for record in self._records.values() if not record.usable)

    def manifests(self) -> tuple[ToolManifest, ...]:
        return tuple(record.manifest for record in self._records.values())

    def resolve_best_matching_capability(self, capability: str) -> Tool[Any, Any]:
        """Resolve the highest-version usable implementation deterministically."""

        for record in self.find_by_capability(capability):
            if record.usable:
                return record.tool
        raise CapabilityUnavailableError(f"No usable implementation for: {capability}")

    async def health_check(self, tool_id: str | None = None) -> tuple[tuple[str, ToolHealth], ...]:
        """Probe one or all enabled/platform-compatible tools and store transitions."""

        records = (self.inspect(tool_id),) if tool_id is not None else tuple(self._records.values())
        results: list[tuple[str, ToolHealth]] = []
        for record in records:
            if record.registration_status is not ToolRegistrationStatus.REGISTERED:
                results.append((record.manifest.tool_id, record.health))
                continue
            try:
                health = await record.tool.health_check()
            except Exception:
                health = ToolHealth(ToolHealthStatus.UNAVAILABLE, "Health check failed")
                logging.getLogger(__name__).exception(
                    "Tool health check failed for %s", record.manifest.tool_id
                )
            self._records[record.manifest.tool_id] = ToolRecord(
                tool=record.tool,
                manifest=record.manifest,
                registration_status=record.registration_status,
                health=health,
            )
            results.append((record.manifest.tool_id, health))
        return tuple(results)

    async def health(self) -> tuple[tuple[str, ToolHealth], ...]:
        """Backward-compatible alias for the Phase 3 health API."""

        return await self.health_check()

    def snapshot(self) -> dict[str, object]:
        """Return serializable, non-secret registry diagnostics."""

        tools = []
        for record in sorted(self._records.values(), key=lambda value: value.manifest.tool_id):
            manifest = record.manifest
            tools.append(
                {
                    "id": manifest.tool_id,
                    "name": manifest.name,
                    "description": manifest.description,
                    "version": str(manifest.version),
                    "capabilities": sorted(manifest.capabilities),
                    "permissions": sorted(
                        permission.value for permission in manifest.declared_permissions
                    ),
                    "platforms": sorted(
                        platform.value for platform in manifest.supported_platforms
                    ),
                    "implementation_id": manifest.implementation_id
                    or type(record.tool).__qualname__,
                    "enabled": record.enabled,
                    "status": record.registration_status.value,
                    "health": record.health.status.value,
                    "health_detail": record.health.detail,
                    "registered": record.registered,
                    "healthy": record.healthy,
                    "usable": record.usable,
                    "optional_dependencies": list(manifest.optional_dependencies),
                }
            )
        return {
            "tools": tools,
            "initialization_failures": [
                {"id": failure.tool_id, "detail": failure.detail}
                for failure in sorted(
                    self._initialization_failures.values(), key=lambda value: value.tool_id
                )
            ],
        }

    @staticmethod
    def _validate_manifest(manifest: ToolManifest) -> None:
        if not manifest.tool_id.strip() or not manifest.name.strip():
            raise ValueError("Tool ID and name must be non-empty")
        if not manifest.capabilities:
            raise ValueError("Tool must declare at least one capability")
        if manifest.timeout_seconds <= 0:
            raise ValueError("Tool timeout guidance must be positive")

    @staticmethod
    def _supports_current_platform(manifest: ToolManifest) -> bool:
        import sys

        if sys.platform.startswith("win"):
            platform = ToolPlatform.WINDOWS
        elif sys.platform == "darwin":
            platform = ToolPlatform.MACOS
        else:
            platform = ToolPlatform.LINUX
        return platform in manifest.supported_platforms
