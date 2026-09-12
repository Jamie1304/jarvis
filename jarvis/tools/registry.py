"""Deterministic registry for explicitly trusted JARVIS tools."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from jarvis.core.errors import (
    CapabilityUnavailableError,
    DuplicateToolError,
    ToolRegistrationError,
)
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import Permission
from jarvis.permissions.policy import PolicyEngine
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
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


class TrustedToolRegistrationPort:
    """Private application port for certified generated-tool swaps.

    The ordinary registry and broker remain sealed after startup.  Only the
    activation service receives this port, and the registry still validates
    the adapter type and exact package identity before changing its records.
    Generated package processes never receive this object.
    """

    def __init__(self, registry: ToolRegistry, authority: object) -> None:
        self._registry = registry
        self._authority = authority

    def activate(
        self,
        package_id: str,
        version: SemanticVersion,
        package_hash: str,
        certification: object,
        tools: Sequence[Tool[Any, Any]],
    ) -> None:
        self._registry._activate_generated(  # noqa: SLF001
            self._authority,
            package_id,
            version,
            package_hash,
            certification,
            tools,
        )

    def deactivate(self, package_id: str) -> None:
        self._registry._deactivate_generated(self._authority, package_id)  # noqa: SLF001


class ToolRegistry:
    """Resolve only explicitly registered tools; never scan or import directories."""

    def __init__(
        self,
        tools: tuple[Tool[Any, Any], ...] = (),
        *,
        permission_broker: PermissionBroker | None = None,
    ) -> None:
        self._records: dict[str, ToolRecord] = {}
        self._initialization_failures: dict[str, InitializationFailure] = {}
        self._permission_broker = permission_broker or PermissionBroker(PolicyEngine())
        self._sealed = False
        self._generated_tool_ids: dict[str, tuple[str, ...]] = {}
        self._trusted_application_port = TrustedToolRegistrationPort(
            self,
            self._permission_broker._trusted_registration_authority,  # noqa: SLF001
        )
        for tool in tools:
            self.register(tool)

    @property
    def permission_broker(self) -> PermissionBroker:
        """Return the broker bound to every tool instance in this registry."""

        return self._permission_broker

    def register(self, tool: Tool[Any, Any]) -> ToolRecord:
        """Register a tool without replacing any existing implementation."""

        # Generated adapters are application-owned projections.  Even before
        # startup sealing, accepting one through the ordinary public method
        # would let a package/fixture bypass certification and lifecycle
        # validation.  The activation-only port is the sole registration path.
        from jarvis.generated_capability import GeneratedCapabilityToolAdapter

        if isinstance(tool, GeneratedCapabilityToolAdapter):
            raise ToolRegistrationError(
                "Generated adapters require the trusted activation registration port"
            )
        if self._sealed:
            raise ToolRegistrationError("Tool registry is sealed")
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
        try:
            self._permission_broker.register_tool(
                tool_id,
                tool,
                manifest.declared_permissions,
            )
        except ValueError as error:
            raise ToolRegistrationError(f"Permission registration failed: {error}") from error
        self._records[tool_id] = record
        return record

    def register_factory(self, tool_id: str, factory: ToolFactory) -> None:
        """Instantiate one explicitly configured trusted provider.

        Factory failures are retained and surfaced in diagnostics; they are never
        silently treated as a missing capability.
        """

        if self._sealed:
            raise ToolRegistrationError("Tool registry is sealed")
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
                detail=(
                    f"Tool factory failed ({type(error).__name__}); provider details were withheld"
                ),
            )

    def unregister(self, tool_id: str) -> bool:
        """Remove an explicitly registered tool and report whether it existed."""

        if self._sealed:
            raise ToolRegistrationError("Tool registry is sealed")
        record = self._records.pop(tool_id, None)
        if record is None:
            return False
        self._permission_broker.unregister_tool(tool_id, record.tool)
        return True

    def _trusted_application_registration_port(self) -> TrustedToolRegistrationPort:
        """Return the narrow activation-only port to the composition root.

        This is deliberately not part of the public registry API.  The package
        activation service receives the port during trusted composition; package
        code and ordinary callers only see the sealed registry's read/invoke
        surface.
        """

        return self._trusted_application_port

    def _activate_generated(
        self,
        authority: object,
        package_id: str,
        version: SemanticVersion,
        package_hash: str,
        certification: object,
        tools: Sequence[Tool[Any, Any]],
    ) -> None:
        from jarvis.generated_capability import GeneratedCapabilityToolAdapter
        from jarvis.package_certification import CertificationRecord

        if authority is not self._trusted_application_port._authority:  # noqa: SLF001
            raise ToolRegistrationError("Untrusted generated-tool registration authority")
        if not self._sealed:
            raise ToolRegistrationError("Generated tools require a sealed startup registry")
        if (
            type(package_id) is not str
            or not package_id.strip()
            or not isinstance(version, SemanticVersion)
            or not re.fullmatch(r"[0-9a-fA-F]{64}", package_hash)
            or not isinstance(certification, CertificationRecord)
            or certification.package_id != package_id
            or certification.version != version
            or certification.package_hash != package_hash
        ):
            raise ToolRegistrationError("Generated tool registration identity is malformed")
        adapters = tuple(tools)
        if not adapters or len(adapters) > 64:
            raise ToolRegistrationError("Generated package must declare semantic actions")
        for tool in adapters:
            if not isinstance(tool, GeneratedCapabilityToolAdapter):
                raise ToolRegistrationError("Only the trusted generated adapter may be registered")
            if (
                tool.package_id != package_id
                or tool.package_version != version
                or tool.package_hash != package_hash
            ):
                raise ToolRegistrationError("Generated adapter identity does not match package")
            self._validate_manifest(tool.manifest)

        tool_ids = tuple(tool.manifest.tool_id for tool in adapters)
        if len(set(tool_ids)) != len(tool_ids):
            raise DuplicateToolError("Generated action tool IDs must be unique")
        old_ids = self._generated_tool_ids.get(package_id, ())
        old_records = {
            tool_id: self._records[tool_id] for tool_id in old_ids if tool_id in self._records
        }
        for tool_id in tool_ids:
            existing = self._records.get(tool_id)
            if existing is not None and tool_id not in old_records:
                raise DuplicateToolError(
                    f"Generated action collides with an existing tool: {tool_id}"
                )
            if tool_id in self._initialization_failures:
                raise DuplicateToolError(f"Generated action has a failed registration: {tool_id}")

        # Validate the complete new set before changing either registry.  The
        # old package actions are removed only for this exact package so a
        # built-in/trusted tool can never be replaced by a generated one.
        for old_id, old_record in old_records.items():
            self._permission_broker._unregister_tool_for_trusted_application(  # noqa: SLF001
                authority, old_id, old_record.tool
            )
            del self._records[old_id]
        try:
            records = tuple(self._record_for(tool) for tool in adapters)
            for record in records:
                self._permission_broker._register_tool_for_trusted_application(  # noqa: SLF001
                    authority,
                    record.manifest.tool_id,
                    record.tool,
                    record.manifest.declared_permissions,
                )
                self._records[record.manifest.tool_id] = record
        except Exception as error:
            for tool_id in tool_ids:
                registered = self._records.get(tool_id)
                if registered is not None:
                    del self._records[tool_id]
                    self._permission_broker._unregister_tool_for_trusted_application(  # noqa: SLF001
                        authority, tool_id, registered.tool
                    )
            for old_id, old_record in old_records.items():
                self._permission_broker._register_tool_for_trusted_application(  # noqa: SLF001
                    authority,
                    old_id,
                    old_record.tool,
                    old_record.manifest.declared_permissions,
                )
                self._records[old_id] = old_record
            raise ToolRegistrationError("Generated action registration swap failed") from error
        self._generated_tool_ids[package_id] = tool_ids

    def _deactivate_generated(self, authority: object, package_id: str) -> None:
        if authority is not self._trusted_application_port._authority:  # noqa: SLF001
            raise ToolRegistrationError("Untrusted generated-tool registration authority")
        tool_ids = self._generated_tool_ids.pop(package_id, ())
        for tool_id in tool_ids:
            record = self._records.pop(tool_id, None)
            if record is not None:
                self._permission_broker._unregister_tool_for_trusted_application(  # noqa: SLF001
                    authority, tool_id, record.tool
                )

    def _record_for(self, tool: Tool[Any, Any]) -> ToolRecord:
        manifest = tool.manifest
        status = manifest.status
        detail = "Registered; health has not been actively probed"
        if not manifest.enabled:
            status = ToolRegistrationStatus.DISABLED
            detail = "Tool is disabled by its manifest"
        elif not self._supports_current_platform(manifest):
            status = ToolRegistrationStatus.UNSUPPORTED_PLATFORM
            detail = "Tool does not support the current platform"
        return ToolRecord(
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

    def seal(self) -> None:
        """Make the trusted startup registry immutable for the runtime lifetime."""

        self._sealed = True
        self._permission_broker.seal_registration()

    @property
    def sealed(self) -> bool:
        return self._sealed

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
                logging.getLogger(__name__).error(
                    "Tool health check failed for %s; provider details were withheld",
                    record.manifest.tool_id,
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
        if any(
            not isinstance(permission, Permission) for permission in manifest.declared_permissions
        ):
            raise ValueError("Tool permissions must use the granular Permission enum")

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
