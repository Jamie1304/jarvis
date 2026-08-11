"""Versioned, typed contracts for JARVIS capabilities."""

import asyncio
import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from jarvis.permissions.models import AuthorizationReceipt, Permission


class ToolResultStatus(StrEnum):
    """All outcomes a tool may return across the stable execution boundary."""

    SUCCESS = "success"
    EXPECTED_FAILURE = "expected_failure"
    UNAVAILABLE = "unavailable"
    PERMISSION_DENIED = "permission_denied"
    TIMEOUT = "timeout"
    VALIDATION_ERROR = "validation_error"
    CANCELLED = "cancelled"
    INTERNAL_FAILURE = "internal_failure"


class ToolHealthStatus(StrEnum):
    """Availability states exposed by a tool health check."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DEGRADED = "degraded"


class ToolRegistrationStatus(StrEnum):
    """Registry state, kept separate from runtime health."""

    REGISTERED = "registered"
    DISABLED = "disabled"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    INITIALIZATION_FAILED = "initialization_failed"


class ToolCaller(StrEnum):
    """Explicit callers permitted to invoke a registered tool."""

    AGENT = "agent"
    USER_INTERFACE = "user_interface"
    TEST = "test"


class ToolPlatform(StrEnum):
    """Platforms a tool explicitly supports."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


@dataclass(frozen=True, slots=True, order=True)
class SemanticVersion:
    """Structured semantic version for a stable tool contract."""

    major: int
    minor: int
    patch: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True, slots=True)
class ToolManifest:
    """Complete, inspectable contract metadata for one registered tool."""

    tool_id: str
    name: str
    description: str
    version: SemanticVersion
    capability_tags: frozenset[str]
    input_schema: type[BaseModel]
    output_schema: type[BaseModel]
    declared_permissions: frozenset[Permission]
    supported_platforms: frozenset[ToolPlatform]
    timeout_seconds: float
    implementation_id: str | None = None
    enabled: bool = True
    status: ToolRegistrationStatus = ToolRegistrationStatus.REGISTERED
    optional_dependencies: tuple[str, ...] = ()

    @property
    def capabilities(self) -> frozenset[str]:
        """Preferred name for the stable capability tag collection."""

        return self.capability_tags


@dataclass(frozen=True, slots=True)
class ToolHealth:
    """Tool availability state with an operator-readable explanation."""

    status: ToolHealthStatus
    detail: str


@dataclass(frozen=True, slots=True)
class ToolExecutionContext:
    """Minimal context supplied to tools; never an application service container."""

    task_id: UUID
    correlation_id: UUID
    caller: ToolCaller
    cancellation: asyncio.Event
    logger: logging.Logger
    user_id: str | None = None
    authorization: AuthorizationReceipt | None = None


@dataclass(frozen=True, slots=True)
class ToolEvidence:
    """A structured fact that a verifier may use independently from tool success."""

    kind: str
    value: str


@dataclass(frozen=True, slots=True)
class ToolMetadata:
    """Non-sensitive execution metadata intended for diagnostics."""

    key: str
    value: str


@dataclass(frozen=True, slots=True)
class ToolResultError:
    """Stable error representation that never exposes raw library exceptions."""

    code: str
    message: str


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Structured result returned for every tool invocation."""

    status: ToolResultStatus
    output: BaseModel | None = None
    error: ToolResultError | None = None
    evidence: tuple[ToolEvidence, ...] = ()
    metadata: tuple[ToolMetadata, ...] = ()

    @property
    def succeeded(self) -> bool:
        """Return true only for a completed tool execution, not verification success."""

        return self.status is ToolResultStatus.SUCCESS

    @classmethod
    def success(
        cls,
        output: BaseModel,
        *,
        evidence: tuple[ToolEvidence, ...] = (),
        metadata: tuple[ToolMetadata, ...] = (),
    ) -> "ToolResult":
        return cls(ToolResultStatus.SUCCESS, output=output, evidence=evidence, metadata=metadata)

    @classmethod
    def failure(
        cls,
        status: ToolResultStatus,
        code: str,
        message: str,
        *,
        metadata: tuple[ToolMetadata, ...] = (),
    ) -> "ToolResult":
        return cls(
            status=status,
            error=ToolResultError(code=code, message=message),
            metadata=metadata,
        )


ToolInput = BaseModel
ToolOutput = BaseModel
RawToolInput = dict[str, Any]
