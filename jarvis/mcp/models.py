"""Validated configuration and lifecycle contracts for MCP extensions."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlparse

from jarvis.permissions.models import Permission


class MCPServerTransport(StrEnum):
    STDIO = "stdio"
    HTTP = "http"


class MCPExtensionState(StrEnum):
    DISCOVERED = "discovered"
    CONFIGURED = "configured"
    STARTING = "starting"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    STOPPED = "stopped"
    FAILED = "failed"


_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


@dataclass(frozen=True, slots=True)
class MCPExtensionConfig:
    """Trusted local configuration; no values are accepted from MCP metadata."""

    extension_id: str
    transport: MCPServerTransport
    command: tuple[str, ...] = ()
    url: str | None = None
    bearer_token: str | None = field(default=None, repr=False)
    permissions: frozenset[Permission] = frozenset()
    timeout_seconds: float = 10.0
    max_result_bytes: int = 65_536
    max_tools: int = 128
    working_directory: Path | None = None
    enabled: bool = True

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.extension_id):
            raise ValueError("MCP extension ID is invalid")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 300:
            raise ValueError("MCP timeout is outside the safe bound")
        if self.max_result_bytes < 1 or self.max_result_bytes > 1_048_576:
            raise ValueError("MCP result bound is outside the safe bound")
        if self.max_tools < 1 or self.max_tools > 1_024:
            raise ValueError("MCP tool bound is outside the safe bound")
        if any(not isinstance(permission, Permission) for permission in self.permissions):
            raise ValueError("MCP permissions must be typed Permission values")
        if self.transport is MCPServerTransport.STDIO:
            if not self.command or any(not item or "\x00" in item for item in self.command):
                raise ValueError("MCP stdio command is invalid")
            if self.url is not None or self.bearer_token is not None:
                raise ValueError("MCP stdio cannot carry HTTP credentials")
            if self.working_directory is not None and not self.working_directory.is_dir():
                raise ValueError("MCP working directory is unavailable")
        elif self.transport is MCPServerTransport.HTTP:
            if not self.url or not self._valid_http_url(self.url):
                raise ValueError("MCP HTTP URL must be HTTPS or loopback HTTP")
            if not self.bearer_token or len(self.bearer_token) > 4096:
                raise ValueError("Authenticated MCP HTTP requires a bounded bearer token")
            if self.command or self.working_directory is not None:
                raise ValueError("MCP HTTP cannot carry a local command")
        else:
            raise ValueError("MCP transport is unsupported")

    @staticmethod
    def _valid_http_url(value: str) -> bool:
        try:
            parsed = urlparse(value)
            port = parsed.port
        except ValueError:
            return False
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return False
        if parsed.scheme == "https" and parsed.hostname and port in (None, 443):
            return True
        return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
