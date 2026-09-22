import logging
import sys
from typing import cast

import pytest
from jarvis.core.errors import CapabilityUnavailableError, DuplicateToolError
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
    ToolExecutionContext,
    ToolHealth,
    ToolHealthStatus,
    ToolManifest,
    ToolPlatform,
    ToolResult,
)
from jarvis.tools.registry import ToolRegistry
from pydantic import BaseModel, ConfigDict


class RegistryInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    value: str


class RegistryOutput(BaseModel):
    value: str


class RegistryTool(Tool[RegistryInput, RegistryOutput]):
    def __init__(
        self,
        tool_id: str = "registry-tool",
        version: SemanticVersion | None = None,
        *,
        enabled: bool = True,
        platforms: frozenset[ToolPlatform] | None = None,
    ) -> None:
        self._tool_id = tool_id
        self._version = version or SemanticVersion(1, 0, 0)
        self._enabled = enabled
        self._platforms = platforms or frozenset(
            {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
        )
        self.health = ToolHealth(ToolHealthStatus.AVAILABLE, "healthy")
        self.health_error: str | None = None

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id=self._tool_id,
            name=self._tool_id,
            description="Registry test tool",
            version=self._version,
            capability_tags=frozenset({"demo"}),
            input_schema=RegistryInput,
            output_schema=RegistryOutput,
            declared_permissions=frozenset(),
            supported_platforms=self._platforms,
            timeout_seconds=1,
            implementation_id=f"tests.{self._tool_id}",
            enabled=self._enabled,
        )

    @property
    def input_model(self) -> type[RegistryInput]:
        return RegistryInput

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: RegistryInput
    ) -> ToolResult:
        del context
        return ToolResult.success(RegistryOutput(value=validated_input.value))

    async def health_check(self) -> ToolHealth:
        if self.health_error is not None:
            raise RuntimeError(self.health_error)
        return self.health


def test_registration_lookup_and_metadata_snapshot() -> None:
    registry = ToolRegistry((RegistryTool(),))
    assert registry.get("registry-tool").manifest.tool_id == "registry-tool"
    assert registry.find_by_capability("demo")[0].manifest.tool_id == "registry-tool"
    snapshot = registry.snapshot()
    tools = cast(list[dict[str, object]], snapshot["tools"])
    assert tools[0]["implementation_id"] == "tests.registry-tool"
    assert tools[0]["usable"] is True


def test_duplicate_ids_never_replace_implementation() -> None:
    original = RegistryTool()
    registry = ToolRegistry((original,))
    with pytest.raises(DuplicateToolError):
        registry.register(RegistryTool(version=SemanticVersion(2, 0, 0)))
    assert registry.get("registry-tool") is original


def test_disabled_and_unsupported_tools_are_registered_but_unusable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    registry = ToolRegistry(
        (
            RegistryTool("disabled", enabled=False),
            RegistryTool("linux-only", platforms=frozenset({ToolPlatform.LINUX})),
        )
    )
    assert {record.manifest.tool_id for record in registry.list_unavailable()} == {
        "disabled",
        "linux-only",
    }
    assert registry.inspect("disabled").registration_status.value == "disabled"
    assert registry.inspect("linux-only").registration_status.value == "unsupported_platform"


def test_failed_initialization_is_retained_in_snapshot() -> None:
    registry = ToolRegistry()

    def broken_factory() -> Tool[RegistryInput, RegistryOutput]:
        raise RuntimeError("boom")

    registry.register_factory("broken", broken_factory)
    failures = cast(list[dict[str, str]], registry.snapshot()["initialization_failures"])
    assert failures == [
        {
            "id": "broken",
            "detail": "Tool factory failed (RuntimeError); provider details were withheld",
        }
    ]
    assert "boom" not in str(failures)
    with pytest.raises(CapabilityUnavailableError):
        registry.get("broken")


@pytest.mark.asyncio
async def test_health_transition_changes_usability() -> None:
    tool = RegistryTool()
    registry = ToolRegistry((tool,))
    tool.health = ToolHealth(ToolHealthStatus.UNAVAILABLE, "dependency stopped")
    await registry.health_check("registry-tool")
    assert registry.inspect("registry-tool").healthy is False
    assert registry.list_available() == ()


@pytest.mark.asyncio
async def test_health_failure_does_not_log_provider_exception_content(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "credential-must-not-enter-registry-logs"
    tool = RegistryTool()
    tool.health_error = secret
    registry = ToolRegistry((tool,))

    with caplog.at_level(logging.ERROR):
        result = await registry.health_check("registry-tool")

    assert result[0][1].status is ToolHealthStatus.UNAVAILABLE
    assert secret not in caplog.text


def test_best_matching_capability_is_highest_version() -> None:
    first = RegistryTool("first", SemanticVersion(1, 0, 0))
    newer = RegistryTool("newer", SemanticVersion(2, 0, 0))
    registry = ToolRegistry((first, newer))
    assert registry.resolve_best_matching_capability("demo") is newer


def test_unregister_reports_existing_and_missing_tools() -> None:
    registry = ToolRegistry((RegistryTool(),))

    assert registry.unregister("registry-tool") is True
    assert registry.unregister("registry-tool") is False


def test_factory_manifest_mismatch_is_retained_as_initialization_failure() -> None:
    registry = ToolRegistry()
    registry.register_factory("expected", lambda: RegistryTool("actual"))

    assert registry.snapshot()["initialization_failures"] == [
        {
            "id": "expected",
            "detail": (
                "Tool factory failed (ToolRegistrationError); provider details were withheld"
            ),
        }
    ]
    with pytest.raises(CapabilityUnavailableError):
        registry.get("expected")
