"""Validated adapters from one untrusted MCP tool into the brokered Tool API."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field, create_model

from jarvis.mcp.client import MCPClient, MCPProtocolError
from jarvis.mcp.models import MCPExtensionConfig
from jarvis.permissions.models import (
    ActionDescriptor,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
)
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
    ToolEffectDisposition,
    ToolExecutionContext,
    ToolManifest,
    ToolMetadata,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)


class MCPToolOutput(BaseModel):
    """Bounded, opaque MCP output; callers must not treat it as policy."""

    model_config = ConfigDict(extra="forbid", strict=True)

    text: str = Field(max_length=65_536)
    structured_json: str = Field(max_length=65_536)


def input_model_from_schema(schema: Mapping[str, object]) -> type[BaseModel]:
    """Build a strict bounded model from the server's untrusted object schema."""

    if schema.get("type") not in (None, "object"):
        raise ValueError("MCP input schema must be an object")
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(properties, dict) or not isinstance(required, list):
        raise ValueError("MCP input schema shape is invalid")
    if (
        len(properties) > 64
        or any(not isinstance(item, str) for item in required)
        or any(item not in properties for item in required)
    ):
        raise ValueError("MCP input schema is too large")
    fields: dict[str, tuple[Any, Any]] = {}
    for name, definition in properties.items():
        if (
            not isinstance(name, str)
            or not name.isidentifier()
            or len(name) > 64
            or not isinstance(definition, dict)
        ):
            raise ValueError("MCP input property is invalid")
        raw_kind = definition.get("type")
        if raw_kind is not None and not isinstance(raw_kind, str):
            raise ValueError("MCP input property type is invalid")
        kind = raw_kind or ""
        python_type: object = {
            "string": str,
            "integer": int,
            "number": float,
            "boolean": bool,
            "object": dict[str, object],
            "array": list[object],
        }.get(kind, object)
        if name in required:
            fields[name] = (python_type, ...)
        else:
            fields[name] = (python_type | None, None)  # type: ignore[operator]
    return cast(
        type[BaseModel],
        create_model(  # type: ignore[call-overload]
            "MCPInput",
            __config__=ConfigDict(extra="forbid", strict=True),
            **fields,
        ),
    )


class MCPToolAdapter(Tool[BaseModel, MCPToolOutput]):
    """One MCP tool; it receives only a client and never a JARVIS service."""

    def __init__(
        self,
        config: MCPExtensionConfig,
        client: MCPClient,
        name: str,
        description: str,
        input_model: type[BaseModel],
    ) -> None:
        if not name or len(name) > 128 or any(ord(char) < 32 for char in name):
            raise ValueError("MCP tool name is invalid")
        if not isinstance(description, str) or len(description) > 2048:
            raise ValueError("MCP tool description is invalid")
        self._config = config
        self._client = client
        self._input_model = input_model
        self._name = name
        self._manifest = ToolManifest(
            tool_id=f"mcp:{config.extension_id}:{name}",
            name=f"MCP {config.extension_id}/{name}",
            description="External MCP tool; server description is untrusted data",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"mcp", f"mcp.{config.extension_id}"}),
            input_schema=input_model,
            output_schema=MCPToolOutput,
            declared_permissions=config.permissions,
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=config.timeout_seconds,
            implementation_id=f"jarvis.mcp:{config.extension_id}/{name}",
        )

    @property
    def manifest(self) -> ToolManifest:
        return self._manifest

    @property
    def input_model(self) -> type[BaseModel]:
        return self._input_model

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: BaseModel
    ) -> ActionDescriptor:
        del context
        arguments = tuple(
            SafeArgument(key, type(value).__name__)
            for key, value in sorted(validated_input.model_dump(mode="python").items())
        )
        return ActionDescriptor(
            action=f"mcp:{self._config.extension_id}/{self._name}",
            arguments_summary=arguments,
            risk=Risk.MEDIUM if self._config.permissions else Risk.LOW,
            permissions=tuple(
                PermissionRequest(permission, PermissionScope(tool_id=self.manifest.tool_id))
                for permission in sorted(self._config.permissions, key=str)
            ),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: BaseModel
    ) -> ToolResult:
        del context
        try:
            result = await self._client.request(
                "tools/call",
                {"name": self._name, "arguments": validated_input.model_dump(mode="json")},
            )
            output = _bounded_output(result, self._config.max_result_bytes)
        except (MCPProtocolError, ValueError, TypeError, json.JSONDecodeError):
            return ToolResult.failure(
                ToolResultStatus.INTERNAL_FAILURE,
                "mcp_result_invalid",
                "MCP server returned an invalid or unavailable result",
                effect_disposition=(
                    ToolEffectDisposition.UNKNOWN
                    if self.manifest.declared_permissions
                    else ToolEffectDisposition.NO_EFFECT
                ),
            )
        return ToolResult(
            ToolResultStatus.SUCCESS,
            output=output,
            metadata=(ToolMetadata("source", "mcp"),),
            effect_disposition=ToolEffectDisposition.CONFIRMED_EFFECT,
        )


def _bounded_output(result: Mapping[str, object], max_bytes: int) -> MCPToolOutput:
    content = result.get("content", [])
    if not isinstance(content, list) or len(content) > 256:
        raise ValueError("MCP content is invalid")
    text_parts: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            raise ValueError("MCP content item is invalid")
        if item.get("type") == "text":
            text = item.get("text")
            if not isinstance(text, str):
                raise ValueError("MCP text content is invalid")
            text_parts.append(text)
        else:
            raise ValueError("MCP content type is unsupported")
    text = "\n".join(text_parts)
    structured = result.get("structuredContent", {})
    if not isinstance(structured, dict):
        raise ValueError("MCP structured content is invalid")
    structured_json = json.dumps(structured, separators=(",", ":"), ensure_ascii=True)
    if len(text.encode("utf-8")) + len(structured_json.encode("utf-8")) > max_bytes:
        raise ValueError("MCP result exceeded its bound")
    return MCPToolOutput(text=text, structured_json=structured_json)
