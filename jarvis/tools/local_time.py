"""Safe local-time capability without network access."""

from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field

from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
    ToolEvidence,
    ToolExecutionContext,
    ToolManifest,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)


class LocalTimeInput(BaseModel):
    """Optional IANA timezone input; omitted means the operating-system local timezone."""

    model_config = ConfigDict(extra="forbid", strict=True)

    timezone: str | None = Field(default=None, max_length=128)


class LocalTimeOutput(BaseModel):
    """Typed time response."""

    model_config = ConfigDict(extra="forbid", strict=True)

    local_time: str
    timezone: str


class LocalTimeTool(Tool[LocalTimeInput, LocalTimeOutput]):
    """Read local or explicitly named time using Python's standard library."""

    _manifest = ToolManifest(
        tool_id="local_time",
        name="Local time",
        description="Returns the local time or time in an explicitly named IANA timezone.",
        version=SemanticVersion(1, 0, 0),
        capability_tags=frozenset({"time", "local", "safe"}),
        input_schema=LocalTimeInput,
        output_schema=LocalTimeOutput,
        declared_permissions=frozenset(),
        supported_platforms=frozenset(
            {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
        ),
        timeout_seconds=1.0,
        implementation_id="jarvis.tools.local_time.LocalTimeTool",
    )

    @property
    def manifest(self) -> ToolManifest:
        return self._manifest

    @property
    def input_model(self) -> type[LocalTimeInput]:
        return LocalTimeInput

    async def execute(
        self, context: ToolExecutionContext, validated_input: LocalTimeInput
    ) -> ToolResult:
        del context
        try:
            zone = ZoneInfo(validated_input.timezone) if validated_input.timezone else None
        except ZoneInfoNotFoundError:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "unknown_timezone",
                "The requested IANA timezone is not available",
            )
        current = datetime.now(zone) if zone else datetime.now().astimezone()
        output = LocalTimeOutput(local_time=current.isoformat(), timezone=str(current.tzinfo))
        return ToolResult.success(
            output,
            evidence=(ToolEvidence("local_time", output.local_time),),
        )
