"""Weather capability placeholder kept unavailable until a network provider is approved."""

from pydantic import BaseModel, ConfigDict, Field

from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
    ToolExecutionContext,
    ToolHealth,
    ToolHealthStatus,
    ToolManifest,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)


class WeatherInput(BaseModel):
    """Future weather request schema."""

    model_config = ConfigDict(extra="forbid", strict=True)

    location: str = Field(min_length=1, max_length=256)


class WeatherOutput(BaseModel):
    """Future weather response schema."""

    model_config = ConfigDict(extra="forbid", strict=True)

    summary: str


class UnavailableWeatherTool(Tool[WeatherInput, WeatherOutput]):
    """Explicitly unavailable placeholder; it makes no network request."""

    _manifest = ToolManifest(
        tool_id="weather",
        name="Weather",
        description="Weather lookup placeholder pending an approved network provider.",
        version=SemanticVersion(1, 0, 0),
        capability_tags=frozenset({"weather", "network"}),
        input_schema=WeatherInput,
        output_schema=WeatherOutput,
        declared_permissions=frozenset(),
        supported_platforms=frozenset(
            {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
        ),
        timeout_seconds=2.0,
        implementation_id="jarvis.tools.weather.UnavailableWeatherTool",
    )

    @property
    def manifest(self) -> ToolManifest:
        return self._manifest

    @property
    def input_model(self) -> type[WeatherInput]:
        return WeatherInput

    async def health_check(self) -> ToolHealth:
        return ToolHealth(
            ToolHealthStatus.UNAVAILABLE,
            "Weather is unavailable until a network provider is approved",
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: WeatherInput
    ) -> ToolResult:
        del context, validated_input
        return ToolResult.failure(
            ToolResultStatus.UNAVAILABLE,
            "weather_unavailable",
            "Weather is unavailable until a network provider is approved",
        )
