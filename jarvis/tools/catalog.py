"""Explicit Phase 3 catalog of safe, non-privileged tools."""

from jarvis.tools.calculator import CalculatorTool
from jarvis.tools.local_time import LocalTimeTool
from jarvis.tools.registry import ToolRegistry
from jarvis.tools.weather import UnavailableWeatherTool


def create_safe_tool_registry() -> ToolRegistry:
    """Return the fixed Phase 3 tool set without dynamic capability discovery."""

    return ToolRegistry((CalculatorTool(), LocalTimeTool(), UnavailableWeatherTool()))
