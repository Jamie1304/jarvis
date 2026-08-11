"""Explicit factory for optional application-manager tools; never default registered."""

from typing import Any

from jarvis.applications.manager import ApplicationManager
from jarvis.applications.tools import (
    CloseManagedApplicationTool,
    FindApplicationTool,
    InstallApplicationTool,
    LaunchManagedApplicationTool,
    PlanInstallTool,
    PlanUpdateTool,
    UpdateApplicationTool,
)
from jarvis.tools.base import Tool


def create_application_tools(manager: ApplicationManager) -> tuple[Tool[Any, Any], ...]:
    """Return opt-in tools; trusted composition must separately provide the broker policy."""

    return (
        FindApplicationTool(manager),
        PlanInstallTool(manager),
        PlanUpdateTool(manager),
        InstallApplicationTool(manager),
        UpdateApplicationTool(manager),
        LaunchManagedApplicationTool(manager),
        CloseManagedApplicationTool(manager),
    )
