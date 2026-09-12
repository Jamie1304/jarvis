"""Controlled Windows application management; no package capability is auto-registered."""

from jarvis.applications.catalog import create_application_tools
from jarvis.applications.configuration import (
    ApplicationConfigurationAdapter,
    ConfigurationRegistry,
)
from jarvis.applications.manager import ApplicationManager
from jarvis.applications.plans import InstallationPlanStore
from jarvis.applications.providers import (
    ApplicationInventoryProvider,
    PackageProvider,
    WindowsRegistryInventoryProvider,
    WingetPackageProvider,
)
from jarvis.applications.runtime import ApplicationRuntime, WindowsApplicationRuntime

__all__ = [
    "ApplicationConfigurationAdapter",
    "ApplicationInventoryProvider",
    "ApplicationManager",
    "ApplicationRuntime",
    "ConfigurationRegistry",
    "InstallationPlanStore",
    "PackageProvider",
    "WindowsApplicationRuntime",
    "WindowsRegistryInventoryProvider",
    "WingetPackageProvider",
    "create_application_tools",
]
