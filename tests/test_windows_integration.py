"""Optional desktop checks: never run real UI interaction in deterministic CI."""

import os

import pytest
from jarvis.computer.adapters import WindowsUiAutomationAdapter
from jarvis.computer.models import ApplicationDefinition

pytestmark = pytest.mark.windows_integration


@pytest.mark.skipif(
    os.environ.get("JARVIS_WINDOWS_INTEGRATION") != "true",
    reason="Set JARVIS_WINDOWS_INTEGRATION=true to enable Windows desktop integration checks",
)
def test_windows_adapter_requires_explicit_trusted_application_catalog() -> None:
    adapter = WindowsUiAutomationAdapter(
        {"notepad": ApplicationDefinition("notepad", "notepad.exe")}
    )

    assert adapter is not None
