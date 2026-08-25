"""Trusted deterministic suite catalog used by local and CI self-tests."""

from __future__ import annotations

import sys

from jarvis.testing.models import SuiteOutputFormat, TestCategory, TestCommand, TestSuite
from jarvis.testing.runner import TestSuiteCatalog


def create_deterministic_suite_catalog() -> TestSuiteCatalog:
    """Return only test suites that never need real hardware or privileged tools."""

    return TestSuiteCatalog(
        (
            TestSuite(
                suite_id="deterministic-workflows",
                category=TestCategory.AGENT_WORKFLOWS,
                command=TestCommand(
                    sys.executable,
                    (
                        "-m",
                        "pytest",
                        "tests/test_orchestrator.py",
                        "tests/test_tools.py",
                        "-q",
                    ),
                ),
                timeout_seconds=90,
                output_format=SuiteOutputFormat.PYTEST_TEXT,
                description="Fake-provider agent workflow and safe-tool regression tests.",
            ),
            TestSuite(
                suite_id="deterministic-permissions",
                category=TestCategory.PERMISSIONS,
                command=TestCommand(
                    sys.executable,
                    ("-m", "pytest", "tests/test_permissions.py", "-q"),
                ),
                timeout_seconds=90,
                output_format=SuiteOutputFormat.PYTEST_TEXT,
                description="Permission broker policy, approval, and audit boundary tests.",
            ),
            TestSuite(
                suite_id="v1-acceptance",
                category=TestCategory.INTEGRATION,
                command=TestCommand(
                    sys.executable,
                    ("-m", "pytest", "tests/test_v1_acceptance.py", "-q"),
                ),
                timeout_seconds=180,
                output_format=SuiteOutputFormat.PYTEST_TEXT,
                description=(
                    "Deterministic v1 acceptance through the default application composition root."
                ),
            ),
            TestSuite(
                suite_id="windows-hardware-manual",
                category=TestCategory.UI,
                command=TestCommand(
                    sys.executable,
                    ("-m", "pytest", "tests/test_windows_integration.py", "-q"),
                ),
                timeout_seconds=120,
                hardware_dependent=True,
                description="Optional real desktop/hardware integration check.",
            ),
        )
    )
