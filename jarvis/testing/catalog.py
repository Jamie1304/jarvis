"""Trusted deterministic suite catalog used by local and CI self-tests."""

from __future__ import annotations

import sys

from jarvis.testing.models import SuiteOutputFormat, TestCategory, TestCommand, TestSuite
from jarvis.testing.runner import TestSuiteCatalog

_V1_ACCEPTANCE_TIMEOUT_SECONDS = 600


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
                    ("-m", "pytest", "tests/test_permissions.py"),
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
                    ("-m", "pytest", "tests/test_v1_acceptance.py"),
                ),
                # Production-composition package generation, Windows sandbox
                # certification, staged activation, and restart evidence are
                # intentionally slower than lower-level deterministic suites.
                # The complete direct suite measured 286.98 seconds on the
                # supported Windows validation host and 461.06 seconds in the
                # R4Q constrained validation environment.  Retain a finite
                # ten-minute execution bound with measured headroom; this is
                # not a product or security authorization timeout.
                timeout_seconds=_V1_ACCEPTANCE_TIMEOUT_SECONDS,
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
