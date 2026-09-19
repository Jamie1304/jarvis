"""Regression checks for the canonical clean-runner typing contract."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


def test_optional_adapter_mypy_exclusions_are_separator_portable() -> None:
    configuration = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    patterns = configuration["tool"]["mypy"]["exclude"]
    expected_paths = (
        "jarvis/desktop.py",
        "jarvis\\desktop.py",
        "jarvis/frontend/desktop.py",
        "jarvis\\frontend\\desktop.py",
        "jarvis/speech/stt.py",
        "jarvis\\speech\\stt.py",
        "jarvis/speech/tts.py",
        "jarvis\\speech\\tts.py",
    )

    for path in expected_paths:
        assert any(re.search(pattern, path) for pattern in patterns)


def test_quality_mypy_uses_recursive_package_discovery() -> None:
    quality_source = Path("scripts/quality.py").read_text(encoding="utf-8")

    assert '"--package", "jarvis", "--package", "tests"' in quality_source
