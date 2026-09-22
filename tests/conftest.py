"""Shared test isolation for inherited local JARVIS configuration."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def isolate_jarvis_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent a developer's process configuration from changing test fixtures."""

    for name in tuple(os.environ):
        if name.startswith("JARVIS_") and not name.startswith("JARVIS_R4R_"):
            monkeypatch.delenv(name, raising=False)
