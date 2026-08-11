"""Trusted loader for structured regressions representing previously fixed failures."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from jarvis.testing.models import TestCategory


@dataclass(frozen=True, slots=True)
class RegressionFixture:
    fixture_id: str
    title: str
    category: TestCategory
    suite_id: str
    scenario_id: str
    expected_status: str
    source_issue: str | None = None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", self.fixture_id):
            raise ValueError("Regression fixture ID must be a safe identifier")
        if not self.title.strip() or not self.suite_id.strip() or not self.scenario_id.strip():
            raise ValueError("Regression fixture fields must be non-empty")
        if self.expected_status != "passed":
            raise ValueError("Regression fixtures must assert a passing fixed behavior")


class RegressionFixtureStore:
    """Load repository fixtures only; the model cannot introduce arbitrary fixture paths."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory.resolve()

    def load(self) -> tuple[RegressionFixture, ...]:
        fixtures: list[RegressionFixture] = []
        for path in sorted(self._directory.glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError(f"Regression fixture is not an object: {path.name}")
            fixtures.append(
                RegressionFixture(
                    fixture_id=str(payload["fixture_id"]),
                    title=str(payload["title"]),
                    category=TestCategory(str(payload["category"])),
                    suite_id=str(payload["suite_id"]),
                    scenario_id=str(payload["scenario_id"]),
                    expected_status=str(payload["expected_status"]),
                    source_issue=str(payload["source_issue"])
                    if payload.get("source_issue") is not None
                    else None,
                )
            )
        return tuple(fixtures)
