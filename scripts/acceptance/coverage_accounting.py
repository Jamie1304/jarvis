"""Machine-readable coverage classification for qualification evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

CRITICAL_FILES = frozenset(
    {
        "jarvis/acceptance/campaign.py",
        "jarvis/acceptance/coordinator.py",
        "jarvis/acceptance/evidence.py",
        "jarvis/qualification_manifest.py",
    }
)


def classify_uncovered_file(
    file_name: str, missing_lines: list[int], missing_branches: list[list[int]]
) -> str:
    """Classify only an uncovered region; a covered file has no such region."""

    if not missing_lines and not missing_branches:
        return "PROVEN_BY_SEPARATE_REAL_EXECUTION"
    if file_name in CRITICAL_FILES:
        return "CRITICAL_UNTESTED"
    if file_name in {
        "jarvis/capability_acquisition.py",
        "jarvis/production_capability.py",
    }:
        return "HIGH_VALUE_UNTESTED"
    return "DEFENSIVE_PLATFORM_SPECIFIC"


def coverage_rows(coverage_json: Mapping[str, Any]) -> list[dict[str, object]]:
    """Return one row per covered/uncovered source file from coverage JSON."""

    files = coverage_json.get("files")
    if not isinstance(files, Mapping):
        raise ValueError("coverage JSON files are malformed")
    rows: list[dict[str, object]] = []
    for raw_name, raw_file in sorted(files.items()):
        if not isinstance(raw_name, str) or not isinstance(raw_file, Mapping):
            raise ValueError("coverage JSON file entry is malformed")
        summary = raw_file.get("summary")
        if not isinstance(summary, Mapping):
            raise ValueError("coverage JSON summary is malformed")
        missing = raw_file.get("missing_lines", [])
        branches = raw_file.get("missing_branches", [])
        if not isinstance(missing, list) or not all(type(item) is int for item in missing):
            raise ValueError("coverage JSON missing lines are malformed")
        if not isinstance(branches, list) or not isinstance(summary.get("num_statements"), int):
            raise ValueError("coverage JSON branch data is malformed")
        file_name = raw_name.replace("\\", "/")
        classification = classify_uncovered_file(file_name, missing, branches)
        rows.append(
            {
                "file": file_name,
                "statements": summary.get("num_statements"),
                "covered_statements": summary.get("covered_lines"),
                "missing_statements": len(missing),
                "uncovered_regions": bool(missing or branches),
                "branches": summary.get("num_branches"),
                "covered_branches": summary.get("covered_branches"),
                "partial_branches": summary.get("num_partial_branches"),
                "missing_lines": missing,
                "missing_branches": branches,
                "classification": classification,
            }
        )
    return rows


def classification_counts(rows: list[dict[str, object]]) -> dict[str, int]:
    """Count final classifications from the rows themselves."""

    counts: dict[str, int] = {}
    for row in rows:
        classification = row.get("classification")
        if not isinstance(classification, str):
            raise ValueError("coverage classification is malformed")
        counts[classification] = counts.get(classification, 0) + (
            1 if row.get("uncovered_regions", row.get("missing_statements", 0)) else 0
        )
    return counts


def validate_classification_accounting(
    rows: list[dict[str, object]], aggregate: Mapping[str, object]
) -> None:
    """Reject an aggregate that disagrees with its classified uncovered rows."""

    counts = classification_counts(rows)
    if aggregate.get("critical_untested_count") != counts.get("CRITICAL_UNTESTED", 0):
        raise ValueError("critical coverage aggregate disagrees with classified rows")
    if aggregate.get("high_value_untested_count") != counts.get("HIGH_VALUE_UNTESTED", 0):
        raise ValueError("high-value coverage aggregate disagrees with classified rows")
