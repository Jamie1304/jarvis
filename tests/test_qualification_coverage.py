from __future__ import annotations

import pytest
from scripts.acceptance.coverage_accounting import (
    classification_counts,
    coverage_rows,
    validate_classification_accounting,
)


def _coverage_file(*, missing_lines: list[int], statements: int = 4) -> dict[str, object]:
    return {
        "summary": {
            "num_statements": statements,
            "covered_lines": statements - len(missing_lines),
            "num_branches": 2,
            "covered_branches": 2,
            "num_partial_branches": 0,
        },
        "missing_lines": missing_lines,
        "missing_branches": [],
    }


def test_coverage_accounting_counts_rows_not_focused_test_status() -> None:
    rows = coverage_rows(
        {
            "files": {
                "jarvis\\acceptance\\evidence.py": _coverage_file(missing_lines=[235]),
                "jarvis\\capability_acquisition.py": _coverage_file(missing_lines=[173]),
                "jarvis\\acceptance\\coordinator.py": _coverage_file(missing_lines=[]),
            }
        }
    )
    counts = classification_counts(rows)
    assert counts["CRITICAL_UNTESTED"] == 1
    assert counts["HIGH_VALUE_UNTESTED"] == 1
    assert counts["PROVEN_BY_SEPARATE_REAL_EXECUTION"] == 0
    validate_classification_accounting(
        rows,
        {"critical_untested_count": 1, "high_value_untested_count": 1},
    )


def test_coverage_accounting_rejects_internal_critical_count_contradiction() -> None:
    rows = coverage_rows(
        {"files": {"jarvis\\acceptance\\campaign.py": _coverage_file(missing_lines=[69])}}
    )
    with pytest.raises(ValueError, match="critical coverage aggregate"):
        validate_classification_accounting(
            rows,
            {"critical_untested_count": 0, "high_value_untested_count": 0},
        )


def test_coverage_accounting_treats_uncovered_branch_as_an_uncovered_region() -> None:
    rows = coverage_rows(
        {
            "files": {
                "jarvis\\acceptance\\campaign.py": {
                    **_coverage_file(missing_lines=[]),
                    "missing_branches": [[10, 12]],
                }
            }
        }
    )
    assert rows[0]["classification"] == "CRITICAL_UNTESTED"
    assert classification_counts(rows)["CRITICAL_UNTESTED"] == 1
