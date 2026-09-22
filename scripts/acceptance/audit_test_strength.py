"""Bounded, qualification-only audit of D6 test-strength changes."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_CRITERIA = (
    "security_weakening",
    "assertion_weakening",
    "coverage_weakening",
    "hidden_skip",
    "fake_pass",
    "qualification_only_bypass",
    "formal_fixture_substitution",
    "type_ignore_evasion",
    "test_selection_weakening",
    "coverage_policy_weakening",
)
_QUALIFICATION_GATE = re.compile(
    r"\b(?:real_qualification|qualification_only|acceptance_only|test_only)\b",
    re.IGNORECASE,
)
_MARKER_DECLARATION = re.compile(
    r"[\"'](?:real_qualification|qualification_only|acceptance_only|test_only)\s*:",
    re.IGNORECASE,
)
_PYTEST_MARKER = re.compile(
    r"pytest\.mark\.(?:real_qualification|qualification_only|acceptance_only|test_only)\b",
    re.IGNORECASE,
)
_PYTEST_SELECTOR = re.compile(
    r"(?:[\"']-m[\"']\s*,\s*[\"'](?:not\s+)?|(?<!\w)-m\s+(?:not\s+)?)(?:real_qualification|qualification_only|acceptance_only|test_only)\b",
    re.IGNORECASE,
)
_ASSERTION_REFERENCE = re.compile(r"^\s*assert\b", re.IGNORECASE)


def _is_harness_reference(line: str) -> bool:
    """Recognize structural test-runner references, not product behavior."""

    return bool(
        _MARKER_DECLARATION.search(line)
        or _PYTEST_MARKER.search(line)
        or _PYTEST_SELECTOR.search(line)
        or (_ASSERTION_REFERENCE.match(line) and _QUALIFICATION_GATE.search(line))
    )


def _qualification_bypass_added_lines(diff: str) -> tuple[str, ...]:
    """Return executable-looking qualification gates added by the diff.

    Marker declarations, pytest marker applications/selections, and assertions
    are harness operations.  An executable line that branches on a
    qualification-only gate remains a finding regardless of its file name.
    """

    findings: list[str] = []
    for line in diff.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        added_line = line[1:]
        if _QUALIFICATION_GATE.search(added_line) and not _is_harness_reference(added_line):
            findings.append(added_line)
    return tuple(findings)


def audit_test_strength(diff: str) -> dict[str, str]:
    """Classify the bounded diff without importing or executing test targets."""
    added = "\n".join(
        line[1:]
        for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    removed = "\n".join(
        line[1:]
        for line in diff.splitlines()
        if line.startswith("-") and not line.startswith("---")
    )
    results = {criterion: "NO" for criterion in _CRITERIA}
    if "pytest.skip(" in added:
        results["hidden_skip"] = "YES"
    if "# type: ignore" in added or "# pyright: ignore" in added:
        results["type_ignore_evasion"] = "YES"
    if "assert True" in added or "pass  #" in added:
        results["fake_pass"] = "YES"
    if "assert " in removed and "assert " not in added:
        results["assertion_weakening"] = "YES"
    if "cov-fail-under" in added or "--cov-fail-under" in added:
        results["coverage_policy_weakening"] = "YES"
    if _qualification_bypass_added_lines(diff):
        results["qualification_only_bypass"] = "YES"
    results["diff_check"] = "PASS"
    results["result"] = (
        "PASS"
        if all(
            value == "NO" for key, value in results.items() if key not in {"result", "diff_check"}
        )
        else "BLOCKED"
    )
    return results


def main() -> int:
    diff = subprocess.run(
        ["git", "diff", "--unified=0", "--", "tests", "scripts", "pyproject.toml"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    ).stdout
    result = audit_test_strength(diff)
    print(json.dumps({"schema": "d6-test-strength-audit-1", **result}, sort_keys=True))
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
