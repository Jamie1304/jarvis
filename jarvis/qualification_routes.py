"""Zero-execution validation for the machine qualification manifest."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from jarvis.qualification_manifest import QualificationStage, qualification_manifest

_PYTHON = re.compile(r"(?P<path>(?:[A-Za-z]:)?[^ ]*python\.exe)", re.IGNORECASE)
_TARGET = re.compile(r"(?:tests|scripts)/[A-Za-z0-9_./\\-]+(?:\.py)?")


@dataclass(frozen=True)
class RoutePreflight:
    inspected: int
    invokable: int
    well_defined: int
    bare_pytest: int
    bare_python: int
    prose_only: int
    missing_executables: tuple[str, ...]
    missing_targets: tuple[str, ...]
    placeholder_runners: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return (
            not (
                self.missing_executables
                or self.missing_targets
                or self.placeholder_runners
                or self.bare_pytest
                or self.bare_python
                or self.prose_only
            )
            and self.inspected == 30
            and self.invokable + self.well_defined == 30
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "inspected": self.inspected,
            "invokable": self.invokable,
            "well_defined": self.well_defined,
            "bare_pytest": self.bare_pytest,
            "bare_python": self.bare_python,
            "prose_only": self.prose_only,
            "missing_executables": list(self.missing_executables),
            "missing_targets": list(self.missing_targets),
            "placeholder_runners": list(self.placeholder_runners),
            "passed": self.passed,
            "executed_targets": False,
        }


def _is_python(stage: QualificationStage) -> bool:
    return "python" in stage.runner.lower() or stage.runner.lower().startswith(".venv")


def _target_paths(stage: QualificationStage) -> tuple[str, ...]:
    return stage.referenced_targets or tuple(_TARGET.findall(stage.runner))


def validate_quality_evidence(kind: str, evidence: Mapping[str, object]) -> bool:
    """Validate Q16's typed static or coverage projection without rerunning tools."""
    if kind == "static":
        return all(evidence.get(tool) == "PASS" for tool in ("ruff_format", "ruff", "mypy"))
    if kind == "coverage":
        percent = evidence.get("coverage_percent")
        critical = evidence.get("critical_uncovered_count")
        return isinstance(percent, int | float) and percent >= 90 and critical == 0
    return False


def validate_cp1_inventory(paths: tuple[str, ...]) -> dict[str, list[str]]:
    """Reuse the established Q0A CP1 policy and reject uncategorized paths."""
    categories: dict[str, list[str]] = {
        "CP1_INCLUDE": [],
        "CP1_EXCLUDE": [],
        "MANUAL_DECISION": [],
    }
    for path in paths:
        lowered = path.casefold()
        if path == ".env.example":
            category = "MANUAL_DECISION"
        elif (
            lowered.startswith("artifacts/")
            or "__pycache__" in lowered
            or lowered.startswith(("build/", "dist/", ".venv/"))
            or lowered.endswith((".log", ".pyc", ".sqlite3"))
            or any(
                token in lowered
                for token in ("vm-image", "rootfs", "runtime-receipt", "screenshot")
            )
        ):
            category = "CP1_EXCLUDE"
        else:
            category = "CP1_INCLUDE"
        categories[category].append(path)
    categorized = {path for values in categories.values() for path in values}
    if categorized != set(paths) or len(categorized) != len(paths):
        raise ValueError("CP1 inventory contains uncategorized or duplicate paths")
    return categories


def validate_semantic_contracts(root: Path) -> dict[str, object]:
    """Check manifest references to required evidence, without executing stages."""
    stages = {stage.stage_id: stage for stage in qualification_manifest()}
    incomplete: list[str] = []

    for stage_id in ("Q09", "Q10", "Q11"):
        stage = stages[stage_id]
        if (
            stage.formal_kind is None
            or stage.required_member_count is None
            or stage.formal_result_units != 1
        ):
            incomplete.append(stage_id)

    for stage_id in ("Q17", "Q20"):
        callable_name = stages[stage_id].validation_callable or ""
        if not callable_name.startswith("jarvis.qualification_routes:validate_quality_evidence"):
            incomplete.append(stage_id)
    if stages["Q28"].validation_callable != "jarvis.qualification_routes:validate_cp1_inventory":
        incomplete.append("Q28")
    if len(stages["Q30"].structured_commands) != 3:
        incomplete.append("Q30")

    for stage_id in ("Q25", "Q27"):
        stage = stages[stage_id]
        for evidence in stage.semantic_evidence:
            path, _, symbol = evidence.partition("::")
            source = root / path
            if not source.is_file() or (
                symbol and symbol not in source.read_text(encoding="utf-8")
            ):
                incomplete.append(stage_id)
                break
        if not stage.semantic_contract:
            incomplete.append(stage_id)
    q26 = stages["Q26"]
    if q26.validation_callable is None or not all(
        (root / target).is_file() for target in q26.referenced_targets
    ):
        incomplete.append("Q26")

    return {
        "stages": len(stages),
        "semantically_incomplete": tuple(dict.fromkeys(incomplete)),
        "semantically_incomplete_count": len(tuple(dict.fromkeys(incomplete))),
        "formal_routes_complete": not any(
            stage_id in incomplete for stage_id in ("Q09", "Q10", "Q11")
        ),
        "validation_routes_machine_resolvable": not any(
            stage_id in incomplete for stage_id in ("Q17", "Q20", "Q28")
        ),
        "executed_targets": False,
    }


def validate_manifest_routes(
    root: Path, stages: tuple[QualificationStage, ...] | None = None
) -> RoutePreflight:
    selected = stages if stages is not None else qualification_manifest()
    missing_executables: list[str] = []
    missing_targets: list[str] = []
    placeholder: list[str] = []
    bare_pytest = 0
    bare_python = 0
    invokable = 0
    well_defined = 0

    for stage in selected:
        runner = stage.runner
        lower = runner.lower()
        if stage.execution_kind != "execution":
            if not stage.validation_input or not stage.validation_callable:
                placeholder.append(stage.stage_id)
            else:
                well_defined += 1
            continue
        if lower.startswith("pytest "):
            bare_pytest += 1
        if re.search(r"(?<![\\/\w])python(?:\s|$)", lower) and "python.exe" not in lower:
            bare_python += 1
        if lower in {"production contamination scanner", "foundation invariant audit"}:
            placeholder.append(stage.stage_id)
        executable = stage.required_executable
        if executable is None:
            if lower.startswith("git "):
                executable = "git"
            else:
                match = _PYTHON.search(runner)
                executable = match.group("path") if match else None
            if executable is None:
                placeholder.append(stage.stage_id)
        if executable and executable != "git":
            executable_path = (
                Path(executable) if Path(executable).is_absolute() else root / executable
            )
            if not executable_path.is_file():
                missing_executables.append(stage.stage_id)
        elif executable == "git":
            # The route is only checked, never spawned; git is a required host tool.
            pass
        for target in _target_paths(stage):
            if not (root / target.replace("\\", "/")).exists():
                missing_targets.append(f"{stage.stage_id}:{target}")
        if stage.stage_id in {"Q09", "Q10", "Q11"} and stage.formal_result_units != 1:
            placeholder.append(stage.stage_id)
        if stage.stage_id not in placeholder and stage.stage_id not in missing_executables:
            invokable += 1

    return RoutePreflight(
        inspected=len(selected),
        invokable=invokable,
        well_defined=well_defined,
        bare_pytest=bare_pytest,
        bare_python=bare_python,
        prose_only=len(placeholder),
        missing_executables=tuple(missing_executables),
        missing_targets=tuple(missing_targets),
        placeholder_runners=tuple(placeholder),
    )
