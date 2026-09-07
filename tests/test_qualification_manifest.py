import re
from dataclasses import replace
from pathlib import Path

from jarvis.qualification_manifest import (
    direct_base_executable,
    manifest_dict,
    qualification_manifest,
    resolve_qualification_manifest,
    write_manifest,
)
from jarvis.qualification_routes import (
    validate_cp1_inventory,
    validate_machine_routes,
    validate_manifest_routes,
    validate_quality_evidence,
    validate_semantic_contracts,
)


def test_pre_self_repair_manifest_defines_all_required_stages() -> None:
    stages = qualification_manifest()
    assert len(stages) == 30
    assert [stage.stage_id for stage in stages] == [f"Q{number:02}" for number in range(1, 31)]
    for stage in stages:
        assert stage.runner and stage.evidence_schema and stage.pass_criteria
        assert stage.timeout_seconds > 0
        assert stage.blocking_states
        assert stage.interpreter


def test_manifest_binds_real_topology_and_quality_evidence_consumers() -> None:
    stages = {stage.stage_id: stage for stage in qualification_manifest()}
    assert "real_qualification" in stages["Q10"].runner
    assert stages["Q09"].formal_kind == "THREE_OF_THREE"
    assert stages["Q09"].required_member_count == 3
    assert stages["Q09"].formal_result_units == 1
    assert stages["Q10"].formal_kind == "SAME_RUNTIME_PAIR"
    assert stages["Q10"].required_member_count == 2
    assert stages["Q10"].formal_result_units == 1
    assert stages["Q11"].formal_kind == "FINAL_TEN"
    assert stages["Q11"].required_member_count == 10
    assert stages["Q11"].formal_result_units == 1
    assert stages["Q17"].execution_kind == "validation"
    assert stages["Q20"].execution_kind == "validation"
    assert "tests/test_sandbox.py" in stages["Q18"].runner


def test_every_real_qualification_marker_has_one_manifest_route() -> None:
    source = (Path(__file__).parent / "test_acceptance_evidence.py").read_text(encoding="utf-8")
    marked_tests = re.findall(
        r"@pytest\.mark\.real_qualification\s+async def (test_[a-z0-9_]+)", source
    )
    assert marked_tests == ["test_real_same_runtime_pair_control"]
    q10_runner = next(stage.runner for stage in qualification_manifest() if stage.stage_id == "Q10")
    assert all(f"tests/test_acceptance_evidence.py::{name}" in q10_runner for name in marked_tests)


def test_manifest_serialization_and_stage_projection_are_typed(tmp_path: Path) -> None:
    stage = qualification_manifest()[0]
    encoded = stage.as_dict()
    assert encoded["stage_id"] == "Q01"
    manifest = manifest_dict()
    assert manifest["schema"] == "r4r-pre-self-repair-qualification-manifest-1"
    assert isinstance(manifest["stages"], list)
    assert len(manifest["stages"]) == 30
    output = tmp_path / "nested" / "qualification-manifest.json"
    write_manifest(output)
    assert output.exists()
    assert output.read_text(encoding="utf-8").endswith("\n")


def test_manifest_route_preflight_accepts_complete_manifest_without_execution() -> None:
    result = validate_manifest_routes(Path.cwd())
    assert result.passed
    assert result.inspected == 30
    assert result.invokable == 27
    assert result.well_defined == 3
    assert result.bare_pytest == 0
    assert result.bare_python == 0
    assert result.missing_executables == ()
    assert result.missing_targets == ()
    assert result.as_dict()["executed_targets"] is False


def test_route_preflight_rejects_bare_and_missing_routes() -> None:
    stages = list(qualification_manifest())
    stages[1] = replace(
        stages[1],
        stage_id="QX",
        runner="pytest tests/test_recovery.py",
        required_executable="C:/missing/python.exe",
    )
    result = validate_manifest_routes(Path.cwd(), tuple(stages), machine=True)
    assert result.bare_pytest == 1
    assert result.missing_executables


def test_validation_routes_are_truthful_and_q19_keeps_venv() -> None:
    stages = {stage.stage_id: stage for stage in qualification_manifest()}
    assert stages["Q17"].validation_input == "Q16 static evidence"
    assert stages["Q20"].validation_input == "Q16 coverage evidence"
    assert stages["Q28"].execution_kind == "validation"
    assert stages["Q19"].required_executable == r".venv\Scripts\python.exe"


def test_route_preflight_rejects_bare_python_missing_target_and_prose() -> None:
    base = qualification_manifest()[0]
    cases = (
        replace(
            base,
            stage_id="QX",
            runner="python scripts/acceptance/validate_specs.py",
            required_executable=None,
        ),
        replace(
            base,
            stage_id="QY",
            runner="C:/missing/python.exe scripts/missing.py",
            required_executable="C:/missing/python.exe",
            referenced_targets=("scripts/missing.py",),
        ),
        replace(
            base,
            stage_id="QZ",
            runner="production contamination scanner",
            required_executable=None,
            referenced_targets=(),
        ),
    )
    result = validate_manifest_routes(Path.cwd(), cases)
    assert result.bare_python == 1
    assert result.missing_executables == ()
    assert result.missing_targets == ("QY:scripts/missing.py",)
    assert result.placeholder_runners == ("QX", "QZ")


def test_structural_routes_do_not_require_host_interpreters() -> None:
    result = validate_manifest_routes(Path.cwd())
    assert result.passed
    assert result.missing_executables == ()


def test_machine_routes_resolve_current_workstation() -> None:
    result = validate_machine_routes(Path.cwd())
    assert result.inspected == 30
    assert result.invokable == 27
    assert result.well_defined == 3
    q19_executable = Path.cwd() / ".venv" / "Scripts" / "python.exe"
    if q19_executable.is_file():
        assert result.passed
        assert result.invokable == 27
        assert result.missing_executables == ()
    else:
        assert not result.passed
        assert result.invokable == 26
        assert result.missing_executables == ("Q19",)


def test_machine_routes_remain_fail_closed_for_missing_executables() -> None:
    stage = replace(
        qualification_manifest()[0],
        stage_id="QX",
        required_executable="C:/definitely-missing/python.exe",
    )
    result = validate_manifest_routes(Path.cwd(), (stage,), machine=True)
    assert result.missing_executables == ("QX",)


def test_direct_base_resolution_is_host_derived_and_portable() -> None:
    resolved = {stage.stage_id: stage for stage in resolve_qualification_manifest()}
    executable = str(direct_base_executable())
    assert resolved["Q01"].required_executable == executable
    assert resolved["Q01"].runner.startswith(executable)
    assert "C:\\Users\\jamie" not in Path("jarvis/qualification_manifest.py").read_text(
        encoding="utf-8"
    )
    assert resolved["Q19"].required_executable == r".venv\Scripts\python.exe"


def test_semantic_contract_preflight_closes_critical_routes_without_execution() -> None:
    result = validate_semantic_contracts(Path.cwd())
    assert result["stages"] == 30
    assert result["semantically_incomplete"] == ()
    assert result["semantically_incomplete_count"] == 0
    assert result["formal_routes_complete"] is True
    assert result["validation_routes_machine_resolvable"] is True
    assert result["executed_targets"] is False


def test_machine_validation_contracts_cover_quality_and_cp1_inventory() -> None:
    assert validate_quality_evidence(
        "static", {"ruff_format": "PASS", "ruff": "PASS", "mypy": "PASS"}
    )
    assert validate_quality_evidence(
        "coverage", {"coverage_percent": 90, "critical_uncovered_count": 0}
    )
    inventory = validate_cp1_inventory((".env.example", "jarvis/core.py", "artifacts/a.json"))
    assert sorted(inventory["MANUAL_DECISION"]) == [".env.example"]
    assert sorted(inventory["CP1_INCLUDE"]) == ["jarvis/core.py"]
    assert sorted(inventory["CP1_EXCLUDE"]) == ["artifacts/a.json"]


def test_critical_stage_contracts_retain_semantic_bindings() -> None:
    stages = {stage.stage_id: stage for stage in qualification_manifest()}
    assert stages["Q09"].formal_kind == "THREE_OF_THREE"
    assert stages["Q10"].formal_kind == "SAME_RUNTIME_PAIR"
    assert stages["Q11"].formal_kind == "FINAL_TEN"
    assert "symbol/executable binding" in stages["Q25"].semantic_contract
    assert "audit_test_strength.py::audit_test_strength" in (
        stages["Q26"].validation_callable or ""
    )
    assert stages["Q27"].semantic_contract == ("final contamination and terminal residue",)
    assert stages["Q28"].validation_callable == "jarvis.qualification_routes:validate_cp1_inventory"
    assert stages["Q29"].runner.endswith("scripts/acceptance/audit_foundation_vision.py")
    assert stages["Q30"].structured_commands == (
        ("git", "status", "--short"),
        ("git", "diff", "--check"),
        ("git", "diff", "--name-only"),
    )
