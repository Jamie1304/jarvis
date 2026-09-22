"""Machine-defined pre-self-repair qualification stages.

This module describes the qualification contract; execution evidence is kept in
the shakedown artifact and is never implied by this manifest.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class QualificationStage:
    stage_id: str
    purpose: str
    runner: str
    environment: str
    real_vm_required: bool
    interpreter: str
    timeout_seconds: int
    evidence_schema: str
    pass_criteria: str
    blocking_states: tuple[str, ...]
    contributes_formal_count: bool
    bound_sources: tuple[str, ...]
    execution_kind: str = "execution"
    formal_kind: str | None = None
    required_member_count: int | None = None
    formal_result_units: int = 0
    required_executable: str | None = None
    referenced_targets: tuple[str, ...] = ()
    validation_input: str | None = None
    validation_callable: str | None = None
    semantic_contract: tuple[str, ...] = ()
    semantic_evidence: tuple[str, ...] = ()
    structured_commands: tuple[tuple[str, ...], ...] = ()

    def __post_init__(self) -> None:
        if self.stage_id in {"Q17", "Q20", "Q28"}:
            object.__setattr__(self, "execution_kind", "validation")
        formal = {
            "Q09": ("THREE_OF_THREE", 3),
            "Q10": ("SAME_RUNTIME_PAIR", 2),
            "Q11": ("FINAL_TEN", 10),
        }.get(self.stage_id)
        if formal is not None:
            object.__setattr__(self, "formal_kind", formal[0])
            object.__setattr__(self, "required_member_count", formal[1])
            object.__setattr__(self, "formal_result_units", 1)
        for name, value in _ROUTE_METADATA.get(self.stage_id, {}).items():
            object.__setattr__(self, name, value)

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


BASE_PYTHON = "{direct-base-python312}"
DIRECT_BASE_INTERPRETER = "direct-base-python312"
ORDINARY_VENV_INTERPRETER = "ordinary-venv"

_STAGE_DATA: tuple[tuple[object, ...], ...] = (
    (
        "Q01",
        "source identity and seal",
        BASE_PYTHON + " scripts/acceptance/audit_source_identity.py",
        "repository",
        False,
        "python312",
        60,
        "source-seal-1",
        "identity and seal computed",
        ("MISMATCH",),
        False,
        ("jarvis/acceptance/evidence.py",),
    ),
    (
        "Q02",
        "recovery precheck",
        BASE_PYTHON + " -m pytest tests/test_recovery.py tests/test_recovery_authority.py",
        "control Windows",
        False,
        "python312",
        300,
        "pytest-junit",
        "terminal pass",
        ("FAIL", "TIMEOUT"),
        False,
        ("jarvis/recovery.py",),
    ),
    (
        "Q03",
        "evidence and liveness",
        BASE_PYTHON + " -m pytest -m 'not real_qualification' tests/test_acceptance_evidence.py",
        "control Windows",
        False,
        "python312",
        300,
        "pytest-junit + lifecycle-json",
        "terminal pass",
        ("FAIL", "MISSING_EVIDENCE"),
        False,
        ("jarvis/acceptance/evidence.py",),
    ),
    (
        "Q04",
        "Acceptance Lab integrity",
        BASE_PYTHON + " scripts/acceptance/validate_specs.py",
        "repository",
        False,
        "python312",
        60,
        "spec-validation-json",
        "115 unique canonical cases",
        ("DUPLICATE", "MISSING"),
        False,
        ("jarvis/acceptance/specs.py",),
    ),
    (
        "Q05",
        "production contamination precheck",
        BASE_PYTHON + " -m pytest tests/test_production_capability.py",
        "control Windows",
        False,
        "python312",
        300,
        "pytest-junit",
        "terminal pass",
        ("FAIL",),
        False,
        ("tests/test_production_capability.py",),
    ),
    (
        "Q06",
        "deterministic foundation matrix",
        BASE_PYTHON
        + " -m pytest tests/test_sandbox.py tests/test_runtime.py tests/test_persistence.py",
        "control Windows",
        False,
        "python312",
        600,
        "pytest-junit",
        "terminal pass",
        ("FAIL",),
        False,
        ("tests/test_sandbox.py",),
    ),
    (
        "Q07",
        "VM-first foundation",
        BASE_PYTHON + " scripts/acceptance/run_acceptance.py --profile vm-foundation --real-vm",
        "WSL2 Workbench and disposable",
        True,
        "python312",
        900,
        "acceptance-report-json",
        "all three VM domains and hardening pass",
        ("FAIL", "UNAVAILABLE"),
        False,
        ("jarvis/acceptance/environment.py", "jarvis/vm/bridge.py"),
    ),
    (
        "Q08",
        "D5 same-runtime sequence",
        (
            BASE_PYTHON
            + " -m pytest -m 'not real_qualification' tests/test_acceptance_evidence.py "
            "-k 'pair_budget or pair_rejects'"
        ),
        "control Windows",
        False,
        "python312",
        600,
        "pair-evidence-json",
        "terminal pass",
        ("FAIL", "TIMEOUT"),
        False,
        ("jarvis/acceptance/evidence.py",),
    ),
    (
        "Q09",
        "formal real 3-of-3 acquisition campaign",
        (BASE_PYTHON + " scripts/acceptance/run_formal_campaign.py --campaign three"),
        "native Windows direct-base qualification",
        False,
        "direct-base-python312",
        2400,
        "formal-qualification-campaign-result-1",
        "exactly three fresh real lifecycles accepted by ConsecutiveQualificationCampaign",
        ("FAIL", "TIMEOUT", "SOURCE_SEAL_MISMATCH", "REPLACEMENT"),
        True,
        ("jarvis/acceptance/formal_campaign.py", "scripts/acceptance/run_formal_campaign.py"),
    ),
    (
        "Q10",
        "formal same-runtime capability-acquisition pair",
        (
            BASE_PYTHON + " "
            "-m pytest -m real_qualification "
            "tests/test_acceptance_evidence.py::test_real_same_runtime_pair_control"
        ),
        "control Windows",
        False,
        "python312",
        600,
        "pair-evidence-json",
        (
            "capability acquisition A and B each reach ACTIVE with certification, "
            "Shadow, Canary, registry/persistence, terminal cleanup, same-runtime "
            "closure, and no cross contamination; full Goal completion is outside Q10"
        ),
        ("FAIL", "TIMEOUT"),
        True,
        ("jarvis/acceptance/evidence.py",),
    ),
    (
        "Q11",
        "formal real final-ten acquisition campaign",
        (BASE_PYTHON + " scripts/acceptance/run_formal_campaign.py --campaign ten"),
        "native Windows direct-base qualification",
        False,
        "direct-base-python312",
        7200,
        "formal-qualification-campaign-result-1",
        "exactly ten fresh real lifecycles accepted by ConsecutiveQualificationCampaign",
        ("FAIL", "TIMEOUT", "SOURCE_SEAL_MISMATCH", "REPLACEMENT", "MISSING_EVIDENCE"),
        True,
        ("jarvis/acceptance/formal_campaign.py", "scripts/acceptance/run_formal_campaign.py"),
    ),
    (
        "Q12",
        "controlled cleanup unknown",
        BASE_PYTHON + " -m pytest tests/test_native_cleanup_recovery.py",
        "native Windows",
        False,
        "direct-base-python312",
        600,
        "cleanup-recovery-json",
        "unknown quarantined then trusted reconciliation confirms",
        ("FAIL", "REUSE_ALLOWED"),
        False,
        ("jarvis/native_cleanup_recovery.py",),
    ),
    (
        "Q13",
        "generated child denial",
        (
            BASE_PYTHON + " "
            "-m pytest tests/test_sandbox.py::test_appcontainer_boundary_is_explicit_and_observable"
        ),
        "native Windows",
        False,
        "direct-base-python312",
        900,
        "pytest-junit",
        "denied, Job limit one, max active one",
        ("FAIL",),
        False,
        ("jarvis/windows_sandbox.py",),
    ),
    (
        "Q14",
        "seal stability",
        BASE_PYTHON + " -m pytest tests/test_acceptance_evidence.py -k source_seal",
        "repository",
        False,
        "python312",
        120,
        "seal-comparison-json",
        "changed mismatch and unchanged equality",
        ("FAIL",),
        False,
        ("jarvis/acceptance/evidence.py",),
    ),
    (
        "Q15",
        "v1 acceptance",
        BASE_PYTHON + " scripts/run_system_tests.py --suite v1-acceptance",
        "control Windows",
        False,
        "python312",
        900,
        "system-test-json",
        "23/23 pass",
        ("FAIL", "TIMEOUT"),
        False,
        ("jarvis/testing/catalog.py",),
    ),
    (
        "Q16",
        "canonical full quality",
        BASE_PYTHON + " scripts/quality.py",
        "control Windows",
        False,
        "python312",
        3600,
        "quality-console + junit",
        (
            "canonical quality passes with real_qualification excluded and emits "
            "static/pytest/coverage evidence"
        ),
        ("FAIL", "TIMEOUT"),
        False,
        ("scripts/quality.py",),
    ),
    (
        "Q17",
        "static",
        "consume Q16 static evidence; no independent tool rerun",
        "control Windows",
        False,
        "python312",
        900,
        "tool-console",
        "Q16 static evidence validates format, ruff, and strict mypy",
        ("FAIL",),
        False,
        ("pyproject.toml",),
    ),
    (
        "Q18",
        "direct-base sandbox",
        (BASE_PYTHON + " -m pytest tests/test_sandbox.py"),
        "native Windows",
        False,
        "direct-base-python312",
        1200,
        "pytest-junit",
        (
            "all 24 collected tests in tests/test_sandbox.py pass; native shim suite "
            "is separately 15 collected tests"
        ),
        ("FAIL", "TIMEOUT"),
        False,
        ("tests/test_windows_sandbox_native.py",),
    ),
    (
        "Q19",
        "ordinary venv differential",
        ".venv/Scripts/python.exe -m pytest tests/test_windows_sandbox_native.py",
        "outer Windows Job",
        False,
        "ordinary-venv",
        1200,
        "pytest-junit + differential",
        "known differential classified",
        ("NEW_SIGNATURE",),
        False,
        ("tests/test_windows_sandbox_native.py",),
    ),
    (
        "Q20",
        "coverage",
        "consume Q16 coverage evidence; no independent coverage suite",
        "control Windows",
        False,
        "python312",
        3600,
        "coverage-report",
        "consume Q16 coverage evidence at repository threshold at least 90 percent",
        ("FAIL", "BELOW_THRESHOLD"),
        False,
        ("pyproject.toml",),
    ),
    (
        "Q21",
        "package smoke",
        BASE_PYTHON + " scripts/package_smoke.py",
        "control Windows",
        False,
        "python312",
        1800,
        "package-smoke-json",
        "artifact build/install smoke pass",
        ("FAIL",),
        False,
        ("scripts/package_smoke.py",),
    ),
    (
        "Q22",
        "persistence and state",
        BASE_PYTHON + " -m pytest tests/test_persistence.py tests/test_package_certification.py",
        "control Windows",
        False,
        "python312",
        600,
        "pytest-junit",
        "state and stale certification controls pass",
        ("FAIL",),
        False,
        ("jarvis/capability_lifecycle.py",),
    ),
    (
        "Q23",
        "idempotency and effect truth",
        BASE_PYTHON
        + " -m pytest tests/test_effects.py tests/test_capability_acquisition_runtime.py",
        "control Windows",
        False,
        "python312",
        900,
        "pytest-junit",
        "typed effect outcomes and observe-before-mutate pass",
        ("FAIL",),
        False,
        ("jarvis/capability_acquisition.py",),
    ),
    (
        "Q24",
        "security regressions",
        BASE_PYTHON + " -m pytest tests/trusted_core tests/test_recovery_authority.py "
        "tests/test_sandbox_proxies.py",
        "control Windows",
        False,
        "python312",
        1800,
        "pytest-junit + coverage-map",
        "all mapped controls pass",
        ("FAIL", "UNMAPPED"),
        False,
        ("tests/trusted_core",),
    ),
    (
        "Q25",
        "recovery authority audit",
        BASE_PYTHON + " -m pytest tests/test_recovery_authority.py",
        "control Windows",
        False,
        "python312",
        600,
        "audit-json",
        "symbol and executable regression binding",
        ("FAIL", "UNBOUND"),
        False,
        ("jarvis/recovery.py",),
    ),
    (
        "Q26",
        "test-strength audit",
        BASE_PYTHON + " scripts/acceptance/audit_test_strength.py",
        "repository",
        False,
        "python312",
        120,
        "diff-audit-json",
        "no weakening or unexplained skip",
        ("WEAKENING", "UNKNOWN"),
        False,
        ("tests/test_windows_sandbox_native.py",),
    ),
    (
        "Q27",
        "final contamination",
        BASE_PYTHON + " -m pytest tests/test_production_capability.py",
        "control Windows",
        False,
        "python312",
        300,
        "contamination-json",
        "terminal clean result",
        ("CONTAMINATED",),
        False,
        ("jarvis/production_capability.py",),
    ),
    (
        "Q28",
        "CP1 inventory",
        "validation: scripts/acceptance/r4r_d6b2q0a_artifact.py::inventory "
        "consumes git status paths",
        "repository",
        False,
        "python312",
        120,
        "cp1-inventory-json",
        "every path categorized",
        ("UNCATEGORIZED",),
        False,
        (".gitignore",),
    ),
    (
        "Q29",
        "vision alignment",
        BASE_PYTHON + " scripts/acceptance/audit_foundation_vision.py",
        "repository",
        False,
        "python312",
        120,
        "vision-audit-json",
        "foundation invariants bound",
        ("FAIL",),
        False,
        ("docs/architecture.md",),
    ),
    (
        "Q30",
        "final git audit",
        "git status --short && git diff --check && git diff --name-only",
        "repository",
        False,
        "python312",
        120,
        "git-audit-json",
        "commands terminal without assumptions",
        ("FAIL",),
        False,
        (".gitignore",),
    ),
)


_ROUTE_METADATA: dict[str, dict[str, object]] = {
    "Q01": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("scripts/acceptance/audit_source_identity.py",),
    },
    "Q02": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("tests/test_recovery.py", "tests/test_recovery_authority.py"),
    },
    "Q03": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("tests/test_acceptance_evidence.py",),
    },
    "Q04": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("scripts/acceptance/validate_specs.py",),
    },
    "Q05": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("tests/test_production_capability.py",),
    },
    "Q06": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": (
            "tests/test_sandbox.py",
            "tests/test_runtime.py",
            "tests/test_persistence.py",
        ),
    },
    "Q07": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("scripts/acceptance/run_acceptance.py",),
    },
    "Q08": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("tests/test_acceptance_evidence.py",),
    },
    "Q09": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("scripts/acceptance/run_formal_campaign.py",),
    },
    "Q10": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("tests/test_acceptance_evidence.py",),
    },
    "Q11": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("scripts/acceptance/run_formal_campaign.py",),
    },
    "Q12": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("tests/test_native_cleanup_recovery.py",),
    },
    "Q13": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("tests/test_sandbox.py",),
    },
    "Q14": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("tests/test_acceptance_evidence.py",),
    },
    "Q15": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("scripts/run_system_tests.py",),
    },
    "Q16": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("scripts/quality.py",),
    },
    "Q18": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("tests/test_sandbox.py",),
    },
    "Q19": {
        "required_executable": r".venv\Scripts\python.exe",
        "referenced_targets": ("tests/test_windows_sandbox_native.py",),
    },
    "Q21": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("scripts/package_smoke.py",),
    },
    "Q22": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("tests/test_persistence.py", "tests/test_package_certification.py"),
    },
    "Q23": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": (
            "tests/test_effects.py",
            "tests/test_capability_acquisition_runtime.py",
        ),
    },
    "Q24": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": (
            "tests/trusted_core",
            "tests/test_recovery_authority.py",
            "tests/test_sandbox_proxies.py",
        ),
    },
    "Q25": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("tests/test_recovery_authority.py",),
    },
    "Q27": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("tests/test_production_capability.py",),
    },
    "Q29": {
        "required_executable": BASE_PYTHON,
        "referenced_targets": ("scripts/acceptance/audit_foundation_vision.py",),
    },
}
_ROUTE_METADATA["Q17"] = {
    "validation_input": "Q16 static evidence",
    "validation_callable": "jarvis.qualification_routes:validate_quality_evidence(static)",
}
_ROUTE_METADATA["Q20"] = {
    "validation_input": "Q16 coverage evidence",
    "validation_callable": "jarvis.qualification_routes:validate_quality_evidence(coverage)",
}
_ROUTE_METADATA["Q25"] = {
    "required_executable": BASE_PYTHON,
    "referenced_targets": ("tests/test_recovery_authority.py",),
    "semantic_contract": ("recovery authority", "symbol/executable binding"),
    "semantic_evidence": (
        "tests/test_recovery_authority.py::test_authority_verifies_each_bound_field_after_valid_authentication",
        "scripts/acceptance/audit_foundation_vision.py::trusted_recovery",
    ),
}
_ROUTE_METADATA["Q26"] = {
    "required_executable": BASE_PYTHON,
    "referenced_targets": ("scripts/acceptance/audit_test_strength.py",),
    "validation_input": "D6 test and quality diff",
    "validation_callable": "scripts/acceptance/audit_test_strength.py::audit_test_strength",
    "semantic_contract": (
        "security/assertion/coverage weakening",
        "hidden skip and fake PASS",
        "qualification-only bypass and formal fixture substitution",
        "type-ignore/evasion and test-selection weakening",
    ),
}
_ROUTE_METADATA["Q27"] = {
    "required_executable": BASE_PYTHON,
    "referenced_targets": ("tests/test_production_capability.py",),
    "semantic_contract": ("final contamination and terminal residue",),
    "semantic_evidence": (
        "tests/test_production_capability.py::test_production_sandbox_selection_and_protocol_history_fail_closed",
        "tests/test_production_capability.py::test_lifecycle_restorer_certified_state_and_binding_fail_closed",
        "tests/test_acceptance_evidence.py::test_pair_validation_reports_each_contamination_dimension",
        "tests/test_sandbox_cleanup_regression.py::test_pending_cleanup_receipt_denies_reuse_until_terminal_observation",
        "tests/test_native_cleanup_recovery.py::test_repeated_restart_can_reconcile_after_prior_failure",
    ),
}
_ROUTE_METADATA["Q28"] = {
    "validation_input": "git status --short paths",
    "validation_callable": "jarvis.qualification_routes:validate_cp1_inventory",
    "semantic_contract": (
        "current CP1 policy",
        "all paths categorized",
        "uncategorized paths rejected",
    ),
}
_ROUTE_METADATA["Q30"] = {
    "required_executable": "git",
    "validation_input": "working tree",
    "validation_callable": "structured git invocations",
    "structured_commands": (
        ("git", "status", "--short"),
        ("git", "diff", "--check"),
        ("git", "diff", "--name-only"),
    ),
    "semantic_contract": ("working-tree inventory", "diff validity", "changed-path evidence"),
}


STAGES: tuple[QualificationStage, ...] = tuple(QualificationStage(*row) for row in _STAGE_DATA)  # type: ignore[arg-type]


def direct_base_executable() -> Path:
    """Resolve the current machine's direct Python 3.12 installation."""

    if sys.version_info[:2] != (3, 12):
        raise RuntimeError("qualification requires Python 3.12")
    executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    if not executable.is_file():
        raise FileNotFoundError(executable)
    return executable


def resolve_qualification_manifest(
    stages: tuple[QualificationStage, ...] | None = None,
) -> tuple[QualificationStage, ...]:
    """Bind logical interpreter contracts to this machine for real execution."""

    executable = str(direct_base_executable())
    selected = stages if stages is not None else STAGES
    resolved: list[QualificationStage] = []
    for stage in selected:
        bound = replace(stage, runner=stage.runner.replace(BASE_PYTHON, executable))
        if stage.required_executable == BASE_PYTHON:
            object.__setattr__(bound, "required_executable", executable)
        resolved.append(bound)
    return tuple(resolved)


def qualification_manifest() -> tuple[QualificationStage, ...]:
    """Return the portable structural manifest without probing this host."""

    return STAGES


def manifest_dict() -> dict[str, object]:
    return {
        "schema": "r4r-pre-self-repair-qualification-manifest-1",
        "stages": [stage.as_dict() for stage in STAGES],
    }


def write_manifest(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
