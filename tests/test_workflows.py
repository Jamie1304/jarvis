from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest
from jarvis.planning.models import EffectOutcome
from jarvis.planning.validation import PlanValidator
from jarvis.skills import SkillContextRequirements
from jarvis.tools.calculator import CalculatorTool
from jarvis.tools.models import SemanticVersion
from jarvis.tools.registry import ToolRegistry
from jarvis.workflows import (
    CandidateForm,
    ProcedureBank,
    ProcedureObservation,
    WorkflowBranch,
    WorkflowInput,
    WorkflowOutput,
    WorkflowStepTemplate,
    WorkflowTemplate,
    WorkflowTemplateError,
    WorkflowTemplateRegistry,
    WorkflowVerificationCriteria,
    _matches,
    _shape,
)


def template(*, branches: tuple[WorkflowBranch, ...] = ()) -> WorkflowTemplate:
    return WorkflowTemplate(
        template_id="calculate",
        version=SemanticVersion(1, 0, 0),
        purpose="Calculate a requested value",
        inputs=(
            WorkflowInput("expression", "string"),
            WorkflowInput("mode", "string", False, "normal"),
        ),
        steps=(
            WorkflowStepTemplate(
                "normal",
                "calculator",
                "math",
                {"expression": "${expression}"},
                "a result",
                "evidence_contains_all",
                ("calculation_result",),
            ),
            WorkflowStepTemplate(
                "alternate",
                "calculator",
                "math",
                {"expression": "${expression}"},
                "a result",
                "evidence_contains_all",
                ("calculation_result",),
            ),
        ),
        outputs=(WorkflowOutput("result", "string"),),
        capabilities=("math",),
        permission_expectations=(),
        workspace_scope=frozenset({"w"}),
        profile_scope=frozenset({"p"}),
        verification=WorkflowVerificationCriteria(("calculation_result",), ("result",)),
        context_requirements=SkillContextRequirements(memory_categories=("preferences",)),
        branches=branches,
    )


def test_template_parameters_scope_and_canonical_plan_validation() -> None:
    workflow = template()
    proposal = workflow.propose({"expression": "2 + 2"}, workspace_id="w", profile_id="p")
    assert proposal.steps[0].input == {"expression": "2 + 2"}
    with pytest.raises(WorkflowTemplateError):
        workflow.propose({"expression": 4}, workspace_id="w", profile_id="p")
    with pytest.raises(WorkflowTemplateError):
        workflow.propose({"expression": "2", "unknown": True}, workspace_id="w", profile_id="p")
    with pytest.raises(WorkflowTemplateError):
        workflow.propose({}, workspace_id="w", profile_id="p")
    with pytest.raises(PermissionError):
        workflow.propose({"expression": "2"}, workspace_id="other", profile_id="p")

    validator = PlanValidator(ToolRegistry((CalculatorTool(),)), max_steps=4)
    plan = workflow.instantiate(
        {"expression": "2 + 2"},
        task_id=uuid4(),
        workspace_id="w",
        profile_id="p",
        validator=validator,
    )
    assert plan.steps[0].tool_id == "calculator"


def test_template_branching_and_context_are_proposal_metadata() -> None:
    workflow = template(
        branches=(
            WorkflowBranch("normal", {"mode": "normal"}, ("normal",)),
            WorkflowBranch("alternate", {"mode": "alternate"}, ("alternate",)),
        )
    )
    assert [
        step.key
        for step in workflow.propose(
            {"expression": "1", "mode": "alternate"}, workspace_id="w", profile_id="p"
        ).steps
    ] == ["alternate"]
    with pytest.raises(WorkflowTemplateError):
        workflow.propose(
            {"expression": "1", "mode": "unsupported"}, workspace_id="w", profile_id="p"
        )
    assert workflow.context_requirements.memory_categories == ("preferences",)

    nested = replace(
        template().steps[0],
        input_template={"expression": "${expression}", "nested": ["${expression}", {"x": 1}]},
    )
    nested_workflow = replace(template(), steps=(nested, template().steps[1]))
    assert nested_workflow.propose({"expression": "3"}, workspace_id="w", profile_id="p").steps[
        0
    ].input["nested"] == ["3", {"x": 1}]


def test_template_contract_validation_and_registry() -> None:
    with pytest.raises(WorkflowTemplateError):
        WorkflowInput("x", "unknown")
    with pytest.raises(WorkflowTemplateError):
        WorkflowInput("x", "string", False)
    with pytest.raises(WorkflowTemplateError):
        WorkflowOutput("x", "unknown")
    with pytest.raises(WorkflowTemplateError):
        WorkflowOutput("x", "string", "\x00")
    step = template().steps[0]
    with pytest.raises(WorkflowTemplateError):
        replace(step, input_template={})
    with pytest.raises(WorkflowTemplateError):
        replace(step, expected_evidence=())
    with pytest.raises(WorkflowTemplateError):
        replace(step, max_retries=9)
    with pytest.raises(WorkflowTemplateError):
        WorkflowBranch("x", None)  # type: ignore[arg-type]
    with pytest.raises(WorkflowTemplateError):
        WorkflowVerificationCriteria((), ("goal",))
    with pytest.raises(WorkflowTemplateError):
        WorkflowVerificationCriteria(("evidence",), ("goal",), "\x00")
    with pytest.raises(WorkflowTemplateError):
        replace(
            template(),
            inputs=(WorkflowInput("expression", "string"), WorkflowInput("expression", "string")),
        )
    registry = WorkflowTemplateRegistry((template(),))
    assert (
        registry.resolve("calculate", workspace_id="w", profile_id="p").template_id == "calculate"
    )
    with pytest.raises(WorkflowTemplateError):
        registry.register(template())
    with pytest.raises(KeyError):
        registry.resolve("missing", workspace_id="w", profile_id="p")
    with pytest.raises(PermissionError):
        registry.resolve("calculate", workspace_id="other", profile_id="p")


def observation(
    *, verified: bool = True, outcome: EffectOutcome = EffectOutcome.EFFECT_CONFIRMED
) -> ProcedureObservation:
    return ProcedureObservation(
        "calculate",
        {"expression": "2 + 2", "user_name": "Jamie", "api_token": "secret"},
        permission_expectations=("filesystem_read",),
        verified=verified,
        outcome=outcome,
        provenance=("test", "api_token-history"),
        secret_fields=frozenset({"api_token"}),
        personal_fields=frozenset({"user_name"}),
    )


def test_procedure_learning_requires_verified_repeated_success_and_validation() -> None:
    bank = ProcedureBank()
    assert bank.observe(observation(verified=False)) is None
    assert bank.observe(observation(outcome=EffectOutcome.UNKNOWN_OUTCOME)) is None
    assert bank.propose("calculate") is None
    first = bank.observe(observation())
    assert first is not None
    assert bank.propose("calculate") is None
    bank.observe(observation())
    candidate = bank.propose("calculate", form=CandidateForm.DETERMINISTIC_HELPER)
    assert candidate is not None
    assert candidate.verified_successes == 2
    assert candidate.permission_expectations == ("filesystem_read",)
    assert all("api" not in key and "user" not in key for key, _ in candidate.parameter_shapes)
    assert all("token" not in item for item in candidate.provenance)
    assert not candidate.validated
    validated = bank.validate(
        candidate, lambda item: item.form is CandidateForm.DETERMINISTIC_HELPER
    )
    assert validated.validated
    with pytest.raises(WorkflowTemplateError):
        bank.validate(candidate, lambda _: False)


def test_procedure_learning_does_not_preserve_exact_secret_or_approval() -> None:
    bank = ProcedureBank(min_verified_successes=3)
    for _ in range(3):
        bank.observe(observation())
    candidate = bank.propose("calculate")
    assert candidate is not None
    assert "2 + 2" not in str(candidate)
    assert candidate.permission_expectations == ("filesystem_read",)


def test_procedure_observation_validation_and_parameter_generalization() -> None:
    with pytest.raises(WorkflowTemplateError):
        ProcedureObservation("x", {str(i): i for i in range(65)})
    with pytest.raises(WorkflowTemplateError):
        ProcedureObservation("x", {}, permission_expectations=("",))

    class Opaque:
        pass

    assert _shape(None) == "null"
    assert _shape(True) == "boolean"
    assert _shape(1) == "integer"
    assert _shape(1.0) == "number"
    assert _shape("text") == "string"
    assert _shape([]) == "list"
    assert _shape({}) == "object"
    assert _shape(Opaque()) == "opaque"
    assert _matches("x", "string")
    assert _matches(1, "integer")
    assert _matches(1.0, "number")
    assert _matches(True, "boolean")
    assert _matches({}, "json")
