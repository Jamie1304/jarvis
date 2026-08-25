from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import uuid4

import pytest
from jarvis.planning.models import EffectOutcome
from jarvis.planning.store import PlanningStore
from jarvis.planning.validation import PlanValidator
from jarvis.skills import SkillContextRequirements
from jarvis.tools.calculator import CalculatorTool
from jarvis.tools.models import SemanticVersion
from jarvis.tools.registry import ToolRegistry
from jarvis.trace import TraceStore
from jarvis.verification import VerificationDisposition, VerificationLevel, VerificationResult
from jarvis.workflows import (
    CandidateForm,
    ProcedureBank,
    ProcedureCandidate,
    ProcedureCandidateStatus,
    ProcedureEvidenceAuthority,
    ProcedureObservation,
    SQLiteWorkflowProcedureStore,
    TrustedProcedureEvidence,
    WorkflowBranch,
    WorkflowInput,
    WorkflowOutput,
    WorkflowProcedureStoreError,
    WorkflowStepTemplate,
    WorkflowTemplate,
    WorkflowTemplateError,
    WorkflowTemplateRegistry,
    WorkflowTemplateStatus,
    WorkflowTemplateVersion,
    WorkflowVerificationCriteria,
    _as_int,
    _iso,
    _json_object,
    _list,
    _matches,
    _parse_datetime,
    _shape,
    _strings,
    _tuple_int,
)


class _AcceptedEvidenceAuthority:
    def validate(self, evidence: TrustedProcedureEvidence) -> bool:
        return isinstance(evidence, TrustedProcedureEvidence)


def trusted_evidence(
    outcome: EffectOutcome = EffectOutcome.EFFECT_CONFIRMED,
) -> TrustedProcedureEvidence:
    return TrustedProcedureEvidence(
        uuid4(),
        uuid4(),
        "calculate",
        str(uuid4()),
        ("trace-event-id",),
        datetime.now(UTC),
        VerificationLevel.AUTOMATED_TESTED,
        outcome,
        b"x" * 32,
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
        evidence=trusted_evidence(outcome) if verified else None,
    )


def test_procedure_learning_requires_verified_repeated_success_and_validation() -> None:
    bank = ProcedureBank(evidence_authority=_AcceptedEvidenceAuthority())
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
    bank = ProcedureBank(
        min_verified_successes=3,
        evidence_authority=_AcceptedEvidenceAuthority(),
    )
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


def test_durable_workflow_versions_and_user_lifecycle(tmp_path: Path) -> None:
    store = SQLiteWorkflowProcedureStore(tmp_path / "workflow-procedures.sqlite3")
    registry = WorkflowTemplateRegistry(store=store)
    registry.register(template())
    version_two = replace(template(), version=SemanticVersion(1, 1, 0))
    registry.register(version_two)
    assert [str(item.template.version) for item in registry.versions("calculate")] == [
        "1.0.0",
        "1.1.0",
    ]
    with pytest.raises(WorkflowTemplateError):
        registry.register(version_two)
    registry.disable("calculate")
    with pytest.raises(KeyError):
        registry.resolve("calculate", workspace_id="w", profile_id="p")
    registry.enable("calculate", version=SemanticVersion(1, 0, 0))
    assert registry.resolve(
        "calculate", workspace_id="w", profile_id="p"
    ).version == SemanticVersion(1, 0, 0)
    registry.retire("calculate", version=SemanticVersion(1, 0, 0))
    registry.delete("calculate", version=SemanticVersion(1, 0, 0))
    store.close()
    restarted_store = SQLiteWorkflowProcedureStore(tmp_path / "workflow-procedures.sqlite3")
    restarted = WorkflowTemplateRegistry(store=restarted_store)
    with pytest.raises(KeyError):
        restarted.resolve("calculate", workspace_id="w", profile_id="p")
    assert restarted.versions("calculate")[0].status is WorkflowTemplateStatus.DISABLED
    restarted_store.close()


def test_procedure_bank_durable_scope_and_acceptance(tmp_path: Path) -> None:
    store = SQLiteWorkflowProcedureStore(tmp_path / "workflow-procedures.sqlite3")
    bank = ProcedureBank(
        store=store,
        evidence_authority=_AcceptedEvidenceAuthority(),
    )
    for _ in range(2):
        bank.observe(
            replace(
                observation(),
                workspace_id="workspace-a",
                profile_id="profile-a",
                context_requirements=SkillContextRequirements(
                    knowledge_library_queries=("scoped query",),
                ),
            )
        )
    candidate = bank.propose(
        "calculate",
        workspace_id="workspace-a",
        profile_id="profile-a",
    )
    assert candidate is not None
    validated = bank.validate(candidate, lambda item: item.form is CandidateForm.WORKFLOW_TEMPLATE)
    accepted = bank.accept(validated, target_id="workflow:calculate:1.0.0")
    assert accepted.status is ProcedureCandidateStatus.ACCEPTED
    assert accepted.linked_target_id == "workflow:calculate:1.0.0"
    assert accepted.context_requirements.knowledge_library_queries == ("scoped query",)
    assert bank.disable(accepted).status is ProcedureCandidateStatus.DISABLED
    assert bank.enable(accepted).status is ProcedureCandidateStatus.ACCEPTED
    store.close()

    restarted_store = SQLiteWorkflowProcedureStore(tmp_path / "workflow-procedures.sqlite3")
    restarted = ProcedureBank(
        store=restarted_store,
        evidence_authority=_AcceptedEvidenceAuthority(),
    )
    restored = restarted.propose(
        "calculate",
        workspace_id="workspace-a",
        profile_id="profile-a",
    )
    assert restored is not None
    assert restored.status is ProcedureCandidateStatus.ACCEPTED
    assert (
        restarted.propose("calculate", workspace_id="workspace-b", profile_id="profile-a") is None
    )
    assert (
        "2 + 2"
        not in restarted_store._connection.execute(  # noqa: SLF001
            "SELECT routine_json FROM procedure_routines"
        ).fetchone()[0]
    )
    restarted_store.close()


def test_caller_flags_and_unknown_outcome_never_create_trusted_learning() -> None:
    bank = ProcedureBank(evidence_authority=_AcceptedEvidenceAuthority())
    assert (
        bank.observe(
            ProcedureObservation(
                "forged",
                {"value": "x"},
                verified=True,
                trusted_source=True,
                outcome=EffectOutcome.EFFECT_CONFIRMED,
            )
        )
        is None
    )
    assert bank.observe(observation(outcome=EffectOutcome.UNKNOWN_OUTCOME)) is None


def test_workflow_procedure_store_refuses_future_schema(tmp_path: Path) -> None:
    path = tmp_path / "future-workflow-procedures.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE workflow_procedure_schema (version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
    )
    connection.execute("INSERT INTO workflow_procedure_schema(version, name) VALUES (99, 'future')")
    connection.commit()
    connection.close()
    with pytest.raises(WorkflowProcedureStoreError, match="future schema"):
        SQLiteWorkflowProcedureStore(path)


def test_workflow_contract_rejects_invalid_declarations_and_lifecycle_paths() -> None:
    base = template()
    with pytest.raises(WorkflowTemplateError):
        replace(base.steps[0], dependencies=tuple(str(i) for i in range(33)))
    with pytest.raises(WorkflowTemplateError):
        WorkflowBranch("x", {str(i): i for i in range(33)})
    with pytest.raises(WorkflowTemplateError):
        WorkflowVerificationCriteria(tuple(str(i) for i in range(33)), ("goal",))
    with pytest.raises(WorkflowTemplateError):
        replace(base, inputs=())
    with pytest.raises(WorkflowTemplateError):
        replace(base, steps=(base.steps[0], base.steps[0]))
    with pytest.raises(WorkflowTemplateError):
        replace(base, outputs=(base.outputs[0], base.outputs[0]))
    with pytest.raises(WorkflowTemplateError):
        replace(base, capabilities=("",))
    with pytest.raises(WorkflowTemplateError):
        replace(
            base,
            steps=(replace(base.steps[0], dependencies=("missing",)), base.steps[1]),
        )
    with pytest.raises(WorkflowTemplateError):
        replace(
            base, branches=(WorkflowBranch("same", {}, ("normal",)), WorkflowBranch("same", {}, ()))
        )
    with pytest.raises(WorkflowTemplateError):
        replace(base, branches=(WorkflowBranch("bad", {}, ("missing",)),))

    with pytest.raises(PermissionError):
        base.propose({"expression": "1"}, workspace_id="w", profile_id="other")
    with pytest.raises(WorkflowTemplateError):
        replace(
            base,
            steps=(replace(base.steps[0], input_template=["not-an-object"]), base.steps[1]),  # type: ignore[arg-type]
        ).propose({"expression": "1"}, workspace_id="w", profile_id="p")
    with pytest.raises(WorkflowTemplateError):
        replace(base, capabilities=("other",)).propose(
            {"expression": "1"}, workspace_id="w", profile_id="p"
        )
    with pytest.raises(WorkflowTemplateError):
        replace(
            base,
            steps=(replace(base.steps[0], required_permissions=("write",)), base.steps[1]),
        ).propose({"expression": "1"}, workspace_id="w", profile_id="p")
    with pytest.raises(WorkflowTemplateError):
        replace(
            base,
            branches=(
                WorkflowBranch("first", {"mode": "normal"}, ("normal",)),
                WorkflowBranch("second", {"mode": "normal"}, ("alternate",)),
            ),
        ).propose({"expression": "1", "mode": "normal"}, workspace_id="w", profile_id="p")

    with pytest.raises(WorkflowTemplateError):
        WorkflowTemplateVersion(
            cast(WorkflowTemplate, "not-a-template"),
            WorkflowTemplateStatus.ACTIVE,
            datetime.now(UTC),
            datetime.now(UTC),
        )
    with pytest.raises(WorkflowTemplateError):
        WorkflowTemplateVersion(
            base,
            cast(WorkflowTemplateStatus, "active"),
            datetime.now(UTC),
            datetime.now(UTC),
        )
    version = WorkflowTemplateVersion(
        base, WorkflowTemplateStatus.ACTIVE, datetime.now(), datetime.now()
    )
    assert version.created_at.tzinfo is not None

    memory = WorkflowTemplateRegistry((base,))
    assert len(memory.versions("calculate")) == 1
    with pytest.raises(WorkflowTemplateError):
        memory.enable("calculate")
    with pytest.raises(WorkflowTemplateError):
        memory.disable("calculate")
    with pytest.raises(WorkflowTemplateError):
        memory.retire("calculate")
    with pytest.raises(WorkflowTemplateError):
        memory.delete("calculate")

    store = SQLiteWorkflowProcedureStore(":memory:")
    assert store.database_path is None
    durable = WorkflowTemplateRegistry(store=store)
    with pytest.raises(KeyError):
        durable.enable("missing")
    with pytest.raises(KeyError):
        durable.retire("missing")
    with pytest.raises(KeyError):
        durable.delete("missing")
    durable.register(base)
    with pytest.raises(WorkflowTemplateError):
        durable.delete("calculate")
    store.close()


def test_workflow_store_is_immutable_and_rejects_malformed_state(tmp_path: Path) -> None:
    store = SQLiteWorkflowProcedureStore(tmp_path / "workflow-procedures.sqlite3")
    with pytest.raises(WorkflowProcedureStoreError):
        store.save_template(template(), status="active")  # type: ignore[arg-type]
    store.save_template(template())
    with pytest.raises(WorkflowProcedureStoreError, match="already exists"):
        store.save_template(template())
    with pytest.raises(WorkflowProcedureStoreError, match="cannot overwrite"):
        store.save_template(replace(template(), purpose="material edit"))
    with pytest.raises(WorkflowProcedureStoreError):
        store.set_template_status("calculate", SemanticVersion(1, 0, 0), "active")  # type: ignore[arg-type]
    with pytest.raises(KeyError):
        store.set_template_status(
            "missing", SemanticVersion(1, 0, 0), WorkflowTemplateStatus.ACTIVE
        )
    with pytest.raises(KeyError):
        store.delete_template("missing", SemanticVersion(1, 0, 0))

    store._connection.execute(  # noqa: SLF001
        "UPDATE workflow_template_versions SET template_json='{}'"
    )
    store._connection.commit()  # noqa: SLF001
    with pytest.raises(WorkflowProcedureStoreError, match="template is malformed"):
        store.list_template_versions()
    store.close()

    routine_store = SQLiteWorkflowProcedureStore(tmp_path / "malformed-routines.sqlite3")
    routine_store._connection.execute(  # noqa: SLF001
        "INSERT INTO procedure_routines VALUES ('r', 'method', 'w', 'p', '{}', 'now')"
    )
    routine_store._connection.execute(  # noqa: SLF001
        "INSERT INTO procedure_candidates VALUES ("
        "'c', 'method', 'w', 'p', 'skill', '{}', 'proposed', NULL, 'now', 'now')"
    )
    routine_store._connection.commit()  # noqa: SLF001
    with pytest.raises(WorkflowProcedureStoreError, match="routine is malformed"):
        routine_store.list_routines()
    with pytest.raises(WorkflowProcedureStoreError, match="candidate is malformed"):
        routine_store.list_candidates()
    routine_store.close()

    migration_path = tmp_path / "wrong-migration.sqlite3"
    connection = sqlite3.connect(migration_path)
    connection.execute(
        "CREATE TABLE workflow_procedure_schema (version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
    )
    connection.execute("INSERT INTO workflow_procedure_schema VALUES (1, 'wrong')")
    connection.commit()
    connection.close()
    with pytest.raises(WorkflowProcedureStoreError, match="migration identity"):
        SQLiteWorkflowProcedureStore(migration_path)


def test_trusted_procedure_evidence_authority_rejects_untrusted_or_incomplete_facts() -> None:
    evidence = trusted_evidence()
    with pytest.raises(WorkflowTemplateError):
        replace(evidence, task_id="bad")  # type: ignore[arg-type]
    with pytest.raises(WorkflowTemplateError):
        replace(evidence, trace_event_ids=())
    naive_evidence = replace(evidence, verified_at=datetime.now())
    assert naive_evidence.verified_at.tzinfo is not None
    with pytest.raises(WorkflowTemplateError):
        replace(evidence, verification_level=1)  # type: ignore[arg-type]
    with pytest.raises(WorkflowTemplateError):
        replace(evidence, effect_outcome="confirmed")  # type: ignore[arg-type]
    with pytest.raises(WorkflowTemplateError):
        replace(evidence, _proof=b"short")

    class PlanningFacts:
        def __init__(self, task: object = None, plan: object = None) -> None:
            self.task = task
            self.plan = plan

        def load_task(self, task_id: object) -> object:
            return self.task

        def load_plan(self, task_id: object) -> object:
            return self.plan

    result = VerificationResult(
        "calculate",
        VerificationLevel.AUTOMATED_TESTED,
        True,
        VerificationDisposition.COMPLETE,
    )
    authority = ProcedureEvidenceAuthority(cast(PlanningStore, PlanningFacts()))
    with pytest.raises(WorkflowTemplateError):
        authority.issue("bad", "calculate", result, trace_event_ids=("trace",))  # type: ignore[arg-type]

    task = SimpleNamespace(status=SimpleNamespace(value="completed"))
    plan = SimpleNamespace(
        plan_id=uuid4(),
        status=SimpleNamespace(value="completed"),
        steps=(
            SimpleNamespace(
                key="calculate", status=SimpleNamespace(value="succeeded"), result={"result": 4}
            ),
        ),
    )
    missing = ProcedureEvidenceAuthority(cast(PlanningStore, PlanningFacts()))
    with pytest.raises(WorkflowTemplateError, match="durable task"):
        missing.issue(uuid4(), "calculate", result, trace_event_ids=("trace",))
    incomplete = ProcedureEvidenceAuthority(
        cast(
            PlanningStore,
            PlanningFacts(
                task,
                SimpleNamespace(
                    plan_id=plan.plan_id, status=SimpleNamespace(value="running"), steps=plan.steps
                ),
            ),
        )
    )
    with pytest.raises(WorkflowTemplateError, match="completed"):
        incomplete.issue(uuid4(), "calculate", result, trace_event_ids=("trace",))
    facts = PlanningFacts(task, plan)
    authority = ProcedureEvidenceAuthority(cast(PlanningStore, facts))
    with pytest.raises(WorkflowTemplateError, match="not in the plan"):
        authority.issue(uuid4(), "missing", result, trace_event_ids=("trace",))
    failed_plan = SimpleNamespace(
        plan_id=plan.plan_id,
        status=SimpleNamespace(value="completed"),
        steps=(
            SimpleNamespace(key="calculate", status=SimpleNamespace(value="failed"), result=None),
        ),
    )
    with pytest.raises(WorkflowTemplateError, match="succeeded"):
        ProcedureEvidenceAuthority(cast(PlanningStore, PlanningFacts(task, failed_plan))).issue(
            uuid4(), "calculate", result, trace_event_ids=("trace",)
        )
    bad_result = VerificationResult(
        "calculate", VerificationLevel.UNKNOWN, False, VerificationDisposition.DIAGNOSE
    )
    with pytest.raises(WorkflowTemplateError, match="not eligible"):
        authority.issue(uuid4(), "calculate", bad_result, trace_event_ids=("trace",))

    class MissingTrace:
        def contains_event_ids(self, event_ids: tuple[str, ...]) -> bool:
            return False

    with pytest.raises(WorkflowTemplateError, match="trace IDs"):
        ProcedureEvidenceAuthority(
            cast(PlanningStore, facts), cast(TraceStore, MissingTrace())
        ).issue(uuid4(), "calculate", result, trace_event_ids=("trace",))
    issued = authority.issue(uuid4(), "calculate", result, trace_event_ids=("trace",))
    assert authority.validate(issued)
    assert not authority.validate(cast(TrustedProcedureEvidence, object()))
    object.__setattr__(issued, "_proof", None)
    assert not authority.validate(issued)


def test_procedure_candidate_lifecycle_and_serialization_helpers() -> None:
    candidate = ProcedureCandidate("method", CandidateForm.SKILL, 2, (), (), ())
    assert candidate.status is ProcedureCandidateStatus.PROPOSED
    validated = replace(candidate, validated=True)
    assert validated.status is ProcedureCandidateStatus.VALIDATED
    with pytest.raises(WorkflowTemplateError):
        replace(candidate, form="skill")  # type: ignore[arg-type]
    with pytest.raises(WorkflowTemplateError):
        replace(candidate, status="proposed")  # type: ignore[arg-type]
    with pytest.raises(WorkflowTemplateError):
        replace(candidate, verified_successes=1)

    bank = ProcedureBank(evidence_authority=_AcceptedEvidenceAuthority())
    first = bank.observe(observation())
    assert first is not None
    second_observation = observation()
    assert bank.observe(second_observation) is not None
    assert bank.observe(second_observation) is None
    proposed = bank.propose("calculate")
    assert proposed is not None
    with pytest.raises(WorkflowTemplateError):
        bank.accept(proposed, target_id="target")
    with pytest.raises(WorkflowTemplateError):
        bank.enable(proposed)
    validated_candidate = bank.validate(proposed, lambda _: True)
    assert bank.enable(validated_candidate).status is ProcedureCandidateStatus.VALIDATED
    assert bank.retire(validated_candidate).status is ProcedureCandidateStatus.RETIRED

    assert _iso(datetime.now()).endswith("+00:00")
    assert _parse_datetime("2026-01-01T00:00:00").tzinfo is not None
    with pytest.raises(WorkflowProcedureStoreError):
        _json_object("[]")
    with pytest.raises(WorkflowProcedureStoreError):
        _list({}, "values")
    with pytest.raises(WorkflowProcedureStoreError):
        _strings([1], "values")
    with pytest.raises(WorkflowProcedureStoreError):
        _tuple_int([1], 2, "version")
    with pytest.raises(WorkflowProcedureStoreError):
        _as_int(True, "version")
