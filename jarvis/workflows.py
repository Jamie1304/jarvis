"""Native reusable workflow templates and conservative procedure candidates.

Workflow templates only produce ordinary plan proposals.  They do not execute
steps, own task state, approve permissions, or replace :class:`PlanningEngine`.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from jarvis.planning.models import EffectOutcome, OwnedPlan
from jarvis.planning.validation import PlanProposal, PlanValidator, ProposedStep
from jarvis.skills import SkillContextRequirements
from jarvis.tools.models import SemanticVersion

type JsonValue = str | int | float | bool | None | list[object] | dict[str, object]


class WorkflowTemplateError(ValueError):
    """A template cannot be safely converted into a plan proposal."""


@dataclass(frozen=True, slots=True)
class WorkflowInput:
    name: str
    type_name: str
    required: bool = True
    default: JsonValue = None

    def __post_init__(self) -> None:
        _bounded(self.name, "Workflow input name", 128)
        if self.type_name not in {"string", "integer", "number", "boolean", "json"}:
            raise WorkflowTemplateError("Workflow input type is unsupported")
        if not self.required and self.default is None:
            raise WorkflowTemplateError("Optional workflow inputs need a default")


@dataclass(frozen=True, slots=True)
class WorkflowOutput:
    name: str
    type_name: str
    description: str = ""

    def __post_init__(self) -> None:
        _bounded(self.name, "Workflow output name", 128)
        if self.type_name not in {"string", "integer", "number", "boolean", "json"}:
            raise WorkflowTemplateError("Workflow output type is unsupported")
        if self.description:
            _bounded(self.description, "Workflow output description", 2_000)


@dataclass(frozen=True, slots=True)
class WorkflowStepTemplate:
    key: str
    tool_id: str
    capability: str
    input_template: dict[str, JsonValue]
    expected_output: str
    verification_rule: str
    expected_evidence: tuple[str, ...]
    dependencies: tuple[str, ...] = ()
    required_permissions: tuple[str, ...] = ()
    expensive_action: bool = False
    max_retries: int = 0

    def __post_init__(self) -> None:
        for value, name, limit in (
            (self.key, "Workflow step key", 128),
            (self.tool_id, "Workflow tool ID", 128),
            (self.capability, "Workflow capability", 128),
            (self.expected_output, "Workflow expected output", 4_000),
            (self.verification_rule, "Workflow verification rule", 1_000),
        ):
            _bounded(value, name, limit)
        if not self.input_template:
            raise WorkflowTemplateError("Workflow step input is required")
        if not self.expected_evidence or len(self.expected_evidence) > 32:
            raise WorkflowTemplateError("Workflow step evidence is required and bounded")
        if len(self.dependencies) > 32 or len(self.required_permissions) > 16:
            raise WorkflowTemplateError("Workflow step dependency or permission count is bounded")
        if self.max_retries < 0 or self.max_retries > 8:
            raise WorkflowTemplateError("Workflow step retry count is invalid")


@dataclass(frozen=True, slots=True)
class WorkflowBranch:
    name: str
    when: dict[str, JsonValue]
    step_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _bounded(self.name, "Workflow branch name", 128)
        if self.when is None:
            raise WorkflowTemplateError("Workflow branch condition is required")
        if len(self.when) > 32 or len(self.step_keys) > 64:
            raise WorkflowTemplateError("Workflow branch is bounded")


@dataclass(frozen=True, slots=True)
class WorkflowVerificationCriteria:
    required_evidence: tuple[str, ...]
    goal_criteria: tuple[str, ...]
    independent_check: str = ""

    def __post_init__(self) -> None:
        if not self.required_evidence or not self.goal_criteria:
            raise WorkflowTemplateError("Workflow verification criteria are required")
        if len(self.required_evidence) > 32 or len(self.goal_criteria) > 32:
            raise WorkflowTemplateError("Workflow verification criteria are bounded")
        for item in (*self.required_evidence, *self.goal_criteria):
            _bounded(item, "Workflow verification criterion", 1_000)
        if self.independent_check:
            _bounded(self.independent_check, "Workflow independent check", 1_000)


@dataclass(frozen=True, slots=True)
class WorkflowTemplate:
    template_id: str
    version: SemanticVersion
    purpose: str
    inputs: tuple[WorkflowInput, ...]
    steps: tuple[WorkflowStepTemplate, ...]
    outputs: tuple[WorkflowOutput, ...]
    capabilities: tuple[str, ...]
    permission_expectations: tuple[str, ...]
    workspace_scope: frozenset[str]
    profile_scope: frozenset[str]
    verification: WorkflowVerificationCriteria
    fallbacks: tuple[str, ...] = ()
    trigger_compatibility: tuple[str, ...] = ()
    context_requirements: SkillContextRequirements = SkillContextRequirements()
    provenance: tuple[str, ...] = ()
    branches: tuple[WorkflowBranch, ...] = ()

    def __post_init__(self) -> None:
        _bounded(self.template_id, "Workflow template ID", 128)
        _bounded(self.purpose, "Workflow template purpose", 2_000)
        if not self.inputs or len(self.inputs) > 64 or len(self.steps) > 64:
            raise WorkflowTemplateError("Workflow inputs and steps are required and bounded")
        if len({item.name for item in self.inputs}) != len(self.inputs):
            raise WorkflowTemplateError("Workflow input names must be unique")
        if len({item.key for item in self.steps}) != len(self.steps):
            raise WorkflowTemplateError("Workflow step keys must be unique")
        if len({item.name for item in self.outputs}) != len(self.outputs):
            raise WorkflowTemplateError("Workflow output names must be unique")
        if any(not value.strip() for value in (*self.capabilities, *self.permission_expectations)):
            raise WorkflowTemplateError("Workflow declarations cannot be empty")
        step_keys = {item.key for item in self.steps}
        for step in self.steps:
            if any(dependency not in step_keys for dependency in step.dependencies):
                raise WorkflowTemplateError("Workflow dependency cannot be resolved")
        branch_names = {branch.name for branch in self.branches}
        if len(branch_names) != len(self.branches):
            raise WorkflowTemplateError("Workflow branch names must be unique")
        for branch in self.branches:
            if any(key not in step_keys for key in branch.step_keys):
                raise WorkflowTemplateError("Workflow branch step cannot be resolved")

    def propose(
        self,
        parameters: Mapping[str, object],
        *,
        workspace_id: str,
        profile_id: str,
    ) -> PlanProposal:
        """Instantiate only a strict proposal; execution remains PlanningEngine-owned."""

        if self.workspace_scope and workspace_id not in self.workspace_scope:
            raise PermissionError("Workflow template is outside the workspace scope")
        if self.profile_scope and profile_id not in self.profile_scope:
            raise PermissionError("Workflow template is outside the profile scope")
        values = self._parameters(parameters)
        selected = self._selected_steps(values)
        steps: list[ProposedStep] = []
        for step in selected:
            resolved_input = _resolve(step.input_template, values)
            if not isinstance(resolved_input, dict):
                raise WorkflowTemplateError("Workflow step input must remain an object")
            steps.append(
                ProposedStep(
                    key=step.key,
                    tool_id=step.tool_id,
                    capability=step.capability,
                    input=resolved_input,
                    dependencies=list(step.dependencies),
                    required_permissions=list(step.required_permissions),
                    expected_output=step.expected_output,
                    verification_rule=step.verification_rule,
                    expected_evidence=list(step.expected_evidence),
                    expensive_action=step.expensive_action,
                    max_retries=step.max_retries,
                )
            )
        capabilities = tuple(sorted({step.capability for step in steps}))
        permissions = tuple(
            sorted({permission for step in steps for permission in step.required_permissions})
        )
        if capabilities != tuple(sorted(self.capabilities)):
            raise WorkflowTemplateError("Template capabilities do not match selected steps")
        if permissions != tuple(sorted(self.permission_expectations)):
            raise WorkflowTemplateError(
                "Template permission expectations do not match selected steps"
            )
        goal = f"{self.purpose} ({self.template_id} v{self.version})"
        return PlanProposal(
            goal=goal,
            assumptions=[f"workspace:{workspace_id}", f"profile:{profile_id}"],
            constraints=list(self.fallbacks),
            required_capabilities=list(capabilities),
            required_permissions=list(permissions),
            completion_criteria=list(self.verification.goal_criteria),
            steps=steps,
        )

    def instantiate(
        self,
        parameters: Mapping[str, object],
        *,
        task_id: UUID,
        workspace_id: str,
        profile_id: str,
        validator: PlanValidator,
    ) -> OwnedPlan:
        """Convert through the canonical PlanValidator; never execute directly."""

        return validator.validate(
            self.propose(parameters, workspace_id=workspace_id, profile_id=profile_id),
            task_id=task_id,
        )

    def _parameters(self, parameters: Mapping[str, object]) -> dict[str, object]:
        declared = {item.name: item for item in self.inputs}
        if set(parameters) - declared.keys():
            raise WorkflowTemplateError("Unknown workflow parameter")
        values: dict[str, object] = {}
        for name, definition in declared.items():
            if name not in parameters:
                if definition.required:
                    raise WorkflowTemplateError(f"Missing workflow parameter: {name}")
                values[name] = definition.default
            else:
                values[name] = parameters[name]
            if not _matches(values[name], definition.type_name):
                raise WorkflowTemplateError(f"Workflow parameter has wrong type: {name}")
        return values

    def _selected_steps(self, values: Mapping[str, object]) -> tuple[WorkflowStepTemplate, ...]:
        if not self.branches:
            return self.steps
        matches = [
            branch
            for branch in self.branches
            if all(values.get(key) == value for key, value in branch.when.items())
        ]
        if len(matches) != 1:
            raise WorkflowTemplateError("Workflow branch selection is ambiguous or unavailable")
        selected = set(matches[0].step_keys)
        return tuple(step for step in self.steps if step.key in selected)


class WorkflowTemplateRegistry:
    def __init__(self, templates: Iterable[WorkflowTemplate] = ()) -> None:
        self._templates: dict[str, WorkflowTemplate] = {}
        for template in templates:
            self.register(template)

    def register(self, template: WorkflowTemplate) -> None:
        if template.template_id in self._templates:
            raise WorkflowTemplateError("Duplicate workflow template ID")
        self._templates[template.template_id] = template

    def resolve(self, template_id: str, *, workspace_id: str, profile_id: str) -> WorkflowTemplate:
        try:
            template = self._templates[template_id]
        except KeyError as error:
            raise KeyError("Unknown workflow template") from error
        if template.workspace_scope and workspace_id not in template.workspace_scope:
            raise PermissionError("Workflow template is outside the workspace scope")
        if template.profile_scope and profile_id not in template.profile_scope:
            raise PermissionError("Workflow template is outside the profile scope")
        return template


class CandidateForm(StrEnum):
    SKILL = "skill"
    WORKFLOW_TEMPLATE = "workflow_template"
    DETERMINISTIC_HELPER = "deterministic_helper"


@dataclass(frozen=True, slots=True)
class ProcedureObservation:
    method_key: str
    parameters: Mapping[str, object]
    permission_expectations: tuple[str, ...] = ()
    verified: bool = False
    outcome: EffectOutcome = EffectOutcome.PRE_EFFECT_FAILURE
    trusted_source: bool = True
    secret_fields: frozenset[str] = frozenset()
    personal_fields: frozenset[str] = frozenset()
    provenance: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _bounded(self.method_key, "Procedure method key", 256)
        if len(self.parameters) > 64 or len(self.permission_expectations) > 16:
            raise WorkflowTemplateError("Procedure observation is bounded")
        if any(not item.strip() for item in self.permission_expectations):
            raise WorkflowTemplateError("Procedure permission expectation is invalid")


@dataclass(frozen=True, slots=True)
class RoutineCandidate:
    method_key: str
    verified_successes: int
    parameter_shapes: tuple[tuple[str, str], ...]
    permission_expectations: tuple[str, ...]
    provenance: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProcedureCandidate:
    method_key: str
    form: CandidateForm
    verified_successes: int
    parameter_shapes: tuple[tuple[str, str], ...]
    permission_expectations: tuple[str, ...]
    provenance: tuple[str, ...]
    validated: bool = False


class ProcedureBank:
    """Bank only verified, repeated, privacy-sanitized methods for later review."""

    def __init__(self, *, min_verified_successes: int = 2) -> None:
        if min_verified_successes < 2:
            raise ValueError("Procedure learning needs repeated verified success")
        self._minimum = min_verified_successes
        self._observations: dict[str, list[RoutineCandidate]] = {}

    def observe(self, observation: ProcedureObservation) -> RoutineCandidate | None:
        if (
            not observation.verified
            or observation.outcome is not EffectOutcome.EFFECT_CONFIRMED
            or not observation.trusted_source
        ):
            return None
        shapes = tuple(
            sorted((key, _shape(value)) for key, value in observation.parameters.items())
        )
        excluded = observation.secret_fields | observation.personal_fields
        shapes = tuple(item for item in shapes if item[0] not in excluded)
        provenance = tuple(item for item in observation.provenance if _safe_label(item))
        previous = self._observations.setdefault(observation.method_key, [])
        candidate = RoutineCandidate(
            observation.method_key,
            len(previous) + 1,
            shapes,
            tuple(sorted(set(observation.permission_expectations))),
            provenance,
        )
        previous.append(candidate)
        return candidate

    def propose(
        self,
        method_key: str,
        *,
        form: CandidateForm = CandidateForm.WORKFLOW_TEMPLATE,
    ) -> ProcedureCandidate | None:
        candidates = self._observations.get(method_key, [])
        if len(candidates) < self._minimum:
            return None
        stable_shapes = tuple(
            sorted(set(item for candidate in candidates for item in candidate.parameter_shapes))
        )
        permissions = tuple(
            sorted(
                set(item for candidate in candidates for item in candidate.permission_expectations)
            )
        )
        provenance = tuple(
            sorted(set(item for candidate in candidates for item in candidate.provenance))
        )
        return ProcedureCandidate(
            method_key, form, len(candidates), stable_shapes, permissions, provenance
        )

    @staticmethod
    def validate(
        candidate: ProcedureCandidate,
        validator: Callable[[ProcedureCandidate], bool],
    ) -> ProcedureCandidate:
        if not validator(candidate):
            raise WorkflowTemplateError("Procedure candidate failed normal validation")
        return ProcedureCandidate(
            candidate.method_key,
            candidate.form,
            candidate.verified_successes,
            candidate.parameter_shapes,
            candidate.permission_expectations,
            candidate.provenance,
            validated=True,
        )


def _resolve(value: object, parameters: Mapping[str, object]) -> object:
    if isinstance(value, str):
        match = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", value)
        return parameters[match.group(1)] if match else value
    if isinstance(value, list):
        return [_resolve(item, parameters) for item in value]
    if isinstance(value, dict):
        return {key: _resolve(item, parameters) for key, item in value.items()}
    return value


def _matches(value: object, type_name: str) -> bool:
    if type_name == "string":
        return type(value) is str
    if type_name == "integer":
        return type(value) is int
    if type_name == "number":
        return type(value) in {int, float}
    if type_name == "boolean":
        return type(value) is bool
    return isinstance(value, str | int | float | bool | list | dict) or value is None


def _shape(value: object) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    if type(value) is str:
        return "string"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "object"
    return "opaque"


def _safe_label(value: str) -> bool:
    lowered = value.casefold()
    return not any(
        token in lowered for token in ("password", "secret", "token", "credential", "api_key")
    )


def _bounded(value: str, name: str, limit: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise WorkflowTemplateError(f"{name} is invalid")
