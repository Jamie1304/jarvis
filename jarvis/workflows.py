"""Native reusable workflow templates and conservative procedure candidates.

Workflow templates only produce ordinary plan proposals.  They do not execute
steps, own task state, approve permissions, or replace :class:`PlanningEngine`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast
from uuid import UUID, uuid4, uuid5

from jarvis.planning.models import EffectOutcome, OwnedPlan
from jarvis.planning.store import PlanningStore
from jarvis.planning.validation import PlanProposal, PlanValidator, ProposedStep
from jarvis.skills import SkillContextRequirements
from jarvis.tools.models import SemanticVersion
from jarvis.verification import VerificationLevel, VerificationResult

if TYPE_CHECKING:
    from jarvis.trace import TraceStore

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


class WorkflowTemplateStatus(StrEnum):
    """User/application lifecycle state for an immutable template version."""

    ACTIVE = "active"
    DISABLED = "disabled"
    RETIRED = "retired"


@dataclass(frozen=True, slots=True)
class WorkflowTemplateVersion:
    """Durable metadata surrounding one immutable template version."""

    template: WorkflowTemplate
    status: WorkflowTemplateStatus
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.template, WorkflowTemplate):
            raise WorkflowTemplateError("Workflow template version is malformed")
        if not isinstance(self.status, WorkflowTemplateStatus):
            raise WorkflowTemplateError("Workflow template status is malformed")
        for name in ("created_at", "updated_at"):
            value = getattr(self, name)
            if value.tzinfo is None:
                value = value.replace(tzinfo=UTC)
            object.__setattr__(self, name, value.astimezone(UTC))


class WorkflowTemplateRegistry:
    """Active template projection; plans remain PlanningEngine-owned."""

    def __init__(
        self,
        templates: Iterable[WorkflowTemplate] = (),
        *,
        store: SQLiteWorkflowProcedureStore | None = None,
    ) -> None:
        self._templates: dict[str, WorkflowTemplate] = {}
        self._store = store
        if store is not None:
            for record in store.list_template_versions(status=WorkflowTemplateStatus.ACTIVE):
                if record.template.template_id in self._templates:
                    raise WorkflowTemplateError("Multiple active workflow template versions")
                self._templates[record.template.template_id] = record.template
        for template in templates:
            self.register(template)

    def register(self, template: WorkflowTemplate) -> None:
        current = self._templates.get(template.template_id)
        if current is not None:
            if template.version <= current.version:
                raise WorkflowTemplateError("Workflow template version already exists or is stale")
        if self._store is not None:
            self._store.save_template(template, status=WorkflowTemplateStatus.ACTIVE)
        self._templates[template.template_id] = template

    def enable(self, template_id: str, *, version: SemanticVersion | None = None) -> None:
        if self._store is None:
            raise WorkflowTemplateError("Workflow template lifecycle requires a durable store")
        record = self._store.load_template_version(template_id, version)
        if record is None:
            raise KeyError("Unknown workflow template version")
        self._store.set_template_status(
            template_id, record.template.version, WorkflowTemplateStatus.ACTIVE
        )
        self._templates[template_id] = record.template

    def disable(self, template_id: str, *, version: SemanticVersion | None = None) -> None:
        self._set_status(template_id, version, WorkflowTemplateStatus.DISABLED)

    def retire(self, template_id: str, *, version: SemanticVersion | None = None) -> None:
        self._set_status(template_id, version, WorkflowTemplateStatus.RETIRED)

    def delete(self, template_id: str, *, version: SemanticVersion | None = None) -> None:
        if self._store is None:
            raise WorkflowTemplateError("Workflow template lifecycle requires a durable store")
        record = self._store.load_template_version(template_id, version)
        if record is None:
            raise KeyError("Unknown workflow template version")
        if record.status is WorkflowTemplateStatus.ACTIVE:
            raise WorkflowTemplateError("Retire or disable a workflow before deletion")
        self._store.delete_template(template_id, record.template.version)
        if self._templates.get(template_id) == record.template:
            self._templates.pop(template_id, None)

    def versions(self, template_id: str) -> tuple[WorkflowTemplateVersion, ...]:
        if self._store is None:
            template = self._templates.get(template_id)
            return () if template is None else (_memory_template_version(template),)
        return self._store.list_template_versions(template_id=template_id)

    def _set_status(
        self,
        template_id: str,
        version: SemanticVersion | None,
        status: WorkflowTemplateStatus,
    ) -> None:
        if self._store is None:
            raise WorkflowTemplateError("Workflow template lifecycle requires a durable store")
        record = self._store.load_template_version(template_id, version)
        if record is None:
            raise KeyError("Unknown workflow template version")
        self._store.set_template_status(template_id, record.template.version, status)
        if self._templates.get(template_id) == record.template:
            self._templates.pop(template_id, None)

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


class ProcedureCandidateStatus(StrEnum):
    PROPOSED = "proposed"
    VALIDATED = "validated"
    ACCEPTED = "accepted"
    DISABLED = "disabled"
    RETIRED = "retired"


class ProcedureEvidenceValidator(Protocol):
    def validate(self, evidence: TrustedProcedureEvidence) -> bool: ...


@dataclass(frozen=True, slots=True)
class TrustedProcedureEvidence:
    """Metadata plus a trusted proof for one verified canonical execution."""

    task_id: UUID
    plan_id: UUID
    step_key: str
    verification_id: str
    trace_event_ids: tuple[str, ...]
    verified_at: datetime
    verification_level: VerificationLevel
    effect_outcome: EffectOutcome
    _proof: bytes = field(repr=False, default=b"")

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, UUID) or not isinstance(self.plan_id, UUID):
            raise WorkflowTemplateError("Trusted procedure evidence identity is malformed")
        _bounded(self.step_key, "Trusted procedure step", 128)
        _bounded(self.verification_id, "Trusted verification ID", 128)
        if not self.trace_event_ids or len(self.trace_event_ids) > 32:
            raise WorkflowTemplateError("Trusted procedure trace evidence is required and bounded")
        for value in self.trace_event_ids:
            _bounded(value, "Trusted trace event ID", 128)
        verified_at = self.verified_at
        if verified_at.tzinfo is None:
            verified_at = verified_at.replace(tzinfo=UTC)
        object.__setattr__(self, "verified_at", verified_at.astimezone(UTC))
        if not isinstance(self.verification_level, VerificationLevel):
            raise WorkflowTemplateError("Trusted verification level is malformed")
        if not isinstance(self.effect_outcome, EffectOutcome):
            raise WorkflowTemplateError("Trusted procedure outcome is malformed")
        if len(self._proof) != hashlib.sha256().digest_size:
            raise WorkflowTemplateError("Trusted procedure evidence proof is malformed")


@dataclass(frozen=True, slots=True)
class ProcedureObservation:
    method_key: str
    parameters: Mapping[str, object]
    permission_expectations: tuple[str, ...] = ()
    verified: bool = False
    outcome: EffectOutcome = EffectOutcome.PRE_EFFECT_FAILURE
    trusted_source: bool = False
    secret_fields: frozenset[str] = frozenset()
    personal_fields: frozenset[str] = frozenset()
    provenance: tuple[str, ...] = ()
    evidence: TrustedProcedureEvidence | None = None
    workspace_id: str = "default"
    profile_id: str = "default"
    context_requirements: SkillContextRequirements = SkillContextRequirements()
    observation_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        _bounded(self.method_key, "Procedure method key", 256)
        if len(self.parameters) > 64 or len(self.permission_expectations) > 16:
            raise WorkflowTemplateError("Procedure observation is bounded")
        if any(not item.strip() for item in self.permission_expectations):
            raise WorkflowTemplateError("Procedure permission expectation is invalid")
        _bounded(self.workspace_id, "Procedure workspace", 128)
        _bounded(self.profile_id, "Procedure profile", 128)
        _bounded(self.observation_id, "Procedure observation ID", 128)


@dataclass(frozen=True, slots=True)
class RoutineCandidate:
    method_key: str
    verified_successes: int
    parameter_shapes: tuple[tuple[str, str], ...]
    permission_expectations: tuple[str, ...]
    provenance: tuple[str, ...]
    workspace_id: str = "default"
    profile_id: str = "default"
    context_requirements: SkillContextRequirements = SkillContextRequirements()
    evidence_id: str = ""


@dataclass(frozen=True, slots=True)
class ProcedureCandidate:
    method_key: str
    form: CandidateForm
    verified_successes: int
    parameter_shapes: tuple[tuple[str, str], ...]
    permission_expectations: tuple[str, ...]
    provenance: tuple[str, ...]
    validated: bool = False
    candidate_id: str = field(default_factory=lambda: str(uuid4()))
    status: ProcedureCandidateStatus = ProcedureCandidateStatus.PROPOSED
    linked_target_id: str | None = None
    workspace_id: str = "default"
    profile_id: str = "default"
    context_requirements: SkillContextRequirements = SkillContextRequirements()

    def __post_init__(self) -> None:
        _bounded(self.method_key, "Procedure candidate method key", 256)
        _bounded(self.candidate_id, "Procedure candidate ID", 128)
        if not isinstance(self.form, CandidateForm):
            raise WorkflowTemplateError("Procedure candidate form is malformed")
        if not isinstance(self.status, ProcedureCandidateStatus):
            raise WorkflowTemplateError("Procedure candidate status is malformed")
        if self.verified_successes < 2:
            raise WorkflowTemplateError("Procedure candidate needs repeated verified success")
        _bounded(self.workspace_id, "Procedure candidate workspace", 128)
        _bounded(self.profile_id, "Procedure candidate profile", 128)
        if self.linked_target_id is not None:
            _bounded(self.linked_target_id, "Procedure candidate linkage", 256)
        if self.validated and self.status is ProcedureCandidateStatus.PROPOSED:
            object.__setattr__(self, "status", ProcedureCandidateStatus.VALIDATED)


class WorkflowProcedureStoreError(RuntimeError):
    """Durable workflow/procedure state is malformed or unavailable."""


class SQLiteWorkflowProcedureStore:
    """Single durable owner for templates and learned-method lifecycle state."""

    _SCHEMA_VERSION = 1
    _MIGRATION_NAME = "create_workflow_procedure_state"

    def __init__(self, database_path: str | Path) -> None:
        self._path = str(database_path)
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self._path, timeout=5.0, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.RLock()
        try:
            self._migrate()
            self._integrity_check()
        except (sqlite3.DatabaseError, ValueError, TypeError, WorkflowProcedureStoreError) as error:
            self.close()
            if isinstance(error, WorkflowProcedureStoreError):
                raise
            raise WorkflowProcedureStoreError("Workflow/procedure store is unavailable") from error

    @property
    def database_path(self) -> Path | None:
        return None if self._path == ":memory:" else Path(self._path)

    def _migrate(self) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS workflow_procedure_schema "
                "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
            )
            rows = self._connection.execute(
                "SELECT version, name FROM workflow_procedure_schema"
            ).fetchall()
            versions = {int(row["version"]): str(row["name"]) for row in rows}
            if any(version > self._SCHEMA_VERSION for version in versions):
                raise WorkflowProcedureStoreError(
                    "Workflow/procedure database uses a future schema"
                )
            if not versions:
                self._connection.executescript(
                    """
                    CREATE TABLE workflow_template_versions (
                        template_id TEXT NOT NULL,
                        version TEXT NOT NULL,
                        template_json TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (template_id, version)
                    );
                    CREATE TABLE procedure_routines (
                        routine_id TEXT PRIMARY KEY,
                        method_key TEXT NOT NULL,
                        workspace_id TEXT NOT NULL,
                        profile_id TEXT NOT NULL,
                        routine_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE procedure_candidates (
                        candidate_id TEXT PRIMARY KEY,
                        method_key TEXT NOT NULL,
                        workspace_id TEXT NOT NULL,
                        profile_id TEXT NOT NULL,
                        form TEXT NOT NULL,
                        candidate_json TEXT NOT NULL,
                        status TEXT NOT NULL,
                        linked_target_id TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        UNIQUE (method_key, workspace_id, profile_id, form)
                    );
                    CREATE INDEX workflow_template_active
                        ON workflow_template_versions(template_id, status);
                    CREATE INDEX procedure_routines_method
                        ON procedure_routines(method_key, workspace_id, profile_id);
                    """
                )
                self._connection.execute(
                    "INSERT INTO workflow_procedure_schema(version, name) VALUES (?, ?)",
                    (self._SCHEMA_VERSION, self._MIGRATION_NAME),
                )
            elif versions.get(1) != self._MIGRATION_NAME:
                raise WorkflowProcedureStoreError("Workflow/procedure migration identity mismatch")

    def _integrity_check(self) -> None:
        row = self._connection.execute("PRAGMA integrity_check").fetchone()
        if row is None or str(row[0]).casefold() != "ok":
            raise WorkflowProcedureStoreError("Workflow/procedure database is corrupt")

    def save_template(
        self,
        template: WorkflowTemplate,
        *,
        status: WorkflowTemplateStatus = WorkflowTemplateStatus.ACTIVE,
    ) -> WorkflowTemplateVersion:
        if not isinstance(status, WorkflowTemplateStatus):
            raise WorkflowProcedureStoreError("Workflow template status is malformed")
        now = _utc_now()
        payload = json.dumps(_template_dict(template), sort_keys=True, separators=(",", ":"))
        with self._lock:
            try:
                existing = self._connection.execute(
                    "SELECT template_json FROM workflow_template_versions "
                    "WHERE template_id=? AND version=?",
                    (template.template_id, str(template.version)),
                ).fetchone()
                if existing is not None:
                    if str(existing["template_json"]) != payload:
                        raise WorkflowProcedureStoreError(
                            "Material workflow edit cannot overwrite a version"
                        )
                    raise WorkflowProcedureStoreError("Workflow template version already exists")
                self._connection.execute(
                    "UPDATE workflow_template_versions SET status=?, updated_at=? "
                    "WHERE template_id=? AND status=?",
                    (
                        WorkflowTemplateStatus.RETIRED.value,
                        _iso(now),
                        template.template_id,
                        WorkflowTemplateStatus.ACTIVE.value,
                    ),
                )
                self._connection.execute(
                    "INSERT INTO workflow_template_versions "
                    "(template_id, version, template_json, status, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        template.template_id,
                        str(template.version),
                        payload,
                        status.value,
                        _iso(now),
                        _iso(now),
                    ),
                )
                self._connection.commit()
            except (sqlite3.DatabaseError, WorkflowProcedureStoreError):
                self._connection.rollback()
                raise
        return WorkflowTemplateVersion(template, status, now, now)

    def list_template_versions(
        self,
        *,
        template_id: str | None = None,
        status: WorkflowTemplateStatus | None = None,
    ) -> tuple[WorkflowTemplateVersion, ...]:
        query = (
            "SELECT template_json, status, created_at, updated_at FROM workflow_template_versions"
        )
        values: list[str] = []
        clauses: list[str] = []
        if template_id is not None:
            clauses.append("template_id=?")
            values.append(template_id)
        if status is not None:
            clauses.append("status=?")
            values.append(status.value)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY template_id, version"
        with self._lock:
            rows = self._connection.execute(query, tuple(values)).fetchall()
        try:
            return tuple(
                WorkflowTemplateVersion(
                    _template_from_dict(_json_object(row["template_json"])),
                    WorkflowTemplateStatus(str(row["status"])),
                    _parse_datetime(str(row["created_at"])),
                    _parse_datetime(str(row["updated_at"])),
                )
                for row in rows
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise WorkflowProcedureStoreError("Stored workflow template is malformed") from error

    def load_template_version(
        self, template_id: str, version: SemanticVersion | None = None
    ) -> WorkflowTemplateVersion | None:
        records = self.list_template_versions(template_id=template_id)
        if version is not None:
            records = tuple(record for record in records if record.template.version == version)
        if not records:
            return None
        if version is None:
            return max(records, key=lambda record: record.template.version)
        if len(records) != 1:
            raise WorkflowProcedureStoreError("Duplicate workflow template version")
        return records[0]

    def set_template_status(
        self, template_id: str, version: SemanticVersion, status: WorkflowTemplateStatus
    ) -> None:
        if not isinstance(status, WorkflowTemplateStatus):
            raise WorkflowProcedureStoreError("Workflow template status is malformed")
        with self._lock:
            cursor = self._connection.execute(
                "UPDATE workflow_template_versions SET status=?, updated_at=? "
                "WHERE template_id=? AND version=?",
                (status.value, _iso(_utc_now()), template_id, str(version)),
            )
            if cursor.rowcount != 1:
                self._connection.rollback()
                raise KeyError("Unknown workflow template version")
            if status is WorkflowTemplateStatus.ACTIVE:
                self._connection.execute(
                    "UPDATE workflow_template_versions SET status=?, updated_at=? "
                    "WHERE template_id=? AND version<>? AND status=?",
                    (
                        WorkflowTemplateStatus.RETIRED.value,
                        _iso(_utc_now()),
                        template_id,
                        str(version),
                        WorkflowTemplateStatus.ACTIVE.value,
                    ),
                )
            self._connection.commit()

    def delete_template(self, template_id: str, version: SemanticVersion) -> None:
        with self._lock:
            cursor = self._connection.execute(
                "DELETE FROM workflow_template_versions WHERE template_id=? AND version=?",
                (template_id, str(version)),
            )
            if cursor.rowcount != 1:
                self._connection.rollback()
                raise KeyError("Unknown workflow template version")
            self._connection.commit()

    def save_routine(self, routine: RoutineCandidate) -> None:
        payload = json.dumps(_routine_dict(routine), sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._connection.execute(
                "INSERT INTO procedure_routines "
                "(routine_id, method_key, workspace_id, profile_id, routine_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(uuid4()),
                    routine.method_key,
                    routine.workspace_id,
                    routine.profile_id,
                    payload,
                    _iso(_utc_now()),
                ),
            )
            self._connection.commit()

    def list_routines(self) -> tuple[RoutineCandidate, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT routine_json FROM procedure_routines ORDER BY created_at, routine_id"
            ).fetchall()
        try:
            return tuple(_routine_from_dict(_json_object(row["routine_json"])) for row in rows)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise WorkflowProcedureStoreError("Stored procedure routine is malformed") from error

    def save_candidate(self, candidate: ProcedureCandidate) -> None:
        payload = json.dumps(_candidate_dict(candidate), sort_keys=True, separators=(",", ":"))
        now = _iso(_utc_now())
        with self._lock:
            self._connection.execute(
                "INSERT INTO procedure_candidates "
                "(candidate_id, method_key, workspace_id, profile_id, form, candidate_json, "
                "status, linked_target_id, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(method_key, workspace_id, profile_id, form) DO UPDATE SET "
                "candidate_id=excluded.candidate_id, candidate_json=excluded.candidate_json, "
                "status=excluded.status, linked_target_id=excluded.linked_target_id, "
                "updated_at=excluded.updated_at",
                (
                    candidate.candidate_id,
                    candidate.method_key,
                    candidate.workspace_id,
                    candidate.profile_id,
                    candidate.form.value,
                    payload,
                    candidate.status.value,
                    candidate.linked_target_id,
                    now,
                    now,
                ),
            )
            self._connection.commit()

    def list_candidates(self) -> tuple[ProcedureCandidate, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT candidate_json FROM procedure_candidates "
                "ORDER BY method_key, workspace_id, profile_id, form"
            ).fetchall()
        try:
            return tuple(_candidate_from_dict(_json_object(row["candidate_json"])) for row in rows)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise WorkflowProcedureStoreError("Stored procedure candidate is malformed") from error

    def close(self) -> None:
        with self._lock:
            self._connection.close()


class ProcedureEvidenceAuthority:
    """Issue/validate learning tokens from completed canonical task evidence."""

    def __init__(
        self, planning_store: PlanningStore, trace_store: TraceStore | None = None
    ) -> None:
        self._planning_store = planning_store
        self._trace_store = trace_store
        self._signing_key = secrets.token_bytes(32)

    def issue(
        self,
        task_id: UUID,
        step_key: str,
        verification: VerificationResult,
        *,
        trace_event_ids: tuple[str, ...],
    ) -> TrustedProcedureEvidence:
        if not isinstance(task_id, UUID) or not isinstance(verification, VerificationResult):
            raise WorkflowTemplateError("Procedure evidence issuance input is malformed")
        task = self._planning_store.load_task(task_id)
        plan = self._planning_store.load_plan(task_id)
        if task is None or plan is None:
            raise WorkflowTemplateError("Procedure evidence requires a durable task and plan")
        if task.status.value != "completed" or plan.status.value != "completed":
            raise WorkflowTemplateError("Procedure evidence requires completed task and plan")
        try:
            step = next(item for item in plan.steps if item.key == step_key)
        except StopIteration as error:
            raise WorkflowTemplateError("Procedure evidence step is not in the plan") from error
        if step.status.value != "succeeded" or step.result is None:
            raise WorkflowTemplateError("Procedure evidence requires a succeeded plan step")
        if (
            not verification.passed
            or verification.level < VerificationLevel.AUTOMATED_TESTED
            or verification.contradictions
            or verification.stale_evidence
            or verification.rejected_model_claims
        ):
            raise WorkflowTemplateError(
                "Verification result is not eligible for procedure learning"
            )
        if self._trace_store is not None and not self._trace_store.contains_event_ids(
            trace_event_ids
        ):
            raise WorkflowTemplateError("Procedure evidence trace IDs are not durable trace facts")
        verification_id = _verification_fingerprint(task_id, plan.plan_id, step_key, verification)
        verified_at = _utc_now()
        unsigned = TrustedProcedureEvidence(
            task_id,
            plan.plan_id,
            step_key,
            verification_id,
            trace_event_ids,
            verified_at,
            verification.level,
            EffectOutcome.EFFECT_CONFIRMED,
            b"0" * hashlib.sha256().digest_size,
        )
        return replace(unsigned, _proof=self._proof(unsigned))

    def validate(self, evidence: TrustedProcedureEvidence) -> bool:
        if not isinstance(evidence, TrustedProcedureEvidence):
            return False
        try:
            return hmac.compare_digest(evidence._proof, self._proof(evidence))
        except (TypeError, ValueError):
            return False

    def _proof(self, evidence: TrustedProcedureEvidence) -> bytes:
        material = json.dumps(
            {
                "task_id": str(evidence.task_id),
                "plan_id": str(evidence.plan_id),
                "step_key": evidence.step_key,
                "verification_id": evidence.verification_id,
                "trace_event_ids": list(evidence.trace_event_ids),
                "verified_at": _iso(evidence.verified_at),
                "verification_level": int(evidence.verification_level),
                "effect_outcome": evidence.effect_outcome.value,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hmac.new(self._signing_key, material, hashlib.sha256).digest()


class ProcedureBank:
    """Bank only verified, repeated, privacy-sanitized methods for later review."""

    def __init__(
        self,
        *,
        min_verified_successes: int = 2,
        store: SQLiteWorkflowProcedureStore | None = None,
        evidence_authority: ProcedureEvidenceValidator | None = None,
    ) -> None:
        if min_verified_successes < 2:
            raise ValueError("Procedure learning needs repeated verified success")
        self._minimum = min_verified_successes
        self._store = store
        self._evidence_authority = evidence_authority
        self._observations: dict[str, list[RoutineCandidate]] = {}
        self._evidence_ids: set[str] = set()
        self._candidates: dict[tuple[str, str, str, CandidateForm], ProcedureCandidate] = {}
        if store is not None:
            for routine in store.list_routines():
                if routine.evidence_id:
                    self._evidence_ids.add(routine.evidence_id)
                self._observations.setdefault(
                    _procedure_scope_key(
                        routine.method_key, routine.workspace_id, routine.profile_id
                    ),
                    [],
                ).append(routine)
            for candidate in store.list_candidates():
                self._candidates[
                    (
                        candidate.method_key,
                        candidate.workspace_id,
                        candidate.profile_id,
                        candidate.form,
                    )
                ] = candidate

    def observe(self, observation: ProcedureObservation) -> RoutineCandidate | None:
        # Legacy boolean flags remain accepted as inert input for compatibility.
        # Only a token issued by the trusted evidence authority can pass this gate.
        evidence = observation.evidence
        if (
            evidence is None
            or self._evidence_authority is None
            or not self._evidence_authority.validate(evidence)
            or evidence.effect_outcome is not EffectOutcome.EFFECT_CONFIRMED
            or evidence.verification_level < VerificationLevel.AUTOMATED_TESTED
        ):
            return None
        if evidence.verification_id in self._evidence_ids:
            return None
        shapes = tuple(
            sorted((key, _shape(value)) for key, value in observation.parameters.items())
        )
        excluded = observation.secret_fields | observation.personal_fields
        shapes = tuple(item for item in shapes if item[0] not in excluded)
        provenance = tuple(item for item in observation.provenance if _safe_label(item))
        previous = self._observations.setdefault(
            _procedure_scope_key(
                observation.method_key, observation.workspace_id, observation.profile_id
            ),
            [],
        )
        candidate = RoutineCandidate(
            observation.method_key,
            len(previous) + 1,
            shapes,
            tuple(sorted(set(observation.permission_expectations))),
            provenance,
            observation.workspace_id,
            observation.profile_id,
            observation.context_requirements,
            evidence.verification_id,
        )
        previous.append(candidate)
        self._evidence_ids.add(evidence.verification_id)
        if self._store is not None:
            self._store.save_routine(candidate)
        return candidate

    def propose(
        self,
        method_key: str,
        *,
        form: CandidateForm = CandidateForm.WORKFLOW_TEMPLATE,
        workspace_id: str = "default",
        profile_id: str = "default",
    ) -> ProcedureCandidate | None:
        key = _procedure_scope_key(method_key, workspace_id, profile_id)
        candidates = self._observations.get(key, [])
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
        context_requirements = _merge_context_requirements(
            candidate.context_requirements for candidate in candidates
        )
        candidate_id = str(
            uuid5(
                _PROCEDURE_NAMESPACE,
                f"{workspace_id}\x1f{profile_id}\x1f{method_key}\x1f{form.value}",
            )
        )
        candidate = ProcedureCandidate(
            method_key,
            form,
            len(candidates),
            stable_shapes,
            permissions,
            provenance,
            candidate_id=candidate_id,
            workspace_id=workspace_id,
            profile_id=profile_id,
            context_requirements=context_requirements,
        )
        existing = self._candidates.get((method_key, workspace_id, profile_id, form))
        if existing is not None:
            candidate = replace(
                candidate,
                status=existing.status,
                validated=existing.validated,
                linked_target_id=existing.linked_target_id,
            )
        self._candidates[(method_key, workspace_id, profile_id, form)] = candidate
        if self._store is not None:
            self._store.save_candidate(candidate)
        return candidate

    def validate(
        self,
        candidate: ProcedureCandidate,
        validator: Callable[[ProcedureCandidate], bool],
    ) -> ProcedureCandidate:
        if not validator(candidate):
            raise WorkflowTemplateError("Procedure candidate failed normal validation")
        validated = replace(
            candidate,
            validated=True,
            status=ProcedureCandidateStatus.VALIDATED,
        )
        self._save_candidate(validated)
        return validated

    def accept(self, candidate: ProcedureCandidate, *, target_id: str) -> ProcedureCandidate:
        if candidate.status is not ProcedureCandidateStatus.VALIDATED or not candidate.validated:
            raise WorkflowTemplateError("Only normally validated procedures can be accepted")
        _bounded(target_id, "Accepted procedure target", 256)
        accepted = replace(
            candidate,
            status=ProcedureCandidateStatus.ACCEPTED,
            linked_target_id=target_id,
        )
        self._save_candidate(accepted)
        return accepted

    def disable(self, candidate: ProcedureCandidate) -> ProcedureCandidate:
        disabled = replace(candidate, status=ProcedureCandidateStatus.DISABLED)
        self._save_candidate(disabled)
        return disabled

    def enable(self, candidate: ProcedureCandidate) -> ProcedureCandidate:
        if candidate.linked_target_id is not None:
            status = ProcedureCandidateStatus.ACCEPTED
        elif candidate.validated:
            status = ProcedureCandidateStatus.VALIDATED
        else:
            raise WorkflowTemplateError("An unvalidated procedure cannot be enabled")
        enabled = replace(candidate, status=status)
        self._save_candidate(enabled)
        return enabled

    def retire(self, candidate: ProcedureCandidate) -> ProcedureCandidate:
        retired = replace(candidate, status=ProcedureCandidateStatus.RETIRED)
        self._save_candidate(retired)
        return retired

    def candidates(self) -> tuple[ProcedureCandidate, ...]:
        return tuple(self._candidates.values())

    def _save_candidate(self, candidate: ProcedureCandidate) -> None:
        self._candidates[
            (candidate.method_key, candidate.workspace_id, candidate.profile_id, candidate.form)
        ] = candidate
        if self._store is not None:
            self._store.save_candidate(candidate)


_PROCEDURE_NAMESPACE = UUID("3f8cc5da-e92f-4f66-9f03-c13d48fdbf5a")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _memory_template_version(template: WorkflowTemplate) -> WorkflowTemplateVersion:
    now = _utc_now()
    return WorkflowTemplateVersion(template, WorkflowTemplateStatus.ACTIVE, now, now)


def _template_dict(template: WorkflowTemplate) -> dict[str, object]:
    return {
        "template_id": template.template_id,
        "version": [template.version.major, template.version.minor, template.version.patch],
        "purpose": template.purpose,
        "inputs": [
            {
                "name": item.name,
                "type_name": item.type_name,
                "required": item.required,
                "default": item.default,
            }
            for item in template.inputs
        ],
        "steps": [
            {
                "key": item.key,
                "tool_id": item.tool_id,
                "capability": item.capability,
                "input_template": item.input_template,
                "expected_output": item.expected_output,
                "verification_rule": item.verification_rule,
                "expected_evidence": list(item.expected_evidence),
                "dependencies": list(item.dependencies),
                "required_permissions": list(item.required_permissions),
                "expensive_action": item.expensive_action,
                "max_retries": item.max_retries,
            }
            for item in template.steps
        ],
        "outputs": [
            {"name": item.name, "type_name": item.type_name, "description": item.description}
            for item in template.outputs
        ],
        "capabilities": list(template.capabilities),
        "permission_expectations": list(template.permission_expectations),
        "workspace_scope": sorted(template.workspace_scope),
        "profile_scope": sorted(template.profile_scope),
        "verification": {
            "required_evidence": list(template.verification.required_evidence),
            "goal_criteria": list(template.verification.goal_criteria),
            "independent_check": template.verification.independent_check,
        },
        "fallbacks": list(template.fallbacks),
        "trigger_compatibility": list(template.trigger_compatibility),
        "context_requirements": _context_dict(template.context_requirements),
        "provenance": list(template.provenance),
        "branches": [
            {"name": item.name, "when": item.when, "step_keys": list(item.step_keys)}
            for item in template.branches
        ],
    }


def _template_from_dict(value: dict[str, object]) -> WorkflowTemplate:
    version = _tuple_int(value["version"], 3, "Workflow version")
    raw_inputs = _list(value["inputs"], "Workflow inputs")
    raw_steps = _list(value["steps"], "Workflow steps")
    raw_outputs = _list(value["outputs"], "Workflow outputs")
    raw_verification = _json_object(value["verification"])
    return WorkflowTemplate(
        str(value["template_id"]),
        SemanticVersion(*version),
        str(value["purpose"]),
        tuple(
            WorkflowInput(
                str(item["name"]),
                str(item["type_name"]),
                bool(item.get("required", True)),
                cast(JsonValue, item.get("default")),
            )
            for item in (_json_object(item) for item in raw_inputs)
        ),
        tuple(
            WorkflowStepTemplate(
                str(item["key"]),
                str(item["tool_id"]),
                str(item["capability"]),
                cast(dict[str, JsonValue], _json_object(item["input_template"])),
                str(item["expected_output"]),
                str(item["verification_rule"]),
                _strings(item["expected_evidence"], "Workflow expected evidence"),
                _strings(item.get("dependencies", []), "Workflow dependencies"),
                _strings(item.get("required_permissions", []), "Workflow permissions"),
                bool(item.get("expensive_action", False)),
                _as_int(item.get("max_retries", 0), "Workflow max retries"),
            )
            for item in (_json_object(item) for item in raw_steps)
        ),
        tuple(
            WorkflowOutput(
                str(item["name"]), str(item["type_name"]), str(item.get("description", ""))
            )
            for item in (_json_object(item) for item in raw_outputs)
        ),
        _strings(value["capabilities"], "Workflow capabilities"),
        _strings(value["permission_expectations"], "Workflow permission expectations"),
        frozenset(_strings(value["workspace_scope"], "Workflow workspace scope")),
        frozenset(_strings(value["profile_scope"], "Workflow profile scope")),
        WorkflowVerificationCriteria(
            _strings(raw_verification["required_evidence"], "Workflow required evidence"),
            _strings(raw_verification["goal_criteria"], "Workflow goal criteria"),
            str(raw_verification.get("independent_check", "")),
        ),
        _strings(value.get("fallbacks", []), "Workflow fallbacks"),
        _strings(value.get("trigger_compatibility", []), "Workflow triggers"),
        _context_from_dict(_json_object(value.get("context_requirements", {}))),
        _strings(value.get("provenance", []), "Workflow provenance"),
        tuple(
            WorkflowBranch(
                str(item["name"]),
                cast(dict[str, JsonValue], _json_object(item["when"])),
                _strings(item.get("step_keys", []), "Workflow branch steps"),
            )
            for item in (
                _json_object(item) for item in _list(value.get("branches", []), "Workflow branches")
            )
        ),
    )


def _context_dict(requirements: SkillContextRequirements) -> dict[str, object]:
    return {
        "memory_categories": list(requirements.memory_categories),
        "knowledge_library_queries": list(requirements.knowledge_library_queries),
        "workspace_documents": list(requirements.workspace_documents),
        "project_knowledge_queries": list(requirements.project_knowledge_queries),
        "preferred_examples": list(requirements.preferred_examples),
        "required_prior_artifacts": list(requirements.required_prior_artifacts),
    }


def _context_from_dict(value: dict[str, object]) -> SkillContextRequirements:
    return SkillContextRequirements(
        _strings(value.get("memory_categories", []), "Memory context requirements"),
        _strings(value.get("knowledge_library_queries", []), "Knowledge context requirements"),
        _strings(value.get("workspace_documents", []), "Workspace context requirements"),
        _strings(value.get("project_knowledge_queries", []), "Project context requirements"),
        _strings(value.get("preferred_examples", []), "Example context requirements"),
        _strings(value.get("required_prior_artifacts", []), "Artifact context requirements"),
    )


def _routine_dict(routine: RoutineCandidate) -> dict[str, object]:
    return {
        "method_key": routine.method_key,
        "verified_successes": routine.verified_successes,
        "parameter_shapes": [list(item) for item in routine.parameter_shapes],
        "permission_expectations": list(routine.permission_expectations),
        "provenance": list(routine.provenance),
        "workspace_id": routine.workspace_id,
        "profile_id": routine.profile_id,
        "context_requirements": _context_dict(routine.context_requirements),
        "evidence_id": routine.evidence_id,
    }


def _routine_from_dict(value: dict[str, object]) -> RoutineCandidate:
    return RoutineCandidate(
        str(value["method_key"]),
        _as_int(value["verified_successes"], "Routine verified successes"),
        tuple(
            (str(item[0]), str(item[1]))
            for item in (
                _list(item, "Procedure parameter shape")
                for item in _list(value["parameter_shapes"], "Procedure parameter shapes")
            )
        ),
        _strings(value["permission_expectations"], "Procedure permissions"),
        _strings(value["provenance"], "Procedure provenance"),
        str(value.get("workspace_id", "default")),
        str(value.get("profile_id", "default")),
        _context_from_dict(_json_object(value.get("context_requirements", {}))),
        str(value.get("evidence_id", "")),
    )


def _candidate_dict(candidate: ProcedureCandidate) -> dict[str, object]:
    return {
        "method_key": candidate.method_key,
        "form": candidate.form.value,
        "verified_successes": candidate.verified_successes,
        "parameter_shapes": [list(item) for item in candidate.parameter_shapes],
        "permission_expectations": list(candidate.permission_expectations),
        "provenance": list(candidate.provenance),
        "validated": candidate.validated,
        "candidate_id": candidate.candidate_id,
        "status": candidate.status.value,
        "linked_target_id": candidate.linked_target_id,
        "workspace_id": candidate.workspace_id,
        "profile_id": candidate.profile_id,
        "context_requirements": _context_dict(candidate.context_requirements),
    }


def _candidate_from_dict(value: dict[str, object]) -> ProcedureCandidate:
    return ProcedureCandidate(
        str(value["method_key"]),
        CandidateForm(str(value["form"])),
        _as_int(value["verified_successes"], "Candidate verified successes"),
        tuple(
            (str(item[0]), str(item[1]))
            for item in (
                _list(item, "Candidate parameter shape")
                for item in _list(value["parameter_shapes"], "Candidate parameter shapes")
            )
        ),
        _strings(value["permission_expectations"], "Candidate permissions"),
        _strings(value["provenance"], "Candidate provenance"),
        bool(value.get("validated", False)),
        str(value["candidate_id"]),
        ProcedureCandidateStatus(str(value["status"])),
        str(value["linked_target_id"]) if value.get("linked_target_id") is not None else None,
        str(value.get("workspace_id", "default")),
        str(value.get("profile_id", "default")),
        _context_from_dict(_json_object(value.get("context_requirements", {}))),
    )


def _verification_fingerprint(
    task_id: UUID, plan_id: UUID, step_key: str, result: VerificationResult
) -> str:
    material = {
        "task_id": str(task_id),
        "plan_id": str(plan_id),
        "step_key": step_key,
        "level": int(result.level),
        "passed": result.passed,
        "evidence": len(result.evidence),
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _procedure_scope_key(method_key: str, workspace_id: str, profile_id: str) -> str:
    return f"{workspace_id}\x1f{profile_id}\x1f{method_key}"


def _merge_context_requirements(
    requirements: Iterable[SkillContextRequirements],
) -> SkillContextRequirements:
    values = tuple(requirements)
    return SkillContextRequirements(
        tuple(sorted({item for value in values for item in value.memory_categories})),
        tuple(sorted({item for value in values for item in value.knowledge_library_queries})),
        tuple(sorted({item for value in values for item in value.workspace_documents})),
        tuple(sorted({item for value in values for item in value.project_knowledge_queries})),
        tuple(sorted({item for value in values for item in value.preferred_examples})),
        tuple(sorted({item for value in values for item in value.required_prior_artifacts})),
    )


def _json_object(value: object) -> dict[str, object]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise WorkflowProcedureStoreError("Stored workflow JSON object is malformed")
    return value


def _list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise WorkflowProcedureStoreError(f"{name} are malformed")
    return value


def _strings(value: object, name: str) -> tuple[str, ...]:
    values = _list(value, name)
    if any(type(item) is not str for item in values):
        raise WorkflowProcedureStoreError(f"{name} are malformed")
    return tuple(str(item) for item in values)


def _tuple_int(value: object, length: int, name: str) -> tuple[int, ...]:
    values = _list(value, name)
    if len(values) != length or any(type(item) is not int for item in values):
        raise WorkflowProcedureStoreError(f"{name} is malformed")
    return tuple(_as_int(item, name) for item in values)


def _as_int(value: object, name: str) -> int:
    if type(value) is not int:
        raise WorkflowProcedureStoreError(f"{name} is malformed")
    return value


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
