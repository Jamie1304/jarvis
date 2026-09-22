"""Trusted application adapters for generated semantic capability actions.

Generated package code remains an out-of-process implementation.  This module
owns only the typed application contract and the adapter that places a
certified, ACTIVE action on the normal ToolRegistry -> PermissionBroker path.
It never imports or executes package source.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Awaitable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Protocol, cast

from pydantic import BaseModel, ConfigDict, ValidationError, create_model

from jarvis.capabilities import CapabilityActionSpec
from jarvis.capability_lifecycle import SQLiteCapabilityLifecycleStore
from jarvis.integration_package import IntegrationPackage
from jarvis.permissions.models import (
    ActionDescriptor,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
)
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    ToolEffectDisposition,
    ToolEvidence,
    ToolExecutionContext,
    ToolHealth,
    ToolHealthStatus,
    ToolManifest,
    ToolMetadata,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)
from jarvis.tools.registry import TrustedToolRegistrationPort
from jarvis.trace import TraceEventType, TraceService

if TYPE_CHECKING:
    from jarvis.package_certification import CertificationRecord


class GeneratedCapabilityError(ValueError):
    """A generated action contract or adapter boundary is malformed."""


class GeneratedRuntimeInvoker(Protocol):
    def __call__(
        self, package_id: str, action_id: str, payload: Mapping[str, object]
    ) -> Mapping[str, object] | Awaitable[Mapping[str, object]]: ...


def _model_for_schema(name: str, schema: Mapping[str, object]) -> type[BaseModel]:
    """Build a strict Pydantic model from the already validated schema subset."""

    def python_type(value: Mapping[str, object], child_name: str) -> Any:
        schema_type = value.get("type")
        if schema_type == "string":
            return str
        if schema_type == "integer":
            return int
        if schema_type == "number":
            return float
        if schema_type == "boolean":
            return bool
        if schema_type == "array":
            items = value.get("items")
            if not isinstance(items, Mapping):
                raise GeneratedCapabilityError("Generated array schema is malformed")
            item_type = python_type(items, child_name + "Item")
            return list[item_type]  # type: ignore[valid-type]
        if schema_type == "object":
            properties = value.get("properties", {})
            required = value.get("required", ())
            if not isinstance(properties, Mapping) or not isinstance(required, Sequence):
                raise GeneratedCapabilityError("Generated object schema is malformed")
            fields: dict[str, tuple[Any, Any]] = {}
            required_names = {item for item in required if isinstance(item, str)}
            for property_name, property_schema in properties.items():
                if not isinstance(property_name, str) or not isinstance(property_schema, Mapping):
                    raise GeneratedCapabilityError("Generated object property is malformed")
                annotation = python_type(
                    property_schema,
                    child_name + re.sub(r"[^A-Za-z0-9]", "", property_name).title(),
                )
                fields[property_name] = (
                    annotation,
                    ... if property_name in required_names else None,
                )
            return cast(
                type[BaseModel],
                create_model(
                    child_name,
                    __config__=ConfigDict(extra="forbid", strict=True),
                    **fields,
                ),  # type: ignore[call-overload]
            )
        raise GeneratedCapabilityError("Generated schema type is unsupported")

    if schema.get("type") != "object":
        raise GeneratedCapabilityError("Generated action schemas must be objects")
    properties = schema.get("properties", {})
    required = schema.get("required", ())
    if not isinstance(properties, Mapping) or not isinstance(required, Sequence):
        raise GeneratedCapabilityError("Generated root schema is malformed")
    required_names = {item for item in required if isinstance(item, str)}
    fields: dict[str, tuple[Any, Any]] = {}
    for property_name, property_schema in properties.items():
        if not isinstance(property_name, str) or not isinstance(property_schema, Mapping):
            raise GeneratedCapabilityError("Generated action property is malformed")
        annotation = python_type(
            property_schema,
            name + re.sub(r"[^A-Za-z0-9]", "", property_name).title(),
        )
        fields[property_name] = (
            annotation,
            ... if property_name in required_names else None,
        )
    return cast(
        type[BaseModel],
        create_model(
            name,
            __config__=ConfigDict(extra="forbid", strict=True),
            **fields,
        ),  # type: ignore[call-overload]
    )


def action_input_model(spec: CapabilityActionSpec) -> type[BaseModel]:
    if not isinstance(spec, CapabilityActionSpec):
        raise GeneratedCapabilityError("Generated action specification is malformed")
    return _model_for_schema(
        "GeneratedInput" + re.sub(r"[^A-Za-z0-9]", "", spec.action_id).title(),
        spec.input_schema,
    )


def action_output_model(spec: CapabilityActionSpec) -> type[BaseModel]:
    if not isinstance(spec, CapabilityActionSpec):
        raise GeneratedCapabilityError("Generated action specification is malformed")
    return _model_for_schema(
        "GeneratedOutput" + re.sub(r"[^A-Za-z0-9]", "", spec.action_id).title(),
        spec.output_schema,
    )


def validate_action_input(spec: CapabilityActionSpec, payload: Mapping[str, object]) -> BaseModel:
    if not isinstance(payload, Mapping):
        raise GeneratedCapabilityError("Generated action input must be an object")
    try:
        return action_input_model(spec).model_validate(dict(payload), strict=True)
    except ValidationError as error:
        raise GeneratedCapabilityError(
            "Generated action input does not match its schema"
        ) from error


def generated_tool_id(spec: CapabilityActionSpec) -> str:
    """Create a stable namespaced ID that changes when package content changes."""

    package = re.sub(r"[^A-Za-z0-9._-]", "-", spec.package_id).strip("-._") or "package"
    action = re.sub(r"[^A-Za-z0-9._-]", "-", spec.action_id).strip("-._") or "action"
    return f"generated.{package}.{action}.{spec.package_hash[:12]}"


def _risk_for(spec: CapabilityActionSpec) -> Risk:
    if spec.effect.classification.value in {"destructive", "unknown"}:
        return Risk.CRITICAL
    if spec.required_permissions or spec.effect.classification.value == "external_effect":
        return Risk.HIGH
    if spec.effect.classification.value == "local_mutation":
        return Risk.MEDIUM
    return Risk.LOW


class GeneratedCapabilityToolAdapter(Tool[BaseModel, BaseModel]):
    """Application-owned Tool facade for one certified generated action."""

    def __init__(
        self,
        spec: CapabilityActionSpec,
        runtime_invoker: GeneratedRuntimeInvoker,
        *,
        trace: TraceService | None = None,
    ) -> None:
        if not isinstance(spec, CapabilityActionSpec) or not callable(runtime_invoker):
            raise GeneratedCapabilityError("Generated adapter dependencies are malformed")
        if not spec.package_hash:
            raise GeneratedCapabilityError("Generated adapter requires a bound package hash")
        self.action_spec = spec
        self.package_id = spec.package_id
        self.package_version = spec.package_version
        self.package_hash = spec.package_hash
        self._runtime_invoker = runtime_invoker
        self._trace = trace
        self._input_model = action_input_model(spec)
        self._output_model = action_output_model(spec)
        tool_id = generated_tool_id(spec)
        self._manifest = ToolManifest(
            tool_id=tool_id,
            name=spec.semantic_name,
            description=spec.description,
            version=spec.package_version,
            capability_tags=frozenset({spec.capability_id, spec.action_id}),
            input_schema=self._input_model,
            output_schema=self._output_model,
            declared_permissions=frozenset(spec.required_permissions),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            # Native Windows process startup can exceed the request budget on
            # a busy host.  Keep this finite and aligned with the production
            # sandbox boundary rather than turning scheduler contention into
            # an ambiguous tool failure.
            timeout_seconds=60.0,
            implementation_id=(
                f"generated-adapter:{spec.package_id}:{spec.package_version}:"
                f"{spec.package_hash}:{spec.action_id}"
            ),
        )

    @property
    def manifest(self) -> ToolManifest:
        return self._manifest

    @property
    def input_model(self) -> type[BaseModel]:
        return self._input_model

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: BaseModel
    ) -> ToolResult:
        payload = validated_input.model_dump(mode="json")
        try:
            response = self._runtime_invoker(self.package_id, self.action_spec.action_id, payload)
            if inspect.isawaitable(response):
                response = await response
            if not isinstance(response, Mapping):
                raise GeneratedCapabilityError("Generated runtime returned a non-object result")
            output = self._output_model.model_validate(dict(response), strict=True)
        except ValidationError:
            self._record_trace(context, "generated action output schema rejected", False)
            return ToolResult.failure(
                ToolResultStatus.INTERNAL_FAILURE,
                "generated_output_schema_invalid",
                "Generated action output did not match its certified schema",
                effect_disposition=(
                    ToolEffectDisposition.UNKNOWN
                    if self.manifest.declared_permissions
                    else ToolEffectDisposition.NO_EFFECT
                ),
            )
        except Exception:
            # The base Tool boundary with permissions will convert an uncertain
            # provider/runtime failure into UNKNOWN_OUTCOME.  Keep package text
            # out of the error and trace surfaces here.
            self._record_trace(context, "generated action runtime failed", False)
            return ToolResult.failure(
                ToolResultStatus.UNKNOWN_OUTCOME
                if self.manifest.declared_permissions
                else ToolResultStatus.INTERNAL_FAILURE,
                "generated_runtime_failure",
                "Generated action runtime failed; provider details were withheld",
                effect_disposition=(
                    ToolEffectDisposition.UNKNOWN
                    if self.manifest.declared_permissions
                    else ToolEffectDisposition.NO_EFFECT
                ),
            )
        if self.manifest.declared_permissions:
            # A generated runtime's well-formed response proves only that the
            # sandbox returned data.  It is not an application-owned
            # observation that the requested real-world effect occurred.
            # Until a trusted broker attestation is supplied on this execution
            # path, fail closed into recovery rather than letting package text
            # satisfy a plan's output/evidence verification rule.
            self._record_trace(context, "generated effect requires trusted attestation", False)
            return ToolResult.failure(
                ToolResultStatus.UNKNOWN_OUTCOME,
                "generated_effect_requires_trusted_attestation",
                "A generated action reported a privileged effect without trusted confirmation",
                effect_disposition=ToolEffectDisposition.UNKNOWN,
            )
        evidence_value = (
            f"generated-action:{self.package_id}:{self.package_version}:"
            f"{self.action_spec.action_id}:completed"
        )
        result = ToolResult.success(
            output,
            evidence=(
                # These are application observations: the trusted adapter
                # validated the response and the package identity, not a
                # package-authored claim of success.
                ToolEvidence("generated_action", evidence_value),
                ToolEvidence("generated_schema", f"{self.package_hash}:valid"),
            ),
            metadata=(
                ToolMetadata("integration_id", self.package_id),
                ToolMetadata("package_version", str(self.package_version)),
                ToolMetadata("package_hash", self.package_hash),
                ToolMetadata("action_id", self.action_spec.action_id),
            ),
        )
        if self.action_spec.effect.classification.value == "observation":
            result = ToolResult(
                result.status,
                result.output,
                result.error,
                result.evidence,
                result.metadata,
                ToolEffectDisposition.NO_EFFECT,
            )
        self._record_trace(context, "generated action output validated", True)
        return result

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: BaseModel
    ) -> ActionDescriptor:
        del validated_input
        permission_requests: list[PermissionRequest] = []
        for permission in self.action_spec.required_permissions:
            scope_values = self.action_spec.target_scope
            permission_scope = PermissionScope(
                paths=scope_values if permission is Permission.FILESYSTEM_WRITE else (),
                hosts=scope_values if permission is Permission.NETWORK_REQUEST else (),
                applications=(
                    scope_values
                    if permission in {Permission.APPLICATION_LAUNCH, Permission.COMPUTER_INPUT}
                    else ()
                ),
                tool_id=self.manifest.tool_id,
                task_id=context.task_id,
            )
            permission_requests.append(PermissionRequest(permission, permission_scope))
        return ActionDescriptor(
            action=f"generated:{self.package_id}:{self.action_spec.action_id}",
            arguments_summary=(
                SafeArgument("package", f"{self.package_id}@{self.package_version}"),
                SafeArgument("action", self.action_spec.action_id),
                SafeArgument("package_hash", self.package_hash[:16]),
                *(
                    (SafeArgument("scope", ",".join(self.action_spec.target_scope)),)
                    if self.action_spec.target_scope
                    else ()
                ),
            ),
            risk=_risk_for(self.action_spec),
            permissions=tuple(permission_requests),
        )

    async def health_check(self) -> ToolHealth:
        return ToolHealth(ToolHealthStatus.AVAILABLE, "certified generated package adapter")

    def _record_trace(self, context: ToolExecutionContext, summary: str, passed: bool) -> None:
        if self._trace is None:
            return
        self._trace.record(
            TraceEventType.CAPABILITY_TOOL,
            summary,
            task_id=context.task_id,
            correlation_id=context.correlation_id,
            integration_id=self.package_id,
            package_version=str(self.package_version),
            package_hash=self.package_hash,
            arguments={"action_id": self.action_spec.action_id},
            result={"schema_validated": passed},
            permissions=tuple(item.value for item in self.action_spec.required_permissions),
            external_effect=bool(self.action_spec.required_permissions),
            replay_safe=not bool(self.action_spec.required_permissions),
        )


class GeneratedCapabilityToolRegistrar:
    """Trusted activation-time owner of generated ToolRegistry registration."""

    def __init__(
        self,
        registration_port: TrustedToolRegistrationPort,
        lifecycle_store: SQLiteCapabilityLifecycleStore,
        runtime_invoker: GeneratedRuntimeInvoker,
        *,
        trace: TraceService | None = None,
    ) -> None:
        if not isinstance(registration_port, TrustedToolRegistrationPort):
            raise GeneratedCapabilityError("Generated registration port is malformed")
        if not isinstance(lifecycle_store, SQLiteCapabilityLifecycleStore):
            raise GeneratedCapabilityError("Generated lifecycle store is malformed")
        if not callable(runtime_invoker):
            raise GeneratedCapabilityError("Generated runtime invoker is malformed")
        self._port = registration_port
        self._lifecycle = lifecycle_store
        self._runtime_invoker = runtime_invoker
        self._trace = trace

    def activate(self, package: IntegrationPackage, certification: CertificationRecord) -> None:
        from jarvis.package_certification import CertificationRecord

        if not isinstance(package, IntegrationPackage) or not isinstance(
            certification, CertificationRecord
        ):
            raise GeneratedCapabilityError("Generated activation identity is malformed")
        stored = getattr(self._lifecycle, "load", lambda *_: None)(
            package.package_id, str(package.version)
        )
        if stored is None or stored.record.state.value != "ACTIVE":
            raise GeneratedCapabilityError("Generated actions require a durable ACTIVE lifecycle")
        if (
            stored.record.package_hash != package.package_hash
            or stored.record.certification != certification
        ):
            raise GeneratedCapabilityError("Generated activation evidence is stale")
        if not package.action_specs:
            raise GeneratedCapabilityError("Active generated package declares no semantic actions")
        adapters = tuple(
            GeneratedCapabilityToolAdapter(spec, self._runtime_invoker, trace=self._trace)
            for spec in package.action_specs
        )
        self._port.activate(
            package.package_id,
            package.version,
            package.package_hash,
            certification,
            adapters,
        )

    def deactivate(self, package_id: str) -> None:
        self._port.deactivate(package_id)


class GeneratedActionPlanPlanner:
    """Select an ACTIVE generated action using typed application request data."""

    def __init__(self, registry: object) -> None:
        self._registry = registry

    def proposal_for(self, intent: object) -> object | None:
        from jarvis.goal_supervisor import GoalIntent
        from jarvis.planning.validation import PlanProposal, ProposedStep

        if not isinstance(intent, GoalIntent) or not intent.required_capabilities:
            return None
        metadata = intent.metadata or {}
        raw_input = metadata.get("generated_action_input")
        expected_output = metadata.get("generated_expected_output")
        if not isinstance(raw_input, Mapping) or type(expected_output) is not str:
            return None
        if not expected_output.strip() or len(expected_output) > 4_000:
            return None
        candidates: list[GeneratedCapabilityToolAdapter] = []
        find = getattr(self._registry, "find_by_capability", None)
        if not callable(find):
            return None
        for capability in intent.required_capabilities:
            for record in find(capability):
                tool = record.tool
                if isinstance(tool, GeneratedCapabilityToolAdapter) and record.usable:
                    candidates.append(tool)
        unique = {tool.manifest.tool_id: tool for tool in candidates}
        if not unique:
            return None
        tool = next(iter(unique.values()))
        try:
            validated = validate_action_input(tool.action_spec, raw_input)
        except GeneratedCapabilityError:
            return None
        capability = next(
            item for item in intent.required_capabilities if item in tool.manifest.capabilities
        )
        criterion = (
            f"generated-action:{tool.package_id}:{tool.package_version}:"
            f"{tool.action_spec.action_id}:completed"
        )
        return PlanProposal(
            goal=intent.original_outcome,
            assumptions=list(intent.assumptions),
            constraints=list(intent.constraints),
            required_capabilities=[capability],
            required_permissions=[item.value for item in tool.manifest.declared_permissions],
            completion_criteria=[criterion],
            steps=[
                ProposedStep(
                    key=f"generated-{tool.action_spec.action_id}",
                    tool_id=tool.manifest.tool_id,
                    capability=capability,
                    input=validated.model_dump(mode="json"),
                    dependencies=[],
                    required_permissions=[
                        item.value for item in tool.manifest.declared_permissions
                    ],
                    expected_output=expected_output,
                    verification_rule="output_contains",
                    expected_evidence=[criterion],
                    expensive_action=bool(tool.manifest.declared_permissions),
                    max_retries=1 if tool.action_spec.retryable else 0,
                )
            ],
        )


__all__ = [
    "GeneratedActionPlanPlanner",
    "GeneratedCapabilityError",
    "GeneratedCapabilityToolAdapter",
    "GeneratedCapabilityToolRegistrar",
    "action_input_model",
    "action_output_model",
    "generated_tool_id",
    "validate_action_input",
]
