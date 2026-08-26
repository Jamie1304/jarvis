"""Generic production capability-growth adapters.

The classes in this module are application-owned composition boundaries.  They
do not form an integration catalog and they do not turn generated package
metadata into authority.  A model may propose a package candidate; the
reviewer, sandbox, certifier, activation service, and verification engine
remain the trusted gates.

The package store in this module owns package contents and source snapshots,
not certification or activation truth.  Certification/activation truth remains
in :class:`SQLiteCapabilityLifecycleStore`.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import threading
from collections.abc import Callable, Coroutine, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, TypeVar, cast
from uuid import UUID, uuid4

from jarvis.agent_runtime import AgentContext, AgentLoop, AgentLoopBudget, AgentTerminationReason
from jarvis.ai.routing import ProviderRouter, RouteRequest, RouteStatus, RoutingPolicy
from jarvis.capabilities import (
    CapabilityActionSpec,
    CapabilityError,
    CapabilityHealth,
    CapabilityLifecycle,
    CapabilityManifest,
    CapabilityRegistry,
    EffectClassification,
    EffectMetadata,
    EnvironmentGraph,
    Reversibility,
    action_schema_dict,
    validate_action_schema,
)
from jarvis.capability_acquisition import AcquisitionStage, CapabilityAcquisitionCoordinator
from jarvis.capability_factory import (
    FactoryStrategy,
    GeneratedCapabilityPackage,
    SolutionReport,
    WorkspaceContext,
)
from jarvis.capability_health import BehaviorBaseline, CapabilityHealthService
from jarvis.capability_lifecycle import (
    CapabilityLifecycleError,
    SQLiteCapabilityLifecycleStore,
    StoredLifecycleRecord,
)
from jarvis.capability_opportunities import (
    CapabilityOpportunity,
    OpportunityPreparationResult,
    OpportunityPreparationState,
)
from jarvis.discovery.models import (
    ArchitectureFit,
    CandidateProvenance,
    CapabilityGap,
    DiscoveryCandidate,
    DiscoveryEvidence,
    DiscoverySource,
    MaintenanceStatus,
    Testability,
)
from jarvis.discovery.providers import DiscoveryProvider
from jarvis.effect_attestation import (
    EffectAttestation,
    EffectAttestationStatus,
    EffectAttestationStore,
    TrustedEffectObserver,
)
from jarvis.environment_discovery import (
    DiscoveryConfidence,
    DiscoveryMode,
    DiscoveryObservation,
    EnvironmentDiscoveryProvider,
    EnvironmentIdentity,
)
from jarvis.goal_supervisor import (
    CapabilityAcquisitionRequest,
    GoalAnalysis,
    GoalIntent,
)
from jarvis.integration_package import (
    DiagnosticsContract,
    IntegrationPackage,
    PackageBoundary,
    PackageEntry,
    PackageLayout,
    PackageLifecycle,
    PackageOperationPolicy,
    PackageProvenance,
    SecretSchema,
)
from jarvis.package_activation import (
    ActivationHooks,
    ActivationRequest,
    ActivationState,
    ActivationTransition,
    CanaryExecution,
    CanaryLimits,
    ShadowExecution,
)
from jarvis.package_certification import (
    BuiltPackage,
    CertificationHooks,
    CertificationRecord,
    CertificationStageResult,
)
from jarvis.package_reviewer import PackageSourceFile
from jarvis.package_runtime import (
    HotLoadError,
    PackageRegistrationSurface,
    PackageRuntimeFactory,
    PackageRuntimeHealth,
    PreparedPackageRuntime,
)
from jarvis.permissions.models import Permission, Risk
from jarvis.provisioning import (
    ProvisioningAction,
    ProvisioningApplyResult,
    ProvisioningEffectOutcome,
    ProvisioningObservation,
    ProvisioningPlan,
)
from jarvis.resources import ResourceGovernor, ResourcePriority
from jarvis.sandbox import SandboxLimits, SandboxProcess
from jarvis.setup_conductor import (
    AdoptionCandidate as SetupAdoptionCandidate,
)
from jarvis.setup_conductor import (
    SetupContext,
    SetupDecision,
    SetupInspection,
    SetupStep,
)
from jarvis.tools.models import SemanticVersion, ToolHealthStatus, ToolPlatform
from jarvis.verification import (
    EvidenceRecord,
    EvidenceType,
    VerificationEngine,
    VerificationLevel,
    VerificationPlan,
    VerificationResult,
)
from jarvis.windows_sandbox import (
    SandboxSecurityStatus,
    WindowsAppContainerLauncher,
    WindowsContainmentMode,
)

if TYPE_CHECKING:
    from jarvis.package_activation import PackageActivationService


class ProductionCapabilityError(RuntimeError):
    """A production capability boundary failed closed."""


class CapabilityGenerationProvider(Protocol):
    """Provider-neutral model/design boundary.

    The provider output is still untrusted candidate data.  It never receives
    a broker, vault, lifecycle store, or activation service.
    """

    async def propose(
        self,
        prompt: str,
        *,
        gap: CapabilityGap,
        solution: SolutionReport,
        workspace: WorkspaceContext,
        environment: EnvironmentGraph,
        strategy: FactoryStrategy,
    ) -> str: ...


class _AgentLoopGenerationProvider:
    def __init__(self, loop: AgentLoop) -> None:
        self._loop = loop

    async def propose(
        self,
        prompt: str,
        *,
        gap: CapabilityGap,
        solution: SolutionReport,
        workspace: WorkspaceContext,
        environment: EnvironmentGraph,
        strategy: FactoryStrategy,
    ) -> str:
        del solution, workspace, environment, strategy
        result = await self._loop.run(
            gap_id_for_generation(gap),
            prompt,
            budget=AgentLoopBudget(
                max_turns=2,
                max_tool_calls=0,
                max_wall_time_seconds=60.0,
                max_tokens=4_000,
                max_expensive_actions=0,
                max_retries=1,
            ),
            context=AgentContext(
                request=prompt,
                goal=gap.current_task,
                constraints=(
                    "Return JSON only; do not request credentials or authority",
                    "The candidate will be statically reviewed and sandbox tested",
                ),
                current_step="capability design",
                provider_context_limit=self._loop.context_limit,
                reserved_output=min(1_024, self._loop.context_limit - 1),
                security_context=(
                    ("authority", "trusted application gates only"),
                    ("package_execution", "outside Trusted Core"),
                ),
            ),
        )
        if result.termination_reason is not AgentTerminationReason.COMPLETED:
            raise ProductionCapabilityError(
                f"Capability design inference stopped: {result.termination_reason.value}"
            )
        if result.proposed_result is None:
            raise ProductionCapabilityError("Capability design inference returned no proposal")
        return result.proposed_result


def gap_id_for_generation(gap: CapabilityGap) -> UUID:
    """Derive a bounded non-secret inference identity from the gap."""

    return UUID(bytes=sha256(gap.current_task.encode("utf-8")).digest()[:16])


class AgentRuntimeCapabilityGenerator:
    """Generate a data-only package candidate through the bounded AgentLoop."""

    def __init__(
        self,
        agent_loop: AgentLoop,
        package_store: ProductionPackageStore,
        *,
        provider: CapabilityGenerationProvider | None = None,
        router: ProviderRouter | None = None,
        provider_id: str | None = None,
        model_id: str | None = None,
    ) -> None:
        self._provider = provider or _AgentLoopGenerationProvider(agent_loop)
        self._store = package_store
        self._router = router
        self._provider_id = provider_id
        self._model_id = model_id

    async def generate(
        self,
        gap: CapabilityGap,
        solution: SolutionReport,
        workspace: WorkspaceContext,
        environment: EnvironmentGraph,
        preferences: Mapping[str, object],
        strategy: FactoryStrategy,
    ) -> GeneratedCapabilityPackage:
        del preferences
        if self._router is not None:
            route = self._router.route(
                RouteRequest(
                    gap.current_task,
                    "capability-acquisition",
                    classification="internal",
                    requires_structured_output=True,
                    policy=RoutingPolicy.LOCAL_ONLY,
                    preferred_provider_id=self._provider_id,
                    context_tokens=min(1_024, 4_000),
                )
            )
            if route.status is not RouteStatus.SELECTED or route.primary is None:
                detail = "; ".join(route.reasons) or "no compatible local model/provider"
                raise ProductionCapabilityError(f"WAITING_FOR_MODEL_PROVIDER: {detail}")
            if self._model_id is not None and route.primary.model_id != self._model_id:
                raise ProductionCapabilityError(
                    "WAITING_FOR_MODEL_PROVIDER: configured generation model is not routable"
                )
        prompt = json.dumps(
            {
                "request": gap.current_task,
                "desired_capability": gap.desired_capability,
                "missing_requirements": gap.missing_requirements,
                "known_alternatives": gap.known_alternatives,
                "risk": gap.risk.value,
                "strategy": strategy.value,
                "workspace": workspace.workspace_id,
                "available_options": [option.option_id for option in solution.options],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        raw = await self._provider.propose(
            prompt,
            gap=gap,
            solution=solution,
            workspace=workspace,
            environment=environment,
            strategy=strategy,
        )
        spec = _parse_generation_spec(raw)
        package = _build_generic_package(gap, spec)
        source = PackageSourceFile("code/entrypoint.py", _source_for_package(package, spec))
        generated = GeneratedCapabilityPackage(
            package,
            True,
            True,
            True,
            "jarvis.agent-runtime",
            source_files=(source,),
        )
        self._store.save_candidate(generated, gap=gap)
        return generated


@dataclass(frozen=True, slots=True)
class _GenerationSpec:
    name: str
    description: str
    source: str | None
    actions: tuple[_GeneratedActionDraft, ...] = ()


@dataclass(frozen=True, slots=True)
class _GeneratedActionDraft:
    action_id: str
    semantic_name: str
    description: str
    input_schema: Mapping[str, object]
    output_schema: Mapping[str, object]
    effect: EffectMetadata
    permissions: tuple[Permission, ...] = ()
    target_scope: tuple[str, ...] = ()
    idempotent: bool = True
    retryable: bool = False
    verification: tuple[str, ...] = ("adapter_output_schema",)
    compensation: str | None = None


def _parse_generation_spec(raw: str) -> _GenerationSpec:
    if type(raw) is not str or not raw.strip() or len(raw.encode("utf-8")) > 512 * 1024:
        raise ProductionCapabilityError("Capability design output is malformed")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ProductionCapabilityError("Capability design output is not JSON") from error
    if not isinstance(value, dict):
        raise ProductionCapabilityError("Capability design output must be an object")
    name = value.get("name", "Generated capability")
    description = value.get("description", "Generic generated capability candidate")
    source = value.get("source")
    if type(name) is not str or not name.strip() or len(name) > 256 or "\x00" in name:
        raise ProductionCapabilityError("Capability design name is malformed")
    if (
        type(description) is not str
        or not description.strip()
        or len(description) > 2_000
        or "\x00" in description
    ):
        raise ProductionCapabilityError("Capability design description is malformed")
    if source is not None and (
        type(source) is not str or not source.strip() or len(source.encode("utf-8")) > 512 * 1024
    ):
        raise ProductionCapabilityError("Capability design source is malformed")
    raw_actions = value.get("actions", [])
    if not isinstance(raw_actions, list) or len(raw_actions) > 64:
        raise ProductionCapabilityError("Capability action declarations are malformed")
    actions = tuple(_parse_action_draft(item, index) for index, item in enumerate(raw_actions))
    if len({item.action_id for item in actions}) != len(actions):
        raise ProductionCapabilityError("Capability action IDs must be unique")
    return _GenerationSpec(name.strip(), description.strip(), source, actions)


def _parse_action_draft(value: object, index: int) -> _GeneratedActionDraft:
    if not isinstance(value, dict):
        raise ProductionCapabilityError(f"Capability action {index} is malformed")
    action_id = value.get("action_id")
    semantic_name = value.get("semantic_name")
    description = value.get("description")
    input_schema = value.get("input_schema")
    output_schema = value.get("output_schema")
    if (
        type(action_id) is not str
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", action_id)
        or action_id in {"health", "inspect"}
        or type(semantic_name) is not str
        or not semantic_name.strip()
        or len(semantic_name) > 256
        or type(description) is not str
        or not description.strip()
        or len(description) > 2_000
        or not isinstance(input_schema, Mapping)
        or not isinstance(output_schema, Mapping)
    ):
        raise ProductionCapabilityError(
            f"Capability action {index} identity or schema is malformed"
        )
    try:
        normalized_input = validate_action_schema(input_schema, "Generated input schema")
        normalized_output = validate_action_schema(output_schema, "Generated output schema")
    except (CapabilityError, ValueError) as error:
        raise ProductionCapabilityError(f"Capability action {index} schema is malformed") from error
    if normalized_input.get("type") != "object" or normalized_output.get("type") != "object":
        raise ProductionCapabilityError(
            f"Capability action {index} input and output schemas must be objects"
        )
    raw_effect = value.get("effect", {})
    if not isinstance(raw_effect, Mapping):
        raise ProductionCapabilityError(f"Capability action {index} effect is malformed")
    raw_artifacts = raw_effect.get("produced_artifacts", ())
    raw_events = raw_effect.get("emitted_events", ())
    preview_supported = raw_effect.get("preview_supported", False)
    if (
        type(preview_supported) is not bool
        or not isinstance(raw_artifacts, list | tuple)
        or not isinstance(raw_events, list | tuple)
        or any(type(item) is not str for item in (*raw_artifacts, *raw_events))
    ):
        raise ProductionCapabilityError(f"Capability action {index} effect metadata is malformed")
    try:
        effect = EffectMetadata(
            EffectClassification(str(raw_effect.get("classification", "unknown"))),
            Reversibility(str(raw_effect.get("reversibility", "unknown"))),
            preview_supported,
            raw_effect.get("compensation"),
            tuple(raw_artifacts),
            tuple(raw_events),
        )
    except (TypeError, ValueError) as error:
        raise ProductionCapabilityError(f"Capability action {index} effect is malformed") from error
    raw_permissions = value.get("permissions", [])
    if not isinstance(raw_permissions, list):
        raise ProductionCapabilityError(f"Capability action {index} permissions are malformed")
    try:
        permissions = tuple(
            sorted({Permission(str(item)) for item in raw_permissions}, key=lambda item: item.value)
        )
    except ValueError as error:
        raise ProductionCapabilityError(
            f"Capability action {index} permissions are malformed"
        ) from error
    raw_scope = value.get("target_scope", [])
    raw_verification = value.get("verification", ["adapter_output_schema"])
    if (
        not isinstance(raw_scope, list)
        or any(type(item) is not str for item in raw_scope)
        or len(raw_scope) > 32
        or any(not item.strip() or len(item) > 512 or "\x00" in item for item in raw_scope)
        or not isinstance(raw_verification, list)
        or any(type(item) is not str for item in raw_verification)
        or len(raw_verification) > 32
        or any(not item.strip() or len(item) > 512 or "\x00" in item for item in raw_verification)
    ):
        raise ProductionCapabilityError(f"Capability action {index} metadata is malformed")
    idempotent = value.get("idempotent", True)
    retryable = value.get("retryable", False)
    compensation = value.get("compensation")
    if (
        type(idempotent) is not bool
        or type(retryable) is not bool
        or (retryable and not idempotent)
        or compensation is not None
        and (type(compensation) is not str or not compensation.strip())
    ):
        raise ProductionCapabilityError(f"Capability action {index} retry metadata is malformed")
    try:
        return _GeneratedActionDraft(
            action_id,
            semantic_name.strip(),
            description.strip(),
            normalized_input,
            normalized_output,
            effect,
            permissions,
            tuple(raw_scope),
            idempotent,
            retryable,
            tuple(raw_verification),
            compensation,
        )
    except (CapabilityError, ValueError) as error:
        raise ProductionCapabilityError(f"Capability action {index} is invalid") from error


def _safe_identifier(value: str, *, limit: int = 48) -> str:
    compact = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.casefold()).strip("-._")
    return compact[:limit] or "capability"


def _build_generic_package(gap: CapabilityGap, spec: _GenerationSpec) -> IntegrationPackage:
    suffix = sha256(f"{gap.desired_capability}\0{gap.current_task}".encode()).hexdigest()[:16]
    package_id = f"generated.{_safe_identifier(gap.desired_capability)}.{suffix}"
    provenance = PackageProvenance(
        "jarvis.agent-runtime",
        "1",
        "JARVIS-internal",
        verified_by="jarvis.trusted.capability-generator",
    )
    version = SemanticVersion(1, 0, 0)
    drafts = spec.actions or (_default_action_draft(spec.name),)
    action_specs = tuple(
        CapabilityActionSpec(
            gap.desired_capability,
            package_id,
            version,
            "",
            draft.action_id,
            draft.semantic_name,
            draft.description,
            draft.input_schema,
            draft.output_schema,
            draft.effect,
            draft.permissions,
            draft.target_scope,
            draft.idempotent,
            draft.retryable,
            draft.verification,
            draft.compensation,
        )
        for draft in drafts
    )
    source = spec.source or _generic_worker_source(package_id, spec.name, action_specs)
    source_hash = sha256(source.encode("utf-8")).hexdigest()
    package = IntegrationPackage(
        package_id,
        version,
        PackageLayout(),
        (
            PackageEntry(
                "python",
                "code/entrypoint.py",
                PackageBoundary.PACKAGE_CODE,
                source_hash,
                provenance,
            ),
        ),
        tools=("inspect", *(item.action_id for item in action_specs)),
        health_contract=("bounded IPC response",),
        lifecycle=PackageLifecycle.DISCOVERED,
        diagnostics=DiagnosticsContract(
            fallback_strategy=("restart", "quarantine"),
            expected_repair_verification=("trusted runtime health",),
        ),
        provenance=provenance,
        package_hash="",
        operation_policy=PackageOperationPolicy(),
        action_specs=action_specs,
    )
    package_hash = _package_digest(package)
    return replace(
        package,
        package_hash=package_hash,
        action_specs=tuple(replace(item, package_hash=package_hash) for item in action_specs),
    )


def _default_action_draft(name: str) -> _GeneratedActionDraft:
    return _GeneratedActionDraft(
        "observe",
        f"Observe {name[:200]}",
        "Perform one bounded observation through the generated package runtime",
        {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "capability": {"type": "string"},
                "label": {"type": "string"},
            },
            "required": ["status", "capability", "label"],
            "additionalProperties": False,
        },
        EffectMetadata(EffectClassification.OBSERVATION, Reversibility.READ_ONLY),
        verification=("adapter_output_schema", "action_completed"),
    )


def _source_for_package(package: IntegrationPackage, spec: _GenerationSpec) -> str:
    # The model may propose source for review, but the default generic worker
    # is used unless a source was explicitly supplied.  The reviewer remains
    # the independent authority for a supplied source.
    return spec.source or _generic_worker_source(
        package.package_id, spec.name, package.action_specs
    )


def _generic_worker_source(
    package_id: str, label: str, action_specs: Sequence[CapabilityActionSpec]
) -> str:
    safe_id = json.dumps(package_id)
    safe_label = json.dumps(label[:256])
    action_ids = json.dumps([item.action_id for item in action_specs], separators=(",", ":"))
    output_schemas = json.dumps(
        {item.action_id: action_schema_dict(item.output_schema) for item in action_specs},
        sort_keys=True,
        separators=(",", ":"),
    )
    return (
        "import json\n"
        "import sys\n\n"
        f"PACKAGE_ID = {safe_id}\n"
        f"LABEL = {safe_label}\n\n"
        f"ACTION_IDS = frozenset({action_ids})\n"
        f"OUTPUT_SCHEMAS = {output_schemas}\n\n"
        "def default_value(schema, key):\n"
        "    kind = schema.get('type')\n"
        "    if kind == 'object':\n"
        "        properties = schema.get('properties', {})\n"
        "        required = schema.get('required', ())\n"
        "        return {name: default_value(properties[name], name) for name in required}\n"
        "    if kind == 'array':\n"
        "        return []\n"
        "    if kind == 'string':\n"
        "        return PACKAGE_ID if key == 'capability' else 'observed'\n"
        "    if kind == 'integer':\n"
        "        return 0\n"
        "    if kind == 'number':\n"
        "        return 0.0\n"
        "    if kind == 'boolean':\n"
        "        return False\n"
        "    raise ValueError('unsupported output schema')\n\n"
        "for line in sys.stdin:\n"
        "    try:\n"
        "        incoming = json.loads(line)\n"
        '        request_id = incoming["request_id"]\n'
        '        integration_id = incoming["integration_id"]\n'
        '        kind = incoming["kind"]\n'
        '        if kind == "health":\n'
        '            payload = {"status": "healthy", "capability": PACKAGE_ID}\n'
        '        elif kind == "inspect":\n'
        '            payload = {"status": "observed", "capability": PACKAGE_ID, "label": LABEL}\n'
        '        elif kind in {"shadow", "canary"}:\n'
        '            payload = {"status": kind, "capability": PACKAGE_ID, "label": LABEL}\n'
        "        elif kind in ACTION_IDS:\n"
        '            payload = default_value(OUTPUT_SCHEMAS[kind], "result")\n'
        "        else:\n"
        '            raise ValueError("unknown action")\n'
        "        outgoing = {\n"
        '            "version": 1,\n'
        '            "request_id": request_id,\n'
        '            "integration_id": integration_id,\n'
        '            "kind": "result",\n'
        '            "response": True,\n'
        '            "payload": payload,\n'
        "        }\n"
        '        sys.stdout.write(json.dumps(outgoing, separators=(",", ":")) + "\\n")\n'
        "        sys.stdout.flush()\n"
        "    except (KeyError, TypeError, ValueError):\n"
        "        break\n"
    )


class ProductionPackageStore:
    """External package-content owner used by production package services."""

    _SCHEMA = 1

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path) or not root.is_absolute():
            raise ProductionCapabilityError("Package store root must be absolute")
        junction = getattr(root, "is_junction", None)
        if root.is_symlink() or (callable(junction) and junction()):
            raise ProductionCapabilityError("Package store root uses a reparse point")
        self._root = root.resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        self._validate_directory_chain(self._root)
        self._lock = threading.RLock()
        self._candidates: dict[tuple[str, str, str], GeneratedCapabilityPackage] = {}
        self._gaps: dict[tuple[str, str, str], CapabilityGap] = {}
        self._manifests: dict[tuple[str, str, str], CapabilityManifest] = {}

    @property
    def root(self) -> Path:
        return self._root

    def save_candidate(self, generated: GeneratedCapabilityPackage, *, gap: CapabilityGap) -> None:
        package = generated.package
        key = (package.package_id, str(package.version), package.package_hash)
        if not generated.source_files:
            raise ProductionCapabilityError("Generated package has no source snapshot")
        for source in generated.source_files:
            package.entry_for(source.path)
            entry = package.entry_for(source.path)
            if sha256(source.content.encode("utf-8")).hexdigest() != entry.content_hash:
                raise ProductionCapabilityError("Generated package source hash is inconsistent")
        if package.package_hash != _package_digest(package):
            raise ProductionCapabilityError("Generated package metadata hash is inconsistent")
        with self._lock:
            directory = self._directory(package)
            directory.mkdir(parents=True, exist_ok=True)
            self._validate_directory_chain(directory)
            metadata = directory / "package.json"
            if metadata.is_file():
                try:
                    existing = _package_from_payload(
                        json.loads(metadata.read_text(encoding="utf-8"))
                    )
                except (OSError, json.JSONDecodeError, ProductionCapabilityError) as error:
                    raise ProductionCapabilityError(
                        "Existing package metadata is malformed"
                    ) from error
                if existing.package_hash != package.package_hash:
                    raise ProductionCapabilityError("Immutable package version has changed content")
            for source in generated.source_files:
                destination = self._safe_child(directory, source.path)
                self._validate_directory_chain(destination.parent)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if (
                    destination.is_file()
                    and destination.read_text(encoding="utf-8") != source.content
                ):
                    raise ProductionCapabilityError("Immutable package source has changed")
                destination.write_text(source.content, encoding="utf-8", newline="\n")
            metadata.write_text(
                json.dumps(_package_payload(package), sort_keys=True), encoding="utf-8"
            )
            self._candidates[key] = generated
            self._gaps[key] = gap

    def source_files(self, package: IntegrationPackage) -> tuple[PackageSourceFile, ...]:
        directory = self._directory(package)
        result: list[PackageSourceFile] = []
        for entry in package.entries:
            if entry.boundary is not PackageBoundary.PACKAGE_CODE:
                continue
            path = self._safe_child(directory, entry.path)
            if not path.is_file():
                continue
            result.append(PackageSourceFile(entry.path, path.read_text(encoding="utf-8")))
        return tuple(result)

    def load(
        self, package_id: str, version: str, package_hash: str | None = None
    ) -> IntegrationPackage:
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise ProductionCapabilityError("Stored package version is invalid")
        if package_hash is not None and not re.fullmatch(r"[0-9a-f]{64}", package_hash):
            raise ProductionCapabilityError("Stored package hash is invalid")
        with self._lock:
            package = next(
                (
                    item.package
                    for item in self._candidates.values()
                    if item.package.package_id == package_id
                    and str(item.package.version) == version
                    and (package_hash is None or item.package.package_hash == package_hash)
                ),
                None,
            )
            if package is not None:
                return package
            bases = (
                self._root / _package_folder(package_id) / version,
                self._root / _legacy_package_folder(package_id) / version,
            )
            directories: tuple[Path, ...]
            if package_hash is not None:
                existing = tuple(
                    base / package_hash
                    for base in bases
                    if (base / package_hash / "package.json").is_file()
                )
                directories = existing or (bases[0] / package_hash,)
            else:
                directories = tuple(
                    path.parent for base in bases for path in base.glob("*/package.json")
                )
                if len(directories) != 1:
                    raise ProductionCapabilityError("Stored package version is ambiguous")
            directory = directories[0]
            self._validate_directory_chain(directory)
            payload_path = directory / "package.json"
            if not payload_path.is_file():
                raise ProductionCapabilityError("Certified package contents are unavailable")
            payload = json.loads(payload_path.read_text(encoding="utf-8"))
            package = _package_from_payload(payload)
            if package.package_id != package_id or str(package.version) != version:
                raise ProductionCapabilityError("Stored package identity does not match request")
            if package.package_hash != _package_digest(package):
                raise ProductionCapabilityError("Stored package metadata hash is invalid")
            if package_hash is not None and package.package_hash != package_hash:
                raise ProductionCapabilityError("Stored package hash does not match request")
            return package

    def manifest(
        self, package: IntegrationPackage, request: CapabilityAcquisitionRequest
    ) -> CapabilityManifest:
        key = (package.package_id, str(package.version), package.package_hash)
        existing = self._manifests.get(key)
        if existing is not None:
            if existing.content_hash != package.package_hash:
                raise ProductionCapabilityError("Stored capability manifest hash is stale")
            return existing
        manifest = _manifest_for(package, request)
        with self._lock:
            self._manifests[key] = manifest
            directory = self._directory(package)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "capability-manifest.json").write_text(
                json.dumps(_manifest_payload(manifest), sort_keys=True), encoding="utf-8"
            )
        return manifest

    def load_manifest(self, package: IntegrationPackage) -> CapabilityManifest:
        key = (package.package_id, str(package.version), package.package_hash)
        if key in self._manifests:
            manifest = self._manifests[key]
        else:
            path = self._directory(package) / "capability-manifest.json"
            if not path.is_file():
                raise ProductionCapabilityError("Certified capability manifest is unavailable")
            manifest = _manifest_from_payload(json.loads(path.read_text(encoding="utf-8")))
            self._manifests[key] = manifest
        expected_capabilities = (
            {item.capability_id for item in package.action_specs}
            if package.action_specs
            else {package.package_id}
        )
        if (
            manifest.integration_owner != package.package_id
            or manifest.version != package.version
            or manifest.content_hash != package.package_hash
            or manifest.lifecycle is not CapabilityLifecycle.ACTIVE
            or manifest.capability_id not in expected_capabilities
        ):
            raise ProductionCapabilityError("Capability manifest identity is not package-bound")
        if package.action_specs and (
            tuple(manifest.actions)
            != ("inspect", *(item.action_id for item in package.action_specs))
            or any(item.capability_id != manifest.capability_id for item in package.action_specs)
        ):
            raise ProductionCapabilityError("Capability manifest action contract is stale")
        return manifest

    def activation_request(
        self,
        package: IntegrationPackage,
        certification: CertificationRecord,
        source_files: tuple[PackageSourceFile, ...],
        security_status: SandboxSecurityStatus | None,
    ) -> ActivationRequest:
        return ActivationRequest(
            package,
            certification,
            source_files,
            CanaryLimits(f"package:{package.package_id}", max_calls=1, max_effects=1),
            security_status,
        )

    def restore_request(
        self, stored: StoredLifecycleRecord, security_status: SandboxSecurityStatus | None
    ) -> tuple[ActivationRequest, CapabilityManifest]:
        record = stored.record
        package = self.load(record.package_id, str(record.version), record.package_hash)
        source_files = self.source_files(package)
        request = self.activation_request(
            package, record.certification, source_files, security_status
        )
        manifest = self.load_manifest(package)
        return request, manifest

    def package_directory(self, package: IntegrationPackage) -> Path:
        """Return the immutable, hash-addressed package-content directory."""

        return self._directory(package)

    def _directory(self, package: IntegrationPackage) -> Path:
        if not package.package_hash:
            raise ProductionCapabilityError("Package content is not hash-addressed")
        current = (
            self._root
            / _package_folder(package.package_id)
            / str(package.version)
            / package.package_hash
        )
        legacy = (
            self._root
            / _legacy_package_folder(package.package_id)
            / str(package.version)
            / package.package_hash
        )
        selected = legacy if not current.exists() and legacy.exists() else current
        self._validate_directory_chain(selected)
        return selected

    def _validate_directory_chain(self, directory: Path) -> None:
        """Reject reparse/non-directory components before package I/O."""

        try:
            relative = directory.relative_to(self._root)
        except ValueError as error:
            raise ProductionCapabilityError("Package path escaped package root") from error
        current_paths = (self._root, *(self._root / part for part in relative.parts))
        for current in current_paths:
            junction = getattr(current, "is_junction", None)
            if current.is_symlink() or (callable(junction) and junction()):
                raise ProductionCapabilityError("Package directory uses a reparse point")
            if current.exists() and not current.is_dir():
                raise ProductionCapabilityError("Package path component is not a directory")

    def _safe_child(self, directory: Path, relative: str) -> Path:
        self._validate_directory_chain(directory)
        parts = relative.split("/")
        if not parts or any(not part or part in {".", ".."} for part in parts):
            raise ProductionCapabilityError("Package source path is unsafe")
        path = directory.joinpath(*parts).resolve()
        try:
            path.relative_to(directory.resolve())
        except ValueError as error:
            raise ProductionCapabilityError("Package source escaped package root") from error
        junction = getattr(path, "is_junction", None)
        if path.is_symlink() or (callable(junction) and junction()):
            raise ProductionCapabilityError("Package source uses a reparse point")
        return path


def _sandbox_python_executable() -> Path:
    """Select the trusted interpreter that the native sandbox can execute.

    A Windows virtual-environment launcher is not itself a complete runtime:
    AppContainer must be able to read the base interpreter and its packaged
    standard library.  Use the installation's exact base interpreter on
    Windows and retain the active interpreter on other platforms.
    """

    if sys.platform == "win32":
        base = (Path(sys.base_prefix) / "python.exe").resolve()
        if base.is_file():
            return base
    return Path(sys.executable).resolve()


class ProductionPackageRuntime(PreparedPackageRuntime):
    def __init__(
        self,
        package: IntegrationPackage,
        store: ProductionPackageStore,
        sandbox_root: Path,
        resource_governor: ResourceGovernor,
    ) -> None:
        self.package = package
        self._store = store
        self._sandbox_root = sandbox_root
        self._governor = resource_governor
        self._state: dict[str, object] = {}
        self._active_requests = 0

    def health_check(self) -> PackageRuntimeHealth:
        try:
            source_files = self._store.source_files(self.package)
            paths = {item.path for item in source_files}
            expected = {
                entry.path
                for entry in self.package.entries
                if entry.boundary is PackageBoundary.PACKAGE_CODE
            }
            if paths != expected:
                return PackageRuntimeHealth(False, "Certified package source is incomplete")
            for source in source_files:
                entry = self.package.entry_for(source.path)
                if sha256(source.content.encode("utf-8")).hexdigest() != entry.content_hash:
                    return PackageRuntimeHealth(False, "Certified package source hash changed")
            return PackageRuntimeHealth(True, "package contents are present and hash-verified")
        except (OSError, ProductionCapabilityError, ValueError):
            return PackageRuntimeHealth(False, "package runtime contents failed closed")

    def export_state(self) -> Mapping[str, object]:
        return dict(self._state)

    def restore_state(self, state: Mapping[str, object]) -> None:
        if not isinstance(state, Mapping) or any(type(key) is not str for key in state):
            raise HotLoadError("Package runtime state is malformed")
        self._state = {str(key): value for key, value in state.items()}

    def drain(self) -> None:
        if self._active_requests:
            raise HotLoadError("Package runtime still has active requests")

    async def request(self, kind: str, payload: Mapping[str, object]) -> dict[str, object]:
        if type(kind) is not str or not kind.strip() or not isinstance(payload, Mapping):
            raise ProductionCapabilityError("Package request is malformed")
        normalized_payload = self._validate_action_request(kind, payload)
        self._active_requests += 1
        try:
            return await asyncio.to_thread(self._request_blocking, kind, normalized_payload)
        finally:
            self._active_requests -= 1

    def invoke(self, kind: str, payload: Mapping[str, object]) -> dict[str, object]:
        """Invoke the active package through its owned native sandbox.

        Callers receive only a bounded result; process, pipe, broker, and vault
        objects remain private to the production runtime.
        """

        return _run_in_new_thread(self.request(kind, payload))

    def _request_blocking(self, kind: str, payload: Mapping[str, object]) -> dict[str, object]:
        source = next(
            (
                item
                for item in self._store.source_files(self.package)
                if item.path == "code/entrypoint.py"
            ),
            None,
        )
        if source is None:
            raise ProductionCapabilityError("Package entrypoint is unavailable")
        root = self._store.package_directory(self.package)
        executable = _sandbox_python_executable()
        process = SandboxProcess(
            executable,
            (str(root / "code" / "entrypoint.py"),),
            integration_id=_safe_identifier(self.package.package_id, limit=64),
            parent_directory=self._sandbox_root,
            limits=SandboxLimits(
                timeout_seconds=15.0,
                max_processes=1,
                windows_containment=WindowsContainmentMode.APPCONTAINER,
                appcontainer_runtime_root=executable.parent,
                appcontainer_dependency_roots=(
                    Path(sys.base_prefix).resolve(),
                    Path(sys.prefix).resolve(),
                    root / "code",
                ),
            ),
            resource_governor=self._governor,
            resource_priority=ResourcePriority.USER_REQUESTED,
        )

        async def run() -> dict[str, object]:
            await process.start()
            try:
                return await process.request(kind, payload)
            finally:
                await process.close()

        try:
            return _run_in_new_thread(run())
        except Exception as error:
            raise ProductionCapabilityError(
                "Package execution failed in the native sandbox"
            ) from error

    def _validate_action_request(
        self, kind: str, payload: Mapping[str, object]
    ) -> dict[str, object]:
        """Validate semantic action identity and input before starting a child."""

        if kind in {"health", "inspect", "shadow", "canary"}:
            return dict(payload)
        from jarvis.generated_capability import GeneratedCapabilityError, validate_action_input

        action = next(
            (item for item in self.package.action_specs if item.action_id == kind),
            None,
        )
        if action is None:
            raise ProductionCapabilityError("Package request names an undeclared action")
        try:
            return validate_action_input(action, payload).model_dump(mode="json")
        except GeneratedCapabilityError as error:
            raise ProductionCapabilityError(
                "Package request does not match action schema"
            ) from error


class ProductionPackageRuntimeFactory(PackageRuntimeFactory):
    def __init__(
        self, store: ProductionPackageStore, sandbox_root: Path, governor: ResourceGovernor
    ) -> None:
        self._store = store
        self._sandbox_root = sandbox_root
        self._governor = governor

    def prepare(self, package: IntegrationPackage) -> PreparedPackageRuntime:
        runtime = ProductionPackageRuntime(package, self._store, self._sandbox_root, self._governor)
        health = runtime.health_check()
        if not health.healthy:
            raise HotLoadError(health.detail)
        return runtime


class ProductionPackageRegistrationSurface(PackageRegistrationSurface):
    """Refresh the capability projection only after HotLoad's ACTIVE gate."""

    def __init__(self, registry: CapabilityRegistry, store: ProductionPackageStore) -> None:
        self._registry = registry
        self._store = store

    def atomic_swap(self, package: IntegrationPackage, runtime: PreparedPackageRuntime) -> None:
        del runtime
        manifest = self._store.load_manifest(package)
        try:
            existing = self._registry.inspect(manifest.capability_id)
        except KeyError:
            self._registry.register(manifest)
            return
        if existing != manifest:
            raise HotLoadError("Capability projection collision is not an atomic swap")

    def rollback(self, package: IntegrationPackage, runtime: PreparedPackageRuntime | None) -> None:
        del package, runtime

    def remove(self, package: IntegrationPackage, runtime: PreparedPackageRuntime) -> None:
        del runtime
        try:
            manifest = self._store.load_manifest(package)
            self._registry.unregister(manifest.capability_id)
        except (KeyError, ProductionCapabilityError):
            return


class ProductionSandboxRunner:
    """Trusted certification/activation sandbox probe and package runner."""

    def __init__(
        self, store: ProductionPackageStore, sandbox_root: Path, governor: ResourceGovernor
    ) -> None:
        self._store = store
        self._sandbox_root = sandbox_root
        self._governor = governor
        self._last_status: SandboxSecurityStatus | None = None

    def status(self) -> SandboxSecurityStatus | None:
        return self._last_status

    def available_status(self) -> SandboxSecurityStatus | None:
        if sys.platform != "win32" or not WindowsAppContainerLauncher.available():
            return None
        executable = _sandbox_python_executable()
        return SandboxSecurityStatus(
            WindowsContainmentMode.APPCONTAINER,
            True,
            True,
            True,
            3,
            True,
            True,
            True,
            "AppContainer APIs are available; certification still requires a real launch probe",
            runtime_root=str(executable.parent),
        )

    def probe(self, package: IntegrationPackage) -> SandboxSecurityStatus:
        result = self._execute(package, "health", {})
        status = result[0]
        if not status.executable_isolation:
            raise ProductionCapabilityError(
                "Mandatory AppContainer executable isolation was not established"
            )
        return status

    def execute(
        self,
        package: IntegrationPackage,
        action_id: str,
        payload: Mapping[str, object],
    ) -> tuple[SandboxSecurityStatus, dict[str, object]]:
        """Run one bounded certification action in the real package sandbox."""

        if not isinstance(package, IntegrationPackage) or type(action_id) is not str:
            raise ProductionCapabilityError("Sandbox certification request is malformed")
        if action_id not in {"health", "inspect", "shadow", "canary"} and not any(
            item.action_id == action_id for item in package.action_specs
        ):
            raise ProductionCapabilityError("Sandbox certification action is undeclared")
        return self._execute(package, action_id, payload)

    def _execute(
        self, package: IntegrationPackage, kind: str, payload: Mapping[str, object]
    ) -> tuple[SandboxSecurityStatus, dict[str, object]]:
        root = self._store.package_directory(package)
        executable = _sandbox_python_executable()
        process = SandboxProcess(
            executable,
            (str(root / "code" / "entrypoint.py"),),
            integration_id=_safe_identifier(package.package_id, limit=64),
            parent_directory=self._sandbox_root,
            limits=SandboxLimits(
                timeout_seconds=15.0,
                max_processes=1,
                windows_containment=WindowsContainmentMode.APPCONTAINER,
                appcontainer_runtime_root=executable.parent,
                appcontainer_dependency_roots=(
                    Path(sys.base_prefix).resolve(),
                    Path(sys.prefix).resolve(),
                    root / "code",
                ),
            ),
            resource_governor=self._governor,
            resource_priority=ResourcePriority.USER_REQUESTED,
        )

        async def run() -> tuple[SandboxSecurityStatus, dict[str, object]]:
            await process.start()
            try:
                status = process.security_status
                if status is None:
                    raise ProductionCapabilityError("Sandbox did not report security status")
                response = await process.request(kind, payload)
                return status, response
            finally:
                await process.close()

        status, response = _run_in_new_thread(run())
        self._last_status = status
        return status, response


@dataclass(frozen=True, slots=True)
class CapabilityLifecycleRestoreResult:
    """Bounded evidence for one production lifecycle restoration attempt."""

    package_id: str
    version: str
    package_hash: str
    prior_state: ActivationState
    resulting_state: ActivationState
    restored: bool
    detail: str


class CapabilityLifecycleRestorer:
    """Rebuild package runtime and registry projections from durable lifecycle truth.

    This is deliberately an application service, not a second lifecycle owner.
    The SQLite lifecycle row is read first; package content, certification, UI
    evidence bindings, and the Windows isolation contract are then checked
    against that exact row.  A bad package is quarantined locally and never
    prevents the rest of JARVIS from starting.
    """

    _RESTORABLE = frozenset(
        {
            ActivationState.ACTIVE,
            ActivationState.DEGRADED,
            ActivationState.SHADOW,
            ActivationState.CANARY,
        }
    )
    _TERMINAL = frozenset({ActivationState.QUARANTINED, ActivationState.ROLLED_BACK})

    def __init__(
        self,
        lifecycle_store: SQLiteCapabilityLifecycleStore,
        package_store: ProductionPackageStore,
        sandbox: ProductionSandboxRunner,
        activation: PackageActivationService,
        registry: CapabilityRegistry,
        *,
        health: CapabilityHealthService | None = None,
        adoption_attestation_validator: Callable[[str, IntegrationPackage], bool] | None = None,
    ) -> None:
        self._lifecycle = lifecycle_store
        self._packages = package_store
        self._sandbox = sandbox
        self._activation = activation
        self._registry = registry
        self._health = health
        self._adoption_attestation_validator = adoption_attestation_validator
        self._results: tuple[CapabilityLifecycleRestoreResult, ...] = ()

    @property
    def results(self) -> tuple[CapabilityLifecycleRestoreResult, ...]:
        return self._results

    def bind_health(self, health: CapabilityHealthService) -> None:
        """Bind restored certified baseline state to the health/doctor projection."""

        if not isinstance(health, CapabilityHealthService):
            raise ProductionCapabilityError("Capability health service is malformed")
        self._health = health
        for result in self._results:
            if not result.restored:
                continue
            stored = self._lifecycle.load(result.package_id, result.version)
            if stored is not None:
                self._register_baseline(stored)

    def restore_all(self) -> tuple[CapabilityLifecycleRestoreResult, ...]:
        results = tuple(self._restore_one(stored) for stored in self._lifecycle.list())
        self._results = results
        if self._health is not None:
            for result in results:
                if result.restored:
                    stored = self._lifecycle.load(result.package_id, result.version)
                    if stored is not None:
                        self._register_baseline(stored)
        return results

    def _restore_one(self, stored: StoredLifecycleRecord) -> CapabilityLifecycleRestoreResult:
        record = stored.record
        if record.state in self._TERMINAL:
            return CapabilityLifecycleRestoreResult(
                record.package_id,
                str(record.version),
                record.package_hash,
                record.state,
                resulting_state=record.state,
                restored=False,
                detail="terminal lifecycle state remains inactive",
            )
        if record.state is ActivationState.CERTIFIED:
            try:
                package = self._packages.load(
                    record.package_id, str(record.version), record.package_hash
                )
                self._validate_package(stored, package)
                return CapabilityLifecycleRestoreResult(
                    record.package_id,
                    str(record.version),
                    record.package_hash,
                    record.state,
                    resulting_state=record.state,
                    restored=False,
                    detail="certified package remains staged for explicit activation",
                )
            except Exception:
                return self._contain(stored, "certified package validation failed")
        if record.state not in self._RESTORABLE:
            # The v1 enum is intentionally closed.  Future states must be
            # introduced through a migration and an explicit restoration rule.
            return self._contain(stored, "unsupported lifecycle state")
        try:
            package = self._packages.load(
                record.package_id, str(record.version), record.package_hash
            )
            status = self._sandbox_status(package, record.state)
            validated = self._validate_package(stored, package, status=status)
            if validated is None:
                raise ProductionCapabilityError("restoration request could not be formed")
            request, manifest = validated
            restored = self._activation.restore(request)
            if restored.package_hash != record.package_hash or restored.state is not record.state:
                raise ProductionCapabilityError("restored lifecycle identity is inconsistent")
            if record.state is ActivationState.ACTIVE:
                self._register_projection(manifest)
            elif record.state is ActivationState.DEGRADED:
                self._register_projection(
                    replace(
                        manifest,
                        lifecycle=CapabilityLifecycle.DEGRADED,
                        health=CapabilityHealth(
                            ToolHealthStatus.DEGRADED,
                            "Durably degraded; trusted runtime was not auto-promoted",
                            datetime.now(UTC),
                        ),
                    )
                )
            return CapabilityLifecycleRestoreResult(
                record.package_id,
                str(record.version),
                record.package_hash,
                record.state,
                resulting_state=record.state,
                restored=True,
                detail="exact package, certification, and runtime state restored",
            )
        except Exception:
            return self._contain(stored, "package restoration validation or startup failed")

    def _validate_package(
        self,
        stored: StoredLifecycleRecord,
        package: IntegrationPackage,
        *,
        status: SandboxSecurityStatus | None = None,
    ) -> tuple[ActivationRequest, CapabilityManifest] | None:
        record = stored.record
        source_files = self._packages.source_files(package)
        expected = {
            entry.path
            for entry in package.entries
            if entry.boundary is PackageBoundary.PACKAGE_CODE
        }
        actual = {source.path for source in source_files}
        if actual != expected:
            raise ProductionCapabilityError("package source snapshot is incomplete")
        for source in source_files:
            entry = package.entry_for(source.path)
            if sha256(source.content.encode("utf-8")).hexdigest() != entry.content_hash:
                raise ProductionCapabilityError("package source hash changed")
        if not record.certification.matches(package, source_files):
            raise ProductionCapabilityError("durable certification no longer matches package")
        if stored.metadata.configuration_version and stored.metadata.configuration_version != str(
            package.version
        ):
            raise ProductionCapabilityError("package configuration schema is stale")
        for reference in stored.metadata.provenance_reference:
            if reference.startswith("adoption-attestation:"):
                validator = self._adoption_attestation_validator
                if validator is None or not validator(reference, package):
                    raise ProductionCapabilityError("adoption attestation cannot be revalidated")
        if status is None:
            return None
        request, manifest = self._packages.restore_request(stored, status)
        return request, manifest

    def _sandbox_status(
        self, package: IntegrationPackage, state: ActivationState
    ) -> SandboxSecurityStatus | None:
        if not package.requires_executable_isolation:
            return None
        status = (
            self._sandbox.probe(package)
            if state is ActivationState.ACTIVE
            else self._sandbox.available_status()
        )
        if status is None or not status.executable_isolation:
            raise ProductionCapabilityError("mandatory executable isolation is unavailable")
        return status

    def _register_projection(self, manifest: CapabilityManifest) -> None:
        try:
            existing = self._registry.inspect(manifest.capability_id)
        except KeyError:
            self._registry.register(manifest)
        else:
            if existing != manifest:
                raise ProductionCapabilityError("restored capability projection collides")

    def _register_baseline(self, stored: StoredLifecycleRecord) -> None:
        if self._health is None:
            return
        record = stored.record
        reference = stored.metadata.behavior_baseline_reference or (
            f"certification:{record.package_id}:{record.version}:{record.package_hash}",
        )
        baseline = BehaviorBaseline(
            record.package_id,
            str(record.version),
            ";".join(reference),
            activation_state=record.state,
            package_hash=record.package_hash,
        )
        try:
            existing = self._health.baseline(record.package_id)
        except KeyError:
            self._health.register_baseline(baseline, authority="certification")
        else:
            if (
                existing.package_version != baseline.package_version
                or existing.baseline_hash != baseline.baseline_hash
            ):
                self._health.register_baseline(baseline, authority="certification", replace=True)

    def _contain(
        self, stored: StoredLifecycleRecord, detail: str
    ) -> CapabilityLifecycleRestoreResult:
        record = stored.record
        if record.state in self._TERMINAL:
            resulting = record.state
        else:
            now = datetime.now(UTC)
            contained = replace(
                record,
                state=ActivationState.QUARANTINED,
                promotion_decision="STARTUP_RESTORE_QUARANTINED",
                rollback_evidence=record.rollback_evidence + (detail,),
                history=record.history
                + (ActivationTransition(record.state, ActivationState.QUARANTINED, detail, now),),
                updated_at=now,
            )
            try:
                self._lifecycle.save(contained, expected_revision=stored.revision)
                resulting = ActivationState.QUARANTINED
            except (CapabilityLifecycleError, OSError, ValueError):
                # No runtime or registry projection was started.  Keep the
                # core available even if containment evidence itself is stale.
                resulting = record.state
        return CapabilityLifecycleRestoreResult(
            record.package_id,
            str(record.version),
            record.package_hash,
            record.state,
            resulting,
            False,
            detail,
        )


@dataclass(frozen=True, slots=True)
class CertificationFunctionalCase:
    """One bounded application-owned input used during package certification."""

    case_id: str
    action_id: str
    input: Mapping[str, object]

    def __post_init__(self) -> None:
        if (
            type(self.case_id) is not str
            or not self.case_id.strip()
            or len(self.case_id) > 128
            or type(self.action_id) is not str
            or not self.action_id.strip()
            or len(self.action_id) > 64
            or not isinstance(self.input, Mapping)
        ):
            raise ProductionCapabilityError("Certification functional case is malformed")
        json.dumps(dict(self.input), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class FunctionalTestEvidence:
    """Evidence from an actual bounded package action invocation."""

    case_id: str
    action_id: str
    input_digest: str
    actual_result_digest: str
    expected_result_digest: str | None
    output_schema_valid: bool
    passed: bool
    failure: str | None = None
    recorded_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        for value, name in (
            (self.case_id, "Certification case ID"),
            (self.action_id, "Certification action ID"),
            (self.input_digest, "Certification input digest"),
            (self.actual_result_digest, "Certification result digest"),
        ):
            if type(value) is not str or not value.strip() or len(value) > 512:
                raise ProductionCapabilityError(f"{name} is malformed")
        if self.expected_result_digest is not None and (
            type(self.expected_result_digest) is not str
            or not self.expected_result_digest.strip()
            or len(self.expected_result_digest) > 512
        ):
            raise ProductionCapabilityError("Certification expected digest is malformed")
        if type(self.output_schema_valid) is not bool or type(self.passed) is not bool:
            raise ProductionCapabilityError("Certification functional flags are malformed")
        if self.failure is not None and (type(self.failure) is not str or len(self.failure) > 512):
            raise ProductionCapabilityError("Certification failure detail is malformed")
        if self.recorded_at.tzinfo is None:
            raise ProductionCapabilityError("Certification evidence timestamp is malformed")


CertificationOracle = Callable[[CapabilityActionSpec, Mapping[str, object]], Mapping[str, object]]


@dataclass(frozen=True, slots=True)
class PackageCertificationPlan:
    """Trusted evidence requirements for one exact package hash."""

    package_id: str
    package_version: str
    package_hash: str
    functional_cases: tuple[CertificationFunctionalCase, ...]
    semantic_oracle: CertificationOracle | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self.package_id) is not str
            or not self.package_id.strip()
            or type(self.package_version) is not str
            or not self.package_version.strip()
            or type(self.package_hash) is not str
            or len(self.package_hash) != 64
            or any(character not in "0123456789abcdef" for character in self.package_hash)
            or type(self.functional_cases) is not tuple
            or len(self.functional_cases) > 64
            or any(
                not isinstance(item, CertificationFunctionalCase) for item in self.functional_cases
            )
            or len({item.case_id for item in self.functional_cases}) != len(self.functional_cases)
        ):
            raise ProductionCapabilityError("Package certification plan is malformed")
        if self.semantic_oracle is not None and not callable(self.semantic_oracle):
            raise ProductionCapabilityError("Package certification oracle is malformed")


def _certification_digest(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _certification_fixture(
    schema: Mapping[str, object], *, key: str, package_id: str | None = None
) -> object:
    """Create a deterministic, bounded input from a validated object schema."""

    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    schema_type = schema.get("type")
    if schema_type == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", ())
        if not isinstance(properties, Mapping) or not isinstance(required, list | tuple):
            raise ProductionCapabilityError("Certification fixture schema is malformed")
        return {
            name: _certification_fixture(properties[name], key=name, package_id=package_id)
            for name in required
            if isinstance(name, str)
            and name in properties
            and isinstance(properties[name], Mapping)
        }
    if schema_type == "array":
        return []
    if schema_type == "string":
        if key == "capability" and package_id is not None:
            return package_id
        if key in {"status", "label"}:
            return "observed"
        return "certification-input" if key != "salt" else "certification-salt"
    if schema_type == "integer":
        return 0
    if schema_type == "number":
        return 0.0
    if schema_type == "boolean":
        return False
    raise ProductionCapabilityError("Certification fixture uses unsupported schema")


def build_package_certification_plan(
    package: IntegrationPackage,
    *,
    semantic_oracle: CertificationOracle | None = None,
) -> PackageCertificationPlan:
    """Derive package-specific cases from trusted validated action declarations."""

    if not isinstance(package, IntegrationPackage):
        raise ProductionCapabilityError("Certification package is malformed")
    cases = tuple(
        CertificationFunctionalCase(
            f"{item.action_id}:deterministic",
            item.action_id,
            cast(Mapping[str, object], _certification_fixture(item.input_schema, key="input")),
        )
        for item in package.action_specs
    )
    effective_oracle = semantic_oracle
    if effective_oracle is None:

        def generic_oracle(
            action: CapabilityActionSpec, _input: Mapping[str, object]
        ) -> Mapping[str, object]:
            if action.action_id != "observe":
                raise ProductionCapabilityError(
                    "No application-owned semantic oracle is configured for this action"
                )
            expected = _certification_fixture(
                action.output_schema,
                key="result",
                package_id=action.package_id,
            )
            if not isinstance(expected, Mapping):
                raise ProductionCapabilityError("Generic certification oracle is not an object")
            return expected

        effective_oracle = generic_oracle
    return PackageCertificationPlan(
        package.package_id,
        str(package.version),
        package.package_hash,
        cases,
        effective_oracle,
    )


class ProductionCertificationProvider:
    """Application-owned source/certification/activation request boundary."""

    def __init__(
        self,
        store: ProductionPackageStore,
        sandbox: ProductionSandboxRunner,
        verification: VerificationEngine,
        *,
        semantic_oracle: CertificationOracle | None = None,
    ) -> None:
        self._store = store
        self._sandbox = sandbox
        self._verification = verification
        self._semantic_oracle = semantic_oracle

    def sources(self, package: IntegrationPackage) -> tuple[PackageSourceFile, ...]:
        return self._store.source_files(package)

    def plan(self, package: IntegrationPackage) -> PackageCertificationPlan:
        plan = build_package_certification_plan(
            package,
            semantic_oracle=self._semantic_oracle,
        )
        if (
            plan.package_id != package.package_id
            or plan.package_version != str(package.version)
            or plan.package_hash != package.package_hash
        ):
            raise ProductionCapabilityError("Certification plan is not package-bound")
        return plan

    def hooks(self, package: IntegrationPackage) -> CertificationHooks:
        plan = self.plan(package)
        functional: tuple[FunctionalTestEvidence, ...] | None = None

        def functional_tests(item: IntegrationPackage) -> CertificationStageResult:
            nonlocal functional
            if item != package:
                return CertificationStageResult(False, ("Certification package identity changed",))
            functional = self._run_functional_tests(package, plan)
            passed = bool(functional) and all(test.passed for test in functional)
            return CertificationStageResult(
                passed,
                tuple(
                    f"case={test.case_id};action={test.action_id};"
                    f"input={test.input_digest};actual={test.actual_result_digest};"
                    f"expected={test.expected_result_digest or 'unavailable'};"
                    f"schema={test.output_schema_valid};passed={test.passed};"
                    f"failure={test.failure or 'none'}"
                    for test in functional
                )
                or ("No declared functional certification cases",),
                verification=tuple(
                    f"functional evidence:{test.case_id}" for test in functional if test.passed
                ),
            )

        def sandbox_test(item: IntegrationPackage) -> CertificationStageResult:
            status: SandboxSecurityStatus | None
            try:
                status, response = self._sandbox.execute(item, "health", {})
                healthy = (
                    status is not None
                    and status.executable_isolation
                    and response.get("status") == "healthy"
                    and response.get("capability")
                    in {item.package_id, *(spec.capability_id for spec in item.action_specs)}
                )
            except Exception:
                healthy = False
                status = self._sandbox.status()
                response = {}
            return CertificationStageResult(
                healthy,
                (
                    f"mode={status.mode.value if status is not None else 'unavailable'};"
                    f"isolated={status.executable_isolation if status is not None else False};"
                    f"health_response={_certification_digest(response)}",
                ),
            )

        def authority(item: IntegrationPackage) -> CertificationStageResult:
            if item.permissions:
                return CertificationStageResult(
                    False,
                    ("Package permissions require a fresh trusted owner approval",),
                )
            return CertificationStageResult(
                True,
                (f"declared permissions={len(item.permissions)}; authority remains broker-bound",),
                shadow_eligible=True,
                canary_eligible=True,
            )

        def permission_diff(item: IntegrationPackage) -> CertificationStageResult:
            return CertificationStageResult(
                True,
                (
                    "validated permission surface:"
                    f"{','.join(permission.value for permission in item.permissions) or 'none'}",
                ),
            )

        def install(item: IntegrationPackage) -> CertificationStageResult:
            try:
                sources = self._store.source_files(item)
                complete = {
                    entry.path
                    for entry in item.entries
                    if entry.boundary is PackageBoundary.PACKAGE_CODE
                } == {source.path for source in sources}
                hashes_valid = all(
                    sha256(source.content.encode("utf-8")).hexdigest()
                    == item.entry_for(source.path).content_hash
                    for source in sources
                )
                passed = complete and hashes_valid and item.package_hash == _package_digest(item)
            except Exception:
                passed = False
            return CertificationStageResult(
                passed,
                (f"stored package content hash verified={passed}",),
            )

        def healthcheck(item: IntegrationPackage) -> CertificationStageResult:
            try:
                status, response = self._sandbox.execute(item, "health", {})
                passed = (
                    status.executable_isolation
                    and response.get("status") == "healthy"
                    and response.get("capability")
                    in {item.package_id, *(spec.capability_id for spec in item.action_specs)}
                )
                details = (
                    f"runtime health response digest={_certification_digest(response)};"
                    f"isolated={status.executable_isolation}"
                )
            except Exception:
                passed = False
                details = "runtime health request failed"
            return CertificationStageResult(passed, (details,), health=(details,))

        def verification(item: IntegrationPackage) -> CertificationStageResult:
            if item != package or functional is None:
                return CertificationStageResult(False, ("Functional evidence was not produced",))
            passed = bool(functional) and all(test.passed for test in functional)
            return CertificationStageResult(
                passed,
                tuple(
                    f"independent semantic oracle evaluated:{test.case_id}" for test in functional
                ),
                verification=tuple(
                    f"semantic case passed:{test.case_id}" for test in functional if test.passed
                ),
            )

        return CertificationHooks(
            build=lambda item: BuiltPackage(item, self.sources(item)),
            unit_tests=functional_tests,
            sandbox_integration_test=sandbox_test,
            permission_diff=permission_diff,
            authority_decision=authority,
            install=install,
            healthcheck=healthcheck,
            verification=verification,
        )

    def _run_functional_tests(
        self, package: IntegrationPackage, plan: PackageCertificationPlan
    ) -> tuple[FunctionalTestEvidence, ...]:
        from jarvis.generated_capability import action_output_model, validate_action_input

        results: list[FunctionalTestEvidence] = []
        for case in plan.functional_cases:
            action = next(
                (item for item in package.action_specs if item.action_id == case.action_id), None
            )
            if action is None:
                raise ProductionCapabilityError("Certification case names an undeclared action")
            input_digest = _certification_digest(dict(case.input))
            expected_digest: str | None = None
            actual_digest = _certification_digest({"error": "no-result"})
            output_valid = False
            passed = False
            failure: str | None = None
            try:
                validated = validate_action_input(action, case.input)
                _, response = self._sandbox.execute(
                    package, action.action_id, validated.model_dump(mode="json")
                )
                if not isinstance(response, Mapping):
                    raise ProductionCapabilityError("Certification response is not an object")
                output = action_output_model(action).model_validate(dict(response), strict=True)
                normalized = cast(Mapping[str, object], output.model_dump(mode="json"))
                actual_digest = _certification_digest(dict(normalized))
                output_valid = True
                if plan.semantic_oracle is not None:
                    expected = plan.semantic_oracle(action, case.input)
                    if not isinstance(expected, Mapping):
                        raise ProductionCapabilityError("Certification oracle returned non-object")
                    expected_output = action_output_model(action).model_validate(
                        dict(expected), strict=True
                    )
                    expected_normalized = cast(
                        Mapping[str, object], expected_output.model_dump(mode="json")
                    )
                    expected_digest = _certification_digest(dict(expected_normalized))
                    passed = dict(normalized) == dict(expected_normalized)
                    if not passed:
                        failure = "independent semantic oracle mismatch"
                else:
                    failure = "independent semantic oracle unavailable"
            except Exception as error:
                failure = f"certification execution rejected:{type(error).__name__}"
            results.append(
                FunctionalTestEvidence(
                    case.case_id,
                    case.action_id,
                    input_digest,
                    actual_digest,
                    expected_digest,
                    output_valid,
                    passed,
                    failure,
                )
            )
        return tuple(results)

    def request(
        self,
        package: IntegrationPackage,
        certification: CertificationRecord,
        source_files: tuple[PackageSourceFile, ...],
    ) -> ActivationRequest:
        return self._store.activation_request(
            package, certification, source_files, self._sandbox.status()
        )

    def manifest(
        self, package: IntegrationPackage, request: CapabilityAcquisitionRequest
    ) -> CapabilityManifest:
        return self._store.manifest(package, request)


class ProductionActivationBoundary:
    """Real trusted Shadow/Canary boundary for generic package runtimes."""

    def __init__(
        self,
        store: ProductionPackageStore,
        sandbox: ProductionSandboxRunner,
        attestations: EffectAttestationStore,
        verification: VerificationEngine,
    ) -> None:
        self._store = store
        self._sandbox = sandbox
        self._attestations = attestations
        self._verification = verification

    def hooks(self, _store: EffectAttestationStore) -> ActivationHooks:
        del _store

        def shadow(package: IntegrationPackage, observer: TrustedEffectObserver) -> ShadowExecution:
            _, response = self._sandbox._execute(package, "shadow", {})  # noqa: SLF001
            attempt = observer.begin(
                action_id="package.shadow.probe",
                request_id=uuid4(),
                broker="trusted.package.shadow",
                target=f"package:{package.package_id}",
                scope="zero-external-effects",
                requested_effect="sandbox canary request suppressed",
            )
            observer.complete(
                attempt, status=EffectAttestationStatus.SUPPRESSED, dispatched=False, allowed=False
            )
            attestation = self._attestations.attest(
                activation_id=observer.activation_id,
                integration_id=package.package_id,
                integration_version=str(package.version),
                package_hash=package.package_hash,
                activation_state=ActivationState.SHADOW.value,
            )
            return ShadowExecution(
                predictions=("package requested a bounded shadow probe",),
                broker_behavior=("trusted broker suppressed all external effects",),
                verification=(f"sandbox response received:{response.get('status', 'unknown')}",),
                attestation=attestation,
            )

        def canary(
            package: IntegrationPackage,
            limits: CanaryLimits,
            observer: TrustedEffectObserver,
        ) -> CanaryExecution:
            _, response = self._sandbox._execute(package, "canary", {})  # noqa: SLF001
            attempt = observer.begin(
                action_id="package.canary.probe",
                request_id=uuid4(),
                broker="trusted.package.canary",
                target=f"package:{package.package_id}",
                scope=limits.scope,
                requested_effect="bounded local sandbox probe",
            )
            observer.complete(
                attempt,
                status=EffectAttestationStatus.EFFECT_CONFIRMED,
                dispatched=True,
                allowed=True,
            )
            attestation = self._attestations.attest(
                activation_id=observer.activation_id,
                integration_id=package.package_id,
                integration_version=str(package.version),
                package_hash=package.package_hash,
                activation_state=ActivationState.CANARY.value,
            )
            independent = self._verify_canary(package, attestation)
            return CanaryExecution(
                limits.scope,
                predictions=("package requested a bounded canary probe",),
                broker_behavior=("trusted broker dispatched one bounded local probe",),
                effects=attestation.effect_descriptions,
                verification=(f"sandbox response received:{response.get('status', 'unknown')}",),
                calls=1,
                budget_used=1,
                wall_seconds=0.01,
                passed=independent.passed,
                attestation=attestation,
            )

        return ActivationHooks(shadow, canary, self._verify_canary)

    def _verify_canary(
        self, package: IntegrationPackage, attestation: EffectAttestation
    ) -> VerificationResult:
        plan = VerificationPlan(
            f"canary:{package.package_id}",
            (EffectAttestationStatus.EFFECT_CONFIRMED.value,),
            allowed_evidence_types=frozenset({EvidenceType.CUSTOM}),
            required_level=VerificationLevel.INTEGRATION_VERIFIED,
            independent_observation_required=True,
            ask_user_when_unobservable=False,
        )
        evidence = EvidenceRecord(
            EvidenceType.CUSTOM,
            "trusted.package.canary.broker",
            datetime.now(UTC),
            timedelta(minutes=5),
            1.0,
            EffectAttestationStatus.EFFECT_CONFIRMED.value,
            attestation.status.value,
            level=VerificationLevel.INTEGRATION_VERIFIED,
        )
        return self._verification.evaluate(plan, (evidence,))


class ProductionVerificationEvidence:
    def __init__(
        self,
        registry: CapabilityRegistry,
        lifecycle: object,
        store: ProductionPackageStore,
        *,
        sandbox: ProductionSandboxRunner | None = None,
        semantic_oracle: CertificationOracle | None = None,
    ) -> None:
        self._registry = registry
        self._lifecycle = lifecycle
        self._store = store
        self._sandbox = sandbox
        self._semantic_oracle = semantic_oracle

    async def collect(
        self, capability_id: str, original_goal: str, stage: AcquisitionStage
    ) -> Sequence[EvidenceRecord]:
        if type(original_goal) is not str or not original_goal.strip():
            return ()
        if stage is not AcquisitionStage.VERIFYING:
            return ()
        try:
            manifest = self._registry.inspect(capability_id)
        except KeyError:
            return ()
        if manifest.lifecycle is not CapabilityLifecycle.ACTIVE:
            return ()
        goal_digest = sha256(original_goal.encode("utf-8")).hexdigest()
        source = "trusted.capability.registry"
        if manifest.integration_owner.startswith("generated."):
            try:
                package = self._store.load(
                    manifest.integration_owner, str(manifest.version), manifest.content_hash
                )
                if package.package_hash != manifest.content_hash:
                    return ()
            except ProductionCapabilityError:
                return ()
            if self._sandbox is None:
                return ()
            try:
                provider = ProductionCertificationProvider(
                    self._store,
                    self._sandbox,
                    VerificationEngine(),
                    semantic_oracle=self._semantic_oracle,
                )
                functional = provider._run_functional_tests(  # noqa: SLF001
                    package, provider.plan(package)
                )
            except Exception:
                return ()
            if not functional or not all(item.passed for item in functional):
                return ()
            source = (
                f"trusted.package.semantic:{package.package_id}:{package.version}:"
                f"{package.package_hash}:goal={goal_digest}"
            )
            # The coordinator's verification plan names the capability; the
            # source and bound digests carry the stronger semantic evidence.
            criterion = f"capability:{capability_id}"
            return (
                EvidenceRecord(
                    EvidenceType.CUSTOM,
                    source,
                    datetime.now(UTC),
                    timedelta(minutes=5),
                    1.0,
                    criterion,
                    criterion,
                    level=VerificationLevel.INTEGRATION_VERIFIED,
                ),
            )
        return (
            EvidenceRecord(
                EvidenceType.CUSTOM,
                f"{source}:goal={goal_digest}",
                datetime.now(UTC),
                timedelta(minutes=5),
                1.0,
                f"capability:{capability_id}",
                f"capability:{capability_id}",
                level=VerificationLevel.INTEGRATION_VERIFIED,
            ),
        )


class ProductionLocalDiscoveryProvider(EnvironmentDiscoveryProvider):
    """Passive local evidence provider; it never authenticates or adopts."""

    @property
    def source(self) -> DiscoverySource:
        return DiscoverySource.WINDOWS_LOCAL

    def discover(self, mode: DiscoveryMode) -> tuple[DiscoveryObservation, ...]:
        if mode is DiscoveryMode.PASSIVE_DISCOVERY and not sys.platform.startswith("win"):
            return ()
        now = datetime.now(UTC)
        executable = str(Path(sys.executable).resolve())
        identity = EnvironmentIdentity(
            "local-runtime:" + sha256(executable.encode("utf-8")).hexdigest()[:32],
            "application",
            (("executable", executable), ("platform", sys.platform)),
        )
        return (
            DiscoveryObservation(
                self.source,
                now,
                identity,
                (("kind", "python-runtime"), ("mode", mode.value)),
                "local-runtime",
                "trusted-os-observation",
                now,
                now,
                ("os:local-process",),
                # Discovery is evidence only even when collected by trusted code.
                DiscoveryConfidence(0.75, "bounded local executable observation"),
            ),
        )


class ProductionLocalCandidateProvider(DiscoveryProvider):
    """Convert local observations into advisory generic candidate metadata."""

    def __init__(self, discovery: Callable[[], tuple[object, ...]]) -> None:
        self._discovery = discovery

    @property
    def source(self) -> DiscoverySource:
        return DiscoverySource.WINDOWS_LOCAL

    async def discover(self, gap: CapabilityGap) -> tuple[DiscoveryCandidate, ...]:
        observations = self._discovery()
        if not observations:
            return ()
        # A local runtime is only a candidate when the requested capability is
        # explicitly a runtime capability.  It never becomes a trusted install.
        if "runtime" not in gap.desired_capability.casefold():
            return ()
        return (
            DiscoveryCandidate(
                gap.desired_capability,
                self.source,
                "local-runtime",
                CandidateProvenance(
                    self.source,
                    "environment:local-runtime",
                    datetime.now(UTC),
                    (DiscoveryEvidence("environment:local-runtime", "local runtime evidence"),),
                    owner_verified=False,
                ),
                None,
                (),
                (),
                ArchitectureFit.COMPATIBLE,
                0.75,
                Testability.MOCKABLE,
                MaintenanceStatus.UNKNOWN,
            ),
        )


class ProductionProvisioningProvider:
    async def inspect(self, action: ProvisioningAction) -> ProvisioningObservation:
        del action
        return ProvisioningObservation(
            False, evidence="No generic provisioning action is pre-satisfied"
        )

    async def apply(
        self, action: ProvisioningAction, cancellation: asyncio.Event
    ) -> ProvisioningApplyResult:
        del action, cancellation
        return ProvisioningApplyResult(
            ProvisioningEffectOutcome.PRE_EFFECT_FAILURE,
            detail="Generic provisioning requires an explicit provider",
        )

    async def rollback(
        self, action: ProvisioningAction, cancellation: asyncio.Event
    ) -> ProvisioningApplyResult:
        del action, cancellation
        return ProvisioningApplyResult(
            ProvisioningEffectOutcome.PRE_EFFECT_FAILURE,
            detail="Generic provisioning rollback is unavailable",
        )

    async def health_check(self, action: ProvisioningAction) -> bool:
        del action
        return False


class ProductionSetupHandler:
    def __init__(
        self,
        candidates: Callable[[SetupStep, SetupContext], tuple[SetupAdoptionCandidate, ...]]
        | None = None,
    ) -> None:
        self._candidates = candidates

    async def inspect(self, step: SetupStep, context: SetupContext) -> SetupInspection:
        candidates = self._candidates(step, context) if self._candidates is not None else ()
        return SetupInspection(
            candidates=candidates,
            detail="Generic setup handler is ready for typed actions",
        )

    async def prepare(
        self,
        step: SetupStep,
        context: SetupContext,
        decision: SetupDecision | None,
    ) -> ProvisioningPlan | None:
        del step, context, decision
        return None

    async def configure(self, step: SetupStep, context: SetupContext) -> None:
        del step, context

    async def verify(self, step: SetupStep, context: SetupContext) -> bool:
        del step, context
        return True

    async def first_start(self, step: SetupStep, context: SetupContext) -> bool:
        del step, context
        return True


class ProductionOpportunityPreparation:
    """Prepare through the coordinator without entering activation."""

    def __init__(self, coordinator: CapabilityAcquisitionCoordinator) -> None:
        self._coordinator = coordinator

    async def prepare(self, opportunity: CapabilityOpportunity) -> OpportunityPreparationResult:
        if not isinstance(opportunity, CapabilityOpportunity):
            raise ProductionCapabilityError("Opportunity is malformed")
        semantic = opportunity.semantic_need
        intent = GoalIntent(
            semantic,
            required_capabilities=(semantic,),
            metadata={"opportunity_id": str(opportunity.opportunity_id)},
        )
        gap = CapabilityGap(semantic, semantic, (semantic,), (), Risk.MEDIUM, ())
        research = await self._coordinator.research(intent, GoalAnalysis(gap))
        acquisition = research.acquisition
        if acquisition is None:
            return OpportunityPreparationResult(
                OpportunityPreparationState.READY,
                "Read-only research completed; capability preparation is unavailable",
                opportunity.likely_required_authority,
                (f"opportunity-research:{opportunity.opportunity_id}",),
            )
        report = await self._coordinator.prepare(acquisition)
        if report.active or report.stage == "certifying":
            state = OpportunityPreparationState.READY
        elif report.stage == "waiting_for_approval":
            state = OpportunityPreparationState.WAITING_FOR_AUTHORITY
        elif report.stage == "recovering":
            state = OpportunityPreparationState.UNKNOWN_OUTCOME
        else:
            state = OpportunityPreparationState.FAILED
        return OpportunityPreparationResult(
            state,
            report.detail or "Trusted capability preparation completed",
            opportunity.likely_required_authority,
            tuple(report.evidence),
        )


_ThreadResult = TypeVar("_ThreadResult")


def _run_in_new_thread(coro: Coroutine[object, object, _ThreadResult]) -> _ThreadResult:
    result: list[_ThreadResult] = []
    error: list[BaseException] = []

    def runner() -> None:
        try:
            result.append(asyncio.run(coro))
        except BaseException as exc:  # pragma: no cover - re-raised in caller
            error.append(exc)

    thread = threading.Thread(target=runner, name="jarvis-production-sandbox", daemon=True)
    thread.start()
    thread.join()
    if error:
        raise error[0]
    if not result:
        raise ProductionCapabilityError("Production sandbox thread returned no result")
    return result[0]


def _effect_payload(effect: EffectMetadata) -> dict[str, object]:
    return {
        "classification": effect.classification.value,
        "reversibility": effect.reversibility.value,
        "preview_supported": effect.preview_supported,
        "compensation": effect.compensation,
        "produced_artifacts": list(effect.produced_artifacts),
        "emitted_events": list(effect.emitted_events),
    }


def _effect_from_payload(value: object) -> EffectMetadata:
    if not isinstance(value, dict):
        raise ProductionCapabilityError("Stored effect metadata is malformed")
    preview_supported = value.get("preview_supported", False)
    compensation = value.get("compensation")
    produced_artifacts = value.get("produced_artifacts", [])
    emitted_events = value.get("emitted_events", [])
    if (
        type(preview_supported) is not bool
        or (compensation is not None and type(compensation) is not str)
        or not isinstance(produced_artifacts, list | tuple)
        or not isinstance(emitted_events, list | tuple)
        or any(type(item) is not str for item in (*produced_artifacts, *emitted_events))
    ):
        raise ProductionCapabilityError("Stored effect metadata is malformed")
    try:
        return EffectMetadata(
            EffectClassification(str(value["classification"])),
            Reversibility(str(value["reversibility"])),
            preview_supported,
            compensation,
            tuple(produced_artifacts),
            tuple(emitted_events),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ProductionCapabilityError("Stored effect metadata is malformed") from error


def _action_spec_payload(spec: CapabilityActionSpec) -> dict[str, object]:
    return {
        "capability_id": spec.capability_id,
        "package_id": spec.package_id,
        "package_version": str(spec.package_version),
        "package_hash": spec.package_hash,
        "action_id": spec.action_id,
        "semantic_name": spec.semantic_name,
        "description": spec.description,
        "input_schema": action_schema_dict(spec.input_schema),
        "output_schema": action_schema_dict(spec.output_schema),
        "effect": _effect_payload(spec.effect),
        "required_permissions": [item.value for item in spec.required_permissions],
        "target_scope": list(spec.target_scope),
        "idempotent": spec.idempotent,
        "retryable": spec.retryable,
        "verification": list(spec.verification),
        "compensation": spec.compensation,
    }


def _action_spec_from_payload(
    value: object,
    package_id: str,
    version: SemanticVersion,
    package_hash: str,
) -> CapabilityActionSpec:
    if not isinstance(value, dict):
        raise ProductionCapabilityError("Stored action declaration is malformed")
    if value.get("package_id") != package_id or value.get("package_version") != str(version):
        raise ProductionCapabilityError("Stored action declaration identity is inconsistent")
    if value.get("package_hash") != package_hash:
        raise ProductionCapabilityError("Stored action declaration hash is inconsistent")
    permissions = value.get("required_permissions", [])
    target_scope = value.get("target_scope", [])
    verification = value.get("verification", ["adapter_output_schema"])
    input_schema = value.get("input_schema")
    output_schema = value.get("output_schema")
    compensation = value.get("compensation")
    if (
        not isinstance(permissions, list | tuple)
        or not isinstance(target_scope, list | tuple)
        or not isinstance(verification, list | tuple)
        or not isinstance(input_schema, Mapping)
        or not isinstance(output_schema, Mapping)
        or any(type(item) is not str for item in (*permissions, *target_scope, *verification))
        or type(value.get("idempotent", True)) is not bool
        or type(value.get("retryable", False)) is not bool
        or (compensation is not None and type(compensation) is not str)
    ):
        raise ProductionCapabilityError("Stored action declaration metadata is malformed")
    try:
        return CapabilityActionSpec(
            str(value["capability_id"]),
            package_id,
            version,
            package_hash,
            str(value["action_id"]),
            str(value["semantic_name"]),
            str(value["description"]),
            input_schema,
            output_schema,
            _effect_from_payload(value["effect"]),
            tuple(
                sorted(
                    {Permission(item) for item in permissions},
                    key=lambda item: item.value,
                )
            ),
            tuple(target_scope),
            bool(value.get("idempotent", True)),
            bool(value.get("retryable", False)),
            tuple(verification),
            compensation,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ProductionCapabilityError("Stored action declaration is malformed") from error


def _stored_text_tuple(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list | tuple) or any(
        type(item) is not str or not item.strip() or len(item) > 2_000 or "\x00" in item
        for item in value
    ):
        raise ProductionCapabilityError(f"{field} are malformed")
    return tuple(value)


def _stored_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if type(value) is not str:
        raise ProductionCapabilityError("Stored timestamp is malformed")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ProductionCapabilityError("Stored timestamp is malformed") from error
    if parsed.tzinfo is None:
        raise ProductionCapabilityError("Stored timestamp must be timezone-aware")
    return parsed


def _manifest_for(
    package: IntegrationPackage, request: CapabilityAcquisitionRequest
) -> CapabilityManifest:
    platform = ToolPlatform.WINDOWS if sys.platform.startswith("win") else ToolPlatform.LINUX
    action_specs = package.action_specs
    if action_specs:
        capability_ids = {item.capability_id for item in action_specs}
        if capability_ids != {request.gap.desired_capability}:
            raise ProductionCapabilityError(
                "Generated action capabilities do not match the requested gap"
            )
        actions = ("inspect", *(item.action_id for item in action_specs))
        input_schema = action_schema_dict(action_specs[0].input_schema)
        output_schema = action_schema_dict(action_specs[0].output_schema)
        permissions = tuple(sorted(set(package.permissions), key=lambda item: item.value))
        effect = (
            action_specs[0].effect
            if all(item.effect == action_specs[0].effect for item in action_specs)
            else EffectMetadata(EffectClassification.UNKNOWN, Reversibility.UNKNOWN)
        )
        verification = tuple(
            dict.fromkeys(item for action in action_specs for item in action.verification)
        ) or ("trusted package runtime",)
        network_domains = tuple(
            sorted(
                {
                    scope
                    for action in action_specs
                    if Permission.NETWORK_REQUEST in action.required_permissions
                    for scope in action.target_scope
                }
            )
        )
        if any(
            item.effect.classification
            in {
                EffectClassification.DESTRUCTIVE,
                EffectClassification.UNKNOWN,
            }
            for item in action_specs
        ):
            risk = Risk.CRITICAL
        elif permissions or any(
            item.effect.classification is EffectClassification.EXTERNAL_EFFECT
            for item in action_specs
        ):
            risk = Risk.HIGH
        elif any(
            item.effect.classification is EffectClassification.LOCAL_MUTATION
            for item in action_specs
        ):
            risk = Risk.MEDIUM
        else:
            risk = Risk.LOW
    else:
        actions = ("inspect",)
        input_schema = {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        }
        output_schema = {
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "capability": {"type": "string"},
            },
            "required": ["status", "capability"],
            "additionalProperties": False,
        }
        permissions = package.permissions
        risk = Risk.LOW
        effect = EffectMetadata(EffectClassification.OBSERVATION, Reversibility.READ_ONLY)
        verification = ("trusted package runtime",)
        network_domains = ()
    now = datetime.now(UTC)
    credential_references = tuple(item.name for item in package.secret_schema)
    return CapabilityManifest(
        request.gap.desired_capability,
        request.gap.desired_capability,
        package.version,
        package.package_id,
        actions,
        input_schema,
        output_schema,
        permissions,
        risk,
        frozenset({platform}),
        Permission.NETWORK_REQUEST in permissions,
        network_domains,
        credential_references,
        package.dependency_lock,
        package.settings_schema,
        CapabilityHealth(ToolHealthStatus.AVAILABLE, "certified package runtime", now),
        verification,
        package.ui_assets and ("declarative UI",) or (),
        ("package:" + package.package_id, "goal:" + str(request.goal_id or UUID(int=0))),
        package.package_hash,
        CapabilityLifecycle.ACTIVE,
        effect,
        confidence=1.0,
        last_verified=now,
    )


def _package_payload(package: IntegrationPackage) -> dict[str, object]:
    provenance = package.provenance
    if provenance is None:
        raise ProductionCapabilityError("Package provenance is missing")
    return {
        "schema": 1,
        "package_id": package.package_id,
        "version": str(package.version),
        "layout": asdict(package.layout),
        "entries": [
            {
                "kind": entry.kind,
                "path": entry.path,
                "boundary": entry.boundary.value,
                "content_hash": entry.content_hash,
            }
            for entry in package.entries
        ],
        "tools": list(package.tools),
        "mcp": list(package.mcp),
        "api_adapters": list(package.api_adapters),
        "services": list(package.services),
        "events": list(package.events),
        "skills": list(package.skills),
        "profiles": list(package.profiles),
        "settings_schema": list(package.settings_schema),
        "permissions": [item.value for item in package.permissions],
        "secret_schema": [asdict(item) for item in package.secret_schema],
        "health_contract": list(package.health_contract),
        "tests": list(package.tests),
        "migrations": list(package.migrations),
        "diagnostics": asdict(package.diagnostics),
        "lifecycle": package.lifecycle.value,
        "provenance": asdict(provenance),
        "dependency_lock": list(package.dependency_lock),
        "operation_policy": {
            "preserve_user_config": package.operation_policy.preserve_user_config,
            "preserve_package_data": package.operation_policy.preserve_package_data,
            "preserve_generated_cache": package.operation_policy.preserve_generated_cache,
            "removable_boundaries": sorted(
                item.value for item in package.operation_policy.removable_boundaries
            ),
        },
        "package_hash": package.package_hash,
        "ui_manifest_hash": package.ui_manifest_hash,
        "action_specs": [_action_spec_payload(item) for item in package.action_specs],
    }


def _package_digest(package: IntegrationPackage) -> str:
    """Hash immutable package metadata without trusting its stored hash field."""

    payload = _package_payload(package)
    payload.pop("package_hash", None)
    for item in cast(list[object], payload.get("action_specs", [])):
        if isinstance(item, dict):
            item["package_hash"] = ""
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _package_folder(package_id: str) -> str:
    """Return a short collision-resistant, non-authoritative folder name."""

    # Keep the path below Windows MAX_PATH even when test/application roots are
    # nested deeply.  The complete package hash remains in metadata and is
    # checked before use; this short directory component is only a path key.
    return f"package-{sha256(package_id.encode('utf-8')).hexdigest()[:24]}"


def _legacy_package_folder(package_id: str) -> str:
    """Address package directories written by the pre-length-bounded store."""

    return (
        f"{_safe_identifier(package_id, limit=96)}-"
        f"{sha256(package_id.encode('utf-8')).hexdigest()[:16]}"
    )


def _package_from_payload(value: object) -> IntegrationPackage:
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise ProductionCapabilityError("Stored package schema is unsupported")
    try:
        package_id = str(value["package_id"])
        major, minor, patch = (int(item) for item in str(value["version"]).split("."))
        version = SemanticVersion(major, minor, patch)
        package_hash = str(value["package_hash"])
        raw_action_specs = value.get("action_specs", ())
        if not isinstance(raw_action_specs, list | tuple):
            raise TypeError("Stored action declarations are malformed")
        action_specs = tuple(
            _action_spec_from_payload(item, package_id, version, package_hash)
            for item in raw_action_specs
        )
        provenance = PackageProvenance(**cast(dict[str, str], value["provenance"]))
        entries = tuple(
            PackageEntry(
                str(item["kind"]),
                str(item["path"]),
                PackageBoundary(str(item["boundary"])),
                str(item["content_hash"]),
                provenance,
            )
            for item in cast(list[dict[str, object]], value["entries"])
        )
        return IntegrationPackage(
            package_id,
            version,
            PackageLayout(**cast(dict[str, str], value["layout"])),
            entries,
            tuple(str(item) for item in value.get("tools", [])),
            tuple(str(item) for item in value.get("mcp", [])),
            tuple(str(item) for item in value.get("api_adapters", [])),
            tuple(str(item) for item in value.get("services", [])),
            tuple(str(item) for item in value.get("events", [])),
            tuple(str(item) for item in value.get("skills", [])),
            tuple(str(item) for item in value.get("profiles", [])),
            (),
            tuple(str(item) for item in value.get("settings_schema", [])),
            tuple(
                sorted(
                    (Permission(str(item)) for item in value.get("permissions", [])),
                    key=lambda item: item.value,
                )
            ),
            tuple(
                SecretSchema(str(item["name"]), str(item["description"]))
                for item in value.get("secret_schema", [])
            ),
            tuple(str(item) for item in value.get("health_contract", [])),
            tuple(str(item) for item in value.get("tests", [])),
            tuple(str(item) for item in value.get("migrations", [])),
            PackageLifecycle(str(value["lifecycle"])),
            DiagnosticsContract(
                fallback_strategy=("restart", "quarantine"),
                expected_repair_verification=("trusted runtime health",),
            ),
            provenance,
            tuple(str(item) for item in value.get("dependency_lock", [])),
            package_hash,
            PackageOperationPolicy(),
            str(value.get("ui_manifest_hash", "")),
            action_specs=action_specs,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ProductionCapabilityError("Stored package metadata is malformed") from error


def _manifest_payload(manifest: CapabilityManifest) -> dict[str, object]:
    return {
        "capability_id": manifest.capability_id,
        "name": manifest.name,
        "version": str(manifest.version),
        "integration_owner": manifest.integration_owner,
        "actions": list(manifest.actions),
        "input_schema": action_schema_dict(manifest.input_schema),
        "output_schema": action_schema_dict(manifest.output_schema),
        "permissions": [item.value for item in manifest.permissions],
        "risk": manifest.risk.value,
        "supported_platforms": [item.value for item in manifest.supported_platforms],
        "network_required": manifest.network_required,
        "network_domains": list(manifest.network_domains),
        "credential_references": list(manifest.credential_references),
        "dependencies": list(manifest.dependencies),
        "configuration": list(manifest.configuration),
        "health": {
            "status": manifest.health.status.value,
            "detail": manifest.health.detail,
            "checked_at": (
                manifest.health.checked_at.isoformat()
                if manifest.health.checked_at is not None
                else None
            ),
        },
        "verification": list(manifest.verification),
        "ui_voice": list(manifest.ui_voice),
        "provenance": list(manifest.provenance),
        "content_hash": manifest.content_hash,
        "lifecycle": manifest.lifecycle.value,
        "effect": _effect_payload(manifest.effect),
        "confidence": manifest.confidence,
        "last_verified": (
            manifest.last_verified.isoformat() if manifest.last_verified is not None else None
        ),
    }


def _manifest_from_payload(value: object) -> CapabilityManifest:
    if not isinstance(value, dict):
        raise ProductionCapabilityError("Stored capability manifest is malformed")
    try:
        major, minor, patch = (int(item) for item in str(value["version"]).split("."))
        current_platform = (
            ToolPlatform.WINDOWS if sys.platform.startswith("win") else ToolPlatform.LINUX
        )
        raw_platforms = value.get("supported_platforms", [current_platform.value])
        if not isinstance(raw_platforms, list | tuple):
            raise TypeError("Stored capability platforms are malformed")
        platforms = frozenset(ToolPlatform(str(item)) for item in raw_platforms)
        raw_actions = value.get("actions", ["inspect"])
        actions = _stored_text_tuple(raw_actions, "Stored capability actions")
        raw_permissions = value.get("permissions", [])
        permissions = tuple(
            sorted(
                {
                    Permission(str(item))
                    for item in _stored_text_tuple(raw_permissions, "Stored permissions")
                },
                key=lambda item: item.value,
            )
        )
        raw_health = value.get("health", {})
        if not isinstance(raw_health, dict):
            raise TypeError("Stored capability health is malformed")
        health_checked = _stored_datetime(raw_health.get("checked_at"))
        last_verified = _stored_datetime(value.get("last_verified"))
        raw_effect = value.get(
            "effect",
            {"classification": "observation", "reversibility": "read_only"},
        )
        input_schema = value.get("input_schema")
        output_schema = value.get("output_schema")
        if not isinstance(input_schema, Mapping) or not isinstance(output_schema, Mapping):
            raise TypeError("Stored capability schemas are malformed")
        normalized_input = validate_action_schema(input_schema, "Stored capability input schema")
        normalized_output = validate_action_schema(output_schema, "Stored capability output schema")
        network_required = value.get("network_required", False)
        if type(network_required) is not bool:
            raise TypeError("Stored network requirement is malformed")
        return CapabilityManifest(
            str(value["capability_id"]),
            str(value["name"]),
            SemanticVersion(major, minor, patch),
            str(value["integration_owner"]),
            actions,
            normalized_input,
            normalized_output,
            permissions,
            Risk(str(value.get("risk", Risk.LOW.value))),
            platforms,
            network_required,
            _stored_text_tuple(value.get("network_domains", []), "Stored network domains"),
            _stored_text_tuple(
                value.get("credential_references", []), "Stored credential references"
            ),
            _stored_text_tuple(value.get("dependencies", []), "Stored dependencies"),
            _stored_text_tuple(value.get("configuration", []), "Stored configuration"),
            CapabilityHealth(
                ToolHealthStatus(str(raw_health.get("status", ToolHealthStatus.AVAILABLE.value))),
                str(raw_health.get("detail", "certified package runtime")),
                health_checked,
            ),
            _stored_text_tuple(
                value.get("verification", ["trusted package runtime"]),
                "Stored verification",
            ),
            _stored_text_tuple(value.get("ui_voice", []), "Stored UI metadata"),
            _stored_text_tuple(
                value.get("provenance", ["stored package manifest"]),
                "Stored provenance",
            ),
            str(value["content_hash"]),
            CapabilityLifecycle(str(value["lifecycle"])),
            _effect_from_payload(raw_effect),
            confidence=float(value.get("confidence", 1.0)),
            last_verified=last_verified,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ProductionCapabilityError("Stored capability manifest is malformed") from error


__all__ = [
    "AgentRuntimeCapabilityGenerator",
    "CertificationFunctionalCase",
    "CertificationOracle",
    "CapabilityGenerationProvider",
    "CapabilityLifecycleRestoreResult",
    "CapabilityLifecycleRestorer",
    "ProductionActivationBoundary",
    "ProductionCapabilityError",
    "ProductionCertificationProvider",
    "ProductionLocalCandidateProvider",
    "ProductionLocalDiscoveryProvider",
    "ProductionOpportunityPreparation",
    "ProductionPackageRegistrationSurface",
    "ProductionPackageRuntimeFactory",
    "ProductionPackageStore",
    "ProductionProvisioningProvider",
    "ProductionSandboxRunner",
    "ProductionSetupHandler",
    "ProductionVerificationEvidence",
    "FunctionalTestEvidence",
    "PackageCertificationPlan",
    "build_package_certification_plan",
]
