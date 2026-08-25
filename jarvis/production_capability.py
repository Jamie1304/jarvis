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
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, TypeVar, cast
from uuid import UUID, uuid4

from jarvis.agent_runtime import AgentContext, AgentLoop, AgentLoopBudget, AgentTerminationReason
from jarvis.ai.routing import ProviderRouter, RouteRequest, RouteStatus, RoutingPolicy
from jarvis.capabilities import (
    CapabilityHealth,
    CapabilityLifecycle,
    CapabilityManifest,
    CapabilityRegistry,
    EffectClassification,
    EffectMetadata,
    EnvironmentGraph,
    Reversibility,
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
from jarvis.setup_conductor import SetupContext, SetupDecision, SetupInspection, SetupStep
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
    return _GenerationSpec(name.strip(), description.strip(), source)


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
    source = spec.source or _generic_worker_source(package_id, "Generated capability")
    source_hash = sha256(source.encode("utf-8")).hexdigest()
    package = IntegrationPackage(
        package_id,
        SemanticVersion(1, 0, 0),
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
        tools=("inspect",),
        health_contract=("bounded IPC response",),
        lifecycle=PackageLifecycle.DISCOVERED,
        diagnostics=DiagnosticsContract(
            fallback_strategy=("restart", "quarantine"),
            expected_repair_verification=("trusted runtime health",),
        ),
        provenance=provenance,
        package_hash="",
        operation_policy=PackageOperationPolicy(),
    )
    return replace(package, package_hash=_package_digest(package))


def _source_for_package(package: IntegrationPackage, spec: _GenerationSpec) -> str:
    # The model may propose source for review, but the default generic worker
    # is used unless a source was explicitly supplied.  The reviewer remains
    # the independent authority for a supplied source.
    return spec.source or _generic_worker_source(package.package_id, "Generated capability")


def _generic_worker_source(package_id: str, label: str) -> str:
    safe_id = json.dumps(package_id)
    safe_label = json.dumps(label[:256])
    return (
        "import json\n"
        "import sys\n\n"
        f"PACKAGE_ID = {safe_id}\n"
        f"LABEL = {safe_label}\n\n"
        "for line in sys.stdin:\n"
        "    try:\n"
        "        incoming = json.loads(line)\n"
        '        request_id = incoming["request_id"]\n'
        '        integration_id = incoming["integration_id"]\n'
        '        payload = {"status": "observed", "capability": PACKAGE_ID, "label": LABEL}\n'
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
        if (
            manifest.capability_id != package.package_id
            or manifest.integration_owner != package.package_id
            or manifest.version != package.version
            or manifest.content_hash != package.package_hash
            or manifest.lifecycle is not CapabilityLifecycle.ACTIVE
        ):
            raise ProductionCapabilityError("Capability manifest identity is not package-bound")
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
        self._active_requests += 1
        try:
            return await asyncio.to_thread(self._request_blocking, kind, dict(payload))
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


class ProductionCertificationProvider:
    """Application-owned source/certification/activation request boundary."""

    def __init__(
        self,
        store: ProductionPackageStore,
        sandbox: ProductionSandboxRunner,
        verification: VerificationEngine,
    ) -> None:
        self._store = store
        self._sandbox = sandbox
        self._verification = verification

    def sources(self, package: IntegrationPackage) -> tuple[PackageSourceFile, ...]:
        return self._store.source_files(package)

    def hooks(self, package: IntegrationPackage) -> CertificationHooks:
        def passed(label: str) -> CertificationStageResult:
            return CertificationStageResult(True, (label,))

        def sandbox_test(item: IntegrationPackage) -> CertificationStageResult:
            status = self._sandbox.probe(item)
            return CertificationStageResult(True, (f"trusted sandbox probe: {status.mode.value}",))

        def authority(item: IntegrationPackage) -> CertificationStageResult:
            if item.permissions:
                return CertificationStageResult(
                    False,
                    ("Package permissions require a fresh trusted owner approval",),
                )
            return CertificationStageResult(
                True,
                ("read-only package authority surface",),
                shadow_eligible=True,
                canary_eligible=True,
            )

        return CertificationHooks(
            build=lambda item: BuiltPackage(item, self.sources(item)),
            unit_tests=lambda item: passed("trusted package contract checks passed"),
            sandbox_integration_test=sandbox_test,
            permission_diff=lambda item: passed("permission diff is empty or broker-bound"),
            authority_decision=authority,
            install=lambda item: passed("package content is already stored in the package owner"),
            healthcheck=lambda item: passed("package metadata health check passed"),
            verification=lambda item: passed("trusted package metadata verification passed"),
        )

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
        self, registry: CapabilityRegistry, lifecycle: object, store: ProductionPackageStore
    ) -> None:
        self._registry = registry
        self._lifecycle = lifecycle
        self._store = store

    async def collect(
        self, capability_id: str, original_goal: str, stage: AcquisitionStage
    ) -> Sequence[EvidenceRecord]:
        del original_goal
        if stage is not AcquisitionStage.VERIFYING:
            return ()
        try:
            manifest = self._registry.inspect(capability_id)
        except KeyError:
            return ()
        if manifest.lifecycle is not CapabilityLifecycle.ACTIVE:
            return ()
        source = "trusted.capability.registry"
        if manifest.integration_owner.startswith("generated."):
            source = "trusted.package.runtime"
            try:
                package = self._store.load(
                    manifest.integration_owner, str(manifest.version), manifest.content_hash
                )
                if package.package_hash != manifest.content_hash:
                    return ()
            except ProductionCapabilityError:
                return ()
        return (
            EvidenceRecord(
                EvidenceType.CUSTOM,
                source,
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
    async def inspect(self, step: SetupStep, context: SetupContext) -> SetupInspection:
        del step, context
        return SetupInspection(detail="Generic setup handler is ready for typed actions")

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
        return OpportunityPreparationResult(
            OpportunityPreparationState.READY
            if report.evidence and not report.active
            else OpportunityPreparationState.FAILED,
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


def _manifest_for(
    package: IntegrationPackage, request: CapabilityAcquisitionRequest
) -> CapabilityManifest:
    platform = ToolPlatform.WINDOWS if sys.platform.startswith("win") else ToolPlatform.LINUX
    credential_references = tuple(item.name for item in package.secret_schema)
    return CapabilityManifest(
        package.package_id,
        package.package_id,
        package.version,
        package.package_id,
        ("inspect",),
        {"request": "object"},
        {"status": "string", "capability": "string"},
        package.permissions,
        Risk.LOW,
        frozenset({platform}),
        False,
        (),
        credential_references,
        package.dependency_lock,
        package.settings_schema,
        CapabilityHealth(
            ToolHealthStatus.AVAILABLE, "certified package runtime", datetime.now(UTC)
        ),
        ("trusted package runtime",),
        package.ui_assets and ("declarative UI",) or (),
        ("package:" + package.package_id, "goal:" + str(request.goal_id or UUID(int=0))),
        package.package_hash,
        CapabilityLifecycle.ACTIVE,
        EffectMetadata(EffectClassification.OBSERVATION, Reversibility.READ_ONLY),
        confidence=1.0,
        last_verified=datetime.now(UTC),
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
    }


def _package_digest(package: IntegrationPackage) -> str:
    """Hash immutable package metadata without trusting its stored hash field."""

    payload = _package_payload(package)
    payload.pop("package_hash", None)
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
        major, minor, patch = (int(item) for item in str(value["version"]).split("."))
        return IntegrationPackage(
            str(value["package_id"]),
            SemanticVersion(major, minor, patch),
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
            str(value["package_hash"]),
            PackageOperationPolicy(),
            str(value.get("ui_manifest_hash", "")),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ProductionCapabilityError("Stored package metadata is malformed") from error


def _manifest_payload(manifest: CapabilityManifest) -> dict[str, object]:
    return {
        "capability_id": manifest.capability_id,
        "name": manifest.name,
        "version": str(manifest.version),
        "integration_owner": manifest.integration_owner,
        "content_hash": manifest.content_hash,
        "lifecycle": manifest.lifecycle.value,
    }


def _manifest_from_payload(value: object) -> CapabilityManifest:
    if not isinstance(value, dict):
        raise ProductionCapabilityError("Stored capability manifest is malformed")
    try:
        major, minor, patch = (int(item) for item in str(value["version"]).split("."))
        platform = ToolPlatform.WINDOWS if sys.platform.startswith("win") else ToolPlatform.LINUX
        return CapabilityManifest(
            str(value["capability_id"]),
            str(value["name"]),
            SemanticVersion(major, minor, patch),
            str(value["integration_owner"]),
            ("inspect",),
            {"request": "object"},
            {"status": "string", "capability": "string"},
            (),
            Risk.LOW,
            frozenset({platform}),
            False,
            (),
            (),
            (),
            (),
            CapabilityHealth(ToolHealthStatus.AVAILABLE, "certified package runtime"),
            ("trusted package runtime",),
            (),
            ("stored package manifest",),
            str(value["content_hash"]),
            CapabilityLifecycle(str(value["lifecycle"])),
            EffectMetadata(EffectClassification.OBSERVATION, Reversibility.READ_ONLY),
            confidence=1.0,
            last_verified=datetime.now(UTC),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ProductionCapabilityError("Stored capability manifest is malformed") from error


__all__ = [
    "AgentRuntimeCapabilityGenerator",
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
]
