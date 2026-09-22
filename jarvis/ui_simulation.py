"""Deterministic, side-effect-free simulation for generated integration UIs.

The harness consumes declarative package UI data only.  It has no ToolRegistry,
PermissionBroker, process, network, filesystem, or real capability executor.
Its fake capability endpoints record simulated calls and always report zero
external effects.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID, uuid4

from jarvis.artifacts import (
    ArtifactClassification,
    ArtifactReference,
    ArtifactStore,
)
from jarvis.integration_package import (
    IntegrationPackage,
    PackageAsset,
    PackageContractError,
    validate_package_path,
)


class UISimulationError(RuntimeError):
    """A simulation request or evidence boundary is invalid."""


class UISimulationValidationError(UISimulationError, ValueError):
    """Declarative UI data failed strict simulation validation."""


class UISimulationAttestationStatus(StrEnum):
    """Trusted result of a complete declarative UI simulation run."""

    PASS = "PASS"
    PASS_WITH_RESTRICTIONS = "PASS_WITH_RESTRICTIONS"
    FAIL = "FAIL"
    INVALID = "INVALID"
    STALE = "STALE"


_HARNESS_VERSION = "jarvis-ui-harness-v1"
_POLICY_VERSION = "jarvis-ui-policy-v1"
_ATTESTATION_ISSUER = object()


class UISimulationState(StrEnum):
    IDLE = "IDLE"
    ACTIVE = "ACTIVE"
    LOADING = "LOADING"
    ERROR = "ERROR"
    DEGRADED = "DEGRADED"
    DISCONNECTED = "DISCONNECTED"
    WAITING_PERMISSION = "WAITING_PERMISSION"


_DEFAULT_STATES = tuple(value.value for value in UISimulationState)


class UISimulationComponentKind(StrEnum):
    CONTAINER = "container"
    TEXT = "text"
    ARTIFACT = "artifact"
    IMAGE = "image"
    DOCUMENT = "document"
    CHART = "chart"
    PLAN = "plan"
    MODEL_COMPARISON = "model_comparison"
    CONTROL = "control"
    DECLARATIVE_VIEW = "declarative_view"


_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_STATE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_KEYS = frozenset(
    {
        "approval_authenticator",
        "code",
        "eval",
        "exec",
        "file",
        "filepath",
        "html",
        "javascript",
        "markup",
        "path",
        "permission_broker",
        "python",
        "script",
        "src",
        "trusted_approval",
    }
)
_APPROVAL_ACTIONS = frozenset(
    {
        "allow",
        "allow_once",
        "approve",
        "permission.approve",
        "permission.allow",
        "trusted.approve",
    }
)
_AUTHORITY_MARKERS = frozenset(
    {"allow", "approve", "authorize", "consent", "grant", "permission", "trusted", "yes"}
)
_MAX_COMPONENTS = 128
_MAX_ASSETS = 128
_MAX_ACTIONS = 128


def _id(value: object, field: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise UISimulationValidationError(f"{field} is malformed")
    return value


def _labels(values: object, name: str, limit: int, item_limit: int) -> None:
    if (
        type(values) is not tuple
        or len(values) > limit
        or any(
            type(value) is not str
            or not value.strip()
            or len(value) > item_limit
            or "\x00" in value
            for value in values
        )
    ):
        raise UISimulationValidationError(f"{name} are malformed")


def _text(value: object, field: str, limit: int = 512, *, empty: bool = False) -> str:
    if (
        type(value) is not str
        or len(value) > limit
        or (not empty and not value.strip())
        or "\x00" in value
        or "<script" in value.casefold()
        or "javascript:" in value.casefold()
    ):
        raise UISimulationValidationError(f"{field} is malformed")
    return value


def _data(value: object, *, field: str = "data", depth: int = 0) -> object:
    if depth > 6:
        raise UISimulationValidationError(f"{field} is too deeply nested")
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        if value != value or value in {float("inf"), float("-inf")}:
            raise UISimulationValidationError(f"{field} contains a non-finite number")
        return value
    if type(value) is str:
        return _text(value, field, 4_000, empty=True)
    if isinstance(value, Mapping):
        if len(value) > 64:
            raise UISimulationValidationError(f"{field} has too many properties")
        result: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str or not _ID.fullmatch(key) or key in _FORBIDDEN_KEYS:
                raise UISimulationValidationError(f"{field} contains an unsafe property")
            result[key] = _data(item, field=f"{field}.{key}", depth=depth + 1)
        return MappingProxyType(result)
    if isinstance(value, tuple | list):
        if len(value) > 128:
            raise UISimulationValidationError(f"{field} has too many items")
        return tuple(_data(item, field=f"{field}[]", depth=depth + 1) for item in value)
    raise UISimulationValidationError(f"{field} contains unsupported content")


def _jsonable(value: object) -> object:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value):
        return {item.name: _jsonable(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in sorted(value.items())}
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class UISimulationAsset:
    """A manifest asset that is package-owned or an opaque artifact reference."""

    asset_id: str
    content_hash: str
    package_path: str | None = None
    artifact: ArtifactReference | None = None

    def __post_init__(self) -> None:
        _id(self.asset_id, "Simulation asset ID")
        if type(self.content_hash) is not str or not _HASH.fullmatch(self.content_hash):
            raise UISimulationValidationError("Simulation asset hash is malformed")
        if (self.package_path is None) == (self.artifact is None):
            raise UISimulationValidationError("Simulation asset must have one safe source")
        if self.package_path is not None:
            try:
                validate_package_path(self.package_path)
            except PackageContractError as error:
                raise UISimulationValidationError("Simulation asset path is unsafe") from error
        if self.artifact is not None and not isinstance(self.artifact, ArtifactReference):
            raise UISimulationValidationError("Simulation artifact reference is malformed")


@dataclass(frozen=True, slots=True)
class UISimulationAction:
    action_id: str
    capability_id: str
    result: Mapping[str, object] = MappingProxyType({})

    def __post_init__(self) -> None:
        _id(self.action_id, "Simulation action ID")
        _id(self.capability_id, "Simulation capability ID")
        validated = _data(self.result, field="simulation action result")
        if not isinstance(validated, Mapping):
            raise UISimulationValidationError("Simulation action result must be an object")
        object.__setattr__(self, "result", validated)


@dataclass(frozen=True, slots=True)
class UISimulationComponent:
    component_id: str
    kind: UISimulationComponentKind
    title: str = ""
    text: str = ""
    data: Mapping[str, object] = MappingProxyType({})
    action_id: str | None = None
    asset_id: str | None = None
    visible_states: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _id(self.component_id, "Simulation component ID")
        if not isinstance(self.kind, UISimulationComponentKind):
            raise UISimulationValidationError("Simulation component kind is malformed")
        _text(self.title, "Simulation component title", empty=True)
        _text(self.text, "Simulation component text", 4_000, empty=True)
        validated = _data(self.data, field="simulation component data")
        if not isinstance(validated, Mapping):
            raise UISimulationValidationError("Simulation component data must be an object")
        object.__setattr__(self, "data", validated)
        if self.action_id is not None:
            _id(self.action_id, "Simulation component action ID")
        if self.asset_id is not None:
            _id(self.asset_id, "Simulation component asset ID")
        if type(self.visible_states) is not tuple or any(
            not _STATE.fullmatch(state) for state in self.visible_states
        ):
            raise UISimulationValidationError("Simulation component states are malformed")


@dataclass(frozen=True, slots=True)
class UISimulationManifest:
    package_id: str
    version: str
    root_component_id: str
    components: tuple[UISimulationComponent, ...]
    assets: tuple[UISimulationAsset, ...] = ()
    actions: tuple[UISimulationAction, ...] = ()
    states: tuple[str, ...] = _DEFAULT_STATES
    schema_version: str = "1"

    def __post_init__(self) -> None:
        _id(self.package_id, "Simulation package ID")
        _text(self.version, "Simulation package version")
        _id(self.root_component_id, "Simulation root component ID")
        _text(self.schema_version, "Simulation manifest schema version", 32)
        if type(self.components) is not tuple or not self.components:
            raise UISimulationValidationError("Simulation components are required")
        if len(self.components) > _MAX_COMPONENTS or any(
            not isinstance(item, UISimulationComponent) for item in self.components
        ):
            raise UISimulationValidationError("Simulation components exceed the bound")
        if (
            type(self.assets) is not tuple
            or len(self.assets) > _MAX_ASSETS
            or any(not isinstance(item, UISimulationAsset) for item in self.assets)
        ):
            raise UISimulationValidationError("Simulation assets are malformed")
        if (
            type(self.actions) is not tuple
            or len(self.actions) > _MAX_ACTIONS
            or any(not isinstance(item, UISimulationAction) for item in self.actions)
        ):
            raise UISimulationValidationError("Simulation actions are malformed")
        if (
            type(self.states) is not tuple
            or not self.states
            or any(type(item) is not str or not _STATE.fullmatch(item) for item in self.states)
        ):
            raise UISimulationValidationError("Simulation states are malformed")
        if len(set(self.states)) != len(self.states):
            raise UISimulationValidationError("Simulation states must be unique")
        if self.root_component_id not in {item.component_id for item in self.components}:
            raise UISimulationValidationError("Simulation root component is unknown")
        if len({item.component_id for item in self.components}) != len(self.components):
            raise UISimulationValidationError("Simulation component IDs must be unique")
        if len({item.asset_id for item in self.assets}) != len(self.assets):
            raise UISimulationValidationError("Simulation asset IDs must be unique")
        if len({item.action_id for item in self.actions}) != len(self.actions):
            raise UISimulationValidationError("Simulation action IDs must be unique")
        known_states = set(self.states)
        if any(
            state not in known_states for item in self.components for state in item.visible_states
        ):
            raise UISimulationValidationError("Component references an undeclared state")

    @property
    def manifest_hash(self) -> str:
        return _fingerprint(self)


@dataclass(frozen=True, slots=True)
class FakeCapabilityCall:
    action_id: str
    capability_id: str


@dataclass(frozen=True, slots=True)
class SimulationActionResult:
    action_id: str
    simulated: bool
    effect_count: int
    payload: Mapping[str, object]


class FakeCapabilityRegistry:
    """Capability-shaped endpoints that can never execute a real tool."""

    def __init__(self) -> None:
        self._actions: dict[str, UISimulationAction] = {}
        self._calls: list[FakeCapabilityCall] = []

    def register(self, action: UISimulationAction) -> None:
        if not isinstance(action, UISimulationAction) or action.action_id in self._actions:
            raise UISimulationValidationError("Simulation action registration is invalid")
        self._actions[action.action_id] = action

    def has(self, action_id: str) -> bool:
        return action_id in self._actions

    def invoke(self, action_id: str) -> SimulationActionResult:
        action = self._actions.get(action_id)
        if action is None:
            raise UISimulationError("Unknown simulated action")
        self._calls.append(FakeCapabilityCall(action.action_id, action.capability_id))
        return SimulationActionResult(action.action_id, True, 0, action.result)

    @property
    def calls(self) -> tuple[FakeCapabilityCall, ...]:
        return tuple(self._calls)

    @property
    def effect_count(self) -> int:
        return 0


@dataclass(frozen=True, slots=True)
class UISimulatedNode:
    component_id: str
    kind: UISimulationComponentKind
    title: str
    text: str
    action_id: str | None
    asset_id: str | None


@dataclass(frozen=True, slots=True)
class UISimulatedView:
    package_id: str
    version: str
    state: str
    nodes: tuple[UISimulatedNode, ...]
    controls: tuple[UISimulatedNode, ...]
    fingerprint: str


class UISimulationCheck(StrEnum):
    BINDINGS = "bindings"
    ASSETS = "assets"
    SECURITY = "security"
    DETERMINISM = "determinism"
    LAYOUT = "layout"
    ZERO_EFFECTS = "zero_effects"


@dataclass(frozen=True, slots=True)
class UISimulationEvidence:
    package_id: str
    version: str
    state: str
    passed: bool
    checks: tuple[tuple[UISimulationCheck, bool, str], ...]
    render_fingerprint: str
    artifact: ArtifactReference | None
    simulated_effect_count: int

    def certification_strings(self) -> tuple[str, ...]:
        result = [
            f"ui-simulation:package={self.package_id}",
            f"ui-simulation:version={self.version}",
            f"ui-simulation:state={self.state}",
            f"ui-simulation:fingerprint={self.render_fingerprint}",
        ]
        result.extend(f"ui-simulation:{name.value}={passed}" for name, passed, _ in self.checks)
        if self.artifact is not None:
            result.append(
                f"ui-simulation:artifact={self.artifact.artifact_id}:{self.artifact.version}"
            )
        return tuple(result)


@dataclass(frozen=True, slots=True)
class UISimulationAttestation:
    """Application-owned proof that the harness actually evaluated a UI.

    The private issuer marker and self-checking digest prevent ordinary package
    metadata, model output, or a caller-provided result from being accepted as
    trusted simulation evidence.  The marker is an application boundary, not a
    cryptographic signature; the attestation is trusted only inside the
    application-owned certification path.
    """

    attestation_id: UUID
    package_id: str
    version: str
    package_hash: str
    source_hash: str
    ui_manifest_hash: str
    schema_version: str
    harness_version: str
    policy_version: str
    tested_states: tuple[str, ...]
    semantic_checks: tuple[str, ...]
    security_checks: tuple[str, ...]
    asset_checks: tuple[str, ...]
    action_bindings: tuple[str, ...]
    zero_real_effect: bool
    artifact_refs: tuple[str, ...]
    issued_at: datetime
    result: UISimulationAttestationStatus
    attestation_digest: str
    _issuer: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.attestation_id, UUID):
            raise UISimulationValidationError("UI attestation ID is malformed")
        _id(self.package_id, "UI attestation package ID")
        _text(self.version, "UI attestation version", 128)
        for value, name in (
            (self.package_hash, "UI attestation package hash"),
            (self.source_hash, "UI attestation source hash"),
            (self.ui_manifest_hash, "UI attestation manifest hash"),
            (self.attestation_digest, "UI attestation digest"),
        ):
            if type(value) is not str or not _HASH.fullmatch(value):
                raise UISimulationValidationError(f"{name} is malformed")
        _text(self.schema_version, "UI attestation schema version", 32)
        _text(self.harness_version, "UI harness version", 64)
        _text(self.policy_version, "UI policy version", 64)
        for values, name in (
            (self.tested_states, "UI tested states"),
            (self.semantic_checks, "UI semantic checks"),
            (self.security_checks, "UI security checks"),
            (self.asset_checks, "UI asset checks"),
            (self.action_bindings, "UI action bindings"),
            (self.artifact_refs, "UI artifact references"),
        ):
            _labels(values, name, 256, 512)
        if type(self.zero_real_effect) is not bool:
            raise UISimulationValidationError("UI zero-effect result is malformed")
        if self.issued_at.tzinfo is None:
            raise UISimulationValidationError("UI attestation timestamp must be timezone-aware")
        if not isinstance(self.result, UISimulationAttestationStatus):
            raise UISimulationValidationError("UI attestation result is malformed")
        if self._issuer is not _ATTESTATION_ISSUER:
            raise UISimulationValidationError("UI attestation is not harness-issued")
        if self.attestation_digest != "0" * 64 and self.attestation_digest != _attestation_digest(
            self
        ):
            raise UISimulationValidationError("UI attestation digest is invalid")

    def valid_for(self, package: IntegrationPackage, source_hash: str) -> bool:
        """Validate identity and freshness against the built package revision."""

        return (
            isinstance(package, IntegrationPackage)
            and package.package_id == self.package_id
            and str(package.version) == self.version
            and package.package_hash == self.package_hash
            and (
                not (package.ui_assets or package.profiles)
                or package.ui_manifest_hash == self.ui_manifest_hash
            )
            and source_hash == self.source_hash
            and self.result
            in {
                UISimulationAttestationStatus.PASS,
                UISimulationAttestationStatus.PASS_WITH_RESTRICTIONS,
            }
            and self.zero_real_effect
            and self._issuer is _ATTESTATION_ISSUER
            and self.attestation_digest == _attestation_digest(self)
        )

    def certification_reference(self) -> str:
        return f"ui-simulation-attestation:{self.attestation_id}"

    @property
    def status(self) -> UISimulationAttestationStatus:
        """Compatibility alias for callers that use status-oriented evidence APIs."""

        return self.result

    def certification_strings(self) -> tuple[str, ...]:
        return (
            self.certification_reference(),
            f"ui-simulation-attestation:digest={self.attestation_digest}",
            f"ui-simulation-attestation:result={self.result.value}",
            *tuple(f"ui-simulation-attestation:state={state}" for state in self.tested_states),
            *tuple(f"ui-simulation-attestation:artifact={ref}" for ref in self.artifact_refs),
        )


@dataclass(frozen=True, slots=True)
class UISimulationShot:
    view: UISimulatedView
    evidence: UISimulationEvidence
    render_bytes: bytes


ScreenshotRenderer = Callable[[UISimulatedView], bytes]


class UISimulationHarness:
    """Load, render, inspect, and certify a declarative UI with zero effects."""

    def __init__(
        self,
        package: IntegrationPackage,
        *,
        artifact_store: ArtifactStore | None = None,
        workspace_id: str | None = None,
        screenshot_renderer: ScreenshotRenderer | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(package, IntegrationPackage):
            raise UISimulationValidationError("Simulation package is malformed")
        if artifact_store is not None and not workspace_id:
            raise UISimulationValidationError("Artifact-backed simulation needs a workspace")
        self._package = package
        self._artifact_store = artifact_store
        self._workspace_id = workspace_id
        self._screenshot_renderer = screenshot_renderer
        self._clock = clock or (lambda: datetime.now(UTC))
        self._manifest: UISimulationManifest | None = None
        self._capabilities = FakeCapabilityRegistry()

    def load_manifest(self, manifest: UISimulationManifest) -> None:
        if not isinstance(manifest, UISimulationManifest):
            raise UISimulationValidationError("Simulation manifest is malformed")
        if manifest.package_id != self._package.package_id or manifest.version != str(
            self._package.version
        ):
            raise UISimulationValidationError("Simulation manifest does not match package")
        if (
            self._package.ui_manifest_hash
            and manifest.manifest_hash != self._package.ui_manifest_hash
        ):
            raise UISimulationValidationError("Simulation manifest hash does not match package")
        self._capabilities = FakeCapabilityRegistry()
        for action in manifest.actions:
            self._capabilities.register(action)
        for asset in manifest.assets:
            self._validate_asset(asset)
        self._manifest = manifest

    def render(self, state: UISimulationState | str) -> UISimulatedView:
        manifest = self._require_manifest()
        state_name = self._state_name(state)
        nodes = tuple(
            UISimulatedNode(
                item.component_id,
                item.kind,
                item.title,
                item.text,
                item.action_id,
                item.asset_id,
            )
            for item in manifest.components
            if not item.visible_states or state_name in item.visible_states
        )
        controls = tuple(item for item in nodes if item.kind is UISimulationComponentKind.CONTROL)
        fingerprint = _fingerprint(
            {
                "package": manifest.package_id,
                "version": manifest.version,
                "state": state_name,
                "nodes": nodes,
            }
        )
        return UISimulatedView(
            manifest.package_id, manifest.version, state_name, nodes, controls, fingerprint
        )

    def shot(self, state: UISimulationState | str) -> UISimulationShot:
        manifest = self._require_manifest()
        view = self.render(state)
        repeat = self.render(state)
        checks: list[tuple[UISimulationCheck, bool, str]] = []
        checks.append(self._bindings_check(view))
        checks.append(self._assets_check(view, manifest))
        checks.append(self._security_check(view, manifest))
        checks.append(
            (
                UISimulationCheck.DETERMINISM,
                view.fingerprint == repeat.fingerprint,
                "semantic render fingerprint is stable",
            )
        )
        checks.append((UISimulationCheck.LAYOUT, True, "declarative layout rendered"))
        checks.append(
            (
                UISimulationCheck.ZERO_EFFECTS,
                self._capabilities.effect_count == 0,
                "fake capability endpoints report zero external effects",
            )
        )
        render_bytes = self._render_bytes(view)
        artifact = self._capture_artifact(render_bytes, view.state)
        evidence = UISimulationEvidence(
            manifest.package_id,
            manifest.version,
            view.state,
            all(passed for _, passed, _ in checks),
            tuple(checks),
            view.fingerprint,
            artifact,
            self._capabilities.effect_count,
        )
        return UISimulationShot(view, evidence, render_bytes)

    def run_all(self) -> tuple[UISimulationShot, ...]:
        manifest = self._require_manifest()
        return tuple(self.shot(state) for state in manifest.states)

    def attest(self, source_hash: str) -> UISimulationAttestation:
        """Run every declared state and issue trusted certification evidence.

        This is the only supported way to obtain a simulation attestation.  A
        package or model can provide UI data to the harness, but cannot provide
        the resulting attestation or its security conclusions.
        """

        manifest = self._require_manifest()
        if type(source_hash) is not str or not _HASH.fullmatch(source_hash):
            raise UISimulationValidationError("UI attestation source hash is malformed")
        shots = self.run_all()
        checks = {
            check: all(
                passed
                for shot in shots
                for check_name, passed, _ in shot.evidence.checks
                if check_name.value == check
            )
            for check in {item.value for shot in shots for item, _, _ in shot.evidence.checks}
        }
        artifact_refs = tuple(
            sorted(
                {
                    f"{shot.evidence.artifact.artifact_id}:{shot.evidence.artifact.version}"
                    for shot in shots
                    if shot.evidence.artifact is not None
                }
            )
        )
        result = (
            UISimulationAttestationStatus.PASS
            if all(checks.values()) and all(shot.evidence.passed for shot in shots)
            else UISimulationAttestationStatus.FAIL
        )
        semantic = tuple(
            sorted(
                check
                for check in checks
                if check in {UISimulationCheck.BINDINGS.value, UISimulationCheck.LAYOUT.value}
            )
        )
        security = tuple(
            sorted(
                check
                for check in checks
                if check in {UISimulationCheck.SECURITY.value, UISimulationCheck.ZERO_EFFECTS.value}
            )
        )
        assets = (
            (UISimulationCheck.ASSETS.value,) if UISimulationCheck.ASSETS.value in checks else ()
        )
        bindings = (
            (UISimulationCheck.BINDINGS.value,)
            if UISimulationCheck.BINDINGS.value in checks
            else ()
        )
        unsigned = UISimulationAttestation(
            uuid4(),
            self._package.package_id,
            str(self._package.version),
            self._package.package_hash,
            source_hash,
            _fingerprint(manifest),
            manifest.schema_version,
            _HARNESS_VERSION,
            _POLICY_VERSION,
            manifest.states,
            semantic,
            security,
            assets,
            bindings,
            self._capabilities.effect_count == 0,
            artifact_refs,
            self._clock(),
            result,
            "0" * 64,
            _ATTESTATION_ISSUER,
        )
        return _with_attestation_digest(unsigned)

    def invoke_simulated_action(self, action_id: str) -> SimulationActionResult:
        """Exercise a fake endpoint; this method cannot reach a real Tool."""

        return self._capabilities.invoke(action_id)

    @property
    def capabilities(self) -> FakeCapabilityRegistry:
        return self._capabilities

    def _require_manifest(self) -> UISimulationManifest:
        if self._manifest is None:
            raise UISimulationError("No UI simulation manifest has been loaded")
        return self._manifest

    def _state_name(self, state: UISimulationState | str) -> str:
        state_name = state.value if isinstance(state, UISimulationState) else state
        if type(state_name) is not str or state_name not in self._require_manifest().states:
            raise UISimulationValidationError("Simulation state is not declared")
        return state_name

    def _validate_asset(self, asset: UISimulationAsset) -> None:
        if asset.package_path is not None:
            try:
                self._package.validate_asset(
                    PackageAsset(asset.asset_id, package_path=asset.package_path)
                )
                entry = self._package.entry_for(asset.package_path)
            except PackageContractError as error:
                raise UISimulationValidationError(
                    "Package simulation asset is not declared"
                ) from error
            if entry.content_hash.lower() != asset.content_hash:
                raise UISimulationValidationError("Package simulation asset hash mismatches")
        elif self._artifact_store is None or self._workspace_id is None:
            raise UISimulationValidationError("Artifact simulation asset has no trusted store")
        else:
            if not isinstance(asset.artifact, ArtifactReference):
                raise UISimulationValidationError("Simulation artifact reference is malformed")
            try:
                version = self._artifact_store.get_version(
                    asset.artifact,
                    workspace_id=self._workspace_id,
                )
            except (KeyError, PermissionError, ValueError) as error:
                raise UISimulationValidationError("Simulation artifact is unavailable") from error
            if version.classification is ArtifactClassification.CREDENTIAL_SECRET:
                raise UISimulationValidationError("Credential secrets cannot be simulated")
            if version.content_hash != asset.content_hash:
                raise UISimulationValidationError("Simulation artifact hash mismatches")

    def _bindings_check(self, view: UISimulatedView) -> tuple[UISimulationCheck, bool, str]:
        missing = tuple(
            item.action_id
            for item in view.controls
            if item.action_id is not None and not self._capabilities.has(item.action_id)
        )
        return (
            UISimulationCheck.BINDINGS,
            not missing,
            "all rendered actions have fake endpoints"
            if not missing
            else "missing actions: " + ",".join(str(item) for item in missing),
        )

    def _assets_check(
        self, view: UISimulatedView, manifest: UISimulationManifest
    ) -> tuple[UISimulationCheck, bool, str]:
        asset_ids = {item.asset_id for item in manifest.assets}
        missing = tuple(
            item.asset_id
            for item in view.nodes
            if item.asset_id is not None and item.asset_id not in asset_ids
        )
        return (
            UISimulationCheck.ASSETS,
            not missing,
            "all rendered assets are manifest-declared"
            if not missing
            else "missing assets: " + ",".join(str(item) for item in missing),
        )

    @staticmethod
    def _security_check(
        view: UISimulatedView,
        manifest: UISimulationManifest,
    ) -> tuple[UISimulationCheck, bool, str]:
        actions = {item.action_id: item for item in manifest.actions}
        spoofed = tuple(
            item.component_id
            for item in view.controls
            if _looks_like_authority_control(item, actions)
        )
        return (
            UISimulationCheck.SECURITY,
            not spoofed,
            "no trusted approval controls are rendered"
            if not spoofed
            else "approval-like controls: " + ",".join(spoofed),
        )

    def _render_bytes(self, view: UISimulatedView) -> bytes:
        if self._screenshot_renderer is not None:
            rendered = self._screenshot_renderer(view)
            if type(rendered) is not bytes or len(rendered) > 8 * 1024 * 1024:
                raise UISimulationError("Screenshot renderer returned invalid or oversized data")
            return rendered
        return json.dumps(_jsonable(view), sort_keys=True, separators=(",", ":")).encode()

    def _capture_artifact(self, render_bytes: bytes, state: str) -> ArtifactReference | None:
        if self._artifact_store is None or self._workspace_id is None:
            return None
        return self._artifact_store.put(
            workspace_id=self._workspace_id,
            name=f"ui-simulation-{state.casefold()}.json",
            content=render_bytes,
            mime_type="application/json",
            classification=ArtifactClassification.INTERNAL,
            producer="ui-simulation-harness",
            provenance=(f"package:{self._package.package_id}", f"version:{self._package.version}"),
        )


def _fingerprint(value: object) -> str:
    encoded = json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _attestation_payload(value: UISimulationAttestation) -> dict[str, object]:
    return {
        "attestation_id": str(value.attestation_id),
        "package_id": value.package_id,
        "version": value.version,
        "package_hash": value.package_hash,
        "source_hash": value.source_hash,
        "ui_manifest_hash": value.ui_manifest_hash,
        "schema_version": value.schema_version,
        "harness_version": value.harness_version,
        "policy_version": value.policy_version,
        "tested_states": value.tested_states,
        "semantic_checks": value.semantic_checks,
        "security_checks": value.security_checks,
        "asset_checks": value.asset_checks,
        "action_bindings": value.action_bindings,
        "zero_real_effect": value.zero_real_effect,
        "artifact_refs": value.artifact_refs,
        "issued_at": value.issued_at.isoformat(),
        "result": value.result.value,
    }


def _attestation_digest(value: UISimulationAttestation) -> str:
    encoded = json.dumps(
        _jsonable(_attestation_payload(value)), sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _with_attestation_digest(value: UISimulationAttestation) -> UISimulationAttestation:
    return UISimulationAttestation(
        value.attestation_id,
        value.package_id,
        value.version,
        value.package_hash,
        value.source_hash,
        value.ui_manifest_hash,
        value.schema_version,
        value.harness_version,
        value.policy_version,
        value.tested_states,
        value.semantic_checks,
        value.security_checks,
        value.asset_checks,
        value.action_bindings,
        value.zero_real_effect,
        value.artifact_refs,
        value.issued_at,
        value.result,
        _attestation_digest(value),
        _ATTESTATION_ISSUER,
    )


def _looks_like_authority_control(
    item: UISimulatedNode,
    actions: Mapping[str, UISimulationAction],
) -> bool:
    if item.action_id is None:
        return False
    action = actions.get(item.action_id)
    values: tuple[str, ...] = (item.action_id, item.title, item.text)
    if action is not None:
        values += (action.capability_id,)
    normalized = tuple(
        token for value in values for token in re.split(r"[^a-z0-9]+", value.casefold()) if token
    )
    return any(token in _AUTHORITY_MARKERS for token in normalized) or any(
        item.action_id.casefold() == value.casefold() for value in _APPROVAL_ACTIONS
    )


__all__ = [
    "FakeCapabilityCall",
    "FakeCapabilityRegistry",
    "SimulationActionResult",
    "UISimulatedNode",
    "UISimulatedView",
    "UISimulationAction",
    "UISimulationAsset",
    "UISimulationAttestation",
    "UISimulationAttestationStatus",
    "UISimulationCheck",
    "UISimulationComponent",
    "UISimulationComponentKind",
    "UISimulationError",
    "UISimulationEvidence",
    "UISimulationHarness",
    "UISimulationManifest",
    "UISimulationShot",
    "UISimulationState",
    "UISimulationValidationError",
]
