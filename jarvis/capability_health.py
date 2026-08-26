"""Trusted capability health observations and certified behavior-drift checks.

This module is deliberately a monitor, not another capability, package, task,
or permission authority.  It owns bounded health reports and observations.  A
certifier supplies an immutable :class:`BehaviorBaseline`; generated code,
model output, and external event payloads cannot create or replace one.

Effectful repair is represented by a small application-owned provider contract.
The provider is still responsible for using the normal PermissionBroker and
typed capabilities.  This module never executes a command, resolves a secret,
or grants authority.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from json import dumps
from typing import Protocol
from uuid import UUID, uuid4

from jarvis.events import EventBus, EventEnvelope, EventType, HealthChanged
from jarvis.package_activation import ActivationState
from jarvis.trace import ExecutionTrace, TraceEvent, TraceEventType


class CapabilityHealthError(ValueError):
    """A health, baseline, observation, or repair contract is malformed."""


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    QUARANTINED = "quarantined"
    UNKNOWN = "unknown"


class HealthProbeMode(StrEnum):
    PASSIVE = "passive"
    READ_ONLY = "read_only"
    FUNCTIONAL = "functional"
    DEPENDENCY = "dependency"
    VERSION_API_COMPATIBILITY = "version_api_compatibility"
    VERSION_API = "version_api_compatibility"


class DependencyKind(StrEnum):
    INTEGRATION = "integration"
    LIBRARY = "library"
    SOFTWARE = "software"
    SERVICE = "service"
    MODEL = "model"
    API = "api"
    MCP = "mcp"
    CONFIG = "config"


class DriftClass(StrEnum):
    EXPECTED = "expected"
    LOW_RISK_DRIFT = "low_risk_drift"
    MATERIAL_DRIFT = "material_drift"
    SECURITY_DRIFT = "security_drift"


class RepairStage(StrEnum):
    DETECT = "detect"
    EVIDENCE = "evidence"
    DIAGNOSE = "diagnose"
    SAFE_REPAIR = "safe_repair"
    RETEST = "retest"
    REBUILD_OR_REPLACE = "rebuild_or_replace"
    AUTHORITY = "authority"
    COMPLETED = "completed"
    FAILED = "failed"


class RepairOutcome(StrEnum):
    COMPLETED = "completed"
    AUTHORITY_REQUIRED = "authority_required"
    FAILED = "failed"


_MAX_ITEMS = 128
_MAX_TEXT = 2_000
_MAX_FINDINGS = 4_096
_TRUSTED_BASELINE_AUTHORITIES = frozenset(
    {"application", "certification", "trusted_certifier", "package_certifier"}
)
_UNTRUSTED_SOURCES = frozenset({"model", "llm", "prompt", "external", "event"})


def _text(value: object, name: str, limit: int = _MAX_TEXT) -> str:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise CapabilityHealthError(f"{name} is malformed")
    return value.strip()


def _labels(values: Iterable[str], name: str, limit: int = _MAX_ITEMS) -> tuple[str, ...]:
    result = tuple(_text(value, name, 512) for value in values)
    if len(result) > limit or len(set(result)) != len(result):
        raise CapabilityHealthError(f"{name} are malformed")
    return result


def _timestamp(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CapabilityHealthError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _hash_payload(payload: Mapping[str, object]) -> str:
    encoded = dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class DependencyNode:
    dependency_id: str
    kind: DependencyKind
    expected_version: str | None = None
    observed_version: str | None = None
    expected_api: str | None = None
    observed_api: str | None = None
    available: bool = True
    detail: str = ""
    provenance: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.dependency_id, "Dependency ID", 256)
        if not isinstance(self.kind, DependencyKind):
            raise CapabilityHealthError("Dependency kind is malformed")
        for value, name in (
            (self.expected_version, "Expected dependency version"),
            (self.observed_version, "Observed dependency version"),
            (self.expected_api, "Expected dependency API"),
            (self.observed_api, "Observed dependency API"),
        ):
            if value is not None:
                _text(value, name, 256)
        if type(self.available) is not bool:
            raise CapabilityHealthError("Dependency availability is malformed")
        if self.detail:
            _text(self.detail, "Dependency detail")
        _labels(self.provenance, "Dependency provenance", 32)

    @property
    def version_compatible(self) -> bool:
        return self.expected_version is None or self.expected_version == self.observed_version

    @property
    def api_compatible(self) -> bool:
        return self.expected_api is None or self.expected_api == self.observed_api

    @property
    def healthy(self) -> bool:
        return self.available and self.version_compatible and self.api_compatible


@dataclass(frozen=True, slots=True)
class DependencyGraph:
    nodes: tuple[DependencyNode, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.nodes, tuple) or any(
            not isinstance(node, DependencyNode) for node in self.nodes
        ):
            raise CapabilityHealthError("Dependency graph is malformed")
        if len(self.nodes) > _MAX_ITEMS or len({node.dependency_id for node in self.nodes}) != len(
            self.nodes
        ):
            raise CapabilityHealthError("Dependency graph contains duplicate nodes")

    def node(self, dependency_id: str) -> DependencyNode:
        dependency_id = _text(dependency_id, "Dependency ID", 256)
        for node in self.nodes:
            if node.dependency_id == dependency_id:
                return node
        raise KeyError(dependency_id)


@dataclass(frozen=True, slots=True)
class HealthProbeResult:
    mode: HealthProbeMode
    passed: bool
    detail: str
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    dependency_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.mode, HealthProbeMode) or type(self.passed) is not bool:
            raise CapabilityHealthError("Health probe is malformed")
        _text(self.detail, "Health probe detail")
        _timestamp(self.checked_at, "Health probe timestamp")
        if self.dependency_id is not None:
            _text(self.dependency_id, "Health probe dependency ID", 256)


@dataclass(frozen=True, slots=True)
class CapabilityHealthReport:
    capability_id: str
    status: HealthStatus
    detail: str
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    probes: tuple[HealthProbeResult, ...] = ()
    dependencies: DependencyGraph = field(default_factory=DependencyGraph)
    evidence: tuple[str, ...] = ()
    version_compatible: bool | None = None
    api_compatible: bool | None = None

    def __post_init__(self) -> None:
        _text(self.capability_id, "Capability ID", 256)
        if not isinstance(self.status, HealthStatus):
            raise CapabilityHealthError("Health status is malformed")
        _text(self.detail, "Health detail")
        _timestamp(self.checked_at, "Health timestamp")
        if not isinstance(self.probes, tuple) or any(
            not isinstance(probe, HealthProbeResult) for probe in self.probes
        ):
            raise CapabilityHealthError("Health probes are malformed")
        if len(self.probes) > _MAX_ITEMS or not isinstance(self.dependencies, DependencyGraph):
            raise CapabilityHealthError("Health report is malformed")
        _labels(self.evidence, "Health evidence", 64)
        for value in (self.version_compatible, self.api_compatible):
            if value is not None and type(value) is not bool:
                raise CapabilityHealthError("Compatibility result is malformed")


@dataclass(frozen=True, slots=True)
class RequestVolumeBaseline:
    window_seconds: int = 60
    max_requests: int = 0
    material_multiplier: float = 2.0

    def __post_init__(self) -> None:
        if (
            type(self.window_seconds) is not int
            or not 1 <= self.window_seconds <= 86_400
            or type(self.max_requests) is not int
            or self.max_requests < 0
            or self.max_requests > 1_000_000
            or type(self.material_multiplier) is not float
            or self.material_multiplier < 1.0
            or self.material_multiplier > 100.0
        ):
            raise CapabilityHealthError("Request volume baseline is malformed")


@dataclass(frozen=True, slots=True)
class BehaviorBaseline:
    """Certified, immutable behavior expectations for one capability version."""

    capability_id: str
    package_version: str
    certification_ref: str
    network_hosts: frozenset[str] = frozenset()
    filesystem_roots: frozenset[str] = frozenset()
    broker_calls: frozenset[str] = frozenset()
    credential_scopes: frozenset[str] = frozenset()
    subprocess_policy: frozenset[str] = frozenset()
    request_volume: RequestVolumeBaseline = field(default_factory=RequestVolumeBaseline)
    event_subscriptions: frozenset[str] = frozenset()
    event_emissions: frozenset[str] = frozenset()
    persistence_operations: frozenset[str] = frozenset()
    activation_state: ActivationState = ActivationState.ACTIVE
    baseline_hash: str = ""
    package_hash: str = ""

    def __post_init__(self) -> None:
        _text(self.capability_id, "Baseline capability ID", 256)
        _text(self.package_version, "Baseline package version", 256)
        _text(self.certification_ref, "Baseline certification reference", 512)
        if self.package_hash and (
            len(self.package_hash) != 64
            or any(character not in "0123456789abcdef" for character in self.package_hash)
        ):
            raise CapabilityHealthError("Baseline package hash is malformed")
        for values, name in (
            (self.network_hosts, "Baseline network hosts"),
            (self.filesystem_roots, "Baseline filesystem roots"),
            (self.broker_calls, "Baseline broker calls"),
            (self.credential_scopes, "Baseline credential scopes"),
            (self.subprocess_policy, "Baseline subprocess policy"),
            (self.event_subscriptions, "Baseline event subscriptions"),
            (self.event_emissions, "Baseline event emissions"),
            (self.persistence_operations, "Baseline persistence operations"),
        ):
            if not isinstance(values, frozenset) or any(
                type(item) is not str or not item.strip() or len(item) > 512 or "\x00" in item
                for item in values
            ):
                raise CapabilityHealthError(f"{name} are malformed")
        if not isinstance(self.request_volume, RequestVolumeBaseline):
            raise CapabilityHealthError("Baseline request volume is malformed")
        if not isinstance(self.activation_state, ActivationState):
            raise CapabilityHealthError("Baseline activation state is malformed")
        payload = self._hash_payload()
        if self.baseline_hash and self.baseline_hash != payload:
            raise CapabilityHealthError("Behavior baseline hash does not match its contents")
        object.__setattr__(self, "baseline_hash", payload)

    def _hash_payload(self) -> str:
        return _hash_payload(
            {
                "capability_id": self.capability_id,
                "package_version": self.package_version,
                "package_hash": self.package_hash,
                "certification_ref": self.certification_ref,
                "network_hosts": sorted(self.network_hosts),
                "filesystem_roots": sorted(self.filesystem_roots),
                "broker_calls": sorted(self.broker_calls),
                "credential_scopes": sorted(self.credential_scopes),
                "subprocess_policy": sorted(self.subprocess_policy),
                "request_volume": {
                    "window_seconds": self.request_volume.window_seconds,
                    "max_requests": self.request_volume.max_requests,
                    "material_multiplier": self.request_volume.material_multiplier,
                },
                "event_subscriptions": sorted(self.event_subscriptions),
                "event_emissions": sorted(self.event_emissions),
                "persistence_operations": sorted(self.persistence_operations),
            }
        )

    def fingerprint(self) -> str:
        return self.baseline_hash


@dataclass(frozen=True, slots=True)
class BehaviorObservation:
    """One bounded observation.  Authority-sensitive use requires trusted=True."""

    capability_id: str
    source: str
    trusted: bool
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    network_hosts: frozenset[str] = frozenset()
    filesystem_roots: frozenset[str] = frozenset()
    broker_calls: frozenset[str] = frozenset()
    credential_scopes: frozenset[str] = frozenset()
    processes: frozenset[str] = frozenset()
    privileged_requests: frozenset[str] = frozenset()
    request_volume: int = 0
    event_subscriptions: frozenset[str] = frozenset()
    event_emissions: frozenset[str] = frozenset()
    persistence_operations: frozenset[str] = frozenset()
    evidence: tuple[str, ...] = ()
    package_version: str | None = None
    package_hash: str | None = None

    def __post_init__(self) -> None:
        _text(self.capability_id, "Observation capability ID", 256)
        source = _text(self.source, "Observation source", 256).casefold()
        object.__setattr__(self, "source", source)
        if type(self.trusted) is not bool or (self.trusted and source in _UNTRUSTED_SOURCES):
            raise CapabilityHealthError("Observation authority is malformed")
        _timestamp(self.observed_at, "Observation timestamp")
        for values, name in (
            (self.network_hosts, "Observed network hosts"),
            (self.filesystem_roots, "Observed filesystem roots"),
            (self.broker_calls, "Observed broker calls"),
            (self.credential_scopes, "Observed credential scopes"),
            (self.processes, "Observed processes"),
            (self.privileged_requests, "Observed privileged requests"),
            (self.event_subscriptions, "Observed event subscriptions"),
            (self.event_emissions, "Observed event emissions"),
            (self.persistence_operations, "Observed persistence operations"),
        ):
            if not isinstance(values, frozenset) or any(
                type(item) is not str or not item.strip() or len(item) > 512 or "\x00" in item
                for item in values
            ):
                raise CapabilityHealthError(f"{name} are malformed")
        if type(self.request_volume) is not int or not 0 <= self.request_volume <= 1_000_000:
            raise CapabilityHealthError("Observed request volume is malformed")
        _labels(self.evidence, "Observation evidence", 64)
        if self.package_version is not None:
            _text(self.package_version, "Observation package version", 256)
        if self.package_hash is not None and (
            len(self.package_hash) != 64
            or any(character not in "0123456789abcdef" for character in self.package_hash)
        ):
            raise CapabilityHealthError("Observation package hash is malformed")


@dataclass(frozen=True, slots=True)
class DriftFinding:
    finding_id: UUID
    capability_id: str
    category: str
    classification: DriftClass
    expected: tuple[str, ...]
    observed: tuple[str, ...]
    detail: str
    observed_at: datetime
    trusted: bool
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.finding_id, UUID):
            raise CapabilityHealthError("Drift finding ID is malformed")
        _text(self.capability_id, "Drift capability ID", 256)
        _text(self.category, "Drift category", 128)
        if not isinstance(self.classification, DriftClass):
            raise CapabilityHealthError("Drift classification is malformed")
        _labels(self.expected, "Expected drift values")
        _labels(self.observed, "Observed drift values")
        _text(self.detail, "Drift detail")
        _timestamp(self.observed_at, "Drift timestamp")
        if type(self.trusted) is not bool:
            raise CapabilityHealthError("Drift trust flag is malformed")
        _labels(self.evidence, "Drift evidence", 64)


@dataclass(frozen=True, slots=True)
class DriftReport:
    capability_id: str
    baseline_hash: str
    observation: BehaviorObservation
    classification: DriftClass
    findings: tuple[DriftFinding, ...]
    previous_activation_state: ActivationState
    resulting_activation_state: ActivationState
    accepted: bool = True

    def __post_init__(self) -> None:
        _text(self.capability_id, "Drift report capability ID", 256)
        _text(self.baseline_hash, "Drift baseline hash", 128)
        if not isinstance(self.observation, BehaviorObservation):
            raise CapabilityHealthError("Drift observation is malformed")
        if (
            not isinstance(self.classification, DriftClass)
            or not isinstance(self.previous_activation_state, ActivationState)
            or not isinstance(self.resulting_activation_state, ActivationState)
        ):
            raise CapabilityHealthError("Drift lifecycle state is malformed")
        if (
            not isinstance(self.findings, tuple)
            or len(self.findings) > _MAX_FINDINGS
            or any(not isinstance(finding, DriftFinding) for finding in self.findings)
        ):
            raise CapabilityHealthError("Drift findings are malformed")
        if type(self.accepted) is not bool:
            raise CapabilityHealthError("Drift acceptance is malformed")


@dataclass(frozen=True, slots=True)
class AttentionNotice:
    capability_id: str
    severity: DriftClass | HealthStatus
    summary: str
    finding_ids: tuple[UUID, ...] = ()
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _text(self.capability_id, "Attention capability ID", 256)
        if not isinstance(self.severity, DriftClass | HealthStatus):
            raise CapabilityHealthError("Attention severity is malformed")
        _text(self.summary, "Attention summary")
        if len(self.finding_ids) > _MAX_ITEMS or any(
            not isinstance(item, UUID) for item in self.finding_ids
        ):
            raise CapabilityHealthError("Attention finding IDs are malformed")
        _timestamp(self.created_at, "Attention timestamp")


class AttentionSink(Protocol):
    def __call__(self, notice: AttentionNotice) -> None: ...


@dataclass(frozen=True, slots=True)
class RepairAction:
    action_id: str
    kind: str
    scope: str
    detail: str
    safe: bool = True
    requires_permission: bool = True

    def __post_init__(self) -> None:
        _text(self.action_id, "Repair action ID", 256)
        _text(self.kind, "Repair action kind", 128)
        _text(self.scope, "Repair action scope", 512)
        _text(self.detail, "Repair action detail")
        if type(self.safe) is not bool or type(self.requires_permission) is not bool:
            raise CapabilityHealthError("Repair action flags are malformed")


@dataclass(frozen=True, slots=True)
class RepairDiagnosis:
    action: RepairAction | None
    rebuild_or_replace: bool = False
    authority_required: bool = False
    detail: str = ""

    def __post_init__(self) -> None:
        if self.action is not None and not isinstance(self.action, RepairAction):
            raise CapabilityHealthError("Repair diagnosis action is malformed")
        if type(self.rebuild_or_replace) is not bool or type(self.authority_required) is not bool:
            raise CapabilityHealthError("Repair diagnosis flags are malformed")
        if self.detail:
            _text(self.detail, "Repair diagnosis detail")


@dataclass(frozen=True, slots=True)
class RepairResult:
    run_id: UUID
    capability_id: str
    outcome: RepairOutcome
    stage: RepairStage
    history: tuple[RepairStage, ...]
    detail: str
    retest: CapabilityHealthReport | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, UUID):
            raise CapabilityHealthError("Repair run ID is malformed")
        _text(self.capability_id, "Repair capability ID", 256)
        if not isinstance(self.outcome, RepairOutcome) or not isinstance(self.stage, RepairStage):
            raise CapabilityHealthError("Repair result state is malformed")
        if not self.history or any(not isinstance(item, RepairStage) for item in self.history):
            raise CapabilityHealthError("Repair history is malformed")
        _text(self.detail, "Repair result detail")
        if self.retest is not None and not isinstance(self.retest, CapabilityHealthReport):
            raise CapabilityHealthError("Repair retest is malformed")


class RepairProvider(Protocol):
    """Application-owned typed repair boundary; never an arbitrary shell hook."""

    def diagnose(
        self, capability_id: str, findings: tuple[DriftFinding, ...]
    ) -> RepairDiagnosis: ...

    def safe_repair(self, capability_id: str, action: RepairAction) -> bool: ...

    def rebuild_or_replace(self, capability_id: str, diagnosis: RepairDiagnosis) -> bool: ...

    def retest(self, capability_id: str) -> CapabilityHealthReport: ...


class CapabilityHealthService:
    """One bounded service for health reports, trusted drift, and repair flow."""

    def __init__(
        self,
        *,
        event_bus: EventBus | None = None,
        trace: ExecutionTrace | None = None,
        attention_sink: AttentionSink | None = None,
        max_findings: int = _MAX_FINDINGS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(max_findings) is not int or not 1 <= max_findings <= _MAX_FINDINGS:
            raise CapabilityHealthError("Health finding bound is malformed")
        self._event_bus = event_bus
        self._trace = trace or ExecutionTrace()
        self._attention_sink = attention_sink
        self._max_findings = max_findings
        self._clock = clock or (lambda: datetime.now(UTC))
        self._baselines: dict[str, BehaviorBaseline] = {}
        self._health: dict[str, CapabilityHealthReport] = {}
        self._drift: dict[str, DriftReport] = {}
        self._activation: dict[str, ActivationState] = {}
        self._activation_state_provider: Callable[[str], ActivationState] | None = None
        self._activation_transition: (
            Callable[[str, ActivationState, str], ActivationState] | None
        ) = None
        self._history: dict[str, list[DriftFinding]] = {}
        self._attention: list[AttentionNotice] = []

    @property
    def trace(self) -> ExecutionTrace:
        return self._trace

    def register_baseline(
        self,
        baseline: BehaviorBaseline,
        *,
        authority: str = "application",
        generated: bool = False,
        model_output: bool = False,
        replace: bool = False,
    ) -> None:
        """Register a certified baseline; replacement is certification-owned only."""

        if not isinstance(baseline, BehaviorBaseline):
            raise CapabilityHealthError("Behavior baseline is malformed")
        authority = _text(authority, "Baseline authority", 128).casefold()
        if generated or model_output or authority not in _TRUSTED_BASELINE_AUTHORITIES:
            raise CapabilityHealthError("Only trusted certification may register a baseline")
        existing = self._baselines.get(baseline.capability_id)
        if existing is not None and not replace:
            raise CapabilityHealthError("Capability already has a certified baseline")
        if existing is not None and baseline.package_version == existing.package_version:
            raise CapabilityHealthError("A certified baseline version cannot be rewritten")
        self._baselines[baseline.capability_id] = baseline
        if self._activation_state_provider is None:
            self._activation[baseline.capability_id] = baseline.activation_state

    def bind_lifecycle(
        self,
        state_provider: Callable[[str], ActivationState],
        transition: Callable[[str, ActivationState, str], ActivationState],
    ) -> None:
        """Bind health/drift to the canonical application lifecycle owner."""

        if not callable(state_provider) or not callable(transition):
            raise CapabilityHealthError("Lifecycle binding is malformed")
        self._activation_state_provider = state_provider
        self._activation_transition = transition

    def baseline(self, capability_id: str) -> BehaviorBaseline:
        capability_id = _text(capability_id, "Capability ID", 256)
        try:
            return self._baselines[capability_id]
        except KeyError as error:
            raise KeyError("Capability has no certified behavior baseline") from error

    def baselines(self) -> tuple[BehaviorBaseline, ...]:
        return tuple(self._baselines.values())

    def health(self, capability_id: str) -> CapabilityHealthReport:
        capability_id = _text(capability_id, "Capability ID", 256)
        report = self._health.get(
            capability_id,
            CapabilityHealthReport(
                capability_id,
                HealthStatus.UNKNOWN,
                "No health observation has been recorded",
            ),
        )
        activation = (
            self._activation_state_provider(capability_id)
            if self._activation_state_provider is not None
            else self._activation.get(capability_id)
        )
        if activation is ActivationState.QUARANTINED:
            return replace(
                report,
                status=HealthStatus.QUARANTINED,
                detail="Capability is quarantined pending trusted lifecycle action",
            )
        if activation is ActivationState.DEGRADED and report.status in {
            HealthStatus.HEALTHY,
            HealthStatus.UNKNOWN,
        }:
            return replace(
                report,
                status=HealthStatus.DEGRADED,
                detail="Capability behavior is degraded pending trusted lifecycle action",
            )
        return report

    def reports(self) -> tuple[CapabilityHealthReport, ...]:
        return tuple(self._health.values())

    def record_status(
        self,
        capability_id: str,
        status: HealthStatus,
        detail: str,
        *,
        evidence: Iterable[str] = (),
    ) -> CapabilityHealthReport:
        """Record an application-owned status when a doctor/fallback has acted."""

        capability_id = _text(capability_id, "Capability ID", 256)
        if not isinstance(status, HealthStatus):
            raise CapabilityHealthError("Health status is malformed")
        report = CapabilityHealthReport(
            capability_id,
            status,
            detail,
            checked_at=self._now(),
            evidence=_labels(evidence, "Health evidence", 64),
        )
        self._health[capability_id] = report
        self._emit_health(report)
        return report

    def evaluate_health(
        self,
        capability_id: str,
        probes: Sequence[HealthProbeResult],
        *,
        dependencies: DependencyGraph | None = None,
        evidence: Iterable[str] = (),
    ) -> CapabilityHealthReport:
        capability_id = _text(capability_id, "Capability ID", 256)
        probes = tuple(probes)
        dependencies = dependencies or DependencyGraph()
        if any(not isinstance(probe, HealthProbeResult) for probe in probes):
            raise CapabilityHealthError("Health probes are malformed")
        if not isinstance(dependencies, DependencyGraph):
            raise CapabilityHealthError("Dependency graph is malformed")
        if any(not node.healthy for node in dependencies.nodes):
            status = (
                HealthStatus.UNAVAILABLE
                if any(not node.available for node in dependencies.nodes)
                else HealthStatus.DEGRADED
            )
            detail = "A dependency is unavailable or incompatible"
        elif not probes:
            status = HealthStatus.UNKNOWN
            detail = "No health probes were supplied"
        elif all(probe.passed for probe in probes):
            status = HealthStatus.HEALTHY
            detail = "All supplied health probes passed"
        elif any(probe.mode is HealthProbeMode.FUNCTIONAL and not probe.passed for probe in probes):
            status = HealthStatus.UNAVAILABLE
            detail = "A functional health probe failed"
        else:
            status = HealthStatus.DEGRADED
            detail = "One or more health probes failed"
        version_compatible = (
            all(node.version_compatible for node in dependencies.nodes)
            if dependencies.nodes
            else None
        )
        api_compatible = (
            all(node.api_compatible for node in dependencies.nodes) if dependencies.nodes else None
        )
        report = CapabilityHealthReport(
            capability_id,
            status,
            detail,
            checked_at=self._now(),
            probes=probes,
            dependencies=dependencies,
            evidence=_labels(evidence, "Health evidence", 64),
            version_compatible=version_compatible,
            api_compatible=api_compatible,
        )
        self._health[capability_id] = report
        self._emit_health(report)
        return report

    check = evaluate_health

    def record_trusted_broker_observation(self, observation: BehaviorObservation) -> DriftReport:
        if not isinstance(observation, BehaviorObservation) or not observation.trusted:
            raise CapabilityHealthError("Only trusted broker observations may affect drift")
        if observation.source not in {"broker", "permission_broker", "trusted_broker"}:
            raise CapabilityHealthError("Observation is not from the trusted broker")
        return self.evaluate_drift(observation)

    observe_broker = record_trusted_broker_observation

    def evaluate_drift(self, observation: BehaviorObservation) -> DriftReport:
        if not isinstance(observation, BehaviorObservation) or not observation.trusted:
            raise CapabilityHealthError("Untrusted observations cannot declare behavior drift")
        baseline = self.baseline(observation.capability_id)
        if baseline.package_hash and observation.package_hash != baseline.package_hash:
            raise CapabilityHealthError("Observation package hash does not match baseline")
        if baseline.package_version and observation.package_version != baseline.package_version:
            raise CapabilityHealthError("Observation package version does not match baseline")
        findings = self._findings_for(baseline, observation)
        classification = max(
            (finding.classification for finding in findings),
            default=DriftClass.EXPECTED,
            key=self._drift_rank,
        )
        previous = (
            self._activation_state_provider(observation.capability_id)
            if self._activation_state_provider is not None
            else self._activation.get(observation.capability_id, baseline.activation_state)
        )
        resulting = self._next_activation(previous, classification)
        if resulting is not previous and self._activation_transition is not None:
            resulting = self._activation_transition(
                observation.capability_id,
                resulting,
                f"behavior drift: {classification.value}",
            )
        report = DriftReport(
            observation.capability_id,
            baseline.baseline_hash,
            observation,
            classification,
            tuple(findings),
            previous,
            resulting,
        )
        self._drift[observation.capability_id] = report
        if self._activation_state_provider is None:
            self._activation[observation.capability_id] = resulting
        history = self._history.setdefault(observation.capability_id, [])
        history.extend(findings)
        del history[: -self._max_findings]
        self._emit_drift(report)
        return report

    compare = evaluate_drift

    def drift(self, capability_id: str) -> DriftReport | None:
        return self._drift.get(_text(capability_id, "Capability ID", 256))

    def findings(self, capability_id: str) -> tuple[DriftFinding, ...]:
        return tuple(self._history.get(_text(capability_id, "Capability ID", 256), ()))

    def activation_state(self, capability_id: str) -> ActivationState:
        capability_id = _text(capability_id, "Capability ID", 256)
        if self._activation_state_provider is not None:
            return self._activation_state_provider(capability_id)
        return self._activation.get(capability_id, ActivationState.CERTIFIED)

    def repair(
        self,
        capability_id: str,
        provider: RepairProvider,
        *,
        authorize: Callable[[RepairAction], bool] | None = None,
    ) -> RepairResult:
        """Run the typed detect/evidence/diagnose/repair/retest flow.

        ``authorize`` is an application-owned gate.  A missing or false gate
        never attempts an effectful repair; the result requests authority.
        """

        capability_id = _text(capability_id, "Capability ID", 256)
        if not all(
            callable(getattr(provider, name, None))
            for name in ("diagnose", "safe_repair", "rebuild_or_replace", "retest")
        ):
            raise CapabilityHealthError("Repair provider does not implement the typed contract")
        report = self.drift(capability_id)
        if report is None or not report.findings:
            raise CapabilityHealthError("No drift evidence is available for repair")
        findings = report.findings
        run_id = uuid4()
        history: list[RepairStage] = [RepairStage.DETECT, RepairStage.EVIDENCE]
        try:
            history.append(RepairStage.DIAGNOSE)
            diagnosis = provider.diagnose(capability_id, findings)
            if not isinstance(diagnosis, RepairDiagnosis):
                raise CapabilityHealthError("Repair diagnosis is malformed")
            if diagnosis.action is not None and diagnosis.action.safe:
                history.append(RepairStage.SAFE_REPAIR)
                action = diagnosis.action
                if action.requires_permission and (authorize is None or not authorize(action)):
                    history.append(RepairStage.AUTHORITY)
                    return RepairResult(
                        run_id,
                        capability_id,
                        RepairOutcome.AUTHORITY_REQUIRED,
                        RepairStage.AUTHORITY,
                        tuple(history),
                        "Repair requires fresh trusted authority",
                    )
                if provider.safe_repair(capability_id, action):
                    history.append(RepairStage.RETEST)
                    retest = provider.retest(capability_id)
                    self._record_retest(retest)
                    if retest.status is HealthStatus.HEALTHY:
                        requires_authority = diagnosis.authority_required or (
                            report.classification
                            in {DriftClass.MATERIAL_DRIFT, DriftClass.SECURITY_DRIFT}
                        )
                        if not requires_authority:
                            history.append(RepairStage.COMPLETED)
                            return RepairResult(
                                run_id,
                                capability_id,
                                RepairOutcome.COMPLETED,
                                RepairStage.COMPLETED,
                                tuple(history),
                                "Safe repair passed retest",
                                retest,
                            )
                        history.append(RepairStage.AUTHORITY)
                        return RepairResult(
                            run_id,
                            capability_id,
                            RepairOutcome.AUTHORITY_REQUIRED,
                            RepairStage.AUTHORITY,
                            tuple(history),
                            "Healthy repair still requires recertification/activation authority",
                            retest,
                        )
            if (
                diagnosis.rebuild_or_replace
                or diagnosis.authority_required
                or diagnosis.action is not None
            ):
                history.append(RepairStage.REBUILD_OR_REPLACE)
                if not provider.rebuild_or_replace(capability_id, diagnosis):
                    history.append(RepairStage.FAILED)
                    return RepairResult(
                        run_id,
                        capability_id,
                        RepairOutcome.FAILED,
                        RepairStage.FAILED,
                        tuple(history),
                        "Rebuild or replacement failed",
                    )
                history.append(RepairStage.RETEST)
                retest = provider.retest(capability_id)
                self._record_retest(retest)
                if retest.status is not HealthStatus.HEALTHY:
                    history.append(RepairStage.FAILED)
                    return RepairResult(
                        run_id,
                        capability_id,
                        RepairOutcome.FAILED,
                        RepairStage.FAILED,
                        tuple(history),
                        "Retest did not restore health",
                        retest,
                    )
                history.append(RepairStage.AUTHORITY)
                return RepairResult(
                    run_id,
                    capability_id,
                    RepairOutcome.AUTHORITY_REQUIRED,
                    RepairStage.AUTHORITY,
                    tuple(history),
                    "Healthy replacement still requires certification/activation authority",
                    retest,
                )
            history.append(RepairStage.FAILED)
            return RepairResult(
                run_id,
                capability_id,
                RepairOutcome.FAILED,
                RepairStage.FAILED,
                tuple(history),
                diagnosis.detail or "No safe repair was available",
            )
        except Exception as error:
            if isinstance(error, CapabilityHealthError):
                detail = str(error)
            else:
                detail = "Typed repair provider failed"
            if not history or history[-1] is not RepairStage.FAILED:
                history.append(RepairStage.FAILED)
            return RepairResult(
                run_id,
                capability_id,
                RepairOutcome.FAILED,
                RepairStage.FAILED,
                tuple(history),
                detail,
            )

    def repair_result(
        self, capability_id: str, provider: RepairProvider, **kwargs: object
    ) -> RepairResult:
        """Named compatibility entry point for callers that prefer result wording."""

        return self.repair(capability_id, provider, **kwargs)  # type: ignore[arg-type]

    def attention_notices(self) -> tuple[AttentionNotice, ...]:
        return tuple(self._attention)

    def _record_retest(self, report: CapabilityHealthReport) -> None:
        if not isinstance(report, CapabilityHealthReport):
            raise CapabilityHealthError("Repair retest returned malformed health")
        self._health[report.capability_id] = report
        self._emit_health(report)

    def _findings_for(
        self, baseline: BehaviorBaseline, observation: BehaviorObservation
    ) -> list[DriftFinding]:
        findings: list[DriftFinding] = []

        def added(
            category: str,
            expected: Iterable[str],
            observed: Iterable[str],
            classification: DriftClass,
        ) -> None:
            values = tuple(sorted(set(observed) - set(expected)))
            if values:
                findings.append(
                    DriftFinding(
                        uuid4(),
                        observation.capability_id,
                        category,
                        classification,
                        tuple(sorted(expected)),
                        values,
                        f"Observed values outside the certified {category} baseline",
                        observation.observed_at,
                        observation.trusted,
                        observation.evidence,
                    )
                )

        added(
            "network_hosts",
            baseline.network_hosts,
            observation.network_hosts,
            DriftClass.MATERIAL_DRIFT,
        )
        added(
            "filesystem_roots",
            baseline.filesystem_roots,
            observation.filesystem_roots,
            DriftClass.MATERIAL_DRIFT,
        )
        added(
            "broker_calls",
            baseline.broker_calls,
            observation.broker_calls,
            DriftClass.MATERIAL_DRIFT,
        )
        added(
            "credential_scopes",
            baseline.credential_scopes,
            observation.credential_scopes,
            DriftClass.SECURITY_DRIFT,
        )
        added(
            "processes",
            baseline.subprocess_policy,
            observation.processes,
            DriftClass.SECURITY_DRIFT,
        )
        added("privileged_requests", (), observation.privileged_requests, DriftClass.SECURITY_DRIFT)
        added(
            "event_subscriptions",
            baseline.event_subscriptions,
            observation.event_subscriptions,
            DriftClass.MATERIAL_DRIFT,
        )
        added(
            "event_emissions",
            baseline.event_emissions,
            observation.event_emissions,
            DriftClass.MATERIAL_DRIFT,
        )
        added(
            "persistence_operations",
            baseline.persistence_operations,
            observation.persistence_operations,
            DriftClass.SECURITY_DRIFT,
        )
        maximum = baseline.request_volume.max_requests
        if observation.request_volume > maximum:
            classification = (
                DriftClass.MATERIAL_DRIFT
                if maximum == 0
                or observation.request_volume
                > maximum * baseline.request_volume.material_multiplier
                else DriftClass.LOW_RISK_DRIFT
            )
            findings.append(
                DriftFinding(
                    uuid4(),
                    observation.capability_id,
                    "request_volume",
                    classification,
                    (str(maximum),),
                    (str(observation.request_volume),),
                    "Observed request volume exceeds the certified window budget",
                    observation.observed_at,
                    observation.trusted,
                    observation.evidence,
                )
            )
        return findings

    @staticmethod
    def _drift_rank(value: DriftClass) -> int:
        return {
            DriftClass.EXPECTED: 0,
            DriftClass.LOW_RISK_DRIFT: 1,
            DriftClass.MATERIAL_DRIFT: 2,
            DriftClass.SECURITY_DRIFT: 3,
        }[value]

    @staticmethod
    def _next_activation(current: ActivationState, classification: DriftClass) -> ActivationState:
        if current is ActivationState.QUARANTINED or current is ActivationState.ROLLED_BACK:
            return current
        if classification is DriftClass.SECURITY_DRIFT:
            return ActivationState.QUARANTINED
        if classification is DriftClass.MATERIAL_DRIFT:
            return (
                ActivationState.QUARANTINED
                if current is ActivationState.DEGRADED
                else ActivationState.DEGRADED
            )
        if classification is DriftClass.LOW_RISK_DRIFT and current is ActivationState.ACTIVE:
            return ActivationState.DEGRADED
        return current

    def _emit_health(self, report: CapabilityHealthReport) -> None:
        self._trace.append(
            TraceEvent(
                trace_id=self._trace.trace_id,
                event_type=TraceEventType.HEALTH,
                source="capability_health",
                summary=f"Health {report.capability_id}: {report.status.value}",
                occurred_at=report.checked_at,
                result={"status": report.status.value, "detail": report.detail},
            )
        )
        if self._event_bus is not None:
            self._event_bus.publish_nowait(
                EventEnvelope.create(
                    EventType.HEALTH_CHANGED,
                    HealthChanged(report.capability_id, report.status.value),
                    source="capability_health",
                    correlation_id=uuid4(),
                    timestamp=report.checked_at,
                )
            )
        if report.status not in {HealthStatus.HEALTHY, HealthStatus.UNKNOWN}:
            self._notify(
                AttentionNotice(
                    report.capability_id,
                    report.status,
                    report.detail,
                    created_at=report.checked_at,
                )
            )

    def _emit_drift(self, report: DriftReport) -> None:
        self._trace.append(
            TraceEvent(
                trace_id=self._trace.trace_id,
                event_type=TraceEventType.DRIFT,
                source="capability_health",
                summary=f"Behavior {report.capability_id}: {report.classification.value}",
                occurred_at=report.observation.observed_at,
                result={
                    "classification": report.classification.value,
                    "previous_activation": report.previous_activation_state.value,
                    "resulting_activation": report.resulting_activation_state.value,
                    "finding_count": len(report.findings),
                },
                evidence=tuple(str(finding.finding_id) for finding in report.findings),
            )
        )
        if report.classification is not DriftClass.EXPECTED:
            self._notify(
                AttentionNotice(
                    report.capability_id,
                    report.classification,
                    f"{report.classification.value}: {len(report.findings)} behavior finding(s)",
                    tuple(finding.finding_id for finding in report.findings),
                    report.observation.observed_at,
                )
            )
        if self._event_bus is not None and report.classification is not DriftClass.EXPECTED:
            self._event_bus.publish_nowait(
                EventEnvelope.create(
                    EventType.HEALTH_CHANGED,
                    HealthChanged(report.capability_id, report.resulting_activation_state.value),
                    source="capability_health",
                    correlation_id=uuid4(),
                    timestamp=report.observation.observed_at,
                )
            )

    def _notify(self, notice: AttentionNotice) -> None:
        self._attention.append(notice)
        if len(self._attention) > self._max_findings:
            del self._attention[: -self._max_findings]
        if self._attention_sink is not None:
            try:
                self._attention_sink(notice)
            except Exception:
                # Attention is a derived notification path and cannot make a
                # trusted health observation disappear or fail closed.
                return

    def _now(self) -> datetime:
        return _timestamp(self._clock(), "Health service clock")

    async def aclose(self) -> None:
        """Composition-root lifecycle hook; the service owns no external resource."""


# Explicit aliases make the contract discoverable without creating competing
# implementations or stores.
HealthCheckMode = HealthProbeMode
CapabilityHealthMonitor = CapabilityHealthService
BehaviorDrift = DriftReport
