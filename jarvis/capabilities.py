"""Canonical capability vocabulary and credential-free environment graph."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256

from jarvis.permissions.models import Permission, Risk
from jarvis.tools.models import SemanticVersion, ToolHealthStatus, ToolPlatform


class CapabilityError(ValueError):
    """Capability metadata failed a deterministic boundary check."""


class Reversibility(StrEnum):
    READ_ONLY = "read_only"
    REVERSIBLE = "reversible"
    COMPENSATABLE = "compensatable"
    IRREVERSIBLE = "irreversible"
    UNKNOWN = "unknown"


class EffectClassification(StrEnum):
    OBSERVATION = "observation"
    LOCAL_MUTATION = "local_mutation"
    EXTERNAL_EFFECT = "external_effect"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


class CapabilityLifecycle(StrEnum):
    DISCOVERED = "discovered"
    CONFIGURED = "configured"
    ACTIVE = "active"
    DEGRADED = "degraded"
    STOPPED = "stopped"
    DEPRECATED = "deprecated"


class EnvironmentNodeKind(StrEnum):
    COMPUTER = "computer"
    APPLICATION = "application"
    SERVICE = "service"
    DEVICE = "device"
    ACCOUNT_REF = "account_ref"
    INTEGRATION = "integration"
    CAPABILITY = "capability"
    MODEL_RUNTIME = "model_runtime"
    WORKSPACE = "workspace"


@dataclass(frozen=True, slots=True)
class EffectMetadata:
    classification: EffectClassification
    reversibility: Reversibility
    preview_supported: bool = False
    compensation: str | None = None
    produced_artifacts: tuple[str, ...] = ()
    emitted_events: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.classification, EffectClassification):
            raise CapabilityError("Effect classification is invalid")
        if not isinstance(self.reversibility, Reversibility):
            raise CapabilityError("Effect reversibility is invalid")
        if self.compensation is not None:
            _bounded(self.compensation, "Effect compensation", 1_000)
        _labels(self.produced_artifacts, "Produced artifacts", 32)
        _labels(self.emitted_events, "Emitted events", 32)


@dataclass(frozen=True, slots=True)
class CapabilityHealth:
    status: ToolHealthStatus
    detail: str
    checked_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ToolHealthStatus):
            raise CapabilityError("Capability health status is invalid")
        _bounded(self.detail, "Capability health detail", 1_000)
        if self.checked_at is not None and self.checked_at.tzinfo is None:
            raise CapabilityError("Capability health timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class CapabilityManifest:
    capability_id: str
    name: str
    version: SemanticVersion
    integration_owner: str
    actions: tuple[str, ...]
    input_schema: Mapping[str, object]
    output_schema: Mapping[str, object]
    permissions: tuple[Permission, ...]
    risk: Risk
    supported_platforms: frozenset[ToolPlatform]
    network_required: bool
    network_domains: tuple[str, ...]
    credential_references: tuple[str, ...]
    dependencies: tuple[str, ...]
    configuration: tuple[str, ...]
    health: CapabilityHealth
    verification: tuple[str, ...]
    ui_voice: tuple[str, ...]
    provenance: tuple[str, ...]
    content_hash: str
    lifecycle: CapabilityLifecycle
    effect: EffectMetadata
    confidence: float = 0.0
    last_verified: datetime | None = None

    def __post_init__(self) -> None:
        _bounded(self.capability_id, "Capability ID", 128)
        _bounded(self.name, "Capability name", 256)
        _bounded(self.integration_owner, "Integration owner", 256)
        _labels(self.actions, "Capability actions", 64)
        _labels(self.network_domains, "Network domains", 64)
        _labels(self.credential_references, "Credential references", 32)
        _labels(self.dependencies, "Capability dependencies", 64)
        _labels(self.configuration, "Capability configuration", 64)
        _labels(self.verification, "Capability verification", 64)
        _labels(self.ui_voice, "Capability UI/voice metadata", 64)
        _labels(self.provenance, "Capability provenance", 64)
        if not self.actions or not self.input_schema or not self.output_schema:
            raise CapabilityError("Capability actions and schemas are required")
        if any(not isinstance(permission, Permission) for permission in self.permissions):
            raise CapabilityError("Capability permissions are invalid")
        if tuple(sorted(set(self.permissions), key=lambda item: item.value)) != self.permissions:
            raise CapabilityError("Capability permissions must be unique and sorted")
        if not self.supported_platforms or any(
            not isinstance(platform, ToolPlatform) for platform in self.supported_platforms
        ):
            raise CapabilityError("Capability platform metadata is invalid")
        if not 0.0 <= self.confidence <= 1.0:
            raise CapabilityError("Capability confidence must be between zero and one")
        if not self.content_hash or len(self.content_hash) > 128:
            raise CapabilityError("Capability provenance hash is invalid")
        if self.last_verified is not None and self.last_verified.tzinfo is None:
            raise CapabilityError("Capability verification timestamp must be timezone-aware")
        if not self.network_required and self.network_domains:
            raise CapabilityError("Network domains require network access")
        if any(_looks_like_secret(value) for value in self.credential_references):
            raise CapabilityError("Credential references must not contain secret values")


@dataclass(frozen=True, slots=True)
class CapabilityRecord:
    manifest: CapabilityManifest
    registered_at: datetime


class CapabilityRegistry:
    """Descriptive capability catalog; it does not execute or authorize actions."""

    def __init__(self, capabilities: Iterable[CapabilityManifest] = ()) -> None:
        self._records: dict[str, CapabilityRecord] = {}
        for capability in capabilities:
            self.register(capability)

    def register(self, capability: CapabilityManifest) -> None:
        if capability.capability_id in self._records:
            raise CapabilityError("Duplicate capability ID")
        self._records[capability.capability_id] = CapabilityRecord(capability, datetime.now(UTC))

    def unregister(self, capability_id: str) -> CapabilityManifest:
        try:
            return self._records.pop(capability_id).manifest
        except KeyError as error:
            raise KeyError("Unknown capability") from error

    def inspect(self, capability_id: str) -> CapabilityManifest:
        try:
            return self._records[capability_id].manifest
        except KeyError as error:
            raise KeyError("Unknown capability") from error

    def search(self, query: str) -> tuple[CapabilityManifest, ...]:
        _bounded(query, "Capability search", 256)
        needle = query.casefold()
        return tuple(
            record.manifest
            for record in self._records.values()
            if needle
            in " ".join(
                (
                    record.manifest.capability_id,
                    record.manifest.name,
                    record.manifest.integration_owner,
                    *record.manifest.actions,
                )
            ).casefold()
        )

    def gap_detection(self, required: Iterable[str]) -> tuple[str, ...]:
        gaps: list[str] = []
        for capability_id in required:
            record = self._records.get(capability_id)
            if record is None or record.manifest.lifecycle in {
                CapabilityLifecycle.STOPPED,
                CapabilityLifecycle.DEPRECATED,
            }:
                gaps.append(capability_id)
                continue
            if any(dependency not in self._records for dependency in record.manifest.dependencies):
                gaps.append(capability_id)
        return tuple(gaps)

    def health(self, capability_id: str) -> CapabilityHealth:
        return self.inspect(capability_id).health

    def permission(self, capability_id: str) -> tuple[Permission, ...]:
        return self.inspect(capability_id).permissions

    def dependency_lookup(self, capability_id: str) -> tuple[str, ...]:
        return self.inspect(capability_id).dependencies

    def manifests(self) -> tuple[CapabilityManifest, ...]:
        return tuple(record.manifest for record in self._records.values())


@dataclass(frozen=True, slots=True)
class EnvironmentNode:
    node_id: str
    kind: EnvironmentNodeKind
    label: str
    account_ref: str | None = None
    provenance: tuple[str, ...] = ()
    confidence: float = 0.0
    last_verified: datetime | None = None

    def __post_init__(self) -> None:
        _bounded(self.node_id, "Environment node ID", 256)
        _bounded(self.label, "Environment node label", 256)
        if not isinstance(self.kind, EnvironmentNodeKind):
            raise CapabilityError("Environment node kind is invalid")
        if self.account_ref is not None:
            _bounded(self.account_ref, "Environment account reference", 256)
            if _looks_like_secret(self.account_ref):
                raise CapabilityError("Environment graph cannot contain credential material")
        _labels(self.provenance, "Environment provenance", 32)
        if not 0.0 <= self.confidence <= 1.0:
            raise CapabilityError("Environment confidence must be between zero and one")
        if self.last_verified is not None and self.last_verified.tzinfo is None:
            raise CapabilityError("Environment verification timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class EnvironmentEdge:
    source_id: str
    target_id: str
    relation: str
    provenance: tuple[str, ...] = ()
    confidence: float = 0.0
    last_verified: datetime | None = None

    def __post_init__(self) -> None:
        _bounded(self.source_id, "Environment edge source", 256)
        _bounded(self.target_id, "Environment edge target", 256)
        _bounded(self.relation, "Environment edge relation", 128)
        _labels(self.provenance, "Environment edge provenance", 32)
        if not 0.0 <= self.confidence <= 1.0:
            raise CapabilityError("Environment edge confidence must be between zero and one")
        if self.last_verified is not None and self.last_verified.tzinfo is None:
            raise CapabilityError("Environment edge timestamp must be timezone-aware")


class EnvironmentGraph:
    """Credential-free observations of the current environment topology."""

    def __init__(self) -> None:
        self._nodes: dict[str, EnvironmentNode] = {}
        self._edges: set[EnvironmentEdge] = set()

    def add_node(self, node: EnvironmentNode) -> None:
        if node.node_id in self._nodes:
            raise CapabilityError("Duplicate environment node ID")
        self._nodes[node.node_id] = node

    def add_edge(self, edge: EnvironmentEdge) -> None:
        if edge.source_id not in self._nodes or edge.target_id not in self._nodes:
            raise CapabilityError("Environment edge references an unknown node")
        self._edges.add(edge)

    def remove_node(self, node_id: str) -> EnvironmentNode:
        try:
            node = self._nodes.pop(node_id)
        except KeyError as error:
            raise KeyError("Unknown environment node") from error
        self._edges = {
            edge for edge in self._edges if edge.source_id != node_id and edge.target_id != node_id
        }
        return node

    def nodes(self, kind: EnvironmentNodeKind | None = None) -> tuple[EnvironmentNode, ...]:
        return tuple(node for node in self._nodes.values() if kind is None or node.kind is kind)

    def edges(self) -> tuple[EnvironmentEdge, ...]:
        return tuple(self._edges)

    def related(self, node_id: str) -> tuple[EnvironmentNode, ...]:
        if node_id not in self._nodes:
            raise KeyError("Unknown environment node")
        related_ids = {
            edge.target_id if edge.source_id == node_id else edge.source_id
            for edge in self._edges
            if edge.source_id == node_id or edge.target_id == node_id
        }
        return tuple(self._nodes[item] for item in related_ids)


def capability_hash(capability_id: str, version: SemanticVersion, actions: Iterable[str]) -> str:
    """Return a stable hash for trusted capability identity metadata."""

    _bounded(capability_id, "Capability ID", 128)
    payload = "|".join((capability_id, str(version), *sorted(actions)))
    return sha256(payload.encode("utf-8")).hexdigest()


def _labels(values: Iterable[str], name: str, limit: int) -> None:
    values = tuple(values)
    if len(values) > limit or any(
        type(value) is not str or not value.strip() or len(value) > 512 or "\x00" in value
        for value in values
    ):
        raise CapabilityError(f"{name} are invalid")


def _bounded(value: str, name: str, limit: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise CapabilityError(f"{name} is invalid")


def _looks_like_secret(value: str) -> bool:
    lowered = value.casefold()
    return any(token in lowered for token in ("password=", "secret=", "token=", "api_key="))
