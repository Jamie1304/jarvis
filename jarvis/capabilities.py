"""Canonical capability vocabulary and credential-free environment graph."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType

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
        if type(self.preview_supported) is not bool:
            raise CapabilityError("Effect preview metadata is invalid")
        if type(self.produced_artifacts) is not tuple or type(self.emitted_events) is not tuple:
            raise CapabilityError("Effect output metadata is invalid")
        if self.compensation is not None:
            _bounded(self.compensation, "Effect compensation", 1_000)
        _labels(self.produced_artifacts, "Produced artifacts", 32)
        _labels(self.emitted_events, "Emitted events", 32)


_ACTION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_ACTION_SCHEMA_KEYS = frozenset(
    {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "title",
        "description",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
    }
)
_ACTION_SCHEMA_TYPES = frozenset({"object", "array", "string", "integer", "number", "boolean"})


def _freeze_action_json(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_action_json(item) for key, item in value.items()}
        )
    if isinstance(value, list | tuple):
        return tuple(_freeze_action_json(item) for item in value)
    return value


def action_schema_dict(value: Mapping[str, object]) -> dict[str, object]:
    """Return a detached JSON-compatible copy of an action schema."""

    def thaw(item: object) -> object:
        if isinstance(item, Mapping):
            return {str(key): thaw(child) for key, child in item.items()}
        if isinstance(item, tuple | list):
            return [thaw(child) for child in item]
        return item

    result = thaw(value)
    if not isinstance(result, dict):  # pragma: no cover - guarded by the contract
        raise CapabilityError("Action schema is not an object")
    return result


def validate_action_schema(schema: object, field: str = "Action schema") -> dict[str, object]:
    """Validate the bounded JSON-schema subset used by generated actions.

    This intentionally supports a small data-only vocabulary.  It is not a
    general JSON-schema interpreter and never permits executable validators.
    """

    def visit(value: object, path: str, depth: int) -> dict[str, object]:
        if depth > 5 or not isinstance(value, Mapping):
            raise CapabilityError(f"{path} must be a bounded object schema")
        if len(value) > 64 or any(type(key) is not str for key in value):
            raise CapabilityError(f"{path} has invalid properties")
        unknown = set(value) - _ACTION_SCHEMA_KEYS
        if unknown:
            raise CapabilityError(f"{path} uses unsupported schema keywords")
        schema_type = value.get("type")
        if type(schema_type) is not str or schema_type not in _ACTION_SCHEMA_TYPES:
            raise CapabilityError(f"{path} has an unsupported type")
        normalized: dict[str, object] = {"type": schema_type}
        for key in ("title", "description"):
            if key in value:
                item = value[key]
                if type(item) is not str or not item.strip() or len(item) > 512 or "\x00" in item:
                    raise CapabilityError(f"{path}.{key} is malformed")
                normalized[key] = item
        for key in ("minLength", "maxLength", "minimum", "maximum"):
            if key in value:
                item = value[key]
                if type(item) is not int and type(item) is not float:
                    raise CapabilityError(f"{path}.{key} is malformed")
                if isinstance(item, float) and not math.isfinite(item):
                    raise CapabilityError(f"{path}.{key} is malformed")
                normalized[key] = item
        if schema_type == "object":
            properties = value.get("properties", {})
            if not isinstance(properties, Mapping) or len(properties) > 64:
                raise CapabilityError(f"{path}.properties is malformed")
            normalized_properties = {
                key: visit(item, f"{path}.properties.{key}", depth + 1)
                for key, item in properties.items()
                if type(key) is str and key.strip()
            }
            normalized["properties"] = normalized_properties
            if len(normalized_properties) != len(properties):
                raise CapabilityError(f"{path}.properties contains an invalid name")
            required = value.get("required", ())
            if not isinstance(required, list | tuple) or len(required) > 64:
                raise CapabilityError(f"{path}.required is malformed")
            if any(type(item) is not str or not item.strip() for item in required):
                raise CapabilityError(f"{path}.required is malformed")
            if len(set(required)) != len(required) or not set(required) <= set(properties):
                raise CapabilityError(f"{path}.required is inconsistent")
            normalized["required"] = list(required)
            additional = value.get("additionalProperties", False)
            if type(additional) is not bool or additional:
                raise CapabilityError(f"{path} must reject additional properties")
            normalized["additionalProperties"] = False
        elif "properties" in value or "required" in value or "additionalProperties" in value:
            raise CapabilityError(f"{path} has object-only keywords")
        if schema_type == "array":
            items = value.get("items")
            if items is None:
                raise CapabilityError(f"{path}.items is required")
            normalized["items"] = visit(items, f"{path}.items", depth + 1)
        elif "items" in value:
            raise CapabilityError(f"{path} has array-only keywords")
        return normalized

    return visit(schema, field, 0)


@dataclass(frozen=True, slots=True)
class CapabilityActionSpec:
    """Validated semantic action metadata bound to one exact package.

    The declaration is a contract, not an authority grant.  A generated
    action can become executable only after trusted review, certification,
    activation, and registration by the application-owned adapter.
    """

    capability_id: str
    package_id: str
    package_version: SemanticVersion
    package_hash: str
    action_id: str
    semantic_name: str
    description: str
    input_schema: Mapping[str, object]
    output_schema: Mapping[str, object]
    effect: EffectMetadata
    required_permissions: tuple[Permission, ...] = ()
    target_scope: tuple[str, ...] = ()
    idempotent: bool = True
    retryable: bool = False
    verification: tuple[str, ...] = ("adapter_output_schema",)
    compensation: str | None = None

    def __post_init__(self) -> None:
        _bounded(self.capability_id, "Action capability ID", 128)
        _bounded(self.package_id, "Action package ID", 128)
        if not isinstance(self.package_version, SemanticVersion):
            raise CapabilityError("Action package version is invalid")
        if self.package_hash and not re.fullmatch(r"[0-9a-fA-F]{64}", self.package_hash):
            raise CapabilityError("Action package hash is invalid")
        if not _ACTION_ID.fullmatch(self.action_id) or self.action_id in {"health", "inspect"}:
            raise CapabilityError("Action ID is invalid or reserved")
        _bounded(self.semantic_name, "Action semantic name", 256)
        _bounded(self.description, "Action description", 2_000)
        input_schema = validate_action_schema(self.input_schema, "Action input schema")
        output_schema = validate_action_schema(self.output_schema, "Action output schema")
        if input_schema.get("type") != "object" or output_schema.get("type") != "object":
            raise CapabilityError("Generated action schemas must be objects")
        object.__setattr__(self, "input_schema", _freeze_action_json(input_schema))
        object.__setattr__(self, "output_schema", _freeze_action_json(output_schema))
        if not isinstance(self.effect, EffectMetadata):
            raise CapabilityError("Action effect metadata is invalid")
        if (
            any(not isinstance(item, Permission) for item in self.required_permissions)
            or tuple(sorted(set(self.required_permissions), key=lambda item: item.value))
            != self.required_permissions
        ):
            raise CapabilityError("Action permissions must be unique and sorted")
        if (
            self.effect.classification is not EffectClassification.OBSERVATION
            and not self.required_permissions
        ):
            raise CapabilityError("Effectful generated actions must declare broker permissions")
        _labels(self.target_scope, "Action target scope", 32)
        if type(self.idempotent) is not bool or type(self.retryable) is not bool:
            raise CapabilityError("Action retry metadata is invalid")
        if self.retryable and not self.idempotent:
            raise CapabilityError("Only idempotent actions may be retryable")
        _labels(self.verification, "Action verification contract", 32)
        if self.compensation is not None:
            _bounded(self.compensation, "Action compensation", 1_000)


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
