"""Immutable records for authoritative and generated project knowledge."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any


class Authority(StrEnum):
    """How a knowledge record may be relied upon."""

    AUTHORITATIVE = "authoritative"
    GENERATED = "generated"
    HISTORICAL = "historical"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class Provenance:
    """Source identity captured when a generated record was produced."""

    source_files: tuple[str, ...]
    source_hashes: tuple[tuple[str, str], ...]
    generated_at: datetime
    revision: str | None = None

    def __post_init__(self) -> None:
        if not self.source_files:
            raise ValueError("Knowledge provenance requires at least one source file")
        if any(not path or Path(path).is_absolute() for path in self.source_files):
            raise ValueError("Knowledge source paths must be non-empty and relative")
        if tuple(sorted(self.source_files)) != self.source_files:
            raise ValueError("Knowledge source paths must be sorted")
        if tuple(sorted(self.source_hashes)) != self.source_hashes:
            raise ValueError("Knowledge source hashes must be sorted")
        hash_paths = tuple(path for path, _ in self.source_hashes)
        if hash_paths != self.source_files:
            raise ValueError("Every source file must have exactly one hash")
        if any(
            len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)
            for _, digest in self.source_hashes
        ):
            raise ValueError("Source hashes must be lowercase SHA-256 digests")
        object.__setattr__(self, "generated_at", _utc(self.generated_at))
        if self.revision is not None and (
            len(self.revision) != 40
            or any(char not in "0123456789abcdef" for char in self.revision)
        ):
            raise ValueError("Revision must be a full lowercase Git commit hash")

    def is_stale(self, project_root: Path) -> bool:
        """Return whether any source disappeared or changed since generation."""

        for relative, expected in self.source_hashes:
            path = project_root / relative
            try:
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
            except (OSError, ValueError):
                return True
            if actual != expected:
                return True
        return False


@dataclass(frozen=True, slots=True)
class ComponentRecord:
    """Structured generated description of one source component."""

    name: str
    purpose: str
    public_interfaces: tuple[str, ...]
    dependencies: tuple[str, ...]
    relevant_files: tuple[str, ...]
    architectural_layer: str
    provenance: Provenance


@dataclass(frozen=True, slots=True)
class ToolPermissionRecord:
    """Tool contract derived from a live trusted registry and schema manifest."""

    tool_id: str
    name: str
    description: str
    version: str
    permissions: tuple[str, ...]
    capabilities: tuple[str, ...]
    platforms: tuple[str, ...]
    input_schema: str
    output_schema: str
    status: str
    provenance: Provenance


@dataclass(frozen=True, slots=True)
class KnowledgeItem:
    """One searchable record; generated records retain source provenance."""

    item_id: str
    kind: str
    title: str
    summary: str
    content: str
    authority: Authority
    provenance: Provenance
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.item_id.strip() or not self.title.strip():
            raise ValueError("Knowledge items require an ID and title")
        if "\x00" in self.content or "\x00" in self.summary:
            raise ValueError("Knowledge content cannot contain NUL bytes")

    def is_stale(self, project_root: Path) -> bool:
        return self.provenance.is_stale(project_root)


@dataclass(frozen=True, slots=True)
class SearchResult:
    """A relevance-ranked local search hit."""

    item: KnowledgeItem
    score: int


@dataclass(frozen=True, slots=True)
class KnowledgeSnapshot:
    """Complete generated project index persisted as one JSON artifact."""

    schema_version: int
    generated_at: datetime
    revision: str | None
    items: tuple[KnowledgeItem, ...]
    components: tuple[ComponentRecord, ...]
    tools: tuple[ToolPermissionRecord, ...]
    permissions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("Unsupported knowledge snapshot schema")
        object.__setattr__(self, "generated_at", _utc(self.generated_at))

    def stale_items(self, project_root: Path) -> tuple[KnowledgeItem, ...]:
        """Return generated records whose source files no longer match."""

        return tuple(item for item in self.items if item.is_stale(project_root))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at.isoformat(),
            "revision": self.revision,
            "items": [_item_dict(item) for item in self.items],
            "components": [_component_dict(component) for component in self.components],
            "tools": [_tool_dict(tool) for tool in self.tools],
            "permissions": list(self.permissions),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def _provenance_dict(value: Provenance) -> dict[str, Any]:
    return {
        "source_files": list(value.source_files),
        "source_hashes": {path: digest for path, digest in value.source_hashes},
        "generated_at": value.generated_at.isoformat(),
        "revision": value.revision,
    }


def _item_dict(value: KnowledgeItem) -> dict[str, Any]:
    return {
        "id": value.item_id,
        "kind": value.kind,
        "title": value.title,
        "summary": value.summary,
        "content": value.content,
        "authority": value.authority.value,
        "provenance": _provenance_dict(value.provenance),
        "metadata": dict(value.metadata),
    }


def _component_dict(value: ComponentRecord) -> dict[str, Any]:
    return {
        "name": value.name,
        "purpose": value.purpose,
        "public_interfaces": list(value.public_interfaces),
        "dependencies": list(value.dependencies),
        "relevant_files": list(value.relevant_files),
        "architectural_layer": value.architectural_layer,
        "provenance": _provenance_dict(value.provenance),
    }


def _tool_dict(value: ToolPermissionRecord) -> dict[str, Any]:
    return {
        "tool_id": value.tool_id,
        "name": value.name,
        "description": value.description,
        "version": value.version,
        "permissions": list(value.permissions),
        "capabilities": list(value.capabilities),
        "platforms": list(value.platforms),
        "input_schema": value.input_schema,
        "output_schema": value.output_schema,
        "status": value.status,
        "provenance": _provenance_dict(value.provenance),
    }
