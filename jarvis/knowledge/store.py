"""Small local search and persistence interface for project knowledge."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import cast

from jarvis.knowledge.models import (
    Authority,
    ComponentRecord,
    KnowledgeItem,
    KnowledgeSnapshot,
    Provenance,
    SearchResult,
    ToolPermissionRecord,
)

_TOKEN = re.compile(r"[a-z0-9_./-]+")
_MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
_MAX_ITEMS = 4096
_MAX_COMPONENTS = 1024
_MAX_TOOLS = 1024
_MAX_PERMISSIONS = 256
_MAX_LIST_ITEMS = 256
_MAX_MAPPING_ITEMS = 512
_MAX_TEXT = 65_536
_MAX_CONTENT = 2 * 1024 * 1024


class KnowledgeStore:
    """Retrieve indexed knowledge with deterministic lexical relevance."""

    def __init__(self, snapshot: KnowledgeSnapshot) -> None:
        self._snapshot = snapshot

    @property
    def snapshot(self) -> KnowledgeSnapshot:
        return self._snapshot

    @classmethod
    def load(cls, path: Path) -> KnowledgeStore:
        """Load a generated JSON artifact without importing project code dynamically."""

        if not isinstance(path, Path):
            raise ValueError("Knowledge snapshot path is invalid")
        try:
            resolved = path.expanduser().resolve(strict=True)
            if not resolved.is_file() or path.is_symlink() or _has_reparse_ancestor(resolved):
                raise ValueError("Knowledge snapshot path is unsafe")
            if resolved.parent.name.casefold() != "generated":
                raise ValueError("Knowledge snapshot must come from the generated root")
            if resolved.stat().st_size > _MAX_SNAPSHOT_BYTES:
                raise ValueError("Knowledge snapshot is too large")
            payload = json.loads(resolved.read_text(encoding="utf-8"))
            root = _object(payload, "snapshot")
            _keys(
                root,
                {
                    "schema_version",
                    "generated_at",
                    "revision",
                    "items",
                    "components",
                    "tools",
                    "permissions",
                },
                {"schema_version", "generated_at", "items", "components", "tools"},
                "snapshot",
            )
            schema_version = _integer(root["schema_version"], "schema_version")
            if schema_version > 1:
                raise ValueError("Knowledge snapshot uses a future schema")
            if schema_version != 1:
                raise ValueError("Knowledge snapshot schema is unsupported")
            generated_at = _text(root["generated_at"], "generated_at", 128)
            revision = root.get("revision")
            if revision is not None:
                revision = _text(revision, "revision", 128)
            items_raw = _list(root["items"], "items", _MAX_ITEMS)
            components_raw = _list(root["components"], "components", _MAX_COMPONENTS)
            tools_raw = _list(root["tools"], "tools", _MAX_TOOLS)
            permissions_raw = _list(root.get("permissions", []), "permissions", _MAX_PERMISSIONS)
            snapshot = KnowledgeSnapshot(
                schema_version=schema_version,
                generated_at=datetime.fromisoformat(generated_at),
                revision=revision,
                items=tuple(_item_from_dict(_object(item, "item")) for item in items_raw),
                components=tuple(
                    _component_from_dict(_object(item, "component")) for item in components_raw
                ),
                tools=tuple(_tool_from_dict(_object(item, "tool")) for item in tools_raw),
                permissions=tuple(_text(value, "permission", 256) for value in permissions_raw),
            )
            return cls(snapshot)
        except (OSError, json.JSONDecodeError, TypeError, KeyError, ValueError) as error:
            if isinstance(error, ValueError) and str(error).startswith("Knowledge snapshot"):
                raise
            raise ValueError("Knowledge snapshot is malformed") from error

    def save(self, path: Path) -> None:
        """Persist the generated snapshot; callers choose the generated directory."""

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self._snapshot.to_json(), encoding="utf-8", newline="\n")

    def search(
        self, query: str, *, kind: str | None = None, limit: int = 10
    ) -> tuple[SearchResult, ...]:
        """Return simple title/summary/content matches, newest index order as tie-breaker."""

        if limit <= 0:
            return ()
        terms = set(_TOKEN.findall(query.casefold()))
        if not terms:
            return ()
        hits: list[SearchResult] = []
        for item in self._snapshot.items:
            if kind is not None and item.kind != kind:
                continue
            title_terms = set(_TOKEN.findall(item.title.casefold()))
            summary_terms = set(_TOKEN.findall(item.summary.casefold()))
            content_terms = set(_TOKEN.findall(item.content.casefold()))
            score = len(terms & title_terms) * 5
            score += len(terms & summary_terms) * 3
            score += len(terms & content_terms)
            if score:
                hits.append(SearchResult(item, score))
        hits.sort(key=lambda hit: (-hit.score, hit.item.title.casefold(), hit.item.item_id))
        return tuple(hits[:limit])

    def stale_items(self, project_root: Path) -> tuple[KnowledgeItem, ...]:
        return self._snapshot.stale_items(project_root)


def _provenance_from_dict(payload: dict[str, object]) -> Provenance:
    _keys(
        payload,
        {"source_files", "source_hashes", "generated_at", "revision"},
        {"source_files", "source_hashes", "generated_at"},
        "provenance",
    )
    source_files = _list(payload["source_files"], "source_files", _MAX_LIST_ITEMS)
    source_files_text = tuple(_relative_source(value) for value in source_files)
    hashes = _mapping(payload["source_hashes"], "source_hashes", _MAX_MAPPING_ITEMS)
    source_hashes = tuple(
        sorted(
            (
                _relative_source(path),
                _digest(digest, "source hash"),
            )
            for path, digest in hashes.items()
        )
    )
    generated_at = _text(payload["generated_at"], "provenance.generated_at", 128)
    revision = payload.get("revision")
    if revision is not None:
        revision = _text(revision, "provenance.revision", 128)
    return Provenance(
        source_files=source_files_text,
        source_hashes=source_hashes,
        generated_at=datetime.fromisoformat(generated_at),
        revision=revision,
    )


def _item_from_dict(payload: dict[str, object]) -> KnowledgeItem:
    _keys(
        payload,
        {"id", "kind", "title", "summary", "content", "authority", "provenance", "metadata"},
        {"id", "kind", "title", "summary", "content", "authority", "provenance"},
        "item",
    )
    metadata = _mapping(payload.get("metadata", {}), "item.metadata", _MAX_MAPPING_ITEMS)
    metadata_text = tuple(
        sorted(
            (
                _text(key, "item metadata key", 256),
                _text(value, "item metadata value", 2_000),
            )
            for key, value in metadata.items()
        )
    )
    provenance = _object(payload["provenance"], "item.provenance")
    return KnowledgeItem(
        item_id=_text(payload["id"], "item id", 256),
        kind=_text(payload["kind"], "item kind", 128),
        title=_text(payload["title"], "item title", 4_000),
        summary=_text(payload["summary"], "item summary", 16_000),
        content=_text(payload["content"], "item content", _MAX_CONTENT),
        authority=Authority(_text(payload["authority"], "item authority", 64)),
        provenance=_provenance_from_dict(provenance),
        metadata=metadata_text,
    )


def _component_from_dict(payload: dict[str, object]) -> ComponentRecord:
    _keys(
        payload,
        {
            "name",
            "purpose",
            "public_interfaces",
            "dependencies",
            "relevant_files",
            "architectural_layer",
            "provenance",
        },
        {
            "name",
            "purpose",
            "public_interfaces",
            "dependencies",
            "relevant_files",
            "architectural_layer",
            "provenance",
        },
        "component",
    )
    provenance = _object(payload["provenance"], "component.provenance")
    return ComponentRecord(
        name=_text(payload["name"], "component name", 256),
        purpose=_text(payload["purpose"], "component purpose", 16_000),
        public_interfaces=_text_list(payload["public_interfaces"], "public_interfaces"),
        dependencies=_text_list(payload["dependencies"], "dependencies"),
        relevant_files=tuple(
            _relative_source(value)
            for value in _list(payload["relevant_files"], "relevant_files", _MAX_LIST_ITEMS)
        ),
        architectural_layer=_text(payload["architectural_layer"], "architectural_layer", 256),
        provenance=_provenance_from_dict(provenance),
    )


def _tool_from_dict(payload: dict[str, object]) -> ToolPermissionRecord:
    _keys(
        payload,
        {
            "tool_id",
            "name",
            "description",
            "version",
            "permissions",
            "capabilities",
            "platforms",
            "input_schema",
            "output_schema",
            "status",
            "provenance",
        },
        {
            "tool_id",
            "name",
            "description",
            "version",
            "permissions",
            "capabilities",
            "platforms",
            "input_schema",
            "output_schema",
            "status",
            "provenance",
        },
        "tool",
    )
    provenance = _object(payload["provenance"], "tool.provenance")
    return ToolPermissionRecord(
        tool_id=_text(payload["tool_id"], "tool id", 256),
        name=_text(payload["name"], "tool name", 256),
        description=_text(payload["description"], "tool description", 16_000),
        version=_text(payload["version"], "tool version", 128),
        permissions=_text_list(payload["permissions"], "tool permissions"),
        capabilities=_text_list(payload["capabilities"], "tool capabilities"),
        platforms=_text_list(payload["platforms"], "tool platforms"),
        input_schema=_text(payload["input_schema"], "tool input schema", 16_000),
        output_schema=_text(payload["output_schema"], "tool output schema", 16_000),
        status=_text(payload["status"], "tool status", 128),
        provenance=_provenance_from_dict(provenance),
    )


def _object(value: object, field: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(f"Invalid knowledge {field} object")
    return cast(dict[str, object], value)


def _mapping(value: object, field: str, limit: int) -> dict[str, object]:
    result = _object(value, field)
    if len(result) > limit or any(type(key) is not str for key in result):
        raise ValueError(f"Invalid knowledge {field} mapping")
    return result


def _list(value: object, field: str, limit: int) -> tuple[object, ...]:
    if type(value) is not list or len(value) > limit:
        raise ValueError(f"Invalid knowledge {field} sequence")
    return tuple(value)


def _keys(payload: dict[str, object], allowed: set[str], required: set[str], field: str) -> None:
    if set(payload) - allowed or required - set(payload):
        raise ValueError(f"Invalid knowledge {field} fields")


def _integer(value: object, field: str) -> int:
    if type(value) is not int:
        raise ValueError(f"Invalid knowledge {field}")
    return value


def _text(value: object, field: str, limit: int) -> str:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError(f"Invalid knowledge {field}")
    return value


def _text_list(value: object, field: str) -> tuple[str, ...]:
    return tuple(_text(item, field, 4_000) for item in _list(value, field, _MAX_LIST_ITEMS))


def _digest(value: object, field: str) -> str:
    text = _text(value, field, 64)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise ValueError(f"Invalid knowledge {field}")
    return text


def _relative_source(value: object) -> str:
    text = _text(value, "source path", 1_024)
    path = Path(text)
    if path.is_absolute() or "\\" in text or ".." in path.parts:
        raise ValueError("Knowledge source path is unsafe")
    return text


def _has_reparse_ancestor(path: Path) -> bool:
    current = path
    while current != current.parent:
        if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
            return True
        current = current.parent
    return False
