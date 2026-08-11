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

        payload = json.loads(path.read_text(encoding="utf-8"))
        snapshot = KnowledgeSnapshot(
            schema_version=int(payload["schema_version"]),
            generated_at=datetime.fromisoformat(payload["generated_at"]),
            revision=payload.get("revision"),
            items=tuple(_item_from_dict(item) for item in payload["items"]),
            components=tuple(_component_from_dict(item) for item in payload["components"]),
            tools=tuple(_tool_from_dict(item) for item in payload["tools"]),
            permissions=tuple(str(value) for value in payload.get("permissions", ())),
        )
        return cls(snapshot)

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
    hashes = _mapping(payload["source_hashes"])
    return Provenance(
        source_files=tuple(str(value) for value in _sequence(payload["source_files"])),
        source_hashes=tuple(sorted((str(path), str(digest)) for path, digest in hashes.items())),
        generated_at=datetime.fromisoformat(str(payload["generated_at"])),
        revision=str(payload["revision"]) if payload.get("revision") else None,
    )


def _item_from_dict(payload: dict[str, object]) -> KnowledgeItem:
    metadata = _mapping(payload.get("metadata", {}))
    provenance = _mapping(payload["provenance"])
    return KnowledgeItem(
        item_id=str(payload["id"]),
        kind=str(payload["kind"]),
        title=str(payload["title"]),
        summary=str(payload["summary"]),
        content=str(payload["content"]),
        authority=Authority(str(payload["authority"])),
        provenance=_provenance_from_dict(provenance),
        metadata=tuple(sorted((str(key), str(value)) for key, value in metadata.items())),
    )


def _component_from_dict(payload: dict[str, object]) -> ComponentRecord:
    provenance = _mapping(payload["provenance"])
    return ComponentRecord(
        name=str(payload["name"]),
        purpose=str(payload["purpose"]),
        public_interfaces=tuple(str(value) for value in _sequence(payload["public_interfaces"])),
        dependencies=tuple(str(value) for value in _sequence(payload["dependencies"])),
        relevant_files=tuple(str(value) for value in _sequence(payload["relevant_files"])),
        architectural_layer=str(payload["architectural_layer"]),
        provenance=_provenance_from_dict(provenance),
    )


def _tool_from_dict(payload: dict[str, object]) -> ToolPermissionRecord:
    provenance = _mapping(payload["provenance"])
    return ToolPermissionRecord(
        tool_id=str(payload["tool_id"]),
        name=str(payload["name"]),
        description=str(payload["description"]),
        version=str(payload["version"]),
        permissions=tuple(str(value) for value in _sequence(payload["permissions"])),
        capabilities=tuple(str(value) for value in _sequence(payload["capabilities"])),
        platforms=tuple(str(value) for value in _sequence(payload["platforms"])),
        input_schema=str(payload["input_schema"]),
        output_schema=str(payload["output_schema"]),
        status=str(payload["status"]),
        provenance=_provenance_from_dict(provenance),
    )


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("Invalid knowledge mapping")
    return cast(dict[str, object], value)


def _sequence(value: object) -> tuple[object, ...]:
    if not isinstance(value, list):
        raise ValueError("Invalid knowledge sequence")
    return tuple(value)
