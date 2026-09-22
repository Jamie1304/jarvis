"""Deterministic tests for provenance-aware project knowledge."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jarvis.knowledge.indexer import KnowledgeIndexDeferred, ProjectKnowledgeBuilder
from jarvis.knowledge.models import Authority
from jarvis.knowledge.store import KnowledgeStore
from jarvis.resources import ResourceGovernor, ResourceSnapshot
from jarvis.tools.catalog import create_safe_tool_registry


def _fixture_project(root: Path) -> None:
    (root / "docs" / "decisions").mkdir(parents=True)
    (root / "jarvis" / "sample").mkdir(parents=True)
    (root / "jarvis" / "permissions").mkdir(parents=True)
    (root / "docs" / "architecture.md").write_text(
        "# Architecture\n\nThe broker protects every tool.\n", encoding="utf-8"
    )
    (root / "docs" / "decisions" / "0001-boundary.md").write_text(
        "# Boundary decision\n\nKeep the planner untrusted.\n", encoding="utf-8"
    )
    (root / "jarvis" / "sample" / "__init__.py").write_text(
        '"""Sample orchestration component."""\n\nfrom .service import Service\n',
        encoding="utf-8",
    )
    (root / "jarvis" / "sample" / "service.py").write_text(
        "class Service:\n    pass\n", encoding="utf-8"
    )
    (root / "jarvis" / "permissions" / "models.py").write_text(
        "class Permission:\n    pass\n", encoding="utf-8"
    )
    (root / "jarvis" / "permissions" / "__init__.py").write_text(
        '"""Permission boundary."""\n', encoding="utf-8"
    )


def test_indexing_builds_components_documents_and_historical_adrs(tmp_path: Path) -> None:
    _fixture_project(tmp_path)

    snapshot = ProjectKnowledgeBuilder(tmp_path).build()

    assert snapshot.schema_version == 1
    assert snapshot.components[0].name == "permissions"
    sample = next(component for component in snapshot.components if component.name == "sample")
    assert sample.purpose == "Sample orchestration component."
    assert "Service" in sample.public_interfaces
    assert "jarvis/sample/service.py" in sample.relevant_files
    assert any(item.authority is Authority.AUTHORITATIVE for item in snapshot.items)
    decision = next(item for item in snapshot.items if item.kind == "decision")
    assert decision.authority is Authority.HISTORICAL
    tree = next(item for item in snapshot.items if item.kind == "project-tree")
    assert "jarvis/sample/service.py" in tree.content


def test_indexing_defers_under_shared_resource_pressure(tmp_path: Path) -> None:
    _fixture_project(tmp_path)

    class Telemetry:
        def snapshot(self) -> ResourceSnapshot:
            return ResourceSnapshot(
                datetime.now(UTC),
                cpu_utilization=0.99,
                ram_total_bytes=100,
                ram_available_bytes=10,
                disk_free_bytes=10_000_000_000,
            )

    builder = ProjectKnowledgeBuilder(tmp_path, resource_governor=ResourceGovernor(Telemetry()))
    with pytest.raises(KnowledgeIndexDeferred):
        builder.build()


def test_provenance_and_stale_detection_cover_changed_and_deleted_sources(tmp_path: Path) -> None:
    _fixture_project(tmp_path)
    snapshot = ProjectKnowledgeBuilder(tmp_path).build()
    architecture = next(item for item in snapshot.items if item.item_id == "docs:architecture")
    assert architecture.provenance.source_files == ("docs/architecture.md",)
    assert not architecture.is_stale(tmp_path)

    source = tmp_path / "docs" / "architecture.md"
    source.write_text("# Architecture\n\nChanged boundary.\n", encoding="utf-8")
    assert architecture in snapshot.stale_items(tmp_path)
    source.unlink()
    assert architecture in snapshot.stale_items(tmp_path)


def test_secret_files_and_secret_bearing_documents_are_excluded(tmp_path: Path) -> None:
    _fixture_project(tmp_path)
    (tmp_path / ".env").write_text("API_KEY='do-not-index'\n", encoding="utf-8")
    (tmp_path / "docs" / "credentials.md").write_text(
        "# Credentials\n\npassword = 'do-not-index'\n", encoding="utf-8"
    )
    snapshot = ProjectKnowledgeBuilder(tmp_path).build()
    serialized = snapshot.to_json()

    assert "do-not-index" not in serialized
    assert not any(
        "credentials" in path for item in snapshot.items for path in item.provenance.source_files
    )


def test_safe_sensitivity_enum_is_not_mistaken_for_a_credential(tmp_path: Path) -> None:
    _fixture_project(tmp_path)
    (tmp_path / "jarvis" / "sample" / "models.py").write_text(
        'from enum import StrEnum\n\nclass Sensitivity(StrEnum):\n    SECRET = "secret"\n',
        encoding="utf-8",
    )

    snapshot = ProjectKnowledgeBuilder(tmp_path).build()
    sample = next(component for component in snapshot.components if component.name == "sample")

    assert "jarvis/sample/models.py" in sample.relevant_files


def test_search_prioritizes_title_and_supports_kind_filter(tmp_path: Path) -> None:
    _fixture_project(tmp_path)
    store = KnowledgeStore(ProjectKnowledgeBuilder(tmp_path).build())

    results = store.search("broker architecture")
    assert results
    assert results[0].item.item_id == "docs:architecture"
    assert store.search("planner", kind="component") == ()


def test_tool_and_permission_index_comes_from_registry_and_enum(tmp_path: Path) -> None:
    # The real repository is used for source provenance because manifests point at real schemas.
    del tmp_path
    root = Path(__file__).resolve().parents[1]
    snapshot = ProjectKnowledgeBuilder(root).build(registry=create_safe_tool_registry())

    tool_ids = {tool.tool_id for tool in snapshot.tools}
    assert {"calculator", "local_time", "weather"} <= tool_ids
    calculator = next(tool for tool in snapshot.tools if tool.tool_id == "calculator")
    assert calculator.input_schema.endswith("CalculatorInput")
    assert "filesystem.read" in snapshot.permissions
    permission = next(item for item in snapshot.items if item.item_id == "permission:code.modify")
    assert permission.provenance.source_files == ("jarvis/permissions/models.py",)


def test_refresh_writes_only_generated_knowledge_artifact(tmp_path: Path) -> None:
    _fixture_project(tmp_path)
    output = tmp_path / "knowledge" / "generated" / "project-index.json"
    snapshot = ProjectKnowledgeBuilder(
        tmp_path, clock=lambda: datetime(2026, 1, 2, tzinfo=UTC)
    ).refresh(output)

    assert output.exists()
    assert snapshot.generated_at.isoformat() == "2026-01-02T00:00:00+00:00"
    assert '"schema_version": 1' in output.read_text(encoding="utf-8")
    loaded = KnowledgeStore.load(output)
    assert loaded.snapshot.revision is None
    assert loaded.search("broker architecture")


def test_knowledge_store_rejects_malformed_or_unbounded_generated_snapshot(
    tmp_path: Path,
) -> None:
    _fixture_project(tmp_path)
    output = tmp_path / "knowledge" / "generated" / "project-index.json"
    builder = ProjectKnowledgeBuilder(tmp_path)
    builder.refresh(output)

    valid = json.loads(output.read_text(encoding="utf-8"))
    malformed = dict(valid)
    malformed["items"] = [*valid["items"], {"id": "not-an-item"}]
    output.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        KnowledgeStore.load(output)

    future = dict(valid)
    future["schema_version"] = 2
    output.write_text(json.dumps(future), encoding="utf-8")
    with pytest.raises(ValueError, match="future"):
        KnowledgeStore.load(output)

    oversized = dict(valid)
    oversized["items"] = list(valid["items"]) * 5000
    output.write_text(json.dumps(oversized), encoding="utf-8")
    with pytest.raises(ValueError, match="too large|too many"):
        KnowledgeStore.load(output)

    unsafe_provenance = dict(valid)
    unsafe_provenance["items"] = [dict(valid["items"][0])]
    unsafe_provenance["items"][0]["provenance"] = dict(unsafe_provenance["items"][0]["provenance"])
    unsafe_provenance["items"][0]["provenance"]["source_files"] = ["../outside.md"]
    output.write_text(json.dumps(unsafe_provenance), encoding="utf-8")
    with pytest.raises(ValueError, match="malformed|unsafe"):
        KnowledgeStore.load(output)


def test_knowledge_store_rejects_invalid_types_and_supports_bounded_queries(
    tmp_path: Path,
) -> None:
    _fixture_project(tmp_path)
    output = tmp_path / "knowledge" / "generated" / "project-index.json"
    builder = ProjectKnowledgeBuilder(tmp_path)
    builder.refresh(output)
    valid = json.loads(output.read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="path is invalid"):
        KnowledgeStore.load("not-a-path")  # type: ignore[arg-type]

    outside_generated = tmp_path / "other" / "index.json"
    outside_generated.parent.mkdir()
    outside_generated.write_text(json.dumps(valid), encoding="utf-8")
    with pytest.raises(ValueError, match="generated root"):
        KnowledgeStore.load(outside_generated)

    cases: list[tuple[str, object, str]] = [
        ("schema_version", 0, "unsupported"),
        ("revision", 17, "malformed"),
        ("items", {}, "malformed"),
    ]
    for field, value, message in cases:
        malformed = json.loads(json.dumps(valid))
        malformed[field] = value
        output.write_text(json.dumps(malformed), encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            KnowledgeStore.load(output)

    malformed_item = json.loads(json.dumps(valid))
    malformed_item["items"][0]["content"] = {"not": "text"}
    output.write_text(json.dumps(malformed_item), encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        KnowledgeStore.load(output)

    malformed_provenance = json.loads(json.dumps(valid))
    malformed_provenance["items"][0]["provenance"]["source_hashes"] = []
    output.write_text(json.dumps(malformed_provenance), encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        KnowledgeStore.load(output)

    bad_digest = json.loads(json.dumps(valid))
    first_hash = next(iter(bad_digest["items"][0]["provenance"]["source_hashes"]))
    bad_digest["items"][0]["provenance"]["source_hashes"][first_hash] = "not-a-digest"
    output.write_text(json.dumps(bad_digest), encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        KnowledgeStore.load(output)

    valid_store = KnowledgeStore(builder.refresh(output))
    assert valid_store.search(" ", limit=10) == ()
    assert valid_store.search("broker", limit=0) == ()
