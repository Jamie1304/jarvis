from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from jarvis.artifacts import (
    ArtifactClassification,
    ArtifactRetentionPolicy,
    ArtifactStore,
)
from jarvis.events import InMemoryEventBus


@pytest.mark.asyncio
async def test_text_binary_versions_derivation_and_event(tmp_path: Path) -> None:
    bus = InMemoryEventBus()
    received: list[object] = []
    ready = asyncio.Event()

    async def observe(event: object) -> None:
        received.append(event)
        ready.set()

    subscription = await bus.subscribe(observe)
    store = ArtifactStore(tmp_path / "artifacts", event_bus=bus)
    task_id = uuid4()
    reference = store.put(
        workspace_id="workspace-a",
        task_id=task_id,
        name="answer.txt",
        content=b"hello",
        mime_type="text/plain",
        classification=ArtifactClassification.INTERNAL,
        producer="test",
        provenance=("task-output",),
    )
    assert store.read(reference, workspace_id="workspace-a") == b"hello"
    version = store.get_version(reference, workspace_id="workspace-a")
    assert version.size == 5
    assert version.content_hash
    derived = store.derive(
        reference,
        workspace_id="workspace-a",
        name="answer.bin",
        content=b"\x00\xff",
        mime_type="application/octet-stream",
        classification=ArtifactClassification.SENSITIVE,
        producer="transform",
    )
    assert derived.version == 2
    assert store.get_version(derived, workspace_id="workspace-a").parent == reference
    await asyncio.wait_for(ready.wait(), timeout=1)
    assert received
    await bus.unsubscribe(subscription)
    await bus.close()
    store.close()


def test_artifact_workspace_isolation_path_attacks_and_secret_rejection(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    reference = store.put(
        workspace_id="one",
        name="safe.txt",
        content=b"data",
        mime_type="text/plain",
        classification=ArtifactClassification.PUBLIC,
        producer="test",
    )
    with pytest.raises(PermissionError):
        store.read(reference, workspace_id="two")
    forged_workspace = reference.__class__(
        reference.artifact_id, reference.version, "two", reference.storage_reference
    )
    with pytest.raises(KeyError):
        store.read(forged_workspace, workspace_id="two")
    with pytest.raises(ValueError):
        store.put(
            workspace_id="one",
            name="../escape.txt",
            content=b"x",
            mime_type="text/plain",
            classification=ArtifactClassification.PUBLIC,
            producer="test",
        )
    with pytest.raises(ValueError):
        store.read(
            reference.__class__(reference.artifact_id, 1, "one", "../escape"),
            workspace_id="one",
        )
    with pytest.raises(PermissionError):
        store.put(
            workspace_id="one",
            name="secret.txt",
            content=b"secret",
            mime_type="text/plain",
            classification=ArtifactClassification.CREDENTIAL_SECRET,
            producer="vault",
        )
    store.close()


def test_artifact_root_rejects_reparse_ancestor_when_supported(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked-root"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Creating a symlink is not available to this test process")

    with pytest.raises(OSError, match="reparse"):
        ArtifactStore(link / "artifacts")


def test_artifact_retention_and_restart(tmp_path: Path) -> None:
    path = tmp_path / "artifacts"
    store = ArtifactStore(path)
    reference = store.put(
        workspace_id="workspace",
        name="temporary.bin",
        content=b"binary",
        mime_type="application/octet-stream",
        classification=ArtifactClassification.INTERNAL,
        producer="test",
        retention=ArtifactRetentionPolicy(expires_at=datetime.now(UTC) - timedelta(seconds=1)),
    )
    assert store.purge_expired() == 1
    with pytest.raises(KeyError):
        store.get_version(reference, workspace_id="workspace")
    store.close()

    reopened = ArtifactStore(path)
    persistent = reopened.put(
        workspace_id="workspace",
        name="persistent.txt",
        content=b"persisted",
        mime_type="text/plain",
        classification=ArtifactClassification.INTERNAL,
        producer="test",
    )
    reopened.close()
    restarted = ArtifactStore(path)
    assert restarted.read(persistent, workspace_id="workspace") == b"persisted"
    assert restarted.get_record(persistent.artifact_id, workspace_id="workspace").task_id is None
    restarted.close()


def test_artifact_retention_limits_versions(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    policy = ArtifactRetentionPolicy(max_versions=2)
    first = store.put(
        workspace_id="workspace",
        name="one.txt",
        content=b"one",
        mime_type="text/plain",
        classification=ArtifactClassification.INTERNAL,
        producer="test",
        retention=policy,
    )
    second = store.derive(
        first,
        workspace_id="workspace",
        name="two.txt",
        content=b"two",
        mime_type="text/plain",
        classification=ArtifactClassification.INTERNAL,
        producer="test",
        retention=policy,
    )
    third = store.derive(
        second,
        workspace_id="workspace",
        name="three.txt",
        content=b"three",
        mime_type="text/plain",
        classification=ArtifactClassification.INTERNAL,
        producer="test",
        retention=policy,
    )
    with pytest.raises(KeyError):
        store.get_version(first, workspace_id="workspace")
    assert store.read(third, workspace_id="workspace") == b"three"
    store.close()


def test_artifact_store_migration_and_future_schema_refusal(tmp_path: Path) -> None:
    future_root = tmp_path / "future-artifacts"
    future_root.mkdir()
    with sqlite3.connect(future_root / "artifacts.sqlite3") as connection:
        connection.execute(
            "CREATE TABLE artifact_schema_migrations "
            "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO artifact_schema_migrations(version, name) VALUES (99, 'future')"
        )
    with pytest.raises(OSError, match="future schema"):
        ArtifactStore(future_root)

    migrated = ArtifactStore(tmp_path / "migrated-artifacts")
    version = migrated._connection.execute(  # noqa: SLF001 - migration assertion
        "SELECT version, name FROM artifact_schema_migrations"
    ).fetchone()
    assert version == (1, "create_artifacts")
    migrated.close()
