"""Tests for derived ambient presence and the generic safe presentation surface."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from jarvis.artifacts import ArtifactClassification, ArtifactReference, ArtifactStore
from jarvis.events import (
    EventEnvelope,
    EventType,
    HealthChanged,
    InMemoryEventBus,
    PermissionRequested,
    RuntimeStateChanged,
    SystemError,
    TaskStateChanged,
    ToolCompleted,
    ToolFailed,
    ToolStarted,
    VoiceStateChanged,
)
from jarvis.presence import (
    PresenceError,
    PresenceProjection,
    PresenceSignals,
    PresenceSnapshot,
    PresenceState,
    PresenceThemeManifest,
)
from jarvis.presentation import (
    PackageAssetReference,
    PresentationContent,
    PresentationEntry,
    PresentationError,
    PresentationKind,
    PresentationSurface,
    PresentationValidationError,
    PresentationVerificationStatus,
    UiStateReference,
    UiStateSnapshot,
    VerificationEngine,
)


async def _publish(
    bus: InMemoryEventBus,
    event_type: EventType,
    payload: object,
    **kwargs: object,
) -> None:
    await bus.publish(
        EventEnvelope.create(
            event_type,
            payload,  # type: ignore[arg-type]
            source="test",
            correlation_id=kwargs.get("correlation_id", uuid4()),  # type: ignore[arg-type]
            task_id=kwargs.get("task_id"),  # type: ignore[arg-type]
        )
    )
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_presence_projection_derives_all_states_from_events() -> None:
    bus = InMemoryEventBus()
    projection = PresenceProjection(bus)
    await projection.start()
    task_id = uuid4()

    assert projection.snapshot().state is PresenceState.IDLE
    await _publish(
        bus,
        EventType.VOICE_STATE_CHANGED,
        VoiceStateChanged("listening"),
    )
    assert projection.snapshot().state is PresenceState.LISTENING
    await _publish(
        bus,
        EventType.TASK_STATE_CHANGED,
        TaskStateChanged("idle", "thinking", "test"),
        task_id=task_id,
    )
    assert projection.snapshot().state is PresenceState.THINKING
    await _publish(bus, EventType.TOOL_STARTED, ToolStarted("fixture"), task_id=task_id)
    assert projection.snapshot().state is PresenceState.EXECUTING
    await _publish(
        bus,
        EventType.PERMISSION_REQUESTED,
        PermissionRequested(uuid4(), "filesystem.read", "low"),
        task_id=task_id,
    )
    assert projection.snapshot().state is PresenceState.WAITING_PERMISSION
    await _publish(
        bus,
        EventType.TASK_STATE_CHANGED,
        TaskStateChanged("waiting_for_permission", "verifying", "test"),
        task_id=task_id,
    )
    assert projection.snapshot().state is PresenceState.VERIFYING
    await _publish(
        bus,
        EventType.TASK_STATE_CHANGED,
        TaskStateChanged("verifying", "idle", "test"),
        task_id=task_id,
    )
    await _publish(bus, EventType.VOICE_STATE_CHANGED, VoiceStateChanged("speaking"))
    assert projection.snapshot().state is PresenceState.SPEAKING
    await _publish(bus, EventType.VOICE_STATE_CHANGED, VoiceStateChanged("idle"))
    await _publish(
        bus,
        EventType.HEALTH_CHANGED,
        HealthChanged("audio", "degraded"),
        task_id=task_id,
    )
    assert projection.snapshot().state is PresenceState.DEGRADED
    await _publish(bus, EventType.SYSTEM_ERROR, SystemError("fixture", "failure"), task_id=task_id)
    assert projection.snapshot().state is PresenceState.ERROR
    await _publish(
        bus,
        EventType.TASK_STATE_CHANGED,
        TaskStateChanged("error", "cancelled", "done"),
        task_id=task_id,
    )
    await _publish(
        bus,
        EventType.TASK_STATE_CHANGED,
        TaskStateChanged("cancelled", "idle", "done"),
        task_id=task_id,
    )
    assert projection.snapshot().state is PresenceState.IDLE
    await _publish(
        bus, EventType.TOOL_COMPLETED, ToolCompleted("fixture", "success"), task_id=task_id
    )
    await _publish(bus, EventType.TOOL_FAILED, ToolFailed("fixture", "failure"), task_id=task_id)
    assert projection.snapshot().state is PresenceState.ERROR
    await projection.stop()
    await projection.stop()
    await bus.close()


@pytest.mark.asyncio
async def test_presence_safe_mode_and_bounded_signals() -> None:
    bus = InMemoryEventBus()
    projection = PresenceProjection(bus, safe_mode=True)
    assert projection.snapshot().state is PresenceState.SAFE_MODE
    updated = projection.update_signals(PresenceSignals(0.25, 0.5, 1.0, "attention"))
    assert updated.signals.activity_level == 1.0
    with pytest.raises(PresenceError):
        PresenceSignals(1.1)
    await bus.close()


def test_presence_validation_fails_closed() -> None:
    for value in (1, -0.1, 1.1, float("nan"), float("inf")):
        with pytest.raises(PresenceError):
            PresenceSignals(cast(float, value))
    with pytest.raises(PresenceError):
        PresenceSignals(alert_state="\x00")
    timestamp = datetime.now(UTC)
    valid = PresenceSignals()
    invalid_snapshots = (
        ("bad", 0, timestamp, None, None, valid),
        (PresenceState.IDLE, -1, timestamp, None, None, valid),
        (PresenceState.IDLE, 0, timestamp.replace(tzinfo=None), None, None, valid),
        (PresenceState.IDLE, 0, timestamp, "bad", None, valid),
        (PresenceState.IDLE, 0, timestamp, None, "bad", valid),
        (PresenceState.IDLE, 0, timestamp, None, None, object()),
    )
    for args in invalid_snapshots:
        with pytest.raises(PresenceError):
            PresenceSnapshot(*args)


def test_presence_theme_bounds_and_projection_validation() -> None:
    base = dict(
        id="native.theme",
        name="Native Theme",
        version="1.0.0",
        supported_states=(PresenceState.IDLE,),
        layout={},
        animation_profile={},
    )
    invalid_themes = (
        {**base, "id": "../theme"},
        {**base, "name": ""},
        {**base, "version": ""},
        {**base, "supported_states": []},
        {**base, "supported_states": [PresenceState.IDLE]},
        {**base, "supported_states": (PresenceState.IDLE, PresenceState.IDLE)},
        {**base, "layout": []},
        {**base, "layout": {"script": "no"}},
        {**base, "layout": {"opacity": float("nan")}},
        {**base, "layout": {"items": object()}},
        {**base, "safe_asset_refs": ("path",)},
    )
    for values in invalid_themes:
        with pytest.raises(PresenceError):
            PresenceThemeManifest(**values)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_presence_runtime_state_event_and_aclose_are_idempotent() -> None:
    bus = InMemoryEventBus()
    projection = PresenceProjection(bus, runtime_state="error")
    assert projection.snapshot().state is PresenceState.ERROR
    await projection.start()
    await projection.start()
    await _publish(bus, EventType.RUNTIME_STATE_CHANGED, RuntimeStateChanged("safe_mode"))
    assert projection.snapshot().state is PresenceState.SAFE_MODE
    await projection.aclose()
    await projection.aclose()
    await bus.close()


def test_presence_theme_is_declarative_and_uses_opaque_assets() -> None:
    asset = PackageAssetReference("native.theme", "idle", "1.0.0", "a" * 64)
    theme = PresenceThemeManifest(
        "native.theme",
        "Native Theme",
        "1.0.0",
        tuple(PresenceState),
        {"panel": {"opacity": 0.8}},
        {"idle": {"duration_ms": 200}},
        (asset,),
        {"accent": "#00ff00"},
    )
    assert theme.safe_asset_refs == (asset,)
    with pytest.raises(PresenceError):
        PresenceThemeManifest(
            "unsafe",
            "Unsafe",
            "1.0.0",
            (PresenceState.IDLE,),
            {"html": "<script>alert(1)</script>"},
            {},
        )
    with pytest.raises(PresenceError):
        PresenceThemeManifest(
            "unsafe",
            "Unsafe",
            "1.0.0",
            (PresenceState.IDLE,),
            {"path": "C:/secret"},
            {},
        )


@pytest.mark.asyncio
async def test_presentation_surface_artifact_controls_actual_query_and_verification(
    tmp_path: Path,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    artifact = store.put(
        workspace_id="workspace",
        name="report.txt",
        content=b"safe report",
        mime_type="text/plain",
        classification=ArtifactClassification.INTERNAL,
        producer="test",
    )
    rendered: list[PresentationEntry] = []

    async def renderer(_surface_id: str, entries: tuple[PresentationEntry, ...]) -> None:
        rendered[:] = entries

    async def observer(_surface_id: str) -> tuple[PresentationEntry, ...]:
        return tuple(rendered)

    surface = PresentationSurface(
        "desktop",
        workspace_id="workspace",
        artifact_store=store,
        renderer=renderer,
        observer=observer,
    )
    intended = await surface.present(
        PresentationContent.from_artifact(PresentationKind.DOCUMENT, artifact, title="Report")
    )
    actual = await surface.query_state()
    result = await VerificationEngine().verify_surface(surface, intended)
    assert result.status is PresentationVerificationStatus.VERIFIED
    assert actual.references[0].artifact == artifact
    assert rendered

    control = PresentationContent.declarative(
        PresentationKind.CONTROL,
        {"action_id": "task.pause", "application_operation": "task.pause", "label": "Pause"},
        title="Pause",
    )
    controls = await surface.present(control)
    assert controls.references[0].kind is PresentationKind.CONTROL

    changed = replace(rendered[0], content_hash="b" * 64)
    rendered[:] = [changed]
    mismatch = await VerificationEngine().verify_surface(surface, intended)
    assert mismatch.status is PresentationVerificationStatus.MISMATCH
    assert mismatch.missing
    assert mismatch.unexpected
    store.close()


@pytest.mark.asyncio
async def test_presentation_rejects_asset_escape_and_untrusted_executable_content() -> None:
    surface = PresentationSurface("desktop", workspace_id="workspace")
    forged = ArtifactReference(uuid4(), 1, "workspace", "../outside.bin")
    with pytest.raises(PresentationValidationError):
        await surface.present(PresentationContent.from_artifact(PresentationKind.IMAGE, forged))
    unsafe_actual = PresentationEntry(
        uuid4(),
        PresentationContent.from_artifact(PresentationKind.IMAGE, forged),
        1,
        "a" * 64,
    )
    observed_surface = PresentationSurface(
        "desktop",
        workspace_id="workspace",
        observer=lambda _surface_id: _unsafe_observed(unsafe_actual),
    )
    with pytest.raises(PresentationValidationError):
        await observed_surface.query_state()
    with pytest.raises(PresentationValidationError):
        PresentationContent.declarative(
            PresentationKind.DECLARATIVE_VIEW,
            {"html": "<script>bad()</script>"},
        )
    with pytest.raises(PresentationValidationError):
        PresentationContent.declarative(
            PresentationKind.DECLARATIVE_VIEW,
            {"content": "javascript:alert(1)"},
        )
    safe = PresentationContent.declarative(
        PresentationKind.DECLARATIVE_VIEW,
        {"content": "Untrusted page text is data"},
    )
    assert safe.data is not None


@pytest.mark.asyncio
async def test_presentation_observer_rejects_snapshot_for_another_surface() -> None:
    requested_surface = PresentationSurface("desktop")
    requested = await requested_surface.present(
        PresentationContent.declarative(PresentationKind.DECLARATIVE_VIEW, {"state": "idle"})
    )

    async def wrong_surface(_surface_id: str) -> UiStateSnapshot:
        return replace(requested, surface_id="other")

    observed_surface = PresentationSurface("desktop", observer=wrong_surface)
    with pytest.raises(PresentationError, match="another surface"):
        await observed_surface.query_state()


async def _unsafe_observed(entry: PresentationEntry) -> tuple[PresentationEntry, ...]:
    return (entry,)


def test_presentation_typed_contract_validation() -> None:
    asset = PackageAssetReference("native.theme", "idle", "1.0.0", "a" * 64)
    artifact = ArtifactReference(uuid4(), 1, "workspace", "0" * 32 + "-1-" + "0" * 32 + ".bin")
    with pytest.raises(PresentationValidationError):
        PackageAssetReference("../theme", "idle", "1.0.0", "a" * 64)
    with pytest.raises(PresentationValidationError):
        PackageAssetReference("native.theme", "idle", "", "a" * 64)
    with pytest.raises(PresentationValidationError):
        PackageAssetReference("native.theme", "idle", "1.0.0", "bad")
    with pytest.raises(PresentationValidationError):
        PresentationContent(cast(PresentationKind, "document"), "title")
    with pytest.raises(PresentationValidationError):
        PresentationContent(PresentationKind.DOCUMENT, "title")
    with pytest.raises(PresentationValidationError):
        PresentationContent(
            PresentationKind.DOCUMENT, "title", artifact=cast(ArtifactReference, asset)
        )
    with pytest.raises(PresentationValidationError):
        PresentationContent(
            PresentationKind.DOCUMENT,
            "title",
            artifact=artifact,
            package_asset=asset,
        )
    with pytest.raises(PresentationValidationError):
        PresentationContent.declarative(PresentationKind.CHART, {"series": object()})
    with pytest.raises(PresentationValidationError):
        PresentationContent.declarative(PresentationKind.CHART, {"items": list(range(129))})
    deep: object = "leaf"
    for _ in range(8):
        deep = {"level": deep}
    with pytest.raises(PresentationValidationError):
        PresentationContent.declarative(PresentationKind.DECLARATIVE_VIEW, {"value": deep})
    with pytest.raises(PresentationValidationError):
        PresentationContent(
            PresentationKind.DECLARATIVE_VIEW,
            "title",
            data=cast(Mapping[str, object], ["not an object"]),
        )
    with pytest.raises(PresentationValidationError):
        PresentationContent(
            PresentationKind.DECLARATIVE_VIEW,
            "<script>bad</script>",
            data={"value": "safe"},
        )
    with pytest.raises(PresentationValidationError):
        PresentationContent(
            PresentationKind.DECLARATIVE_VIEW,
            "title",
            data={"value": "safe"},
            presentation_id=cast(UUID, "bad"),
        )


def test_presentation_snapshot_and_entry_validation() -> None:
    artifact = ArtifactReference(uuid4(), 1, "workspace", "0" * 32 + "-1-" + "0" * 32 + ".bin")
    content = PresentationContent.declarative(PresentationKind.CONTROL, {"action_id": "task.pause"})
    entry = PresentationEntry(uuid4(), content, 1, "a" * 64)
    assert entry.content is content
    with pytest.raises(PresentationValidationError):
        PresentationEntry(cast(UUID, "bad"), content, 1, "a" * 64)
    with pytest.raises(PresentationValidationError):
        PresentationEntry(uuid4(), cast(PresentationContent, "bad"), 1, "a" * 64)
    with pytest.raises(PresentationValidationError):
        PresentationEntry(uuid4(), content, 0, "a" * 64)
    with pytest.raises(PresentationValidationError):
        PresentationEntry(uuid4(), content, 1, "bad")
    reference = UiStateReference(uuid4(), PresentationKind.CONTROL, "", 1, "a" * 64)
    snapshot = UiStateSnapshot("desktop", 0, datetime.now(UTC), (reference,), "a" * 64)
    assert snapshot.references == (reference,)
    for values in (
        ("bad/path", 0, datetime.now(UTC), (), "a" * 64),
        ("desktop", -1, datetime.now(UTC), (), "a" * 64),
        ("desktop", 0, datetime.now(UTC).replace(tzinfo=None), (), "a" * 64),
        ("desktop", 0, datetime.now(UTC), (object(),), "a" * 64),
        ("desktop", 0, datetime.now(UTC), (reference, reference), "a" * 64),
        ("desktop", 0, datetime.now(UTC), (), "bad"),
    ):
        with pytest.raises(PresentationValidationError):
            UiStateSnapshot(*values)
    with pytest.raises(PresentationValidationError):
        UiStateReference(cast(UUID, "bad"), PresentationKind.CONTROL, "", 1, "a" * 64)
    with pytest.raises(PresentationValidationError):
        UiStateReference(uuid4(), cast(PresentationKind, "bad"), "", 1, "a" * 64)
    with pytest.raises(PresentationValidationError):
        UiStateReference(uuid4(), PresentationKind.CONTROL, "", 0, "a" * 64)
    with pytest.raises(PresentationValidationError):
        UiStateReference(uuid4(), PresentationKind.CONTROL, "", 1, "bad")
    with pytest.raises(PresentationValidationError):
        UiStateReference(
            uuid4(),
            PresentationKind.CONTROL,
            "",
            1,
            "a" * 64,
            cast(ArtifactReference, "bad"),
        )
    with pytest.raises(PresentationValidationError):
        UiStateReference(
            uuid4(),
            PresentationKind.CONTROL,
            "",
            1,
            "a" * 64,
            package_asset=PackageAssetReference("native.theme", "idle", "1.0.0", "a" * 64),
            artifact=artifact,
        )
