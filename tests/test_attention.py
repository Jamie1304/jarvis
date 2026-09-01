from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from jarvis.attention import (
    AttentionDecision,
    AttentionDeliveryState,
    AttentionError,
    AttentionItem,
    AttentionPolicy,
    AttentionPolicyState,
    AttentionPriority,
    AttentionQueueEntry,
    DigestBucket,
    InMemoryAttentionStore,
    SQLiteAttentionStore,
)

NOW = datetime(2026, 1, 5, 23, 30, tzinfo=UTC)


def item(
    priority: AttentionPriority,
    *,
    item_type: str = "activity",
    key: str | None = None,
    created_at: datetime = NOW,
    expires_at: datetime | None = None,
    requires_user_action: bool = False,
    opportunity_id: UUID | None = None,
    cooldown_until: datetime | None = None,
) -> AttentionItem:
    return AttentionItem(
        uuid4(),
        item_type,
        "workspace",
        priority,
        created_at,
        expires_at,
        requires_user_action,
        related_opportunity_id=opportunity_id,
        dedupe_key=key or f"{item_type}:{uuid4()}",
        cooldown_until=cooldown_until,
        summary="Synthetic attention item",
    )


def policy(clock: list[datetime] | None = None) -> AttentionPolicy:
    return AttentionPolicy(
        InMemoryAttentionStore(),
        clock=lambda: (clock or [NOW])[0],
    )


def test_restart_preserves_unresolved_important_attention(tmp_path: Path) -> None:
    path = tmp_path / "attention.sqlite3"
    store = SQLiteAttentionStore(path)
    active = AttentionPolicy(store, clock=lambda: NOW)
    notice = item(AttentionPriority.HIGH, key="important:restart")
    entry = active.enqueue(notice)
    store.close()

    restored_store = SQLiteAttentionStore(path)
    restored = AttentionPolicy(restored_store, clock=lambda: NOW)

    assert restored.pending()[0].item_id == notice.item_id
    assert restored_store.get_entry(notice.item_id) == entry
    restored_store.close()


def test_quiet_hours_defer_low_and_normal_but_not_high() -> None:
    clock = [NOW]
    current = policy(clock)
    current.configure(quiet_hours=(22 * 60, 7 * 60))

    low = item(AttentionPriority.LOW, key="quiet:low")
    normal = item(AttentionPriority.NORMAL, key="quiet:normal")
    high = item(AttentionPriority.HIGH, key="quiet:high")

    assert current.enqueue(low).decision is AttentionDecision.DEFER
    assert current.enqueue(normal).decision is AttentionDecision.DEFER
    assert current.enqueue(high).decision is AttentionDecision.DELIVER_NOW
    assert current.pending()[0].item_id == high.item_id


def test_background_and_low_priority_items_use_digest() -> None:
    current = policy()

    background_entry = current.enqueue(item(AttentionPriority.BACKGROUND, key="digest:background"))
    low_entry = current.enqueue(item(AttentionPriority.LOW, key="digest:low"))

    assert background_entry.decision is AttentionDecision.BUNDLE_IN_DIGEST
    assert low_entry.decision is AttentionDecision.BUNDLE_IN_DIGEST
    assert background_entry.digest_id is not None
    assert low_entry.digest_id is not None
    assert background_entry.digest_id == low_entry.digest_id
    digest = current.digest(background_entry.digest_id)
    assert len(digest.item_ids) == 2


def test_urgent_is_delivered_immediately() -> None:
    current = policy()

    entry = current.enqueue(item(AttentionPriority.URGENT, key="urgent"))

    assert entry.decision is AttentionDecision.DELIVER_NOW
    assert current.pending()[0].priority is AttentionPriority.URGENT


def test_expiring_authority_request_remains_visible_during_quiet_hours() -> None:
    current = policy()
    current.configure(quiet_hours=(22 * 60, 7 * 60))
    permission_id = uuid4()
    request = AttentionItem(
        uuid4(),
        "permission.request",
        "workspace",
        AttentionPriority.NORMAL,
        NOW,
        NOW + timedelta(minutes=30),
        True,
        related_permission_id=permission_id,
        dedupe_key="permission:expiring",
        summary="Owner approval is required",
    )

    entry = current.enqueue(request)

    assert entry.decision is AttentionDecision.DELIVER_NOW
    assert request.item_id in {item.item_id for item in current.pending()}


def test_security_critical_cannot_be_silently_suppressed_or_deferred() -> None:
    current = policy()
    current.configure(quiet_hours=(0, 1))
    current.set_user_preference(suppress_background=True)
    security = item(AttentionPriority.SECURITY_CRITICAL, key="security:critical")

    assert current.enqueue(security).decision is AttentionDecision.DELIVER_NOW
    with pytest.raises(AttentionError):
        current.defer(security.item_id, NOW + timedelta(hours=1))


def test_duplicate_informational_items_collapse_but_urgent_items_do_not() -> None:
    current = policy()
    first = item(AttentionPriority.NORMAL, key="same:info")
    duplicate = item(AttentionPriority.NORMAL, key="same:info")
    urgent = item(AttentionPriority.URGENT, key="same:urgent")
    urgent_duplicate = item(AttentionPriority.URGENT, key="same:urgent")

    assert current.enqueue(first).decision is AttentionDecision.DELIVER_NOW
    assert current.enqueue(duplicate).decision is AttentionDecision.SUPPRESS_DUPLICATE
    assert current.enqueue(urgent).decision is AttentionDecision.DELIVER_NOW
    assert current.enqueue(urgent_duplicate).decision is AttentionDecision.DELIVER_NOW


def test_declined_opportunity_cooldown_defers_notice_until_new_evidence() -> None:
    clock = [NOW]
    current = policy(clock)
    opportunity_id = uuid4()
    notice = item(
        AttentionPriority.NORMAL,
        item_type="capability.opportunity",
        key="opportunity:one",
        opportunity_id=opportunity_id,
        cooldown_until=NOW + timedelta(days=2),
    )

    assert current.enqueue(notice).decision is AttentionDecision.DEFER
    assert notice.item_id in {item.item_id for item in current.pending()}
    clock[0] += timedelta(days=3)

    assert current.pending()[0].item_id == notice.item_id
    assert current._store.get_entry(notice.item_id).decision is AttentionDecision.DELIVER_NOW  # type: ignore[union-attr]


def test_resolved_item_is_removed_from_pending_and_survives_restart(tmp_path: Path) -> None:
    path = tmp_path / "attention.sqlite3"
    store = SQLiteAttentionStore(path)
    current = AttentionPolicy(store, clock=lambda: NOW)
    notice = item(AttentionPriority.HIGH, key="resolved")
    current.enqueue(notice)
    resolved = current.resolve(notice.item_id)
    assert resolved.delivery_state is AttentionDeliveryState.RESOLVED
    assert current.pending() == ()
    store.close()

    restored_store = SQLiteAttentionStore(path)
    restored = AttentionPolicy(restored_store, clock=lambda: NOW)
    assert restored.pending() == ()
    restored_store.close()


def test_user_preference_can_silence_background_only() -> None:
    current = policy()
    current.set_user_preference(suppress_background=True)

    background = item(AttentionPriority.BACKGROUND, key="preference:background")
    security = item(AttentionPriority.SECURITY_CRITICAL, key="preference:security")

    assert current.enqueue(background).decision is AttentionDecision.SILENT_ACTIVITY
    assert current.enqueue(security).decision is AttentionDecision.DELIVER_NOW


def test_malformed_persisted_policy_state_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "attention.sqlite3"
    store = SQLiteAttentionStore(path)
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE attention_state SET payload_json=? WHERE state_id=1",
            (
                json.dumps(
                    {
                        "quiet_hours_start_minute": None,
                        "quiet_hours_end_minute": None,
                        "digest_window_seconds": 3600,
                        "expiring_authority_window_seconds": 900,
                        "user_preference_suppress_background": "yes",
                        "updated_at": NOW.isoformat(),
                    }
                ),
            ),
        )
    malformed = SQLiteAttentionStore(path)
    with pytest.raises(AttentionError):
        AttentionPolicy(malformed, clock=lambda: NOW)
    malformed.close()


def test_attention_models_reject_malformed_security_metadata() -> None:
    valid = item(AttentionPriority.NORMAL, key="validation")
    invalid_items: tuple[Callable[[], object], ...] = (
        lambda: replace(valid, item_id="not-a-uuid"),  # type: ignore[arg-type]
        lambda: replace(valid, item_type=""),
        lambda: replace(valid, workspace=""),
        lambda: replace(valid, priority="normal"),  # type: ignore[arg-type]
        lambda: replace(valid, created_at=datetime(2026, 1, 5)),
        lambda: replace(valid, expires_at=NOW - timedelta(seconds=1)),
        lambda: replace(valid, requires_user_action="yes"),  # type: ignore[arg-type]
        lambda: replace(valid, related_goal_id="not-a-uuid"),  # type: ignore[arg-type]
        lambda: replace(valid, dedupe_key=""),
        lambda: replace(valid, delivery_state="queued"),  # type: ignore[arg-type]
        lambda: replace(valid, summary="token=raw"),
        lambda: replace(valid, resolved=True),
        lambda: replace(valid, resolved_at=NOW),
        lambda: replace(valid, resolved=True, delivery_state=AttentionDeliveryState.QUEUED),
    )
    for factory in invalid_items:
        with pytest.raises(AttentionError):
            factory()


def test_attention_queue_digest_and_policy_models_fail_closed() -> None:
    with pytest.raises(AttentionError):
        AttentionQueueEntry("bad", uuid4(), AttentionDecision.DEFER, NOW)  # type: ignore[arg-type]
    with pytest.raises(AttentionError):
        AttentionQueueEntry(uuid4(), uuid4(), "defer", NOW)  # type: ignore[arg-type]
    with pytest.raises(AttentionError):
        DigestBucket(uuid4(), "workspace", NOW, NOW)
    with pytest.raises(AttentionError):
        duplicate = uuid4()
        DigestBucket(
            uuid4(),
            "workspace",
            NOW,
            NOW + timedelta(hours=1),
            (duplicate, duplicate),
        )
    with pytest.raises(AttentionError):
        AttentionPolicyState(quiet_hours_start_minute=10)
    with pytest.raises(AttentionError):
        AttentionPolicyState(digest_window_seconds=59)
    with pytest.raises(AttentionError):
        AttentionPolicyState(expiring_authority_window_seconds=-1)


def test_attention_policy_rejects_invalid_configuration_and_missing_entries() -> None:
    current = policy()
    with pytest.raises(AttentionError):
        current.configure(quiet_hours=(1,))  # type: ignore[arg-type]
    with pytest.raises(AttentionError):
        current.configure(quiet_hours=(1, 1_440))
    with pytest.raises(AttentionError):
        current.configure(digest_window_seconds=59)
    with pytest.raises(AttentionError):
        current.set_user_preference(suppress_background="yes")  # type: ignore[arg-type]
    with pytest.raises(AttentionError):
        current.resolve(uuid4())
    with pytest.raises(AttentionError):
        current.defer(uuid4(), NOW)
    with pytest.raises(AttentionError):
        current.digest(uuid4())


def test_attention_expiry_and_authority_boundaries() -> None:
    clock = [NOW + timedelta(days=1)]
    current = policy(clock)
    expired = item(
        AttentionPriority.NORMAL,
        key="expired",
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    entry = current.enqueue(expired)
    assert entry.decision is AttentionDecision.SILENT_ACTIVITY
    assert current.pending() == ()

    authority = item(
        AttentionPriority.NORMAL,
        key="authority-expired",
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        requires_user_action=True,
    )
    assert current.enqueue(authority).decision is AttentionDecision.DELIVER_NOW
    with pytest.raises(AttentionError):
        current.defer(authority.item_id, clock[0] + timedelta(days=1))


def test_attention_sqlite_store_rejects_invalid_foreign_digest_binding(tmp_path: Path) -> None:
    store = SQLiteAttentionStore(tmp_path / "attention.sqlite3")
    notice = item(AttentionPriority.LOW, key="binding")
    entry = AttentionQueueEntry(uuid4(), notice.item_id, AttentionDecision.DEFER, NOW)
    digest = DigestBucket(uuid4(), notice.workspace, NOW, NOW + timedelta(hours=1))
    with pytest.raises(AttentionError):
        store.save_evaluation(notice, entry, digest)
    store.close()


def test_attention_sqlite_round_trip_digest_and_policy_state(tmp_path: Path) -> None:
    path = tmp_path / "attention.sqlite3"
    store = SQLiteAttentionStore(path)
    current = AttentionPolicy(store, clock=lambda: NOW)
    configured = current.configure(
        quiet_hours=(23 * 60, 7 * 60),
        digest_window_seconds=600,
        expiring_authority_window_seconds=1_800,
    )
    assert configured.quiet_hours_start_minute == 1_380
    notice = item(AttentionPriority.BACKGROUND, key="round-trip")
    entry = current.enqueue(notice)
    digest = current.digest(entry.digest_id)  # type: ignore[arg-type]
    stored_notice = replace(notice, delivery_state=AttentionDeliveryState.BUNDLED)
    assert store.get_item(notice.item_id) == stored_notice
    assert store.list_items() == (stored_notice,)
    assert store.get_entry(notice.item_id) == entry
    assert store.get_digest(digest.digest_id) == digest
    store.close()
    store.close()

    restarted = SQLiteAttentionStore(path)
    assert restarted.load_state() == configured
    restarted.close()


def test_attention_security_boundaries_and_overnight_quiet_hours() -> None:
    clock = [datetime(2026, 1, 5, 23, 45, tzinfo=UTC)]
    current = policy(clock)
    current.configure(quiet_hours=(23 * 60, 7 * 60))
    low = item(AttentionPriority.LOW, key="overnight")
    deferred = current.enqueue(low)
    assert deferred.decision is AttentionDecision.DEFER
    assert current._store.get_entry(low.item_id).next_evaluation_at.hour == 7  # type: ignore[union-attr]

    critical = item(AttentionPriority.SECURITY_CRITICAL, key="critical")
    current.enqueue(critical)
    with pytest.raises(AttentionError):
        current.defer(critical.item_id, clock[0] + timedelta(hours=1))

    equal = item(AttentionPriority.NORMAL, key="equal")
    clock[0] = datetime(2026, 1, 5, 12, tzinfo=UTC)
    current.configure(quiet_hours=(12 * 60, 12 * 60))
    assert current.enqueue(equal).decision is AttentionDecision.DELIVER_NOW


def test_attention_persisted_payloads_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "attention.sqlite3"
    store = SQLiteAttentionStore(path)
    notice = item(AttentionPriority.NORMAL, key="payload")
    current = AttentionPolicy(store, clock=lambda: NOW)
    entry = current.enqueue(notice)
    store.close()

    cases = (
        ("attention_items", "payload_json", {"item_id": "bad"}),
        ("attention_queue", "payload_json", {"entry_id": "bad"}),
    )
    for table, column, payload in cases:
        with sqlite3.connect(path) as connection:
            connection.execute(f"UPDATE {table} SET {column}=?", (json.dumps(payload),))
        reopened = SQLiteAttentionStore(path)
        with pytest.raises((AttentionError, ValueError, KeyError)):
            (
                reopened.get_item(notice.item_id)
                if table == "attention_items"
                else reopened.get_entry(notice.item_id)
            )
        reopened.close()
        # Restore a valid queue/item row for the next malformed payload case.
        restored = SQLiteAttentionStore(path)
        restored.save_evaluation(notice, entry)
        restored.close()

    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT OR REPLACE INTO attention_digests(digest_id, payload_json) VALUES (?, ?)",
            (str(uuid4()), json.dumps({"item_ids": "not-a-list"})),
        )
        digest_id = connection.execute(
            "SELECT digest_id FROM attention_digests ORDER BY rowid DESC LIMIT 1"
        ).fetchone()[0]
    reopened = SQLiteAttentionStore(path)
    with pytest.raises(AttentionError):
        reopened.get_digest(UUID(digest_id))
    reopened.close()
