"""Durable attention decisions, separate from delivery and permission policy.

Attention is an application decision about when a fact should be shown.  It
does not authorize an action, authenticate an owner, or deliver a message by
itself.  Notification transports consume queue projections after this policy
has made a bounded decision.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5


class AttentionError(RuntimeError):
    """An attention record, policy, or store is invalid."""


class AttentionPriority(StrEnum):
    BACKGROUND = "background"
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"
    SECURITY_CRITICAL = "security_critical"


class AttentionDecision(StrEnum):
    DELIVER_NOW = "deliver_now"
    DEFER = "defer"
    BUNDLE_IN_DIGEST = "bundle_in_digest"
    SILENT_ACTIVITY = "silent_activity"
    SUPPRESS_DUPLICATE = "suppress_duplicate"


class AttentionDeliveryState(StrEnum):
    QUEUED = "queued"
    DELIVERED = "delivered"
    DEFERRED = "deferred"
    BUNDLED = "bundled"
    SILENT = "silent"
    SUPPRESSED_DUPLICATE = "suppressed_duplicate"
    EXPIRED = "expired"
    RESOLVED = "resolved"


_MAX_TEXT = 2_000
_MAX_ITEMS = 512
_UTC_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _text(value: object, field: str, limit: int = _MAX_TEXT) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > limit
        or "\x00" in value
        or any(not character.isprintable() for character in value)
    ):
        raise AttentionError(f"{field} is malformed")
    return value.strip()


def _secret_free(values: Iterable[str]) -> None:
    markers = ("password=", "secret=", "token=", "private_key=", "credential_value=")
    if any(marker in value.casefold() for value in values for marker in markers):
        raise AttentionError("Raw credential material is not attention metadata")


def _timestamp(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AttentionError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _uuid(value: UUID | None, field: str) -> None:
    if value is not None and not isinstance(value, UUID):
        raise AttentionError(f"{field} is malformed")


@dataclass(frozen=True, slots=True)
class AttentionItem:
    item_id: UUID
    item_type: str
    workspace: str
    priority: AttentionPriority
    created_at: datetime
    expires_at: datetime | None = None
    requires_user_action: bool = False
    related_goal_id: UUID | None = None
    related_permission_id: UUID | None = None
    related_opportunity_id: UUID | None = None
    dedupe_key: str = ""
    delivery_state: AttentionDeliveryState = AttentionDeliveryState.QUEUED
    defer_until: datetime | None = None
    cooldown_until: datetime | None = None
    resolved: bool = False
    resolved_at: datetime | None = None
    summary: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.item_id, UUID):
            raise AttentionError("Attention item ID is malformed")
        _text(self.item_type, "Attention item type", 256)
        _text(self.workspace, "Attention workspace", 256)
        if not isinstance(self.priority, AttentionPriority):
            raise AttentionError("Attention priority is malformed")
        created = _timestamp(self.created_at, "Attention creation time")
        for value, field in (
            (self.expires_at, "Attention expiry"),
            (self.defer_until, "Attention defer time"),
            (self.cooldown_until, "Attention cooldown"),
            (self.resolved_at, "Attention resolution time"),
        ):
            if value is not None:
                _timestamp(value, field)
        if self.expires_at is not None and self.expires_at < created:
            raise AttentionError("Attention expiry precedes creation")
        if type(self.requires_user_action) is not bool or type(self.resolved) is not bool:
            raise AttentionError("Attention flags are malformed")
        _uuid(self.related_goal_id, "Attention goal reference")
        _uuid(self.related_permission_id, "Attention permission reference")
        _uuid(self.related_opportunity_id, "Attention opportunity reference")
        _text(self.dedupe_key, "Attention dedupe key", 512)
        if not isinstance(self.delivery_state, AttentionDeliveryState):
            raise AttentionError("Attention delivery state is malformed")
        _text(self.summary, "Attention summary")
        if self.resolved and self.resolved_at is None:
            raise AttentionError("Resolved attention requires a resolution time")
        if not self.resolved and self.resolved_at is not None:
            raise AttentionError("Unresolved attention cannot have a resolution time")
        if self.resolved and self.delivery_state not in {
            AttentionDeliveryState.RESOLVED,
            AttentionDeliveryState.SUPPRESSED_DUPLICATE,
            AttentionDeliveryState.EXPIRED,
        }:
            raise AttentionError("Resolved attention has an active delivery state")
        _secret_free(
            (
                self.item_type,
                self.workspace,
                self.dedupe_key,
                self.summary,
            )
        )


@dataclass(frozen=True, slots=True)
class AttentionQueueEntry:
    entry_id: UUID
    item_id: UUID
    decision: AttentionDecision
    queued_at: datetime
    next_evaluation_at: datetime | None = None
    delivered_at: datetime | None = None
    digest_id: UUID | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.entry_id, UUID) or not isinstance(self.item_id, UUID):
            raise AttentionError("Attention queue identity is malformed")
        if not isinstance(self.decision, AttentionDecision):
            raise AttentionError("Attention queue decision is malformed")
        _timestamp(self.queued_at, "Attention queue time")
        for value, field in (
            (self.next_evaluation_at, "Attention next evaluation"),
            (self.delivered_at, "Attention delivery time"),
        ):
            if value is not None:
                _timestamp(value, field)
        _uuid(self.digest_id, "Attention digest reference")


@dataclass(frozen=True, slots=True)
class DigestBucket:
    digest_id: UUID
    workspace: str
    period_start: datetime
    period_end: datetime
    item_ids: tuple[UUID, ...] = ()
    created_at: datetime = _UTC_EPOCH
    delivered: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.digest_id, UUID):
            raise AttentionError("Digest ID is malformed")
        _text(self.workspace, "Digest workspace", 256)
        start = _timestamp(self.period_start, "Digest start")
        end = _timestamp(self.period_end, "Digest end")
        if end <= start:
            raise AttentionError("Digest period is malformed")
        _timestamp(self.created_at, "Digest creation time")
        if type(self.item_ids) is not tuple or len(self.item_ids) > _MAX_ITEMS:
            raise AttentionError("Digest items are malformed")
        if any(not isinstance(item, UUID) for item in self.item_ids):
            raise AttentionError("Digest item IDs are malformed")
        if len(set(self.item_ids)) != len(self.item_ids):
            raise AttentionError("Digest item IDs must be unique")
        if type(self.delivered) is not bool:
            raise AttentionError("Digest delivery state is malformed")


@dataclass(frozen=True, slots=True)
class AttentionPolicyState:
    quiet_hours_start_minute: int | None = None
    quiet_hours_end_minute: int | None = None
    digest_window_seconds: int = 3_600
    expiring_authority_window_seconds: int = 900
    user_preference_suppress_background: bool = False
    updated_at: datetime = _UTC_EPOCH

    def __post_init__(self) -> None:
        for value, field in (
            (self.quiet_hours_start_minute, "Quiet-hours start"),
            (self.quiet_hours_end_minute, "Quiet-hours end"),
        ):
            if value is not None and (type(value) is not int or not 0 <= value < 1_440):
                raise AttentionError(f"{field} is malformed")
        if (self.quiet_hours_start_minute is None) != (self.quiet_hours_end_minute is None):
            raise AttentionError("Quiet-hours bounds must be configured together")
        if (
            type(self.digest_window_seconds) is not int
            or not 60 <= self.digest_window_seconds <= 86_400
        ):
            raise AttentionError("Digest window is malformed")
        if (
            type(self.expiring_authority_window_seconds) is not int
            or not 0 <= self.expiring_authority_window_seconds <= 86_400
        ):
            raise AttentionError("Expiring authority window is malformed")
        if type(self.user_preference_suppress_background) is not bool:
            raise AttentionError("Attention preference is malformed")
        _timestamp(self.updated_at, "Attention policy update time")


class AttentionStore(Protocol):
    def get_item(self, item_id: UUID) -> AttentionItem | None: ...

    def list_items(self) -> tuple[AttentionItem, ...]: ...

    def find_unresolved_dedupe(self, workspace: str, dedupe_key: str) -> AttentionItem | None: ...

    def get_entry(self, item_id: UUID) -> AttentionQueueEntry | None: ...

    def save_state(self, state: AttentionPolicyState) -> None: ...

    def load_state(self) -> AttentionPolicyState: ...

    def save_evaluation(
        self,
        item: AttentionItem,
        entry: AttentionQueueEntry,
        digest: DigestBucket | None = None,
    ) -> None: ...

    def get_digest(self, digest_id: UUID) -> DigestBucket | None: ...

    def close(self) -> None: ...


class SQLiteAttentionStore:
    """Authoritative durable owner for attention items and policy decisions."""

    _SCHEMA_VERSION = 1

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self._path, timeout=5.0, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()
        self._closed = False
        self._migrate()

    def _migrate(self) -> None:
        with self._connection:
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS attention_schema "
                "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
            )
            versions = {
                int(row[0]): str(row[1])
                for row in self._connection.execute("SELECT version, name FROM attention_schema")
            }
            if any(version > self._SCHEMA_VERSION for version in versions):
                raise AttentionError("Attention database uses a future schema")
            if not versions:
                self._connection.execute(
                    "CREATE TABLE attention_state (state_id INTEGER PRIMARY KEY CHECK(state_id=1), "
                    "payload_json TEXT NOT NULL)"
                )
                self._connection.execute(
                    "CREATE TABLE attention_items (item_id TEXT PRIMARY KEY, "
                    "workspace TEXT NOT NULL, dedupe_key TEXT NOT NULL, "
                    "resolved INTEGER NOT NULL, payload_json TEXT NOT NULL)"
                )
                self._connection.execute(
                    "CREATE TABLE attention_queue (entry_id TEXT PRIMARY KEY, "
                    "item_id TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, "
                    "FOREIGN KEY(item_id) REFERENCES attention_items(item_id) "
                    "ON DELETE CASCADE)"
                )
                self._connection.execute(
                    "CREATE TABLE attention_digests (digest_id TEXT PRIMARY KEY, "
                    "payload_json TEXT NOT NULL)"
                )
                self._connection.execute(
                    "INSERT INTO attention_schema(version, name) VALUES (1, 'create_attention')"
                )
                self._connection.execute(
                    "INSERT INTO attention_state(state_id, payload_json) VALUES (1, ?)",
                    (json.dumps(_state_to_json(AttentionPolicyState()), sort_keys=True),),
                )
            elif versions.get(1) != "create_attention":
                raise AttentionError("Attention migration identity mismatch")

    def get_item(self, item_id: UUID) -> AttentionItem | None:
        if not isinstance(item_id, UUID):
            raise AttentionError("Attention item ID is malformed")
        with self._lock:
            row = self._connection.execute(
                "SELECT payload_json FROM attention_items WHERE item_id=?", (str(item_id),)
            ).fetchone()
        return _item_from_json(json.loads(str(row[0]))) if row else None

    def list_items(self) -> tuple[AttentionItem, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT payload_json FROM attention_items "
                "ORDER BY json_extract(payload_json, '$.created_at')"
            ).fetchall()
        return tuple(_item_from_json(json.loads(str(row[0]))) for row in rows)

    def find_unresolved_dedupe(self, workspace: str, dedupe_key: str) -> AttentionItem | None:
        _text(workspace, "Attention workspace", 256)
        _text(dedupe_key, "Attention dedupe key", 512)
        with self._lock:
            row = self._connection.execute(
                "SELECT payload_json FROM attention_items WHERE workspace=? AND dedupe_key=? "
                "AND resolved=0 ORDER BY json_extract(payload_json, '$.created_at') DESC LIMIT 1",
                (workspace, dedupe_key),
            ).fetchone()
        return _item_from_json(json.loads(str(row[0]))) if row else None

    def get_entry(self, item_id: UUID) -> AttentionQueueEntry | None:
        if not isinstance(item_id, UUID):
            raise AttentionError("Attention item ID is malformed")
        with self._lock:
            row = self._connection.execute(
                "SELECT payload_json FROM attention_queue WHERE item_id=?", (str(item_id),)
            ).fetchone()
        return _entry_from_json(json.loads(str(row[0]))) if row else None

    def save_state(self, state: AttentionPolicyState) -> None:
        _validate_state(state)
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO attention_state(state_id, payload_json) VALUES (1, ?) "
                "ON CONFLICT(state_id) DO UPDATE SET payload_json=excluded.payload_json",
                (json.dumps(_state_to_json(state), sort_keys=True),),
            )

    def load_state(self) -> AttentionPolicyState:
        with self._lock:
            row = self._connection.execute(
                "SELECT payload_json FROM attention_state WHERE state_id=1"
            ).fetchone()
        if row is None:
            raise AttentionError("Attention policy state is missing")
        return _state_from_json(json.loads(str(row[0])))

    def save_evaluation(
        self,
        item: AttentionItem,
        entry: AttentionQueueEntry,
        digest: DigestBucket | None = None,
    ) -> None:
        _validate_item(item)
        if entry.item_id != item.item_id:
            raise AttentionError("Attention queue item mismatch")
        _validate_entry(entry)
        if digest is not None:
            _validate_digest(digest)
            if entry.digest_id != digest.digest_id or item.item_id not in digest.item_ids:
                raise AttentionError("Attention digest binding is malformed")
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO attention_items(item_id, workspace, dedupe_key, "
                "resolved, payload_json) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(item_id) DO UPDATE SET "
                "workspace=excluded.workspace, dedupe_key=excluded.dedupe_key, "
                "resolved=excluded.resolved, payload_json=excluded.payload_json",
                (
                    str(item.item_id),
                    item.workspace,
                    item.dedupe_key,
                    int(item.resolved),
                    json.dumps(_item_to_json(item), sort_keys=True),
                ),
            )
            self._connection.execute(
                "INSERT INTO attention_queue(entry_id, item_id, payload_json) VALUES (?, ?, ?) "
                "ON CONFLICT(item_id) DO UPDATE SET entry_id=excluded.entry_id, "
                "payload_json=excluded.payload_json",
                (
                    str(entry.entry_id),
                    str(entry.item_id),
                    json.dumps(_entry_to_json(entry), sort_keys=True),
                ),
            )
            if digest is not None:
                self._connection.execute(
                    "INSERT INTO attention_digests(digest_id, payload_json) VALUES (?, ?) "
                    "ON CONFLICT(digest_id) DO UPDATE SET payload_json=excluded.payload_json",
                    (str(digest.digest_id), json.dumps(_digest_to_json(digest), sort_keys=True)),
                )

    def get_digest(self, digest_id: UUID) -> DigestBucket | None:
        if not isinstance(digest_id, UUID):
            raise AttentionError("Digest ID is malformed")
        with self._lock:
            row = self._connection.execute(
                "SELECT payload_json FROM attention_digests WHERE digest_id=?", (str(digest_id),)
            ).fetchone()
        return _digest_from_json(json.loads(str(row[0]))) if row else None

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True


class InMemoryAttentionStore:
    """Deterministic store used by unit tests; production uses SQLiteAttentionStore."""

    def __init__(self) -> None:
        self._items: dict[UUID, AttentionItem] = {}
        self._entries: dict[UUID, AttentionQueueEntry] = {}
        self._digests: dict[UUID, DigestBucket] = {}
        self._state = AttentionPolicyState()

    def get_item(self, item_id: UUID) -> AttentionItem | None:
        return self._items.get(item_id)

    def list_items(self) -> tuple[AttentionItem, ...]:
        return tuple(self._items.values())

    def find_unresolved_dedupe(self, workspace: str, dedupe_key: str) -> AttentionItem | None:
        candidates = (
            item
            for item in self._items.values()
            if item.workspace == workspace and item.dedupe_key == dedupe_key and not item.resolved
        )
        return next(iter(candidates), None)

    def get_entry(self, item_id: UUID) -> AttentionQueueEntry | None:
        return self._entries.get(item_id)

    def save_state(self, state: AttentionPolicyState) -> None:
        _validate_state(state)
        self._state = state

    def load_state(self) -> AttentionPolicyState:
        return self._state

    def save_evaluation(
        self, item: AttentionItem, entry: AttentionQueueEntry, digest: DigestBucket | None = None
    ) -> None:
        _validate_item(item)
        _validate_entry(entry)
        if digest is not None:
            _validate_digest(digest)
        self._items[item.item_id] = item
        self._entries[item.item_id] = entry
        if digest is not None:
            self._digests[digest.digest_id] = digest

    def get_digest(self, digest_id: UUID) -> DigestBucket | None:
        return self._digests.get(digest_id)

    def close(self) -> None:
        return None


class AttentionPolicy:
    """Durable priority/expiry/defer decision owner, not a transport."""

    def __init__(
        self, store: AttentionStore, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        if not hasattr(store, "save_evaluation"):
            raise AttentionError("Attention store is malformed")
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._state = store.load_state()

    @property
    def state(self) -> AttentionPolicyState:
        return self._state

    def configure(
        self,
        *,
        quiet_hours: tuple[int, int] | None = None,
        digest_window_seconds: int | None = None,
        expiring_authority_window_seconds: int | None = None,
    ) -> AttentionPolicyState:
        start = end = None
        if quiet_hours is not None:
            if type(quiet_hours) is not tuple or len(quiet_hours) != 2:
                raise AttentionError("Quiet-hours configuration is malformed")
            start, end = quiet_hours
        updated = replace(
            self._state,
            quiet_hours_start_minute=start,
            quiet_hours_end_minute=end,
            digest_window_seconds=(
                self._state.digest_window_seconds
                if digest_window_seconds is None
                else digest_window_seconds
            ),
            expiring_authority_window_seconds=(
                self._state.expiring_authority_window_seconds
                if expiring_authority_window_seconds is None
                else expiring_authority_window_seconds
            ),
            updated_at=self._now(),
        )
        _validate_state(updated)
        self._store.save_state(updated)
        self._state = updated
        return updated

    def set_user_preference(self, *, suppress_background: bool) -> AttentionPolicyState:
        """Apply only a non-security preference from UserModel/application policy."""

        if type(suppress_background) is not bool:
            raise AttentionError("Attention preference is malformed")
        updated = replace(
            self._state,
            user_preference_suppress_background=suppress_background,
            updated_at=self._now(),
        )
        self._store.save_state(updated)
        self._state = updated
        return updated

    def enqueue(self, item: AttentionItem) -> AttentionQueueEntry:
        _validate_item(item)
        if item.resolved:
            raise AttentionError("Resolved attention cannot be enqueued")
        now = self._now()
        duplicate = self._store.find_unresolved_dedupe(item.workspace, item.dedupe_key)
        if (
            duplicate is not None
            and duplicate.item_id != item.item_id
            and item.priority not in {AttentionPriority.URGENT, AttentionPriority.SECURITY_CRITICAL}
            and not item.requires_user_action
        ):
            suppressed = replace(
                item,
                delivery_state=AttentionDeliveryState.SUPPRESSED_DUPLICATE,
                resolved=True,
                resolved_at=now,
            )
            entry = AttentionQueueEntry(
                uuid4(), item.item_id, AttentionDecision.SUPPRESS_DUPLICATE, now
            )
            self._store.save_evaluation(suppressed, entry)
            return entry
        return self._evaluate_and_save(item, now)

    def resolve(self, item_id: UUID) -> AttentionItem:
        item = self._require(item_id)
        if item.resolved:
            return item
        resolved = replace(
            item,
            delivery_state=AttentionDeliveryState.RESOLVED,
            resolved=True,
            resolved_at=self._now(),
        )
        entry = self._entry(item_id)
        if entry is None:
            raise AttentionError("Attention queue entry is missing")
        self._store.save_evaluation(
            resolved,
            replace(entry, decision=AttentionDecision.SILENT_ACTIVITY),
        )
        return resolved

    def defer(self, item_id: UUID, until: datetime) -> AttentionItem:
        item = self._require(item_id)
        until = _timestamp(until, "Attention defer time")
        if item.priority is AttentionPriority.SECURITY_CRITICAL:
            raise AttentionError("Security-critical attention cannot be deferred")
        if item.expires_at is not None and until >= item.expires_at and item.requires_user_action:
            raise AttentionError("Authority attention cannot be deferred past expiry")
        deferred = replace(
            item,
            delivery_state=AttentionDeliveryState.DEFERRED,
            defer_until=until,
            resolved=False,
            resolved_at=None,
        )
        entry = self._entry(item_id)
        if entry is None:
            raise AttentionError("Attention queue entry is missing")
        self._store.save_evaluation(
            deferred,
            replace(entry, decision=AttentionDecision.DEFER, next_evaluation_at=until),
        )
        return deferred

    def pending(self) -> tuple[AttentionItem, ...]:
        self.reconcile()
        priority = {
            AttentionPriority.SECURITY_CRITICAL: 5,
            AttentionPriority.URGENT: 4,
            AttentionPriority.HIGH: 3,
            AttentionPriority.NORMAL: 2,
            AttentionPriority.LOW: 1,
            AttentionPriority.BACKGROUND: 0,
        }
        return tuple(
            sorted(
                (item for item in self._store.list_items() if not item.resolved),
                key=lambda item: (
                    -priority[item.priority],
                    item.expires_at or datetime.max.replace(tzinfo=UTC),
                    item.created_at,
                ),
            )
        )

    def digest(self, digest_id: UUID) -> DigestBucket:
        digest = self._store.get_digest(digest_id)
        if digest is None:
            raise AttentionError("Unknown attention digest")
        return digest

    def reconcile(self) -> None:
        now = self._now()
        for item in self._store.list_items():
            if item.resolved:
                continue
            entry = self._entry(item.item_id)
            if entry is None:
                raise AttentionError("Unresolved attention has no queue entry")
            expiring = item.requires_user_action and item.expires_at is not None
            due = entry.next_evaluation_at is None or entry.next_evaluation_at <= now
            near_expiry = item.expires_at is not None and item.expires_at <= now + timedelta(
                seconds=self._state.expiring_authority_window_seconds
            )
            if due or (expiring and near_expiry):
                self._evaluate_and_save(item, now)

    def _evaluate_and_save(self, item: AttentionItem, now: datetime) -> AttentionQueueEntry:
        decision, state, defer_until, resolved = self._decide(item, now)
        digest: DigestBucket | None = None
        digest_id: UUID | None = None
        if decision is AttentionDecision.BUNDLE_IN_DIGEST:
            digest = self._digest_for(item.workspace, now)
            digest_id = digest.digest_id
            if item.item_id not in digest.item_ids:
                digest = replace(digest, item_ids=(*digest.item_ids, item.item_id))
        updated = replace(
            item,
            delivery_state=state,
            defer_until=defer_until,
            resolved=resolved,
            resolved_at=now if resolved else None,
        )
        prior_entry = self._entry(item.item_id)
        entry = AttentionQueueEntry(
            prior_entry.entry_id if prior_entry is not None else uuid4(),
            item.item_id,
            decision,
            prior_entry.queued_at if prior_entry is not None else now,
            defer_until,
            now if decision is AttentionDecision.DELIVER_NOW else None,
            digest_id,
        )
        self._store.save_evaluation(updated, entry, digest)
        return entry

    def _decide(
        self, item: AttentionItem, now: datetime
    ) -> tuple[AttentionDecision, AttentionDeliveryState, datetime | None, bool]:
        if item.expires_at is not None and item.expires_at <= now:
            if item.requires_user_action or item.priority is AttentionPriority.SECURITY_CRITICAL:
                return AttentionDecision.DELIVER_NOW, AttentionDeliveryState.QUEUED, None, False
            return AttentionDecision.SILENT_ACTIVITY, AttentionDeliveryState.EXPIRED, None, True
        if item.requires_user_action and item.expires_at is not None:
            if item.expires_at <= now + timedelta(
                seconds=self._state.expiring_authority_window_seconds
            ):
                return AttentionDecision.DELIVER_NOW, AttentionDeliveryState.QUEUED, None, False
        if (
            item.requires_user_action
            and item.expires_at is not None
            and item.cooldown_until is not None
            and item.cooldown_until >= item.expires_at
        ):
            return AttentionDecision.DELIVER_NOW, AttentionDeliveryState.QUEUED, None, False
        if item.cooldown_until is not None and item.cooldown_until > now:
            return (
                AttentionDecision.DEFER,
                AttentionDeliveryState.DEFERRED,
                item.cooldown_until,
                False,
            )
        if item.priority in {
            AttentionPriority.SECURITY_CRITICAL,
            AttentionPriority.URGENT,
            AttentionPriority.HIGH,
        }:
            return AttentionDecision.DELIVER_NOW, AttentionDeliveryState.QUEUED, None, False
        if self._is_quiet(now) and item.priority in {
            AttentionPriority.LOW,
            AttentionPriority.NORMAL,
        }:
            quiet_end = self._quiet_end(now)
            if (
                item.requires_user_action
                and item.expires_at is not None
                and quiet_end >= item.expires_at
            ):
                return AttentionDecision.DELIVER_NOW, AttentionDeliveryState.QUEUED, None, False
            return (
                AttentionDecision.DEFER,
                AttentionDeliveryState.DEFERRED,
                quiet_end,
                False,
            )
        if (
            item.priority is AttentionPriority.BACKGROUND
            and self._state.user_preference_suppress_background
        ):
            return AttentionDecision.SILENT_ACTIVITY, AttentionDeliveryState.SILENT, None, False
        if item.priority in {AttentionPriority.BACKGROUND, AttentionPriority.LOW}:
            return AttentionDecision.BUNDLE_IN_DIGEST, AttentionDeliveryState.BUNDLED, None, False
        return AttentionDecision.DELIVER_NOW, AttentionDeliveryState.QUEUED, None, False

    def _digest_for(self, workspace: str, now: datetime) -> DigestBucket:
        window = self._state.digest_window_seconds
        seconds = int((now - _UTC_EPOCH).total_seconds())
        start = _UTC_EPOCH + timedelta(seconds=(seconds // window) * window)
        end = start + timedelta(seconds=window)
        digest_id = uuid5(NAMESPACE_URL, f"attention-digest:{workspace}:{start.isoformat()}")
        existing = self._store.get_digest(digest_id)
        if existing is not None:
            return existing
        return DigestBucket(digest_id, workspace, start, end, (), now)

    def _is_quiet(self, now: datetime) -> bool:
        start = self._state.quiet_hours_start_minute
        end = self._state.quiet_hours_end_minute
        if start is None or end is None or start == end:
            return False
        minute = now.hour * 60 + now.minute
        return start <= minute < end if start < end else minute >= start or minute < end

    def _quiet_end(self, now: datetime) -> datetime:
        end = self._state.quiet_hours_end_minute
        if end is None:
            return now
        candidate = now.replace(hour=end // 60, minute=end % 60, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate

    def _entry(self, item_id: UUID) -> AttentionQueueEntry | None:
        return self._store.get_entry(item_id)

    def _require(self, item_id: UUID) -> AttentionItem:
        if not isinstance(item_id, UUID):
            raise AttentionError("Attention item ID is malformed")
        item = self._store.get_item(item_id)
        if item is None:
            raise AttentionError("Unknown attention item")
        return item

    def _now(self) -> datetime:
        return _timestamp(self._clock(), "Attention policy clock")


def _validate_item(item: AttentionItem) -> None:
    if not isinstance(item, AttentionItem):
        raise AttentionError("Attention item is malformed")


def _validate_entry(entry: AttentionQueueEntry) -> None:
    if not isinstance(entry, AttentionQueueEntry):
        raise AttentionError("Attention queue entry is malformed")


def _validate_digest(digest: DigestBucket) -> None:
    if not isinstance(digest, DigestBucket):
        raise AttentionError("Attention digest is malformed")


def _validate_state(state: AttentionPolicyState) -> None:
    if not isinstance(state, AttentionPolicyState):
        raise AttentionError("Attention policy state is malformed")


def _item_to_json(item: AttentionItem) -> dict[str, object]:
    return {
        "item_id": str(item.item_id),
        "item_type": item.item_type,
        "workspace": item.workspace,
        "priority": item.priority.value,
        "created_at": item.created_at.isoformat(),
        "expires_at": item.expires_at.isoformat() if item.expires_at else None,
        "requires_user_action": item.requires_user_action,
        "related_goal_id": str(item.related_goal_id) if item.related_goal_id else None,
        "related_permission_id": str(item.related_permission_id)
        if item.related_permission_id
        else None,
        "related_opportunity_id": str(item.related_opportunity_id)
        if item.related_opportunity_id
        else None,
        "dedupe_key": item.dedupe_key,
        "delivery_state": item.delivery_state.value,
        "defer_until": item.defer_until.isoformat() if item.defer_until else None,
        "cooldown_until": item.cooldown_until.isoformat() if item.cooldown_until else None,
        "resolved": item.resolved,
        "resolved_at": item.resolved_at.isoformat() if item.resolved_at else None,
        "summary": item.summary,
    }


def _item_from_json(payload: Mapping[str, object]) -> AttentionItem:
    return AttentionItem(
        UUID(str(payload["item_id"])),
        str(payload["item_type"]),
        str(payload["workspace"]),
        AttentionPriority(str(payload["priority"])),
        datetime.fromisoformat(str(payload["created_at"])),
        _optional_time(payload.get("expires_at")),
        _strict_bool(payload.get("requires_user_action", False), "requires_user_action"),
        _optional_uuid(payload.get("related_goal_id")),
        _optional_uuid(payload.get("related_permission_id")),
        _optional_uuid(payload.get("related_opportunity_id")),
        str(payload["dedupe_key"]),
        AttentionDeliveryState(str(payload["delivery_state"])),
        _optional_time(payload.get("defer_until")),
        _optional_time(payload.get("cooldown_until")),
        _strict_bool(payload.get("resolved", False), "resolved"),
        _optional_time(payload.get("resolved_at")),
        str(payload["summary"]),
    )


def _entry_to_json(entry: AttentionQueueEntry) -> dict[str, object]:
    return {
        "entry_id": str(entry.entry_id),
        "item_id": str(entry.item_id),
        "decision": entry.decision.value,
        "queued_at": entry.queued_at.isoformat(),
        "next_evaluation_at": entry.next_evaluation_at.isoformat()
        if entry.next_evaluation_at
        else None,
        "delivered_at": entry.delivered_at.isoformat() if entry.delivered_at else None,
        "digest_id": str(entry.digest_id) if entry.digest_id else None,
    }


def _entry_from_json(payload: Mapping[str, object]) -> AttentionQueueEntry:
    return AttentionQueueEntry(
        UUID(str(payload["entry_id"])),
        UUID(str(payload["item_id"])),
        AttentionDecision(str(payload["decision"])),
        datetime.fromisoformat(str(payload["queued_at"])),
        _optional_time(payload.get("next_evaluation_at")),
        _optional_time(payload.get("delivered_at")),
        _optional_uuid(payload.get("digest_id")),
    )


def _digest_to_json(digest: DigestBucket) -> dict[str, object]:
    return {
        "digest_id": str(digest.digest_id),
        "workspace": digest.workspace,
        "period_start": digest.period_start.isoformat(),
        "period_end": digest.period_end.isoformat(),
        "item_ids": [str(item) for item in digest.item_ids],
        "created_at": digest.created_at.isoformat(),
        "delivered": digest.delivered,
    }


def _digest_from_json(payload: Mapping[str, object]) -> DigestBucket:
    raw_ids = payload.get("item_ids", [])
    if not isinstance(raw_ids, list):
        raise AttentionError("Persisted digest items are malformed")
    return DigestBucket(
        UUID(str(payload["digest_id"])),
        str(payload["workspace"]),
        datetime.fromisoformat(str(payload["period_start"])),
        datetime.fromisoformat(str(payload["period_end"])),
        tuple(UUID(str(item)) for item in raw_ids),
        datetime.fromisoformat(str(payload["created_at"])),
        _strict_bool(payload.get("delivered", False), "delivered"),
    )


def _state_to_json(state: AttentionPolicyState) -> dict[str, object]:
    return {
        "quiet_hours_start_minute": state.quiet_hours_start_minute,
        "quiet_hours_end_minute": state.quiet_hours_end_minute,
        "digest_window_seconds": state.digest_window_seconds,
        "expiring_authority_window_seconds": state.expiring_authority_window_seconds,
        "user_preference_suppress_background": state.user_preference_suppress_background,
        "updated_at": state.updated_at.isoformat(),
    }


def _state_from_json(payload: Mapping[str, object]) -> AttentionPolicyState:
    return AttentionPolicyState(
        _optional_int(payload.get("quiet_hours_start_minute")),
        _optional_int(payload.get("quiet_hours_end_minute")),
        _strict_int(payload["digest_window_seconds"], "digest_window_seconds"),
        _strict_int(
            payload["expiring_authority_window_seconds"],
            "expiring_authority_window_seconds",
        ),
        _strict_bool(
            payload.get("user_preference_suppress_background", False),
            "user_preference_suppress_background",
        ),
        datetime.fromisoformat(str(payload["updated_at"])),
    )


def _optional_time(value: object) -> datetime | None:
    return None if value is None else datetime.fromisoformat(str(value))


def _optional_uuid(value: object) -> UUID | None:
    return None if value is None else UUID(str(value))


def _optional_int(value: object) -> int | None:
    return None if value is None else _strict_int(value, "optional integer")


def _strict_int(value: object, field: str) -> int:
    if type(value) is not int:
        raise AttentionError(f"Persisted {field} is malformed")
    return value


def _strict_bool(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise AttentionError(f"Persisted {field} is malformed")
    return value


__all__ = [
    "AttentionDecision",
    "AttentionDeliveryState",
    "AttentionError",
    "AttentionItem",
    "AttentionPolicy",
    "AttentionPolicyState",
    "AttentionPriority",
    "AttentionQueueEntry",
    "AttentionStore",
    "DigestBucket",
    "InMemoryAttentionStore",
    "SQLiteAttentionStore",
]
