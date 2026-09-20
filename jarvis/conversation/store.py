"""Bounded durable conversation history and restart truth."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import UUID

from jarvis.ai.models import ChatMessage, MessageRole


class ConversationStoreError(RuntimeError):
    """Conversation storage is malformed, unavailable, or incompatible."""


class DurableTurnStatus(StrEnum):
    ACTIVE = "active"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


@dataclass(frozen=True, slots=True)
class DurableConversation:
    conversation_id: UUID
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class DurableTurn:
    turn_id: UUID
    conversation_id: UUID
    generation: int
    status: str
    created_at: datetime
    completed_at: datetime | None = None


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


class ConversationStore:
    """Own the only durable completed-message history for conversations."""

    CURRENT_SCHEMA = 1

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._connection = sqlite3.connect(path, timeout=5.0, check_same_thread=False)
        self._lock = threading.RLock()
        try:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS conversation_schema_migrations "
                "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
            )
            versions = {
                int(row[0]): str(row[1])
                for row in self._connection.execute(
                    "SELECT version, name FROM conversation_schema_migrations"
                )
            }
            if any(version > self.CURRENT_SCHEMA for version in versions):
                raise ConversationStoreError("Conversation database uses a future schema")
            if not versions:
                self._connection.executescript(
                    """
                    CREATE TABLE conversations (
                        conversation_id TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE TABLE conversation_messages (
                        message_id TEXT PRIMARY KEY,
                        conversation_id TEXT NOT NULL,
                        role TEXT NOT NULL,
                        content TEXT NOT NULL,
                        ordinal INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        UNIQUE(conversation_id, ordinal),
                        FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
                    );
                    CREATE TABLE conversation_turns (
                        turn_id TEXT PRIMARY KEY,
                        conversation_id TEXT NOT NULL,
                        generation INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        completed_at TEXT,
                        FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
                    );
                    CREATE INDEX conversation_messages_order
                        ON conversation_messages(conversation_id, ordinal);
                    CREATE INDEX conversation_turns_current
                        ON conversation_turns(conversation_id, generation);
                    INSERT INTO conversation_schema_migrations(version, name)
                        VALUES (1, 'create_conversation_records');
                    """
                )
            elif versions.get(1) != "create_conversation_records":
                raise ConversationStoreError("Conversation migration identity mismatch")
            self._connection.commit()
        except (sqlite3.DatabaseError, ValueError, ConversationStoreError) as error:
            self._connection.close()
            if isinstance(error, ConversationStoreError):
                raise
            raise ConversationStoreError("Conversation database is unavailable") from error
        self.reconcile_after_restart()

    @property
    def database_path(self) -> Path:
        return self._path

    def create(self, conversation_id: UUID, *, now: datetime | None = None) -> UUID:
        if not isinstance(conversation_id, UUID):
            raise ConversationStoreError("Conversation identity is malformed")
        timestamp = _timestamp(now or datetime.now(UTC))
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT OR IGNORE INTO conversations(conversation_id, created_at, updated_at) "
                    "VALUES (?, ?, ?)",
                    (str(conversation_id), timestamp, timestamp),
                )
                self._connection.commit()
            except sqlite3.DatabaseError as error:
                self._connection.rollback()
                raise ConversationStoreError("Conversation could not be created") from error
        return conversation_id

    def list(self) -> tuple[DurableConversation, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT conversation_id, created_at, updated_at FROM conversations "
                "ORDER BY created_at, conversation_id"
            ).fetchall()
        return tuple(
            DurableConversation(
                UUID(str(row[0])), _parse_timestamp(str(row[1])), _parse_timestamp(str(row[2]))
            )
            for row in rows
        )

    def append_message(self, message: ChatMessage) -> ChatMessage:
        if not isinstance(message, ChatMessage) or not isinstance(message.role, MessageRole):
            raise ConversationStoreError("Conversation message is malformed")
        if not message.content or len(message.content) > 32_000 or "\x00" in message.content:
            raise ConversationStoreError("Conversation message content is malformed")
        self.create(message.conversation_id)
        with self._lock:
            try:
                ordinal_row = self._connection.execute(
                    "SELECT COALESCE(MAX(ordinal), -1) + 1 FROM conversation_messages "
                    "WHERE conversation_id=?",
                    (str(message.conversation_id),),
                ).fetchone()
                ordinal = int(ordinal_row[0])
                self._connection.execute(
                    "INSERT OR IGNORE INTO conversation_messages "
                    "(message_id, conversation_id, role, content, ordinal, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        str(message.id),
                        str(message.conversation_id),
                        message.role.value,
                        message.content,
                        ordinal,
                        _timestamp(message.created_at),
                    ),
                )
                self._connection.execute(
                    "UPDATE conversations SET updated_at=? WHERE conversation_id=?",
                    (_timestamp(message.created_at), str(message.conversation_id)),
                )
                self._connection.commit()
            except sqlite3.DatabaseError as error:
                self._connection.rollback()
                raise ConversationStoreError("Conversation message could not be stored") from error
        return message

    def history(self, conversation_id: UUID) -> tuple[ChatMessage, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT message_id, role, content, created_at FROM conversation_messages "
                "WHERE conversation_id=? ORDER BY ordinal",
                (str(conversation_id),),
            ).fetchall()
        try:
            return tuple(
                ChatMessage(
                    UUID(str(row[0])),
                    conversation_id,
                    MessageRole(str(row[1])),
                    str(row[2]),
                    _parse_timestamp(str(row[3])),
                )
                for row in rows
            )
        except (ValueError, TypeError) as error:
            raise ConversationStoreError("Conversation history is malformed") from error

    def begin_turn(self, turn: DurableTurn) -> DurableTurn:
        self.create(turn.conversation_id, now=turn.created_at)
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO conversation_turns "
                    "(turn_id, conversation_id, generation, status, created_at, completed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        str(turn.turn_id),
                        str(turn.conversation_id),
                        turn.generation,
                        turn.status,
                        _timestamp(turn.created_at),
                        None,
                    ),
                )
                self._connection.commit()
            except sqlite3.DatabaseError as error:
                self._connection.rollback()
                raise ConversationStoreError("Conversation turn could not be started") from error
        return turn

    def set_turn_status(
        self, turn_id: UUID, status: str, *, completed_at: datetime | None = None
    ) -> None:
        if status not in {
            DurableTurnStatus.ACTIVE,
            DurableTurnStatus.COMPLETED,
            DurableTurnStatus.CANCELLED,
            DurableTurnStatus.FAILED,
            DurableTurnStatus.INTERRUPTED,
        }:
            raise ConversationStoreError("Conversation turn status is invalid")
        with self._lock:
            self._connection.execute(
                "UPDATE conversation_turns SET status=?, completed_at=? WHERE turn_id=?",
                (status, _timestamp(completed_at) if completed_at else None, str(turn_id)),
            )
            self._connection.commit()

    def turns(self, conversation_id: UUID) -> tuple[DurableTurn, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT turn_id, generation, status, created_at, completed_at "
                "FROM conversation_turns WHERE conversation_id=? ORDER BY generation",
                (str(conversation_id),),
            ).fetchall()
        return tuple(
            DurableTurn(
                UUID(str(row[0])),
                conversation_id,
                int(row[1]),
                str(row[2]),
                _parse_timestamp(str(row[3])),
                _parse_timestamp(str(row[4])) if row[4] else None,
            )
            for row in rows
        )

    def reconcile_after_restart(self) -> tuple[UUID, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT turn_id FROM conversation_turns WHERE status=?",
                (DurableTurnStatus.ACTIVE,),
            ).fetchall()
            if rows:
                self._connection.executemany(
                    "UPDATE conversation_turns SET status=?, completed_at=? WHERE turn_id=?",
                    [
                        (DurableTurnStatus.INTERRUPTED, _timestamp(datetime.now(UTC)), str(row[0]))
                        for row in rows
                    ],
                )
                self._connection.commit()
        return tuple(UUID(str(row[0])) for row in rows)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> ConversationStore:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


__all__ = [
    "ConversationStore",
    "ConversationStoreError",
    "DurableConversation",
    "DurableTurn",
    "DurableTurnStatus",
]
