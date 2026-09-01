"""Persistent execution-session records, separate from tasks and memory."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import UUID, uuid4


class AgentSessionStoreError(RuntimeError):
    """The durable session store is malformed or uses an unsupported schema."""


class AgentSessionType(StrEnum):
    INTERACTIVE = "interactive"
    VOICE = "voice"
    TASK = "task"
    BACKGROUND = "background"
    SUBAGENT = "subagent"
    RESEARCH = "research"
    CODING = "coding"
    INTERNAL = "internal"


@dataclass(frozen=True, slots=True)
class AgentSession:
    session_id: UUID
    session_type: AgentSessionType
    provider_id: str
    model_id: str
    created_at: datetime
    last_used_at: datetime
    context_metadata: tuple[tuple[str, str], ...] = ()
    usage_tokens: int = 0
    usage_cost: float = 0.0
    parent_session_id: UUID | None = None
    archived: bool = False
    synchronized: bool = True


class AgentSessionStore:
    """Own the durable session registry; no task or user-memory truth lives here."""

    _SCHEMA_VERSION = 1
    _MIGRATION_NAME = "create_agent_sessions"

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise AgentSessionStoreError("Session database path is invalid")
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, timeout=5.0)
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA journal_mode=WAL")
        try:
            self._migrate()
        except (sqlite3.DatabaseError, AgentSessionStoreError) as error:
            self._connection.close()
            if isinstance(error, AgentSessionStoreError):
                raise
            raise AgentSessionStoreError("Session database is unavailable") from error

    def _migrate(self) -> None:
        with self._connection:
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS agent_session_schema "
                "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
            )
            rows = self._connection.execute(
                "SELECT version, name FROM agent_session_schema"
            ).fetchall()
            versions = {int(row[0]): str(row[1]) for row in rows}
            if any(version > self._SCHEMA_VERSION for version in versions):
                raise AgentSessionStoreError("Session database uses a future schema")
            if versions and versions.get(1) != self._MIGRATION_NAME:
                raise AgentSessionStoreError("Session migration identity mismatch")
            if not versions:
                # This also upgrades databases created before the schema table
                # existed; CREATE TABLE IF NOT EXISTS preserves their records.
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS agent_sessions (
                        session_id TEXT PRIMARY KEY,
                        session_type TEXT NOT NULL,
                        provider_id TEXT NOT NULL,
                        model_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        last_used_at TEXT NOT NULL,
                        context_metadata TEXT NOT NULL,
                        usage_tokens INTEGER NOT NULL DEFAULT 0,
                        usage_cost REAL NOT NULL DEFAULT 0,
                        parent_session_id TEXT REFERENCES agent_sessions(session_id),
                        archived INTEGER NOT NULL DEFAULT 0,
                        synchronized INTEGER NOT NULL DEFAULT 1
                    )
                    """
                )
                self._connection.execute(
                    "INSERT INTO agent_session_schema(version, name) VALUES (?, ?)",
                    (self._SCHEMA_VERSION, self._MIGRATION_NAME),
                )

    def create(
        self,
        session_type: AgentSessionType,
        provider_id: str,
        model_id: str,
        *,
        context_metadata: tuple[tuple[str, str], ...] = (),
        parent_session_id: UUID | None = None,
    ) -> AgentSession:
        now = _now()
        session = AgentSession(
            uuid4(),
            session_type,
            provider_id,
            model_id,
            now,
            now,
            context_metadata,
            parent_session_id=parent_session_id,
        )
        self._write(session)
        return session

    def get(self, session_id: UUID) -> AgentSession | None:
        row = self._connection.execute(
            "SELECT * FROM agent_sessions WHERE session_id=?", (str(session_id),)
        ).fetchone()
        return _from_row(row) if row else None

    def record_usage(self, session_id: UUID, tokens: int, cost: float = 0.0) -> AgentSession:
        if tokens < 0 or cost < 0:
            raise ValueError("Session usage must be non-negative")
        self._connection.execute(
            """UPDATE agent_sessions SET last_used_at=?, usage_tokens=usage_tokens+?,
               usage_cost=usage_cost+? WHERE session_id=? AND archived=0""",
            (_now().isoformat(), tokens, cost, str(session_id)),
        )
        self._connection.commit()
        result = self.get(session_id)
        if result is None:
            raise KeyError(session_id)
        return result

    def mark_synchronized(self, session_id: UUID, synchronized: bool) -> AgentSession:
        self._connection.execute(
            "UPDATE agent_sessions SET synchronized=?, last_used_at=? WHERE session_id=?",
            (int(synchronized), _now().isoformat(), str(session_id)),
        )
        self._connection.commit()
        result = self.get(session_id)
        if result is None:
            raise KeyError(session_id)
        return result

    def archive(self, session_id: UUID) -> None:
        self._connection.execute(
            "UPDATE agent_sessions SET archived=1, synchronized=0 WHERE session_id=?",
            (str(session_id),),
        )
        self._connection.commit()

    def rebuild(self, session_id: UUID) -> AgentSession:
        current = self.get(session_id)
        if current is None:
            raise KeyError(session_id)
        self.archive(session_id)
        return self.create(
            current.session_type,
            current.provider_id,
            current.model_id,
            context_metadata=current.context_metadata,
            parent_session_id=current.parent_session_id,
        )

    def child(self, session_id: UUID, session_type: AgentSessionType) -> AgentSession:
        parent = self.get(session_id)
        if parent is None or parent.archived:
            raise KeyError(session_id)
        return self.create(
            session_type,
            parent.provider_id,
            parent.model_id,
            context_metadata=parent.context_metadata,
            parent_session_id=parent.session_id,
        )

    def change_model(self, session_id: UUID, model_id: str) -> AgentSession:
        current = self.get(session_id)
        if current is None:
            raise KeyError(session_id)
        self.archive(session_id)
        return self.create(
            current.session_type,
            current.provider_id,
            model_id,
            context_metadata=current.context_metadata,
            parent_session_id=current.parent_session_id,
        )

    def close(self) -> None:
        self._connection.close()

    def _write(self, session: AgentSession) -> None:
        self._connection.execute(
            """INSERT INTO agent_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(session.session_id),
                session.session_type.value,
                session.provider_id,
                session.model_id,
                session.created_at.isoformat(),
                session.last_used_at.isoformat(),
                json.dumps(session.context_metadata),
                session.usage_tokens,
                session.usage_cost,
                str(session.parent_session_id) if session.parent_session_id else None,
                int(session.archived),
                int(session.synchronized),
            ),
        )
        self._connection.commit()


def _now() -> datetime:
    return datetime.now(UTC)


def _from_row(row: tuple[object, ...]) -> AgentSession:
    return AgentSession(
        UUID(str(row[0])),
        AgentSessionType(str(row[1])),
        str(row[2]),
        str(row[3]),
        datetime.fromisoformat(str(row[4])),
        datetime.fromisoformat(str(row[5])),
        tuple(tuple(item) for item in json.loads(str(row[6]))),
        int(str(row[7])),
        float(str(row[8])),
        UUID(str(row[9])) if row[9] else None,
        bool(row[10]),
        bool(row[11]),
    )
