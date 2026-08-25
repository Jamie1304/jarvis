"""Secure credential authority and provider-neutral authentication contracts.

Credential metadata may live in the app-owned SQLite database. Secret bytes are
written only to the explicitly selected secret backend; production composition
selects Windows Credential Manager and unsupported hosts fail closed. No raw
secret is included in events, exceptions, metadata, or authentication results.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import hashlib
import hmac
import json
import secrets
import sqlite3
import sys
import threading
from collections.abc import Callable, Iterable
from contextlib import closing
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

from jarvis.events import CredentialChanged, EventBus, EventEnvelope, EventType


class CredentialVaultError(RuntimeError):
    """Sanitized credential-vault failure without provider or secret details."""


class SecretBackendUnavailable(CredentialVaultError):
    """No approved secure secret backend is available."""


class CredentialNotFound(CredentialVaultError):
    """The requested credential metadata does not exist."""


class CredentialUseDenied(CredentialVaultError):
    """Credential use failed because status, expiry, or scope denied it."""


class AuthenticationError(CredentialVaultError):
    """Provider authentication failed without exposing provider response data."""


class CredentialStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    DELETED = "deleted"


class AuthenticationMethod(StrEnum):
    API_TOKEN = "api_token"
    API_KEY = "api_key"
    OAUTH_AUTHORIZATION_CODE = "oauth_authorization_code"
    OAUTH_DEVICE_CODE = "oauth_device_code"
    LOCAL_CALLBACK = "local_callback"


_UNSET = object()


def _text(value: object, field: str, limit: int, *, allow_empty: bool = False) -> str:
    if (
        type(value) is not str
        or (not allow_empty and not value.strip())
        or len(value) > limit
        or any(not character.isprintable() for character in value)
    ):
        raise CredentialVaultError(f"{field} is invalid")
    return value


def _scope(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, str | bytes):
        raise CredentialVaultError("Credential scope is invalid")
    result = tuple(values)
    if len(result) > 64 or any(
        type(value) is not str
        or not value.strip()
        or len(value) > 256
        or any(not character.isprintable() for character in value)
        for value in result
    ):
        raise CredentialVaultError("Credential scope is invalid")
    return tuple(dict.fromkeys(result))


def _secret_bytes(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        try:
            value = secret.encode("utf-8")
        except UnicodeError as error:
            raise CredentialVaultError("Credential secret is invalid") from error
    elif type(secret) is bytes:
        value = secret
    else:
        raise CredentialVaultError("Credential secret is invalid")
    if not value or len(value) > 1_048_576:
        raise CredentialVaultError("Credential secret is invalid")
    return value


def _timestamp(value: datetime | None, field: str) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise CredentialVaultError(f"{field} must be timezone-aware")
    return value.astimezone(UTC).isoformat()


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise CredentialVaultError("Credential metadata timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise CredentialVaultError("Credential metadata timestamp is invalid")
    return parsed


def _package_hash(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CredentialVaultError("Package hash is invalid")
    return value


def _credential_ref_material(reference: CredentialRef) -> bytes:
    return json.dumps(
        (
            str(reference.credential_id),
            reference.integration_id,
            reference.package_version,
            reference.package_hash,
            reference.association,
            reference.operation,
            reference.destination,
            reference.workspace_id,
            reference.scope,
            reference.issued_at.astimezone(UTC).isoformat(),
            reference.expires_at.astimezone(UTC).isoformat(),
        ),
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class CredentialMetadata:
    credential_id: UUID
    label: str
    association: str
    scope: tuple[str, ...]
    auth_method: AuthenticationMethod
    created_at: datetime
    updated_at: datetime
    status: CredentialStatus
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.credential_id, UUID):
            raise CredentialVaultError("Credential ID is invalid")
        _text(self.label, "Credential label", 256)
        _text(self.association, "Credential association", 256)
        _scope(self.scope)
        if not isinstance(self.auth_method, AuthenticationMethod):
            raise CredentialVaultError("Credential authentication method is invalid")
        for value, field in (
            (self.created_at, "Credential created timestamp"),
            (self.updated_at, "Credential updated timestamp"),
        ):
            if value.tzinfo is None:
                raise CredentialVaultError(f"{field} must be timezone-aware")
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise CredentialVaultError("Credential expiry must be timezone-aware")
        if not isinstance(self.status, CredentialStatus):
            raise CredentialVaultError("Credential status is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class CredentialRef:
    """A bounded, non-secret capability reference for one trusted operation.

    The reference contains metadata only.  It is issued by the Vault and is
    useful to a trusted host adapter, while the raw secret remains behind the
    Vault boundary.  Every field that can change the authorization meaning is
    part of the reference so a broker can reject substitution or widening.
    """

    credential_id: UUID
    integration_id: str
    package_version: str
    package_hash: str
    association: str
    operation: str
    destination: str
    workspace_id: str
    scope: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    _proof: bytes = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.credential_id, UUID):
            raise CredentialVaultError("Credential reference identity is invalid")
        for value, field, limit in (
            (self.integration_id, "Credential integration", 256),
            (self.package_version, "Credential package version", 128),
            (self.association, "Credential association", 256),
            (self.operation, "Credential operation", 256),
            (self.destination, "Credential destination", 2_048),
            (self.workspace_id, "Credential workspace", 256),
        ):
            _text(value, field, limit)
        _package_hash(self.package_hash)
        _scope(self.scope)
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise CredentialVaultError("Credential reference timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise CredentialVaultError("Credential reference expiry is invalid")
        if type(self._proof) is not bytes or len(self._proof) != hashlib.sha256().digest_size:
            raise CredentialVaultError("Credential reference proof is invalid")

    def __repr__(self) -> str:
        return f"CredentialRef({self.credential_id}, <metadata-only>)"


class SecretBackend(Protocol):
    def put(self, target: str, secret: bytes) -> None: ...

    def get(self, target: str) -> bytes: ...

    def delete(self, target: str) -> None: ...


class UnavailableSecretBackend:
    """Explicit fail-closed backend used when secure host storage is unavailable."""

    def put(self, target: str, secret: bytes) -> None:
        del target, secret
        raise SecretBackendUnavailable("Windows Credential Manager is unavailable")

    def get(self, target: str) -> bytes:
        del target
        raise SecretBackendUnavailable("Windows Credential Manager is unavailable")

    def delete(self, target: str) -> None:
        del target
        raise SecretBackendUnavailable("Windows Credential Manager is unavailable")


class TestOnlyInMemorySecretBackend:
    """Explicit deterministic test backend; never selected by production defaults."""

    __test__ = False

    def __init__(self) -> None:
        self._values: dict[str, bytes] = {}

    def put(self, target: str, secret: bytes) -> None:
        self._values[target] = bytes(secret)

    def get(self, target: str) -> bytes:
        try:
            return bytes(self._values[target])
        except KeyError as error:
            raise CredentialNotFound("Credential secret is unavailable") from error

    def delete(self, target: str) -> None:
        self._values.pop(target, None)


class _CREDENTIALW(ctypes.Structure):  # pragma: no cover - exercised by opt-in Windows test
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


class WindowsCredentialManagerBackend:  # pragma: no cover - opt-in native Windows integration
    """Native Windows Credential Manager generic-credential backend."""

    _CRED_TYPE_GENERIC = 1
    _CRED_PERSIST_LOCAL_MACHINE = 2
    _ERROR_NOT_FOUND = 1168

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise SecretBackendUnavailable("Windows Credential Manager is unavailable")
        try:
            library = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
            library.CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIALW), wintypes.DWORD]
            library.CredWriteW.restype = wintypes.BOOL
            library.CredReadW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            library.CredReadW.restype = wintypes.BOOL
            library.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
            library.CredDeleteW.restype = wintypes.BOOL
            library.CredFree.argtypes = [ctypes.c_void_p]
            library.CredFree.restype = None
            self._library = library
        except (AttributeError, OSError) as error:
            raise SecretBackendUnavailable("Windows Credential Manager is unavailable") from error

    @staticmethod
    def _target(target: str) -> str:
        _text(target, "Credential backend target", 256)
        if not target.startswith("jarvis:credential:"):
            raise CredentialVaultError("Credential backend target is invalid")
        return target

    def put(self, target: str, secret: bytes) -> None:
        target = self._target(target)
        value = _secret_bytes(secret)
        buffer = ctypes.create_string_buffer(value)
        record = _CREDENTIALW(
            Flags=0,
            Type=self._CRED_TYPE_GENERIC,
            TargetName=target,
            Comment=None,
            CredentialBlobSize=len(value),
            CredentialBlob=ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
            Persist=self._CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount=0,
            Attributes=None,
            TargetAlias=None,
            UserName="JARVIS",
        )
        if not self._library.CredWriteW(ctypes.byref(record), 0):
            raise CredentialVaultError("Secure credential write failed")

    def get(self, target: str) -> bytes:
        target = self._target(target)
        pointer = ctypes.c_void_p()
        if not self._library.CredReadW(target, self._CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)):
            error = ctypes.get_last_error()
            if error == self._ERROR_NOT_FOUND:
                raise CredentialNotFound("Credential secret is unavailable")
            raise CredentialVaultError("Secure credential read failed")
        try:
            record = ctypes.cast(pointer, ctypes.POINTER(_CREDENTIALW)).contents
            if not record.CredentialBlob or record.CredentialBlobSize > 1_048_576:
                raise CredentialVaultError("Secure credential data is invalid")
            return ctypes.string_at(record.CredentialBlob, record.CredentialBlobSize)
        finally:
            self._library.CredFree(pointer)

    def delete(self, target: str) -> None:
        target = self._target(target)
        if not self._library.CredDeleteW(target, self._CRED_TYPE_GENERIC, 0):
            error = ctypes.get_last_error()
            if error != self._ERROR_NOT_FOUND:
                raise CredentialVaultError("Secure credential deletion failed")


def _default_backend() -> SecretBackend:
    if sys.platform != "win32":
        return UnavailableSecretBackend()
    return WindowsCredentialManagerBackend()


class CredentialVault:
    """Sole owner of secret material and credential metadata."""

    _SCHEMA_VERSION = 1

    def __init__(
        self,
        metadata_path: Path,
        *,
        backend: SecretBackend | None = None,
        event_bus: EventBus | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(metadata_path, Path):
            raise CredentialVaultError("Credential metadata path is invalid")
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        self._path = metadata_path
        self._backend = backend or _default_backend()
        self._event_bus = event_bus
        self._clock = clock or (lambda: datetime.now(UTC))
        self._ref_signing_key = secrets.token_bytes(32)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        with self._lock, closing(self._connect()) as connection, connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"
            )
            versions = tuple(connection.execute("SELECT version FROM schema_version"))
            if versions and max(int(row[0]) for row in versions) > self._SCHEMA_VERSION:
                raise CredentialVaultError("Credential metadata schema is newer than this runtime")
            if not versions:
                connection.execute("INSERT INTO schema_version(version) VALUES (?)", (1,))
            connection.execute(
                """CREATE TABLE IF NOT EXISTS credentials (
                    credential_id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    association TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    auth_method TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT,
                    status TEXT NOT NULL
                )"""
            )
            columns = {
                str(row[1]).casefold()
                for row in connection.execute("PRAGMA table_info(credentials)")
            }
            if columns & {"secret", "secret_blob", "password", "token", "key"}:
                raise CredentialVaultError("Credential metadata schema contains secret material")

    @staticmethod
    def _target(credential_id: UUID) -> str:
        return f"jarvis:credential:{credential_id}"

    def create(
        self,
        *,
        label: str,
        association: str,
        scope: Iterable[str],
        auth_method: AuthenticationMethod,
        secret: str | bytes,
        expires_at: datetime | None = None,
    ) -> CredentialMetadata:
        label = _text(label, "Credential label", 256)
        association = _text(association, "Credential association", 256)
        normalized_scope = _scope(scope)
        if not isinstance(auth_method, AuthenticationMethod):
            raise CredentialVaultError("Credential authentication method is invalid")
        secret_bytes = _secret_bytes(secret)
        now = self._now()
        credential_id = uuid4()
        metadata = CredentialMetadata(
            credential_id,
            label,
            association,
            normalized_scope,
            auth_method,
            now,
            now,
            CredentialStatus.ACTIVE,
            expires_at,
        )
        target = self._target(credential_id)
        try:
            self._backend.put(target, secret_bytes)
            with self._lock, closing(self._connect()) as connection, connection:
                connection.execute(
                    "INSERT INTO credentials VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    self._row_values(metadata),
                )
        except Exception as error:
            try:
                self._backend.delete(target)
            except Exception:
                pass
            if isinstance(error, CredentialVaultError):
                raise error
            raise CredentialVaultError("Credential metadata write failed") from error
        self._emit(metadata, "created")
        return metadata

    def update(
        self,
        credential_id: UUID,
        *,
        label: str | None = None,
        association: str | None = None,
        scope: Iterable[str] | None = None,
        secret: str | bytes | None = None,
        expires_at: datetime | None | object = _UNSET,
    ) -> CredentialMetadata:
        current = self.metadata(credential_id)
        if current.status is CredentialStatus.DELETED:
            raise CredentialUseDenied("Deleted credentials cannot be updated")
        if expires_at is _UNSET:
            next_expiry = current.expires_at
        elif expires_at is None or isinstance(expires_at, datetime):
            next_expiry = expires_at
        else:
            raise CredentialVaultError("Credential expiry must be timezone-aware")
        next_metadata = replace(
            current,
            label=current.label if label is None else _text(label, "Credential label", 256),
            association=(
                current.association
                if association is None
                else _text(association, "Credential association", 256)
            ),
            scope=current.scope if scope is None else _scope(scope),
            expires_at=next_expiry,
            updated_at=self._now(),
        )
        if secret is not None:
            self._put_secret(credential_id, secret)
        self._write_metadata(next_metadata)
        self._emit(next_metadata, "updated")
        return next_metadata

    def rotate(
        self,
        credential_id: UUID,
        secret: str | bytes,
        *,
        expires_at: datetime | None | object = _UNSET,
    ) -> CredentialMetadata:
        current = self.metadata(credential_id)
        if current.status is not CredentialStatus.ACTIVE:
            raise CredentialUseDenied("Only active credentials can rotate")
        self._put_secret(credential_id, secret)
        next_expiry = current.expires_at if expires_at is _UNSET else expires_at
        if next_expiry is not None and not isinstance(next_expiry, datetime):
            raise CredentialVaultError("Credential expiry must be timezone-aware")
        next_metadata = replace(current, expires_at=next_expiry, updated_at=self._now())
        self._write_metadata(next_metadata)
        self._emit(next_metadata, "rotated")
        return next_metadata

    def revoke(self, credential_id: UUID) -> CredentialMetadata:
        current = self.metadata(credential_id)
        if current.status in {CredentialStatus.REVOKED, CredentialStatus.DELETED}:
            return current
        next_metadata = replace(current, status=CredentialStatus.REVOKED, updated_at=self._now())
        self._write_metadata(next_metadata)
        try:
            self._backend.delete(self._target(credential_id))
        except Exception as error:
            raise CredentialVaultError(
                "Credential was revoked but secure cleanup failed"
            ) from error
        self._emit(next_metadata, "revoked")
        return next_metadata

    def delete(self, credential_id: UUID) -> CredentialMetadata:
        current = self.metadata(credential_id)
        if current.status is CredentialStatus.DELETED:
            return current
        next_metadata = replace(current, status=CredentialStatus.DELETED, updated_at=self._now())
        self._write_metadata(next_metadata)
        try:
            self._backend.delete(self._target(credential_id))
        except Exception as error:
            raise CredentialVaultError(
                "Credential was deleted but secure cleanup failed"
            ) from error
        self._emit(next_metadata, "deleted")
        return next_metadata

    def metadata(self, credential_id: UUID) -> CredentialMetadata:
        if not isinstance(credential_id, UUID):
            raise CredentialNotFound("Credential metadata was not found")
        with self._lock, closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT * FROM credentials WHERE credential_id = ?", (str(credential_id),)
            ).fetchone()
        if row is None:
            raise CredentialNotFound("Credential metadata was not found")
        metadata = self._metadata_from_row(row)
        if (
            metadata.status is CredentialStatus.ACTIVE
            and metadata.expires_at is not None
            and metadata.expires_at <= self._now()
        ):
            metadata = replace(metadata, status=CredentialStatus.EXPIRED, updated_at=self._now())
            self._write_metadata(metadata)
            self._emit(metadata, "expired")
        return metadata

    def list(self, *, association: str | None = None) -> tuple[CredentialMetadata, ...]:
        with self._lock, closing(self._connect()) as connection, connection:
            rows = tuple(
                connection.execute("SELECT * FROM credentials ORDER BY created_at, credential_id")
            )
        result = tuple(self._metadata_from_row(row) for row in rows)
        if association is None:
            return result
        association = _text(association, "Credential association", 256)
        return tuple(item for item in result if item.association == association)

    def scoped_use(
        self,
        credential_id: UUID,
        *,
        association: str,
        scope: Iterable[str],
    ) -> bytes:
        metadata = self.metadata(credential_id)
        association = _text(association, "Credential association", 256)
        requested_scope = _scope(scope)
        if (
            metadata.status is not CredentialStatus.ACTIVE
            or metadata.association != association
            or not set(requested_scope).issubset(metadata.scope)
        ):
            raise CredentialUseDenied("Credential use is outside its trusted scope")
        try:
            return self._backend.get(self._target(credential_id))
        except CredentialVaultError:
            raise
        except Exception as error:
            raise CredentialVaultError("Secure credential read failed") from error

    def issue_ref(
        self,
        credential_id: UUID,
        *,
        integration_id: str,
        package_version: str,
        package_hash: str,
        operation: str,
        destination: str,
        workspace_id: str,
        scope: Iterable[str],
        ttl_seconds: float = 300.0,
    ) -> CredentialRef:
        """Issue a short-lived operation-bound reference without exposing bytes."""

        metadata = self.metadata(credential_id)
        integration_id = _text(integration_id, "Credential integration", 256)
        package_version = _text(package_version, "Credential package version", 128)
        package_hash = _package_hash(package_hash)
        operation = _text(operation, "Credential operation", 256)
        destination = _text(destination, "Credential destination", 2_048)
        workspace_id = _text(workspace_id, "Credential workspace", 256)
        requested_scope = _scope(scope)
        if not set(requested_scope).issubset(metadata.scope):
            raise CredentialUseDenied("Credential use is outside its trusted scope")
        if not isinstance(ttl_seconds, int | float) or isinstance(ttl_seconds, bool):
            raise CredentialVaultError("Credential reference lifetime is invalid")
        if not 0 < float(ttl_seconds) <= 3_600:
            raise CredentialVaultError("Credential reference lifetime is invalid")
        now = self._now()
        expiry = now + timedelta(seconds=float(ttl_seconds))
        if metadata.expires_at is not None:
            expiry = min(expiry, metadata.expires_at)
        if expiry <= now:
            raise CredentialUseDenied("Credential is expired")
        unsigned = CredentialRef(
            credential_id,
            integration_id,
            package_version,
            package_hash,
            metadata.association,
            operation,
            destination,
            workspace_id,
            requested_scope,
            now,
            expiry,
            b"\0" * hashlib.sha256().digest_size,
        )
        return replace(unsigned, _proof=self._reference_proof(unsigned))

    def resolve_ref(
        self,
        reference: CredentialRef,
        *,
        integration_id: str,
        package_version: str,
        package_hash: str,
        operation: str,
        destination: str,
        workspace_id: str,
        scope: Iterable[str],
    ) -> bytes:
        """Resolve an exact trusted reference for use by a host-side adapter."""

        if type(reference) is not CredentialRef:
            raise CredentialUseDenied("Credential reference is not trusted")
        if not hmac.compare_digest(reference._proof, self._reference_proof(reference)):
            raise CredentialUseDenied("Credential reference proof is invalid")
        now = self._now()
        if reference.expires_at <= now:
            raise CredentialUseDenied("Credential reference has expired")
        expected_scope = _scope(scope)
        if (
            reference.integration_id != _text(integration_id, "Credential integration", 256)
            or reference.package_version
            != _text(package_version, "Credential package version", 128)
            or reference.package_hash != _package_hash(package_hash)
            or reference.operation != _text(operation, "Credential operation", 256)
            or reference.destination != _text(destination, "Credential destination", 2_048)
            or reference.workspace_id != _text(workspace_id, "Credential workspace", 256)
            or reference.scope != expected_scope
        ):
            raise CredentialUseDenied("Credential reference binding does not match")
        return self.scoped_use(
            reference.credential_id,
            association=reference.association,
            scope=expected_scope,
        )

    def status(self, credential_id: UUID) -> CredentialStatus:
        return self.metadata(credential_id).status

    def close(self) -> None:
        """Metadata connections are short-lived; retained for composition symmetry."""

    def _put_secret(self, credential_id: UUID, secret: str | bytes) -> None:
        try:
            self._backend.put(self._target(credential_id), _secret_bytes(secret))
        except CredentialVaultError:
            raise
        except Exception as error:
            raise CredentialVaultError("Secure credential write failed") from error

    def _write_metadata(self, metadata: CredentialMetadata) -> None:
        with self._lock, closing(self._connect()) as connection, connection:
            connection.execute(
                """UPDATE credentials SET label=?, association=?, scope_json=?, auth_method=?,
                   created_at=?, updated_at=?, expires_at=?, status=? WHERE credential_id=?""",
                (*self._row_values(metadata)[1:], str(metadata.credential_id)),
            )

    @staticmethod
    def _row_values(metadata: CredentialMetadata) -> tuple[object, ...]:
        return (
            str(metadata.credential_id),
            metadata.label,
            metadata.association,
            json.dumps(metadata.scope, separators=(",", ":")),
            metadata.auth_method.value,
            _timestamp(metadata.created_at, "Credential created timestamp"),
            _timestamp(metadata.updated_at, "Credential updated timestamp"),
            _timestamp(metadata.expires_at, "Credential expiry"),
            metadata.status.value,
        )

    @staticmethod
    def _metadata_from_row(row: sqlite3.Row) -> CredentialMetadata:
        try:
            raw_scope = json.loads(str(row["scope_json"]))
            if type(raw_scope) is not list:
                raise CredentialVaultError("Credential scope is malformed")
            scope = _scope(raw_scope)
            expires_value = row["expires_at"]
            return CredentialMetadata(
                UUID(str(row["credential_id"])),
                str(row["label"]),
                str(row["association"]),
                scope,
                AuthenticationMethod(str(row["auth_method"])),
                _parse_timestamp(str(row["created_at"])) or datetime.min.replace(tzinfo=UTC),
                _parse_timestamp(str(row["updated_at"])) or datetime.min.replace(tzinfo=UTC),
                CredentialStatus(str(row["status"])),
                _parse_timestamp(None if expires_value is None else str(expires_value)),
            )
        except (
            CredentialVaultError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise CredentialVaultError("Credential metadata is malformed") from error

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise CredentialVaultError("Credential clock is invalid")
        return value.astimezone(UTC)

    def _reference_proof(self, reference: CredentialRef) -> bytes:
        return hmac.new(
            self._ref_signing_key,
            _credential_ref_material(reference),
            hashlib.sha256,
        ).digest()

    def _emit(self, metadata: CredentialMetadata, operation: str) -> None:
        if self._event_bus is None:
            return
        self._event_bus.publish_nowait(
            EventEnvelope.create(
                EventType.CREDENTIAL_CHANGED,
                CredentialChanged(metadata.credential_id, metadata.status.value, operation),
                source="credentials.vault",
                correlation_id=uuid4(),
            )
        )


class CredentialBroker:
    """Trusted application adapter for scoped Vault use.

    Integrations receive :class:`CredentialRef` metadata, not this object and
    never the Vault backend.  The return value is intended only for a trusted
    adapter callback that immediately constructs an authenticated operation.
    """

    def __init__(self, vault: CredentialVault) -> None:
        if type(vault) is not CredentialVault:
            raise CredentialVaultError("Credential broker requires the authoritative Vault")
        self._vault = vault

    def issue_ref(
        self,
        credential_id: UUID,
        *,
        integration_id: str,
        package_version: str,
        package_hash: str,
        operation: str,
        destination: str,
        workspace_id: str,
        scope: Iterable[str],
        ttl_seconds: float = 300.0,
    ) -> CredentialRef:
        return self._vault.issue_ref(
            credential_id,
            integration_id=integration_id,
            package_version=package_version,
            package_hash=package_hash,
            operation=operation,
            destination=destination,
            workspace_id=workspace_id,
            scope=scope,
            ttl_seconds=ttl_seconds,
        )

    def resolve(
        self,
        reference: CredentialRef,
        *,
        integration_id: str,
        package_version: str,
        package_hash: str,
        operation: str,
        destination: str,
        workspace_id: str,
        scope: Iterable[str],
    ) -> bytes:
        return self._vault.resolve_ref(
            reference,
            integration_id=integration_id,
            package_version=package_version,
            package_hash=package_hash,
            operation=operation,
            destination=destination,
            workspace_id=workspace_id,
            scope=scope,
        )


@dataclass(frozen=True, slots=True, repr=False)
class AuthTokenSet:
    """Transient provider result; never serialize or persist this object."""

    access_token: str | bytes
    refresh_token: str | bytes | None
    expires_at: datetime | None
    scope: tuple[str, ...]

    def __post_init__(self) -> None:
        _secret_bytes(self.access_token)
        if self.refresh_token is not None:
            _secret_bytes(self.refresh_token)
        _scope(self.scope)
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise CredentialVaultError("Authentication expiry must be timezone-aware")

    def __repr__(self) -> str:
        return "AuthTokenSet(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class DeviceCodeChallenge:
    challenge_id: UUID
    verification_uri: str
    user_code: str
    device_code: str
    expires_at: datetime
    interval_seconds: int = 5

    def __post_init__(self) -> None:
        if not isinstance(self.challenge_id, UUID):
            raise CredentialVaultError("Authentication challenge is invalid")
        _text(self.verification_uri, "Verification URI", 4_096)
        _text(self.user_code, "User code", 256)
        _text(self.device_code, "Device code", 1_024)
        if self.expires_at.tzinfo is None or not 1 <= self.interval_seconds <= 300:
            raise CredentialVaultError("Authentication challenge is invalid")

    def __repr__(self) -> str:
        return f"DeviceCodeChallenge({self.challenge_id}, <redacted>)"


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    request_id: UUID
    authorization_url: str
    redirect_uri: str
    scope: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, UUID):
            raise CredentialVaultError("Authorization request is invalid")
        _text(self.authorization_url, "Authorization URL", 4_096)
        _text(self.redirect_uri, "Redirect URI", 4_096)
        _scope(self.scope)


@dataclass(frozen=True, slots=True)
class AuthenticationResult:
    access_credential: CredentialMetadata
    refresh_credential: CredentialMetadata | None = None


class GenericAuthenticationProvider(Protocol):
    def authorization_url(
        self, *, state: str, redirect_uri: str, scope: tuple[str, ...]
    ) -> str: ...

    async def exchange_authorization_code(
        self, *, code: str, redirect_uri: str, scope: tuple[str, ...]
    ) -> AuthTokenSet: ...

    async def begin_device_code(self, *, scope: tuple[str, ...]) -> DeviceCodeChallenge: ...

    async def poll_device_code(
        self, *, device_code: str, scope: tuple[str, ...]
    ) -> AuthTokenSet: ...

    async def refresh(self, *, refresh_token: bytes, scope: tuple[str, ...]) -> AuthTokenSet: ...


class GenericAuthenticationService:
    """Orchestrate generic auth without knowing any provider or integration."""

    def __init__(self, vault: CredentialVault, *, max_pending: int = 128) -> None:
        if not isinstance(max_pending, int) or max_pending < 1:
            raise AuthenticationError("Pending authentication bound is invalid")
        self._vault = vault
        self._pending_states: dict[str, tuple[UUID, str, tuple[str, ...]]] = {}
        self._pending_devices: dict[UUID, tuple[str, str, tuple[str, ...]]] = {}
        self._max_pending = max_pending

    def store_api_token(
        self, *, label: str, association: str, scope: Iterable[str], secret: str | bytes
    ) -> CredentialMetadata:
        return self._vault.create(
            label=label,
            association=association,
            scope=scope,
            auth_method=AuthenticationMethod.API_TOKEN,
            secret=secret,
        )

    def store_api_key(
        self, *, label: str, association: str, scope: Iterable[str], secret: str | bytes
    ) -> CredentialMetadata:
        return self._vault.create(
            label=label,
            association=association,
            scope=scope,
            auth_method=AuthenticationMethod.API_KEY,
            secret=secret,
        )

    def begin_authorization_code(
        self,
        provider: GenericAuthenticationProvider,
        *,
        redirect_uri: str,
        scope: Iterable[str],
    ) -> AuthorizationRequest:
        redirect_uri = _text(redirect_uri, "Redirect URI", 4_096)
        normalized_scope = _scope(scope)
        self._bound_pending()
        request_id = uuid4()
        state = secrets.token_urlsafe(32)
        try:
            authorization_url = provider.authorization_url(
                state=state, redirect_uri=redirect_uri, scope=normalized_scope
            )
        except Exception as error:
            raise AuthenticationError("Authorization request could not be created") from error
        _text(authorization_url, "Authorization URL", 4_096)
        self._pending_states[state] = (request_id, redirect_uri, normalized_scope)
        return AuthorizationRequest(request_id, authorization_url, redirect_uri, normalized_scope)

    async def complete_authorization_code(
        self,
        provider: GenericAuthenticationProvider,
        *,
        state: str,
        code: str,
        association: str,
        label: str,
        method: AuthenticationMethod = AuthenticationMethod.OAUTH_AUTHORIZATION_CODE,
    ) -> AuthenticationResult:
        if method not in {
            AuthenticationMethod.OAUTH_AUTHORIZATION_CODE,
            AuthenticationMethod.LOCAL_CALLBACK,
        }:
            raise AuthenticationError("Authorization-code authentication method is invalid")
        state = _text(state, "Authorization state", 512)
        code = _text(code, "Authorization code", 4_096)
        try:
            _request_id, redirect_uri, scope = self._pending_states.pop(state)
        except KeyError as error:
            raise AuthenticationError("Authorization state is invalid or expired") from error
        try:
            tokens = await provider.exchange_authorization_code(
                code=code, redirect_uri=redirect_uri, scope=scope
            )
            return self._store_tokens(
                tokens,
                association=association,
                label=label,
                scope=scope,
                access_method=method,
            )
        except CredentialVaultError:
            raise
        except Exception as error:
            raise AuthenticationError("Authorization code exchange failed") from error

    async def begin_device_code(
        self,
        provider: GenericAuthenticationProvider,
        *,
        association: str,
        label: str,
        scope: Iterable[str],
    ) -> DeviceCodeChallenge:
        association = _text(association, "Credential association", 256)
        label = _text(label, "Credential label", 256)
        normalized_scope = _scope(scope)
        self._bound_pending()
        try:
            challenge = await provider.begin_device_code(scope=normalized_scope)
            if not isinstance(challenge, DeviceCodeChallenge):
                raise AuthenticationError("Device-code response is invalid")
            if challenge.expires_at <= self._vault._now():
                raise AuthenticationError("Device-code challenge is already expired")
        except Exception as error:
            if isinstance(error, AuthenticationError):
                raise
            raise AuthenticationError("Device-code start failed") from error
        self._pending_devices[challenge.challenge_id] = (
            association,
            label,
            normalized_scope,
        )
        return challenge

    async def complete_device_code(
        self,
        provider: GenericAuthenticationProvider,
        challenge: DeviceCodeChallenge,
    ) -> AuthenticationResult:
        if not isinstance(challenge, DeviceCodeChallenge):
            raise AuthenticationError("Device-code challenge is invalid")
        if challenge.expires_at <= self._vault._now():
            self._pending_devices.pop(challenge.challenge_id, None)
            raise AuthenticationError("Device-code challenge has expired")
        try:
            association, label, scope = self._pending_devices.pop(challenge.challenge_id)
        except KeyError as error:
            raise AuthenticationError(
                "Device-code challenge is unknown or already consumed"
            ) from error
        try:
            tokens = await provider.poll_device_code(device_code=challenge.device_code, scope=scope)
            return self._store_tokens(
                tokens,
                association=association,
                label=label,
                scope=scope,
                access_method=AuthenticationMethod.OAUTH_DEVICE_CODE,
            )
        except CredentialVaultError:
            raise
        except Exception as error:
            raise AuthenticationError("Device-code exchange failed") from error

    async def refresh(
        self,
        provider: GenericAuthenticationProvider,
        credential_id: UUID,
        *,
        label: str | None = None,
    ) -> AuthenticationResult:
        metadata = self._vault.metadata(credential_id)
        if metadata.auth_method not in {
            AuthenticationMethod.OAUTH_AUTHORIZATION_CODE,
            AuthenticationMethod.OAUTH_DEVICE_CODE,
            AuthenticationMethod.LOCAL_CALLBACK,
        }:
            raise AuthenticationError("Credential does not support refresh")
        refresh_token = self._vault.scoped_use(
            credential_id,
            association=metadata.association,
            scope=metadata.scope,
        )
        try:
            tokens = await provider.refresh(refresh_token=refresh_token, scope=metadata.scope)
            refreshed_metadata = metadata
            if tokens.refresh_token is not None:
                refreshed_metadata = self._vault.rotate(credential_id, tokens.refresh_token)
            access = self._vault.create(
                label=label or f"{metadata.label} access",
                association=metadata.association,
                scope=metadata.scope,
                auth_method=metadata.auth_method,
                secret=tokens.access_token,
                expires_at=tokens.expires_at,
            )
            return AuthenticationResult(access, refreshed_metadata)
        except CredentialVaultError:
            raise
        except Exception as error:
            raise AuthenticationError("Credential refresh failed") from error

    def _store_tokens(
        self,
        tokens: AuthTokenSet,
        *,
        association: str,
        label: str,
        scope: tuple[str, ...],
        access_method: AuthenticationMethod,
    ) -> AuthenticationResult:
        access = self._vault.create(
            label=f"{_text(label, 'Credential label', 256)} access",
            association=association,
            scope=scope,
            auth_method=access_method,
            secret=tokens.access_token,
            expires_at=tokens.expires_at,
        )
        refresh = None
        if tokens.refresh_token is not None:
            refresh = self._vault.create(
                label=f"{label} refresh",
                association=association,
                scope=scope,
                auth_method=access_method,
                secret=tokens.refresh_token,
            )
        return AuthenticationResult(access, refresh)

    def _bound_pending(self) -> None:
        if len(self._pending_states) + len(self._pending_devices) >= self._max_pending:
            raise AuthenticationError("Too many pending authentication requests")


__all__ = [
    "AuthenticationError",
    "AuthenticationMethod",
    "AuthenticationResult",
    "AuthorizationRequest",
    "AuthTokenSet",
    "CredentialBroker",
    "CredentialMetadata",
    "CredentialNotFound",
    "CredentialRef",
    "CredentialStatus",
    "CredentialUseDenied",
    "CredentialVault",
    "CredentialVaultError",
    "DeviceCodeChallenge",
    "GenericAuthenticationProvider",
    "GenericAuthenticationService",
    "SecretBackend",
    "SecretBackendUnavailable",
    "TestOnlyInMemorySecretBackend",
    "UnavailableSecretBackend",
    "WindowsCredentialManagerBackend",
]
