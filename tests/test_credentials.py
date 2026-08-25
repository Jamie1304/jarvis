from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from jarvis.credentials import (
    AuthenticationError,
    AuthenticationMethod,
    AuthorizationRequest,
    AuthTokenSet,
    CredentialMetadata,
    CredentialNotFound,
    CredentialRef,
    CredentialStatus,
    CredentialUseDenied,
    CredentialVault,
    CredentialVaultError,
    DeviceCodeChallenge,
    GenericAuthenticationService,
    TestOnlyInMemorySecretBackend,
    UnavailableSecretBackend,
)
from jarvis.events import CredentialChanged, EventEnvelope, EventPayload, EventType


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value


class EventSink:
    def __init__(self) -> None:
        self.events: list[EventEnvelope[EventPayload]] = []

    async def publish(self, event: EventEnvelope[EventPayload]) -> bool:
        self.events.append(event)
        return True

    def publish_nowait(self, event: EventEnvelope[EventPayload]) -> bool:
        asyncio.get_running_loop().create_task(self.publish(event))
        return True


class Provider:
    def __init__(self) -> None:
        self.refresh_calls: list[bytes] = []

    def authorization_url(self, *, state: str, redirect_uri: str, scope: tuple[str, ...]) -> str:
        return (
            f"https://auth.example/authorize?state={state}&redirect={redirect_uri}&scope={scope[0]}"
        )

    async def exchange_authorization_code(
        self, *, code: str, redirect_uri: str, scope: tuple[str, ...]
    ) -> AuthTokenSet:
        assert code == "one-time-code"
        assert redirect_uri.startswith("http://127.0.0.1")
        return AuthTokenSet("access-secret", "refresh-secret", None, scope)

    async def begin_device_code(self, *, scope: tuple[str, ...]) -> DeviceCodeChallenge:
        assert scope == ("read",)
        return DeviceCodeChallenge(
            uuid4(),
            "https://auth.example/device",
            "ABCD-EFGH",
            "device-secret",
            datetime.now(UTC) + timedelta(minutes=5),
        )

    async def poll_device_code(self, *, device_code: str, scope: tuple[str, ...]) -> AuthTokenSet:
        assert device_code == "device-secret"
        return AuthTokenSet(b"device-access", None, None, scope)

    async def refresh(self, *, refresh_token: bytes, scope: tuple[str, ...]) -> AuthTokenSet:
        self.refresh_calls.append(refresh_token)
        return AuthTokenSet(b"refreshed-access", b"rotated-refresh", None, scope)


class FailingBackend(TestOnlyInMemorySecretBackend):
    def __init__(
        self, *, fail_put: bool = False, fail_get: bool = False, fail_delete: bool = False
    ) -> None:
        super().__init__()
        self.fail_put = fail_put
        self.fail_get = fail_get
        self.fail_delete = fail_delete

    def put(self, target: str, secret: bytes) -> None:
        if self.fail_put:
            raise RuntimeError("backend failure")
        super().put(target, secret)

    def get(self, target: str) -> bytes:
        if self.fail_get:
            raise RuntimeError("backend failure")
        return super().get(target)

    def delete(self, target: str) -> None:
        if self.fail_delete:
            raise RuntimeError("backend failure")
        super().delete(target)


class BadDeviceProvider(Provider):
    async def begin_device_code(self, *, scope: tuple[str, ...]) -> DeviceCodeChallenge:
        del scope
        return object()  # type: ignore[return-value]


def vault(
    tmp_path: Path, *, clock: Clock | None = None, events: EventSink | None = None
) -> CredentialVault:
    return CredentialVault(
        tmp_path / "credentials.sqlite3",
        backend=TestOnlyInMemorySecretBackend(),
        clock=clock,
        event_bus=None if events is None else events,  # type: ignore[arg-type]
    )


def test_metadata_only_storage_and_scoped_use(tmp_path: Path) -> None:
    store = TestOnlyInMemorySecretBackend()
    instance = CredentialVault(tmp_path / "credentials.sqlite3", backend=store)
    metadata = instance.create(
        label="Example API",
        association="example",
        scope=("read", "write"),
        auth_method=AuthenticationMethod.API_TOKEN,
        secret="do-not-store-in-db",
    )
    raw_db = (tmp_path / "credentials.sqlite3").read_bytes()
    assert b"do-not-store-in-db" not in raw_db
    assert instance.metadata(metadata.credential_id) == metadata
    assert (
        instance.scoped_use(metadata.credential_id, association="example", scope=("read",))
        == b"do-not-store-in-db"
    )
    reopened = CredentialVault(tmp_path / "credentials.sqlite3", backend=store)
    assert reopened.metadata(metadata.credential_id) == metadata
    assert (
        reopened.scoped_use(metadata.credential_id, association="example", scope=("write",))
        == b"do-not-store-in-db"
    )
    assert instance.list(association="example") == (metadata,)
    with pytest.raises(CredentialUseDenied):
        instance.scoped_use(metadata.credential_id, association="other", scope=("read",))
    with pytest.raises(CredentialUseDenied):
        instance.scoped_use(metadata.credential_id, association="example", scope=("admin",))
    with pytest.raises(CredentialNotFound):
        instance.metadata(uuid4())


def test_close_releases_metadata_database_handle(tmp_path: Path) -> None:
    path = tmp_path / "credentials.sqlite3"
    instance = CredentialVault(path, backend=TestOnlyInMemorySecretBackend())
    instance.create(
        label="Close check",
        association="test",
        scope=("read",),
        auth_method=AuthenticationMethod.API_TOKEN,
        secret="close-check-secret",
    )
    instance.close()
    path.unlink()
    assert not path.exists()


def test_typed_credential_reference_binds_exact_host_operation_and_expiry(tmp_path: Path) -> None:
    clock = Clock()
    backend = TestOnlyInMemorySecretBackend()
    instance = CredentialVault(
        tmp_path / "credentials.sqlite3",
        backend=backend,
        clock=clock,
    )
    metadata = instance.create(
        label="Bound token",
        association="synthetic-service",
        scope=("read",),
        auth_method=AuthenticationMethod.API_TOKEN,
        secret="bound-secret",
    )
    reference = instance.issue_ref(
        metadata.credential_id,
        integration_id="synthetic.integration",
        package_version="1.0.0",
        package_hash="a" * 64,
        operation="network.request",
        destination="https://service.synthetic.test:443",
        workspace_id="workspace-a",
        scope=("read",),
    )
    assert isinstance(reference, CredentialRef)
    assert (
        instance.resolve_ref(
            reference,
            integration_id="synthetic.integration",
            package_version="1.0.0",
            package_hash="a" * 64,
            operation="network.request",
            destination="https://service.synthetic.test:443",
            workspace_id="workspace-a",
            scope=("read",),
        )
        == b"bound-secret"
    )
    with pytest.raises(CredentialUseDenied):
        instance.resolve_ref(
            replace(reference, _proof=b"\0" * 32),
            integration_id="synthetic.integration",
            package_version="1.0.0",
            package_hash="a" * 64,
            operation="network.request",
            destination="https://service.synthetic.test:443",
            workspace_id="workspace-a",
            scope=("read",),
        )
    mismatches = (
        (
            "b" * 64,
            "network.request",
            "https://service.synthetic.test:443",
            "workspace-a",
            ("read",),
        ),
        (
            "a" * 64,
            "network.request",
            "https://other.synthetic.test:443",
            "workspace-a",
            ("read",),
        ),
        (
            "a" * 64,
            "network.request",
            "https://service.synthetic.test:443",
            "workspace-b",
            ("read",),
        ),
        (
            "a" * 64,
            "filesystem.read",
            "https://service.synthetic.test:443",
            "workspace-a",
            ("read",),
        ),
        (
            "a" * 64,
            "network.request",
            "https://service.synthetic.test:443",
            "workspace-a",
            ("write",),
        ),
    )
    for package_hash, operation, destination, workspace_id, scope in mismatches:
        with pytest.raises(CredentialUseDenied):
            instance.resolve_ref(
                reference,
                integration_id="synthetic.integration",
                package_version="1.0.0",
                package_hash=package_hash,
                operation=operation,
                destination=destination,
                workspace_id=workspace_id,
                scope=scope,
            )
    instance.close()
    restarted = CredentialVault(
        tmp_path / "credentials.sqlite3",
        backend=backend,
        clock=clock,
    )
    with pytest.raises(CredentialUseDenied):
        restarted.resolve_ref(
            reference,
            integration_id="synthetic.integration",
            package_version="1.0.0",
            package_hash="a" * 64,
            operation="network.request",
            destination="https://service.synthetic.test:443",
            workspace_id="workspace-a",
            scope=("read",),
        )
    clock.value += timedelta(minutes=6)
    with pytest.raises(CredentialUseDenied):
        restarted.resolve_ref(
            reference,
            integration_id="synthetic.integration",
            package_version="1.0.0",
            package_hash="a" * 64,
            operation="network.request",
            destination="https://service.synthetic.test:443",
            workspace_id="workspace-a",
            scope=("read",),
        )
    restarted.close()


def test_update_rotate_revoke_delete_and_expiry(tmp_path: Path) -> None:
    clock = Clock()
    instance = vault(tmp_path, clock=clock)
    metadata = instance.create(
        label="Token",
        association="service",
        scope=("read",),
        auth_method=AuthenticationMethod.API_TOKEN,
        secret=b"first",
        expires_at=clock.value + timedelta(hours=1),
    )
    updated = instance.update(metadata.credential_id, label="Updated", scope=("read", "write"))
    assert updated.label == "Updated"
    rotated = instance.rotate(metadata.credential_id, b"second")
    assert (
        instance.scoped_use(rotated.credential_id, association="service", scope=("write",))
        == b"second"
    )
    clock.value += timedelta(hours=2)
    assert instance.status(metadata.credential_id) is CredentialStatus.EXPIRED
    with pytest.raises(CredentialUseDenied):
        instance.scoped_use(metadata.credential_id, association="service", scope=("read",))
    revoked = instance.revoke(metadata.credential_id)
    assert revoked.status is CredentialStatus.REVOKED
    assert instance.revoke(metadata.credential_id).status is CredentialStatus.REVOKED
    with pytest.raises(CredentialUseDenied):
        instance.scoped_use(metadata.credential_id, association="service", scope=("read",))
    deleted = instance.delete(metadata.credential_id)
    assert deleted.status is CredentialStatus.DELETED
    assert instance.delete(metadata.credential_id).status is CredentialStatus.DELETED
    with pytest.raises(CredentialUseDenied):
        instance.scoped_use(metadata.credential_id, association="service", scope=("read",))


@pytest.mark.asyncio
async def test_status_events_are_metadata_only(tmp_path: Path) -> None:
    events = EventSink()
    instance = vault(tmp_path, events=events)
    metadata = instance.create(
        label="Token",
        association="service",
        scope=("read",),
        auth_method=AuthenticationMethod.API_TOKEN,
        secret="event-secret",
    )
    await asyncio.sleep(0)
    assert [event.event_type for event in events.events] == [EventType.CREDENTIAL_CHANGED]
    payload = events.events[0].payload
    assert isinstance(payload, CredentialChanged)
    assert metadata.credential_id == payload.credential_id
    assert "event-secret" not in repr(events.events)
    assert "event-secret" not in repr(metadata)


def test_secure_backend_fail_closed_without_plaintext_fallback(tmp_path: Path) -> None:
    backend = UnavailableSecretBackend()
    with pytest.raises(CredentialVaultError):
        backend.put("jarvis:credential:test", b"secret")
    with pytest.raises(CredentialVaultError):
        backend.get("jarvis:credential:test")
    with pytest.raises(CredentialVaultError):
        backend.delete("jarvis:credential:test")
    instance = CredentialVault(
        tmp_path / "credentials.sqlite3",
        backend=UnavailableSecretBackend(),
    )
    with pytest.raises(CredentialVaultError):
        instance.create(
            label="Token",
            association="service",
            scope=("read",),
            auth_method=AuthenticationMethod.API_TOKEN,
            secret="must-fail",
        )


def test_metadata_schema_refuses_future_and_secret_columns(tmp_path: Path) -> None:
    future = tmp_path / "future.sqlite3"
    with sqlite3.connect(future) as connection:
        connection.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        connection.execute("INSERT INTO schema_version VALUES (99)")
    with pytest.raises(CredentialVaultError):
        CredentialVault(future, backend=TestOnlyInMemorySecretBackend())

    unsafe = tmp_path / "unsafe.sqlite3"
    with sqlite3.connect(unsafe) as connection:
        connection.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        connection.execute("INSERT INTO schema_version VALUES (1)")
        connection.execute("CREATE TABLE credentials (credential_id TEXT, secret TEXT)")
    with pytest.raises(CredentialVaultError):
        CredentialVault(unsafe, backend=TestOnlyInMemorySecretBackend())


@pytest.mark.asyncio
async def test_generic_auth_code_local_callback_device_code_and_refresh(tmp_path: Path) -> None:
    instance = vault(tmp_path)
    service = GenericAuthenticationService(instance)
    provider = Provider()
    request = service.begin_authorization_code(
        provider, redirect_uri="http://127.0.0.1:8765/callback", scope=("read",)
    )
    state = request.authorization_url.split("state=", 1)[1].split("&", 1)[0]
    result = await service.complete_authorization_code(
        provider,
        state=state,
        code="one-time-code",
        association="example",
        label="Example OAuth",
    )
    assert result.access_credential.auth_method is AuthenticationMethod.OAUTH_AUTHORIZATION_CODE
    assert result.refresh_credential is not None
    assert (
        instance.scoped_use(
            result.refresh_credential.credential_id,
            association="example",
            scope=("read",),
        )
        == b"refresh-secret"
    )
    refreshed = await service.refresh(provider, result.refresh_credential.credential_id)
    assert refreshed.access_credential.status is CredentialStatus.ACTIVE
    assert provider.refresh_calls == [b"refresh-secret"]

    local_request = service.begin_authorization_code(
        provider, redirect_uri="http://127.0.0.1:8765/callback", scope=("read",)
    )
    local_state = local_request.authorization_url.split("state=", 1)[1].split("&", 1)[0]
    local = await service.complete_authorization_code(
        provider,
        state=local_state,
        code="one-time-code",
        association="example",
        label="Local OAuth",
        method=AuthenticationMethod.LOCAL_CALLBACK,
    )
    assert local.access_credential.auth_method is AuthenticationMethod.LOCAL_CALLBACK

    challenge = await service.begin_device_code(
        provider, association="example", label="Device OAuth", scope=("read",)
    )
    device = await service.complete_device_code(provider, challenge)
    assert device.access_credential.auth_method is AuthenticationMethod.OAUTH_DEVICE_CODE
    with pytest.raises(AuthenticationError):
        await service.complete_device_code(provider, challenge)


def test_api_token_and_key_are_opaque_metadata_references(tmp_path: Path) -> None:
    instance = vault(tmp_path)
    service = GenericAuthenticationService(instance)
    token = service.store_api_token(
        label="Token", association="api", scope=("read",), secret="token-secret"
    )
    key = service.store_api_key(
        label="Key", association="api", scope=("read",), secret="key-secret"
    )
    assert token.credential_id != key.credential_id
    assert "token-secret" not in repr(token)
    assert "key-secret" not in repr(key)
    with pytest.raises(AuthenticationError):
        # API credentials have no provider refresh lifecycle.
        import asyncio as _asyncio

        _asyncio.run(
            GenericAuthenticationService(instance).refresh(Provider(), token.credential_id)
        )


def test_validation_and_backend_failures_are_sanitized(tmp_path: Path) -> None:
    from jarvis import credentials as module

    for value in ("", b"", 123, b"x" * 1_048_577):
        with pytest.raises(CredentialVaultError):
            module._secret_bytes(value)  # type: ignore[arg-type]
    invalid_scopes: tuple[Any, ...] = ("", ("",), ("bad\nvalue",), "read")
    for value in invalid_scopes:
        with pytest.raises(CredentialVaultError):
            module._scope(value)  # type: ignore[arg-type]
    with pytest.raises(CredentialVaultError):
        module._text("bad\nvalue", "field", 20)
    with pytest.raises(CredentialVaultError):
        module._timestamp(datetime.now(), "timestamp")
    with pytest.raises(CredentialVaultError):
        module._parse_timestamp("not-a-timestamp")
    with pytest.raises(CredentialVaultError):
        module._parse_timestamp("2026-01-01T00:00:00")

    now = datetime(2026, 1, 1, tzinfo=UTC)
    invalid_metadata: tuple[tuple[Any, ...], ...] = (
        (
            "id",
            "label",
            "association",
            (),
            AuthenticationMethod.API_TOKEN,
            now,
            now,
            CredentialStatus.ACTIVE,
        ),
        (uuid4(), "label", "association", (), "api", now, now, CredentialStatus.ACTIVE),
        (
            uuid4(),
            "label",
            "association",
            (),
            AuthenticationMethod.API_TOKEN,
            now.replace(tzinfo=None),
            now,
            CredentialStatus.ACTIVE,
        ),
        (uuid4(), "label", "association", (), AuthenticationMethod.API_TOKEN, now, now, "active"),
    )
    for values in invalid_metadata:
        with pytest.raises(CredentialVaultError):
            CredentialMetadata(*values)
    with pytest.raises(CredentialVaultError):
        AuthTokenSet("access", None, now.replace(tzinfo=None), ("read",))
    with pytest.raises(CredentialVaultError):
        DeviceCodeChallenge(uuid4(), "https://auth.example/device", "code", "device", now, 0)
    with pytest.raises(CredentialVaultError):
        AuthorizationRequest("not-an-id", "https://auth.example", "http://localhost", ())  # type: ignore[arg-type]

    failing = CredentialVault(tmp_path / "failing.sqlite3", backend=FailingBackend(fail_put=True))
    with pytest.raises(CredentialVaultError) as error:
        failing.create(
            label="Token",
            association="service",
            scope=("read",),
            auth_method=AuthenticationMethod.API_TOKEN,
            secret="never-in-error",
        )
    assert "never-in-error" not in str(error.value)
    instance = vault(tmp_path / "normal")
    metadata = instance.create(
        label="Token",
        association="service",
        scope=("read",),
        auth_method=AuthenticationMethod.API_TOKEN,
        secret="secret",
    )
    with pytest.raises(CredentialVaultError):
        CredentialVault(
            tmp_path / "bad-clock.sqlite3",
            backend=TestOnlyInMemorySecretBackend(),
            clock=lambda: datetime.now(),
        )._now()
    with pytest.raises(CredentialVaultError):
        instance.update(metadata.credential_id, expires_at="bad")
    with pytest.raises(CredentialVaultError):
        instance.rotate(metadata.credential_id, "secret", expires_at="bad")

    failing_get = CredentialVault(
        tmp_path / "failing-get.sqlite3", backend=FailingBackend(fail_get=True)
    )
    get_metadata = failing_get.create(
        label="Token",
        association="service",
        scope=("read",),
        auth_method=AuthenticationMethod.API_TOKEN,
        secret="secret",
    )
    with pytest.raises(CredentialVaultError):
        failing_get.scoped_use(get_metadata.credential_id, association="service", scope=("read",))


@pytest.mark.asyncio
async def test_authentication_failures_and_pending_bounds(tmp_path: Path) -> None:
    instance = vault(tmp_path)
    service = GenericAuthenticationService(instance, max_pending=1)
    provider = Provider()
    request = service.begin_authorization_code(
        provider, redirect_uri="http://127.0.0.1/callback", scope=("read",)
    )
    with pytest.raises(AuthenticationError):
        service.begin_authorization_code(
            provider, redirect_uri="http://127.0.0.1/callback", scope=("read",)
        )
    with pytest.raises(AuthenticationError):
        await service.complete_authorization_code(
            provider, state="wrong", code="code", association="service", label="Token"
        )
    state = request.authorization_url.split("state=", 1)[1].split("&", 1)[0]
    with pytest.raises(AuthenticationError):
        await service.complete_authorization_code(
            provider,
            state=state,
            code="code",
            association="service",
            label="Token",
            method=AuthenticationMethod.API_TOKEN,
        )

    with pytest.raises(AuthenticationError):
        GenericAuthenticationService(instance, max_pending=0)


@pytest.mark.asyncio
async def test_malformed_device_provider_response_fails_closed(tmp_path: Path) -> None:
    service = GenericAuthenticationService(vault(tmp_path))
    with pytest.raises(AuthenticationError):
        await service.begin_device_code(
            BadDeviceProvider(), association="example", label="Device", scope=("read",)
        )


def test_revoke_reports_secure_cleanup_failure_without_secret(tmp_path: Path) -> None:
    backend = FailingBackend(fail_delete=True)
    instance = CredentialVault(tmp_path / "cleanup.sqlite3", backend=backend)
    metadata = instance.create(
        label="Token",
        association="service",
        scope=("read",),
        auth_method=AuthenticationMethod.API_TOKEN,
        secret="cleanup-secret",
    )
    with pytest.raises(CredentialVaultError) as error:
        instance.revoke(metadata.credential_id)
    assert "cleanup-secret" not in str(error.value)
    assert instance.status(metadata.credential_id) is CredentialStatus.REVOKED
