from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest
from jarvis.effect_attestation import (
    EffectAttestationError,
    EffectAttestationStatus,
    EffectAttestationStore,
    TrustedEffectObserver,
    _as_json,
)
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import Decision, Permission, PolicyRule, ScopeConstraint
from jarvis.permissions.policy import PolicyEngine
from jarvis.sandbox_proxies import (
    HostProxy,
    HostProxyDenied,
    HostProxyManifest,
    HostProxyRequest,
    NetworkRequest,
    ProxyCapability,
    ProxyKind,
)

HASH = "a" * 64


def _observer(
    store: EffectAttestationStore, state: str, activation_id: str
) -> TrustedEffectObserver:
    return store.observer("fixture", "1.0.0", HASH, state, activation_id)


def _invalid_replace(value: object, **changes: object) -> Callable[[], object]:
    return lambda: replace(cast(Any, value), **changes)


def test_shadow_attestation_proves_suppression_and_rejects_fake() -> None:
    store = EffectAttestationStore()
    observer = _observer(store, "SHADOW", "activation-1")
    attempt = observer.begin(
        action_id="write",
        request_id=uuid4(),
        broker="filesystem",
        target="fixture.txt",
        scope="workspace-a",
        requested_effect="filesystem write",
    )
    observer.complete(attempt, status=EffectAttestationStatus.SUPPRESSED, dispatched=False)
    attestation = store.attest(
        activation_id="activation-1",
        integration_id="fixture",
        integration_version="1.0.0",
        package_hash=HASH,
        activation_state="SHADOW",
    )
    assert attestation.zero_trusted_dispatch is True
    assert attestation.status is EffectAttestationStatus.SUPPRESSED
    assert store.is_trusted(attestation)
    assert not store.is_trusted(replace(attestation, attestation_id=uuid4()))
    assert not store.is_trusted(replace(attestation, package_hash="b" * 64))


def test_attestation_validation_and_future_schema_fail_closed(tmp_path: Path) -> None:
    store = EffectAttestationStore()
    with pytest.raises(EffectAttestationError):
        store.attest(
            activation_id="missing",
            integration_id="fixture",
            integration_version="1.0.0",
            package_hash=HASH,
            activation_state="SHADOW",
        )
    with pytest.raises(EffectAttestationError):
        store.observer("bad id", "1.0.0", HASH, "SHADOW", "activation")
    observer = _observer(store, "SHADOW", "activation-validation")
    attempt = observer.begin(
        action_id="probe",
        request_id=uuid4(),
        broker="filesystem",
        target="x",
        scope="y",
        requested_effect="read",
    )
    with pytest.raises(EffectAttestationError):
        observer.complete(attempt, status="not-a-status", dispatched=False)  # type: ignore[arg-type]

    path = tmp_path / "future.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE effect_schema(version INTEGER PRIMARY KEY)")
    connection.execute("INSERT INTO effect_schema(version) VALUES (99)")
    connection.commit()
    connection.close()
    with pytest.raises(EffectAttestationError):
        EffectAttestationStore(path)


def test_observation_queries_and_binding_checks() -> None:
    store = EffectAttestationStore()
    observer = _observer(store, "CANARY", "activation-query")
    attempt = observer.begin(
        action_id="process",
        request_id=uuid4(),
        broker="process",
        target="child",
        scope="fixture",
        requested_effect="process action",
    )
    observation = observer.complete(
        attempt, status=EffectAttestationStatus.EFFECT_CONFIRMED, dispatched=True
    )
    assert store.observations("activation-query") == (observation,)
    assert store.is_trusted_for(
        (observation.observation_id,), "activation-query", "CANARY", "fixture", "1.0.0", HASH
    )
    assert (
        store.is_trusted_attestation(
            uuid4(),
            activation_id="activation-query",
            activation_state="CANARY",
            integration_id="fixture",
            integration_version="1.0.0",
            package_hash=HASH,
        )
        is False
    )


def test_typed_effect_records_reject_malformed_security_metadata() -> None:
    store = EffectAttestationStore()
    observer = _observer(store, "CANARY", "activation-malformed")
    attempt = observer.begin(
        action_id="process",
        request_id=uuid4(),
        broker="process",
        target="child",
        scope="fixture",
        requested_effect="process action",
    )
    observation = observer.complete(
        attempt, status=EffectAttestationStatus.EFFECT_CONFIRMED, dispatched=True
    )
    attestation = store.attest(
        activation_id="activation-malformed",
        integration_id="fixture",
        integration_version="1.0.0",
        package_hash=HASH,
        activation_state="CANARY",
    )

    invalid_attempts = (
        _invalid_replace(attempt, attempt_id="bad"),
        _invalid_replace(attempt, request_id="bad"),
        _invalid_replace(attempt, package_hash="bad"),
        _invalid_replace(attempt, correlation_id="bad"),
        _invalid_replace(attempt, started_at="bad"),
    )
    for invalid in invalid_attempts:
        with pytest.raises(EffectAttestationError):
            invalid()
    invalid_observations = (
        _invalid_replace(observation, observation_id="bad"),
        _invalid_replace(observation, request_id="bad"),
        _invalid_replace(observation, allowed=1),
        _invalid_replace(observation, result_category="bad"),
        _invalid_replace(
            observation, result_category=EffectAttestationStatus.SUPPRESSED, dispatched=True
        ),
        _invalid_replace(observation, allowed=False),
        _invalid_replace(observation, correlation_id="bad"),
        _invalid_replace(observation, observed_at="bad"),
    )
    for invalid in invalid_observations:
        with pytest.raises(EffectAttestationError):
            invalid()
    invalid_attestations = (
        _invalid_replace(attestation, attestation_id="bad"),
        _invalid_replace(attestation, status="bad"),
        _invalid_replace(attestation, observation_ids=()),
        _invalid_replace(attestation, observation_ids=("bad",)),
        _invalid_replace(attestation, request_count=-1),
        _invalid_replace(attestation, dispatched_count=2),
        _invalid_replace(attestation, zero_trusted_dispatch=1),
        _invalid_replace(attestation, zero_trusted_dispatch=True),
        _invalid_replace(attestation, effect_descriptions=("",)),
        _invalid_replace(attestation, created_at="bad"),
    )
    for invalid in invalid_attestations:
        with pytest.raises(EffectAttestationError):
            invalid()
    with pytest.raises(EffectAttestationError):
        EffectAttestationStore()._begin(object(), attempt)
    with pytest.raises(EffectAttestationError):
        EffectAttestationStore()._complete(
            object(), attempt, EffectAttestationStatus.EFFECT_CONFIRMED, True, True
        )
    with pytest.raises(TypeError):
        _as_json(object())


def test_canary_dispatch_is_trusted_and_package_binding_is_exact() -> None:
    store = EffectAttestationStore()
    observer = _observer(store, "CANARY", "activation-2")
    attempt = observer.begin(
        action_id="request",
        request_id=uuid4(),
        broker="network",
        target="api.example.test",
        scope="api.example.test",
        requested_effect="network request",
    )
    observer.complete(attempt, status=EffectAttestationStatus.EFFECT_CONFIRMED, dispatched=True)
    attestation = store.attest(
        activation_id="activation-2",
        integration_id="fixture",
        integration_version="1.0.0",
        package_hash=HASH,
        activation_state="CANARY",
    )
    assert attestation.dispatched_count == 1
    assert attestation.status is EffectAttestationStatus.EFFECT_CONFIRMED
    with pytest.raises(ValueError):
        store.attest(
            activation_id="activation-2",
            integration_id="fixture",
            integration_version="2.0.0",
            package_hash=HASH,
            activation_state="CANARY",
        )


def test_restart_reconciles_unfinished_dispatch_as_unknown(tmp_path: Path) -> None:
    path = tmp_path / "effects.sqlite"
    store = EffectAttestationStore(path)
    completed_observer = _observer(store, "CANARY", "activation-persisted")
    completed_attempt = completed_observer.begin(
        action_id="request",
        request_id=uuid4(),
        broker="network",
        target="fixture",
        scope="fixture",
        requested_effect="network request",
    )
    completed_observer.complete(
        completed_attempt, status=EffectAttestationStatus.EFFECT_CONFIRMED, dispatched=True
    )
    persisted = store.attest(
        activation_id="activation-persisted",
        integration_id="fixture",
        integration_version="1.0.0",
        package_hash=HASH,
        activation_state="CANARY",
    )
    observer = _observer(store, "CANARY", "activation-restart")
    observer.begin(
        action_id="process",
        request_id=uuid4(),
        broker="process",
        target="fixture-child",
        scope="fixture",
        requested_effect="process action",
    )
    store.close()
    restarted = EffectAttestationStore(path)
    assert restarted.is_trusted(persisted)
    attestation = restarted.attest(
        activation_id="activation-restart",
        integration_id="fixture",
        integration_version="1.0.0",
        package_hash=HASH,
        activation_state="CANARY",
    )
    assert attestation.status is EffectAttestationStatus.UNKNOWN_OUTCOME
    assert attestation.unknown_count == 1
    restarted.close()


def _allow_network() -> PermissionBroker:
    return PermissionBroker(
        PolicyEngine(
            (
                PolicyRule(
                    "fixture-network",
                    Permission.NETWORK_REQUEST,
                    Decision.ALLOW,
                    ScopeConstraint(hosts=("api.example.test",)),
                    frozenset({"sandbox.network.request"}),
                ),
            )
        )
    )


@pytest.mark.asyncio
async def test_shadow_host_proxy_never_dispatches_network_request() -> None:
    manifest = HostProxyManifest(
        "fixture",
        "1.0.0",
        HASH,
        (ProxyCapability("net", ProxyKind.NETWORK, ("request",), Permission.NETWORK_REQUEST),),
        network_origins=("https://api.example.test",),
    )
    store = EffectAttestationStore()
    observer = _observer(store, "SHADOW", "activation-host")
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=b"unexpected", request=request)

    proxy = HostProxy(
        manifest,
        _allow_network(),
        effect_observer=observer,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        resolver=lambda _: ("93.184.216.34",),
    )
    request = HostProxyRequest(uuid4(), "fixture", HASH, "net", "request", uuid4())
    try:
        with pytest.raises(HostProxyDenied):
            await proxy.network(NetworkRequest(request, "GET", "https://api.example.test/"))
        assert calls == 0
        attestation = store.attest(
            activation_id="activation-host",
            integration_id="fixture",
            integration_version="1.0.0",
            package_hash=HASH,
            activation_state="SHADOW",
        )
        assert attestation.zero_trusted_dispatch
    finally:
        await proxy.close()
