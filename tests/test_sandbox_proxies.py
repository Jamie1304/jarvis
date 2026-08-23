from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

import httpx
import jarvis.sandbox_proxies as proxy_module
import pytest
from jarvis.credentials import (
    AuthenticationMethod,
    CredentialVault,
    TestOnlyInMemorySecretBackend,
)
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import Decision, Permission, PolicyRule, ScopeConstraint
from jarvis.permissions.policy import PolicyEngine
from jarvis.sandbox_proxies import (
    CredentialBinding,
    CredentialLocation,
    FileListRequest,
    FileReadRequest,
    FilesystemRoot,
    FilesystemRootKind,
    FileWriteRequest,
    HostProxy,
    HostProxyApprovalRequired,
    HostProxyBoundExceeded,
    HostProxyDenied,
    HostProxyError,
    HostProxyManifest,
    HostProxyRequest,
    InMemoryHostProxyAudit,
    NetworkRequest,
    ProxyCapability,
    ProxyKind,
    TypedActionRequest,
)

HASH = "a" * 64


def request(manifest: HostProxyManifest, *, capability: str, action: str) -> HostProxyRequest:
    return HostProxyRequest(
        uuid4(), manifest.integration_id, manifest.package_hash, capability, action, uuid4()
    )


def broker_for(*rules: PolicyRule) -> PermissionBroker:
    return PermissionBroker(PolicyEngine(tuple(rules)))


def allow(
    permission: Permission, action: str, *, host: str = "", path: str = "", app: str = ""
) -> PolicyRule:
    return PolicyRule(
        f"allow.{action}",
        permission,
        Decision.ALLOW,
        ScopeConstraint(
            hosts=(host,) if host else (),
            paths=(path,) if path else (),
            applications=(app,) if app else (),
        ),
        frozenset({action}),
    )


def network_manifest(
    *,
    origin: str = "https://api.example.test:443",
    credential_bindings: tuple[CredentialBinding, ...] = (),
    max_response_bytes: int = 1_048_576,
) -> HostProxyManifest:
    return HostProxyManifest(
        "demo.integration",
        "1.0.0",
        HASH,
        (ProxyCapability("net", ProxyKind.NETWORK, ("request",), Permission.NETWORK_REQUEST),),
        network_origins=(origin,),
        credential_bindings=credential_bindings,
        max_response_bytes=max_response_bytes,
    )


@pytest.mark.asyncio
async def test_network_proxy_is_exact_origin_bounded_and_audited() -> None:
    manifest = network_manifest()
    audit = InMemoryHostProxyAudit()

    def handler(http_request: httpx.Request) -> httpx.Response:
        assert http_request.url.host == "api.example.test"
        return httpx.Response(200, content=b"ok", request=http_request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    proxy = HostProxy(
        manifest,
        broker_for(
            allow(Permission.NETWORK_REQUEST, "sandbox.network.request", host="api.example.test")
        ),
        audit=audit,
        http_client=client,
        resolver=lambda _: ("93.184.216.34",),
    )
    try:
        result = await proxy.network(
            NetworkRequest(
                request(manifest, capability="net", action="request"),
                "GET",
                "https://api.example.test/path",
            )
        )
        assert result.body == b"ok"
        assert audit.events[-1].outcome == "effect_confirmed"
        with pytest.raises(HostProxyDenied):
            await proxy.network(
                NetworkRequest(
                    request(manifest, capability="net", action="request"),
                    "GET",
                    "https://other.example.test/path",
                )
            )
    finally:
        await proxy.close()
        await client.aclose()


@pytest.mark.asyncio
async def test_proxy_permission_approval_is_not_satisfied_by_sandbox_input() -> None:
    manifest = network_manifest()
    proxy = HostProxy(
        manifest,
        broker_for(
            PolicyRule(
                "approval.network",
                Permission.NETWORK_REQUEST,
                Decision.REQUIRE_APPROVAL,
                ScopeConstraint(hosts=("api.example.test",)),
                frozenset({"sandbox.network.request"}),
            )
        ),
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"must-not-run"))
        ),
        resolver=lambda _: ("93.184.216.34",),
    )
    try:
        with pytest.raises(HostProxyApprovalRequired):
            await proxy.network(
                NetworkRequest(
                    request(manifest, capability="net", action="request"),
                    "GET",
                    "https://api.example.test/",
                )
            )
    finally:
        await proxy.close()


@pytest.mark.asyncio
async def test_network_proxy_denies_private_redirect_and_oversized_response() -> None:
    manifest = network_manifest()

    def redirect(http_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302, headers={"location": "https://api.example.test/next"}, request=http_request
        )

    proxy = HostProxy(
        manifest,
        broker_for(
            allow(Permission.NETWORK_REQUEST, "sandbox.network.request", host="api.example.test")
        ),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(redirect)),
        resolver=lambda _: ("93.184.216.34",),
    )
    with pytest.raises(HostProxyDenied):
        await proxy.network(
            NetworkRequest(
                request(manifest, capability="net", action="request"),
                "GET",
                "https://api.example.test/",
            )
        )
    await proxy.close()

    private_proxy = HostProxy(
        manifest,
        broker_for(
            allow(Permission.NETWORK_REQUEST, "sandbox.network.request", host="api.example.test")
        ),
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"ok"))
        ),
        resolver=lambda _: ("10.0.0.4",),
    )
    with pytest.raises(HostProxyDenied):
        await private_proxy.network(
            NetworkRequest(
                request(manifest, capability="net", action="request"),
                "GET",
                "https://api.example.test/",
            )
        )
    await private_proxy.close()

    large_manifest = network_manifest(max_response_bytes=4)
    large_proxy = HostProxy(
        large_manifest,
        broker_for(
            allow(Permission.NETWORK_REQUEST, "sandbox.network.request", host="api.example.test")
        ),
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"12345"))
        ),
        resolver=lambda _: ("93.184.216.34",),
    )
    with pytest.raises(HostProxyBoundExceeded):
        await large_proxy.network(
            NetworkRequest(
                request(large_proxy.manifest, capability="net", action="request"),
                "GET",
                "https://api.example.test/",
            )
        )
    await large_proxy.close()


@pytest.mark.asyncio
async def test_filesystem_proxy_allows_only_declared_roots_and_new_files(tmp_path: Path) -> None:
    package_data = tmp_path / "package-data"
    user_data = tmp_path / "approved-user"
    forbidden = tmp_path / "trusted-core"
    package_data.mkdir()
    user_data.mkdir()
    forbidden.mkdir()
    (forbidden / "secret.txt").write_text("no", encoding="utf-8")
    manifest = HostProxyManifest(
        "demo.integration",
        "1.0.0",
        HASH,
        (
            ProxyCapability(
                "read", ProxyKind.FILESYSTEM, ("read", "list"), Permission.FILESYSTEM_READ
            ),
            ProxyCapability("write", ProxyKind.FILESYSTEM, ("write",), Permission.FILESYSTEM_WRITE),
        ),
        filesystem_roots=(
            FilesystemRoot("pkg", package_data, FilesystemRootKind.PACKAGE_DATA, True),
            FilesystemRoot("user", user_data, FilesystemRootKind.APPROVED_USER, True),
        ),
    )
    broker = broker_for(
        allow(Permission.FILESYSTEM_READ, "sandbox.filesystem.read", path=str(package_data)),
        allow(Permission.FILESYSTEM_READ, "sandbox.filesystem.list", path=str(package_data)),
        allow(Permission.FILESYSTEM_WRITE, "sandbox.filesystem.write", path=str(package_data)),
    )
    proxy = HostProxy(manifest, broker, forbidden_roots=(forbidden,))
    try:
        context = request(manifest, capability="write", action="write")
        await proxy.write_file(FileWriteRequest(context, "pkg", "result.txt", b"result"))
        assert (
            await proxy.read_file(
                FileReadRequest(
                    request(manifest, capability="read", action="read"), "pkg", "result.txt"
                )
            )
            == b"result"
        )
        assert (
            await proxy.list_files(
                FileListRequest(request(manifest, capability="read", action="list"), "pkg")
            )
        )[0].name == "result.txt"
        with pytest.raises(HostProxyDenied):
            await proxy.read_file(
                FileReadRequest(
                    request(manifest, capability="read", action="read"),
                    "pkg",
                    "../trusted-core/secret.txt",
                )
            )
        with pytest.raises(HostProxyDenied):
            await proxy.write_file(FileWriteRequest(context, "pkg", "result.txt", b"overwrite"))
        with pytest.raises(HostProxyDenied):
            await proxy.read_file(
                FileReadRequest(
                    request(manifest, capability="read", action="read"), "user", ".git/config"
                )
            )
    finally:
        await proxy.close()


@pytest.mark.asyncio
async def test_credentials_are_opaque_and_resolved_only_on_trusted_side(tmp_path: Path) -> None:
    manifest = network_manifest(
        credential_bindings=(
            CredentialBinding("api", "demo-api", CredentialLocation.BEARER, ("read",)),
        )
    )
    vault = CredentialVault(
        tmp_path / "credentials.sqlite", backend=TestOnlyInMemorySecretBackend()
    )
    credential = vault.create(
        label="test",
        association="demo-api",
        scope=("read",),
        auth_method=AuthenticationMethod.API_TOKEN,
        secret="secret-token",
    )
    wrong_credential = vault.create(
        label="wrong",
        association="other-api",
        scope=("read",),
        auth_method=AuthenticationMethod.API_TOKEN,
        secret="wrong-secret",
    )
    seen: list[str] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        seen.append(http_request.headers["authorization"])
        return httpx.Response(200, content=b"opaque", request=http_request)

    proxy = HostProxy(
        manifest,
        broker_for(
            allow(Permission.NETWORK_REQUEST, "sandbox.network.request", host="api.example.test")
        ),
        vault=vault,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        resolver=lambda _: ("93.184.216.34",),
    )
    try:
        response = await proxy.network(
            NetworkRequest(
                request(manifest, capability="net", action="request"),
                "GET",
                "https://api.example.test/",
                credential_ref=credential.credential_id,
                credential_binding_id="api",
                credential_scope=("read",),
            )
        )
        assert response.body == b"opaque"
        assert seen == ["Bearer secret-token"]
        with pytest.raises(HostProxyDenied):
            await proxy.network(
                NetworkRequest(
                    request(manifest, capability="net", action="request"),
                    "GET",
                    "https://api.example.test/",
                    credential_ref=credential.credential_id,
                    credential_binding_id="api",
                    credential_scope=("write",),
                )
            )
        with pytest.raises(HostProxyDenied):
            await proxy.network(
                NetworkRequest(
                    request(manifest, capability="net", action="request"),
                    "GET",
                    "https://api.example.test/",
                    credential_ref=wrong_credential.credential_id,
                    credential_binding_id="api",
                    credential_scope=("read",),
                )
            )
    finally:
        await proxy.close()
        vault.close()


@pytest.mark.asyncio
async def test_identity_manifest_action_and_process_boundaries_fail_closed() -> None:
    manifest = HostProxyManifest(
        "demo.integration",
        "1.0.0",
        HASH,
        (
            ProxyCapability(
                "proc", ProxyKind.PROCESS, ("start",), Permission.APPLICATION_LAUNCH, ("mode",)
            ),
        ),
    )
    proxy = HostProxy(
        manifest,
        broker_for(allow(Permission.APPLICATION_LAUNCH, "sandbox.process.start", app="proc")),
    )
    try:
        forged = HostProxyRequest(uuid4(), "other.integration", HASH, "proc", "start", uuid4())
        with pytest.raises(HostProxyDenied):
            await proxy.invoke_typed(
                TypedActionRequest(forged, {"mode": "safe"}),
                kind=ProxyKind.PROCESS,
                executor=_executor,
            )
        with pytest.raises(HostProxyDenied):
            await proxy.invoke_typed(
                TypedActionRequest(request(manifest, capability="proc", action="unknown"), {}),
                kind=ProxyKind.PROCESS,
                executor=_executor,
            )
        with pytest.raises(HostProxyDenied):
            await proxy.invoke_typed(
                TypedActionRequest(
                    request(manifest, capability="proc", action="start"), {"argv": ["cmd"]}
                ),
                kind=ProxyKind.PROCESS,
                executor=_executor,
            )
        assert await proxy.invoke_typed(
            TypedActionRequest(
                request(manifest, capability="proc", action="start"), {"mode": "safe"}
            ),
            kind=ProxyKind.PROCESS,
            executor=_executor,
        ) == {"ok": True}
    finally:
        await proxy.close()


async def _executor(action: str, payload: Mapping[str, object]) -> Mapping[str, object]:
    assert action == "start"
    assert payload == {"mode": "safe"}
    return {"ok": True}


def test_manifest_and_request_validation() -> None:
    with pytest.raises(HostProxyError):
        HostProxyManifest(
            "bad id",
            "1",
            HASH,
            (ProxyCapability("x", ProxyKind.NETWORK, ("read",), Permission.NETWORK_REQUEST),),
        )
    with pytest.raises(HostProxyError):
        HostProxyRequest(uuid4(), "demo.integration", "b" * 64, "x", "read", uuid4(), "bad\nuser")
    with pytest.raises(HostProxyError):
        NetworkRequest(
            request(network_manifest(), capability="net", action="request"),
            "GET",
            "https://api.example.test/",
            headers={"Authorization": "forged"},
        )


def test_proxy_contract_rejects_malformed_metadata_and_payloads(tmp_path: Path) -> None:
    with pytest.raises(HostProxyError):
        proxy_module._sha256("b" * 63, "hash")
    with pytest.raises(HostProxyError):
        proxy_module._identifier("bad space", "id")
    with pytest.raises(HostProxyBoundExceeded):
        proxy_module._json_value("x" * 65_537)
    with pytest.raises(HostProxyBoundExceeded):
        proxy_module._json_value([0] * 257)
    with pytest.raises(HostProxyError):
        proxy_module._json_value(float("nan"))
    with pytest.raises(HostProxyError):
        proxy_module._json_value(object())
    with pytest.raises(HostProxyDenied):
        proxy_module._origin("https://user:password@api.example.test/")
    with pytest.raises(HostProxyDenied):
        proxy_module._origin("ftp://api.example.test/")
    with pytest.raises(HostProxyDenied):
        proxy_module._path_text("folder\\file")
    with pytest.raises(HostProxyDenied):
        proxy_module._path_text(".git/config")
    file_path = tmp_path / "not-a-root"
    file_path.write_text("x", encoding="utf-8")
    with pytest.raises(HostProxyError):
        FilesystemRoot("root", file_path, FilesystemRootKind.PACKAGE_DATA)
    with pytest.raises(HostProxyError):
        CredentialBinding("api", "association", CredentialLocation.HEADER)
    with pytest.raises(HostProxyError):
        CredentialBinding("api", "association", CredentialLocation.BEARER, header_name="X-Key")
    with pytest.raises(HostProxyError):
        ProxyCapability("bad", ProxyKind.NETWORK, ("read", "read"), Permission.NETWORK_REQUEST)
    with pytest.raises(HostProxyError):
        ProxyCapability("bad", "network", ("read",), Permission.NETWORK_REQUEST)  # type: ignore[arg-type]
    with pytest.raises(HostProxyError):
        FilesystemRoot("root", tmp_path, "package_data", "yes")  # type: ignore[arg-type]
    with pytest.raises(HostProxyError):
        CredentialBinding("api", "association", "bearer")  # type: ignore[arg-type]
    with pytest.raises(HostProxyError):
        CredentialBinding("api", "association", CredentialLocation.BEARER, ("",))
    with pytest.raises(HostProxyError):
        CredentialBinding("api", "association", CredentialLocation.HEADER, header_name="bad name")
    with pytest.raises(HostProxyBoundExceeded):
        proxy_module._json_value({str(index): index for index in range(257)})
    with pytest.raises(HostProxyBoundExceeded):
        proxy_module._json_value({"value": "x" * 65_530})
    with pytest.raises(HostProxyBoundExceeded):
        proxy_module._json_value([[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]])
    assert proxy_module._json_value(1.5) == 1.5
    with pytest.raises(HostProxyError):
        proxy_module._json_value({1: "bad"})
    with pytest.raises(HostProxyDenied):
        proxy_module._origin("https://*.example.test/")
    with pytest.raises(HostProxyDenied):
        proxy_module._origin("https://api.example.test:bad/")
    with pytest.raises(HostProxyDenied):
        proxy_module._origin("https://api.example.test/#fragment")
    with pytest.raises(HostProxyDenied):
        proxy_module._path_text("folder/")
    with pytest.raises(HostProxyError):
        FilesystemRoot("root", Path("relative"), FilesystemRootKind.PACKAGE_DATA)
    with pytest.raises(HostProxyError):
        CredentialBinding("api", "association", CredentialLocation.BEARER, ("",))
    with pytest.raises(HostProxyError):
        NetworkRequest(
            request(network_manifest(), capability="net", action="request"),
            "TRACE",
            "https://api.example.test/",
        )
    with pytest.raises(HostProxyBoundExceeded):
        NetworkRequest(
            request(network_manifest(), capability="net", action="request"),
            "GET",
            "https://api.example.test/",
            body=b"x" * (proxy_module._MAX_BODY_BYTES + 1),
        )
    with pytest.raises(HostProxyDenied):
        NetworkRequest(
            request(network_manifest(), capability="net", action="request"),
            "GET",
            "https://api.example.test/",
            credential_ref="not-a-uuid",  # type: ignore[arg-type]
        )
    with pytest.raises(HostProxyDenied):
        NetworkRequest(
            request(network_manifest(), capability="net", action="request"),
            "GET",
            "https://api.example.test/",
            credential_binding_id="api",
        )
    with pytest.raises(HostProxyError):
        NetworkRequest(
            request(network_manifest(), capability="net", action="request"),
            "GET",
            "https://api.example.test/",
            credential_ref=uuid4(),
            credential_scope=("",),
        )
    capability = ProxyCapability("one", ProxyKind.NETWORK, ("read",), Permission.NETWORK_REQUEST)
    with pytest.raises(HostProxyError):
        HostProxyManifest("demo.integration", "1", HASH, (capability, capability))
    with pytest.raises(HostProxyError):
        HostProxyManifest("demo.integration", "1", HASH, (capability,), timeout_seconds=0)
    root = FilesystemRoot("root", tmp_path, FilesystemRootKind.PACKAGE_DATA)
    with pytest.raises(HostProxyError):
        HostProxyManifest(
            "demo.integration", "1", HASH, (capability,), filesystem_roots=(root, root)
        )
    binding = CredentialBinding("binding", "association", CredentialLocation.BEARER)
    with pytest.raises(HostProxyError):
        HostProxyManifest(
            "demo.integration", "1", HASH, (capability,), credential_bindings=(binding, binding)
        )
    with pytest.raises(HostProxyError):
        HostProxy("bad", broker_for())  # type: ignore[arg-type]
    assert proxy_module._literal_addresses("127.0.0.1") == ("127.0.0.1",)
    assert proxy_module._resolve_addresses("localhost")


@pytest.mark.asyncio
async def test_network_redirect_opt_in_and_typed_executor_failure(tmp_path: Path) -> None:
    manifest = network_manifest()
    redirect_manifest = HostProxyManifest(
        manifest.integration_id,
        manifest.package_version,
        manifest.package_hash,
        manifest.capabilities,
        network_origins=manifest.network_origins,
        allow_redirects=True,
    )
    calls = 0

    def handler(http_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(302, headers={"location": "/next"}, request=http_request)
        return httpx.Response(200, content=b"redirected", request=http_request)

    proxy = HostProxy(
        redirect_manifest,
        broker_for(
            allow(Permission.NETWORK_REQUEST, "sandbox.network.request", host="api.example.test")
        ),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        resolver=lambda _: ("93.184.216.34",),
    )
    try:
        response = await proxy.network(
            NetworkRequest(
                request(redirect_manifest, capability="net", action="request"),
                "GET",
                "https://api.example.test/",
            )
        )
        assert response.body == b"redirected"
    finally:
        await proxy.close()

    process_manifest = HostProxyManifest(
        "typed.integration",
        "1.0.0",
        HASH,
        (ProxyCapability("device", ProxyKind.DEVICE, ("use",), Permission.CAMERA_READ, ("x",)),),
    )
    device_proxy = HostProxy(
        process_manifest,
        broker_for(allow(Permission.CAMERA_READ, "sandbox.device.use", app="device")),
    )

    async def failing_executor(action: str, payload: Mapping[str, object]) -> Mapping[str, object]:
        del action, payload
        raise RuntimeError("device failed")

    try:
        with pytest.raises(proxy_module.HostProxyEffectUnknown):
            await device_proxy.invoke_typed(
                TypedActionRequest(
                    request(process_manifest, capability="device", action="use"),
                    {"x": "one"},
                ),
                kind=ProxyKind.DEVICE,
                executor=failing_executor,
            )
    finally:
        await device_proxy.close()


@pytest.mark.asyncio
async def test_proxy_effect_and_file_response_failures_are_bounded(tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    (root / "large.txt").write_bytes(b"large")
    manifest = HostProxyManifest(
        "file.integration",
        "1.0.0",
        HASH,
        (
            ProxyCapability("read", ProxyKind.FILESYSTEM, ("read",), Permission.FILESYSTEM_READ),
            ProxyCapability("write", ProxyKind.FILESYSTEM, ("write",), Permission.FILESYSTEM_WRITE),
        ),
        filesystem_roots=(FilesystemRoot("data", root, FilesystemRootKind.PACKAGE_DATA, True),),
        max_response_bytes=4,
    )
    proxy = HostProxy(
        manifest,
        broker_for(
            allow(Permission.FILESYSTEM_READ, "sandbox.filesystem.read", path=str(root)),
            allow(Permission.FILESYSTEM_WRITE, "sandbox.filesystem.write", path=str(root)),
        ),
    )
    try:
        with pytest.raises(HostProxyBoundExceeded):
            await proxy.read_file(
                FileReadRequest(
                    request(manifest, capability="read", action="read"), "data", "large.txt"
                )
            )
        with pytest.raises(HostProxyBoundExceeded):
            await proxy.write_file(
                FileWriteRequest(
                    request(manifest, capability="write", action="write"),
                    "data",
                    "new.txt",
                    b"large",
                )
            )
        with pytest.raises(HostProxyError):
            await proxy.read_file(
                FileReadRequest(
                    request(manifest, capability="read", action="read"), "data", "missing.txt"
                )
            )
    finally:
        await proxy.close()

    network = network_manifest()

    def offline(http_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=http_request)

    offline_proxy = HostProxy(
        network,
        broker_for(
            allow(Permission.NETWORK_REQUEST, "sandbox.network.request", host="api.example.test")
        ),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(offline)),
        resolver=lambda _: ("93.184.216.34",),
    )
    try:
        with pytest.raises(proxy_module.HostProxyEffectUnknown):
            await offline_proxy.network(
                NetworkRequest(
                    request(network, capability="net", action="request"),
                    "GET",
                    "https://api.example.test/",
                )
            )
    finally:
        await offline_proxy.close()


@pytest.mark.asyncio
async def test_proxy_remaining_denials_and_private_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = network_manifest()
    with pytest.raises(HostProxyBoundExceeded):
        NetworkRequest(
            request(manifest, capability="net", action="request"),
            "GET",
            "https://api.example.test/",
            headers={"X-Test": "1"} | {f"X-{index}": "1" for index in range(64)},
        )
    proxy = HostProxy(manifest, broker_for())
    try:
        with pytest.raises(HostProxyDenied):
            await proxy.network(
                NetworkRequest(
                    request(manifest, capability="net", action="request"),
                    "GET",
                    "https://api.example.test/",
                )
            )
        with pytest.raises(HostProxyDenied):
            await proxy._validate_network_address("https://api.example.test/")
    finally:
        await proxy.close()

    private_manifest = HostProxyManifest(
        "local.integration",
        "1.0.0",
        HASH,
        (ProxyCapability("net", ProxyKind.NETWORK, ("request",), Permission.NETWORK_REQUEST),),
        network_origins=("http://127.0.0.1:80",),
        allow_private_addresses=True,
    )
    fake_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"local", request=request)
        )
    )
    private_proxy = HostProxy(
        private_manifest,
        broker_for(allow(Permission.NETWORK_REQUEST, "sandbox.network.request", host="127.0.0.1")),
    )
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_: fake_client)
    try:
        assert (
            await private_proxy.network(
                NetworkRequest(
                    request(private_manifest, capability="net", action="request"),
                    "GET",
                    "http://127.0.0.1/",
                )
            )
        ).body == b"local"
    finally:
        await private_proxy.close()
        await fake_client.aclose()

    invalid_proxy = HostProxy(
        manifest,
        broker_for(),
        resolver=lambda _: ("not-an-address",),
    )
    try:
        with pytest.raises(HostProxyDenied):
            await invalid_proxy._validate_network_address("https://api.example.test/")
    finally:
        await invalid_proxy.close()

    error_proxy = HostProxy(
        manifest, broker_for(), resolver=lambda _: (_ for _ in ()).throw(OSError())
    )
    try:
        with pytest.raises(HostProxyDenied):
            await error_proxy._validate_network_address("https://api.example.test/")
    finally:
        await error_proxy.close()

    file_root = tmp_path / "files"
    file_root.mkdir()
    file_manifest = HostProxyManifest(
        "file-errors",
        "1.0.0",
        HASH,
        (ProxyCapability("read", ProxyKind.FILESYSTEM, ("read",), Permission.FILESYSTEM_READ),),
        filesystem_roots=(FilesystemRoot("root", file_root, FilesystemRootKind.PACKAGE_DATA),),
    )
    file_proxy = HostProxy(file_manifest, broker_for())
    try:
        with pytest.raises(HostProxyDenied):
            file_proxy._safe_path("missing", "x", write=False)
        with pytest.raises(HostProxyDenied):
            file_proxy._safe_path("root", "", write=False)
        with pytest.raises(HostProxyDenied):
            file_proxy._safe_path("root", "x", write=True)
        with pytest.raises(HostProxyDenied):
            await file_proxy.invoke_typed(
                TypedActionRequest(request(file_manifest, capability="read", action="read"), {}),
                kind=ProxyKind.NETWORK,
                executor=_executor,
            )
    finally:
        await file_proxy.close()
