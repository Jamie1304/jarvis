"""D6B1H3 trusted target permission binding and broker authority matrix."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest
from jarvis.capabilities import (
    CapabilityActionSpec,
    EffectClassification,
    EffectMetadata,
    Reversibility,
)
from jarvis.integration_package import (
    IntegrationPackage,
    PackageBoundary,
    PackageEntry,
    PackageLayout,
    PackageLifecycle,
    PackageProvenance,
)
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    Decision,
    Permission,
    PermissionScope,
    PolicyRule,
    Risk,
    ScopeConstraint,
)
from jarvis.permissions.policy import PolicyEngine
from jarvis.production_capability import (
    ProductionCapabilityError,
    ProductionHostOperationBridge,
    TrustedHostOperation,
)
from jarvis.sandbox_proxies import HostProxy, HostProxyDenied, HostProxyManifest
from jarvis.tools.models import SemanticVersion


@pytest.mark.asyncio
async def test_d6b1h3_fresh_native_allow_and_deny_reach_real_broker(tmp_path: Path) -> None:
    """Exercise the ApplicationRuntime -> worker -> bridge -> broker route."""

    # The native run is intentionally separate from the direct matrix above:
    # a passing in-process bridge test cannot stand in for AppContainer IPC.
    from jarvis.agent_runtime import AgentLoop
    from jarvis.capabilities import EnvironmentGraph
    from jarvis.capability_factory import FactoryStrategy, SolutionReport, WorkspaceContext
    from jarvis.core.config import Settings
    from jarvis.credentials import TestOnlyInMemorySecretBackend
    from jarvis.discovery.models import CapabilityGap
    from jarvis.production_capability import AgentRuntimeCapabilityGenerator
    from jarvis.runtime import ApplicationRuntime, RuntimeStatus

    class Proposal:
        async def propose(self, prompt: str, **kwargs: object) -> str:
            del prompt, kwargs
            return (
                '{"name":"permission target","description":"bounded target",'
                '"actions":[{"action_id":"observe","semantic_name":"Observe",'
                '"description":"Observe one target value",'
                '"input_schema":{"type":"object","properties":{"value":{"type":"string"}},'
                '"required":["value"],"additionalProperties":false},'
                '"output_schema":{"type":"object","properties":{"result":{"type":"string"}},'
                '"required":["result"],"additionalProperties":false},'
                '"effect":{"classification":"observation","reversibility":"read_only"},'
                '"permissions":["camera.read"],"operation":"trusted.target.read"}]}'
            )

    async def run(decision: Decision) -> int:
        calls = 0

        def target(arguments: Mapping[str, object]) -> Mapping[str, object]:
            nonlocal calls
            calls += 1
            return {"result": f"trusted:{arguments['value']}"}

        runtime = ApplicationRuntime.create(
            Settings(
                environment="test",
                app_data_dir=tmp_path / decision.value.lower(),
                ai_provider="ollama",
                _env_file=None,
            ),
            recovery_key_backend=TestOnlyInMemorySecretBackend(),
            permission_policy=PolicyEngine(
                (
                    PolicyRule(
                        f"camera.{decision.value.lower()}",
                        Permission.CAMERA_READ,
                        decision,
                        ScopeConstraint(),
                        frozenset({"sandbox.device.observe"}),
                    ),
                )
            ),
            trusted_host_operations={
                OPERATION: TrustedHostOperation(target, (Permission.CAMERA_READ,))
            },
        )
        assert runtime.status is RuntimeStatus.READY, runtime.error
        assert runtime.container is not None
        container = runtime.container
        generator = AgentRuntimeCapabilityGenerator(
            cast(AgentLoop, object()),
            container.package_store,
            provider=Proposal(),
        )
        gap = CapabilityGap(
            "permission-target", "observe", ("permission-target",), (), Risk.LOW, ()
        )
        generated = await generator.generate(
            gap,
            SolutionReport(gap),
            WorkspaceContext("d6b1h3"),
            EnvironmentGraph(),
            {},
            FactoryStrategy.GENERATE_ADAPTER,
        )
        try:
            status, response = container.production_sandbox.execute(
                generated.package,
                "observe",
                {"value": "native"},
            )
        except Exception as error:
            await runtime.aclose()
            if "SandboxIsolationUnavailable" in str(error) or "AppContainer" in str(error):
                pytest.skip(f"current host native differential: {error}")
            raise
        assert status.executable_isolation
        assert status.max_processes == 1
        bridge = cast(
            ProductionHostOperationBridge,
            container.production_sandbox._broker,  # noqa: SLF001
        )
        assert bridge.request_history
        print(
            f"R4R_D6B1H3_OPERATION {decision.value} "
            f"{bridge.request_history[-1]} target_calls={calls}",
            flush=True,
        )
        await runtime.aclose()
        if decision is Decision.ALLOW:
            assert response == {"result": "trusted:native"}
            assert calls == 1
        else:
            assert response["status"] == "action_failed"
            assert calls == 0
        return calls

    allow_calls = await run(Decision.ALLOW)
    deny_calls = await run(Decision.DENY)
    assert allow_calls == 1
    assert deny_calls == 0


PACKAGE_HASH = "a" * 64
ENTRY_HASH = "b" * 64
PACKAGE_ID = "trusted-bound-capability"
OPERATION = "trusted.target.read"


def _package(permissions: tuple[Permission, ...]) -> IntegrationPackage:
    version = SemanticVersion(1, 0, 0)
    provenance = PackageProvenance("D6B1H3 test", "fixture", "MIT")
    action = CapabilityActionSpec(
        PACKAGE_ID,
        PACKAGE_ID,
        version,
        PACKAGE_HASH,
        "observe",
        "Observe trusted target",
        "One bounded trusted target observation",
        {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {"result": {"type": "string"}},
            "required": ["result"],
            "additionalProperties": False,
        },
        EffectMetadata(EffectClassification.OBSERVATION, Reversibility.READ_ONLY),
        permissions,
        operation=OPERATION,
    )
    return IntegrationPackage(
        PACKAGE_ID,
        version,
        PackageLayout(),
        (
            PackageEntry(
                "payload", "code/payload.json", PackageBoundary.PACKAGE_CODE, ENTRY_HASH, provenance
            ),
        ),
        permissions=permissions,
        lifecycle=PackageLifecycle.VALIDATED,
        provenance=provenance,
        package_hash=PACKAGE_HASH,
        action_specs=(action,),
    )


def _bridge(
    package: IntegrationPackage,
    target_permissions: tuple[Permission, ...],
    policy_decision: Decision,
    calls: list[Mapping[str, object]],
) -> ProductionHostOperationBridge:
    identity = object()
    tool_id = "trusted.target.tool"
    broker = PermissionBroker(
        PolicyEngine(
            tuple(
                PolicyRule(
                    f"{policy_decision.value.lower()}.{permission.value}",
                    permission,
                    policy_decision,
                    ScopeConstraint(applications=(package.package_id,)),
                    frozenset({"sandbox.device.observe"}),
                )
                for permission in target_permissions
            )
        )
    )
    broker.register_tool(tool_id, identity, frozenset(target_permissions))

    def target(arguments: Mapping[str, object]) -> Mapping[str, object]:
        calls.append(dict(arguments))
        return {"result": "trusted"}

    trusted = TrustedHostOperation(
        target,
        target_permissions,
        PermissionScope(applications=(package.package_id,)),
    )

    def host_proxy(manifest: HostProxyManifest) -> HostProxy:
        return HostProxy(
            manifest,
            broker,
            tool_bindings={OPERATION: (tool_id, identity)},
        )

    return ProductionHostOperationBridge(host_proxy, {OPERATION: trusted})


def test_d6b1h3_allow_and_deny_bind_all_permissions_before_target() -> None:
    permissions = (Permission.CAMERA_READ, Permission.COMPUTER_INPUT)
    package = _package(permissions)
    allowed_calls: list[Mapping[str, object]] = []
    allowed = _bridge(package, permissions, Decision.ALLOW, allowed_calls)

    assert allowed(package, "observe", OPERATION, {"value": "A"}) == {"result": "trusted"}
    assert allowed_calls == [{"value": "A"}]

    denied_calls: list[Mapping[str, object]] = []
    denied = _bridge(package, permissions, Decision.DENY, denied_calls)
    with pytest.raises(HostProxyDenied):
        denied(package, "observe", OPERATION, {"value": "B"})
    assert denied_calls == []


def test_d6b1h3_omission_downgrade_and_self_grant_fail_closed() -> None:
    calls: list[Mapping[str, object]] = []
    package = _package(())
    bridge = _bridge(package, (Permission.CAMERA_READ,), Decision.ALLOW, calls)
    with pytest.raises(ProductionCapabilityError, match="REQUIREMENT_MISMATCH"):
        bridge(package, "observe", OPERATION, {"value": "omitted"})
    assert calls == []

    package = _package((Permission.CAMERA_READ,))
    bridge = _bridge(package, (Permission.COMPUTER_INPUT,), Decision.ALLOW, calls)
    with pytest.raises(ProductionCapabilityError, match="REQUIREMENT_MISMATCH"):
        bridge(package, "observe", OPERATION, {"value": "downgrade"})
    assert calls == []

    bridge = _bridge(package, (Permission.CAMERA_READ,), Decision.ALLOW, calls)
    with pytest.raises(HostProxyDenied):
        bridge(
            package,
            "observe",
            OPERATION,
            {"value": "smuggle", "permission_granted": True},
        )
    assert calls == []


def test_d6b1h3_undeclared_unknown_and_missing_bridge_are_parent_side_failures() -> None:
    package = _package((Permission.CAMERA_READ,))
    calls: list[Mapping[str, object]] = []
    bridge = _bridge(package, (Permission.CAMERA_READ,), Decision.ALLOW, calls)
    with pytest.raises(ProductionCapabilityError, match="UNAVAILABLE"):
        bridge(package, "observe", "unknown.target", {"value": "unknown"})
    with pytest.raises(ProductionCapabilityError, match="REQUIREMENT_MISMATCH"):
        bridge(package, "missing", OPERATION, {"value": "undeclared"})

    def unavailable(_manifest: HostProxyManifest) -> HostProxy:
        raise ProductionCapabilityError("BROKER_UNAVAILABLE")

    missing_bridge = ProductionHostOperationBridge(
        unavailable,
        {
            OPERATION: TrustedHostOperation(
                lambda _arguments: {"result": "unreachable"},
                (Permission.CAMERA_READ,),
            )
        },
    )
    with pytest.raises(ProductionCapabilityError, match="BROKER_UNAVAILABLE"):
        missing_bridge(package, "observe", OPERATION, {"value": "no-bridge"})
    assert calls == []
