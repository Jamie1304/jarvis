"""D6B1F proof of the generic production broker traversal."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from jarvis.agent_runtime import AgentLoop
from jarvis.capabilities import EnvironmentGraph
from jarvis.capability_factory import FactoryStrategy, SolutionReport, WorkspaceContext
from jarvis.core.config import Settings
from jarvis.credentials import TestOnlyInMemorySecretBackend
from jarvis.discovery.models import CapabilityGap
from jarvis.package_certification import (
    CertificationFailure,
    CertificationRequest,
    PackageCertifier,
)
from jarvis.permissions.models import Risk
from jarvis.production_capability import (
    AgentRuntimeCapabilityGenerator,
    CapabilityGenerationProvider,
    ProductionCapabilityError,
    ProductionCertificationProvider,
)
from jarvis.runtime import ApplicationRuntime, RuntimeStatus
from jarvis.sandbox_proxies import HostProxy, HostProxyManifest
from jarvis.verification import VerificationEngine


class _GeneratedProposal(CapabilityGenerationProvider):
    def __init__(self, capability_id: str, operation: str) -> None:
        self.capability_id = capability_id
        self.operation = operation

    async def propose(self, prompt: str, **kwargs: object) -> str:
        del prompt, kwargs
        return json.dumps(
            {
                "name": f"Fresh {self.capability_id}",
                "description": "A bounded D6B1F brokered observation",
                "actions": [
                    {
                        "action_id": "observe",
                        "semantic_name": "Observe a value",
                        "description": "Return one bounded value from a trusted target",
                        "input_schema": {
                            "type": "object",
                            "properties": {"value": {"type": "string"}},
                            "required": ["value"],
                            "additionalProperties": False,
                        },
                        "output_schema": {
                            "type": "object",
                            "properties": {"result": {"type": "string"}},
                            "required": ["result"],
                            "additionalProperties": False,
                        },
                        "effect": {
                            "classification": "observation",
                            "reversibility": "read_only",
                        },
                        "operation": self.operation,
                        "permissions": [],
                        "verification": ["adapter_output_schema", "action_completed"],
                    }
                ],
            }
        )


async def _run_capability(
    tmp_path: Path, capability_id: str
) -> tuple[dict[str, object], ApplicationRuntime]:
    operation = f"d6b1f.target.{uuid4().hex}"
    calls = 0

    def target(arguments: Mapping[str, object]) -> Mapping[str, object]:
        nonlocal calls
        calls += 1
        return {"result": f"trusted:{arguments['value']}"}

    runtime = ApplicationRuntime.create(
        Settings(
            environment="test",
            app_data_dir=tmp_path / capability_id,
            ai_provider="ollama",
            _env_file=None,
        ),
        recovery_key_backend=TestOnlyInMemorySecretBackend(),
        trusted_host_operations={operation: target},
    )
    assert runtime.status is RuntimeStatus.READY, runtime.error
    assert runtime.container is not None
    container = runtime.container
    store = container.package_store
    generator = AgentRuntimeCapabilityGenerator(
        cast(AgentLoop, object()),
        store,
        provider=_GeneratedProposal(capability_id, operation),
    )
    gap = CapabilityGap(
        capability_id, f"observe {capability_id}", (capability_id,), (), Risk.LOW, ()
    )
    generated = await generator.generate(
        gap,
        SolutionReport(gap),
        WorkspaceContext("d6b1f-proof"),
        EnvironmentGraph(),
        {},
        FactoryStrategy.GENERATE_ADAPTER,
    )
    package = generated.package

    def oracle(action: object, value: Mapping[str, object]) -> Mapping[str, object]:
        del action
        return {"result": f"trusted:{value['value']}"}

    provider = ProductionCertificationProvider(
        store,
        container.production_sandbox,
        VerificationEngine(),
        semantic_oracle=oracle,
    )
    hooks = provider.hooks(package)
    try:
        record = PackageCertifier().certify(
            CertificationRequest(package, "rollback:d6b1f", ("local",), ("trusted result",)),
            hooks,
        )
    except CertificationFailure as error:
        if any(
            "SandboxIsolationUnavailable" in item
            for stage in error.evidence
            for item in stage.evidence
        ):
            await runtime.aclose()
            pytest.skip(
                "current host reproduced the established AppContainer isolation differential"
            )
        await runtime.aclose()
        raise
    status, result = container.production_sandbox.execute(package, "observe", {"value": "probe"})
    assert status.executable_isolation
    assert result == {"result": "trusted:probe"}
    assert calls == 2  # certification functional case plus the independent runtime probe
    assert package.package_id not in Path(__file__).read_text(encoding="utf-8")
    print(
        f"R4R_D6B1H3_CAPABILITY {package.package_id} target_calls={calls}",
        flush=True,
    )
    return {
        "identity": package.package_id,
        "operation": operation,
        "package_hash": package.package_hash,
        "manifest_bound": record.package_id == package.package_id
        and record.package_hash == package.package_hash,
        "worker": "PASS",
        "payload": "PAYLOAD_LOADED",
        "target_calls": calls,
        "result": result,
        "semantic_oracle": "PASS",
        "certification": "PASS",
    }, runtime


@pytest.mark.asyncio
async def test_d6b1f_fresh_identities_traverse_real_production_broker(tmp_path: Path) -> None:
    first, runtime = await _run_capability(tmp_path, f"first-{uuid4().hex}")
    await runtime.aclose()
    second, runtime = await _run_capability(tmp_path, f"second-{uuid4().hex}")
    await runtime.aclose()
    assert first["identity"] != second["identity"]
    production = Path(__file__).resolve().parents[1] / "jarvis"
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in production.rglob("*.py")
        if path.name != "__pycache__"
    )
    assert str(first["identity"]) not in source
    assert str(second["identity"]) not in source


def test_d6b1f_negative_parent_controls_are_fail_closed() -> None:
    # These are parent-side checks, before any trusted target is callable.
    from jarvis.production_capability import ProductionHostOperationBridge

    bridge = ProductionHostOperationBridge(
        cast(Callable[[HostProxyManifest], HostProxy], lambda manifest: cast(HostProxy, object())),
        {},
    )
    with pytest.raises(ProductionCapabilityError, match="UNAVAILABLE"):
        bridge(object(), "observe", "unknown.target", {})  # type: ignore[arg-type]
