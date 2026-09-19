"""Run one test-owned real Windows startup disable/restore qualification probe."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from jarvis.permissions import (  # noqa: E402
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    ApprovalSource,
    AuthorizationReceipt,
    Decision,
    Permission,
    PermissionBroker,
    PolicyEngine,
    PolicyRule,
    ScopeConstraint,
    TrustedApprovalAuthenticator,
)
from jarvis.startup_mutation import (  # noqa: E402
    StartupMutationService,
    StartupMutationState,
    StartupMutationStore,
    WindowsRegistryStartupBackend,
    WindowsStartupMutationProvider,
)
from jarvis.system_stewardship import StartupHealthService, StartupMutationPlan  # noqa: E402
from jarvis.vm.bridge import HostBridge  # noqa: E402

RUN_SCOPE = ("current-user", r"Software\Microsoft\Windows\CurrentVersion\Run")
TEST_COMMAND = r"C:\Windows\System32\cmd.exe /c exit 0"


def _broker(entry_id: str) -> tuple[PermissionBroker, TrustedApprovalAuthenticator]:
    authenticator = TrustedApprovalAuthenticator(ApprovalSource.TRUSTED_LOCAL_API)
    policy = PolicyEngine(
        (
            PolicyRule(
                "r3c-real-startup-qualification",
                Permission.STARTUP_WRITE,
                Decision.ALLOW,
                ScopeConstraint(
                    startup_entries=(entry_id,),
                    tools=frozenset({StartupMutationService.TOOL_ID}),
                ),
                frozenset(
                    {
                        "system.startup.disable",
                        "system.startup.restore",
                    }
                ),
            ),
        )
    )
    return (
        PermissionBroker(policy, approval_context_verifier=authenticator.verifier()),
        authenticator,
    )


async def _approved_receipt(
    service: StartupMutationService,
    broker: PermissionBroker,
    authenticator: TrustedApprovalAuthenticator,
    plan: StartupMutationPlan,
) -> AuthorizationReceipt:
    pending = await service.authorize(plan, user_id="real-host-qualification")
    if pending.authorized or not pending.approval_requests:
        raise RuntimeError("qualification did not produce the expected approval request")
    request = pending.approval_requests[0]
    context = authenticator.issue_context(
        request_id=request.request_id,
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("real-host-qualification", ApprovalActorKind.TRUSTED_USER),
    )
    decision = await broker.decide(context)
    if not decision.accepted:
        raise RuntimeError("qualification approval was not accepted")
    authorized = await service.authorize(plan, user_id="real-host-qualification")
    if not authorized.authorized or authorized.receipt is None:
        raise RuntimeError("qualification receipt was not issued")
    return authorized.receipt


async def _probe() -> dict[str, object]:
    if sys.platform != "win32":
        return {
            "status": "NOT_PROBED",
            "reason": "real Windows startup mutation requires sys.platform == win32",
        }
    backend = WindowsRegistryStartupBackend()
    name = f"JARVIS Qualification {uuid4()}"
    state_path = PROJECT_ROOT / "build" / "r3c-c-real-host-startup-state.json"
    entry_id: str | None = None
    created = False
    result: dict[str, object] | None = None
    try:
        # This is the uniquely named qualification fixture.  Product effects
        # still flow through StartupMutationService after receipt authorization.
        backend.set(*RUN_SCOPE, name, TEST_COMMAND, 1)
        created = True
        provider = WindowsStartupMutationProvider(backend=backend)
        observed = await provider.observer.observe()
        matches = tuple(item for item in observed if item.owner == name)
        if len(matches) != 1:
            raise RuntimeError("qualification startup value was not observed uniquely")
        entry_id = matches[0].entry_id
        broker, authenticator = _broker(entry_id)
        service = StartupMutationService(
            StartupHealthService(provider.observer),
            provider,
            StartupMutationStore(state_path),
            broker,
            HostBridge(),
        )
        plan = await service.plan_disable(entry_id)
        receipt = await _approved_receipt(service, broker, authenticator, plan)
        disabled = await service.execute(plan, receipt)
        if disabled.state is not StartupMutationState.DISABLED:
            raise RuntimeError("qualification disable did not reach DISABLED")

        restart_provider = WindowsStartupMutationProvider(backend=backend)
        restart_broker, restart_authenticator = _broker(entry_id)
        restarted = StartupMutationService(
            StartupHealthService(restart_provider.observer),
            restart_provider,
            StartupMutationStore(state_path),
            restart_broker,
            HostBridge(),
        )
        restore_plan = await restarted.plan_restore(disabled.mutation_id)
        restore_receipt = await _approved_receipt(
            restarted, restart_broker, restart_authenticator, restore_plan
        )
        restored = await restarted.execute(restore_plan, restore_receipt)
        if restored.state is not StartupMutationState.RESTORED:
            raise RuntimeError("qualification restore did not reach RESTORED")
        remaining = tuple(
            item for item in await restart_provider.observer.observe() if item.owner == name
        )
        if len(remaining) != 1:
            raise RuntimeError("qualification value was not restored uniquely")
        result = {
            "status": "PASS",
            "entry_id": entry_id,
            "provider": type(provider).__name__,
            "states": [disabled.state.value, restored.state.value],
            "bridge_request_count": len(service.host_bridge.requests)
            + len(restarted.host_bridge.requests),
            "cleanup": "PENDING_FINALLY_VERIFIED",
        }
    finally:
        if created:
            values = backend.read(*RUN_SCOPE)
            if any(item[0] == name for item in values):
                backend.delete(*RUN_SCOPE, name)
            if result is not None:
                result["cleanup"] = (
                    "PASS"
                    if not any(item[0] == name for item in backend.read(*RUN_SCOPE))
                    else "FAILED"
                )
        state_path.unlink(missing_ok=True)
    if result is None:
        raise RuntimeError("real-host qualification did not produce a result")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--artifact",
        type=Path,
        default=PROJECT_ROOT / "build" / "r3c-c-real-host-startup.json",
    )
    arguments = parser.parse_args()
    probe = asyncio.run(_probe())
    payload = {
        "schema": "v1-i-r3c-c-real-host-1",
        "observed_at": datetime.now(UTC).isoformat(),
        "platform": sys.platform,
        "probe": probe,
        "privacy": "raw startup command, registry locator, and receipt omitted",
    }
    arguments.artifact.parent.mkdir(parents=True, exist_ok=True)
    arguments.artifact.write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(payload, sort_keys=True))
    status = probe.get("status")
    return 0 if status in {"PASS", "NOT_PROBED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
