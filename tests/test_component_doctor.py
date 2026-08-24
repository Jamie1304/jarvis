from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import pytest
from jarvis.capability_health import CapabilityHealthService, HealthStatus
from jarvis.component_doctor import (
    ComponentDoctor,
    ComponentDoctorError,
    ComponentDoctorSecurityError,
    ComponentProblem,
    DiagnosticOwner,
    DiagnosticProbe,
    DiagnosticProbeResult,
    DoctorResult,
    DoctorStatus,
    FailureSignature,
    FallbackOption,
    RepairAction,
    RepairAttempt,
    RepairAttemptState,
    RepairCandidate,
    RepairEffectOutcome,
    RepairExecution,
    RepairPlaybook,
)
from jarvis.integration_package import (
    DiagnosticsContract,
    IntegrationPackage,
    PackageBoundary,
    PackageEntry,
    PackageLayout,
    PackageLifecycle,
    PackageProvenance,
)
from jarvis.tools.models import SemanticVersion

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def playbook(
    *,
    owner: DiagnosticOwner = DiagnosticOwner.CAPABILITY,
    fallbacks: tuple[str, ...] = (),
    verification: tuple[str, ...] = ("verified",),
) -> RepairPlaybook:
    return RepairPlaybook(
        "fixture-playbook",
        "fixture.component",
        owner,
        (FailureSignature("offline", "The component is offline"),),
        (DiagnosticProbe("status", "Read current component status"),),
        (RepairAction("restart", "Restart the configured component"),),
        fallbacks,
        verification,
    )


def problem(summary: str = "offline") -> ComponentProblem:
    return ComponentProblem(
        "fixture.component",
        summary,
        DiagnosticOwner.CAPABILITY,
        failure_code="offline",
        source="health",
        trusted=True,
        evidence=("trusted health observation",),
        occurred_at=NOW,
    )


def doctor(
    *,
    authorize: Callable[[ComponentProblem, RepairAction], bool | Awaitable[bool]] | None = None,
    research: (
        Callable[[ComponentProblem], RepairCandidate | None | Awaitable[RepairCandidate | None]]
        | None
    ) = None,
    attempts: int = 2,
) -> ComponentDoctor:
    health = CapabilityHealthService(clock=lambda: NOW)
    result = ComponentDoctor(
        health,
        authorize=authorize,
        research=research,
        clock=lambda: NOW,
        max_attempts=attempts,
    )
    result.register_playbook(playbook())
    return result


@pytest.mark.asyncio
async def test_known_repair_runs_owner_probe_and_verification() -> None:
    service = doctor(authorize=lambda _problem, _action: True)
    probe_calls: list[str] = []
    action_calls: list[str] = []

    async def probe_callback(item: ComponentProblem) -> DiagnosticProbeResult:
        probe_calls.append(item.component_id)
        return DiagnosticProbeResult("status", True, "service is installed", ("installed",), NOW)

    async def action_callback(item: ComponentProblem, action: RepairAction) -> RepairExecution:
        action_calls.append(action.action_id)
        return RepairExecution(
            RepairEffectOutcome.EFFECT_CONFIRMED,
            True,
            "restart verified",
            ("verified",),
        )

    service.register_probe("fixture.component", "status", probe_callback)
    service.register_action("fixture.component", "restart", action_callback)
    result = await service.run(problem())
    assert result.status is DoctorStatus.REPAIRED
    assert result.signature is not None
    assert result.probes[0].passed
    assert result.attempts[0].state is RepairAttemptState.VERIFIED
    assert probe_calls == ["fixture.component"]
    assert action_calls == ["restart"]


@pytest.mark.asyncio
async def test_repair_requires_approval_and_does_not_call_action() -> None:
    service = doctor()
    calls: list[str] = []

    async def action_callback(item: ComponentProblem, action: RepairAction) -> RepairExecution:
        calls.append(action.action_id)
        return RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "done", ("verified",))

    service.register_action("fixture.component", "restart", action_callback)
    result = await service.run(problem())
    assert result.status is DoctorStatus.PERMISSION_REQUIRED
    assert result.attempts[0].state is RepairAttemptState.PERMISSION_REQUIRED
    assert calls == []


@pytest.mark.asyncio
async def test_failed_repair_degrades_to_declared_safe_fallback() -> None:
    service = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        authorize=lambda _problem, _action: True,
        clock=lambda: NOW,
    )
    service.register_playbook(playbook(fallbacks=("ptt",)))
    calls: list[str] = []

    async def action_callback(item: ComponentProblem, action: RepairAction) -> RepairExecution:
        calls.append(action.action_id)
        return RepairExecution(
            RepairEffectOutcome.PRE_EFFECT_FAILURE,
            False,
            "restart failed before effect",
        )

    service.register_action("fixture.component", "restart", action_callback)
    service.register_fallback(
        "fixture.component",
        FallbackOption("ptt", "Push-to-talk remains available"),
        lambda _item: True,
    )
    result = await service.run(problem())
    assert result.status is DoctorStatus.DEGRADED
    assert result.fallback_id == "ptt"
    assert len(result.attempts) == 2
    assert calls == ["restart", "restart"]


@pytest.mark.asyncio
async def test_unknown_outcome_quarantines_and_never_retries() -> None:
    service = doctor(authorize=lambda _problem, _action: True, attempts=3)
    calls: list[str] = []

    def action_callback(item: ComponentProblem, action: RepairAction) -> RepairExecution:
        calls.append(action.action_id)
        return RepairExecution(RepairEffectOutcome.UNKNOWN_OUTCOME, False, "effect uncertain")

    service.register_action("fixture.component", "restart", action_callback)
    result = await service.run(problem())
    assert result.status is DoctorStatus.QUARANTINED
    assert result.attempts[0].state is RepairAttemptState.UNKNOWN_OUTCOME
    assert len(result.attempts) == 1
    assert calls == ["restart"]


@pytest.mark.asyncio
async def test_unknown_failure_requests_research_and_rejects_unverified_candidate() -> None:
    candidate = RepairCandidate(
        "research-1",
        "Install a replacement helper",
        "restart",
        "model",
    )
    research_calls: list[str] = []

    async def research_callback(item: ComponentProblem) -> RepairCandidate:
        research_calls.append(item.component_id)
        return candidate

    service = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        research=research_callback,
        clock=lambda: NOW,
    )
    unknown_playbook = RepairPlaybook(
        "unknown-playbook",
        "fixture.component",
        DiagnosticOwner.CAPABILITY,
        (FailureSignature("never-matches", "unknown"),),
    )
    service.register_playbook(unknown_playbook)
    result = await service.run(problem("provider failure"))
    assert result.status is DoctorStatus.RESEARCH_REQUIRED
    assert result.research is candidate
    assert research_calls == ["fixture.component"]


@pytest.mark.asyncio
async def test_capability_crash_is_isolated_and_marks_only_component_unavailable() -> None:
    service = doctor(authorize=lambda _problem, _action: True)

    def crashing_callback(item: ComponentProblem, action: RepairAction) -> RepairExecution:
        raise RuntimeError("simulated capability crash")

    service.register_action("fixture.component", "restart", crashing_callback)
    result = await service.run(problem())
    assert result.status is DoctorStatus.FAILED
    assert service._health.health("fixture.component").status is HealthStatus.UNAVAILABLE


def test_ownership_and_security_rules_reject_cross_owner_or_unsafe_actions() -> None:
    service = ComponentDoctor(CapabilityHealthService(clock=lambda: NOW))
    for owner in DiagnosticOwner:
        item = RepairPlaybook(f"playbook-{owner.value}", f"component-{owner.value}", owner)
        service.register_playbook(item)
        assert service.owner_for(item.component_id) is owner
    cross_owner = RepairPlaybook(
        "cross-owner",
        "cross-owner.component",
        DiagnosticOwner.PROVIDER,
        probes=(DiagnosticProbe("missing", "Read status"),),
    )
    service.register_playbook(cross_owner)
    with pytest.raises(ComponentDoctorSecurityError):
        service.register_probe(
            "cross-owner.component",
            "missing",
            lambda _item: DiagnosticProbeResult("missing", True, "ok"),
            owner=DiagnosticOwner.CORE,
        )
    unsafe = RepairPlaybook(
        "unsafe",
        "unsafe.component",
        DiagnosticOwner.CAPABILITY,
        actions=(RepairAction("bad", "Disable permission policy"),),
    )
    service.register_playbook(unsafe)

    def bad_callback(_item: ComponentProblem, _action: RepairAction) -> RepairExecution:
        return RepairExecution(RepairEffectOutcome.PRE_EFFECT_FAILURE, False, "not run")

    with pytest.raises(ComponentDoctorSecurityError):
        service.register_action("unsafe.component", "bad", bad_callback)
    with pytest.raises(ComponentDoctorSecurityError):
        FallbackOption("unsafe", "Fallback", preserves_privacy=False)


def test_package_diagnostics_become_capability_playbook() -> None:
    source = "def run():\n    return 1\n"
    provenance = PackageProvenance("fixture", "revision", "MIT")
    package = IntegrationPackage(
        "fixture.package",
        SemanticVersion(1, 0, 0),
        PackageLayout(),
        (
            PackageEntry(
                "python",
                "code/main.py",
                PackageBoundary.PACKAGE_CODE,
                sha256(source.encode()).hexdigest(),
                provenance,
            ),
        ),
        lifecycle=PackageLifecycle.VALIDATED,
        diagnostics=DiagnosticsContract(
            known_failure_signatures=(FailureSignature("offline", "Offline"),),
            probes=(DiagnosticProbe("probe", "Read status"),),
            safe_repairs=(RepairAction("restart", "Restart service"),),
            fallback_strategy=("text-only",),
            expected_repair_verification=("healthy",),
        ),
        provenance=provenance,
    )
    derived = RepairPlaybook.from_package(package)
    assert derived.owner is DiagnosticOwner.CAPABILITY
    assert derived.package_id == package.package_id
    assert derived.fallback_strategy == ("text-only",)
    assert derived.expected_repair_verification == ("healthy",)
    assert derived.signatures == derived.failure_signatures


def test_contract_models_fail_closed_on_malformed_security_data() -> None:
    with pytest.raises(ComponentDoctorError):
        ComponentProblem("", "bad", DiagnosticOwner.CAPABILITY)
    with pytest.raises(ComponentDoctorError):
        ComponentProblem("component", "bad", cast(DiagnosticOwner, "core"))
    with pytest.raises(ComponentDoctorError):
        ComponentProblem(
            "component",
            "bad",
            DiagnosticOwner.CAPABILITY,
            health_status=cast(HealthStatus, "healthy"),
        )
    with pytest.raises(ComponentDoctorSecurityError):
        ComponentProblem("component", "model claim", DiagnosticOwner.CAPABILITY, source="model")
    with pytest.raises(ComponentDoctorError):
        ComponentProblem(
            "component",
            "bad",
            DiagnosticOwner.CAPABILITY,
            trusted=cast(bool, 1),
        )
    with pytest.raises(ComponentDoctorError):
        ComponentProblem(
            "component",
            "bad",
            DiagnosticOwner.CAPABILITY,
            evidence=("duplicate", "duplicate"),
        )
    with pytest.raises(ComponentDoctorError):
        ComponentProblem(
            "component",
            "bad",
            DiagnosticOwner.CAPABILITY,
            occurred_at=datetime(2026, 1, 1),
        )
    with pytest.raises(ComponentDoctorError):
        DiagnosticProbeResult("probe", cast(bool, 1), "detail")
    with pytest.raises(ComponentDoctorError):
        RepairExecution(cast(RepairEffectOutcome, "confirmed"), True, "detail")
    with pytest.raises(ComponentDoctorError):
        RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, False, "detail")
    with pytest.raises(ComponentDoctorError):
        FallbackOption("fallback", "safe", preserves_security=cast(bool, 1))
    with pytest.raises(ComponentDoctorSecurityError):
        FallbackOption("fallback", "unsafe", preserves_privacy=False)
    with pytest.raises(ComponentDoctorError):
        RepairCandidate(
            "candidate",
            "description",
            "action",
            "trusted",
            trusted=cast(bool, 1),
        )
    with pytest.raises(ComponentDoctorSecurityError):
        RepairCandidate("candidate", "description", "action", "model", trusted=True)


def test_playbook_attempt_and_result_contracts_reject_invalid_shapes() -> None:
    signature = FailureSignature("offline", "Offline")
    probe = DiagnosticProbe("status", "Read status")
    action = RepairAction("restart", "Restart")
    with pytest.raises(ComponentDoctorError):
        RepairPlaybook("bad", "component", cast(DiagnosticOwner, "capability"))
    with pytest.raises(ComponentDoctorError):
        RepairPlaybook(
            "bad",
            "component",
            DiagnosticOwner.CAPABILITY,
            failure_signatures=(cast(FailureSignature, object()),),
        )
    with pytest.raises(ComponentDoctorError):
        RepairPlaybook(
            "bad",
            "component",
            DiagnosticOwner.CAPABILITY,
            probes=(cast(DiagnosticProbe, object()),),
        )
    with pytest.raises(ComponentDoctorError):
        RepairPlaybook(
            "bad", "component", DiagnosticOwner.CAPABILITY, actions=(cast(RepairAction, object()),)
        )
    with pytest.raises(ComponentDoctorError):
        RepairPlaybook("bad", "component", DiagnosticOwner.CAPABILITY, probes=(probe, probe))
    with pytest.raises(ComponentDoctorError):
        RepairPlaybook("bad", "component", DiagnosticOwner.CAPABILITY, actions=(action, action))
    with pytest.raises(ComponentDoctorError):
        RepairPlaybook("bad", "component", DiagnosticOwner.CAPABILITY, package_id="")
    with pytest.raises(ComponentDoctorError):
        RepairPlaybook.from_package(cast(IntegrationPackage, object()))

    attempt = RepairAttempt(
        uuid4(),
        "component",
        "restart",
        1,
        RepairAttemptState.FAILED,
        RepairEffectOutcome.PRE_EFFECT_FAILURE,
        "failed",
    )
    with pytest.raises(ComponentDoctorError):
        RepairAttempt(
            cast(UUID, "id"), "component", "restart", 1, RepairAttemptState.FAILED, None, "failed"
        )
    with pytest.raises(ComponentDoctorError):
        RepairAttempt(uuid4(), "component", "restart", 0, RepairAttemptState.FAILED, None, "failed")
    with pytest.raises(ComponentDoctorError):
        RepairAttempt(
            uuid4(), "component", "restart", 1, cast(RepairAttemptState, "failed"), None, "failed"
        )
    with pytest.raises(ComponentDoctorError):
        RepairAttempt(
            uuid4(),
            "component",
            "restart",
            1,
            RepairAttemptState.FAILED,
            cast(RepairEffectOutcome, "failed"),
            "failed",
        )
    valid = DoctorResult(
        problem(),
        DoctorStatus.NO_ACTION,
        DiagnosticOwner.CAPABILITY,
        signature,
        (),
        (attempt,),
        None,
        None,
        "detail",
    )
    with pytest.raises(ComponentDoctorError):
        replace(valid, status=cast(DoctorStatus, "bad"))
    with pytest.raises(ComponentDoctorError):
        replace(valid, signature=cast(FailureSignature, object()))
    with pytest.raises(ComponentDoctorError):
        replace(valid, probes=(cast(DiagnosticProbeResult, object()),))
    with pytest.raises(ComponentDoctorError):
        replace(valid, attempts=(cast(RepairAttempt, object()),))
    with pytest.raises(ComponentDoctorError):
        replace(valid, research=cast(RepairCandidate, object()))


def test_registration_rejects_duplicate_or_undeclared_bindings() -> None:
    service = ComponentDoctor(CapabilityHealthService(clock=lambda: NOW))
    item = playbook(fallbacks=("fallback",))
    service.register_playbook(item)
    with pytest.raises(ComponentDoctorError):
        service.register_playbook(item)
    with pytest.raises(ComponentDoctorError):
        service.register_probe(
            "fixture.component", "missing", cast(Callable[..., DiagnosticProbeResult], object())
        )
    with pytest.raises(ComponentDoctorError):
        service.register_action(
            "fixture.component", "missing", cast(Callable[..., RepairExecution], object())
        )
    with pytest.raises(ComponentDoctorSecurityError):
        service.register_probe(
            "fixture.component",
            "status",
            lambda _item: DiagnosticProbeResult("status", True, "ok"),
            owner=DiagnosticOwner.PROVIDER,
        )
    service.register_probe(
        "fixture.component",
        "status",
        lambda _item: DiagnosticProbeResult("status", True, "ok"),
    )
    with pytest.raises(ComponentDoctorError):
        service.register_probe(
            "fixture.component",
            "status",
            lambda _item: DiagnosticProbeResult("status", True, "ok"),
        )
    with pytest.raises(ComponentDoctorSecurityError):
        service.register_action(
            "fixture.component",
            "restart",
            cast(Callable[..., RepairExecution], object()),
        )
    service.register_action(
        "fixture.component",
        "restart",
        lambda _item, _action: RepairExecution(
            RepairEffectOutcome.PRE_EFFECT_FAILURE, False, "failed"
        ),
    )
    with pytest.raises(ComponentDoctorError):
        service.register_action(
            "fixture.component",
            "restart",
            lambda _item, _action: RepairExecution(
                RepairEffectOutcome.PRE_EFFECT_FAILURE, False, "failed"
            ),
        )
    with pytest.raises(ComponentDoctorError):
        service.register_fallback(
            "fixture.component",
            FallbackOption("unknown", "Unknown"),
            lambda _item: True,
        )
    with pytest.raises(ComponentDoctorSecurityError):
        service.register_fallback(
            "fixture.component",
            FallbackOption("fallback", "Fallback"),
            lambda _item: True,
            owner=DiagnosticOwner.PROVIDER,
        )
    service.register_fallback(
        "fixture.component",
        FallbackOption("fallback", "Fallback"),
        lambda _item: True,
    )
    with pytest.raises(ComponentDoctorError):
        service.register_fallback(
            "fixture.component",
            FallbackOption("fallback", "Fallback"),
            lambda _item: True,
        )
    with pytest.raises(ComponentDoctorError):
        service.owner_for("missing.component")


@pytest.mark.asyncio
async def test_doctor_research_validation_and_fallback_boundaries() -> None:
    no_playbook = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        research=lambda _item: None,
        clock=lambda: NOW,
    )
    result = await no_playbook.run(problem())
    assert result.status is DoctorStatus.RESEARCH_REQUIRED
    assert result.research is None

    mismatch = ComponentDoctor(CapabilityHealthService(clock=lambda: NOW))
    mismatch.register_playbook(
        RepairPlaybook("provider", "fixture.component", DiagnosticOwner.PROVIDER)
    )
    with pytest.raises(ComponentDoctorSecurityError):
        await mismatch.run(problem())

    unknown = RepairPlaybook(
        "unknown",
        "fixture.component",
        DiagnosticOwner.CAPABILITY,
        actions=(RepairAction("restart", "Restart"),),
        fallback_strategy=("text",),
    )
    malformed_research = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        research=lambda _item: cast(RepairCandidate, object()),
        clock=lambda: NOW,
    )
    malformed_research.register_playbook(unknown)
    result = await malformed_research.run(problem("unrecognized"))
    assert result.status is DoctorStatus.FAILED

    candidate = RepairCandidate(
        "candidate",
        "Restart safely",
        "restart",
        "trusted-review",
        trusted=True,
        sandbox_verified=True,
        security_reviewed=True,
    )
    no_binding = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        research=lambda _item: candidate,
        clock=lambda: NOW,
    )
    no_binding.register_playbook(unknown)
    result = await no_binding.run(problem("unrecognized"))
    assert result.status is DoctorStatus.FAILED

    approval_fallback = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        authorize=lambda _item, _action: False,
        clock=lambda: NOW,
    )
    approval_fallback.register_playbook(unknown)
    approval_fallback.register_fallback(
        "fixture.component",
        FallbackOption("text", "Text-only", requires_approval=True),
        lambda _item: True,
    )
    result = await approval_fallback.run(problem("unrecognized"))
    assert result.status is DoctorStatus.PERMISSION_REQUIRED


@pytest.mark.asyncio
async def test_doctor_isolates_probe_callback_and_malformed_repair_results() -> None:
    service = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        authorize=lambda _item, _action: True,
        clock=lambda: NOW,
        max_attempts=1,
    )
    service.register_playbook(playbook())

    def bad_probe(_item: ComponentProblem) -> DiagnosticProbeResult:
        raise RuntimeError("probe crashed")

    service.register_probe("fixture.component", "status", bad_probe)
    service.register_action(
        "fixture.component",
        "restart",
        lambda _item, _action: cast(RepairExecution, object()),
    )
    result = await service.run(problem())
    assert result.status is DoctorStatus.FAILED
    assert result.probes[0].passed is False

    fallback_error = ComponentDoctor(CapabilityHealthService(clock=lambda: NOW), clock=lambda: NOW)
    fallback_error.register_playbook(playbook(fallbacks=("text",)))
    fallback_error.register_fallback(
        "fixture.component",
        FallbackOption("text", "Text-only"),
        lambda _item: (_ for _ in ()).throw(RuntimeError("fallback crashed")),
    )
    result = await fallback_error.run(problem())
    assert result.status is DoctorStatus.FAILED
    await fallback_error.aclose()
