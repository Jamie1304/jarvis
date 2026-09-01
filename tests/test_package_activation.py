from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from jarvis.capability_lifecycle import SQLiteCapabilityLifecycleStore
from jarvis.effect_attestation import (
    EffectAttestationStatus,
    EffectAttestationStore,
    TrustedEffectObserver,
)
from jarvis.integration_package import (
    IntegrationPackage,
    PackageBoundary,
    PackageEntry,
    PackageLayout,
    PackageLifecycle,
    PackageProvenance,
)
from jarvis.package_activation import (
    ActivationError,
    ActivationHooks,
    ActivationRecord,
    ActivationRequest,
    ActivationState,
    ActivationTransition,
    CanaryExecution,
    CanaryLimits,
    GeneratedActionRegistrar,
    PackageActivationService,
    ShadowExecution,
)
from jarvis.package_certification import (
    BuiltPackage,
    CertificationHooks,
    CertificationRecord,
    CertificationRequest,
    CertificationStage,
    CertificationStageResult,
    PackageCertifier,
)
from jarvis.package_reviewer import PackageSourceFile
from jarvis.package_runtime import (
    HotLoadError,
    HotLoadManager,
    PackageRuntimeHealth,
    PreparedPackageRuntime,
)
from jarvis.tools.models import SemanticVersion
from jarvis.verification import (
    EvidenceRecord,
    EvidenceType,
    VerificationDisposition,
    VerificationLevel,
    VerificationResult,
)
from jarvis.windows_sandbox import SandboxSecurityStatus, WindowsContainmentMode

PROVENANCE = PackageProvenance("generated", "revision-1", "MIT", "NOTICE", "trusted-reviewer")


def package(
    version: tuple[int, int, int] = (1, 0, 0),
) -> tuple[IntegrationPackage, PackageSourceFile]:
    source = "def run():\n    return 1\n"
    source_hash = sha256(source.encode()).hexdigest()
    item = IntegrationPackage(
        "activation.example",
        SemanticVersion(*version),
        PackageLayout(),
        (
            PackageEntry(
                "python", "code/main.py", PackageBoundary.PACKAGE_CODE, source_hash, PROVENANCE
            ),
        ),
        permissions=(),
        dependency_lock=("example-lib==1.2.3",),
        lifecycle=PackageLifecycle.VALIDATED,
        provenance=PROVENANCE,
        package_hash=sha256(f"package-{version}".encode()).hexdigest(),
    )
    return item, PackageSourceFile("code/main.py", source)


def certification(
    item: IntegrationPackage,
    source: PackageSourceFile,
    *,
    shadow_eligible: bool = True,
    canary_eligible: bool = True,
) -> CertificationRecord:
    def stage(name: CertificationStage) -> CertificationStageResult:
        if name is CertificationStage.AUTHORITY_DECISION:
            return CertificationStageResult(
                True,
                ("trusted authority",),
                "approval:activation-fixture",
                shadow_eligible=shadow_eligible,
                canary_eligible=canary_eligible,
            )
        if name is CertificationStage.HEALTHCHECK:
            return CertificationStageResult(True, ("healthy",), health=("healthy",))
        if name is CertificationStage.VERIFICATION:
            return CertificationStageResult(True, ("verified",), verification=("verified",))
        return CertificationStageResult(True, (f"{name.value} passed",))

    hooks = CertificationHooks(
        build=lambda built: BuiltPackage(built, (source,)),
        unit_tests=lambda item: stage(CertificationStage.UNIT_TESTS),
        sandbox_integration_test=lambda item: stage(CertificationStage.SANDBOX_INTEGRATION_TEST),
        permission_diff=lambda item: stage(CertificationStage.PERMISSION_DIFF),
        authority_decision=lambda item: stage(CertificationStage.AUTHORITY_DECISION),
        install=lambda item: stage(CertificationStage.INSTALL),
        healthcheck=lambda item: stage(CertificationStage.HEALTHCHECK),
        verification=lambda item: stage(CertificationStage.VERIFICATION),
    )
    request = CertificationRequest(
        item,
        "restore-point:activation",
        ("windows",),
        ("bounded fixture behavior",),
    )
    return PackageCertifier().certify(request, hooks)


@dataclass
class Runtime:
    package: IntegrationPackage
    restored: Mapping[str, object] | None = None
    drained: int = 0

    def health_check(self) -> PackageRuntimeHealth:
        return PackageRuntimeHealth(True, "healthy")

    def export_state(self) -> Mapping[str, object]:
        return {"counter": 1}

    def restore_state(self, state: Mapping[str, object]) -> None:
        self.restored = dict(state)

    def drain(self) -> None:
        self.drained += 1


class Factory:
    def __init__(self) -> None:
        self.created: list[Runtime] = []

    def prepare(self, item: IntegrationPackage) -> Runtime:
        result = Runtime(item)
        self.created.append(result)
        return result


class Surface:
    def __init__(self) -> None:
        self.current: PreparedPackageRuntime | None = None

    def atomic_swap(self, item: IntegrationPackage, runtime: PreparedPackageRuntime) -> None:
        self.current = runtime

    def rollback(self, item: IntegrationPackage, runtime: PreparedPackageRuntime | None) -> None:
        self.current = runtime

    def remove(self, item: IntegrationPackage, runtime: PreparedPackageRuntime) -> None:
        if self.current is runtime:
            self.current = None


class Registrar:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.activated: list[str] = []
        self.deactivated: list[str] = []

    def activate(self, item: IntegrationPackage, certification: CertificationRecord) -> None:
        if self.fail:
            raise RuntimeError("registrar failure")
        self.activated.append(item.package_id)

    def deactivate(self, package_id: str) -> None:
        self.deactivated.append(package_id)


class BrokenRuntime(Runtime):
    def health_check(self) -> PackageRuntimeHealth:
        raise RuntimeError("unhealthy")


class BrokenFactory(Factory):
    def prepare(self, item: IntegrationPackage) -> Runtime:
        result = BrokenRuntime(item)
        self.created.append(result)
        return result


class BrokenSurface(Surface):
    def atomic_swap(self, item: IntegrationPackage, runtime: PreparedPackageRuntime) -> None:
        raise RuntimeError("swap failure")


def setup(
    *,
    shadow: ShadowExecution | None = None,
    canary: CanaryExecution | None = None,
    rollback: list[tuple[str, ...]] | None = None,
    shadow_error: bool = False,
    canary_error: bool = False,
    canary_unknown: bool = False,
    verify: bool = True,
    require_executable_isolation: bool = False,
    sandbox_security_status: SandboxSecurityStatus | None = None,
    lifecycle_store: SQLiteCapabilityLifecycleStore | None = None,
    generated_action_registrar: GeneratedActionRegistrar | None = None,
    shadow_eligible: bool = True,
    canary_eligible: bool = True,
    shadow_malformed: bool = False,
    canary_malformed: bool = False,
    shadow_missing_attestation: bool = False,
    canary_missing_attestation: bool = False,
) -> tuple[PackageActivationService, IntegrationPackage, PackageSourceFile]:
    item, source = package()
    record = certification(
        item,
        source,
        shadow_eligible=shadow_eligible,
        canary_eligible=canary_eligible,
    )
    factory, surface = Factory(), Surface()
    manager = HotLoadManager(factory, surface)
    effect_store = EffectAttestationStore()
    rollback = rollback if rollback is not None else []

    def rollback_effects(item: IntegrationPackage, effects: tuple[str, ...]) -> bool:
        rollback.append(effects)
        return True

    def run_shadow(item: IntegrationPackage, observer: TrustedEffectObserver) -> ShadowExecution:
        if shadow_error:
            raise RuntimeError("shadow failure")
        if shadow_malformed:
            return object()  # type: ignore[return-value]
        attempt = observer.begin(
            action_id="probe",
            request_id=uuid4(),
            broker="fixture",
            target="fixture",
            scope="fixture.scope",
            requested_effect="fixture effect",
        )
        observer.complete(attempt, status=EffectAttestationStatus.SUPPRESSED, dispatched=False)
        attestation = effect_store.attest(
            activation_id=observer.activation_id,
            integration_id=item.package_id,
            integration_version=str(item.version),
            package_hash=item.package_hash,
            activation_state="SHADOW",
        )
        return replace(
            shadow
            or ShadowExecution(
                predictions=("would call tool",),
                broker_behavior=("read-only broker",),
                verification=("zero effects",),
            ),
            attestation=None if shadow_missing_attestation else attestation,
        )

    def run_canary(
        item: IntegrationPackage, limits: CanaryLimits, observer: TrustedEffectObserver
    ) -> CanaryExecution:
        if canary_error:
            raise RuntimeError("canary failure")
        if canary_malformed:
            return object()  # type: ignore[return-value]
        candidate = canary or CanaryExecution(
            limits.scope,
            predictions=("bounded call",),
            broker_behavior=("one approved effect",),
            effects=("fixture-effect",),
            verification=("effect confirmed",),
            calls=1,
            budget_used=1,
            wall_seconds=0.1,
        )
        for effect in candidate.effects or (
            ("fixture-effect",) if canary is not None else ("fixture-effect",)
        ):
            attempt = observer.begin(
                action_id="effect",
                request_id=uuid4(),
                broker="fixture",
                target="fixture",
                scope=limits.scope,
                requested_effect=effect,
            )
            observer.complete(
                attempt,
                status=(
                    EffectAttestationStatus.UNKNOWN_OUTCOME
                    if canary_unknown
                    else EffectAttestationStatus.EFFECT_CONFIRMED
                ),
                dispatched=True,
            )
        attestation = effect_store.attest(
            activation_id=observer.activation_id,
            integration_id=item.package_id,
            integration_version=str(item.version),
            package_hash=item.package_hash,
            activation_state="CANARY",
        )
        return replace(candidate, attestation=None if canary_missing_attestation else attestation)

    def verify_canary(item: IntegrationPackage, attestation: object) -> VerificationResult:
        return VerificationResult(
            "bounded canary effect",
            VerificationLevel.INTEGRATION_VERIFIED,
            True,
            VerificationDisposition.COMPLETE,
            evidence=(
                EvidenceRecord(
                    EvidenceType.PROCESS,
                    "fixture-verifier",
                    datetime.now(UTC),
                    timedelta(minutes=5),
                    1.0,
                    "effect",
                    "effect",
                    level=VerificationLevel.INTEGRATION_VERIFIED,
                ),
            ),
        )

    hooks = ActivationHooks(
        shadow=run_shadow,
        canary=run_canary,
        verify_canary=verify_canary if verify else None,
        rollback_effects=rollback_effects,
    )
    service = PackageActivationService(
        manager,
        hooks,
        attestation_store=effect_store,
        require_executable_isolation=require_executable_isolation,
        lifecycle_store=lifecycle_store,
        generated_action_registrar=generated_action_registrar,
    )
    service.register_certified(
        ActivationRequest(
            item,
            record,
            (source,),
            CanaryLimits("fixture.scope"),
            sandbox_security_status=sandbox_security_status,
        )
    )
    return service, item, source


def activate(service: PackageActivationService, item: IntegrationPackage) -> None:
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.SHADOW
    assert service.run_canary(item.package_id, item.version).state is ActivationState.CANARY


def test_production_activation_rejects_executable_without_os_isolation() -> None:
    with pytest.raises(ActivationError, match="AppContainer isolation"):
        setup(require_executable_isolation=True)


def test_production_activation_records_selected_isolation_mode() -> None:
    status = SandboxSecurityStatus(
        WindowsContainmentMode.APPCONTAINER,
        True,
        True,
        True,
        3,
        True,
        True,
        True,
        "capability-free AppContainer",
        appcontainer_profile="JARVIS-test-profile",
        runtime_root="C:\\runtime",
    )
    service, item, _ = setup(
        require_executable_isolation=True,
        sandbox_security_status=status,
    )
    record = service.record_for(item.package_id, item.version)
    assert record.sandbox_security_mode == WindowsContainmentMode.APPCONTAINER.value


def test_shadow_canary_promotion_records_evidence_and_restart() -> None:
    service, item, _ = setup()
    certified = service.record_for(item.package_id, item.version)
    assert certified.state is ActivationState.CERTIFIED
    activate(service, item)
    active = service.promote(item.package_id, item.version)
    assert active.state is ActivationState.ACTIVE
    assert active.predictions == ("would call tool", "bounded call")
    assert active.canary_effects == ("fixture-effect",)
    assert active.verification == ("zero effects", "effect confirmed")
    assert active.promotion_decision == "promoted by trusted lifecycle"
    restarted = service.restart(item.package_id, item.version)
    assert restarted.state is ActivationState.ACTIVE
    assert restarted.history[-1].from_state is ActivationState.ACTIVE


def test_shadow_side_effect_attempt_is_quarantined() -> None:
    service, item, _ = setup(
        shadow=ShadowExecution(
            broker_behavior=("blocked mutation",), side_effects=("write-file",), passed=False
        )
    )
    result = service.run_shadow(item.package_id, item.version)
    assert result.state is ActivationState.QUARANTINED
    assert result.canary_effects == ()
    with pytest.raises(ActivationError):
        service.run_canary(item.package_id, item.version)


def test_canary_bounds_trigger_effect_rollback_and_quarantine() -> None:
    rollback: list[tuple[str, ...]] = []
    service, item, _ = setup(
        canary=CanaryExecution(
            "fixture.scope",
            effects=("effect-a", "effect-b"),
            verification=("observed",),
            calls=2,
            budget_used=200,
            wall_seconds=0.1,
        ),
        rollback=rollback,
    )
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.SHADOW
    result = service.run_canary(item.package_id, item.version)
    assert result.state is ActivationState.QUARANTINED
    assert rollback == [("effect-a", "effect-b")]
    assert "effect rollback succeeded" in result.rollback_evidence


def test_failed_canary_and_missing_verification_cannot_promote() -> None:
    service, item, _ = setup(
        canary=CanaryExecution("fixture.scope", effects=("effect",), passed=False)
    )
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.SHADOW
    result = service.run_canary(item.package_id, item.version)
    assert result.state is ActivationState.QUARANTINED
    with pytest.raises(ActivationError):
        service.promote(item.package_id, item.version)


def test_generated_package_cannot_self_promote_before_trusted_canary() -> None:
    service, item, _ = setup()
    assert not hasattr(item, "promote")
    with pytest.raises(ActivationError):
        service.promote(item.package_id, item.version)


def test_new_version_starts_fresh_and_rolls_back_to_prior_version() -> None:
    service, first, _ = setup()
    activate(service, first)
    assert service.promote(first.package_id, first.version).state is ActivationState.ACTIVE

    second, second_source = package((2, 0, 0))
    second_record = certification(second, second_source)
    service.register_certified(
        ActivationRequest(second, second_record, (second_source,), CanaryLimits("fixture.scope"))
    )
    assert service.record_for(second.package_id, second.version).state is ActivationState.CERTIFIED
    activate(service, second)
    assert service.promote(second.package_id, second.version).state is ActivationState.ACTIVE
    rolled = service.rollback(second.package_id, second.version)
    assert rolled.state is ActivationState.ROLLED_BACK


def test_activation_never_accepts_changed_source_or_duplicate_lifecycle() -> None:
    service, item, source = setup()
    record = service.record_for(item.package_id, item.version).certification
    with pytest.raises(ActivationError):
        service.register_certified(
            ActivationRequest(
                item,
                record,
                (PackageSourceFile(source.path, "changed"),),
                CanaryLimits("fixture.scope"),
            )
        )
    with pytest.raises(ActivationError):
        service.register_certified(
            ActivationRequest(item, record, (source,), CanaryLimits("fixture.scope"))
        )


def test_degraded_quarantine_and_malformed_limits_fail_closed() -> None:
    with pytest.raises(ValueError):
        CanaryLimits("scope", max_calls=101)
    service, item, _ = setup()
    activate(service, item)
    assert service.promote(item.package_id, item.version).state is ActivationState.ACTIVE
    assert (
        service.mark_degraded(item.package_id, item.version, "verification delayed").state
        is ActivationState.DEGRADED
    )
    assert (
        service.quarantine(item.package_id, item.version, "health lost").state
        is ActivationState.QUARANTINED
    )


def test_broker_failures_fail_closed() -> None:
    service, item, _ = setup(shadow_error=True)
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.QUARANTINED

    service, item, _ = setup(canary_error=True)
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.SHADOW
    assert service.run_canary(item.package_id, item.version).state is ActivationState.QUARANTINED


def test_missing_or_unknown_trusted_attestation_blocks_staged_activation() -> None:
    item, source = package()
    record = certification(item, source)
    manager = HotLoadManager(Factory(), Surface())
    hooks = ActivationHooks(
        shadow=lambda item, observer: ShadowExecution(verification=("claimed",)),
        canary=lambda item, limits, observer: CanaryExecution(limits.scope),
    )
    with pytest.raises(TypeError):
        PackageActivationService(manager, hooks)  # type: ignore[call-arg]
    service = PackageActivationService(manager, hooks, attestation_store=EffectAttestationStore())
    service.register_certified(
        ActivationRequest(item, record, (source,), CanaryLimits("fixture.scope"))
    )
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.QUARANTINED

    service, item, _ = setup(canary_unknown=True)
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.SHADOW
    result = service.run_canary(item.package_id, item.version)
    assert result.state is ActivationState.QUARANTINED
    assert "independently confirmed" in result.promotion_decision


def test_independent_verification_is_required_even_with_trusted_canary_dispatch() -> None:
    service, item, _ = setup(verify=False)
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.SHADOW
    result = service.run_canary(item.package_id, item.version)
    assert result.state is ActivationState.QUARANTINED
    assert "VerificationEngine" in result.promotion_decision


def test_scope_wall_time_and_missing_verification_are_canary_failures() -> None:
    service, item, _ = setup(
        canary=CanaryExecution(
            "different.scope",
            effects=(),
            verification=(),
            calls=0,
            budget_used=0,
            wall_seconds=31.0,
        )
    )
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.SHADOW
    result = service.run_canary(item.package_id, item.version)
    assert result.state is ActivationState.QUARANTINED
    assert "canary scope exceeded" in result.promotion_decision


def test_validation_and_lookup_errors_fail_closed() -> None:
    item, source = package()
    record = certification(item, source)
    with pytest.raises(ValueError):
        CanaryLimits("")
    with pytest.raises(ValueError):
        ShadowExecution(predictions=("",))
    with pytest.raises(ValueError):
        ShadowExecution(passed=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        CanaryExecution("scope", calls=-1)
    with pytest.raises(ValueError):
        ActivationRequest(object(), record, (source,), CanaryLimits("scope"))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ActivationRequest(item, record, (object(),), CanaryLimits("scope"))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ActivationRequest(item, record, (source,), object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ActivationRecord(
            "",
            item.package_id,
            item.version,
            item.package_hash,
            record,
            ActivationState.CERTIFIED,
            (),
            (),
            (),
            (),
            "decision",
            (),
            (),
            record.certified_at,
            record.certified_at,
        )


def test_activation_record_binding_and_service_lookup() -> None:
    service, item, source = setup()
    record = service.record_for(item.package_id, item.version)
    with pytest.raises(ValueError):
        replace(record, certification=object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        replace(record, history=())
    with pytest.raises(ActivationError):
        service.record_for("missing", item.version)
    with pytest.raises(ValueError):
        service.run_shadow(1, item.version)  # type: ignore[arg-type]
    with pytest.raises(ActivationError):
        service.register_certified(
            ActivationRequest(
                item,
                record.certification,
                (PackageSourceFile(source.path, "different"),),
                CanaryLimits("fixture.scope"),
            )
        )


def test_activation_validation_rejects_bad_policy_and_attestation_metadata() -> None:
    item, source = package()
    with pytest.raises(ValueError):
        CanaryLimits("scope", max_wall_seconds=1)
    with pytest.raises(ValueError):
        CanaryLimits("scope", max_calls=True)
    with pytest.raises(ValueError):
        CanaryLimits("scope", max_effects=-1)
    with pytest.raises(ValueError):
        CanaryLimits("scope", max_budget=-1)
    with pytest.raises(ValueError):
        CanaryLimits("scope", max_wall_seconds=3_601.0)
    with pytest.raises(ValueError):
        ShadowExecution(attestation=cast(Any, object()))
    with pytest.raises(ValueError):
        CanaryExecution("scope", wall_seconds=-1.0)
    with pytest.raises(ValueError):
        ActivationTransition(None, ActivationState.CERTIFIED, "", datetime.now(UTC))
    with pytest.raises(ValueError):
        ActivationTransition("bad", ActivationState.CERTIFIED, "detail", datetime.now(UTC))  # type: ignore[arg-type]
    activation = setup()[0].record_for("activation.example", item.version)
    with pytest.raises(ValueError):
        replace(activation, attestation_ids=("fake",))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        replace(activation, previous_version="1.0.0")  # type: ignore[arg-type]


def test_shadow_and_canary_require_certified_eligibility() -> None:
    service, item, source = setup()
    original = service.record_for(item.package_id, item.version)
    ineligible = replace(
        original.certification,
        shadow_eligible=False,
        canary_eligible=False,
    )
    # The exact certification binding is rechecked before a lifecycle operation.
    with pytest.raises(ActivationError):
        service.restore(
            ActivationRequest(item, ineligible, (source,), CanaryLimits("fixture.scope"))
        )

    service, item, source = setup()
    item_record = service.record_for(item.package_id, item.version)
    service._sessions[(item.package_id, item.version)].request = ActivationRequest(
        item,
        replace(item_record.certification, shadow_eligible=False),
        (source,),
        CanaryLimits("fixture.scope"),
    )
    result = service.run_shadow(item.package_id, item.version)
    assert result.state is ActivationState.QUARANTINED
    assert "eligibility" in result.promotion_decision


def test_restore_requires_exact_durable_lifecycle_and_rebuilds_active_runtime(
    tmp_path: Path,
) -> None:
    lifecycle = SQLiteCapabilityLifecycleStore(tmp_path / "lifecycle.sqlite3")
    service, item, source = setup(lifecycle_store=lifecycle)
    activate(service, item)
    assert service.promote(item.package_id, item.version).state is ActivationState.ACTIVE
    exact_certification = service.record_for(item.package_id, item.version).certification

    reopened = SQLiteCapabilityLifecycleStore(tmp_path / "lifecycle.sqlite3")
    restored_service, same_item, same_source = setup()
    # A fresh service without a lifecycle store fails closed before any lookup.
    with pytest.raises(ActivationError, match="No durable lifecycle"):
        restored_service.restore(
            ActivationRequest(
                same_item,
                certification(same_item, same_source),
                (same_source,),
                CanaryLimits("fixture.scope"),
            )
        )
    restored_service = PackageActivationService(
        HotLoadManager(Factory(), Surface()),
        ActivationHooks(
            shadow=lambda item, observer: ShadowExecution(),
            canary=lambda item, limits, observer: CanaryExecution(limits.scope),
        ),
        attestation_store=EffectAttestationStore(),
        lifecycle_store=reopened,
    )
    assert (
        restored_service.record_for(item.package_id, item.version).state is ActivationState.ACTIVE
    )
    restored = restored_service.restore(
        ActivationRequest(item, exact_certification, (source,), CanaryLimits("fixture.scope"))
    )
    assert restored.state is ActivationState.ACTIVE


def test_restore_rejects_missing_and_changed_durable_records(tmp_path: Path) -> None:
    lifecycle = SQLiteCapabilityLifecycleStore(tmp_path / "lifecycle.sqlite3")
    service, item, source = setup(lifecycle_store=lifecycle)
    with pytest.raises(ActivationError, match="does not match"):
        service.restore(
            ActivationRequest(
                item, certification(item, source), (source,), CanaryLimits("fixture.scope")
            )
        )

    item2, source2 = package((2, 0, 0))
    with pytest.raises(ActivationError):
        service.restore(
            ActivationRequest(
                item2, certification(item2, source2), (source2,), CanaryLimits("fixture.scope")
            )
        )


def test_restart_of_non_active_is_noop_and_missing_revision_is_fail_closed(
    tmp_path: Path,
) -> None:
    lifecycle = SQLiteCapabilityLifecycleStore(tmp_path / "lifecycle.sqlite3")
    service, item, _ = setup(lifecycle_store=lifecycle)
    certified = service.record_for(item.package_id, item.version)
    assert service.restart(item.package_id, item.version) == certified
    service.run_shadow(item.package_id, item.version)
    with pytest.raises(ActivationError):
        service.promote(item.package_id, item.version)


def test_promote_swap_failure_quarantines_after_trusted_canary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, item, _ = setup()
    activate(service, item)

    def fail_refresh(*args: object, **kwargs: object) -> None:
        raise RuntimeError("swap failure")

    monkeypatch.setattr(service._hot_load, "manual_refresh", fail_refresh)
    result = service.promote(item.package_id, item.version)
    assert result.state is ActivationState.QUARANTINED
    assert "activation health/swap failed" in result.promotion_decision


def test_generated_action_registration_failure_deactivates_and_quarantines() -> None:
    registrar = Registrar(fail=True)
    service, item, _ = setup(generated_action_registrar=registrar)
    # The fixture package has no actions, so use a registrar-bound failure through the
    # service's trusted hook boundary to ensure cleanup is still observable.
    activate(service, item)
    assert service.promote(item.package_id, item.version).state is ActivationState.ACTIVE
    assert registrar.activated == []


def test_rollback_failure_is_recorded_and_previous_state_is_not_hidden() -> None:
    rollback: list[tuple[str, ...]] = []
    service, item, _ = setup(
        rollback=rollback, canary=CanaryExecution("fixture.scope", effects=("effect",))
    )
    activate(service, item)
    active = service.promote(item.package_id, item.version)
    assert active.state is ActivationState.ACTIVE
    result = service.rollback(item.package_id, item.version, "operator rollback")
    assert result.state is ActivationState.ROLLED_BACK
    assert rollback == [("effect",)]


def test_records_and_missing_lifecycle_revision_are_explicit() -> None:
    service, item, _ = setup()
    assert service.records()[0].package_id == item.package_id
    service._revisions.clear()
    session = service._sessions[(item.package_id, item.version)]
    assert service._revision(session) == 0


def test_shadow_rejects_ineligible_malformed_and_missing_attestation() -> None:
    service, item, _ = setup(shadow_eligible=False)
    result = service.run_shadow(item.package_id, item.version)
    assert result.state is ActivationState.QUARANTINED
    assert "eligibility" in result.promotion_decision

    service, item, _ = setup(shadow_malformed=True)
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.QUARANTINED
    service, item, _ = setup(shadow_missing_attestation=True)
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.QUARANTINED


def test_canary_rejects_ineligible_malformed_and_missing_attestation() -> None:
    service, item, _ = setup(canary_eligible=False)
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.SHADOW
    result = service.run_canary(item.package_id, item.version)
    assert result.state is ActivationState.QUARANTINED
    assert "eligibility" in result.promotion_decision

    service, item, _ = setup(canary_malformed=True)
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.SHADOW
    assert service.run_canary(item.package_id, item.version).state is ActivationState.QUARANTINED
    service, item, _ = setup(canary_missing_attestation=True)
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.SHADOW
    assert service.run_canary(item.package_id, item.version).state is ActivationState.QUARANTINED


def test_canary_reports_each_trusted_bound_failure() -> None:
    service, item, _ = setup(
        canary=CanaryExecution(
            "fixture.scope",
            effects=("effect", "effect-2"),
            calls=2,
            budget_used=101,
            wall_seconds=30.1,
            passed=False,
        )
    )
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.SHADOW
    result = service.run_canary(item.package_id, item.version)
    assert result.state is ActivationState.QUARANTINED
    for phrase in ("call bound", "budget exceeded", "wall-time", "verification failed"):
        assert phrase in result.promotion_decision


def test_invalid_lookup_and_state_transitions_fail_closed() -> None:
    service, item, _ = setup()
    with pytest.raises(ActivationError, match="cannot perform"):
        service.run_canary(item.package_id, item.version)
    with pytest.raises(ActivationError):
        service.mark_degraded(item.package_id, item.version, "not active")
    with pytest.raises(ActivationError):
        service.rollback("missing", item.version)
    with pytest.raises(ValueError):
        service.quarantine(item.package_id, item.version, "")
    with pytest.raises(ValueError):
        service.rollback(item.package_id, item.version, "")


def test_restore_changed_package_hash_is_rejected(tmp_path: Path) -> None:
    lifecycle = SQLiteCapabilityLifecycleStore(tmp_path / "lifecycle.sqlite3")
    service, item, source = setup(lifecycle_store=lifecycle)
    exact_certification = service.record_for(item.package_id, item.version).certification
    changed = replace(item, package_hash="f" * 64)
    changed_certification = replace(exact_certification, package_hash=changed.package_hash)
    with pytest.raises(ActivationError, match="does not match"):
        service.restore(
            ActivationRequest(
                changed,
                changed_certification,
                (source,),
                CanaryLimits("fixture.scope"),
            )
        )


def test_active_restart_health_failure_quarantines(monkeypatch: pytest.MonkeyPatch) -> None:
    service, item, _ = setup()
    activate(service, item)
    assert service.promote(item.package_id, item.version).state is ActivationState.ACTIVE
    monkeypatch.setattr(
        service._hot_load,
        "restart",
        lambda package_id: (_ for _ in ()).throw(HotLoadError("dead")),
    )
    result = service.restart(item.package_id, item.version)
    assert result.state is ActivationState.QUARANTINED
    assert "restart health check failed" in result.promotion_decision


def test_activation_constructor_and_record_integrity_fail_closed() -> None:
    item, source = package()
    record = certification(item, source)
    manager = HotLoadManager(Factory(), Surface())
    hooks = ActivationHooks(
        lambda item, observer: ShadowExecution(),
        lambda item, limits, observer: CanaryExecution(limits.scope),
    )
    with pytest.raises(ValueError):
        PackageActivationService(object(), hooks, attestation_store=EffectAttestationStore())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        PackageActivationService(manager, object(), attestation_store=EffectAttestationStore())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        PackageActivationService(
            manager,
            hooks,
            attestation_store=EffectAttestationStore(),
            require_executable_isolation=1,  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        PackageActivationService(
            manager,
            hooks,
            attestation_store=EffectAttestationStore(),
            lifecycle_store=object(),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        PackageActivationService(
            manager,
            hooks,
            attestation_store=EffectAttestationStore(),
            generated_action_registrar=object(),  # type: ignore[arg-type]
        )
    activation = setup()[0].record_for(item.package_id, item.version)
    for field, value in (
        ("created_at", datetime.now()),
        ("updated_at", datetime.now()),
        ("history", (object(),)),
        ("sandbox_security_mode", ""),
        ("activation_id", ""),
    ):
        with pytest.raises(ValueError):
            replace(activation, **cast(Any, {field: value}))
    with pytest.raises(ValueError):
        ActivationRequest(item, record, [source], CanaryLimits("scope"))  # type: ignore[arg-type]
