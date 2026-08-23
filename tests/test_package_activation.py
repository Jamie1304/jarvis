from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from hashlib import sha256

import pytest
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
    CanaryExecution,
    CanaryLimits,
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
from jarvis.package_runtime import HotLoadManager, PackageRuntimeHealth, PreparedPackageRuntime
from jarvis.tools.models import SemanticVersion

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


def certification(item: IntegrationPackage, source: PackageSourceFile) -> CertificationRecord:
    def stage(name: CertificationStage) -> CertificationStageResult:
        if name is CertificationStage.AUTHORITY_DECISION:
            return CertificationStageResult(
                True,
                ("trusted authority",),
                "approval:activation-fixture",
                shadow_eligible=True,
                canary_eligible=True,
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


def setup(
    *,
    shadow: ShadowExecution | None = None,
    canary: CanaryExecution | None = None,
    rollback: list[tuple[str, ...]] | None = None,
    shadow_error: bool = False,
    canary_error: bool = False,
) -> tuple[PackageActivationService, IntegrationPackage, PackageSourceFile]:
    item, source = package()
    record = certification(item, source)
    factory, surface = Factory(), Surface()
    manager = HotLoadManager(factory, surface)
    rollback = rollback if rollback is not None else []

    def rollback_effects(item: IntegrationPackage, effects: tuple[str, ...]) -> bool:
        rollback.append(effects)
        return True

    def run_shadow(item: IntegrationPackage) -> ShadowExecution:
        if shadow_error:
            raise RuntimeError("shadow failure")
        return shadow or ShadowExecution(
            predictions=("would call tool",),
            broker_behavior=("read-only broker",),
            verification=("zero effects",),
        )

    def run_canary(item: IntegrationPackage, limits: CanaryLimits) -> CanaryExecution:
        if canary_error:
            raise RuntimeError("canary failure")
        return canary or CanaryExecution(
            limits.scope,
            predictions=("bounded call",),
            broker_behavior=("one approved effect",),
            effects=("fixture-effect",),
            verification=("effect confirmed",),
            calls=1,
            budget_used=1,
            wall_seconds=0.1,
        )

    hooks = ActivationHooks(
        shadow=run_shadow,
        canary=run_canary,
        rollback_effects=rollback_effects,
    )
    service = PackageActivationService(manager, hooks)
    service.register_certified(
        ActivationRequest(item, record, (source,), CanaryLimits("fixture.scope"))
    )
    return service, item, source


def activate(service: PackageActivationService, item: IntegrationPackage) -> None:
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.SHADOW
    assert service.run_canary(item.package_id, item.version).state is ActivationState.CANARY


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
