from __future__ import annotations

from dataclasses import replace
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
from jarvis.package_certification import (
    BuiltPackage,
    CertificationFailure,
    CertificationHooks,
    CertificationRecord,
    CertificationRequest,
    CertificationStage,
    CertificationStageResult,
    PackageCertifier,
    package_fingerprints,
)
from jarvis.package_reviewer import PackageSourceFile
from jarvis.package_runtime import PackageCertification
from jarvis.permissions.models import Permission
from jarvis.tools.models import SemanticVersion

PROVENANCE = PackageProvenance("generated", "revision-1", "MIT", "NOTICE", "trusted-reviewer")


def package(
    source: str = "def run():\n    return 1\n",
) -> tuple[IntegrationPackage, PackageSourceFile]:
    source_hash = sha256(source.encode()).hexdigest()
    item = IntegrationPackage(
        "certification.example",
        SemanticVersion(1, 0, 0),
        PackageLayout(),
        (
            PackageEntry(
                "python", "code/main.py", PackageBoundary.PACKAGE_CODE, source_hash, PROVENANCE
            ),
        ),
        permissions=(Permission.NETWORK_REQUEST,),
        dependency_lock=("example-lib==1.2.3",),
        lifecycle=PackageLifecycle.VALIDATED,
        provenance=PROVENANCE,
        package_hash=sha256(b"package-revision").hexdigest(),
    )
    return item, PackageSourceFile("code/main.py", source)


def request(item: IntegrationPackage) -> CertificationRequest:
    return CertificationRequest(
        item,
        "restore-point:previous",
        ("windows", "python-3.12"),
        ("returns deterministic bounded result",),
    )


def hooks(
    order: list[CertificationStage], *, failed: CertificationStage | None = None
) -> CertificationHooks:
    def stage(stage_name: CertificationStage) -> CertificationStageResult:
        order.append(stage_name)
        if failed is stage_name:
            return CertificationStageResult(False, (f"{stage_name.value} failed",))
        if stage_name is CertificationStage.AUTHORITY_DECISION:
            return CertificationStageResult(
                True,
                ("trusted authority decision",),
                "approval:fixture",
                shadow_eligible=True,
                canary_eligible=True,
            )
        if stage_name is CertificationStage.HEALTHCHECK:
            return CertificationStageResult(True, ("healthy",), health=("healthy",))
        if stage_name is CertificationStage.VERIFICATION:
            return CertificationStageResult(
                True, ("baseline verified",), verification=("verified",)
            )
        return CertificationStageResult(True, (f"{stage_name.value} passed",))

    return CertificationHooks(
        build=lambda item: BuiltPackage(item, ()),
        unit_tests=lambda item: stage(CertificationStage.UNIT_TESTS),
        sandbox_integration_test=lambda item: stage(CertificationStage.SANDBOX_INTEGRATION_TEST),
        permission_diff=lambda item: stage(CertificationStage.PERMISSION_DIFF),
        authority_decision=lambda item: stage(CertificationStage.AUTHORITY_DECISION),
        install=lambda item: stage(CertificationStage.INSTALL),
        healthcheck=lambda item: stage(CertificationStage.HEALTHCHECK),
        verification=lambda item: stage(CertificationStage.VERIFICATION),
    )


def test_certification_runs_in_order_and_is_not_activation() -> None:
    item, source = package()
    order: list[CertificationStage] = []
    cert_hooks = hooks(order)

    def build_with_source(built: IntegrationPackage) -> BuiltPackage:
        order.append(CertificationStage.BUILD)
        return BuiltPackage(built, (source,))

    cert_hooks = replace(
        cert_hooks,
        build=build_with_source,
    )
    record = PackageCertifier().certify(request(item), cert_hooks)
    assert tuple(order) == (
        CertificationStage.BUILD,
        CertificationStage.UNIT_TESTS,
        CertificationStage.SANDBOX_INTEGRATION_TEST,
        CertificationStage.PERMISSION_DIFF,
        CertificationStage.AUTHORITY_DECISION,
        CertificationStage.INSTALL,
        CertificationStage.HEALTHCHECK,
        CertificationStage.VERIFICATION,
    )
    assert tuple(stage.stage for stage in record.stages) == tuple(CertificationStage)
    assert record.shadow_eligible and record.canary_eligible
    assert record.approval_ref == "approval:fixture"
    assert record.matches(item, (source,))
    assert record.stages[-1].stage is CertificationStage.CERTIFIED
    activation_gate = PackageCertification.from_record(record)
    assert activation_gate.record is record
    assert activation_gate.certified and activation_gate.permission_diff_approved


@pytest.mark.parametrize("stage", tuple(CertificationStage)[:-1])
def test_each_certification_failure_stops_at_the_failed_stage(stage: CertificationStage) -> None:
    item, source = package()
    order: list[CertificationStage] = []
    cert_hooks = hooks(order, failed=stage)

    def build_with_source(built: IntegrationPackage) -> BuiltPackage:
        order.append(CertificationStage.BUILD)
        return BuiltPackage(built, (source,))

    cert_hooks = replace(
        cert_hooks,
        build=build_with_source,
    )
    if stage is CertificationStage.BUILD:
        cert_hooks = replace(
            cert_hooks, build=lambda built: (_ for _ in ()).throw(RuntimeError("build"))
        )
    if stage is CertificationStage.STATIC_AUDIT:
        bad_item, bad_source = package("value = eval(payload)\n")
        cert_hooks = replace(
            cert_hooks,
            build=lambda built: BuiltPackage(bad_item, (bad_source,)),
        )
    with pytest.raises(CertificationFailure) as failure:
        PackageCertifier().certify(request(item), cert_hooks)
    assert failure.value.stage is stage
    assert failure.value.evidence[-1].stage is stage
    assert CertificationStage.CERTIFIED not in order


def test_privileged_package_requires_trusted_authority_reference() -> None:
    item, source = package()
    cert_hooks = hooks([])
    cert_hooks = replace(
        cert_hooks,
        build=lambda built: BuiltPackage(built, (source,)),
        authority_decision=lambda item: CertificationStageResult(True, ("missing approval",)),
    )
    with pytest.raises(CertificationFailure) as failure:
        PackageCertifier().certify(request(item), cert_hooks)
    assert failure.value.stage is CertificationStage.AUTHORITY_DECISION


def test_ui_harness_requirement_is_mandatory_and_fail_closed() -> None:
    item, source = package()
    ui_item = replace(item, profiles=("desktop",))
    cert_hooks = replace(hooks([]), build=lambda built: BuiltPackage(built, (source,)))
    with pytest.raises(CertificationFailure) as unavailable:
        PackageCertifier().certify(request(ui_item), cert_hooks)
    assert unavailable.value.stage is CertificationStage.VERIFICATION
    with pytest.raises(CertificationFailure) as failure:
        PackageCertifier().certify(
            replace(request(ui_item), ui_simulation_harness_available=True),
            cert_hooks,
        )
    assert failure.value.stage is CertificationStage.VERIFICATION
    record = PackageCertifier().certify(
        replace(
            request(ui_item),
            ui_simulation_harness_available=True,
            ui_simulation_evidence=("ui harness passed",),
        ),
        cert_hooks,
    )
    assert record.verification[-1] == "ui harness passed"


def test_fingerprints_invalidate_code_dependency_manifest_and_permission_changes() -> None:
    item, source = package()
    order: list[CertificationStage] = []
    cert_hooks = replace(
        hooks(order),
        build=lambda built: BuiltPackage(built, (source,)),
    )
    record = PackageCertifier().certify(request(item), cert_hooks)
    assert record.matches(item, (source,))
    assert not record.matches(item, (PackageSourceFile(source.path, "changed"),))
    assert not record.matches(replace(item, dependency_lock=("example-lib==9.9.9",)), (source,))
    assert not record.matches(replace(item, events=("new-event",)), (source,))
    assert not record.matches(replace(item, permissions=()), (source,))
    assert not record.matches(replace(item, version=SemanticVersion(2, 0, 0)), (source,))
    assert len(package_fingerprints(item, (source,))) == 3


def test_malformed_stage_and_record_evidence_fails_closed() -> None:
    with pytest.raises(ValueError):
        CertificationStageResult(True, evidence=("",))
    with pytest.raises(ValueError):
        CertificationRequest(object(), "rollback", (), ())  # type: ignore[arg-type]
    item, source = package()
    cert_hooks = replace(hooks([]), build=lambda built: BuiltPackage(built, (source,)))
    record = PackageCertifier().certify(request(item), cert_hooks)
    with pytest.raises(ValueError):
        CertificationRecord(
            record.package_id,
            record.version,
            "not-a-hash",
            record.source_hash,
            record.dependency_hash,
            record.manifest_hash,
            record.test_evidence,
            record.audit,
            record.permissions,
            record.approval_ref,
            record.environment_compatibility,
            record.health,
            record.verification,
            record.rollback_target,
            record.shadow_eligible,
            record.canary_eligible,
            record.expected_behavior_baseline,
            record.stages,
            record.certified_at,
        )
