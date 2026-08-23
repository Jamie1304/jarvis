from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import pytest
from jarvis.capability_health import (
    AttentionNotice,
    BehaviorBaseline,
    BehaviorObservation,
    CapabilityHealthError,
    CapabilityHealthReport,
    CapabilityHealthService,
    DependencyGraph,
    DependencyKind,
    DependencyNode,
    DriftClass,
    DriftFinding,
    DriftReport,
    HealthProbeMode,
    HealthProbeResult,
    HealthStatus,
    RepairAction,
    RepairDiagnosis,
    RepairOutcome,
    RepairResult,
    RepairStage,
    RequestVolumeBaseline,
)
from jarvis.events import InMemoryEventBus
from jarvis.package_activation import ActivationState
from jarvis.trace import TraceEventType

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def baseline(**changes: object) -> BehaviorBaseline:
    values: dict[str, object] = {
        "capability_id": "fixture.integration",
        "package_version": "1.0.0",
        "certification_ref": "certification:fixture:1.0.0",
        "network_hosts": frozenset({"api.example.test"}),
        "filesystem_roots": frozenset({"workspace-root"}),
        "broker_calls": frozenset({"read_file"}),
        "credential_scopes": frozenset({"fixture.read"}),
        "subprocess_policy": frozenset({"fixture-helper.exe"}),
        "request_volume": RequestVolumeBaseline(60, 10, 2.0),
        "event_subscriptions": frozenset({"task.completed"}),
        "event_emissions": frozenset({"capability.changed"}),
        "persistence_operations": frozenset({"package-cache.read"}),
    }
    values.update(changes)
    return BehaviorBaseline(**cast(Any, values))


def observation(**changes: object) -> BehaviorObservation:
    values: dict[str, object] = {
        "capability_id": "fixture.integration",
        "source": "broker",
        "trusted": True,
        "network_hosts": frozenset({"api.example.test"}),
        "filesystem_roots": frozenset({"workspace-root"}),
        "broker_calls": frozenset({"read_file"}),
        "credential_scopes": frozenset({"fixture.read"}),
        "processes": frozenset({"fixture-helper.exe"}),
        "request_volume": 10,
        "event_subscriptions": frozenset({"task.completed"}),
        "event_emissions": frozenset({"capability.changed"}),
        "persistence_operations": frozenset({"package-cache.read"}),
        "evidence": ("trusted broker observation",),
    }
    values.update(changes)
    return BehaviorObservation(**cast(Any, values))


def service(*, attention: list[AttentionNotice] | None = None) -> CapabilityHealthService:
    return CapabilityHealthService(
        attention_sink=(cast(Any, attention.append) if attention is not None else None),
        clock=lambda: NOW,
    )


def test_health_modes_dependencies_and_compatibility() -> None:
    monitor = service()
    graph = DependencyGraph(
        (
            DependencyNode(
                "local-model",
                DependencyKind.MODEL,
                expected_version="1.0",
                observed_version="1.0",
                expected_api="chat.v1",
                observed_api="chat.v1",
            ),
            DependencyNode("config", DependencyKind.CONFIG),
        )
    )
    report = monitor.evaluate_health(
        "fixture.integration",
        (
            HealthProbeResult(HealthProbeMode.PASSIVE, True, "seen", NOW),
            HealthProbeResult(HealthProbeMode.READ_ONLY, True, "inspected", NOW),
            HealthProbeResult(HealthProbeMode.FUNCTIONAL, True, "worked", NOW),
            HealthProbeResult(HealthProbeMode.DEPENDENCY, True, "available", NOW, "config"),
            HealthProbeResult(
                HealthProbeMode.VERSION_API_COMPATIBILITY,
                True,
                "compatible",
                NOW,
                "local-model",
            ),
        ),
        dependencies=graph,
    )
    assert report.status is HealthStatus.HEALTHY
    assert report.version_compatible is True
    assert report.api_compatible is True
    assert monitor.health("fixture.integration") is report

    unavailable = monitor.evaluate_health(
        "fixture.integration",
        (HealthProbeResult(HealthProbeMode.FUNCTIONAL, False, "failed", NOW),),
    )
    assert unavailable.status is HealthStatus.UNAVAILABLE
    degraded = monitor.evaluate_health(
        "fixture.integration",
        (HealthProbeResult(HealthProbeMode.READ_ONLY, False, "stale", NOW),),
        dependencies=DependencyGraph((DependencyNode("api", DependencyKind.API, "v1", "v2"),)),
    )
    assert degraded.status is HealthStatus.DEGRADED
    assert monitor.evaluate_health("new", ()).status is HealthStatus.UNKNOWN


def test_contract_validation_and_dependency_lookup_fail_closed() -> None:
    with pytest.raises(CapabilityHealthError):
        HealthProbeResult("bad", True, "detail", NOW)  # type: ignore[arg-type]
    with pytest.raises(CapabilityHealthError):
        HealthProbeResult(HealthProbeMode.PASSIVE, True, "detail", datetime.now())
    with pytest.raises(CapabilityHealthError):
        DependencyNode("dependency", "bad")  # type: ignore[arg-type]
    with pytest.raises(CapabilityHealthError):
        DependencyNode("dependency", DependencyKind.API, available=1)  # type: ignore[arg-type]
    node = DependencyNode("dependency", DependencyKind.API, detail="API", provenance=("test",))
    graph = DependencyGraph((node,))
    assert graph.node("dependency") is node
    with pytest.raises(KeyError):
        graph.node("missing")
    with pytest.raises(CapabilityHealthError):
        DependencyGraph((node, node))
    with pytest.raises(CapabilityHealthError):
        DependencyGraph((object(),))  # type: ignore[arg-type]

    with pytest.raises(CapabilityHealthError):
        CapabilityHealthReport("fixture", "bad", "detail", NOW)  # type: ignore[arg-type]
    with pytest.raises(CapabilityHealthError):
        CapabilityHealthReport("fixture", HealthStatus.HEALTHY, "detail", NOW, (object(),))  # type: ignore[arg-type]
    with pytest.raises(CapabilityHealthError):
        CapabilityHealthReport("fixture", HealthStatus.HEALTHY, "detail", NOW, version_compatible=1)  # type: ignore[arg-type]
    with pytest.raises(CapabilityHealthError):
        RequestVolumeBaseline(0, 1, 1.0)
    with pytest.raises(CapabilityHealthError):
        RequestVolumeBaseline(1, 1, 0.5)

    bad = baseline()
    with pytest.raises(CapabilityHealthError):
        BehaviorBaseline(
            bad.capability_id,
            bad.package_version,
            bad.certification_ref,
            request_volume=object(),  # type: ignore[arg-type]
        )
    with pytest.raises(CapabilityHealthError):
        BehaviorBaseline(
            bad.capability_id,
            bad.package_version,
            bad.certification_ref,
            activation_state="ACTIVE",  # type: ignore[arg-type]
        )
    with pytest.raises(CapabilityHealthError):
        BehaviorObservation("fixture", "broker", True, request_volume=-1)
    with pytest.raises(CapabilityHealthError):
        BehaviorObservation("fixture", "model", True)

    with pytest.raises(CapabilityHealthError):
        DriftFinding("bad", "fixture", "host", DriftClass.EXPECTED, (), (), "detail", NOW, True)  # type: ignore[arg-type]
    finding = DriftFinding(
        uuid4(), "fixture", "host", DriftClass.MATERIAL_DRIFT, (), ("x",), "detail", NOW, True
    )
    report = DriftReport(
        "fixture",
        "hash",
        observation(),
        DriftClass.MATERIAL_DRIFT,
        (finding,),
        ActivationState.ACTIVE,
        ActivationState.DEGRADED,
    )
    assert report.accepted is True
    with pytest.raises(CapabilityHealthError):
        DriftReport(
            "fixture",
            "hash",
            cast(Any, object()),
            DriftClass.MATERIAL_DRIFT,
            (),
            ActivationState.ACTIVE,
            ActivationState.DEGRADED,
        )
    with pytest.raises(CapabilityHealthError):
        DriftReport(
            "fixture",
            "hash",
            observation(),
            DriftClass.MATERIAL_DRIFT,
            cast(Any, (object(),)),
            ActivationState.ACTIVE,
            ActivationState.DEGRADED,
        )
    with pytest.raises(CapabilityHealthError):
        AttentionNotice("fixture", "bad", "notice")  # type: ignore[arg-type]
    with pytest.raises(CapabilityHealthError):
        AttentionNotice("fixture", DriftClass.MATERIAL_DRIFT, "notice", ("bad",))  # type: ignore[arg-type]


def test_repair_contract_validation_and_failure_paths() -> None:
    with pytest.raises(CapabilityHealthError):
        RepairAction("id", "refresh", "scope", "detail", safe=1)  # type: ignore[arg-type]
    action = RepairAction("id", "refresh", "scope", "detail", requires_permission=False)
    with pytest.raises(CapabilityHealthError):
        RepairDiagnosis(object())  # type: ignore[arg-type]
    diagnosis = RepairDiagnosis(action, detail="diagnosis")
    with pytest.raises(CapabilityHealthError):
        RepairDiagnosis(action, rebuild_or_replace=1)  # type: ignore[arg-type]
    with pytest.raises(CapabilityHealthError):
        RepairResult(
            cast(Any, "bad"),
            "fixture",
            RepairOutcome.FAILED,
            RepairStage.FAILED,
            (RepairStage.FAILED,),
            "detail",
        )
    with pytest.raises(CapabilityHealthError):
        RepairResult(uuid4(), "fixture", RepairOutcome.FAILED, RepairStage.FAILED, (), "detail")
    assert diagnosis.detail == "diagnosis"

    monitor = service()
    monitor.register_baseline(baseline())
    with pytest.raises(CapabilityHealthError):
        monitor.repair("fixture.integration", object())  # type: ignore[arg-type]
    with pytest.raises(CapabilityHealthError):
        monitor.repair(
            "fixture.integration",
            RepairFixture(
                CapabilityHealthReport("fixture.integration", HealthStatus.HEALTHY, "ok", NOW)
            ),
        )
    monitor.record_trusted_broker_observation(observation(request_volume=11))

    class NoAction:
        def diagnose(
            self, capability_id: str, findings: tuple[DriftFinding, ...]
        ) -> RepairDiagnosis:
            return RepairDiagnosis(None, detail="manual review")

        def safe_repair(self, capability_id: str, action: RepairAction) -> bool:
            return True

        def rebuild_or_replace(self, capability_id: str, diagnosis: RepairDiagnosis) -> bool:
            return False

        def retest(self, capability_id: str) -> CapabilityHealthReport:
            return CapabilityHealthReport(capability_id, HealthStatus.HEALTHY, "ok", NOW)

    result = monitor.repair("fixture.integration", NoAction())
    assert result.outcome is RepairOutcome.FAILED

    class BadDiagnosis:
        def diagnose(self, capability_id: str, findings: tuple[DriftFinding, ...]) -> object:
            return object()

        def safe_repair(self, capability_id: str, action: RepairAction) -> bool:
            return True

        def rebuild_or_replace(self, capability_id: str, diagnosis: RepairDiagnosis) -> bool:
            return True

        def retest(self, capability_id: str) -> CapabilityHealthReport:
            return healthy_report()

    result = monitor.repair("fixture.integration", cast(Any, BadDiagnosis()))
    assert result.outcome is RepairOutcome.FAILED


def healthy_report() -> CapabilityHealthReport:
    return CapabilityHealthReport("fixture.integration", HealthStatus.HEALTHY, "ok", NOW)


def test_baseline_is_hashed_and_generated_or_model_rewrites_fail() -> None:
    monitor = service()
    original = baseline()
    monitor.register_baseline(original, authority="certification")
    assert monitor.baseline(original.capability_id).fingerprint() == original.baseline_hash
    with pytest.raises(CapabilityHealthError):
        monitor.register_baseline(original)
    with pytest.raises(CapabilityHealthError):
        monitor.register_baseline(original, generated=True, replace=True)
    with pytest.raises(CapabilityHealthError):
        monitor.register_baseline(original, model_output=True, replace=True)
    with pytest.raises(CapabilityHealthError):
        monitor.register_baseline(original, authority="model", replace=True)
    with pytest.raises(CapabilityHealthError):
        monitor.register_baseline(replace(original, package_version="1.0.0"), replace=True)
    replacement = baseline(package_version="2.0.0", certification_ref="certification:fixture:2.0.0")
    monitor.register_baseline(replacement, authority="package_certifier", replace=True)
    assert monitor.baseline(original.capability_id).package_version == "2.0.0"
    with pytest.raises(CapabilityHealthError):
        replace(original, baseline_hash="not-the-content-hash")


def test_expected_and_low_risk_drift_are_traced_and_notify_attention() -> None:
    notices: list[AttentionNotice] = []
    monitor = service(attention=notices)
    monitor.register_baseline(baseline())
    expected = monitor.record_trusted_broker_observation(observation())
    assert expected.classification is DriftClass.EXPECTED
    assert expected.resulting_activation_state is ActivationState.ACTIVE
    low = monitor.record_trusted_broker_observation(observation(request_volume=11))
    assert low.classification is DriftClass.LOW_RISK_DRIFT
    assert low.resulting_activation_state is ActivationState.DEGRADED
    assert notices[-1].severity is DriftClass.LOW_RISK_DRIFT
    assert [event.event_type for event in monitor.trace.events] == [
        TraceEventType.DRIFT,
        TraceEventType.DRIFT,
    ]


def test_material_and_security_drift_escalate_without_auto_recovery() -> None:
    monitor = service()
    monitor.register_baseline(baseline())
    material = monitor.record_trusted_broker_observation(
        observation(network_hosts=frozenset({"api.example.test", "new.example.test"}))
    )
    assert material.classification is DriftClass.MATERIAL_DRIFT
    assert material.resulting_activation_state is ActivationState.DEGRADED
    security = monitor.record_trusted_broker_observation(
        observation(credential_scopes=frozenset({"fixture.read", "fixture.write"}))
    )
    assert security.classification is DriftClass.SECURITY_DRIFT
    assert security.resulting_activation_state is ActivationState.QUARANTINED
    assert monitor.activation_state("fixture.integration") is ActivationState.QUARANTINED
    assert monitor.health("fixture.integration").status is HealthStatus.QUARANTINED
    still = monitor.record_trusted_broker_observation(observation())
    assert still.resulting_activation_state is ActivationState.QUARANTINED
    assert {finding.category for finding in security.findings} == {"credential_scopes"}


def test_all_security_drift_categories_and_broker_trust_boundary() -> None:
    monitor = service()
    monitor.register_baseline(baseline())
    drift = monitor.record_trusted_broker_observation(
        observation(
            filesystem_roots=frozenset({"workspace-root", "outside-root"}),
            broker_calls=frozenset({"read_file", "write_file"}),
            processes=frozenset({"fixture-helper.exe", "powershell.exe"}),
            privileged_requests=frozenset({"filesystem.write"}),
            persistence_operations=frozenset({"package-cache.read", "startup.install"}),
            event_subscriptions=frozenset({"task.completed", "unknown.event"}),
            event_emissions=frozenset({"capability.changed", "unknown.emission"}),
            request_volume=100,
        )
    )
    assert drift.classification is DriftClass.SECURITY_DRIFT
    assert {finding.category for finding in drift.findings} >= {
        "filesystem_roots",
        "broker_calls",
        "processes",
        "privileged_requests",
        "persistence_operations",
        "event_subscriptions",
        "event_emissions",
        "request_volume",
    }
    with pytest.raises(CapabilityHealthError):
        monitor.record_trusted_broker_observation(observation(trusted=False))
    with pytest.raises(CapabilityHealthError):
        monitor.record_trusted_broker_observation(observation(source="model"))
    with pytest.raises(CapabilityHealthError):
        monitor.evaluate_drift(observation(trusted=False))


class RepairFixture:
    def __init__(self, report: CapabilityHealthReport, *, rebuild: bool = False) -> None:
        self.report = report
        self.rebuild = rebuild
        self.calls: list[str] = []

    def diagnose(self, capability_id: str, findings: tuple[DriftFinding, ...]) -> RepairDiagnosis:
        self.calls.append("diagnose")
        return RepairDiagnosis(
            RepairAction("repair-1", "refresh", "fixture.scope", "Refresh compatible state"),
            rebuild_or_replace=self.rebuild,
        )

    def safe_repair(self, capability_id: str, action: RepairAction) -> bool:
        self.calls.append("safe_repair")
        return not self.rebuild

    def rebuild_or_replace(self, capability_id: str, diagnosis: RepairDiagnosis) -> bool:
        self.calls.append("rebuild_or_replace")
        return True

    def retest(self, capability_id: str) -> CapabilityHealthReport:
        self.calls.append("retest")
        return self.report


def test_repair_requires_authority_then_retests_safe_repair() -> None:
    monitor = service()
    monitor.register_baseline(baseline())
    monitor.record_trusted_broker_observation(observation(request_volume=11))
    healthy = CapabilityHealthReport("fixture.integration", HealthStatus.HEALTHY, "retested", NOW)
    provider = RepairFixture(healthy)
    denied = monitor.repair("fixture.integration", provider)
    assert denied.outcome is RepairOutcome.AUTHORITY_REQUIRED
    assert denied.stage is RepairStage.AUTHORITY
    assert provider.calls == ["diagnose"]
    completed = monitor.repair("fixture.integration", provider, authorize=lambda action: True)
    assert completed.outcome is RepairOutcome.COMPLETED
    assert completed.history == (
        RepairStage.DETECT,
        RepairStage.EVIDENCE,
        RepairStage.DIAGNOSE,
        RepairStage.SAFE_REPAIR,
        RepairStage.RETEST,
        RepairStage.COMPLETED,
    )


def test_repair_rebuild_requires_authority_even_after_healthy_retest() -> None:
    monitor = service()
    monitor.register_baseline(baseline())
    monitor.record_trusted_broker_observation(
        observation(privileged_requests=frozenset({"settings.write"}))
    )
    healthy = CapabilityHealthReport("fixture.integration", HealthStatus.HEALTHY, "retested", NOW)
    provider = RepairFixture(healthy, rebuild=True)
    result = monitor.repair("fixture.integration", provider, authorize=lambda action: True)
    assert result.outcome is RepairOutcome.AUTHORITY_REQUIRED
    assert RepairStage.REBUILD_OR_REPLACE in result.history
    assert provider.calls == ["diagnose", "safe_repair", "rebuild_or_replace", "retest"]


@pytest.mark.asyncio
async def test_health_event_is_published_without_becoming_authority() -> None:
    events = InMemoryEventBus(queue_size=2)
    observed: list[str] = []

    async def collect(event: object) -> None:
        observed.append(type(event).__name__)

    await events.subscribe(collect)
    monitor = CapabilityHealthService(event_bus=events, clock=lambda: NOW)
    report = monitor.evaluate_health(
        "fixture.integration",
        (HealthProbeResult(HealthProbeMode.FUNCTIONAL, True, "ok", NOW),),
    )
    assert report.status is HealthStatus.HEALTHY
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert observed == ["EventEnvelope"]
    await events.close()
