from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from jarvis.artifacts import ArtifactClassification, ArtifactReference, ArtifactStore
from jarvis.integration_package import (
    IntegrationPackage,
    PackageAsset,
    PackageBoundary,
    PackageEntry,
    PackageLayout,
    PackageLifecycle,
    PackageProvenance,
)
from jarvis.tools.models import SemanticVersion
from jarvis.ui_simulation import (
    FakeCapabilityRegistry,
    UISimulatedView,
    UISimulationAction,
    UISimulationAsset,
    UISimulationAttestationStatus,
    UISimulationCheck,
    UISimulationComponent,
    UISimulationComponentKind,
    UISimulationError,
    UISimulationHarness,
    UISimulationManifest,
    UISimulationState,
    UISimulationValidationError,
)

PROVENANCE = PackageProvenance("generated", "revision-1", "MIT")
UI_BYTES = b'{"view":"safe"}'
UI_HASH = sha256(UI_BYTES).hexdigest()


def package(*, profiles: tuple[str, ...] = ()) -> IntegrationPackage:
    code = b"def run():\n    return 1\n"
    return IntegrationPackage(
        "simulation.example",
        SemanticVersion(1, 0, 0),
        PackageLayout(),
        (
            PackageEntry(
                "python",
                "code/main.py",
                PackageBoundary.PACKAGE_CODE,
                sha256(code).hexdigest(),
                PROVENANCE,
            ),
            PackageEntry(
                "ui",
                "assets/view.json",
                PackageBoundary.PACKAGE_CODE,
                UI_HASH,
                PROVENANCE,
            ),
        ),
        profiles=profiles,
        ui_assets=(PackageAsset("view", package_path="assets/view.json"),),
        lifecycle=PackageLifecycle.VALIDATED,
        provenance=PROVENANCE,
        package_hash=sha256(b"package").hexdigest(),
    )


def manifest(
    *,
    components: tuple[UISimulationComponent, ...] | None = None,
    actions: tuple[UISimulationAction, ...] = (),
    assets: tuple[UISimulationAsset, ...] = (),
    states: tuple[str, ...] = (
        "IDLE",
        "ACTIVE",
        "LOADING",
        "ERROR",
        "DEGRADED",
        "DISCONNECTED",
        "WAITING_PERMISSION",
    ),
) -> UISimulationManifest:
    return UISimulationManifest(
        "simulation.example",
        "1.0.0",
        "root",
        components
        or (
            UISimulationComponent("root", UISimulationComponentKind.CONTAINER),
            UISimulationComponent("text", UISimulationComponentKind.TEXT, text="hello"),
        ),
        assets,
        actions,
        states,
    )


def test_all_states_and_generic_component_types_render_deterministically() -> None:
    components = (
        UISimulationComponent("root", UISimulationComponentKind.CONTAINER),
        UISimulationComponent("text", UISimulationComponentKind.TEXT, text="hello"),
        UISimulationComponent("artifact", UISimulationComponentKind.ARTIFACT),
        UISimulationComponent("image", UISimulationComponentKind.IMAGE),
        UISimulationComponent("document", UISimulationComponentKind.DOCUMENT),
        UISimulationComponent("chart", UISimulationComponentKind.CHART),
        UISimulationComponent("plan", UISimulationComponentKind.PLAN),
        UISimulationComponent("comparison", UISimulationComponentKind.MODEL_COMPARISON),
        UISimulationComponent("control", UISimulationComponentKind.CONTROL, action_id="pause"),
        UISimulationComponent("view", UISimulationComponentKind.DECLARATIVE_VIEW),
    )
    harness = UISimulationHarness(package())
    harness.load_manifest(
        manifest(
            components=components,
            actions=(UISimulationAction("pause", "task", {"simulated": True}),),
        )
    )
    first = harness.shot(UISimulationState.IDLE)
    second = harness.shot(UISimulationState.IDLE)
    assert first.evidence.passed
    assert first.view.fingerprint == second.view.fingerprint
    assert first.render_bytes == second.render_bytes
    assert len(first.view.controls) == 1
    assert len(harness.run_all()) == len(UISimulationState)


def test_shot_captures_semantic_render_artifact(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    harness = UISimulationHarness(package(), artifact_store=store, workspace_id="workspace")
    harness.load_manifest(
        manifest(
            assets=(UISimulationAsset("view", UI_HASH, package_path="assets/view.json"),),
        )
    )
    shot = harness.shot("ERROR")
    assert shot.evidence.artifact is not None
    assert store.read(shot.evidence.artifact, workspace_id="workspace") == shot.render_bytes
    store.close()


def test_missing_action_is_evidence_failure_and_fake_action_has_zero_effects() -> None:
    missing = UISimulationHarness(package())
    missing.load_manifest(
        manifest(
            components=(
                UISimulationComponent("root", UISimulationComponentKind.CONTAINER),
                UISimulationComponent(
                    "control", UISimulationComponentKind.CONTROL, action_id="missing"
                ),
            )
        )
    )
    result = missing.shot("ACTIVE")
    assert not result.evidence.passed
    assert any(
        name is UISimulationCheck.BINDINGS and not passed
        for name, passed, _ in result.evidence.checks
    )

    fake = FakeCapabilityRegistry()
    action = UISimulationAction("safe.inspect", "capability.inspect")
    fake.register(action)
    simulated = fake.invoke("safe.inspect")
    assert simulated.simulated and simulated.effect_count == 0
    assert fake.calls[0].capability_id == "capability.inspect"


def test_error_custom_state_and_state_specific_components() -> None:
    components = (
        UISimulationComponent("root", UISimulationComponentKind.CONTAINER),
        UISimulationComponent(
            "error", UISimulationComponentKind.TEXT, text="failure", visible_states=("ERROR",)
        ),
        UISimulationComponent(
            "custom", UISimulationComponentKind.TEXT, text="custom", visible_states=("CUSTOM",)
        ),
    )
    harness = UISimulationHarness(package())
    harness.load_manifest(manifest(components=components, states=("ERROR", "CUSTOM")))
    assert tuple(item.component_id for item in harness.render("ERROR").nodes) == ("root", "error")
    assert tuple(item.component_id for item in harness.render("CUSTOM").nodes) == ("root", "custom")


def test_approval_spoof_is_rejected_by_security_evidence() -> None:
    harness = UISimulationHarness(package())
    harness.load_manifest(
        manifest(
            components=(
                UISimulationComponent("root", UISimulationComponentKind.CONTAINER),
                UISimulationComponent(
                    "approval",
                    UISimulationComponentKind.CONTROL,
                    title="Allow once",
                    action_id="permission.approve",
                ),
            ),
            actions=(UISimulationAction("permission.approve", "permission"),),
        )
    )
    shot = harness.shot("WAITING_PERMISSION")
    assert not shot.evidence.passed
    assert any(
        name is UISimulationCheck.SECURITY and not passed
        for name, passed, _ in shot.evidence.checks
    )


def test_semantic_authority_spoof_is_rejected_even_without_known_button_names() -> None:
    harness = UISimulationHarness(package())
    harness.load_manifest(
        manifest(
            components=(
                UISimulationComponent("root", UISimulationComponentKind.CONTAINER),
                UISimulationComponent(
                    "security-request",
                    UISimulationComponentKind.CONTROL,
                    title="Authorize this security request",
                    action_id="continue",
                ),
            ),
            actions=(UISimulationAction("continue", "settings.write"),),
        )
    )

    shot = harness.shot("WAITING_PERMISSION")

    assert not shot.evidence.passed
    assert any(
        name is UISimulationCheck.SECURITY and not passed
        for name, passed, _ in shot.evidence.checks
    )


def test_bad_asset_and_hash_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(UISimulationValidationError):
        UISimulationAsset("bad", "a" * 64, package_path="../outside.svg")
    harness = UISimulationHarness(package())
    with pytest.raises(UISimulationValidationError):
        harness.load_manifest(
            manifest(
                assets=(UISimulationAsset("missing", "a" * 64, package_path="assets/missing.svg"),)
            )
        )
    with pytest.raises(UISimulationValidationError):
        harness.load_manifest(
            manifest(assets=(UISimulationAsset("view", "a" * 64, package_path="assets/view.json"),))
        )
    store = ArtifactStore(tmp_path / "artifacts")
    artifact = store.put(
        workspace_id="workspace",
        name="image.bin",
        content=b"secret? no",
        mime_type="application/octet-stream",
        classification=ArtifactClassification.INTERNAL,
        producer="test",
    )
    artifact_harness = UISimulationHarness(
        package(), artifact_store=store, workspace_id="workspace"
    )
    with pytest.raises(UISimulationValidationError):
        artifact_harness.load_manifest(
            manifest(assets=(UISimulationAsset("artifact", "a" * 64, artifact=artifact),))
        )
    store.close()


def test_oversized_or_executable_content_is_not_loaded() -> None:
    with pytest.raises(UISimulationValidationError):
        UISimulationComponent("text", UISimulationComponentKind.TEXT, text="x" * 4_001)
    with pytest.raises(UISimulationValidationError):
        UISimulationComponent(
            "view", UISimulationComponentKind.DECLARATIVE_VIEW, data={"script": "bad"}
        )
    with pytest.raises(UISimulationValidationError):
        UISimulationManifest(
            "simulation.example",
            "1.0.0",
            "root",
            tuple(
                UISimulationComponent(f"component-{index}", UISimulationComponentKind.TEXT)
                for index in range(129)
            ),
        )


def test_manifest_and_component_contracts_fail_closed() -> None:
    artifact = ArtifactReference(UUID(int=1), 1, "workspace", "0" * 32 + "-1-" + "0" * 32 + ".bin")
    invalid_assets = (
        ("", "a" * 64, None, None),
        ("asset", "bad", "assets/a", None),
        ("asset", "a" * 64, None, None),
        ("asset", "a" * 64, "assets/a", artifact),
        ("asset", "a" * 64, None, cast(ArtifactReference, "bad")),
    )
    for asset_id, content_hash, package_path, asset_artifact in invalid_assets:
        with pytest.raises(UISimulationValidationError):
            UISimulationAsset(asset_id, content_hash, package_path, asset_artifact)
    with pytest.raises(UISimulationValidationError):
        UISimulationAction("bad id", "capability")
    with pytest.raises(UISimulationValidationError):
        UISimulationAction("action", "bad capability")
    with pytest.raises(UISimulationValidationError):
        UISimulationAction("action", "capability", cast(dict[str, object], ["bad"]))
    with pytest.raises(UISimulationValidationError):
        UISimulationComponent("bad id", UISimulationComponentKind.TEXT)
    with pytest.raises(UISimulationValidationError):
        UISimulationComponent("text", cast(UISimulationComponentKind, "text"))
    with pytest.raises(UISimulationValidationError):
        UISimulationComponent("text", UISimulationComponentKind.TEXT, title=cast(str, None))
    with pytest.raises(UISimulationValidationError):
        UISimulationComponent(
            "text", UISimulationComponentKind.TEXT, data=cast(dict[str, object], [])
        )
    with pytest.raises(UISimulationValidationError):
        UISimulationComponent("text", UISimulationComponentKind.TEXT, action_id="bad id")
    with pytest.raises(UISimulationValidationError):
        UISimulationComponent("text", UISimulationComponentKind.TEXT, asset_id="bad id")
    with pytest.raises(UISimulationValidationError):
        UISimulationComponent(
            "text", UISimulationComponentKind.TEXT, visible_states=cast(tuple[str, ...], ["IDLE"])
        )
    with pytest.raises(UISimulationValidationError):
        UISimulationComponent("text", UISimulationComponentKind.TEXT, visible_states=("bad",))

    root = UISimulationComponent("root", UISimulationComponentKind.CONTAINER)
    with pytest.raises(UISimulationValidationError):
        UISimulationManifest("simulation.example", "1.0.0", "root", ())
    with pytest.raises(UISimulationValidationError):
        UISimulationManifest("simulation.example", "1.0.0", "unknown", (root,))
    with pytest.raises(UISimulationValidationError):
        UISimulationManifest("simulation.example", "1.0.0", "root", (root, root))
    with pytest.raises(UISimulationValidationError):
        UISimulationManifest("simulation.example", "1.0.0", "root", (root,), states=())
    with pytest.raises(UISimulationValidationError):
        UISimulationManifest("simulation.example", "1.0.0", "root", (root,), states=("idle",))
    with pytest.raises(UISimulationValidationError):
        UISimulationManifest(
            "simulation.example", "1.0.0", "root", (root,), states=("IDLE", "IDLE")
        )
    with pytest.raises(UISimulationValidationError):
        UISimulationManifest(
            "simulation.example",
            "1.0.0",
            "root",
            (
                UISimulationComponent(
                    "child", UISimulationComponentKind.TEXT, visible_states=("ERROR",)
                ),
            ),
            states=("IDLE",),
        )
    action = UISimulationAction("action", "capability")
    asset = UISimulationAsset("asset", "a" * 64, package_path="assets/a")
    with pytest.raises(UISimulationValidationError):
        UISimulationManifest("simulation.example", "1.0.0", "root", (root,), assets=(asset, asset))
    with pytest.raises(UISimulationValidationError):
        UISimulationManifest(
            "simulation.example", "1.0.0", "root", (root,), actions=(action, action)
        )


def test_harness_loading_and_fake_registry_errors(tmp_path: Path) -> None:
    package_value = package()
    with pytest.raises(UISimulationValidationError):
        UISimulationHarness(cast(IntegrationPackage, object()))
    bad_store = ArtifactStore(tmp_path / "bad-artifacts")
    try:
        with pytest.raises(UISimulationValidationError):
            UISimulationHarness(package_value, artifact_store=bad_store)
    finally:
        bad_store.close()
    harness = UISimulationHarness(package_value)
    with pytest.raises(UISimulationError):
        harness.render("IDLE")
    with pytest.raises(UISimulationValidationError):
        harness.load_manifest(cast(UISimulationManifest, object()))
    wrong = manifest()
    wrong = UISimulationManifest(
        "other.example", wrong.version, wrong.root_component_id, wrong.components
    )
    with pytest.raises(UISimulationValidationError):
        harness.load_manifest(wrong)
    harness.load_manifest(manifest(actions=(UISimulationAction("action", "capability"),)))
    with pytest.raises(UISimulationValidationError):
        harness.shot("UNKNOWN")
    with pytest.raises(UISimulationError):
        harness.invoke_simulated_action("missing")
    harness.load_manifest(manifest(actions=(UISimulationAction("action", "capability"),)))
    assert harness.capabilities.has("action")


def test_missing_asset_and_screenshot_renderer_bounds(tmp_path: Path) -> None:
    missing = UISimulationHarness(package())
    missing.load_manifest(
        manifest(
            components=(
                UISimulationComponent("root", UISimulationComponentKind.CONTAINER),
                UISimulationComponent("image", UISimulationComponentKind.IMAGE, asset_id="missing"),
            )
        )
    )
    shot = missing.shot("IDLE")
    assert not shot.evidence.passed
    bad_renderer = UISimulationHarness(
        package(),
        screenshot_renderer=cast(Callable[[UISimulatedView], bytes], lambda _view: "not-bytes"),
    )
    bad_renderer.load_manifest(manifest())
    with pytest.raises(UISimulationError):
        bad_renderer.shot("IDLE")
    huge = UISimulationHarness(
        package(),
        screenshot_renderer=lambda _view: b"x" * (8 * 1024 * 1024 + 1),
    )
    huge.load_manifest(manifest())
    with pytest.raises(UISimulationError):
        huge.shot("IDLE")


def test_artifact_asset_and_evidence_serialization(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    content = b"render input"
    artifact = store.put(
        workspace_id="workspace",
        name="input.bin",
        content=content,
        mime_type="application/octet-stream",
        classification=ArtifactClassification.INTERNAL,
        producer="test",
    )
    simulation_manifest = manifest(
        assets=(UISimulationAsset("input", sha256(content).hexdigest(), artifact=artifact),)
    )
    bound_package = replace(package(), ui_manifest_hash=simulation_manifest.manifest_hash)
    harness = UISimulationHarness(bound_package, artifact_store=store, workspace_id="workspace")
    harness.load_manifest(simulation_manifest)
    shot = harness.shot("IDLE")
    assert shot.evidence.passed
    assert any("ui-simulation:artifact=" in item for item in shot.evidence.certification_strings())
    attestation = harness.attest("a" * 64)
    assert attestation.result is UISimulationAttestationStatus.PASS
    assert attestation.zero_real_effect
    assert attestation.artifact_refs
    assert attestation.valid_for(bound_package, "a" * 64)
    assert not attestation.valid_for(bound_package, "b" * 64)
    store.close()


def test_attestation_is_not_caller_constructible_and_failed_ui_cannot_certify() -> None:
    harness = UISimulationHarness(package())
    harness.load_manifest(manifest())
    attestation = harness.attest("a" * 64)
    assert attestation.attestation_digest == attestation.attestation_digest
    with pytest.raises(UISimulationValidationError):
        type(attestation)(
            attestation.attestation_id,
            attestation.package_id,
            attestation.version,
            attestation.package_hash,
            attestation.source_hash,
            attestation.ui_manifest_hash,
            attestation.schema_version,
            attestation.harness_version,
            attestation.policy_version,
            attestation.tested_states,
            attestation.semantic_checks,
            attestation.security_checks,
            attestation.asset_checks,
            attestation.action_bindings,
            attestation.zero_real_effect,
            attestation.artifact_refs,
            attestation.issued_at,
            attestation.result,
            attestation.attestation_digest,
        )


def test_manifest_hash_change_invalidates_the_previous_attestation() -> None:
    original_manifest = manifest(states=("IDLE",))
    bound_package = replace(package(), ui_manifest_hash=original_manifest.manifest_hash)
    harness = UISimulationHarness(bound_package)
    harness.load_manifest(original_manifest)
    attestation = harness.attest("a" * 64)
    changed_manifest = manifest(
        components=(
            UISimulationComponent("root", UISimulationComponentKind.CONTAINER),
            UISimulationComponent("text", UISimulationComponentKind.TEXT, text="changed"),
        ),
        states=("IDLE",),
    )
    changed_package = replace(bound_package, ui_manifest_hash=changed_manifest.manifest_hash)
    assert not attestation.valid_for(changed_package, "a" * 64)
    with pytest.raises(UISimulationValidationError):
        harness.load_manifest(changed_manifest)


def test_attestation_input_and_package_identity_validation_is_fail_closed() -> None:
    simulation_manifest = manifest(states=("IDLE",))
    bound_package = replace(package(), ui_manifest_hash=simulation_manifest.manifest_hash)
    harness = UISimulationHarness(bound_package)
    with pytest.raises(UISimulationError):
        harness.attest("a" * 64)
    harness.load_manifest(simulation_manifest)
    with pytest.raises(UISimulationValidationError):
        harness.attest("not-a-digest")
    attestation = harness.attest("a" * 64)
    assert attestation.status is UISimulationAttestationStatus.PASS
    assert not attestation.valid_for(replace(bound_package, package_id="other.example"), "a" * 64)
    assert not attestation.valid_for(
        replace(bound_package, version=SemanticVersion(2, 0, 0)), "a" * 64
    )
    assert not attestation.valid_for(replace(bound_package, package_hash="b" * 64), "a" * 64)
    assert not attestation.valid_for(replace(bound_package, ui_manifest_hash="b" * 64), "a" * 64)
