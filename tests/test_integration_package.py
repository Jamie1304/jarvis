from __future__ import annotations

from hashlib import sha256

import pytest
from jarvis.integration_package import (
    DiagnosticFailureSignature,
    DiagnosticProbe,
    DiagnosticsContract,
    IntegrationPackage,
    PackageAsset,
    PackageBoundary,
    PackageContractError,
    PackageEntry,
    PackageLayout,
    PackageLifecycle,
    PackageOperationPolicy,
    PackageProvenance,
    SafeRepairAction,
    SecretSchema,
    validate_package_path,
)
from jarvis.permissions.models import Permission
from jarvis.tools.models import SemanticVersion

HASH = sha256(b"fixture").hexdigest()
PROVENANCE = PackageProvenance("official", "rev-123", "MIT", "NOTICE", "reviewer")


def package() -> IntegrationPackage:
    entries = (
        PackageEntry("tool", "code/tools.json", PackageBoundary.PACKAGE_CODE, HASH, PROVENANCE),
        PackageEntry("asset", "assets/icon.svg", PackageBoundary.PACKAGE_CODE, HASH, PROVENANCE),
        PackageEntry(
            "data", "data/schema.json", PackageBoundary.PACKAGE_DATA, HASH, PROVENANCE, False
        ),
        PackageEntry(
            "cache", "cache/index.json", PackageBoundary.GENERATED_CACHE, HASH, PROVENANCE, False
        ),
    )
    return IntegrationPackage(
        "example.integration",
        SemanticVersion(1, 2, 3),
        PackageLayout(),
        entries,
        tools=("tool",),
        mcp=("stdio-server",),
        api_adapters=("backend",),
        services=("service",),
        events=("event",),
        skills=("skill",),
        profiles=("profile",),
        ui_assets=(
            PackageAsset("icon", package_path="assets/icon.svg"),
            PackageAsset("artifact", artifact_ref="artifact:123"),
        ),
        settings_schema=("endpoint",),
        permissions=(Permission.NETWORK_REQUEST,),
        secret_schema=(SecretSchema("api_key", "Vault reference"),),
        health_contract=("health",),
        tests=("tests/test_package.py",),
        migrations=("migrations/001.sql",),
        lifecycle=PackageLifecycle.VALIDATED,
        diagnostics=DiagnosticsContract(
            (DiagnosticFailureSignature("offline", "service is offline"),),
            (
                DiagnosticProbe(
                    "health", "read health", required_permissions=(Permission.NETWORK_REQUEST,)
                ),
            ),
            (SafeRepairAction("restart", "restart service", (Permission.NETWORK_REQUEST,)),),
            ("use local fallback",),
        ),
        provenance=PROVENANCE,
        dependency_lock=("dependency==1.0",),
        package_hash=HASH,
    )


def test_package_contract_boundaries_assets_and_metadata() -> None:
    item = package()
    assert item.entry_for("code/tools.json").immutable
    item.validate_asset(item.ui_assets[0])
    item.validate_asset(item.ui_assets[1])
    assert item.operation_policy.preserve_user_config
    assert item.operation_policy.preserve_package_data
    assert item.secret_schema[0].vault_reference_only
    with pytest.raises(KeyError):
        item.entry_for("missing")


def test_package_rejects_unsafe_paths_and_data_source_confusion() -> None:
    for path in ("../code/a", "/code/a", "code\\a", "code/../a", "code//a", "C:code/a", "code/a?b"):
        with pytest.raises(PackageContractError):
            validate_package_path(path)
    base = package()
    with pytest.raises(PackageContractError):
        PackageEntry(
            "config", "config/settings.json", PackageBoundary.USER_CONFIG, HASH, PROVENANCE, False
        )
    with pytest.raises(PackageContractError):
        PackageEntry("secret", "code/secret.json", PackageBoundary.CREDENTIALS, HASH, PROVENANCE)
    with pytest.raises(PackageContractError):
        bad_entry = PackageEntry(
            "bad", "config/settings.json", PackageBoundary.PACKAGE_CODE, HASH, PROVENANCE
        )
        IntegrationPackage(
            base.package_id,
            base.version,
            base.layout,
            (bad_entry,),
            provenance=PROVENANCE,
        )
    with pytest.raises(PackageContractError):
        base.validate_asset(PackageAsset("bad", package_path="data/schema.json"))
    with pytest.raises(PackageContractError):
        base.validate_asset(PackageAsset("bad", package_path="assets/missing.svg"))


def test_package_rejects_secret_or_unsafe_lifecycle_contracts() -> None:
    with pytest.raises(PackageContractError):
        SecretSchema("password", "value", False)
    with pytest.raises(PackageContractError):
        SafeRepairAction("bypass", "disable policy", requires_approval=False)
    with pytest.raises(PackageContractError):
        PackageOperationPolicy(removable_boundaries=frozenset({PackageBoundary.USER_CONFIG}))
    with pytest.raises(PackageContractError):
        base = package()
        IntegrationPackage(
            base.package_id,
            base.version,
            base.layout,
            base.entries,
            diagnostics=DiagnosticsContract(
                probes=(
                    DiagnosticProbe(
                        "x", "probe", required_permissions=(Permission.NETWORK_REQUEST,)
                    ),
                )
            ),
            provenance=PROVENANCE,
        )
    with pytest.raises(PackageContractError):
        PackageProvenance("", "rev", "MIT")
    with pytest.raises(PackageContractError):
        PackageLayout(manifest_path="../manifest.json")
