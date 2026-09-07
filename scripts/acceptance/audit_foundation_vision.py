"""Machine-check the pre-CP1 foundation symbol/test bindings."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


CHECKS = {
    "minimal_adaptive_core": (
        "jarvis/capability_factory.py",
        "class CapabilityFactory",
        "tests/test_capability_factory.py",
    ),
    "generic_capability_acquisition": (
        "jarvis/capability_acquisition.py",
        "class CapabilityAcquisitionCoordinator",
        "tests/test_capability_acquisition_runtime.py",
    ),
    "discover_adopt_reuse_build": (
        "jarvis/capability_acquisition.py",
        "FactoryStrategy",
        "tests/test_v1_acceptance.py",
    ),
    "vm_first_execution": (
        "jarvis/vm/router.py",
        "class ExecutionRouter",
        "tests/test_vm_fabric.py",
    ),
    "non_ambient_host_bridge": (
        "jarvis/vm/bridge.py",
        "class HostBridge",
        "tests/test_vm_fabric.py",
    ),
    "generated_code_untrusted": (
        "jarvis/package_reviewer.py",
        "class GeneratedPackageReviewer",
        "tests/test_production_capability.py",
    ),
    "permission_broker_authority": (
        "jarvis/permissions/broker.py",
        "class PermissionBroker",
        "tests/trusted_core",
    ),
    "trusted_certification": (
        "jarvis/package_certification.py",
        "class PackageCertifier",
        "tests/test_package_certification.py",
    ),
    "trusted_recovery": (
        "jarvis/recovery.py",
        "class TrustedRecoveryAuthority",
        "tests/test_recovery_authority.py",
    ),
    "one_process_appcontainer": (
        "jarvis/windows_sandbox.py",
        "class WindowsAppContainerLauncher",
        "tests/test_sandbox.py",
    ),
    "unknown_no_blind_retry": ("jarvis/effects.py", "UNKNOWN_OUTCOME", "tests/test_effects.py"),
    "self_development_not_authority": (
        "jarvis/improvement/engine.py",
        "class ImprovementEngine",
        "tests/test_improvement.py",
    ),
}


def main() -> int:
    bindings = {}
    for name, (source, symbol, regression) in CHECKS.items():
        source_path = ROOT / source
        regression_path = ROOT / regression
        source_text = source_path.read_text(encoding="utf-8") if source_path.is_file() else ""
        bindings[name] = {
            "source": source,
            "symbol": symbol,
            "symbol_present": symbol in source_text,
            "regression": regression,
            "regression_present": regression_path.exists(),
        }
    passed = all(
        item["symbol_present"] and item["regression_present"] for item in bindings.values()
    )
    print(
        json.dumps(
            {
                "schema": "foundation-vision-audit-1",
                "result": "PASS" if passed else "BLOCKED",
                "post_cp1_rebaseline": "September-6 expansion excluded",
                "bindings": bindings,
            },
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
