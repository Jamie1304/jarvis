"""Build minimized real-host evidence for V1-I-R3C-B."""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from jarvis.applications.providers import WingetPackageProvider  # noqa: E402
from jarvis.security.startup import SourceCheckoutIntegrityEvidenceProvider  # noqa: E402
from jarvis.system_stewardship import (  # noqa: E402
    SecurityFindingState,
    create_real_windows_system_stewardship,
)


def _git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    return result.stdout.strip()


def _source_identity() -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "scripts/acceptance/audit_source_identity.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    value = json.loads(result.stdout.strip().splitlines()[-1])
    if not isinstance(value, dict):
        raise ValueError("source identity must be an object")
    return value


async def _probe() -> dict[str, Any]:
    composition = create_real_windows_system_stewardship(
        project_root=ROOT,
        integrity_evidence=SourceCheckoutIntegrityEvidenceProvider(ROOT),
    )
    projection = await composition.refresh()
    software_states = Counter(item.state.value for item in projection.software.applications)
    startup_sources = Counter(item.provider for item in projection.startup.entries)
    update_states = Counter(item.state.value for item in projection.updates)
    jarvis_findings = tuple(
        item for item in projection.security.findings if item.provider == "jarvis-integrity"
    )
    host_security_findings = tuple(
        item for item in projection.security.findings if item.provider == "host-wide-security"
    )
    winget_available = await WingetPackageProvider.available()
    return {
        "provider_composition": {
            "software_inventory": "WindowsRegistryInventoryProvider",
            "security": ["IntegritySecurityProvider", "UnavailableSecurityProvider"],
            "startup": "WindowsStartupProvider",
            "updates": "WingetPackageProvider",
            "projection": "SystemStewardshipComposition.refresh",
        },
        "software_inventory": {
            "status": "PASS",
            "record_count": len(projection.software.applications),
            "health_state_counts": dict(sorted(software_states.items())),
        },
        "jarvis_integrity": {
            "status": (
                jarvis_findings[0].state.value.upper() if jarvis_findings else "UNAVAILABLE"
            ),
            "provider": "jarvis-integrity",
            "finding_count": len(jarvis_findings),
            "targets": sorted({item.target for item in jarvis_findings}),
        },
        "host_wide_security": {
            "status": (
                host_security_findings[0].state.value.upper()
                if host_security_findings
                else SecurityFindingState.UNAVAILABLE.value.upper()
            ),
            "provider": "host-wide-security",
        },
        "startup_read_only": {
            "status": (
                "PASS" if projection.startup.overall.value != "unavailable" else "UNAVAILABLE"
            ),
            "entry_count": len(projection.startup.entries),
            "provider_categories": dict(sorted(startup_sources.items())),
        },
        "update_read_only": {
            "status": "AVAILABLE" if winget_available else "UNAVAILABLE",
            "provider": "WingetPackageProvider",
            "candidate_count": sum(
                count for state, count in update_states.items() if state == "update_available"
            ),
            "evidence_state_counts": dict(sorted(update_states.items())),
        },
        "effect_capabilities": {
            "startup": composition.startup_effect.value,
            "update": "COMPOSED_APPROVAL_GATED_APPLICATION_MANAGER_ROUTE",
        },
        "privacy": {
            "raw_startup_commands_persisted": False,
            "full_application_inventory_persisted": False,
            "user_paths_persisted": False,
            "provider_private_details_persisted": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    artifact = {
        "schema": "v1-i-r3c-b-real-host-1",
        "canonical_system_stewardship_version": "V1-I-R3C-B",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "source_identity": _source_identity(),
        "git": {"sha": _git("rev-parse", "HEAD"), "branch": _git("branch", "--show-current")},
        "real_host_observation": asyncio.run(_probe()),
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(artifact, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
