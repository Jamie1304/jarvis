"""Read-only host virtualization probe; it never enables features or creates guests."""

import shutil
import sys
from dataclasses import dataclass

from jarvis.vm.models import VirtualizationAvailability


@dataclass(frozen=True, slots=True)
class HostProbe:
    backends: tuple[str, ...]
    availability: VirtualizationAvailability
    setup_required: bool
    reboot_required: bool
    detail: str
    hypervisor_present: bool = False
    firmware_virtualization_enabled: bool | None = None
    vm_monitor_mode_extensions: bool | None = None
    wsl_runtime_available: bool = False


def classify_windows_readiness(
    *,
    hypervisor_present: bool,
    firmware_virtualization_enabled: bool | None,
    vm_monitor_mode_extensions: bool | None,
    wsl_runtime_available: bool = False,
) -> tuple[VirtualizationAvailability, bool, str]:
    """Classify readiness without treating post-hypervisor WMI fields as gates."""
    if wsl_runtime_available:
        return (
            VirtualizationAvailability.AVAILABLE,
            False,
            "WSL runtime is functionally available",
        )
    if hypervisor_present:
        return (
            VirtualizationAvailability.AVAILABLE_REQUIRES_SETUP,
            True,
            "Windows hypervisor is running; WMI processor fields are supporting evidence only",
        )
    if firmware_virtualization_enabled is False or vm_monitor_mode_extensions is False:
        return (
            VirtualizationAvailability.AVAILABLE_REQUIRES_SETUP,
            True,
            "processor virtualization capability is reported disabled before a "
            "hypervisor is running",
        )
    return (
        VirtualizationAvailability.AVAILABLE_REQUIRES_SETUP,
        True,
        "virtualization backend requires functional runtime verification",
    )


def probe_windows_host(
    *,
    hypervisor_present: bool | None = None,
    firmware_virtualization_enabled: bool | None = None,
    vm_monitor_mode_extensions: bool | None = None,
    wsl_runtime_available: bool = False,
) -> HostProbe:
    if sys.platform != "win32":
        return HostProbe((), VirtualizationAvailability.UNSUPPORTED, False, False, "not Windows")
    candidates = tuple(
        name
        for name, command in (
            ("wsl", "wsl.exe"),
            ("docker", "docker.exe"),
            ("qemu", "qemu-system-x86_64.exe"),
        )
        if shutil.which(command)
    )
    if not candidates:
        return HostProbe(
            (),
            VirtualizationAvailability.UNAVAILABLE,
            False,
            False,
            "no supported virtualization command detected",
        )
    availability, setup_required, detail = classify_windows_readiness(
        hypervisor_present=bool(hypervisor_present),
        firmware_virtualization_enabled=firmware_virtualization_enabled,
        vm_monitor_mode_extensions=vm_monitor_mode_extensions,
        wsl_runtime_available=wsl_runtime_available,
    )
    return HostProbe(
        candidates,
        availability,
        setup_required,
        False,
        detail,
        bool(hypervisor_present),
        firmware_virtualization_enabled,
        vm_monitor_mode_extensions,
        wsl_runtime_available,
    )
