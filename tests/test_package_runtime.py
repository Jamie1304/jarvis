from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import cast

import pytest
from jarvis.integration_package import (
    IntegrationPackage,
    PackageBoundary,
    PackageEntry,
    PackageLayout,
    PackageLifecycle,
    PackageProvenance,
)
from jarvis.package_runtime import (
    HotLoadError,
    HotLoadManager,
    PackageCertification,
    PackageChange,
    PackageChangeKind,
    PackageRuntimeHealth,
    PreparedPackageRuntime,
    compare_package_versions,
)
from jarvis.tools.models import SemanticVersion

HASH = sha256(b"certified-package").hexdigest()
PROVENANCE = PackageProvenance("fixture", "revision", "MIT")


def package(
    version: tuple[int, int, int] = (1, 0, 0), package_hash: str = HASH
) -> IntegrationPackage:
    return IntegrationPackage(
        "fixture.integration",
        SemanticVersion(*version),
        PackageLayout(),
        (PackageEntry("code", "code/entry.py", PackageBoundary.PACKAGE_CODE, HASH, PROVENANCE),),
        tools=("tool",),
        skills=("skill",),
        profiles=("profile",),
        ui_assets=(),
        events=("event",),
        package_hash=package_hash,
        provenance=PROVENANCE,
        lifecycle=PackageLifecycle.VALIDATED,
    )


def certification(item: IntegrationPackage, **changes: bool) -> PackageCertification:
    values = {
        "certified": True,
        "permission_diff_approved": True,
        "shadow_passed": True,
        "canary_passed": True,
    }
    values.update(changes)
    return PackageCertification(
        item.package_id,
        item.version,
        item.package_hash,
        certified=values["certified"],
        permission_diff_approved=values["permission_diff_approved"],
        shadow_passed=values["shadow_passed"],
        canary_passed=values["canary_passed"],
    )


@dataclass
class FakeRuntime:
    package: IntegrationPackage
    healthy: bool = True
    state: dict[str, object] | None = None
    restored: dict[str, object] | None = None
    drained: int = 0

    def health_check(self) -> PackageRuntimeHealth:
        return PackageRuntimeHealth(self.healthy, "fixture")

    def export_state(self) -> dict[str, object]:
        return dict(self.state or {"counter": 1})

    def restore_state(self, state: Mapping[str, object]) -> None:
        self.restored = dict(state)

    def drain(self) -> None:
        self.drained += 1


class FakeFactory:
    def __init__(self) -> None:
        self.fail_health = False
        self.created: list[FakeRuntime] = []

    def prepare(self, item: IntegrationPackage) -> FakeRuntime:
        runtime = FakeRuntime(item, healthy=not self.fail_health)
        self.created.append(runtime)
        return runtime


class FakeSurface:
    def __init__(self) -> None:
        self.current: PreparedPackageRuntime | None = None
        self.refreshes: list[tuple[str, ...]] = []
        self.fail_swap = False

    def atomic_swap(self, item: IntegrationPackage, runtime: PreparedPackageRuntime) -> None:
        if self.fail_swap:
            self.current = runtime
            raise RuntimeError("projection refresh failed")
        self.current = runtime
        self.refreshes.append(("capability", "tool", "skill", "profile", "ui", "event"))

    def rollback(self, item: IntegrationPackage, runtime: PreparedPackageRuntime | None) -> None:
        self.current = runtime if runtime is not None else None

    def remove(self, item: IntegrationPackage, runtime: PreparedPackageRuntime) -> None:
        if self.current is runtime:
            self.current = None


class FakeWatcher:
    def __init__(self) -> None:
        self.callback: Callable[[PackageChange], None] | None = None
        self.started = False
        self.stopped = False

    def start(self, callback: Callable[[PackageChange], None]) -> None:
        self.callback = callback
        self.started = True

    def stop(self) -> None:
        self.stopped = True


def test_certification_version_comparison_and_active_invocation() -> None:
    assert compare_package_versions(SemanticVersion(1, 0, 0), SemanticVersion(2, 0, 0)) == -1
    assert compare_package_versions(SemanticVersion(1, 0, 0), SemanticVersion(1, 0, 0)) == 0
    factory, surface = FakeFactory(), FakeSurface()
    manager = HotLoadManager(factory, surface)
    first = package()
    active = manager.manual_refresh(first, certification(first))
    assert (
        manager.invoke(first.package_id, lambda runtime: runtime.package.version) == first.version
    )
    assert active.runtime is surface.current
    assert surface.refreshes == [("capability", "tool", "skill", "profile", "ui", "event")]
    with pytest.raises(HotLoadError):
        manager.manual_refresh(package((0, 9, 0)), certification(package((0, 9, 0))))
    with pytest.raises(HotLoadError):
        manager.manual_refresh(
            package((2, 0, 0)), certification(package((2, 0, 0)), shadow_passed=False)
        )


def test_update_preserves_state_and_drains_old_runtime() -> None:
    factory, surface = FakeFactory(), FakeSurface()
    manager = HotLoadManager(factory, surface)
    first = package()
    old = cast(FakeRuntime, manager.manual_refresh(first, certification(first)).runtime)
    new = package((2, 0, 0))
    replacement = cast(FakeRuntime, manager.manual_refresh(new, certification(new)).runtime)
    assert replacement.restored == {"counter": 1}
    assert old.drained == 1
    assert manager.active(first.package_id).package.version == new.version


def test_failed_health_or_swap_rolls_back_without_losing_active() -> None:
    factory, surface = FakeFactory(), FakeSurface()
    manager = HotLoadManager(factory, surface)
    first = package()
    manager.manual_refresh(first, certification(first))
    factory.fail_health = True
    failed = package((2, 0, 0))
    with pytest.raises(HotLoadError):
        manager.manual_refresh(failed, certification(failed))
    assert manager.active(first.package_id).package.version == first.version
    factory.fail_health = False
    surface.fail_swap = True
    with pytest.raises(HotLoadError):
        manager.manual_refresh(failed, certification(failed))
    assert manager.active(first.package_id).package.version == first.version
    assert surface.current is manager.active(first.package_id).runtime


def test_watcher_manual_refresh_remove_stale_and_restart() -> None:
    factory, surface, watcher = FakeFactory(), FakeSurface(), FakeWatcher()
    manager = HotLoadManager(factory, surface, watcher=watcher)
    item = package()
    manager.start_watching()
    assert watcher.started and watcher.callback is not None
    callback = watcher.callback
    assert callback is not None
    callback(PackageChange(PackageChangeKind.INSTALL, item, certification(item)))
    before = cast(FakeRuntime, manager.active(item.package_id).runtime)
    restarted = manager.restart(item.package_id)
    restarted_runtime = cast(FakeRuntime, restarted.runtime)
    assert restarted.runtime is not before
    assert restarted_runtime.restored == {"counter": 1}
    assert before.drained == 1
    assert manager.cleanup_stale(("other",)) == (item.package_id,)
    assert manager.active_packages() == ()
    callback(PackageChange(PackageChangeKind.REMOVE, item))
    manager.stop_watching()
    assert watcher.stopped


def test_certification_binding_and_permission_gate() -> None:
    factory, surface = FakeFactory(), FakeSurface()
    manager = HotLoadManager(factory, surface)
    item = package()
    with pytest.raises(HotLoadError):
        manager.manual_refresh(item, certification(item, permission_diff_approved=False))
    wrong = PackageCertification(
        item.package_id, SemanticVersion(9, 0, 0), HASH, True, True, True, True
    )
    with pytest.raises(HotLoadError):
        manager.manual_refresh(item, wrong)
