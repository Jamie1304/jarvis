"""Deterministic tests for the controlled application-manager boundary."""

import asyncio
from collections.abc import Callable, Mapping
from uuid import UUID, uuid4

import pytest
from jarvis.applications.catalog import create_application_tools
from jarvis.applications.configuration import ApplicationConfigurationAdapter, ConfigurationRegistry
from jarvis.applications.manager import ApplicationManager
from jarvis.applications.models import (
    ApplicationAmbiguousError,
    ApplicationManagerError,
    ApplicationRecord,
    ApplicationStatus,
    InstallationCandidate,
    InstallationPlanError,
    InstallationPlanKind,
    InstallationVerification,
    PackageNotFoundError,
    PackageOperationError,
    VerificationError,
)
from jarvis.applications.plans import InstallationPlanStore
from jarvis.applications.providers import (
    ApplicationInventoryProvider,
    PackageProvider,
    WingetPackageProvider,
)
from jarvis.applications.runtime import ApplicationRuntime
from jarvis.applications.tools import (
    CloseManagedApplicationTool,
    FindApplicationTool,
    InstallApplicationTool,
    LaunchManagedApplicationTool,
    PlanInstallTool,
    PlanUpdateTool,
    UpdateApplicationTool,
)
from jarvis.computer.models import LaunchInfo
from jarvis.permissions import (
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    ApprovalSource,
    Decision,
    Permission,
    PermissionBroker,
    PolicyEngine,
    PolicyRule,
    ScopeConstraint,
    TrustedApprovalAuthenticator,
    TrustedApprovalContext,
)
from jarvis.tools.harness import ToolHarness
from jarvis.tools.models import ToolResultStatus
from jarvis.tools.registry import ToolRegistry


def record(*, version: str = "30.0.0", name: str = "OBS Studio") -> ApplicationRecord:
    return ApplicationRecord(
        "app:obs-studio",
        name,
        version,
        "OBS Project",
        "C:/Program Files/obs-studio/bin/64bit/obs64.exe",
        "test-inventory",
        ApplicationStatus.INSTALLED,
    )


def candidate(
    *,
    version: str = "30.0.0",
    name: str = "OBS Studio",
    publisher: str | None = "OBS Project",
) -> InstallationCandidate:
    return InstallationCandidate(
        "OBSProject.OBSStudio",
        "winget",
        name,
        publisher,
        version,
        (Permission.APPLICATION_INSTALL,),
        "Exact trusted provider catalog match",
        0.99,
        InstallationVerification(name, publisher, version),
    )


class FakeInventory(ApplicationInventoryProvider):
    def __init__(self, records: tuple[ApplicationRecord, ...] = ()) -> None:
        self.records = records
        self.calls = 0

    async def enumerate_installed(self) -> tuple[ApplicationRecord, ...]:
        self.calls += 1
        return self.records


class FakePackages(PackageProvider):
    def __init__(
        self,
        candidates: tuple[InstallationCandidate, ...] = (),
        *,
        update: InstallationCandidate | None = None,
        failure: Exception | None = None,
        on_install: Callable[[InstallationCandidate], None] | None = None,
        on_update: Callable[[InstallationCandidate], None] | None = None,
    ) -> None:
        self.candidates = candidates
        self.update_candidate = update
        self.failure = failure
        self.on_install = on_install
        self.on_update = on_update
        self.install_calls: list[str] = []
        self.update_calls: list[str] = []

    async def search(self, semantic_name: str) -> tuple[InstallationCandidate, ...]:
        return tuple(
            item for item in self.candidates if semantic_name.casefold() in item.name.casefold()
        )

    async def find_update(self, current: ApplicationRecord) -> InstallationCandidate | None:
        del current
        return self.update_candidate

    async def install(self, item: InstallationCandidate, cancellation: asyncio.Event) -> None:
        assert not cancellation.is_set()
        self.install_calls.append(item.package_id)
        if self.failure is not None:
            raise self.failure
        if self.on_install is not None:
            self.on_install(item)

    async def update(self, item: InstallationCandidate, cancellation: asyncio.Event) -> None:
        assert not cancellation.is_set()
        self.update_calls.append(item.package_id)
        if self.failure is not None:
            raise self.failure
        if self.on_update is not None:
            self.on_update(item)


class FakeRuntime(ApplicationRuntime):
    def __init__(self, *, launchable: bool = True, launch_fails: bool = False) -> None:
        self.launchable = launchable
        self.launch_fails = launch_fails
        self.launches: list[str] = []
        self.closed: list[tuple[str, int]] = []

    async def can_launch(self, item: ApplicationRecord) -> bool:
        del item
        return self.launchable

    async def launch(self, item: ApplicationRecord) -> LaunchInfo:
        self.launches.append(item.application_id)
        if self.launch_fails:
            from jarvis.applications.models import ApplicationManagerError

            raise ApplicationManagerError("mock launch failure")
        return LaunchInfo(item.application_id, 456)

    async def close(self, application_id: str, process_id: int) -> None:
        self.closed.append((application_id, process_id))


class FakeConfiguration(ApplicationConfigurationAdapter):
    @property
    def application_id(self) -> str:
        return "app:obs-studio"

    async def configure(self, item: ApplicationRecord, settings: Mapping[str, object]) -> None:
        del item, settings


def manager(
    inventory: FakeInventory,
    packages: FakePackages,
    runtime: FakeRuntime | None = None,
) -> ApplicationManager:
    return ApplicationManager(
        inventory,
        packages,
        runtime or FakeRuntime(),
        InstallationPlanStore(),
    )


_APPROVAL_AUTHENTICATORS: dict[int, TrustedApprovalAuthenticator] = {}


def broker(*, install_decision: Decision = Decision.REQUIRE_APPROVAL) -> PermissionBroker:
    authenticator = TrustedApprovalAuthenticator(ApprovalSource.TRUSTED_UI)
    permission_broker = PermissionBroker(
        PolicyEngine(
            (
                PolicyRule(
                    "install-exact-package",
                    Permission.APPLICATION_INSTALL,
                    install_decision,
                    ScopeConstraint(
                        applications=("obsproject.obsstudio",),
                        tools=frozenset({"application.install", "application.update"}),
                    ),
                    frozenset({"install application", "update application"}),
                ),
                PolicyRule(
                    "launch-managed-obs",
                    Permission.APPLICATION_LAUNCH,
                    Decision.ALLOW,
                    ScopeConstraint(
                        applications=("app:obs-studio",),
                        tools=frozenset({"application.launch", "application.close"}),
                    ),
                    frozenset({"launch managed application", "close managed application"}),
                ),
            )
        ),
        approval_context_verifier=authenticator.verifier(),
    )
    _APPROVAL_AUTHENTICATORS[id(permission_broker)] = authenticator
    return permission_broker


def approval_context(
    permission_broker: PermissionBroker,
    request_id: UUID,
    choice: ApprovalChoice,
) -> TrustedApprovalContext:
    return _APPROVAL_AUTHENTICATORS[id(permission_broker)].issue_context(
        request_id=request_id,
        choice=choice,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )


def harness(tool: object, permission_broker: PermissionBroker) -> ToolHarness:
    ToolRegistry((tool,), permission_broker=permission_broker)  # type: ignore[arg-type]
    return ToolHarness(broker=permission_broker)


@pytest.mark.asyncio
async def test_plan_install_is_idempotent_for_existing_valid_application() -> None:
    packages = FakePackages((candidate(),))
    app_manager = manager(FakeInventory((record(),)), packages)

    plan, existing = await app_manager.plan_install("obs")

    assert plan is None
    assert existing == record()
    assert packages.install_calls == []


@pytest.mark.asyncio
async def test_winget_provider_requires_explicit_trusted_executable() -> None:
    item = candidate()
    provider = WingetPackageProvider((item,))

    with pytest.raises(PackageOperationError, match="explicitly configured"):
        await provider.install(item, asyncio.Event())


@pytest.mark.asyncio
async def test_ambiguous_package_search_requires_resolution() -> None:
    app_manager = manager(FakeInventory(), FakePackages((candidate(), candidate(name="OBS Beta"))))

    with pytest.raises(ApplicationAmbiguousError):
        await app_manager.plan_install("obs")


@pytest.mark.asyncio
async def test_missing_package_is_not_installable() -> None:
    app_manager = manager(FakeInventory(), FakePackages())

    with pytest.raises(PackageNotFoundError):
        await app_manager.plan_install("obs")


@pytest.mark.parametrize(
    "hostile_publisher",
    (
        "Evil\tPublisher",
        "Evil\x1b[2JPublisher",
        "Evil\x85Publisher",
        "Evil\u202ePublisher",
        "Evil\u2066Publisher\u2069",
    ),
)
def test_installation_candidate_rejects_approval_display_spoofing(
    hostile_publisher: str,
) -> None:
    with pytest.raises(ValueError, match="display controls"):
        candidate(publisher=hostile_publisher)


@pytest.mark.asyncio
async def test_corrupted_package_metadata_denies_before_plan_or_approval_display() -> None:
    corrupted = candidate()
    object.__setattr__(corrupted, "publisher", "Forged\x1b[2JPublisher")
    packages = FakePackages((corrupted,))
    tool = PlanInstallTool(manager(FakeInventory(), packages))
    permission_broker = PermissionBroker(PolicyEngine())
    runner = harness(tool, permission_broker)

    result = await runner.invoke(tool, {"name": "obs"})

    assert result.status is ToolResultStatus.EXPECTED_FAILURE
    assert result.error is not None
    assert result.error.code == "installation_plan_failed"
    assert await permission_broker.pending_approvals() == ()
    assert packages.install_calls == []


@pytest.mark.asyncio
async def test_denied_trusted_approval_does_not_reach_package_provider() -> None:
    packages = FakePackages((candidate(),))
    app_manager = manager(FakeInventory(), packages)
    plan, _ = await app_manager.plan_install("obs")
    assert plan is not None
    tool = InstallApplicationTool(app_manager)
    permission_broker = broker()
    runner = harness(tool, permission_broker)
    task_id = uuid4()

    first = await runner.invoke(tool, {"plan_id": plan.plan_id}, task_id=task_id)
    metadata = dict((item.key, item.value) for item in first.metadata)
    request_id = UUID(metadata["approval_request_id"])
    decision = await permission_broker.decide(
        approval_context(permission_broker, request_id, ApprovalChoice.DENY_ONCE)
    )
    second = await runner.invoke(tool, {"plan_id": plan.plan_id}, task_id=task_id)

    assert first.status is ToolResultStatus.PERMISSION_DENIED
    assert decision.accepted is True
    assert second.status is ToolResultStatus.PERMISSION_DENIED
    assert second.error is not None and second.error.code == "approval_pending"
    assert packages.install_calls == []


@pytest.mark.asyncio
async def test_install_still_requires_fresh_approval_when_policy_otherwise_allows() -> None:
    packages = FakePackages((candidate(),))
    app_manager = manager(FakeInventory(), packages)
    plan, _ = await app_manager.plan_install("obs")
    assert plan is not None
    tool = InstallApplicationTool(app_manager)
    runner = harness(tool, broker(install_decision=Decision.ALLOW))

    result = await runner.invoke(tool, {"plan_id": plan.plan_id})

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert result.error is not None and result.error.code == "approval_pending"
    assert packages.install_calls == []


@pytest.mark.asyncio
async def test_failed_install_consumes_plan_and_does_not_claim_verification() -> None:
    packages = FakePackages((candidate(),), failure=PackageOperationError("mock failure"))
    app_manager = manager(FakeInventory(), packages)
    plan, _ = await app_manager.plan_install("obs")
    assert plan is not None

    with pytest.raises(PackageOperationError):
        await app_manager.execute_plan(plan.plan_id, InstallationPlanKind.INSTALL, asyncio.Event())

    assert packages.install_calls == ["OBSProject.OBSStudio"]


@pytest.mark.asyncio
async def test_successful_install_requeries_identity_version_and_launch_capability() -> None:
    inventory = FakeInventory()

    def install(item: InstallationCandidate) -> None:
        inventory.records = (record(version=item.version),)

    packages = FakePackages((candidate(),), on_install=install)
    app_manager = manager(inventory, packages)
    plan, _ = await app_manager.plan_install("obs")
    assert plan is not None

    outcome = await app_manager.execute_plan(
        plan.plan_id, InstallationPlanKind.INSTALL, asyncio.Event()
    )

    assert outcome.record.version == "30.0.0"
    assert outcome.launch_verified is True
    assert outcome.already_present is False
    assert packages.install_calls == ["OBSProject.OBSStudio"]
    assert inventory.calls >= 2


@pytest.mark.asyncio
async def test_mismatched_post_install_identity_fails_verification() -> None:
    inventory = FakeInventory()

    def install(item: InstallationCandidate) -> None:
        del item
        inventory.records = (record(name="Different Application"),)

    app_manager = manager(inventory, FakePackages((candidate(),), on_install=install))
    plan, _ = await app_manager.plan_install("obs")
    assert plan is not None

    with pytest.raises(VerificationError):
        await app_manager.execute_plan(plan.plan_id, InstallationPlanKind.INSTALL, asyncio.Event())


@pytest.mark.asyncio
async def test_update_is_separate_and_rejects_downgrade() -> None:
    inventory = FakeInventory((record(version="30.0.0"),))
    update = candidate(version="31.0.0")

    def apply_update(item: InstallationCandidate) -> None:
        inventory.records = (record(version=item.version),)

    app_manager = manager(inventory, FakePackages(update=update, on_update=apply_update))
    plan = await app_manager.plan_update("app:obs-studio")
    outcome = await app_manager.execute_plan(
        plan.plan_id, InstallationPlanKind.UPDATE, asyncio.Event()
    )

    assert plan.kind is InstallationPlanKind.UPDATE
    assert outcome.record.version == "31.0.0"

    mismatch_manager = manager(
        FakeInventory((record(version="30.0.0"),)),
        FakePackages(update=candidate(version="31.0.0")),
    )
    wrong_kind_plan = await mismatch_manager.plan_update("app:obs-studio")
    with pytest.raises(InstallationPlanError):
        await mismatch_manager.execute_plan(
            wrong_kind_plan.plan_id,
            InstallationPlanKind.INSTALL,
            asyncio.Event(),
        )

    with pytest.raises(ApplicationManagerError):
        await manager(
            FakeInventory((record(version="31.0.0"),)),
            FakePackages(update=candidate(version="30.0.0")),
        ).plan_update("app:obs-studio")


@pytest.mark.asyncio
async def test_launch_failure_is_reported_after_broker_authorization() -> None:
    runtime = FakeRuntime(launch_fails=True)
    tool = LaunchManagedApplicationTool(
        manager(FakeInventory((record(),)), FakePackages(), runtime)
    )
    runner = harness(tool, broker())

    result = await runner.invoke(tool, {"application_id": "app:obs-studio"})

    assert result.status is ToolResultStatus.UNKNOWN_OUTCOME
    assert result.error is not None and result.error.code == "tool_execution_outcome_unknown"
    assert runtime.launches == ["app:obs-studio"]


@pytest.mark.asyncio
async def test_discovery_and_install_planning_tools_return_safe_structured_results() -> None:
    existing_manager = manager(FakeInventory((record(),)), FakePackages((candidate(),)))
    find = FindApplicationTool(existing_manager)
    plan = PlanInstallTool(existing_manager)
    no_permission_broker = PermissionBroker(PolicyEngine())
    find_runner = harness(find, no_permission_broker)
    plan_runner = harness(plan, no_permission_broker)

    found = await find_runner.invoke(find, {"name": "obs"})
    already = await plan_runner.invoke(plan, {"name": "obs"})

    assert found.status is ToolResultStatus.SUCCESS
    assert found.output is not None and found.output.model_dump()["status"] == "found"
    assert already.status is ToolResultStatus.SUCCESS
    assert already.output is not None
    assert already.output.model_dump()["outcome"] == "already_installed"

    ambiguous = PlanInstallTool(
        manager(FakeInventory(), FakePackages((candidate(), candidate(name="OBS Beta"))))
    )
    missing = PlanInstallTool(manager(FakeInventory(), FakePackages()))
    ambiguous_runner = harness(ambiguous, PermissionBroker(PolicyEngine()))
    missing_runner = harness(missing, PermissionBroker(PolicyEngine()))

    ambiguous_result = await ambiguous_runner.invoke(ambiguous, {"name": "obs"})
    missing_result = await missing_runner.invoke(missing, {"name": "obs"})
    assert ambiguous_result.error is not None
    assert ambiguous_result.error.code == "application_ambiguous"
    assert missing_result.error is not None
    assert missing_result.error.code == "package_not_found"


@pytest.mark.asyncio
async def test_brokered_install_and_update_execute_only_the_matching_approved_plan() -> None:
    install_inventory = FakeInventory()

    def install(item: InstallationCandidate) -> None:
        install_inventory.records = (record(version=item.version),)

    install_packages = FakePackages((candidate(),), on_install=install)
    install_manager = manager(install_inventory, install_packages)
    install_plan, _ = await install_manager.plan_install("obs")
    assert install_plan is not None
    install_tool = InstallApplicationTool(install_manager)
    install_broker = broker()
    install_runner = harness(install_tool, install_broker)
    install_task_id = uuid4()
    initial = await install_runner.invoke(
        install_tool, {"plan_id": install_plan.plan_id}, task_id=install_task_id
    )
    install_metadata = dict((item.key, item.value) for item in initial.metadata)
    install_request_id = UUID(install_metadata["approval_request_id"])
    await install_broker.decide(
        approval_context(
            install_broker,
            install_request_id,
            ApprovalChoice.APPROVE_ONCE,
        )
    )
    installed = await install_runner.invoke(
        install_tool, {"plan_id": install_plan.plan_id}, task_id=install_task_id
    )

    assert installed.status is ToolResultStatus.SUCCESS
    assert installed.output is not None and installed.output.model_dump()["launch_verified"] is True

    update_inventory = FakeInventory((record(version="30.0.0"),))
    update_candidate = candidate(version="31.0.0")

    def update(item: InstallationCandidate) -> None:
        update_inventory.records = (record(version=item.version),)

    update_manager = manager(
        update_inventory,
        FakePackages(update=update_candidate, on_update=update),
    )
    update_plan = await update_manager.plan_update("app:obs-studio")
    update_tool = UpdateApplicationTool(update_manager)
    update_broker = broker()
    update_runner = harness(update_tool, update_broker)
    update_task_id = uuid4()
    waiting = await update_runner.invoke(
        update_tool, {"plan_id": update_plan.plan_id}, task_id=update_task_id
    )
    update_metadata = dict((item.key, item.value) for item in waiting.metadata)
    update_request_id = UUID(update_metadata["approval_request_id"])
    await update_broker.decide(
        approval_context(
            update_broker,
            update_request_id,
            ApprovalChoice.APPROVE_ONCE,
        )
    )
    updated = await update_runner.invoke(
        update_tool, {"plan_id": update_plan.plan_id}, task_id=update_task_id
    )

    assert updated.status is ToolResultStatus.SUCCESS
    assert updated.output is not None and updated.output.model_dump()["kind"] == "update"


@pytest.mark.asyncio
async def test_update_plan_and_close_tools_stay_separate_from_launch() -> None:
    runtime = FakeRuntime()
    app_manager = manager(
        FakeInventory((record(version="30.0.0"),)),
        FakePackages(update=candidate(version="31.0.0")),
        runtime,
    )
    update_plan_tool = PlanUpdateTool(app_manager)
    update_plan_runner = harness(update_plan_tool, PermissionBroker(PolicyEngine()))
    plan_result = await update_plan_runner.invoke(
        update_plan_tool, {"application_id": "app:obs-studio"}
    )
    assert plan_result.status is ToolResultStatus.SUCCESS
    assert plan_result.output is not None and plan_result.output.model_dump()["kind"] == "update"

    close_tool = CloseManagedApplicationTool(app_manager)
    close_runner = harness(close_tool, broker())
    launch_tool = LaunchManagedApplicationTool(app_manager)
    launch_runner = harness(launch_tool, broker())
    launched = await launch_runner.invoke(launch_tool, {"application_id": "app:obs-studio"})
    closed = await close_runner.invoke(
        close_tool, {"application_id": "app:obs-studio", "process_id": 456}
    )

    assert launched.status is ToolResultStatus.SUCCESS
    assert runtime.launches == ["app:obs-studio"]
    assert closed.status is ToolResultStatus.SUCCESS
    assert runtime.closed == [("app:obs-studio", 456)]


def test_configuration_registry_and_catalogue_are_explicit() -> None:
    configuration = FakeConfiguration()
    registry = ConfigurationRegistry((configuration,))
    app_manager = manager(FakeInventory(), FakePackages())

    assert registry.for_application("app:obs-studio") is configuration
    with pytest.raises(ApplicationManagerError):
        registry.for_application("unknown")
    assert len(create_application_tools(app_manager)) == 7
