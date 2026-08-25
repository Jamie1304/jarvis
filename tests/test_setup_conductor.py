from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from jarvis.permissions.models import Permission
from jarvis.provisioning import (
    ProvisioningAction,
    ProvisioningActionKind,
    ProvisioningPlan,
    ProvisioningPlanState,
    ProvisioningResult,
)
from jarvis.setup_conductor import (
    AdoptionCandidate,
    AdoptionChoice,
    InMemorySetupStore,
    SetupConductor,
    SetupContext,
    SetupDecision,
    SetupError,
    SetupInspection,
    SetupRequirement,
    SetupRun,
    SetupRunState,
    SetupStep,
    SetupStepResult,
    SetupStepState,
    SetupValidationError,
    SQLiteSetupStore,
)

from tests.adoption_fixtures import adoption_candidate


class Handler:
    def __init__(self, *, candidate: AdoptionCandidate | None = None) -> None:
        self.candidate = candidate
        self.installed = False
        self.configured = False
        self.starts = 0
        self.prepare_calls = 0
        self.fail_config_once = False

    async def inspect(self, step: SetupStep, context: SetupContext) -> SetupInspection:
        del step, context
        return SetupInspection(
            completed=self.installed,
            candidates=(self.candidate,) if self.candidate else (),
            partial=self.configured and not self.installed,
            detail="fixture inspection",
        )

    async def prepare(
        self, step: SetupStep, context: SetupContext, decision: SetupDecision | None
    ) -> ProvisioningPlan | None:
        del step, context, decision
        self.prepare_calls += 1
        self.installed = True
        return provisioning_plan()

    async def configure(self, step: SetupStep, context: SetupContext) -> None:
        del step, context
        if self.fail_config_once:
            self.fail_config_once = False
            raise RuntimeError("interrupted configuration")
        self.configured = True

    async def verify(self, step: SetupStep, context: SetupContext) -> bool:
        del step, context
        return self.installed and self.configured

    async def first_start(self, step: SetupStep, context: SetupContext) -> bool:
        del step, context
        self.starts += 1
        return True


def step(*, requirements: tuple[SetupRequirement, ...] = ()) -> SetupStep:
    return SetupStep("runtime", "runtime", requirements)


def result() -> ProvisioningResult:
    return ProvisioningResult(uuid4(), ProvisioningPlanState.VERIFIED, (), "verified")


def provisioning_plan() -> ProvisioningPlan:
    now = datetime.now(UTC)
    return ProvisioningPlan(
        uuid4(),
        uuid4(),
        (
            ProvisioningAction(
                "setup",
                "fixture",
                ProvisioningActionKind.WRITE_CONFIG,
                "fixture.config",
                {"mode": "safe"},
                Permission.FILESYSTEM_WRITE,
            ),
        ),
        now,
        now + timedelta(minutes=5),
    )


async def provision_ok(_plan: ProvisioningPlan) -> ProvisioningResult:
    return result()


@pytest.mark.asyncio
async def test_existing_local_runtime_is_adopted_without_provisioning() -> None:
    candidate, adoption_policy = adoption_candidate("local", location="C:/existing")
    handler = Handler(candidate=candidate)
    handler.installed = True
    handler.configured = True
    decisions: list[tuple[SetupRequirement, ...]] = []

    async def collect(
        requirements: tuple[SetupRequirement, ...],
        candidates: tuple[AdoptionCandidate, ...],
    ) -> tuple[SetupDecision, ...]:
        decisions.append(requirements)
        assert candidates[0].has_user_data
        return (
            SetupDecision(
                "runtime-choice",
                AdoptionChoice.USE_IN_PLACE,
                {"candidate_id": "local", "identity_digest": candidate.identity_digest},
            ),
        )

    provision_calls = 0

    async def provision(plan: ProvisioningPlan) -> ProvisioningResult:
        nonlocal provision_calls
        provision_calls += 1
        return result()

    requirement = SetupRequirement(
        "runtime-choice", "Choose the existing runtime", (AdoptionChoice.USE_IN_PLACE,)
    )
    run = await SetupConductor(
        {"runtime": handler},
        InMemorySetupStore(),
        provision,
        decision_collector=collect,
        adoption_policy=adoption_policy,
    ).run("first_run", (step(requirements=(requirement,)),), SetupContext())
    assert run.state is SetupRunState.COMPLETED
    assert run.steps[0].state is SetupStepState.ADOPTED
    assert run.steps[0].candidate_id == "local"
    assert run.steps[0].identity_digest == candidate.identity_digest
    assert run.steps[0].adoption_attestation is not None
    assert provision_calls == 0
    assert len(decisions) == 1


@pytest.mark.asyncio
async def test_adoption_rejects_unlisted_candidate_identity() -> None:
    candidate = AdoptionCandidate(
        "local", "runtime", "C:/existing", "1.0", identity_digest="a" * 64
    )
    handler = Handler(candidate=candidate)
    handler.installed = True
    handler.configured = True

    async def collect(
        requirements: tuple[SetupRequirement, ...],
        candidates: tuple[AdoptionCandidate, ...],
    ) -> tuple[SetupDecision, ...]:
        del candidates
        return (
            SetupDecision(
                requirements[0].requirement_id,
                AdoptionChoice.USE_IN_PLACE,
                {"candidate_id": "unlisted", "identity_digest": "b" * 64},
            ),
        )

    requirement = SetupRequirement("runtime-choice", "Choose the existing runtime")

    async def provision(_plan: ProvisioningPlan) -> ProvisioningResult:
        return result()

    with pytest.raises(SetupError, match="candidate"):
        await SetupConductor(
            {"runtime": handler},
            InMemorySetupStore(),
            provision,
            decision_collector=collect,
        ).run("adoption", (step(requirements=(requirement,)),), SetupContext())


@pytest.mark.asyncio
async def test_adoption_rejects_candidate_replacement_before_verification() -> None:
    class ReplacingHandler(Handler):
        inspections = 0

        async def inspect(self, item: SetupStep, context: SetupContext) -> SetupInspection:
            self.inspections += 1
            if self.inspections == 2:
                self.candidate = adoption_candidate(
                    "local", location="C:/replacement", seed="replacement"
                )[0]
            return await super().inspect(item, context)

    original, adoption_policy = adoption_candidate("local", location="C:/existing")
    handler = ReplacingHandler(candidate=original)
    handler.installed = True
    handler.configured = True

    async def collect(
        requirements: tuple[SetupRequirement, ...],
        candidates: tuple[AdoptionCandidate, ...],
    ) -> tuple[SetupDecision, ...]:
        del candidates
        return (
            SetupDecision(
                requirements[0].requirement_id,
                AdoptionChoice.USE_IN_PLACE,
                {"candidate_id": "local", "identity_digest": original.identity_digest},
            ),
        )

    requirement = SetupRequirement("runtime-choice", "Choose the existing runtime")

    async def provision(_plan: ProvisioningPlan) -> ProvisioningResult:
        return result()

    with pytest.raises(SetupError, match="candidate|identity"):
        await SetupConductor(
            {"runtime": handler},
            InMemorySetupStore(),
            provision,
            decision_collector=collect,
            adoption_policy=adoption_policy,
        ).run("adoption", (step(requirements=(requirement,)),), SetupContext())
    assert handler.starts == 0


@pytest.mark.asyncio
async def test_adoption_attestation_survives_setup_store_restart(tmp_path: Path) -> None:
    candidate, adoption_policy = adoption_candidate("restart", location="C:/restart.exe")
    handler = Handler(candidate=candidate)
    handler.installed = True
    handler.configured = True
    requirement = SetupRequirement("restart-choice", "Use the existing runtime")

    async def collect(
        requirements: tuple[SetupRequirement, ...],
        candidates: tuple[AdoptionCandidate, ...],
    ) -> tuple[SetupDecision, ...]:
        assert candidates
        return (
            SetupDecision(
                requirements[0].requirement_id,
                AdoptionChoice.USE_IN_PLACE,
                {
                    "candidate_id": candidates[0].candidate_id,
                    "identity_digest": candidates[0].identity_digest,
                },
            ),
        )

    database = tmp_path / "setup.sqlite3"
    first_store = SQLiteSetupStore(database)
    first = await SetupConductor(
        {"runtime": handler},
        first_store,
        lambda plan: _async_provision(plan),
        decision_collector=collect,
        adoption_policy=adoption_policy,
    ).run("restart-adoption", (step(requirements=(requirement,)),), SetupContext())
    assert first.state is SetupRunState.COMPLETED
    assert first.steps[0].adoption_attestation is not None
    first_store.close()

    second_store = SQLiteSetupStore(database)
    second = await SetupConductor(
        {"runtime": handler},
        second_store,
        lambda plan: _async_provision(plan),
        decision_collector=collect,
        adoption_policy=adoption_policy,
    ).run(
        "restart-adoption",
        (step(requirements=(requirement,)),),
        SetupContext(),
        run_id=first.run_id,
    )
    assert second.state is SetupRunState.COMPLETED
    assert second.steps[0].adoption_attestation is not None
    second_store.close()


async def _async_provision(plan: ProvisioningPlan) -> ProvisioningResult:
    del plan
    return result()


@pytest.mark.asyncio
async def test_incompatible_installation_is_not_adopted_and_install_new_is_typed() -> None:
    handler = Handler(
        candidate=AdoptionCandidate("old", "runtime", "C:/old", "0.1", compatible=False)
    )
    provision_calls = 0

    async def provision(plan: ProvisioningPlan) -> ProvisioningResult:
        nonlocal provision_calls
        provision_calls += 1
        return result()

    async def collect(
        requirements: tuple[SetupRequirement, ...],
        candidates: tuple[AdoptionCandidate, ...],
    ) -> tuple[SetupDecision, ...]:
        assert candidates[0].compatible is False
        return (SetupDecision(requirements[0].requirement_id, AdoptionChoice.INSTALL_NEW),)

    run = await SetupConductor(
        {"runtime": handler},
        InMemorySetupStore(),
        provision,
        decision_collector=collect,
    ).run(
        "model_setup",
        (step(requirements=(SetupRequirement("choice", "Select runtime"),)),),
        SetupContext(configuration={"model": "local"}),
    )
    assert run.state is SetupRunState.COMPLETED
    assert handler.prepare_calls == 1
    assert provision_calls == 1


@pytest.mark.asyncio
async def test_partial_setup_resumes_and_successful_rerun_does_not_duplicate_install() -> None:
    handler = Handler()
    handler.fail_config_once = True
    store = InMemorySetupStore()

    async def provision(plan: ProvisioningPlan) -> ProvisioningResult:
        return result()

    conductor = SetupConductor({"runtime": handler}, store, provision)
    with pytest.raises(RuntimeError, match="interrupted"):
        await conductor.run("repair", (step(),), SetupContext(), run_id=uuid4())
    run_id = next(iter(store._runs))
    resumed = await conductor.run("repair", (step(),), SetupContext(), run_id=run_id)
    assert resumed.state is SetupRunState.COMPLETED
    assert handler.prepare_calls == 2
    calls = handler.prepare_calls
    rerun = await conductor.run("repair", (step(),), SetupContext(), run_id=run_id)
    assert rerun.state is SetupRunState.COMPLETED
    assert handler.prepare_calls == calls
    assert handler.starts == 1


@pytest.mark.asyncio
async def test_declined_adoption_preserves_existing_user_data() -> None:
    candidate = AdoptionCandidate("folder", "runtime", "C:/user-data", has_user_data=True)
    handler = Handler(candidate=candidate)

    async def collect(
        requirements: tuple[SetupRequirement, ...],
        candidates: tuple[AdoptionCandidate, ...],
    ) -> tuple[SetupDecision, ...]:
        assert candidates[0].has_user_data
        return (SetupDecision(requirements[0].requirement_id, AdoptionChoice.IGNORE),)

    async def provision(plan: ProvisioningPlan) -> ProvisioningResult:
        raise AssertionError("declined adoption must not provision")

    run = await SetupConductor(
        {"runtime": handler},
        InMemorySetupStore(),
        provision,
        decision_collector=collect,
    ).run(
        "onboarding",
        (step(requirements=(SetupRequirement("choice", "Use existing folder"),)),),
        SetupContext(),
    )
    assert run.state is SetupRunState.COMPLETED
    assert run.steps[0].state is SetupStepState.DECLINED
    assert handler.candidate is not None
    assert handler.candidate.has_user_data


@pytest.mark.asyncio
async def test_permission_required_provisioning_is_not_bypassed() -> None:
    handler = Handler()

    async def provision(plan: ProvisioningPlan) -> ProvisioningResult:
        raise SetupError("Permission approval is required")

    with pytest.raises(SetupError, match="approval"):
        await SetupConductor({"runtime": handler}, InMemorySetupStore(), provision).run(
            "integration_install", (step(),), SetupContext()
        )
    assert handler.prepare_calls == 1


def test_setup_state_survives_sqlite_restart(tmp_path: Path) -> None:
    path = tmp_path / "setup.sqlite3"
    store = SQLiteSetupStore(path)
    run_id = uuid4()
    run = SetupRun(
        run_id,
        "first_run",
        "a" * 64,
        SetupRunState.WAITING_DECISIONS,
        (),
        (SetupDecision("choice", AdoptionChoice.IGNORE),),
        datetime.now(UTC),
    )
    store.save(run)
    store.close()
    restarted = SQLiteSetupStore(path)
    loaded = restarted.load(run_id)
    assert loaded is not None
    assert loaded.decisions[0].choice is AdoptionChoice.IGNORE
    restarted.close()


def test_setup_rejects_raw_secrets_and_invalid_steps() -> None:
    with pytest.raises(SetupValidationError):
        SetupContext(configuration={"token": "raw"})
    with pytest.raises(SetupValidationError):
        SetupDecision("choice", AdoptionChoice.INSTALL_NEW, {"password": "raw"})

    async def empty_provision(plan: ProvisioningPlan) -> ProvisioningResult:
        return result()

    with pytest.raises(SetupValidationError):
        SetupConductor({}, InMemorySetupStore(), empty_provision)
    with pytest.raises(SetupValidationError):
        SetupStep("bad id!", "runtime")
    with pytest.raises(SetupValidationError):
        AdoptionCandidate("local", "runtime", "C:/existing", identity_digest="bad")
    with pytest.raises(SetupValidationError):
        SetupStepResult("bad id!", SetupStepState.VERIFIED)
    with pytest.raises(SetupValidationError):
        SetupStepResult("runtime", SetupStepState.VERIFIED, identity_digest="bad")


@pytest.mark.asyncio
async def test_setup_waits_for_decisions_and_honors_cancellation() -> None:
    handler = Handler()
    conductor = SetupConductor(
        {"runtime": handler},
        InMemorySetupStore(),
        provision_ok,
    )
    waiting = await conductor.run(
        "waiting",
        (step(requirements=(SetupRequirement("choice", "Choose"),)),),
        SetupContext(),
    )
    assert waiting.state is SetupRunState.WAITING_DECISIONS

    cancelled = asyncio.Event()
    cancelled.set()
    recovered = await conductor.run("cancelled", (step(),), SetupContext(), cancellation=cancelled)
    assert recovered.state is SetupRunState.RECOVERING
    assert recovered.error == "cancelled"


@pytest.mark.asyncio
async def test_setup_rejects_context_change_dependency_and_unknown_decision() -> None:
    store = InMemorySetupStore()
    conductor = SetupConductor({"runtime": Handler()}, store, provision_ok)
    run_id = uuid4()
    first = await conductor.run("context", (step(),), SetupContext(), run_id=run_id)
    assert first.state is SetupRunState.COMPLETED
    with pytest.raises(SetupError, match="context changed"):
        await conductor.run(
            "context", (step(),), SetupContext(configuration={"changed": True}), run_id=run_id
        )

    async def collect_unknown(
        requirements: tuple[SetupRequirement, ...], candidates: tuple[AdoptionCandidate, ...]
    ) -> tuple[SetupDecision, ...]:
        del requirements, candidates
        return (SetupDecision("unknown", AdoptionChoice.IGNORE),)

    with pytest.raises(SetupValidationError, match="unknown requirement"):
        await SetupConductor(
            {"runtime": Handler()},
            InMemorySetupStore(),
            provision_ok,
            decision_collector=collect_unknown,
        ).run(
            "unknown", (step(requirements=(SetupRequirement("choice", "Choose"),)),), SetupContext()
        )

    dependent = (
        SetupStep("first", "runtime"),
        SetupStep("second", "runtime", depends_on=("first",)),
    )
    declined = await SetupConductor(
        {"runtime": Handler()},
        InMemorySetupStore(),
        provision_ok,
        decision_collector=lambda requirements, candidates: _ignore_decision(requirements),
    ).run(
        "dependency",
        (SetupStep("first", "runtime", (SetupRequirement("choice", "Choose"),)), dependent[1]),
        SetupContext(),
    )
    assert declined.state is SetupRunState.FAILED
    assert declined.error == "dependency is not verified"


async def _ignore_decision(requirements: tuple[SetupRequirement, ...]) -> tuple[SetupDecision, ...]:
    return tuple(SetupDecision(item.requirement_id, AdoptionChoice.IGNORE) for item in requirements)


@pytest.mark.asyncio
async def test_setup_provision_verify_and_first_start_failures_are_recorded() -> None:
    plan = provisioning_plan()

    async def failed_provision(_plan: ProvisioningPlan) -> ProvisioningResult:
        return ProvisioningResult(uuid4(), ProvisioningPlanState.FAILED, (), "failed")

    failed = await SetupConductor(
        {"runtime": Handler()}, InMemorySetupStore(), failed_provision
    ).run("provision-fail", (step(),), SetupContext())
    assert failed.state is SetupRunState.FAILED
    assert failed.error == "provisioning failed"

    class VerifyFailHandler(Handler):
        async def verify(self, step: SetupStep, context: SetupContext) -> bool:
            del step, context
            return False

    verified = await SetupConductor(
        {"runtime": VerifyFailHandler()}, InMemorySetupStore(), provision_ok
    ).run("verify-fail", (step(),), SetupContext())
    assert verified.state is SetupRunState.FAILED
    assert verified.error == "verification failed"

    class StartFailHandler(Handler):
        async def first_start(self, step: SetupStep, context: SetupContext) -> bool:
            del step, context
            return False

    started = await SetupConductor(
        {"runtime": StartFailHandler()}, InMemorySetupStore(), provision_ok
    ).run("start-fail", (step(),), SetupContext())
    assert started.state is SetupRunState.FAILED
    assert started.error == "first-start test failed"
    assert plan.actions
