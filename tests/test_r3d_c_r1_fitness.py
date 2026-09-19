import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jarvis.ai.fitness import (
    FitnessEvidence,
    RoutingFitnessProjection,
    RoutingFitnessStoreError,
    SemanticOutcome,
    SQLiteRoutingFitnessStore,
    VerifiedRouteOutcome,
)
from jarvis.autonomy.routing import (
    EligibilityCode,
    ExecutionRouteSelector,
    ExecutionRouteStatus,
    ModelInferencePolicy,
    StepRequirements,
    StepRoutingContext,
)
from jarvis.core.config import Settings
from jarvis.runtime import ApplicationRuntime, RuntimeStatus
from jarvis.tools.catalog import create_safe_tool_registry

from tests.test_r3d_b_execution_routing import step

NOW = datetime(2026, 9, 19, tzinfo=UTC)


def outcome(
    number: int,
    *,
    semantic: SemanticOutcome = SemanticOutcome.VERIFIED_SUCCESS,
    observed_at: datetime = NOW,
) -> VerifiedRouteOutcome:
    return VerifiedRouteOutcome(
        observation_id=f"trusted-attempt-{number}",
        route_identity="calculator",
        candidate_kind="tool",
        task_class="math",
        role="orchestration",
        observed_at=observed_at,
        operational_outcome="succeeded",
        semantic_outcome=semantic,
        verification_source=(
            "planning.step_verifier"
            if semantic in {SemanticOutcome.VERIFIED_SUCCESS, SemanticOutcome.VERIFIED_FAILURE}
            else None
        ),
        retry_count=number,
        failure_class=None,
        evidence_refs=("task:trusted", f"attempt:{number}"),
    )


def projection(path: Path) -> tuple[SQLiteRoutingFitnessStore, RoutingFitnessProjection]:
    store = SQLiteRoutingFitnessStore(path)
    return store, RoutingFitnessProjection(clock=lambda: NOW, store=store)


def test_restart_preserves_metrics_recency_and_sufficiency(tmp_path: Path) -> None:
    path = tmp_path / "routing-fitness.sqlite3"
    store, first = projection(path)
    for number in range(1, 4):
        assert first.record(outcome(number))
    before = first.view("calculator", "math", now=NOW)
    store.close()

    reopened, second = projection(path)
    after = second.view("calculator", "math", now=NOW)

    assert after == before
    assert after.sample_count == 3
    assert after.semantic_verified_success_count == 3
    assert after.operational_success_count == 3
    assert after.last_observed_at == NOW
    assert after.evidence is FitnessEvidence.SUFFICIENT
    reopened.close()


def test_restart_replay_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "routing-fitness.sqlite3"
    store, first = projection(path)
    item = outcome(1)
    assert first.record(item)
    store.close()

    reopened, second = projection(path)
    assert not second.record(item)
    assert second.view("calculator", "math", now=NOW).sample_count == 1
    reopened.close()


def test_replayed_attempt_timestamp_does_not_rejuvenate_history(tmp_path: Path) -> None:
    path = tmp_path / "routing-fitness.sqlite3"
    store, first = projection(path)
    original = outcome(1, observed_at=NOW - timedelta(days=31))
    assert first.record(original)
    store.close()

    reopened, second = projection(path)
    assert not second.record(outcome(1, observed_at=NOW))
    view = second.view("calculator", "math", now=NOW)
    assert view.last_observed_at == original.observed_at
    assert view.evidence is FitnessEvidence.INSUFFICIENT
    reopened.close()


def test_conflicting_duplicate_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "routing-fitness.sqlite3"
    store, first = projection(path)
    assert first.record(outcome(1))
    store.close()

    reopened, second = projection(path)
    with pytest.raises(RoutingFitnessStoreError, match="Conflicting"):
        second.record(outcome(1, semantic=SemanticOutcome.VERIFIED_FAILURE))
    assert second.view("calculator", "math", now=NOW).sample_count == 1
    reopened.close()


def test_future_schema_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "routing-fitness.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE routing_fitness_schema (version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
    )
    connection.execute("INSERT INTO routing_fitness_schema(version, name) VALUES (99, 'future')")
    connection.commit()
    connection.close()

    with pytest.raises(RoutingFitnessStoreError, match="future schema"):
        SQLiteRoutingFitnessStore(path)


def test_corrupt_database_translates_and_releases_handle(tmp_path: Path) -> None:
    path = tmp_path / "routing-fitness.sqlite3"
    path.write_bytes(b"not a sqlite database")

    with pytest.raises(RoutingFitnessStoreError) as failure:
        SQLiteRoutingFitnessStore(path)

    assert isinstance(failure.value.__cause__, sqlite3.DatabaseError)
    path.unlink()
    assert not path.exists()


def test_stale_timestamp_survives_restart_without_rejuvenation(tmp_path: Path) -> None:
    path = tmp_path / "routing-fitness.sqlite3"
    old = NOW - timedelta(days=31)
    store, first = projection(path)
    for number in range(1, 4):
        first.record(outcome(number, observed_at=old))
    assert first.view("calculator", "math", now=NOW).evidence is FitnessEvidence.STALE
    store.close()

    reopened, second = projection(path)
    view = second.view("calculator", "math", now=NOW)
    assert view.last_observed_at == old
    assert view.evidence is FitnessEvidence.STALE
    reopened.close()


def test_quality_floor_remains_hard_after_restart(tmp_path: Path) -> None:
    path = tmp_path / "routing-fitness.sqlite3"
    store, first = projection(path)
    for number in range(1, 4):
        first.record(outcome(number, semantic=SemanticOutcome.VERIFIED_FAILURE))
    store.close()
    reopened, second = projection(path)
    selector = ExecutionRouteSelector(
        model_router=None,
        tool_registry=create_safe_tool_registry(),
        fitness=second,
    )
    requirements = StepRequirements.from_step(
        step(),
        context=StepRoutingContext(
            model_inference=ModelInferencePolicy.FORBIDDEN,
            task_class="math",
            preferred_tool_id="calculator",
            minimum_verified_reliability=0.8,
        ),
    )

    decision = selector.route(requirements)

    assert decision.status is ExecutionRouteStatus.NO_VALID_ROUTE
    assert EligibilityCode.QUALITY_FLOOR_NOT_MET in decision.reasons
    reopened.close()


@pytest.mark.asyncio
async def test_production_runtime_reuses_durable_fitness_state(tmp_path: Path) -> None:
    settings = Settings(app_data_dir=tmp_path / "jarvis-data", ai_provider="ollama")
    runtime = ApplicationRuntime.create(settings)
    assert runtime.status is RuntimeStatus.READY
    assert runtime.container is not None
    assert runtime.container.routing_fitness_store.database_path == (
        tmp_path / "jarvis-data" / "routing-fitness.sqlite3"
    )
    for number in range(1, 4):
        assert runtime.container.routing_fitness.record(outcome(number))
    await runtime.aclose()

    restarted = ApplicationRuntime.create(settings)
    assert restarted.status is RuntimeStatus.READY
    assert restarted.container is not None
    view = restarted.container.routing_fitness.view("calculator", "math", now=NOW)
    assert view.sample_count == 3
    assert view.evidence is FitnessEvidence.SUFFICIENT
    await restarted.aclose()
