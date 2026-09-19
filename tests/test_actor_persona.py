from datetime import UTC, datetime
from inspect import signature
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from jarvis.actor_persona import (
    ActorContextService,
    ActorContextSource,
    ForbiddenActorSource,
    PersonaKernel,
    PersonaProfile,
)
from jarvis.memory.models import RetentionPolicy, Sensitivity
from jarvis.permissions.models import ApprovalActorKind
from jarvis.user_model import (
    UserModelKind,
    UserModelOrigin,
    UserModelRecord,
    UserModelSource,
    UserModelStore,
)


def test_actor_context_requires_trusted_source_and_expires() -> None:
    service = ActorContextService(clock=lambda: datetime(2026, 1, 1, tzinfo=UTC))
    context = service.create_trusted(
        session_id=uuid4(),
        principal_id="desktop-local-user",
        source=ActorContextSource.LOCAL_DESKTOP_SESSION,
        ttl_seconds=10,
    )
    assert service.approval_identity(context).kind is ApprovalActorKind.TRUSTED_USER
    expired_service = ActorContextService(clock=lambda: datetime(2026, 1, 1, 0, 0, 11, tzinfo=UTC))
    with pytest.raises(PermissionError):
        expired_service.approval_identity(context)


def test_actor_authority_bridge_fails_closed_for_expiry_end_system_and_foreign_context() -> None:
    clock_time = datetime(2026, 1, 1, tzinfo=UTC)
    service = ActorContextService(clock=lambda: clock_time)
    system = service.create_trusted(
        session_id=uuid4(), principal_id="system", source=ActorContextSource.SYSTEM_SERVICE
    )
    with pytest.raises(PermissionError):
        service.approval_identity(system)

    expiring = service.create_trusted(
        session_id=uuid4(),
        principal_id="desktop",
        source=ActorContextSource.LOCAL_DESKTOP_SESSION,
        ttl_seconds=1,
    )
    expired_clock = [clock_time]
    expiring_service = ActorContextService(clock=lambda: expired_clock[0])
    expiring = expiring_service.create_trusted(
        session_id=uuid4(),
        principal_id="desktop",
        source=ActorContextSource.LOCAL_DESKTOP_SESSION,
        ttl_seconds=1,
    )
    expired_clock[0] = datetime(2026, 1, 1, 0, 0, 2, tzinfo=UTC)
    with pytest.raises(PermissionError):
        expiring_service.approval_identity(expiring)
    ended = service.create_trusted(
        session_id=uuid4(), principal_id="desktop", source=ActorContextSource.LOCAL_DESKTOP_SESSION
    )
    service.end(ended)
    with pytest.raises(PermissionError):
        service.approval_identity(ended)
    with pytest.raises(PermissionError):
        ActorContextService().approval_identity(expiring)


@pytest.mark.parametrize("forbidden", tuple(ForbiddenActorSource))
def test_forbidden_actor_concepts_cannot_mint_context(forbidden: ForbiddenActorSource) -> None:
    with pytest.raises(ValueError):
        ActorContextService().create_trusted(
            session_id=uuid4(),
            principal_id=forbidden.value,
            source=cast(ActorContextSource, forbidden),
        )


def test_relationship_data_has_no_actor_authority_constructor() -> None:
    assert "relationship" not in signature(ActorContextService.create_trusted).parameters


def test_persona_is_bounded_and_persists_as_user_model_preference(tmp_path: Path) -> None:
    path = tmp_path / "user-model.sqlite3"
    with UserModelStore(path) as store:
        kernel = PersonaKernel(store)
        assert kernel.get() == PersonaProfile.defaults()
        updated = kernel.update(verbosity=4, humor_level=1)
        assert updated.verbosity == 4
        assert kernel.get() == updated
    with UserModelStore(path) as store:
        assert PersonaKernel(store).get().verbosity == 4


def test_persona_rejects_authority_fields_and_reset_is_safe(tmp_path: Path) -> None:
    with UserModelStore(tmp_path / "user-model.sqlite3") as store:
        kernel = PersonaKernel(store)
        with pytest.raises(ValueError):
            kernel.update(permission_level=4)
        kernel.update(verbosity=4)
        assert kernel.reset() == PersonaProfile.defaults()
        assert kernel.get() == PersonaProfile.defaults()


def test_persona_presentation_guidance_is_bounded_and_non_authoritative() -> None:
    guidance = PersonaProfile(
        verbosity=4, response_length=1, technical_depth=3
    ).presentation_guidance()

    assert "verbosity level 4/4" in guidance
    assert "response length 1/4" in guidance
    assert "technical depth 3/4" in guidance
    assert "permissions" in guidance
    assert "verification" in guidance
    assert "ignore permissions" not in guidance.lower()
    assert "administrator" not in guidance.lower()


def test_inferred_persona_never_becomes_active_or_is_deleted_by_reset(tmp_path: Path) -> None:
    with UserModelStore(tmp_path / "user-model.sqlite3") as store:
        now = datetime.now(UTC)
        inferred = UserModelRecord(
            uuid4(),
            None,
            "persona.profile",
            UserModelKind.PREFERENCE,
            "presentation",
            PersonaProfile(verbosity=4).as_dict(),
            UserModelSource.MODEL,
            "model-suggestion",
            0.5,
            now,
            now,
            None,
            Sensitivity.PRIVATE,
            RetentionPolicy.UNTIL_DELETED,
            UserModelOrigin.INFERRED,
        )
        store.create(inferred)
        kernel = PersonaKernel(store)
        assert kernel.get() == PersonaProfile.defaults()
        assert kernel.reset() == PersonaProfile.defaults()
        assert store.get(inferred.record_id) is not None
