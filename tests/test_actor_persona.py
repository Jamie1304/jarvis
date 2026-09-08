from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from jarvis.actor_persona import (
    ActorContextService,
    ActorContextSource,
    PersonaKernel,
    PersonaProfile,
)
from jarvis.permissions.models import ApprovalActorKind
from jarvis.user_model import UserModelStore


def test_actor_context_requires_trusted_source_and_expires() -> None:
    service = ActorContextService(clock=lambda: datetime(2026, 1, 1, tzinfo=UTC))
    context = service.create_trusted(
        session_id=uuid4(),
        principal_id="desktop-local-user",
        source=ActorContextSource.LOCAL_DESKTOP_SESSION,
        ttl_seconds=10,
    )
    assert service.approval_identity(context).kind is ApprovalActorKind.TRUSTED_USER
    with pytest.raises(PermissionError):
        context.require_active(datetime(2026, 1, 1, 0, 0, 11, tzinfo=UTC))


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
