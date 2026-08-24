"""Adversarial tests for trusted self-modification classification."""

from __future__ import annotations

import pytest
from jarvis.security import (
    ModificationTrustClassifier,
    ModificationTrustError,
    ModificationTrustLevel,
    MutationPolicy,
)
from jarvis.security.models import (
    MutationAuthority,
    MutationContext,
    MutationReason,
    MutationStage,
)


@pytest.fixture()
def classifier() -> ModificationTrustClassifier:
    return ModificationTrustClassifier()


def test_generated_integration_is_level_one(classifier: ModificationTrustClassifier) -> None:
    result = classifier.classify(("integrations/example/manifest.json",))

    assert result.level is ModificationTrustLevel.GENERATED_INTEGRATION
    assert result.agent_editable
    assert result.approval_mode == "trusted_approval"


def test_user_space_is_level_two(classifier: ModificationTrustClassifier) -> None:
    result = classifier.classify(("jarvis/memory/preferences.py",))

    assert result.level is ModificationTrustLevel.USER_SPACE_JARVIS
    assert result.agent_editable


def test_core_runtime_is_level_three(classifier: ModificationTrustClassifier) -> None:
    result = classifier.classify(("jarvis/runtime.py",))

    assert result.level is ModificationTrustLevel.CORE_AGENT_RUNTIME
    assert len(result.required_gates) > len(
        classifier.classify(("jarvis/memory/preferences.py",)).required_gates
    )


def test_permission_broker_and_vault_are_level_four(
    classifier: ModificationTrustClassifier,
) -> None:
    result = classifier.classify(
        (
            "jarvis/permissions/broker.py",
            "jarvis/credentials/vault.py",
            "jarvis/credentials.py",
            "jarvis/security.py",
        )
    )

    assert result.level is ModificationTrustLevel.PERMISSION_BROKER_SECURITY
    assert not result.agent_editable
    assert result.approval_mode == "trusted_release_only"


@pytest.mark.parametrize(
    "path",
    (
        "jarvis/updater/service.py",
        "jarvis/recovery/restore.py",
        "docs/security-constitution.md",
        "jarvis/security/modification_policy.py",
    ),
)
def test_updater_recovery_and_root_of_trust_are_level_five(
    classifier: ModificationTrustClassifier,
    path: str,
) -> None:
    result = classifier.classify((path,))

    assert result.level is ModificationTrustLevel.UPDATER_RECOVERY_ROOT_OF_TRUST
    assert not result.agent_editable


def test_renaming_a_protected_module_does_not_lower_its_level(
    classifier: ModificationTrustClassifier,
) -> None:
    assert (
        classifier.classify(("jarvis/renamed_permission_broker.py",)).level
        is ModificationTrustLevel.PERMISSION_BROKER_SECURITY
    )
    assert (
        classifier.classify(("jarvis/renamed_security_constitution.py",)).level
        is ModificationTrustLevel.UPDATER_RECOVERY_ROOT_OF_TRUST
    )
    assert (
        classifier.classify(
            (
                "jarvis/permissions/broker.py",
                "jarvis/renamed_service.py",
            )
        ).level
        is ModificationTrustLevel.PERMISSION_BROKER_SECURITY
    )
    assert (
        classifier.classify(
            (
                "jarvis/security/modification_policy.py",
                "jarvis/renamed_service.py",
            )
        ).level
        is ModificationTrustLevel.UPDATER_RECOVERY_ROOT_OF_TRUST
    )


def test_mixed_scope_patch_uses_highest_level(classifier: ModificationTrustClassifier) -> None:
    result = classifier.classify(
        (
            "integrations/example/manifest.json",
            "jarvis/runtime.py",
            "jarvis/permissions/broker.py",
        )
    )

    assert result.level is ModificationTrustLevel.PERMISSION_BROKER_SECURITY
    assert set(result.paths) == {
        "integrations/example/manifest.json",
        "jarvis/runtime.py",
        "jarvis/permissions/broker.py",
    }


def test_classifier_policy_tampering_is_level_five(classifier: ModificationTrustClassifier) -> None:
    result = classifier.classify(("jarvis/improvement/renamed_classifier.py",))

    assert result.level is ModificationTrustLevel.UPDATER_RECOVERY_ROOT_OF_TRUST
    assert not result.agent_editable


@pytest.mark.parametrize(
    "path",
    (
        "jarvis/renamed_permission_broker.py",
        "jarvis/updater/service.py",
        "jarvis/improvement/renamed_classifier.py",
    ),
)
def test_routine_mutation_cannot_apply_renamed_protected_surfaces(path: str) -> None:
    decision = MutationPolicy().evaluate(
        path,
        MutationContext(
            MutationAuthority.ROUTINE_IMPROVEMENT,
            MutationStage.ISOLATED_PROPOSAL,
        ),
    )

    assert not decision.allowed
    assert decision.reason is MutationReason.TRUSTED_CORE_OWNER_RELEASE_REQUIRED


def test_mixed_patch_is_not_split_into_lower_trust_operations(
    classifier: ModificationTrustClassifier,
) -> None:
    mixed = classifier.classify(
        (
            "integrations/example/manifest.json",
            "jarvis/user_feature.py",
            "jarvis/renamed_permission_broker.py",
        )
    )

    assert mixed.level is ModificationTrustLevel.PERMISSION_BROKER_SECURITY
    assert not mixed.agent_editable


@pytest.mark.parametrize("paths", ((), ("../jarvis/runtime.py",), ("jarvis\\runtime.py",)))
def test_malformed_or_empty_patch_fails_closed(
    classifier: ModificationTrustClassifier,
    paths: tuple[str, ...],
) -> None:
    with pytest.raises(ModificationTrustError):
        classifier.classify(paths)


def test_gate_strength_is_monotonic(classifier: ModificationTrustClassifier) -> None:
    levels = [
        classifier.classify(("integrations/example.py",)),
        classifier.classify(("jarvis/memory/store.py",)),
        classifier.classify(("jarvis/runtime.py",)),
        classifier.classify(("jarvis/permissions/broker.py",)),
        classifier.classify(("jarvis/updater/service.py",)),
    ]

    assert [len(item.required_gates) for item in levels] == sorted(
        len(item.required_gates) for item in levels
    )
