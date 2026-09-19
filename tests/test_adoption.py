from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from jarvis.adoption import (
    AdoptionIdentityError,
    AdoptionIdentityInspector,
    AdoptionOutcome,
    AdoptionValidationError,
    DependencyEvidence,
    DependencyProvenance,
    EvidenceAuthority,
    EvidenceConfidence,
    LocalDependencyProvenanceProvider,
    SignerEvidence,
    SignerStatus,
    StaticDependencyProvenanceProvider,
    StaticFileIdentityProvider,
    StaticSignerVerifier,
    WindowsFileIdentity,
    WindowsFileIdentityProvider,
    WindowsSignerVerifier,
)

from tests.adoption_fixtures import adoption_candidate


def test_identity_includes_stable_file_id_and_hash() -> None:
    candidate, _ = adoption_candidate()
    assert candidate.identity_evidence is not None
    assert candidate.identity_digest == candidate.identity_evidence.fingerprint
    assert candidate.adoption_attestation is not None


def test_same_filename_different_file_identity_is_not_reused() -> None:
    location = "C:/same-name.exe"
    first = adoption_candidate(location=location, seed="first")[0]
    second = adoption_candidate(location=location, seed="second")[0]
    assert first.identity_digest != second.identity_digest
    assert first.identity_evidence is not None and second.identity_evidence is not None
    assert first.identity_evidence.file.file_id != second.identity_evidence.file.file_id


def test_reparse_target_is_rejected_before_policy() -> None:
    location = "C:/reparse.exe"
    file = WindowsFileIdentity(
        location,
        1,
        "reparse-file",
        5,
        sha256(b"reparse").hexdigest(),
        "executable",
        True,
        datetime.now(UTC),
    )
    signer = SignerEvidence(SignerStatus.VALID_TRUSTED_SIGNATURE)
    dependencies = DependencyProvenance(
        "receipt",
        EvidenceAuthority.PACKAGE_RECEIPT,
        EvidenceConfidence.HIGH,
        (
            DependencyEvidence(
                "runtime",
                "receipt",
                "receipt://runtime",
                sha256(b"runtime").hexdigest(),
                EvidenceAuthority.PACKAGE_RECEIPT,
                EvidenceConfidence.HIGH,
            ),
        ),
    )
    inspector = AdoptionIdentityInspector(
        StaticFileIdentityProvider({location: file}),
        StaticSignerVerifier({location: signer}),
        StaticDependencyProvenanceProvider({location: dependencies}),
    )
    try:
        inspector.inspect(location)
    except AdoptionIdentityError:
        pass
    else:
        raise AssertionError("reparse target must fail closed")


def test_signer_status_is_not_forged_from_candidate_metadata() -> None:
    candidate, policy = adoption_candidate(signer_status=SignerStatus.UNSIGNED)
    assert candidate.identity_evidence is not None
    assert (
        policy.evaluate(
            candidate.identity_evidence,
            compatible=True,
            read_only=True,
            user_confirmed=False,
        )
        is AdoptionOutcome.REQUIRES_USER_CONFIRMATION
    )


def test_unsigned_local_tool_can_be_adopted_only_with_restricted_confirmation() -> None:
    candidate, policy = adoption_candidate(signer_status=SignerStatus.UNSIGNED)
    assert candidate.identity_evidence is not None
    assert (
        policy.evaluate(
            candidate.identity_evidence,
            compatible=True,
            read_only=True,
            user_confirmed=True,
        )
        is AdoptionOutcome.ADOPT_WITH_RESTRICTIONS
    )


def test_missing_provenance_requires_confirmation_and_privileged_use_is_not_implicit() -> None:
    candidate, policy = adoption_candidate(provenance_available=False, issue_attestation=False)
    assert candidate.identity_evidence is not None
    assert (
        policy.evaluate(
            candidate.identity_evidence,
            compatible=True,
            read_only=True,
            user_confirmed=False,
        )
        is AdoptionOutcome.REQUIRES_USER_CONFIRMATION
    )
    assert (
        policy.evaluate(
            candidate.identity_evidence,
            compatible=True,
            read_only=False,
            user_confirmed=True,
            requires_privilege=True,
        )
        is AdoptionOutcome.REJECTED
    )


def test_stale_evidence_requires_revalidation() -> None:
    candidate, policy = adoption_candidate()
    assert candidate.identity_evidence is not None
    stale = candidate.identity_evidence.captured_at + timedelta(minutes=11)
    assert (
        policy.evaluate(
            candidate.identity_evidence,
            compatible=True,
            read_only=True,
            user_confirmed=False,
            now=stale,
        )
        is AdoptionOutcome.REQUIRES_REVALIDATION
    )


def test_dependency_provenance_change_changes_attestation_binding() -> None:
    first, _ = adoption_candidate(seed="dependency-one")
    second, _ = adoption_candidate(seed="dependency-two")
    assert first.adoption_attestation is not None and second.adoption_attestation is not None
    assert (
        first.adoption_attestation.dependency_fingerprint
        != second.adoption_attestation.dependency_fingerprint
    )


@pytest.mark.windows_integration
def test_real_windows_identity_is_opt_in_and_observation_only() -> None:
    if os.name != "nt" or os.environ.get("JARVIS_RUN_WINDOWS_IDENTITY_TESTS") != "1":
        pytest.skip("set JARVIS_RUN_WINDOWS_IDENTITY_TESTS=1 for the local Windows identity check")
    from jarvis.adoption import WindowsFileIdentityProvider, WindowsSignerVerifier

    identity = WindowsFileIdentityProvider().inspect(sys.executable)
    signer = WindowsSignerVerifier().verify(sys.executable)
    assert identity.file_id
    assert len(identity.content_hash) == 64
    assert signer.status in set(SignerStatus)


def test_file_identity_and_provenance_providers_use_bounded_local_evidence(
    tmp_path: Path,
) -> None:
    target = tmp_path / "fixture.bin"
    target.write_bytes(b"synthetic-adoption")
    identity = WindowsFileIdentityProvider().inspect(str(target))
    assert identity.content_hash == sha256(b"synthetic-adoption").hexdigest()
    assert identity.file_id
    signer = WindowsSignerVerifier().verify(str(target))
    assert signer.status in set(SignerStatus)

    (tmp_path / "install.lock").write_text("fixture==1", encoding="utf-8")
    provenance = LocalDependencyProvenanceProvider().inspect(str(target))
    assert provenance.available
    assert provenance.independent


def test_attestation_round_trip_and_malformed_persisted_data_are_fail_closed() -> None:
    candidate, _ = adoption_candidate()
    assert candidate.adoption_attestation is not None
    restored = type(candidate.adoption_attestation).from_dict(
        candidate.adoption_attestation.to_dict()
    )
    assert restored.fingerprint == candidate.adoption_attestation.fingerprint
    with pytest.raises(AdoptionValidationError):
        type(candidate.adoption_attestation).from_dict({"policy_outcome": "invalid"})


def test_policy_rejects_forged_evidence_and_incompatible_or_privileged_requests() -> None:
    candidate, policy = adoption_candidate()
    assert candidate.identity_evidence is not None
    forged = type(candidate.identity_evidence)(
        candidate.identity_evidence.file,
        candidate.identity_evidence.signer,
        candidate.identity_evidence.dependencies,
        candidate.identity_evidence.captured_at,
    )
    assert (
        policy.evaluate(forged, compatible=True, read_only=True, user_confirmed=True)
        is AdoptionOutcome.REJECTED
    )
    assert (
        policy.evaluate(
            candidate.identity_evidence, compatible=False, read_only=True, user_confirmed=False
        )
        is AdoptionOutcome.INCOMPATIBLE
    )
    assert (
        policy.evaluate(
            candidate.identity_evidence,
            compatible=True,
            read_only=False,
            user_confirmed=False,
            requires_privilege=True,
        )
        is AdoptionOutcome.REQUIRES_USER_CONFIRMATION
    )
    assert (
        policy.evaluate(
            candidate.identity_evidence,
            compatible=True,
            read_only=False,
            user_confirmed=True,
            requires_privilege=True,
        )
        is AdoptionOutcome.ADOPT_WITH_RESTRICTIONS
    )


def test_adoption_metadata_validation_rejects_secret_and_invalid_shapes() -> None:
    import jarvis.adoption as adoption

    with pytest.raises(AdoptionValidationError):
        adoption._safe_mapping(None)
    with pytest.raises(AdoptionValidationError):
        adoption._safe_mapping({"token": "not-stored"})
    with pytest.raises(AdoptionValidationError):
        adoption._safe_mapping({"value": object()})
    with pytest.raises(AdoptionValidationError):
        WindowsFileIdentityProvider(max_bytes=0)
    with pytest.raises(AdoptionValidationError):
        WindowsFileIdentity(
            "C:/fixture",
            -1,
            "id",
            1,
            "0" * 64,
            "file",
            False,
            datetime.now(UTC),
        )


def test_static_provider_missing_observations_fail_closed() -> None:
    with pytest.raises(AdoptionIdentityError):
        StaticFileIdentityProvider({}).inspect("missing")
    with pytest.raises(AdoptionIdentityError):
        StaticSignerVerifier({}).verify("missing")
    with pytest.raises(AdoptionIdentityError):
        StaticDependencyProvenanceProvider({}).inspect("missing")
