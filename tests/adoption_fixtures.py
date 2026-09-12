"""Synthetic trusted adoption evidence for local tests only."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from jarvis.adoption import (
    AdoptionIdentityInspector,
    AdoptionPolicy,
    DependencyEvidence,
    DependencyProvenance,
    EvidenceAuthority,
    EvidenceConfidence,
    SignerEvidence,
    SignerStatus,
    StaticDependencyProvenanceProvider,
    StaticFileIdentityProvider,
    StaticSignerVerifier,
    WindowsFileIdentity,
)
from jarvis.setup_conductor import AdoptionCandidate


def adoption_candidate(
    candidate_id: str = "local",
    *,
    location: str = "C:/synthetic-existing.exe",
    seed: str = "local",
    version: str = "1.0",
    signer_status: SignerStatus = SignerStatus.VALID_TRUSTED_SIGNATURE,
    provenance_available: bool = True,
    compatible: bool = True,
    issue_attestation: bool = True,
) -> tuple[AdoptionCandidate, AdoptionPolicy]:
    content_hash = hashlib.sha256(f"content:{seed}".encode()).hexdigest()
    receipt_hash = hashlib.sha256(f"receipt:{seed}".encode()).hexdigest()
    file = WindowsFileIdentity(
        location,
        1,
        f"file-{seed}",
        len(seed),
        content_hash,
        "executable",
        False,
        datetime.now(UTC),
    )
    dependency = DependencyEvidence(
        f"dependency-{seed}",
        "synthetic-receipt",
        f"receipt://{seed}",
        receipt_hash,
        EvidenceAuthority.PACKAGE_RECEIPT,
        EvidenceConfidence.HIGH,
    )
    provenance = DependencyProvenance(
        "synthetic-receipt",
        EvidenceAuthority.PACKAGE_RECEIPT,
        EvidenceConfidence.HIGH,
        (dependency,) if provenance_available else (),
        provenance_available,
    )
    signer = SignerEvidence(signer_status, verifier="synthetic-verifier")
    inspector = AdoptionIdentityInspector(
        StaticFileIdentityProvider({location: file}),
        StaticSignerVerifier({location: signer}),
        StaticDependencyProvenanceProvider({location: provenance}),
    )
    policy = AdoptionPolicy(inspector)
    evidence = inspector.inspect(location)
    attestation = (
        policy.attest(
            candidate_id,
            evidence,
            version=version,
            compatibility_fingerprint=hashlib.sha256(b"synthetic-compatible").hexdigest(),
            workspace_scope="synthetic-workspace",
            setup_run_id="synthetic-setup",
            acquisition_id="synthetic-acquisition",
            compatible=compatible,
            read_only=True,
            user_confirmed=signer_status is not SignerStatus.VALID_TRUSTED_SIGNATURE,
        )
        if issue_attestation
        else None
    )
    return (
        AdoptionCandidate(
            candidate_id,
            "synthetic-runtime",
            location,
            version,
            compatible,
            True,
            True,
            "trusted synthetic evidence",
            evidence.fingerprint,
            evidence,
            attestation,
        ),
        policy,
    )
