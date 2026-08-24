from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from typing import cast

import pytest
from jarvis.improvement.donor_study import (
    DonorDecision,
    DonorFileReference,
    DonorLicenseEvidence,
    DonorStudy,
    DonorStudyError,
    DonorStudySecurityError,
    DonorStudyService,
    DonorStudyStage,
    NativeAdaptationProposal,
    NativeAdaptationStatus,
)
from jarvis.improvement.models import EvaluationDirection, Reversibility
from jarvis.permissions.models import Risk

NOW = datetime(2026, 8, 24, tzinfo=UTC)
REVISION = "a" * 40
FILE_DIGEST = sha256(b"source file at pinned revision").hexdigest()
LICENSE_DIGEST = sha256(b"LICENSE at pinned revision").hexdigest()


def study(
    *,
    stage: DonorStudyStage = DonorStudyStage.DISCOVERED,
    decision: DonorDecision = DonorDecision.REIMPLEMENT,
    port_reviewed: bool = False,
) -> DonorStudy:
    return DonorStudy(
        project="Example donor",
        authoritative_upstream="https://github.com/example/donor",
        revision=REVISION,
        files=(DonorFileReference("src/agent.py", FILE_DIGEST, "agent loop behavior"),),
        license=DonorLicenseEvidence(
            "MIT",
            "LICENSE",
            LICENSE_DIGEST,
            ("Copyright Example Project",),
        ),
        concept="Bounded operation loop with explicit tool results",
        comparison="JARVIS already has a durable planner and brokered tools",
        risk=Risk.HIGH,
        benefit="Reduce repeated discovery while preserving JARVIS ownership",
        decision=decision,
        destination="docs/native-donor-study.md",
        security_impact="No donor code or authority crosses into the trusted process",
        tests=("provenance validation", "security boundary regression"),
        benchmarks=("compare bounded loop latency against native baseline",),
        stage=stage,
        dependency_notes=("No dependency additions are authorized",),
        port_provenance_reviewed=port_reviewed,
    )


def ready_study(
    *,
    decision: DonorDecision = DonorDecision.REIMPLEMENT,
    port_reviewed: bool = False,
) -> DonorStudy:
    current = study(decision=decision, port_reviewed=port_reviewed)
    service = DonorStudyService()
    for stage in DonorStudyStage:
        if stage is DonorStudyStage.DISCOVERED:
            continue
        current = service.advance(current, stage)
    return current


def test_stage_workflow_requires_one_bounded_transition() -> None:
    service = DonorStudyService()
    current = study()
    current = service.advance(current, DonorStudyStage.UPSTREAM_VERIFIED)
    assert current.stage is DonorStudyStage.UPSTREAM_VERIFIED
    with pytest.raises(DonorStudyError, match="one bounded step"):
        service.advance(current, DonorStudyStage.LICENSE_INSPECTED)
    with pytest.raises(DonorStudyError, match="one bounded step"):
        service.advance(current, DonorStudyStage.UPSTREAM_VERIFIED)


def test_ready_study_creates_fingerprinted_review_only_proposal() -> None:
    service = DonorStudyService()
    current = study()
    for stage in DonorStudyStage:
        if stage is not DonorStudyStage.DISCOVERED:
            current = service.advance(current, stage)
    proposal = service.create_proposal(
        current,
        proposal_id="native-adaptation-example",
        created_at=NOW,
    )
    assert isinstance(proposal, NativeAdaptationProposal)
    assert proposal.project == "Example donor"
    assert proposal.revision == REVISION
    assert proposal.files[0].path == "src/agent.py"
    assert proposal.status is NativeAdaptationStatus.REVIEW_REQUIRED
    assert len(proposal.proposal_fingerprint) == 64
    assert not hasattr(proposal, "import_source")
    assert not hasattr(proposal, "install_dependency")


def test_proposal_can_only_handoff_to_existing_improvement_pipeline() -> None:
    proposal = NativeAdaptationProposal.from_study(
        ready_study(), proposal_id="native-adaptation-example", created_at=NOW
    )
    signal = proposal.to_improvement_signal(
        metric="verified_reuse",
        baseline_value=0,
        target_delta=1,
        direction=EvaluationDirection.INCREASE,
        reversibility=Reversibility.FULL,
        impact=70,
        confidence=80,
        implementation_cost=30,
        user_relevance=60,
    )
    assert signal.source.value == "donor_study"
    assert signal.source_reference == f"donor:{proposal.proposal_fingerprint}"
    assert signal.external_content is None
    assert signal.affected_component == proposal.destination


def test_study_before_all_provenance_stages_cannot_produce_proposal() -> None:
    with pytest.raises(DonorStudyError, match="complete all provenance stages"):
        NativeAdaptationProposal.from_study(
            study(), proposal_id="native-adaptation-example", created_at=NOW
        )


def test_directly_forged_ready_stage_is_not_service_authorized() -> None:
    with pytest.raises(DonorStudySecurityError, match="service-authorized"):
        DonorStudyService().create_proposal(
            study(stage=DonorStudyStage.PROPOSAL_READY),
            proposal_id="native-adaptation-example",
            created_at=NOW,
        )
    with pytest.raises(DonorStudyError, match="complete all provenance stages"):
        DonorStudyService().create_proposal(
            study(stage=DonorStudyStage.ASSESSED),
            proposal_id="native-adaptation-example",
            created_at=NOW,
        )


def test_port_requires_explicit_provenance_review_but_still_only_proposes() -> None:
    with pytest.raises(DonorStudySecurityError, match="PORT"):
        study(decision=DonorDecision.PORT)
    record = ready_study(decision=DonorDecision.PORT, port_reviewed=True)
    proposal = NativeAdaptationProposal.from_study(
        record, proposal_id="native-adaptation-port", created_at=NOW
    )
    assert proposal.decision is DonorDecision.PORT
    assert proposal.status is NativeAdaptationStatus.REVIEW_REQUIRED


def test_decision_alias_preserves_inspire_only_vocabulary() -> None:
    assert DonorDecision("inspire") is DonorDecision.INSPIRE
    assert DonorDecision.INSPIRE.value == "inspire"


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/example/donor",
        "https://github.com/example/donor?download=1",
        "https://user:password@github.com/example/donor",
    ],
)
def test_upstream_metadata_rejects_unsafe_or_incomplete_values(url: str) -> None:
    with pytest.raises(DonorStudySecurityError, match="HTTPS"):
        DonorStudy(
            "Example donor",
            url,
            REVISION,
            (DonorFileReference("src/agent.py", FILE_DIGEST, "agent loop"),),
            DonorLicenseEvidence("MIT", "LICENSE", LICENSE_DIGEST, ("Copyright",)),
            "Concept",
            "Comparison",
            Risk.HIGH,
            "Benefit",
            DonorDecision.REIMPLEMENT,
            "docs/design.md",
            "Security impact",
            ("test",),
            ("benchmark",),
        )


def test_exact_revision_and_source_paths_are_required() -> None:
    with pytest.raises(DonorStudyError, match="Revision"):
        replace(study(), revision="main")
    with pytest.raises(DonorStudySecurityError, match="repository-relative"):
        DonorFileReference("../agent.py", FILE_DIGEST, "agent")
    with pytest.raises(DonorStudySecurityError, match="repository-relative"):
        DonorFileReference(".git/config", FILE_DIGEST, "metadata")
    with pytest.raises(DonorStudyError, match="SHA-256"):
        DonorFileReference("src/agent.py", "BAD", "agent")


def test_license_notices_and_third_party_review_are_validated() -> None:
    with pytest.raises(DonorStudyError, match="Copyright notices"):
        DonorLicenseEvidence("MIT", "LICENSE", LICENSE_DIGEST, ())
    with pytest.raises(DonorStudyError, match="Third-party"):
        DonorLicenseEvidence(
            "MIT",
            "LICENSE",
            LICENSE_DIGEST,
            ("Copyright",),
            cast(bool, 1),
        )
    with pytest.raises(DonorStudyError, match="License identifier"):
        DonorLicenseEvidence("", "LICENSE", LICENSE_DIGEST, ("Copyright",))


def test_study_rejects_duplicate_files_missing_evidence_and_unsafe_destination() -> None:
    file_ref = DonorFileReference("src/agent.py", FILE_DIGEST, "agent")
    with pytest.raises(DonorStudyError, match="unique"):
        replace(study(), files=(file_ref, file_ref))
    with pytest.raises(DonorStudyError, match="non-empty"):
        replace(study(), tests=())
    with pytest.raises(DonorStudySecurityError, match="repository-relative"):
        replace(study(), destination="../jarvis/runtime.py")


def test_proposal_fingerprint_rejects_tampering_and_non_review_status() -> None:
    proposal = NativeAdaptationProposal.from_study(
        ready_study(), proposal_id="native-adaptation-example", created_at=NOW
    )
    with pytest.raises(DonorStudySecurityError, match="fingerprint"):
        replace(proposal, benefit="changed benefit")
    with pytest.raises(DonorStudySecurityError, match="review-only"):
        replace(proposal, status=cast(NativeAdaptationStatus, "approved"))
    with pytest.raises(DonorStudyError, match="timestamp"):
        NativeAdaptationProposal.from_study(
            ready_study(), proposal_id="proposal", created_at=datetime(2026, 1, 1)
        )


def test_dependency_notes_are_metadata_only() -> None:
    proposal = NativeAdaptationProposal.from_study(
        ready_study(), proposal_id="native-adaptation-example", created_at=NOW
    )
    assert proposal.dependency_notes == ("No dependency additions are authorized",)
    assert not hasattr(DonorStudyService(), "install")
