"""Provenance-first study of external projects for native JARVIS adaptation.

This module accepts bounded study metadata only.  It deliberately has no
repository downloader, source importer, package installer, subprocess adapter,
or dependency mutator.  A ready proposal can only be handed to the existing
proposal-and-test improvement pipeline as an unexecuted improvement signal.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from jarvis.improvement.analysis import ObservedImprovementSignal
from jarvis.improvement.models import (
    EvaluationDirection,
    ImprovementSource,
    Reversibility,
)
from jarvis.permissions.models import Risk


class DonorStudyError(ValueError):
    """A donor record is incomplete or violates the study contract."""


class DonorStudySecurityError(DonorStudyError):
    """A donor record attempts uncontrolled import, authority, or dependency use."""


class DonorStudyStage(StrEnum):
    DISCOVERED = "discovered"
    UPSTREAM_VERIFIED = "upstream_verified"
    REVISION_PINNED = "revision_pinned"
    LICENSE_INSPECTED = "license_inspected"
    CONCEPT_ANALYZED = "concept_analyzed"
    COMPARED = "compared"
    ASSESSED = "assessed"
    PROPOSAL_READY = "proposal_ready"


class DonorDecision(StrEnum):
    PORT = "port"
    REIMPLEMENT = "reimplement"
    INSPIRE = "inspire"
    INSPIRE_ONLY = "inspire"
    REJECT = "reject"


class NativeAdaptationStatus(StrEnum):
    REVIEW_REQUIRED = "review_required"


_STAGES = tuple(DonorStudyStage)
_MAX_ITEMS = 64


def _text(value: object, name: str, maximum: int = 2_000) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
        or any(character in value for character in ("\x00", "\r", "\n"))
    ):
        raise DonorStudyError(f"{name} must be bounded single-line text")
    return value


def _label(value: object, name: str, maximum: int = 128) -> str:
    value = _text(value, name, maximum)
    if not all(character.isalnum() or character in "._- /" for character in value):
        raise DonorStudyError(f"{name} contains unsupported characters")
    return value


def _labels(values: Iterable[str], name: str, maximum: int = _MAX_ITEMS) -> tuple[str, ...]:
    result = tuple(_text(value, name, 512) for value in values)
    if not result or len(result) > maximum or len(set(result)) != len(result):
        raise DonorStudyError(f"{name} must be non-empty and unique")
    return result


def _sha256(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value.casefold() != value
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DonorStudyError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _revision(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) not in {40, 64}
        or value.casefold() != value
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DonorStudyError("Revision must be an exact lowercase immutable Git object ID")
    return value


def _relative_path(value: object, name: str) -> str:
    value = _text(value, name, 512)
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or normalized != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
        or ":" in value
        or any(part.casefold() == ".git" for part in path.parts)
    ):
        raise DonorStudySecurityError(f"{name} must be a safe repository-relative path")
    return normalized


def _upstream_url(value: object) -> str:
    value = _text(value, "Authoritative upstream URL", 512)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path in {"", "/"}
    ):
        raise DonorStudySecurityError("Authoritative upstream must be a canonical HTTPS URL")
    return value.rstrip("/")


def _time(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DonorStudyError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class DonorFileReference:
    """A reviewed source-file reference; source contents never enter JARVIS."""

    path: str
    sha256: str
    useful_for: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _relative_path(self.path, "Donor source file"))
        object.__setattr__(self, "sha256", _sha256(self.sha256, "Donor source file digest"))
        object.__setattr__(self, "useful_for", _text(self.useful_for, "Donor file purpose", 1_000))


@dataclass(frozen=True, slots=True)
class DonorLicenseEvidence:
    """License and notice metadata inspected at the pinned upstream revision."""

    identifier: str
    source_file: str
    license_sha256: str
    copyright_notices: tuple[str, ...]
    third_party_reviewed: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "identifier", _label(self.identifier, "License identifier", 128))
        object.__setattr__(
            self,
            "source_file",
            _relative_path(self.source_file, "License source file"),
        )
        object.__setattr__(
            self,
            "license_sha256",
            _sha256(self.license_sha256, "License digest"),
        )
        object.__setattr__(
            self,
            "copyright_notices",
            _labels(self.copyright_notices, "Copyright notices", 32),
        )
        if type(self.third_party_reviewed) is not bool:
            raise DonorStudyError("Third-party license review flag is malformed")


@dataclass(frozen=True, slots=True)
class DonorStudy:
    """Bounded evidence collected through the donor-study workflow."""

    project: str
    authoritative_upstream: str
    revision: str
    files: tuple[DonorFileReference, ...]
    license: DonorLicenseEvidence
    concept: str
    comparison: str
    risk: Risk
    benefit: str
    decision: DonorDecision
    destination: str
    security_impact: str
    tests: tuple[str, ...]
    benchmarks: tuple[str, ...]
    stage: DonorStudyStage = DonorStudyStage.DISCOVERED
    dependency_notes: tuple[str, ...] = ()
    port_provenance_reviewed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "project", _label(self.project, "Donor project", 256))
        object.__setattr__(
            self,
            "authoritative_upstream",
            _upstream_url(self.authoritative_upstream),
        )
        object.__setattr__(self, "revision", _revision(self.revision))
        if (
            not self.files
            or len(self.files) > _MAX_ITEMS
            or any(not isinstance(item, DonorFileReference) for item in self.files)
        ):
            raise DonorStudyError("Donor study files are malformed")
        paths = tuple(item.path.casefold() for item in self.files)
        if len(paths) != len(set(paths)):
            raise DonorStudyError("Donor study files must be unique")
        if not isinstance(self.license, DonorLicenseEvidence):
            raise DonorStudyError("Donor license evidence is malformed")
        object.__setattr__(self, "concept", _text(self.concept, "Donor concept"))
        object.__setattr__(self, "comparison", _text(self.comparison, "JARVIS comparison"))
        if not isinstance(self.risk, Risk):
            raise DonorStudyError("Donor risk must be a known risk class")
        object.__setattr__(self, "benefit", _text(self.benefit, "Donor benefit"))
        if not isinstance(self.decision, DonorDecision):
            raise DonorStudyError("Donor decision must be known")
        object.__setattr__(
            self, "destination", _relative_path(self.destination, "JARVIS destination")
        )
        object.__setattr__(
            self,
            "security_impact",
            _text(self.security_impact, "Security impact"),
        )
        object.__setattr__(self, "tests", _labels(self.tests, "Donor tests"))
        object.__setattr__(self, "benchmarks", _labels(self.benchmarks, "Donor benchmarks"))
        if not isinstance(self.stage, DonorStudyStage):
            raise DonorStudyError("Donor study stage must be known")
        object.__setattr__(self, "dependency_notes", _labels_or_empty(self.dependency_notes))
        if type(self.port_provenance_reviewed) is not bool:
            raise DonorStudyError("PORT provenance review flag is malformed")
        if self.decision is DonorDecision.PORT and not self.port_provenance_reviewed:
            raise DonorStudySecurityError("PORT requires explicit provenance and notice review")


@dataclass(frozen=True, slots=True)
class NativeAdaptationProposal:
    """Review-only native adaptation proposal, fingerprinted over all evidence."""

    proposal_id: str
    project: str
    authoritative_upstream: str
    revision: str
    files: tuple[DonorFileReference, ...]
    license: DonorLicenseEvidence
    concept: str
    comparison: str
    risk: Risk
    benefit: str
    decision: DonorDecision
    destination: str
    security_impact: str
    tests: tuple[str, ...]
    benchmarks: tuple[str, ...]
    dependency_notes: tuple[str, ...]
    created_at: datetime
    proposal_fingerprint: str
    status: NativeAdaptationStatus = NativeAdaptationStatus.REVIEW_REQUIRED

    @classmethod
    def from_study(
        cls,
        study: DonorStudy,
        *,
        proposal_id: str,
        created_at: datetime,
    ) -> NativeAdaptationProposal:
        if study.stage is not DonorStudyStage.PROPOSAL_READY:
            raise DonorStudyError("Donor study must complete all provenance stages")
        created_at = _time(created_at, "Proposal timestamp")
        normalized_id = _label(proposal_id, "Native adaptation proposal ID", 256)
        values = {
            "proposal_id": normalized_id,
            "project": study.project,
            "authoritative_upstream": study.authoritative_upstream,
            "revision": study.revision,
            "files": study.files,
            "license": study.license,
            "concept": study.concept,
            "comparison": study.comparison,
            "risk": study.risk,
            "benefit": study.benefit,
            "decision": study.decision,
            "destination": study.destination,
            "security_impact": study.security_impact,
            "tests": study.tests,
            "benchmarks": study.benchmarks,
            "dependency_notes": study.dependency_notes,
            "created_at": created_at,
            "status": NativeAdaptationStatus.REVIEW_REQUIRED,
        }
        return cls(
            proposal_id=normalized_id,
            project=study.project,
            authoritative_upstream=study.authoritative_upstream,
            revision=study.revision,
            files=study.files,
            license=study.license,
            concept=study.concept,
            comparison=study.comparison,
            risk=study.risk,
            benefit=study.benefit,
            decision=study.decision,
            destination=study.destination,
            security_impact=study.security_impact,
            tests=study.tests,
            benchmarks=study.benchmarks,
            dependency_notes=study.dependency_notes,
            created_at=created_at,
            proposal_fingerprint=_fingerprint(values),
            status=NativeAdaptationStatus.REVIEW_REQUIRED,
        )

    def __post_init__(self) -> None:
        object.__setattr__(self, "proposal_id", _label(self.proposal_id, "Proposal ID", 256))
        object.__setattr__(self, "project", _label(self.project, "Donor project", 256))
        object.__setattr__(
            self, "authoritative_upstream", _upstream_url(self.authoritative_upstream)
        )
        object.__setattr__(self, "revision", _revision(self.revision))
        if not self.files or any(not isinstance(item, DonorFileReference) for item in self.files):
            raise DonorStudyError("Proposal source files are malformed")
        if not isinstance(self.license, DonorLicenseEvidence):
            raise DonorStudyError("Proposal license evidence is malformed")
        object.__setattr__(self, "concept", _text(self.concept, "Donor concept"))
        object.__setattr__(self, "comparison", _text(self.comparison, "JARVIS comparison"))
        if not isinstance(self.risk, Risk) or not isinstance(self.decision, DonorDecision):
            raise DonorStudyError("Proposal risk or decision is malformed")
        object.__setattr__(self, "benefit", _text(self.benefit, "Donor benefit"))
        object.__setattr__(
            self, "destination", _relative_path(self.destination, "JARVIS destination")
        )
        object.__setattr__(self, "security_impact", _text(self.security_impact, "Security impact"))
        object.__setattr__(self, "tests", _labels(self.tests, "Donor tests"))
        object.__setattr__(self, "benchmarks", _labels(self.benchmarks, "Donor benchmarks"))
        object.__setattr__(self, "dependency_notes", _labels_or_empty(self.dependency_notes))
        object.__setattr__(self, "created_at", _time(self.created_at, "Proposal timestamp"))
        if self.status is not NativeAdaptationStatus.REVIEW_REQUIRED:
            raise DonorStudySecurityError("Native adaptation proposals remain review-only")
        expected = _fingerprint(self._fingerprint_values())
        if _sha256(self.proposal_fingerprint, "Proposal fingerprint") != expected:
            raise DonorStudySecurityError("Native adaptation proposal fingerprint mismatch")

    def _fingerprint_values(self) -> dict[str, object]:
        return {
            "proposal_id": self.proposal_id,
            "project": self.project,
            "authoritative_upstream": self.authoritative_upstream,
            "revision": self.revision,
            "files": self.files,
            "license": self.license,
            "concept": self.concept,
            "comparison": self.comparison,
            "risk": self.risk,
            "benefit": self.benefit,
            "decision": self.decision,
            "destination": self.destination,
            "security_impact": self.security_impact,
            "tests": self.tests,
            "benchmarks": self.benchmarks,
            "dependency_notes": self.dependency_notes,
            "created_at": self.created_at,
            "status": self.status,
        }

    def to_improvement_signal(
        self,
        *,
        metric: str,
        baseline_value: float,
        target_delta: float,
        direction: EvaluationDirection,
        reversibility: Reversibility,
        impact: int,
        confidence: int,
        implementation_cost: int,
        user_relevance: int,
    ) -> ObservedImprovementSignal:
        """Create an unexecuted signal for the existing ImprovementEngine only."""

        return ObservedImprovementSignal(
            signal_code=f"donor-{self.proposal_fingerprint[:16]}",
            source=ImprovementSource.DONOR_STUDY,
            source_reference=f"donor:{self.proposal_fingerprint}",
            trusted_summary="Evaluate a native adaptation proposal from reviewed donor evidence",
            occurrence_count=1,
            affected_component=self.destination,
            expected_benefit=self.benefit,
            metric=metric,
            baseline_value=baseline_value,
            target_delta=target_delta,
            direction=direction,
            declared_risk=self.risk,
            reversibility=reversibility,
            impact=impact,
            confidence=confidence,
            implementation_cost=implementation_cost,
            user_relevance=user_relevance,
        )


class DonorStudyService:
    """Advance metadata through provenance stages and emit review-only proposals."""

    def __init__(self) -> None:
        self._authorized_studies: set[str] = set()

    def advance(self, study: DonorStudy, stage: DonorStudyStage) -> DonorStudy:
        if not isinstance(study, DonorStudy) or not isinstance(stage, DonorStudyStage):
            raise DonorStudyError("Donor study transition is malformed")
        current = _STAGES.index(study.stage)
        target = _STAGES.index(stage)
        if target != current + 1:
            raise DonorStudyError("Donor study stages must advance one bounded step at a time")
        next_study = replace(study, stage=stage)
        self._authorized_studies.add(_study_key(next_study))
        return next_study

    def create_proposal(
        self,
        study: DonorStudy,
        *,
        proposal_id: str,
        created_at: datetime,
    ) -> NativeAdaptationProposal:
        if not isinstance(study, DonorStudy):
            raise DonorStudyError("Donor study is malformed")
        if study.stage is not DonorStudyStage.PROPOSAL_READY:
            raise DonorStudyError("Donor study must complete all provenance stages")
        if _study_key(study) not in self._authorized_studies:
            raise DonorStudySecurityError(
                "Proposal requires service-authorized provenance transitions"
            )
        return NativeAdaptationProposal.from_study(
            study,
            proposal_id=proposal_id,
            created_at=created_at,
        )

    propose = create_proposal


def _labels_or_empty(values: Iterable[str]) -> tuple[str, ...]:
    values = tuple(values)
    if not values:
        return ()
    return _labels(values, "Dependency notes")


def _study_key(study: DonorStudy) -> str:
    return _fingerprint(
        {
            "project": study.project,
            "authoritative_upstream": study.authoritative_upstream,
            "revision": study.revision,
            "files": study.files,
            "license": study.license,
            "concept": study.concept,
            "comparison": study.comparison,
            "risk": study.risk,
            "benefit": study.benefit,
            "decision": study.decision,
            "destination": study.destination,
            "security_impact": study.security_impact,
            "tests": study.tests,
            "benchmarks": study.benchmarks,
            "stage": study.stage,
            "dependency_notes": study.dependency_notes,
            "port_provenance_reviewed": study.port_provenance_reviewed,
        }
    )


def _fingerprint(values: dict[str, object]) -> str:
    def canonical(value: object) -> object:
        if isinstance(value, DonorDecision | DonorStudyStage | NativeAdaptationStatus | Risk):
            return value.value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, DonorFileReference):
            return {"path": value.path, "sha256": value.sha256, "useful_for": value.useful_for}
        if isinstance(value, DonorLicenseEvidence):
            return {
                "identifier": value.identifier,
                "source_file": value.source_file,
                "license_sha256": value.license_sha256,
                "copyright_notices": value.copyright_notices,
                "third_party_reviewed": value.third_party_reviewed,
            }
        if isinstance(value, tuple):
            return [canonical(item) for item in value]
        if isinstance(value, dict):
            return {key: canonical(item) for key, item in value.items()}
        return value

    encoded = json.dumps(canonical(values), sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


__all__ = [
    "DonorDecision",
    "DonorFileReference",
    "DonorLicenseEvidence",
    "DonorStudy",
    "DonorStudyError",
    "DonorStudySecurityError",
    "DonorStudyService",
    "DonorStudyStage",
    "NativeAdaptationProposal",
    "NativeAdaptationStatus",
]
