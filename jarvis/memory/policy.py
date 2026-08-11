"""Trusted privacy policy for deciding what may enter durable user memory."""

from __future__ import annotations

import re

from jarvis.memory.models import (
    LongTermEligibility,
    LongTermMemoryCandidate,
    MemorySource,
    RetentionDecision,
    Sensitivity,
)

_SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_-]{12,}\b", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b", re.IGNORECASE),
    re.compile(r"\b(?:api[_ -]?key|password|secret|token)\s*[:=]\s*\S+", re.IGNORECASE),
)


def contains_secret(value: str) -> bool:
    """Conservatively identify credentials that must use a dedicated secret store."""

    return any(pattern.search(value) is not None for pattern in _SECRET_PATTERNS)


class LongTermRetentionPolicy:
    """Deny by default; durable user facts require a meaningful, confirmed candidate."""

    def evaluate(self, candidate: LongTermMemoryCandidate) -> LongTermEligibility:
        if candidate.sensitivity is Sensitivity.SECRET or contains_secret(
            candidate.content + "\n" + candidate.data
        ):
            return LongTermEligibility(RetentionDecision.DENY, "secret_content", candidate)
        if candidate.provenance.untrusted_content:
            return LongTermEligibility(RetentionDecision.DENY, "untrusted_source", candidate)
        if candidate.provenance.source is not MemorySource.USER:
            return LongTermEligibility(RetentionDecision.DENY, "non_user_source", candidate)
        if not candidate.user_confirmed:
            return LongTermEligibility(
                RetentionDecision.DENY, "user_confirmation_required", candidate
            )
        if candidate.confidence < 0.5:
            return LongTermEligibility(RetentionDecision.DENY, "insufficient_confidence", candidate)
        return LongTermEligibility(RetentionDecision.ALLOW, "eligible_user_memory", candidate)
