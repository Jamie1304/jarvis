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
    re.compile(
        r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}"
        r"\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])"
    ),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(
        r"\bBearer[ \t]+"
        r"(?=[A-Za-z0-9\-._~+/=]{16,}(?![A-Za-z0-9\-._~+/=]))"
        r"(?=[A-Za-z0-9\-._~+/=]*[0-9])"
        r"[A-Za-z0-9][A-Za-z0-9\-._~+/]{15,}={0,2}"
        r"(?![A-Za-z0-9\-._~+/=])",
        re.IGNORECASE,
    ),
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(r"\b(?:api[_ -]?key|password|secret|token)\s*[:=]\s*\S+", re.IGNORECASE),
)


def contains_secret(value: str) -> bool:
    """Heuristically identify common credentials before durable persistence.

    This is a conservative defense-in-depth filter, not a complete DLP or secret
    classification system. Callers must continue to honor explicit sensitivity.
    """

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
