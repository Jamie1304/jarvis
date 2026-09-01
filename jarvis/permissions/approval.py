"""Opaque, instance-bound contexts for trusted approval ingress.

The authenticator is a capability owned by trusted application composition.  The
broker receives only its verifier, so planners and tools cannot mint approval
contexts through the authorization boundary they use for execution.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from jarvis.permissions.models import (
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    ApprovalSource,
    DecisionReason,
)

type Clock = Callable[[], datetime]

_TRUSTED_SOURCES = frozenset(
    {
        ApprovalSource.TRUSTED_UI,
        ApprovalSource.TRUSTED_LOCAL_API,
    }
)
_MAX_CONTEXT_TTL_SECONDS = 300


@dataclass(frozen=True, slots=True)
class TrustedApprovalContext:
    """A short-lived bearer capability for one exact approval decision.

    The proof is deliberately excluded from representations.  Constructing or
    copying this class does not create authority: only the verifier paired with
    the issuing authenticator can validate and consume its proof.
    """

    context_id: UUID
    authenticator_id: UUID
    request_id: UUID
    choice: ApprovalChoice
    identity: ApprovalIdentity
    source: ApprovalSource
    remember_for_seconds: int | None
    issued_at: datetime
    expires_at: datetime
    _proof: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class ApprovalContextVerification:
    """Result returned by a trusted verifier without exposing signing state."""

    accepted: bool
    reason: DecisionReason
    context: TrustedApprovalContext | None = None


class ApprovalContextVerifier(Protocol):
    """Consume exactly one context issued by a paired trusted authenticator."""

    def verify_and_consume(self, context: object) -> ApprovalContextVerification: ...


@dataclass(slots=True)
class _ApprovalAuthority:
    authority_id: UUID
    secret: bytes = field(repr=False)
    source: ApprovalSource
    context_ttl_seconds: int
    clock: Clock
    issued_context_expiries: dict[UUID, datetime] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


class TrustedApprovalAuthenticator:
    """Mint approval contexts after a trusted channel authenticates a user.

    Possession of this object is authority.  It must be retained only by trusted
    UI/local ingress composition and must never be injected into a planner, tool,
    integration, event, or model-facing context.
    """

    def __init__(
        self,
        source: ApprovalSource,
        *,
        context_ttl_seconds: int = 60,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(source, ApprovalSource) or source not in _TRUSTED_SOURCES:
            raise ValueError("Approval authenticator requires a trusted local source")
        if (
            isinstance(context_ttl_seconds, bool)
            or not isinstance(context_ttl_seconds, int)
            or context_ttl_seconds <= 0
            or context_ttl_seconds > _MAX_CONTEXT_TTL_SECONDS
        ):
            raise ValueError("Approval context lifetime must be between 1 and 300 seconds")
        self._authority = _ApprovalAuthority(
            authority_id=uuid4(),
            secret=secrets.token_bytes(32),
            source=source,
            context_ttl_seconds=context_ttl_seconds,
            clock=clock or (lambda: datetime.now(UTC)),
        )

    def verifier(self) -> ApprovalContextVerifier:
        """Return a verifier that deliberately has no context-minting method."""

        return _TrustedApprovalVerifier(self._authority)

    def issue_context(
        self,
        *,
        request_id: UUID,
        choice: ApprovalChoice,
        identity: ApprovalIdentity,
        remember_for_seconds: int | None = None,
    ) -> TrustedApprovalContext:
        """Issue one exact, short-lived decision after channel authentication."""

        if not isinstance(request_id, UUID) or not isinstance(choice, ApprovalChoice):
            raise ValueError("Approval context requires a typed request and decision")
        if (
            not isinstance(identity, ApprovalIdentity)
            or identity.kind is not ApprovalActorKind.TRUSTED_USER
        ):
            raise ValueError("Approval context requires an authenticated trusted user")
        try:
            verified_identity = ApprovalIdentity(identity.identity_id, identity.kind)
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError("Approval context requires an authenticated trusted user") from error
        if choice is ApprovalChoice.APPROVE_LIMITED:
            if (
                remember_for_seconds is None
                or isinstance(remember_for_seconds, bool)
                or remember_for_seconds <= 0
            ):
                raise ValueError("Limited approval requires a positive remembered duration")
        elif remember_for_seconds is not None:
            raise ValueError("Remembered duration is valid only for limited approval")

        now = _aware_now(self._authority.clock, "Approval authenticator")
        context = TrustedApprovalContext(
            context_id=uuid4(),
            authenticator_id=self._authority.authority_id,
            request_id=request_id,
            choice=choice,
            identity=verified_identity,
            source=self._authority.source,
            remember_for_seconds=remember_for_seconds,
            issued_at=now,
            expires_at=now + timedelta(seconds=self._authority.context_ttl_seconds),
            _proof=b"",
        )
        signed = TrustedApprovalContext(
            context_id=context.context_id,
            authenticator_id=context.authenticator_id,
            request_id=context.request_id,
            choice=context.choice,
            identity=context.identity,
            source=context.source,
            remember_for_seconds=context.remember_for_seconds,
            issued_at=context.issued_at,
            expires_at=context.expires_at,
            _proof=_sign(self._authority.secret, context),
        )
        with self._authority.lock:
            # An issued-context ledger makes replay resistance independent of
            # wall-clock rollback: consumption removes authority permanently.
            self._authority.issued_context_expiries = {
                context_id: expiry
                for context_id, expiry in self._authority.issued_context_expiries.items()
                if expiry > now
            }
            self._authority.issued_context_expiries[signed.context_id] = signed.expires_at
        return signed


class _TrustedApprovalVerifier:
    """Verification-only view of one authenticator's private authority state."""

    def __init__(self, authority: _ApprovalAuthority) -> None:
        self._authority = authority

    def verify_and_consume(self, context: object) -> ApprovalContextVerification:
        try:
            well_formed = isinstance(context, TrustedApprovalContext) and _is_well_formed(context)
        except (AttributeError, OverflowError, TypeError, ValueError):
            well_formed = False
        if not well_formed:
            return ApprovalContextVerification(
                False,
                DecisionReason.MALFORMED_APPROVAL_DECISION,
            )
        assert isinstance(context, TrustedApprovalContext)
        if context.authenticator_id != self._authority.authority_id:
            return ApprovalContextVerification(False, DecisionReason.UNTRUSTED_APPROVER)
        try:
            proof_matches = hmac.compare_digest(
                context._proof,
                _sign(self._authority.secret, context),
            )
        except (AttributeError, OverflowError, TypeError, ValueError):
            proof_matches = False
        if not proof_matches:
            return ApprovalContextVerification(False, DecisionReason.UNTRUSTED_APPROVER)

        now = _aware_now(self._authority.clock, "Approval context verifier")
        with self._authority.lock:
            issued_expiry = self._authority.issued_context_expiries.pop(
                context.context_id,
                None,
            )
            if issued_expiry is None:
                return ApprovalContextVerification(False, DecisionReason.APPROVAL_CONSUMED)
            if issued_expiry != context.expires_at:
                return ApprovalContextVerification(False, DecisionReason.UNTRUSTED_APPROVER)
            if context.expires_at <= now:
                return ApprovalContextVerification(False, DecisionReason.APPROVAL_EXPIRED)
        return ApprovalContextVerification(True, DecisionReason.APPROVAL_APPROVED, context)


class DenyAllApprovalContextVerifier:
    """Fail-closed verifier used when no trusted approval channel is configured."""

    def verify_and_consume(self, context: object) -> ApprovalContextVerification:
        reason = (
            DecisionReason.MALFORMED_APPROVAL_DECISION
            if not isinstance(context, TrustedApprovalContext)
            else DecisionReason.UNTRUSTED_APPROVER
        )
        return ApprovalContextVerification(False, reason)


def _is_well_formed(context: TrustedApprovalContext) -> bool:
    remember_for_seconds = context.remember_for_seconds
    return (
        isinstance(context.context_id, UUID)
        and isinstance(context.authenticator_id, UUID)
        and isinstance(context.request_id, UUID)
        and isinstance(context.choice, ApprovalChoice)
        and isinstance(context.identity, ApprovalIdentity)
        and isinstance(context.identity.identity_id, str)
        and bool(context.identity.identity_id)
        and context.identity.kind is ApprovalActorKind.TRUSTED_USER
        and isinstance(context.source, ApprovalSource)
        and context.source in _TRUSTED_SOURCES
        and (
            context.choice is ApprovalChoice.APPROVE_LIMITED
            and isinstance(remember_for_seconds, int)
            and not isinstance(remember_for_seconds, bool)
            and remember_for_seconds > 0
            or context.choice is not ApprovalChoice.APPROVE_LIMITED
            and remember_for_seconds is None
        )
        and isinstance(context.issued_at, datetime)
        and context.issued_at.tzinfo is not None
        and isinstance(context.expires_at, datetime)
        and context.expires_at.tzinfo is not None
        and context.expires_at > context.issued_at
        and context.expires_at - context.issued_at <= timedelta(seconds=_MAX_CONTEXT_TTL_SECONDS)
        and isinstance(context._proof, bytes)
        and len(context._proof) == hashlib.sha256().digest_size
    )


def _sign(secret: bytes, context: TrustedApprovalContext) -> bytes:
    payload = json.dumps(
        {
            "authenticator_id": str(context.authenticator_id),
            "choice": context.choice.value,
            "context_id": str(context.context_id),
            "expires_at": context.expires_at.astimezone(UTC).isoformat(),
            "identity_id": context.identity.identity_id,
            "identity_kind": context.identity.kind.value,
            "issued_at": context.issued_at.astimezone(UTC).isoformat(),
            "remember_for_seconds": context.remember_for_seconds,
            "request_id": str(context.request_id),
            "source": context.source.value,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).digest()


def _aware_now(clock: Clock, owner: str) -> datetime:
    value = clock()
    if value.tzinfo is None:
        raise ValueError(f"{owner} clock must return timezone-aware timestamps")
    return value.astimezone(UTC)
