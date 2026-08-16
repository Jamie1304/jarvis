"""Deny-by-default permission broker public API."""

from jarvis.permissions.approval import (
    ApprovalContextVerifier,
    TrustedApprovalAuthenticator,
    TrustedApprovalContext,
)
from jarvis.permissions.audit import AuditSink, AuditStoreError, InMemoryAuditSink, SQLiteAuditSink
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ActionDescriptor,
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    ApprovalRequest,
    ApprovalSource,
    ApprovalStatus,
    AuditRecord,
    AuthorizationReceipt,
    Decision,
    DecisionReason,
    Permission,
    PermissionRequest,
    PermissionScope,
    PolicyRule,
    Risk,
    SafeArgument,
    SafetyClass,
    ScopeConstraint,
)
from jarvis.permissions.policy import PolicyEngine, normalize_path, path_is_within

__all__ = [
    "ActionDescriptor",
    "ApprovalActorKind",
    "ApprovalChoice",
    "ApprovalContextVerifier",
    "ApprovalIdentity",
    "ApprovalRequest",
    "ApprovalSource",
    "ApprovalStatus",
    "AuditSink",
    "AuditStoreError",
    "AuditRecord",
    "AuthorizationReceipt",
    "Decision",
    "DecisionReason",
    "InMemoryAuditSink",
    "SQLiteAuditSink",
    "Permission",
    "PermissionBroker",
    "PermissionRequest",
    "PermissionScope",
    "PolicyEngine",
    "PolicyRule",
    "Risk",
    "SafeArgument",
    "SafetyClass",
    "ScopeConstraint",
    "TrustedApprovalAuthenticator",
    "TrustedApprovalContext",
    "normalize_path",
    "path_is_within",
]
