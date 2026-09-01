# ADR 0006: Brokered granular permissions and trusted approvals

## Decision

Bind every registered tool instance to a `PermissionBroker`. After strict input
validation, trusted tool code derives an exact action descriptor and granular
scope. The broker applies explicit deny-by-default rules, hard-safety overrides,
and optional trusted-user approval before the private tool implementation runs.
Approval matching includes task, tool, permission, action, normalized scope, and a
canonical argument fingerprint. Decisions and execution outcomes are audited
without raw arguments.

## Rationale

A permission set supplied in execution context can be forged or widened by the
caller and cannot safely support approval replay protection. Central registration,
trusted descriptors, atomic one-time approval consumption, expiring exact-scope
grants, and canonical filesystem containment create one reviewable boundary.

## Consequences

Unknown tools, permissions, malformed scopes, and absent/disabled policy deny.
Privileged tools require policy and adversarial tests before use. Python remains an
in-process trust boundary rather than an operating-system sandbox, so registered
implementation code and policy configuration must be trusted and reviewed.
