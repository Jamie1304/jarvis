# Capability Opportunity Engine

**Status:** v1 production composition
**Updated:** 2026-08-24

`CapabilityOpportunityEngine` is the production-owned queue for proactive
capability preparation. It records a possible recurring need; it is not a task
engine, planner, permission authority, capability registry, package store, or
activation service.

The boundary is deliberately one-way:

```text
observed evidence -> durable opportunity -> safe preparation -> proposal
                                                   |
                                   user decision/normal policy
                                                   v
                              CapabilityAcquisitionCoordinator
```

## Durable owner

`SQLiteOpportunityStore` in `opportunities.sqlite3` is the only authoritative
owner of opportunity evidence, lifecycle state, decision, cooldown/expiry, and
preparation metadata. The in-memory engine and UI/AttentionPolicy views are
projections. SQLite uses WAL, foreign keys, a bounded busy timeout, optimistic
revisions, and a versioned schema that refuses future or unknown migration
identities.

The composition root creates one store and one
`CapabilityOpportunityEngine`. Restart reloads the same records, including a
declined opportunity's cooldown and an interrupted safe-preparation state.

## Evidence threshold

Evidence is typed metadata, not an instruction channel. Accepted sources are
repeated workflows, GUI fallback, repeated failures, environment discovery,
User Model preferences, capability health, technology intelligence, and
ProcedureLearner observations. References and summaries are bounded and raw
credential markers are rejected.

The default policy requires at least two sufficiently confident observations
(`0.65` or higher) and either repeated evidence from one source or evidence
from at least two source types. A single weak observation therefore cannot
create an opportunity. Deployments may use a stricter policy, but the engine
does not accept a policy that lowers the minimum below two observations.

Evidence raises a proposal for a semantic need in a workspace; it does not
prove ownership, user intent, safety, compatibility, or permission.

## Lifecycle

The durable status vocabulary is:

`DETECTED`, `ASSESSING`, `PREPARING`, `READY_TO_PROPOSE`, `PROPOSED`,
`ACCEPTED`, `DECLINED`, `EXPIRED`, `ACTIVATING`, `ACTIVE`, `FAILED`, and
`ARCHIVED`.

Preparation progress is separately recorded as `NOT_STARTED`, `RESEARCHING`,
`DESIGNING`, `BUILDING`, `SANDBOX_TESTING`, `AUDITING`, `CERTIFYING`, `READY`,
`WAITING_FOR_AUTHORITY`, `FAILED`, `SECURITY_BLOCKED`, or `UNKNOWN_OUTCOME`.

### State validity and failure reconciliation

`READY_TO_PROPOSE` and `PROPOSED` are proposal-ready statuses only when the
preparation state is exactly `READY`. `FAILED`, `SECURITY_BLOCKED`,
`UNKNOWN_OUTCOME`, and waiting/in-progress preparation are never proposal-ready.
The same predicate is rechecked by both `proposal()` and `accept()` against the
current durable record, so a proposal cannot become authority after the
opportunity has degraded.

An acquisition exception or preparation-provider exception is recorded as
`FAILED` with preparation state `FAILED`, while retaining the opportunity's
evidence and diagnostic error. It is
not returned to `READY_TO_PROPOSE`. Durable stores validate new writes and
reconcile legacy inconsistent rows on read: failed rows become `FAILED`,
security-blocked rows become `ARCHIVED`, unknown outcomes become `ASSESSING`,
and other waiting/incomplete rows become `PREPARING`. Reconciliation never
interprets failure or uncertainty as successful preparation.

## Autonomous preparation

When the configured preparation provider allows it, the engine may perform
bounded, non-authoritative preparation such as read-only environment discovery,
research, design, static review, sandbox testing, and certification evidence
collection. The default composition provider delegates only read-only research
and discovery to `CapabilityAcquisitionCoordinator.research`.

Preparation must not:

- log in or use personal credentials;
- access sensitive personal systems;
- install privileged software or modify protected user data;
- execute an external effect on behalf of the opportunity;
- grant a permission, create an approval, self-certify, self-promote, or activate
  a package.

Preparation results are untrusted reports until the normal owner services
validate them. A preparation result that claims activation is rejected.

## User handoff and acceptance

`proposal()` produces one concise typed proposal containing the expected
benefit, what was prepared, remaining authority, privacy impact, and resource
cost. The proposal is data for the application/AttentionPolicy layer; it is
not a standing approval.

Declining records `DECLINED` and a cooldown. Repeated observations during the
cooldown do not nag the user. New evidence after the cooldown may reopen the
same semantic opportunity, while preserving its evidence lineage.

Acceptance requires a typed `CapabilityAcquisitionRequest` and delegates to the
existing `CapabilityAcquisitionCoordinator`. The opportunity engine has no
PermissionBroker, credential, package activation, or direct effect API. The
coordinator continues through discover/adopt/reuse/build, review, sandbox,
certification, setup/provisioning, PermissionBroker, Shadow/Canary, and
VerificationEngine. A non-active result remains `ACTIVATING` and
`WAITING_FOR_AUTHORITY`; it is not converted to active by the opportunity
engine.

## Separation of truth

| Concern | Owner | Opportunity relationship |
|---|---|---|
| Original user outcome and task execution | `GoalSupervisorStore` / `PlanningEngine` | Evidence may reference a need; it cannot create a task or replace its plan. |
| Capability metadata | `CapabilityRegistry` | Used for discovery/reuse; opportunity state cannot register a capability. |
| Package certification and activation | lifecycle store and trusted activation services | Preparation may collect evidence; only trusted services decide certification/activation. |
| Permission and credentials | `PermissionBroker` / `CredentialVault` | Opportunity state stores authority descriptions and opaque references only; it cannot grant or resolve secrets. |
| User notification/attention | `AttentionPolicy` when connected | Receives a proposal projection; it cannot approve or activate. |
| Outcome verification | `VerificationEngine` | Acquisition evidence is not proof of external success. |

This preserves the adaptive-core rule: a normal new capability is acquired by
the generic pipeline, without adding a service-specific branch to core.
