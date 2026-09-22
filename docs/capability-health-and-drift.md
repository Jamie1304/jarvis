# Capability health and behavior drift

JARVIS keeps capability health and certified behavior separate from capability
execution, planning, permission, and package certification. The native
`CapabilityHealthService` is a bounded monitor and repair coordinator. It does
not execute tools, resolve credentials, grant approval, certify a package, or
promote an integration.

## Health

Health reports support five states:

- `HEALTHY`
- `DEGRADED`
- `UNAVAILABLE`
- `QUARANTINED`
- `UNKNOWN`

Checks are explicitly typed as passive, read-only, functional, dependency, or
version/API compatibility checks. Dependency nodes describe generic
integration, library, software, service, model, API, MCP, and configuration
relationships. A missing dependency can make a capability unavailable;
incompatibility is reported separately from a functional failure.

Health reports are observations. They are emitted through the typed EventBus,
recorded in the human-readable execution trace, and exposed to the Control
Center. Attention notices are derived notifications and cannot change policy or
authority.

## Certified behavior baseline

The certifier supplies one immutable `BehaviorBaseline` for each certified
capability version. It records the expected:

- network hosts and filesystem roots;
- broker calls and credential scopes;
- subprocess policy;
- bounded request volume/window;
- event subscriptions and emissions; and
- persistence operations.

The baseline has an exact content fingerprint. `CapabilityHealthService` rejects
model output, untrusted external/event content, generated-package writes, and
same-version replacement attempts. A new certified version receives a new
baseline through the normal trusted certification path. Health observations can
never rewrite the certified record.

Trusted broker observations are the authority-sensitive evidence source. An
observation marked untrusted, or one that does not come from the trusted broker
boundary, is rejected for drift evaluation rather than allowed to change
activation state.

## Drift and response

The comparison reports `EXPECTED`, `LOW_RISK_DRIFT`, `MATERIAL_DRIFT`, or
`SECURITY_DRIFT`. New hosts/roots, broker calls, or event behavior are material
by default. New credential scopes, processes, privileged requests, and
unexpected persistence are security drift. Request volume has a certified
window and a bounded low-risk band before it becomes material.

For an active capability, response is monotonic:

`ACTIVE -> DEGRADED -> QUARANTINED`

Security drift can quarantine immediately. A quarantined or rolled-back version
is never silently restored by a later healthy observation. Material drift may
require re-certification and activation authority even after a repair retest
passes.

The health view reflects this lifecycle gate: a degraded activation is exposed
as `DEGRADED`, and a quarantined activation as `QUARANTINED`, even if its last
functional probe was healthy. A later probe cannot clear that gate.

## Repair lifecycle

Repair is a typed application-owned boundary:

`DETECT -> EVIDENCE -> DIAGNOSE -> SAFE_REPAIR -> RETEST -> REBUILD_OR_REPLACE -> AUTHORITY`

Only a composition-owned `RepairProvider` can implement a safe repair, rebuild,
replacement, or retest. The provider must use normal typed capabilities,
PermissionBroker policy, and audit boundaries. No arbitrary shell hook exists in
the health monitor. Missing or denied authority produces an explicit
`AUTHORITY_REQUIRED` result without attempting an effect. A healthy rebuild does
not self-certify or self-promote the resulting package.

## Ownership and limitations

`CapabilityHealthService` owns transient health reports, observations, findings,
attention notices, and repair results. The authoritative-state map remains the
source of truth for all durable domains. Certified behavior belongs to package
certification; lifecycle transitions belong to package activation; broker
observations come from the trusted PermissionBroker path; trace and EventBus
records are projections.

The service does not claim that passive telemetry proves an external effect. A
missing observation is `UNKNOWN`, and any physical or external result still
requires the existing VerificationEngine and evidence contracts. Windows path,
reparse-point, process, network, and device guarantees remain those of the
trusted broker and their native providers; this monitor only compares the
bounded observations they provide.
