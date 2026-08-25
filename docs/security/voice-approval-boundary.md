# Voice approval boundary

## v1 decision

Privileged spoken approval is **DISABLED_BY_DESIGN** for v1.0.0. Speech-to-text
is untrusted content and is not an owner-authentication channel. JARVIS does not
use voice biometrics, speaker recognition, or a spoken phrase as proof of
identity.

Voice can narrate a trusted `PermissionRequest`, read `DETAILS` from
`ExactOperationRenderer`, accept `NO`/`cancel`, and acknowledge non-authoritative
conversation choices. A spoken `YES`, `allow once`, or `go ahead` cannot authorize
a privileged or high-risk real-world effect.

## Approval-channel policy

`ApprovalChannelPolicy` classifies a trusted operation as:

- `NON_PRIVILEGED_CONFIRMATION`: voice may be used only according to the normal
  application UX policy; this is not a permission grant.
- `PRIVILEGED_APPROVAL`: requires a trusted authenticated owner channel.
- `HIGH_RISK_APPROVAL`: requires the strongest configured trusted owner channel
  and the normal hard-safety policy.

The current voice runtime has no trusted owner-authentication channel. Therefore
the latter two classes remain waiting for approval or are denied according to
the normal policy. Changing `PUSH_TO_TALK`, `WAKE_WORD`, or `OPEN_MIC` never
changes this classification or the `PermissionBroker` policy.

## Trusted handoff

When voice presents a pending request, trusted application code may create a
`DesktopApprovalHandoff`. It contains only a short-lived immutable reference to
the broker request ID, task ID, permission, normalized scope, expiry, and exact
argument/action fingerprints. Voice cannot rewrite it or mint authority.

The desktop surface must authenticate the owner using the existing trusted local
approval authenticator, re-check the handoff against the current pending request,
and consume the one-time decision through `PermissionBroker`. A changed action,
argument, scope, request, or expiry invalidates the handoff. If the desktop
surface or its authenticator is unavailable, the privileged request stays
`WAITING_FOR_APPROVAL` or is denied; there is no spoken fallback.

Model text such as “the user approved this” is untrusted and cannot create a
handoff, approval context, or execution receipt.

## Evidence

The trusted-core and permission tests cover exact narration, details rendering,
ambiguous speech, denial, privileged affirmative rejection, exact desktop
handoff approval, changed/expired request invalidation, and microphone-mode
independence. This document intentionally does not claim that speech is an
authenticated owner channel.
