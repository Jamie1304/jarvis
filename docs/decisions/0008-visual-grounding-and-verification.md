# ADR 0008: Provider-neutral visual grounding with post-action verification

## Decision

Implement visual desktop interaction as an application service above the Phase 6
brokered computer tools. It obtains observations through registered `screen.read`
tools, uses an injected provider-neutral vision contract, fuses accessibility data
before visual suggestions, and maps only a current target ID to existing brokered
semantic actions or the explicit coordinate fallback. It re-observes before action
and verifies using a new observation afterward.

## Rationale

Computer input without grounded freshness checks risks acting on a changed window or
incorrectly scaled screen. Treating vision output as an authorization signal would
allow model/provider hallucination or prompt injection to bypass the permission broker.
Normalized geometry, screenshot-content fingerprints, semantic-first fusion, and
explicit verification create inspectable evidence without coupling core logic to a
single model or Windows library.

## Consequences

Visual success takes at least two observations and does not mean the underlying tool
result alone. Providers remain pluggable but require trusted composition. Actual
desktop execution stays opt-in; deterministic CI uses static fixtures and mocks.
