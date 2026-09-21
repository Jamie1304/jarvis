# Adaptive personalization

Adaptive personalization extends the existing `PersonaKernel` and `UserModel`
instead of creating a second user model or conversation store.

## Ownership and modes

`PersonaKernel` remains the explicit user-owned `PersonaProfile`. The
`HumanAdaptationService` stores bounded adaptive overlays, expression
aggregates, routine candidates, preferences, and inspectable history in the
versioned local `human-adaptation.sqlite3` store. Explicit persona updates are
also pinned in the adaptation layer, so inferred state cannot overwrite them.

Learning depth is typed: `OFF`, `EXPLICIT_ONLY`, `COMMUNICATION`, `CONTEXTUAL`,
and `DEEP`. `DEEP` is not the default. Adaptive JARVIS presentation is separate
from learning depth and is independently `FIXED` or `ADAPTIVE`.

Adaptive changes require repeated evidence, a confidence threshold, and a
cooldown. Each applied change is at most one bounded trait step per evidence
window. Changes record field, previous/new value, time, evidence class,
confidence, provenance, and correction state. Freeze, resume, pin, unpin,
reset-adaptations, reset-learning, and inspection are explicit APIs.

## Expression and communication

The local Expression Profile stores aggregates such as tone, length, directness,
greeting, closing, and relationship-scoped values. It stores no unlimited raw
message corpus. Style fidelity is controlled separately (`OFF` through
`MAXIMUM`) and rendering happens after semantic content is formed. The renderer
does not send messages or grant communication authority.

Relationship style is a bounded presentation scope. It can change greetings or
closing style for permitted contexts while preserving the semantic draft.
Cloud projection is limited to abstract values such as `tone`, `length`, and
`directness`; raw messages, typing history, mouse history, routine history,
relationship graphs, and complete profiles do not cross the boundary.

## Routines and behavior

Repeated safe patterns create `RoutineCandidate` suggestions only. A candidate
cannot register automation, approve an action, or bypass the PermissionBroker.
Behavioral aggregates are allowed only in `DEEP`, with explicit behavioral
learning and a bounded `JARVIS_ONLY` or `APP_SCOPED` observation setting.
`SYSTEM_WIDE` is represented as unavailable unless a trusted OS observer is
later supplied; it is never faked.

Secure input is a hard exclusion. Secure events are rejected before aggregate
storage, and raw typed content is not an event field. Behavioral resemblance
never creates `ActorContext`, `ApprovalIdentity`, or authority.

## Persistence and safety

The store has a version table, rejects future schemas, migrates idempotently,
and closes its connection if migration fails. Restart reconstructs language
preferences, personalization settings, adaptive pause/freeze state, expression
attributes, routine candidates, pins, and history. Resetting adaptations or
behavioral learning does not delete unrelated Memory or explicit PersonaKernel
records.

Safe Mode remains authoritative: normal runtime composition is unavailable, and
the safe current-context projection reports learning as paused. Personalization
does not affect PermissionBroker decisions, approval fingerprints, actor
identity, resource admission, verification, `UNKNOWN_OUTCOME`, CredentialVault,
generated capability trust, or recovery authority.

Physical system-wide observation, physical voice behavior, visual layout
qualification, and independent frozen acceptance remain reviewer/qualification
work, not claims of this development handoff.
