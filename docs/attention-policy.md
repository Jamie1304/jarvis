# AttentionPolicy

**Status:** v1 production composition
**Updated:** 2026-08-24

`AttentionPolicy` is the durable owner of interruption, defer, bundling, and
duplicate-collapse decisions. It is deliberately separate from both delivery
and authority:

```text
trusted application fact -> AttentionPolicy -> AttentionQueueEntry
                                             |
                                  NotificationTransport delivery
```

`NotificationTransport` may render or deliver a queue entry, but it cannot
change the decision or authorize an operation. `PermissionPolicy` and
`PermissionBroker` remain the only authority path. An attention item can point
at a Goal, PermissionRequest, or capability opportunity; the reference never
grants standing authority.

## Durable ownership

`SQLiteAttentionStore` in `attention.sqlite3` is the sole authoritative store
for `AttentionItem`, `AttentionQueueEntry`, `DigestBucket`, and
`AttentionPolicyState`. It uses WAL, foreign keys, a bounded SQLite busy
timeout, an explicit schema version, and future-schema refusal. In-memory
policy views are projections and are rebuilt from the store after restart.

Unresolved items and their queue decisions survive restart. Malformed persisted
state fails closed instead of being interpreted as a delivery permission or a
silent suppression.

## Priorities and decisions

The priority order is:

`BACKGROUND`, `LOW`, `NORMAL`, `HIGH`, `URGENT`, `SECURITY_CRITICAL`.

The policy emits only these decisions:

- `DELIVER_NOW`
- `DEFER`
- `BUNDLE_IN_DIGEST`
- `SILENT_ACTIVITY`
- `SUPPRESS_DUPLICATE`

Delivery state and resolved state are stored independently from the decision.
Resolving an item is an explicit application action; delivery is not proof that
the related task, permission, or capability succeeded.

## Rules

- Low and normal items may defer during configured quiet hours. The defer time
  is persisted and is reevaluated after restart.
- Background and low informational activity may be placed in a durable digest
  bucket. Duplicate informational items with the same workspace and dedupe key
  collapse into `SUPPRESS_DUPLICATE`.
- High, urgent, and security-critical items are not quiet-hour-suppressed.
- `SECURITY_CRITICAL` items cannot be silently suppressed or manually deferred
  through the policy API.
- A user-action item whose authority request is near expiry is delivered now,
  including during quiet hours. An expired security/authority item remains
  unresolved and visible rather than being silently discarded.
- Capability opportunity cooldowns are represented by `cooldown_until` on the
  attention item. While the cooldown is active, the item is deferred; after it
  expires, reconciliation reevaluates it. This is a notification decision only
  and does not alter the opportunity's authoritative lifecycle.
- UserModel/application preferences may suppress background activity only.
  They cannot alter mandatory security visibility, permission state, or policy
  rules.

## Producers and transports

Producers such as capability health submit typed facts. The production runtime
maps health/drift severity to an `AttentionPriority` and persists the resulting
item. The existing transient `AttentionNotice` callback remains a compatibility
observation path; it is not authoritative.

No transport is embedded in this module. Desktop, voice, notification, and
future channels consume the same durable queue projection and must not recreate
priority logic or show model-authored approval controls. A transport failure
does not delete, resolve, or downgrade an attention item.

Attention is therefore not an interruption bypass: an urgent permission item
stays visible because it is unresolved, but the permission still requires the
normal trusted approval channel and exact broker fingerprint.
