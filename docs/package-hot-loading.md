# Certified Package Hot-Loading

Hot-loading is an application-owned lifecycle around the validated
`IntegrationPackage` contract. It is not an integration catalog or a second
execution engine.

```text
package change
  -> validate exact package/version/hash/provenance
  -> prepare sandbox runtime
  -> health check
  -> atomic registration swap
  -> capability/tool/skill/profile/UI/event projection refresh
  -> drain old runtime
```

`HotLoadManager` supports a watcher abstraction and explicit manual refresh.
The watcher only reports changes; it cannot activate a package by itself.
Every new version must provide fresh certification, permission-diff approval,
Shadow evidence, and Canary evidence. A new version never inherits ACTIVE
status, approvals, identity, or runtime state implicitly.

Failed preparation or health leaves the old runtime active. A failed atomic
swap invokes an idempotent rollback surface and drains the prepared runtime.
After a successful swap, the old runtime is drained before the new record is
published as active. Invocation and swapping are serialized by the manager so
an active call cannot race old-runtime drain.

Restart prepares the same certified version again and transfers only the
runtime’s explicit external state snapshot. It does not transfer approvals,
credentials, or authority. Removal and stale cleanup remove registrations and
drain runtimes; they do not delete user configuration or package data.

The registration surface is responsible for refreshing capability, tool,
Skill, profile, UI, and event projections atomically with registration. Those
projections remain derived metadata and cannot become execution or permission
authorities.
