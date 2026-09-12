# Generic Control Center

`ControlCenterService` is a read-only application projection. It refreshes
explicitly registered sources and exposes current metadata for:

`system`, `capabilities`, `integrations`, `tools`, `skills`, `agents`,
`models`, `permissions`, `memory`, `knowledge`, `goals`, `automations`,
`audit`, `health`, and `recovery`. The desktop shell's Settings surface is
represented by non-secret settings metadata under `system`.

The projection has no durable domain authority. Capability and tool execution
remain owned by their registries and application services; planning remains
owned by `PlanningEngine`; permissions remain owned by `PermissionBroker`;
memory, knowledge, audit, recovery, and artifacts retain their existing stores.
Refresh failures are isolated and reported as degraded metadata. An absent
production scheduler is explicitly `NOT_AVAILABLE`; it is never presented as a
working automation service.

## Dynamic controls and voice

Sources return `ControlCenterItem` values with `SemanticActionMetadata`. This
is semantic action metadata, not a fixed product command tree. The metadata
names the application operation and parameters; desktop and voice adapters must
call application services, and privileged operations still pass through
`Tool -> PermissionBroker -> Policy -> approval`.

`JarvisAssistantService.refresh_semantic_actions()` is the common discovery
surface for both channels. Model text cannot register an action, create a
control, or grant permission.

## Output mediums

`OutputMediumProfile` controls presentation only:

- `DESKTOP` may retain Markdown and tables;
- `VOICE` uses short, speakable text without raw Markdown;
- `NOTIFICATION`, `PRESENTATION`, and `COMPACT` provide bounded channel
  formatting.

Changing a medium cannot change facts, goal semantics, authority, or policy.

## Trusted permission UX

`TrustedPermissionSurface` accepts only a broker-created `ApprovalRequest` or
trusted `PermissionRequest` plus its trusted `ActionDescriptor`. It creates one
immutable `TrustedPermissionPresentation` and derives both views from it:

- desktop: trusted short narration, impact, scope, exact details, `Allow once`,
  and `Deny`;
- voice: `TrustedActionNarrator` plus `ExactOperationRenderer`, with the fixed
  `YES / NO / DETAILS` choices.

The UI labels are presentation controls, not approval tokens. Only the trusted
approval context and broker decide path can authorize an operation. Model-
generated narration or model text that resembles a button is not accepted as a
trusted input.
