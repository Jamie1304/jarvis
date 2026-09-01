# Minimal Desktop Shell

The native desktop adapter renders one generic application shell. Its
navigation is limited to:

```text
Home | Tasks | Memory | Capabilities | Activity | Settings
```

These are presentation surfaces, not fixed product-integration pages. A
capability or package may project activity into the generic surfaces only after
its normal application-service, registry, permission, and lifecycle checks.

The PySide adapter calls `DesktopShellService` and `JarvisAssistantService`; it
does not import providers, tools, planners, stores, Vault objects, or broker
internals. Conversation, task control, permission state, verification,
notifications, health, Safe Mode, and model/capability activity remain
application-service data. UI code cannot bypass those services.

`LaunchProfile` choices are presentation/startup preferences:
`NORMAL`, `VOICE`, `FOCUS`, `PRIVACY`, `PRESENTATION`, `SAFE_MODE`, and
`DEVELOPER`. Selecting a profile preserves the security-policy version and
does not grant capabilities, alter permission policy, change goal semantics,
or create a second runtime constitution. Actual Safe Mode remains a trusted
runtime state.

The shell's generic surfaces may consume the refreshable Control Center
projection and semantic action metadata through `JarvisAssistantService`.
Channel formatting is selected with `OutputMediumProfile`; see
`docs/control-center.md`. No product-specific page or hard-coded voice command
tree is part of the shell.
