# ADR 0007: Controlled brokered Windows computer capabilities

## Decision

Expose Windows interaction only as typed, explicitly registered brokered tools
backed by a platform-neutral `ComputerAdapter`. Prefer semantic application/window
and accessibility operations. Keep coordinate input as a separately named fallback.
Use `computer.input` for focus, text entry, and fallback mouse input, while retaining
separate granular permissions for capture, clipboard, launch, filesystem, and
terminal operations.

Terminal execution resolves trusted command IDs to fixed executable definitions and
uses an argument vector with `shell=False`; filesystem execution consumes the
canonical path from the broker authorization receipt. Screenshot bytes stay in a
trusted store and results return opaque references plus metadata.

## Rationale

Passing raw Win32/UI Automation handles, executable paths, shell strings, or binary
screen data to a model would make authority difficult to audit and constrain. A
semantic contract allows policies and approvals to describe the exact action while
isolating Windows-specific dependencies and enabling deterministic adapter mocks.

## Consequences

Production composition must explicitly supply trusted catalogues and register the
tools. Optional real desktop integration requires a dedicated Windows environment;
the normal CI suite validates the contracts with mocks and cannot demonstrate a UI
interaction.
