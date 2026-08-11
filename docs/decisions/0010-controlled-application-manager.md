# ADR 0010: controlled application manager

## Decision

Use distinct inventory, package-provider, plan-store, and managed-runtime boundaries.
Package installation/update requires a single-use immutable plan and the hard
`software_installation` safety class, which forces fresh trusted-user approval.

## Rationale

Search results, registry data, and model text cannot safely be interpreted as OS
commands. Separating plan creation from execution binds approval to an exact package
identity/source/version and permits independent post-operation verification. A runtime
owned-process table makes generic process termination unavailable to the model.

## Consequences

Application management is explicit composition only; no default catalog exposes it.
There is no generic configuration capability and no autonomous install/update. The
optional winget provider has a trusted candidate catalog and uses argument vectors;
other repositories require a new reviewed provider implementation.
