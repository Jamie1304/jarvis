# ADR 0001: Phase 0 boundaries

## Decision

Use a single typed Python package with explicit top-level domain boundaries and a minimal FastAPI health-only entry point. Keep future providers behind interfaces and reserve tools plus a permission broker for host-affecting actions.

## Rationale

This gives later phases stable import boundaries and observable startup behavior without prematurely introducing agent behavior, cloud coupling, or privileged operations.
