# Fault-injection foundation

`FaultSpec` is the canonical representation of a fault. It has an immutable
ID, typed family, target environment/resource, precondition, injection and
cleanup contract, lifetime, risk, and evidence requirements. `FaultTransaction`
rejects host and persistent-Workbench targets and proves both fault presence
and baseline recovery. Cleanup failure is represented as an orphan and cannot
be silently treated as success.

The initial fixture set covers provider unavailable, guest/process failure,
missing dependency, invalid configuration, API schema mutation, API timeout,
generated-capability crash, controlled test failure, candidate health failure,
and revoked scoped permission. These fixtures are deterministic and safe; they
do not implement diagnosis, patch generation, promotion, or self-repair.
