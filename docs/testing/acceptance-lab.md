# JARVIS Acceptance Lab

The lab exposes a typed `AcceptanceEnvironment` boundary. Run VM cases
against the existing WSL2 fabric with:

```text
python scripts/acceptance/run_acceptance.py --test 078 --real-vm
python scripts/acceptance/run_acceptance.py --test 043 --real-vm --fault
```

Workbench leases are serialized. Disposable leases are cloned from
`jarvis-workbench`, destroyed after the case, and followed by a Workbench
guest-readiness check. The harmless fault transaction records the provider,
instance, guest identity, injection/verification/cleanup exit codes, and
cleanup state. Export/import timeouts are failures; temporary archives are
removed in the adapter cleanup path.

## Native-sensitive qualification environment

Native-sensitive capability acquisition, certification, and activation
qualification runs use the direct-base Python 3.12 executable:
`C:\Users\jamie\AppData\Local\Programs\Python\Python312\python.exe`.
The repository `.venv` running inside the current agent Windows Job is a
differential/control environment only; it does not qualify AppContainer or
native Job behavior. This rule describes the qualification environment and
does not alter the shipped runtime or weaken its containment checks.

The randomized production capability regression is currently classified as an
`ENVIRONMENT_DEFECT`: all 22 preceding v1 acceptance tests pass, while the
capability path reaches `CertificationFailure` because Windows AppContainer
ACL restoration does not complete. Native cleanup is bounded and fails closed
instead of hanging the runner. The legacy v1 launcher was observed at the
same final test; no 600-second PASS run or run ID was produced, so the timeout
criterion remains unproven.

The canonical registry is `jarvis.acceptance.specs.SPECS`. It validates the
immutable IDs `001` through `115` exactly once and keeps specification version
separate from the committed Git identity. Run a selection with:

```text
python scripts/acceptance/run_acceptance.py --profile smoke
python scripts/acceptance/run_acceptance.py --tests 1-30
python scripts/acceptance/run_acceptance.py --profile security --tags phase-f
```

Each run writes a manifest, checkpoint, JSON report, and Markdown report under
the ignored `artifacts/acceptance/run-*` directory. The manifest records HEAD
and a deterministic mutable-worktree fingerprint, so a dirty Candidate-15
worktree is not misreported as Candidate 14.

Statuses are explicit: PASS, FAIL, BLOCKED_ENVIRONMENT, BLOCKED_FEATURE,
REAL_HARDWARE_REQUIRED, EXTERNAL_SERVICE_REQUIRED, HUMAN_JUDGMENT_REQUIRED,
LONG_RUNNING_PENDING, and UNKNOWN_OUTCOME. A model statement is never accepted
as evidence. Evidence envelopes carry a trust class; critical assertions must
be machine, broker, OS, VM, synthetic-fixture, external-service, or user
evidence.

VM-first tests declare `workbench_vm_or_disposable_test_vm`; host-only tests
declare native Windows or a clean Windows VM. The host-effect monitor stores
foreground/cursor/process observations and digests/change indicators, and
never stores clipboard contents. Real host
effects require the existing trusted bridge and permission path.

The fault foundation is in `jarvis.acceptance.faults`. Its initial faults use
synthetic disposable fixtures and follow prepare, baseline, inject, verify,
collect, cleanup, and cleanup verification. No persistent Workbench or host is
deliberately corrupted. R4R-E may use the typed transaction as an evaluator,
but repair reasoning is intentionally outside this package.
