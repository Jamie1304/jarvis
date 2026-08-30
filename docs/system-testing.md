# System-level self-testing

Phase 13 adds a controlled system-test layer above ordinary unit tests. It answers
whether a candidate revision is healthy using structured evidence; it is not a
general-purpose command or deployment service.

## Execution boundary

`trusted suite catalog -> ControlledTestRunner -> explicit executable + argv ->
scoped working directory -> no-shell subprocess -> redacted artifacts -> TestRun ->
optional diagnosis`

`TestSuiteCatalog` is trusted application configuration. A caller selects only a
known suite ID; it cannot supply a shell string, executable, arguments, working
directory, environment, or hardware permission. Unknown suites and path escapes are
rejected. The adapter resolves the catalogued executable identity, uses no shell,
disconnects standard input, and continuously drains stdout/stderr into bounded
tails. A run can pass only when exit state, cleanup state, and the expected output
format agree. Pytest-text suites require a pytest session header and a terminal
pytest summary; arbitrary body text such as `999 passed` is malformed evidence.
Structured-JSON suites require a valid `results` array, and an exit-zero process
cannot pass when any individual result is `FAILED` or `UNKNOWN`; that
contradiction is malformed evidence rather than a green aggregate result.

On Windows the trusted runner creates the catalogued root suspended, assigns it to
an owned Job Object before resume, and uses kill-on-close process-tree cleanup.
It also keeps a bounded creation-time-bound ledger of descendants observed while
that root is live, validates their native parent edge, and treats any required
cleanup failure as non-pass evidence. It never uses a process-name-wide kill,
mutable `PATH`, or mutable `SystemRoot` to target cleanup. This is lifecycle
containment for trusted repository tests, not generated-code isolation. On other
platforms it owns a new process group. Timeout/cancellation has precedence over a
simultaneous nominal completion, and cleanup failure prevents a nominal pass.

The child receives a minimal bootstrap environment rather than the user's credential
environment. Only an exact parent-selected `JARVIS_ENVIRONMENT=test` crosses this
boundary for deterministic suites; arbitrary `JARVIS_*` values, credentials, and
ambient `PATH` values do not. Artifacts are written only beneath an
application-owned root and redact recognizable credential assignments and token
formats before persistence. `TestFailureDiagnoser` uses only structured run metadata
and evidence codes, so an advisory diagnosis cannot replace or modify evidence.
On Windows the runner also creates a compact owned `TEMP`/`TMP` root and rejects
an unusually deep root before a nested pytest fixture could cross the legacy path
boundary; this is a controlled launch failure, never a false product regression.

## Categories and hardware policy

The model supports unit, integration, tools, permissions, API, UI, voice, agent
workflow, regression, startup, shutdown, and health categories. Hardware-dependent
UI/voice/camera/desktop suites carry `hardware_dependent=True` and are skipped unless
trusted composition explicitly enables them. They never run in the deterministic CI
path.

The current trusted catalog includes deterministic fake-provider workflow and
permission suites plus a separately gated Windows hardware/manual suite. CI sets
`JARVIS_ENVIRONMENT=test` for the full synthetic quality gate and the deterministic
catalogue suites. The artifact-only package smoke deliberately creates a separate
production-mode runtime and does not inherit that test selector.

## Workflow and regression evaluation

`DeterministicWorkflowEvaluator` uses fake planners/tools or the safe calculator tool
to cover calculator success, permission pause before execution, bounded replan/retry,
cancellation, verification failure, and a Phase 15 meeting-preparation DAG. The
meeting scenario runs independent calendar and notes nodes before a dependent focus
node through broker-bound fake tools. It does not contact an AI provider, send a
message, access hardware, or use a privileged computer tool.

The `multi-agent-comparison` scenario additionally runs the same deterministic brief
objective through the disabled single-agent path and an enabled three-node delegated
DAG. It records both elapsed times and equal abstract resource cost. The fixture
demonstrates critical-path parallelism, not provider quality or production speed.

Previously fixed behavior is represented by JSON records in
`tests/fixtures/regressions/`. A fixture identifies its suite and deterministic
scenario, expected passing status, and optional issue reference. It is evidence for a
regression test, not executable instructions.

## Startup smoke tests

`StartupSmokeTester` is optional. Trusted composition must supply an explicit
localhost-only command and health URL. It launches an isolated process, waits for
`/health` readiness, records the process/startup/health/shutdown checks, and requests
clean termination. The CI suite uses a fake process/probe; no real server smoke test
is claimed by default. `create_local_startup_smoke_definition(port)` provides the
fixed `uvicorn jarvis.api:app` command for an explicit manual smoke harness. Manual
execution should use a disposable environment and an unused loopback port.

## Local use

Run a trusted deterministic suite and emit one JSON `TestRun` record:

```powershell
$env:JARVIS_ENVIRONMENT = "test"
.venv\Scripts\python.exe scripts\quality.py
.venv\Scripts\python.exe scripts\run_system_tests.py --suite deterministic-workflows
.venv\Scripts\python.exe scripts\run_system_tests.py --suite deterministic-permissions
Remove-Item Env:JARVIS_ENVIRONMENT
.venv\Scripts\python.exe scripts\package_smoke.py
```

Artifacts are stored below ignored `build/system-test-artifacts/`. The hardware/manual
suite reports `skipped` until a future trusted manual harness explicitly enables it.
System-test records are suitable input for the Phase 11 improvement evaluator, but a
passing suite is evidence only; it never authorizes merge, deployment, software
installation, or production mutation.
