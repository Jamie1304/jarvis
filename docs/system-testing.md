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
rejected. The default process adapter uses `asyncio.create_subprocess_exec`, standard
input is disconnected, output is capped, and cancellation/timeout terminates the
child process.

The child receives a minimal bootstrap environment rather than the user's credential
environment. Artifacts are written only beneath an application-owned root and redact
recognizable credential assignments and token formats before persistence. Raw logs
remain artifacts; `TestFailureDiagnoser` uses only structured run metadata and evidence
codes, so an advisory diagnosis cannot replace or modify raw evidence.

## Categories and hardware policy

The model supports unit, integration, tools, permissions, API, UI, voice, agent
workflow, regression, startup, shutdown, and health categories. Hardware-dependent
UI/voice/camera/desktop suites carry `hardware_dependent=True` and are skipped unless
trusted composition explicitly enables them. They never run in the deterministic CI
path.

The current trusted catalog includes deterministic fake-provider workflow and
permission suites plus a separately gated Windows hardware/manual suite. CI invokes
the deterministic workflow suite through `scripts/run_system_tests.py` after the full
quality gate.

## Workflow and regression evaluation

`DeterministicWorkflowEvaluator` uses fake planners/tools or the safe calculator tool
to cover calculator success, permission pause before execution, bounded replan/retry,
cancellation, verification failure, and a Phase 15 meeting-preparation DAG. The
meeting scenario runs independent calendar and notes nodes before a dependent focus
node through broker-bound fake tools. It does not contact an AI provider, send a
message, access hardware, or use a privileged computer tool.

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
.venv\Scripts\python.exe scripts\run_system_tests.py --suite deterministic-workflows
.venv\Scripts\python.exe scripts\run_system_tests.py --suite deterministic-permissions
```

Artifacts are stored below ignored `build/system-test-artifacts/`. The hardware/manual
suite reports `skipped` until a future trusted manual harness explicitly enables it.
System-test records are suitable input for the Phase 11 improvement evaluator, but a
passing suite is evidence only; it never authorizes merge, deployment, software
installation, or production mutation.
