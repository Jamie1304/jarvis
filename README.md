# JARVIS

JARVIS is a local-first, Windows-first adaptive core. It is not an assistant
with a large collection of built-in integrations. It provides generic,
brokered primitives and grows capabilities through the reviewed path:

```text
DISCOVER -> ADOPT -> REUSE -> BUILD -> review -> sandbox -> certify -> activate
```

PlanningEngine owns durable task execution. Privileged effects remain behind
`Tool -> PermissionBroker -> Policy -> approval` when policy requires it.
Model, browser, document, package, event, and speech-recognition content are
untrusted data; none of them can create approval or authority.

JARVIS does not require Goose, Agent Zero, fullstack-agent, Backtalk,
ai-visualizer, ai-memory-vault, or barehands at runtime. They are
reference/provenance material only. See the
[donor provenance map](docs/reference/donor-provenance-map.md).

## Current v1 status

The source package version is `1.0.0`, but that is not a public release claim.
The current working tree is prepared for a future release-candidate freeze only
after its preflight gates are satisfied. Read the
[release preflight](docs/releases/v1.0.0-rc-preflight.md),
[CHANGELOG](CHANGELOG.md), and [VERSION_LOG](VERSION_LOG.md) together:

- `CHANGELOG.md` is the concise product-facing change summary.
- `VERSION_LOG.md` is factual engineering and release-candidate chronology.
- The preflight records candidate evidence and remaining release gates.

Optional voice, camera, browser companion, MCP, Windows accessibility, and
generated executable capability paths are unavailable or degraded until they
are explicitly configured and supported. Missing support never enables an
uncontrolled fallback.

## Windows setup (validated Python 3.12 path)

Install Python **3.12.x**. From PowerShell in the repository root, inspect the
launcher and create the environment with that exact interpreter:

```powershell
py -0p
py -3.12 --version
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python --version
python -m pip install -r requirements-dev.lock
python -m pip install -e ".[desktop]"
```

Do not continue unless `python --version` reports Python 3.12.x. Do not use an
unqualified `python -m venv .venv` as the validated Windows v1 path: Windows
Store aliases can select a different interpreter. Python 3.13/3.14 is not the
validated v1 development path.

`requirements-dev.lock` is the locked development/test set. The editable
`.[desktop]` extra installs the optional PySide6 desktop shell. API-only or
test-only work does not need that extra.

### Recover a stale or failed repository venv

If `py -3.12 -m venv .venv` fails, do **not** activate an old `.venv` and assume
it was recreated. Stop any process using it, then remove only the repository
local `.venv` and repeat the explicit Python 3.12 creation:

```powershell
deactivate  # only if this PowerShell session has an active venv
Remove-Item -LiteralPath .\.venv -Recurse -Force
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python --version
python -m pip install -r requirements-dev.lock
```

Never point that removal command at a parent directory, user profile, or
`.jarvis`. `.jarvis` may contain local application data; deleting it is not a
venv repair step and can affect recovery evidence and local state.

## Local model with Ollama

The default provider is local Ollama using `llama3.2:3b` at the loopback-only
endpoint `http://127.0.0.1:11434`. Install Ollama for Windows, then run:

```powershell
ollama pull llama3.2:3b
ollama serve
```

`ollama serve` is only needed if the local Ollama service is not already
running. Do not point the local default at an unreviewed remote endpoint.

## Configuration is explicit

JARVIS reads explicit `JARVIS_` process environment variables and typed defaults
from [jarvis/core/config.py](jarvis/core/config.py). It does **not**
automatically load `.env` (`env_file=None`). `.env.example` is a reference
template, not an implicitly loaded runtime configuration file.

Set values in a trusted PowerShell session or owner launcher, for example:

```powershell
$env:JARVIS_ENVIRONMENT = "local"
$env:JARVIS_APP_DATA_DIR = "$env:LOCALAPPDATA\JARVIS"
$env:JARVIS_AI_PROVIDER = "ollama"
$env:JARVIS_AI_MODEL = "llama3.2:3b"
$env:JARVIS_AI_ENDPOINT = "http://127.0.0.1:11434"
```

Do not commit `.env` files, API keys, credentials, recordings, model files,
local databases, or `.jarvis` state.

## Start JARVIS

For the normal optional desktop shell, after installing `.[desktop]` in the
active Python 3.12 environment:

```powershell
$env:JARVIS_ENVIRONMENT = "local"
$env:JARVIS_APP_DATA_DIR = "$env:LOCALAPPDATA\JARVIS"
python -m jarvis.desktop
```

Successful desktop startup opens the JARVIS window; provider availability is
shown separately and does not grant optional hardware capability authority.
Voice, camera, and computer-control features are not automatically enabled.

For a local health surface instead:

```powershell
python -m uvicorn jarvis.api:app --host 127.0.0.1 --port 8000
```

In another PowerShell window, use only the loopback health endpoints:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/version
```

`GET /health` returns HTTP 200 only after canonical runtime startup completes;
it returns HTTP 503 when startup is unavailable or Safe Mode is active.
`GET /version` reports the application version only. Neither endpoint is an
approval or privileged-control API.

## How I can test JARVIS myself

Run these in the active Python 3.12 environment. They use local deterministic
fixtures and are automated release evidence, not proof of unexecuted physical
or third-party behavior.

```powershell
# Focused fast checks
python -m pytest tests/test_capability_opportunities.py -q
python -m pytest tests/test_system_testing.py -q

# Direct composition acceptance and the full deterministic quality gate
$env:JARVIS_ENVIRONMENT = "test"
python -m pytest tests/test_v1_acceptance.py -q
python scripts/quality.py

# Controlled deterministic system suites
python scripts/run_system_tests.py --suite deterministic-workflows
python scripts/run_system_tests.py --suite deterministic-permissions
python scripts/run_system_tests.py --suite v1-acceptance
Remove-Item Env:JARVIS_ENVIRONMENT

# Artifact-only distribution smoke deliberately starts its own production-mode runtime.
python scripts/package_smoke.py
```

`JARVIS_ENVIRONMENT=test` is intentionally restricted to deterministic tests.
It uses test-only deterministic seams such as the test recovery backend. It is
not a production workaround, does not grant permission, and must not be used
for real/private operation.

There is no separately certified interactive test-mode desktop command. The
nearest verified developer smoke is the deterministic v1 acceptance suite,
which creates and closes the production composition path with local fakes. Use
the normal desktop command above only after its optional dependency and trusted
local runtime prerequisites are available.

The optional `windows-hardware-manual` suite requires a dedicated interactive
Windows environment and explicit operator authorization. It is not ordinary CI
coverage. Camera, microphone, browser-companion, desktop-automation, MCP, and
other hardware/manual behavior are not claimed as passed by the commands above.

## Troubleshooting

| Symptom | Safe first check |
| --- | --- |
| `py -3.12` is unavailable | Install Python 3.12, reopen PowerShell, run `py -0p`, and do not substitute an unknown interpreter. |
| Dependency or import mismatch | Recreate only the repository `.venv` with the guarded steps above; do not delete `.jarvis`. |
| Ollama/model unavailable | Confirm `ollama serve` is running locally, check `ollama list`, and verify the loopback endpoint. |
| `Application runtime is not ready` or `/health` returns 503 | Inspect local startup output and trusted configuration. JARVIS fails closed when recovery, integrity, or configuration prerequisites are unavailable. Do not set test mode as a production fix. |
| Desktop import fails | Confirm `python -m pip install -e ".[desktop]"` completed in the same active Python 3.12 environment. |
| A privileged action waits | Use the trusted desktop approval surface. Spoken recognition alone cannot authorize privileged/high-risk actions in v1. |
| Voice/camera unavailable | Treat it as an optional capability degradation; verify the configured provider/device rather than weakening permission policy. |

Do not enable privileged capabilities merely to bypass policy. Do not assume
`.env` was loaded. Do not delete `.jarvis` just to silence recovery errors
without understanding the local-data consequence.

## Further reading

- [Development guide](docs/development.md)
- [Security constitution](docs/security-constitution.md)
- [Authoritative state map](docs/authoritative-state-map.md)
- [Windows integration isolation contract](docs/security/windows-integration-isolation.md)
- [Release preflight](docs/releases/v1.0.0-rc-preflight.md)
- [Donor provenance map](docs/reference/donor-provenance-map.md)

## License

First-party JARVIS software is proprietary software in private-use,
pre-commercial development. Use is subject to [LICENSE.txt](LICENSE.txt) and
[EULA.txt](EULA.txt); current privacy practices are in
[PRIVACY_POLICY.txt](PRIVACY_POLICY.txt). Third-party dependencies retain their
own license terms.
