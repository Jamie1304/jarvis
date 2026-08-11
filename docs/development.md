# Development

JARVIS targets Python 3.12+ and Windows first. Create a virtual environment and install the pinned baseline:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.lock

Production/runtime installation can use `requirements.lock`; development and test tools are isolated in `requirements-dev.lock`.
```

Configuration precedence is: process environment variables, then values in `.env`, then typed defaults in `jarvis/core/config.py`. Variables use the `JARVIS_` prefix. Copy `.env.example` to `.env` for local overrides; never commit `.env` or secrets.

Run the health-only service with `python -m uvicorn jarvis.api:app --reload`. Run the full quality gate with `python scripts/quality.py`. It checks formatting, linting, static typing, tests, and the 90% coverage threshold.

## Optional Phase 6 Windows integration

The controlled computer layer is not enabled by the default catalog. To install its
optional Windows UI Automation dependencies for a manually configured, brokered
integration, run `python -m pip install -e ".[windows]"`. Real desktop checks are
opt-in: set `JARVIS_WINDOWS_INTEGRATION=true` and run
`python -m pytest -m windows_integration`. Run them only on a dedicated interactive
Windows desktop with a trusted application and policy configuration. The ordinary
CI suite uses mocks and does not claim a desktop action was performed.

## Phase 2 orchestration

Phase 2 is a core service, not an enabled desktop workflow yet. `AgentOrchestrator` requires an injected `TaskStore`, planner, tool registry, executor, observer, verifier, response generator, and finite limits. Production composition intentionally provides no OS-capable tools. Use deterministic fake planners and tools in tests while adding new capability types.

The relevant safeguards are configured through `JARVIS_AGENT_MAX_STEPS`, `JARVIS_AGENT_TIMEOUT_SECONDS`, and `JARVIS_AGENT_MAX_REPLANS`. Cancellation persists to the task store and interrupts an active asynchronous tool call. Any future persistent store must implement `TaskStore` without moving lifecycle state transitions out of the orchestrator.

## Phase 1 manual smoke test

1. Install [Ollama](https://ollama.com/) for Windows, then run `ollama pull llama3.2:3b`. Ollama normally starts its local server automatically; if it is not running, use `ollama serve` in a separate terminal.
2. Copy `.env.example` to `.env`. Set `JARVIS_AI_MODEL` to a locally pulled model and leave `JARVIS_AI_ENDPOINT=http://127.0.0.1:11434` unless Ollama is configured differently.
3. Install the desktop client with `python -m pip install -e ".[desktop]"`, then start it with `python -m jarvis.desktop`.
4. Send `Jarvis, hoeveel is 25 procent van 800?`. The expected response is 200 (or an equivalent explanation).
5. For microphone input, install `python -m pip install -e ".[speech]"`, set `JARVIS_STT_ENABLED=true`, and restart JARVIS. Leave `JARVIS_STT_DEVICE` blank to use the Windows default input, or set it to an exact numeric device ID from `python -c "import sounddevice as sd; print(sd.query_devices())"`. `JARVIS_STT_COMPUTE_DEVICE=cpu` and `JARVIS_STT_COMPUTE_TYPE=int8` are the safe Windows defaults; set CUDA only on a machine with a matching CUDA runtime. Click **Start microphone**, speak, then click **Stop microphone**. The device is open only between those clicks.
6. For spoken responses, install the same speech extra, set `JARVIS_TTS_ENABLED=true`, optionally set `JARVIS_TTS_VOICE`, and restart. A completed text response should play through the configured Windows voice.
7. Disable either feature by setting its corresponding `JARVIS_STT_ENABLED` or `JARVIS_TTS_ENABLED` value to `false`; restart the app. No raw recordings are written to disk.
