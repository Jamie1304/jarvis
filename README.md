# JARVIS

[![Windows quality](https://github.com/Jamie1304/jarvis/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Jamie1304/jarvis/actions/workflows/ci.yml)

JARVIS is a local-first Windows desktop AI assistant. Phase 6 adds controlled,
brokered Windows computer capabilities: semantic UI operations, scoped filesystem
access, catalogued application launch, secure screenshot references, and controlled
argument-array terminal execution. Phase 5's granular deny-by-default permission
broker, trusted-user approvals, hard-safety rules, and secret-safe audit trail
remain mandatory. No privileged OS tool is enabled by the default catalog.

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.lock
python -m pip install -e ".[desktop,speech]"
ollama pull llama3.2:3b
python -m jarvis.desktop
```

For a text-only setup, omit the desktop/speech extra and run the health API with `python -m uvicorn jarvis.api:app --reload`. Run all quality checks with:

```powershell
python scripts/quality.py
```

See [docs/development.md](docs/development.md) for the complete workflow.
