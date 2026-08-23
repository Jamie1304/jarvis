# JARVIS

[![Windows quality](https://github.com/Jamie1304/jarvis/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Jamie1304/jarvis/actions/workflows/ci.yml)

JARVIS is a local-first Windows desktop AI assistant. Phase 7 adds provider-neutral
desktop visual understanding with semantic UI fusion, grounded current-screen targets,
and explicit post-action verification. Phase 6's controlled brokered Windows
capabilities and Phase 5's granular deny-by-default permission broker, trusted-user
approvals, hard-safety rules, and secret-safe audit trail remain mandatory. No
privileged OS tool is enabled by the default catalog. Phase 8 adds optional, brokered
one-shot camera capture with expiring frame handoff to the vision provider; physical
camera access remains disabled unless explicitly composed and authorized. Phase 9 adds
an opt-in application-manager boundary with inventory, immutable package plans, fresh
approval-bound installation/update, independent verification, and no default package
or process capability. Phase 10 adds advisory capability-gap detection and
provider-neutral candidate discovery; discovery findings cannot install, execute, or
authorize anything.
Capability health and behavior drift are monitored through trusted broker
observations against immutable certified baselines; drift can degrade or
quarantine an active capability without allowing generated code to rewrite its
baseline or self-recertify.

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
