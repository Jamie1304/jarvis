# Contributing to JARVIS

JARVIS is a local-first, Windows-first desktop assistant targeting Python 3.12+.

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.lock
```

Run the complete quality gate before opening a pull request:

```powershell
python scripts/quality.py
```

The gate checks formatting, linting, strict typing, tests, and the 90% coverage threshold.

## Contribution expectations

- Add or update tests for behavioral changes.
- Preserve the local-first architecture and bounded orchestration safeguards.
- Do not add privileged OS capabilities without a separate design review.
- Keep `.env`, credentials, local model files, recordings, and machine-specific state local-only.
- Use `JARVIS_` environment variables; configuration precedence is process environment, `.env`, then typed defaults.
- Pull requests must pass the complete quality gate on the Windows CI runner.
