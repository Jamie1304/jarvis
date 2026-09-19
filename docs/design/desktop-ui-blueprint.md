# JARVIS Desktop UI Blueprint

This document describes the implemented native desktop foundation. It is a
presentation layer over `DesktopApplicationFacade` and `DesktopBackendHost`;
it does not own runtime state, credentials, tools, planning, or permission
authority.

## Design language

JARVIS uses a dark, local-first visual language: `#050A0F` background,
`#090F15` surfaces, `#101820` raised surfaces, cyan accents (`#24A8FF`),
green success, amber trusted attention, red danger, and violet special state.
Tokens are centralized in `jarvis/frontend/theme.py`; page code does not own
the palette. Cards, restrained borders, typography, and spacing establish
hierarchy without pervasive glow or gradients.

## Shell and components

The shell contains a system bar, persistent generic navigation, a stacked
workspace, and an observability rail. Pages are Overview, Chat, Tasks, Memory,
Capabilities, Tools, Automations, Permissions, Activity, and Settings. Common
visual primitives are cards, page headers, status labels, bounded list rows,
and action bars. Empty projections remain empty and are described truthfully.

The overview and observability surfaces show only facade projections. Provider
status is real Ollama status when available; no uptime, confidence, token, or
health percentage is invented.

## Responsive and high-DPI behavior

Qt layouts and size policies provide the layout. The shell has a usable
minimum size and expands the workspace while keeping navigation and the
observability rail bounded. The visual harness renders 1672x941, 1440x900,
and 1280x720 candidates; Windows scaling is supported by layout-driven sizing
and native font metrics rather than pixel-positioned controls.

## Boundaries and evidence

All consequential actions continue through the backend host and application
facade. Trusted permission decisions use the existing live request and
fingerprint-bound approval surface. Generated capability UI remains declarative
and cannot render trusted approval or execute arbitrary code. The UI shows
operational statuses and safe summaries, never credentials or private
chain-of-thought. Safe Mode disables normal execution while leaving Settings
and recovery-oriented presentation available.

## Visual validation

`scripts/render_desktop_visuals.py` captures deterministic candidate baselines
from the real shell. It is test-only synthetic state, stored under
`artifacts/desktop-visual-candidates/`, and is not an owner-approved golden
baseline. The harness checks page count, minimum geometry, and captures every
navigation page. Future owner-approved baselines must be recorded separately.
