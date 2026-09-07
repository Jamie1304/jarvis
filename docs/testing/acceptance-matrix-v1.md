# Acceptance matrix v1

The complete 115-test matrix is stored as typed data in
`jarvis/acceptance/specs.py`, preserving the handoff's phase and title for
every immutable ID. `validate_specs()` is the canonical coverage check and
fails on a missing, reordered, or duplicate ID. Classification and automation
level are present for every row. Future product gaps remain explicit blocked
results rather than fabricated passes.
