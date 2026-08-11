# Phase 5 permission-boundary threat model

## Assets and security goals

JARVIS must protect user files, credentials, private sensor data, clipboard data,
applications, network destinations, and host availability. Untrusted model output
must never create, widen, remember, or approve authority. A tool may execute a
privileged action only after trusted code has validated its arguments, described
the exact action, evaluated policy, and (when required) matched a live trusted-user
approval to the same task, tool, permission, scope, and argument fingerprint.

## Capability inventory

Current implemented capability contracts are:

- calculator and local-time agent tools, which are non-privileged;
- an unavailable weather placeholder, which performs no network request;
- Ollama HTTP transport (`network.request`), selected by trusted composition code;
- on-demand microphone capture (`microphone.read`), started by a direct UI gesture;
- local speech synthesis/audio output, which is not an input or host-mutation
  permission in the Phase 5 taxonomy.
- controlled, opt-in computer tools for window discovery, catalogued application
  launch, focus, semantic text entry, explicit mouse fallback, screen capture,
  clipboard, scoped filesystem read, and catalogued terminal commands. They are
  not registered in the default runtime catalog.

The Ollama and microphone paths are provider/UI flows, not planner-selected tools.
They remain separately bounded by trusted configuration and an explicit user
gesture. If either becomes planner-selectable it must first be converted to a
brokered tool.

Planned or reserved privileged capabilities are filesystem write, camera capture,
application installation, arbitrary network requests, source-code modification,
persistent memory storage, and system power control. Computer input uses its own
`computer.input` permission. Each capability requires a granular permission;
there is no aggregate computer-access permission.

Developer-only subprocess use in `scripts/quality.py` is outside the running
assistant and is not an agent capability.

## Adversaries and abuse cases

The primary adversary is malicious or confused model output, including prompt
injection embedded in files, web content, tool output, or user text. It may name an
unknown permission or tool, forge an approval claim, alter arguments after a user
review, replay an approval, request an over-broad scope, use path traversal or a
link/junction escape, or disguise a destructive command as an ordinary action.

Other failures include buggy tools under-declaring permissions, stale or disabled
policy, races around cancellation/expiry, approval API misuse, secret leakage in
audit logs, and a developer accidentally calling a privileged implementation
without the broker.

Phase 6 additionally considers UI spoofing/incorrect-window targeting, raw input
used in place of semantic controls, application-ID or command-ID substitution,
shell interpretation, unbounded child processes, screenshots or clipboard data
leaking through results, and filesystem paths escaping approved roots after policy
evaluation.

Phase 7 adds adversarial visual content, provider hallucination, accessibility/vision
disagreement, stale screenshots, race conditions between observation and input,
window switching, coordinate/DPI confusion, and visual recognition of sensitive
controls. A model or provider may describe a button but must not turn that description
into authority or a verified outcome.

## Trust boundaries

1. Model/planner output to strict plan and tool-input schemas: entirely untrusted.
2. Registered tool metadata and action descriptors: trusted application code,
   reviewed with the tool implementation.
3. Tool to `PermissionBroker`: mandatory runtime authorization boundary.
4. Policy configuration and normalized scope roots: trusted operator input.
5. Approval presentation and decision: trusted application UI/API plus an
   authenticated human identity; model/tool identities are rejected.
6. Broker to host/provider implementation: only an exact, short-lived
   authorization receipt may cross this boundary.
7. Audit sink: trusted append-only destination receiving fingerprints and safe
   summaries, never raw arguments or secrets.
8. Platform-neutral adapter to Windows UI Automation/Win32/subprocess APIs: only
   the authorized private tool hook may call this boundary. Windows adapter output
   is evidence, not an authorization decision.
9. Vision provider output to trusted semantic-first fusion: untrusted structured
   suggestions; it cannot directly access input adapters, the broker, or approvals.

Python does not provide an in-process security sandbox. The boundary assumes
registered tool code and the application process are trusted and reviewed; a
malicious Python module running in-process can call operating-system APIs directly.
The registry therefore prohibits dynamic discovery, and privileged implementation
methods are deliberately private and reachable only through the brokered tool
entry point by convention and tests.

## Fail-closed invariants

- Unknown/malformed permissions, unknown tools/actions, malformed scopes, missing
  or disabled policies, and invalid action descriptors deny with machine-readable
  reasons.
- Approval data is built from trusted descriptors, never free-form model prose.
- Approval matching includes task, tool, action, permission, normalized scope, and
  a canonical full-argument fingerprint.
- One-time approvals are atomically consumed once and cannot authorize changed
  arguments. Cancellation and expiry win over execution.
- Limited remembered grants have explicit scope and expiry and cannot cover hard
  safety actions. There is no global or unbounded remember option.
- Bulk deletion and destructive system commands require a fresh trusted approval;
  privilege escalation is denied by hard policy.
- Filesystem scope accepts only absolute, canonical paths beneath trusted roots and
  rejects traversal plus symlink/junction escape.
- Audit records contain decision provenance and execution outcome without raw
  arguments, approval tokens, credentials, or file contents.
- Application and terminal command IDs resolve only through trusted catalogues;
  executable paths and shell strings are never model-controlled.
- Terminal execution uses an argument vector with `shell=False`, explicit working
  directory and timeout, and kills the child process on timeout or cancellation.
- Screenshot bytes remain in a trusted artifact store. The model receives an opaque
  reference and metadata, not an adapter-private binary payload.
- Visual actions name a current trusted-fusion target ID. The interaction service
  re-observes and rejects changed display/window/target/fingerprint state before it
  invokes an action tool, then verifies with a new observation.
- A visual finding never grants a permission. Sensitive input still receives the
  original tool's policy, approval, audit, cancellation, and hard-safety controls.
