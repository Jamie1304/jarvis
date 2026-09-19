# Controlled Windows computer capabilities

## Boundary and composition

All computer capabilities are brokered `Tool` implementations. The required path is:

`AI/planner -> strict typed action -> PermissionBroker -> policy/approval -> private tool hook -> adapter`

The planner never receives a Windows automation object, an executable path, a shell
string, an approval decision, or a raw authorization receipt. Trusted application
composition supplies the adapter, application catalogue, command catalogue,
screenshot store, filesystem adapter, policy, and broker. `create_computer_tools`
returns tools for explicit registry registration; it does not enable them by default.

## Capability map

| Semantic operation | Tool | Permission | Scope/evidence |
| --- | --- | --- | --- |
| Discover windows | `computer.discover_windows` | `screen.read` | query, matching window IDs/titles |
| Read accessibility tree | `computer.read_accessibility` | `screen.read` | bounded UI Automation controls/value fingerprints |
| Launch application | `computer.launch_application` | `application.launch` | trusted application ID, process ID |
| Focus window / set text | `computer.focus_window`, `computer.set_text` | `computer.input` | window/control ID, focused/control state |
| Mouse fallback | `computer.mouse_fallback` | `computer.input` | coordinates and explicit fallback reason |
| Capture screenshot | `computer.capture_screen` | `screen.read` | opaque artifact reference, dimensions/time |
| Read/write clipboard | `computer.read_clipboard`, `computer.write_clipboard` | separate `clipboard.read` / `clipboard.write` | read flag or write confirmation |
| Read text file | `computer.read_text_file` | `filesystem.read` | broker-normalized canonical path |
| Execute command | `computer.execute_command` | `terminal.execute` | trusted command family, workdir, timeout, exit/output state |

Semantic UI Automation is the normal path. `mouse_fallback` exists only where no
semantic control can be located and remains conspicuous in policy and audit data.
Window IDs are observations, not reusable authority: focus and input still pass the
broker independently.

## Visual understanding protocol

The Phase 7 visual layer uses the mandatory loop
`OBSERVE -> UNDERSTAND -> GROUND -> ACT -> OBSERVE AGAIN -> VERIFY`. It invokes
`computer.capture_screen`, `computer.discover_windows`, and the optional
`computer.read_accessibility` tool through the existing `PermissionBroker` boundary.
A vision provider receives a screenshot reference and structured semantic context;
it cannot call an adapter or grant a permission. The trusted observation assembler
prefers accessibility matches, augments them with visual candidates, assigns target
IDs, and records dimensions, DPI/physical geometry, active window, timestamp,
confidence, and a state fingerprint that includes a screenshot-content fingerprint.

Every action proposal names a target ID from its observation. Just before input, the
service obtains another observation and denies the action if the dimensions, active
window, target set, or screenshot fingerprint changed. Coordinate fallback converts
normalized target bounds through trusted current DPI/display metrics; it never assumes
a fixed resolution. After any broker-authorized action it observes again and returns
`SUCCESS`, `FAILURE`, or `UNCERTAIN` only from explicit verification evidence.

## Adapter requirements

`ComputerAdapter` is platform-neutral. The optional `WindowsUiAutomationAdapter`
uses Windows UI Automation by semantic title, automation ID, and control type where
available. It is configured with a trusted `ApplicationDefinition` catalogue.
Production composition must not instantiate it from model data. Windows-specific
dependencies are optional (`.[windows]`) and integration tests require explicit
operator opt-in.

Application and command executable identities must be absolute, existing regular
files. Launch paths reject symlinks/junctions and path aliases where the resolved
identity differs. Child processes receive a minimal environment and are launched
with argument vectors; `PATH`, shell expansion, Python hooks, and ambient
credentials are not inherited. These checks narrow identity confusion but cannot
eliminate all Windows TOCTOU races or prove signer/code identity; use a trusted
fixed-volume catalog and future OS-level isolation for hostile integrations.

Adapters return structured facts—window details, process ID, control state, cursor
action, or captured screen metadata—to let later verification inspect what happened.
They must not report success when a platform call failed or was not attempted.

## Terminal and filesystem constraints

`ControlledCommandService` maps only trusted command IDs to a fixed executable and
command family, with an exact catalogue-owned allow-list of complete argument
sequences. Commands are destructive-system-command actions by default and therefore
require fresh approval; trusted catalogue code may classify a narrowly reviewed,
non-destructive command as ordinary. The model can provide only a selected permitted
sequence, a scoped working directory, and a bounded timeout. The subprocess adapter calls
`asyncio.create_subprocess_exec`, never a shell, captures bounded stdout/stderr,
and terminates the child on timeout or cancellation.

Filesystem paths are validated and canonicalized by the permission broker before
execution. The filesystem tool reads the path from the authorization receipt rather
than its raw input. Relative paths, traversal, NUL characters, and symlink/junction
escape beyond configured roots are denied before the adapter runs.

## Screenshot and data handling

Screen bytes are adapter-private and are passed directly to a trusted
`ScreenshotStore`. Tool output contains an opaque `screenshot:<id>` reference,
content type, dimensions, and capture timestamp only. Audit summaries use safe
metadata/fingerprints and never contain clipboard contents, entered text, command
arguments, command output, or screenshots.

## Policy and approval guidance

Allow rules should be narrow: one tool/action, a named application, a canonical
directory root, one command family, and a short duration. Policy may require a
trusted-user approval for high-risk input, launch, clipboard write, or terminal
activity. Hard-safety policies from Phase 5 still apply; no computer tool may turn
destructive system commands or privilege escalation into an automatic authorization.

## Developer checklist

1. Add a new capability as a strict typed brokered tool—not a public OS helper.
2. Use the smallest granular permission and derive scope in trusted code.
3. Add a semantic adapter method before considering a coordinate fallback.
4. Return structured evidence and safe metadata; keep private data out of audit.
5. Test denial before adapter invocation, scope escape, cancellation/timeout, and
   any mutable or destructive effect with fake adapters.
6. Keep real Windows desktop checks opt-in and do not use skipped checks as proof
   of interaction.
