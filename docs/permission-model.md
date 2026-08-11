# Permission and approval model

## Permissions and risk

The broker recognizes only `filesystem.read`, `filesystem.write`, `screen.read`,
`camera.read`, `microphone.read`, `clipboard.read`, `clipboard.write`,
`terminal.execute`, `application.launch`, `application.install`,
`network.request`, `code.modify`, `system.power`, and `computer.input`.

`computer.input` is limited to authorized keyboard/control entry, window focus,
and the explicitly labelled coordinate-mouse fallback. It is not an aggregate
computer-access grant. Clipboard read/write, screenshots, application launch,
filesystem access, and terminal execution retain their own permissions.

Risk is classified as low, medium, high, or critical by trusted tool code. Reading
private data or sending a bounded network request is normally medium; mutations,
process launch, and clipboard writes are high; installation, power control,
privilege escalation, destructive commands, and bulk deletion are critical.
Policy may be stricter than this baseline.

Every evaluation returns `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` and a stable reason
code. Rules enumerate exact trusted action labels; an unrecognized or malformed
action denies. No rule means deny. Scope can constrain canonical filesystem paths,
applications, normalized hosts, command families, tool ID, task ID, and expiry.

## Approval lifecycle

For `REQUIRE_APPROVAL`, the broker creates a trusted `ApprovalRequest` containing
the request/task IDs, trusted action label and safe argument summary, permission,
risk, normalized scope, policy reason, and expiry. The human-facing UI/API renders
that object directly and must not substitute model-provided approval text.

A trusted human may approve or deny once, cancel a pending request, or create a
limited remembered grant. One-time approval is bound to the exact canonical
argument fingerprint and consumed atomically by execution. Remembered grants must
be no broader than the approved request, must expire within the configured maximum,
and are forbidden for hard-safety actions. Expired, cancelled, denied, consumed,
or argument-mismatched approvals do not authorize execution.

## Filesystem policy

Filesystem and code permissions require at least one absolute path. Trusted policy
declares canonical root directories. Requests containing NULs, relative paths,
`..` components, different drives, or paths resolving through symlinks/junctions
outside an allowed root are malformed or out of scope and deny. Policy comparisons
use canonical resolved paths and platform-aware containment, never string prefixes.

## Rules for privileged tools

1. Register tools explicitly and declare every granular permission in the manifest.
2. Accept model arguments only through strict input schemas.
3. Implement the trusted action descriptor in application code: static action
   name, safe summary, risk/destructive class, and normalized least-privilege scope.
4. Put host-affecting code only in the private authorized implementation hook. Do
   not expose an alternate public execution method or import it from orchestration.
5. Execute only through `DefaultToolExecutor`/`Tool.invoke` with the application
   `PermissionBroker`. Never accept permission state or approval claims in tool
   arguments, prompts, or model output.
6. Add policy intentionally. Missing and disabled policy must remain a denial.
7. Redact secrets in summaries and return data. Audit stores the broker-generated
   fingerprint, not arguments or contents.
8. Test unknown/malformed inputs, scope escapes, approval expiry/replay/mutation,
   cancellation, disabled policy, and the tool's destructive cases.

## Controlled Windows computer tools

Computer tools use a platform-neutral adapter and must retain the brokered base
tool entry point. A tool resolves applications and terminal commands only from
trusted application-owned catalogues. It must not accept an executable, a complete
shell command, an arbitrary Windows handle, a policy decision, or approval text
from the model as authority.

Terminal tools pass a trusted executable plus a validated, catalogue-allowlisted
argument array to an adapter using `shell=False`; policy scopes the command family,
working directory, tool, task, and duration. Filesystem tools execute only the canonical path emitted
by the broker's scoped receipt. Screenshot tools save bytes in a trusted artifact
store and return an opaque reference and metadata, never binary image payloads.

Terminal catalogue entries are `destructive_system_command` by default, so even an
allow policy produces a fresh approval request. Only trusted code may classify a
narrowly reviewed, non-destructive command as ordinary.
