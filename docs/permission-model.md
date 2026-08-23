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

Camera access is similarly explicit: `camera.list` and `camera.capture` declare
`camera.read`, and a model mentioning a camera does not invoke either tool. Device
IDs are additionally constrained by a trusted application catalogue. There is no
camera-open or infinite-stream agent primitive.

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
Trusted display values and normalized scopes reject C0/C1 controls, ANSI escapes,
non-printing Unicode, and bidi override/isolate characters so provider metadata cannot
spoof the action shown to the user.

The native presentation contract is `TrustedActionNarrator` plus
`ExactOperationRenderer`. The narrator accepts the broker's typed request (or a
trusted `PermissionRequest` paired with its exact `ActionDescriptor`) and creates
one immutable `TrustedPermissionPresentation` with the short explanation, exact
details, target, scope, effect, risk, and permission requested. The renderer is
pure and receives that same object; desktop and future voice surfaces must not
ask the model to restate the permission. Voice labels are fixed `YES`, `NO`, and
`DETAILS` choices for presentation only. They never represent a broker decision,
and conditional or ambiguous speech must be rejected by a future authenticated
voice ingress.

A trusted human may approve or deny once, cancel a pending request, or create a
limited remembered grant. One-time approval is bound to the exact canonical
keyed argument fingerprint and a separate keyed action/resource fingerprint over
the trusted safe summary, risk, and safety class. Changing an indirect resource
identity/version or safety classification requires fresh approval even when the
model arguments are unchanged. Remembered grants bind the same action fingerprint
and must
be no broader than the approved request, must expire within the configured maximum,
and are forbidden for hard-safety actions. Expired, cancelled, denied, consumed,
or argument-mismatched approvals do not authorize execution.

The broker does not accept caller-asserted identity/source fields. Trusted local UI
composition authenticates the human, then uses its separately held
`TrustedApprovalAuthenticator` to mint an expiring, single-use context bound to the
request, choice, identity, source, and optional remembered duration. The broker owns
only the paired verifier. Model, planner, tool, worker, event, and integration
contexts receive neither minting capability nor a way to construct a valid proof.
The canonical runtime currently has no authenticator and uses a deny-all verifier;
remote approval remains disabled.

A broker-minted execution receipt expires no later than its approval and scope,
and `Tool.invoke` claims it exactly once immediately before the provider effect.
Health checks occur before this claim. If authorization expires while health is
checked, the effect does not run. If a privileged timeout, cancellation, provider
failure, or outcome-audit failure makes the external result uncertain, the tool
returns `unknown_outcome`; the canonical planner enters `RECOVERING` and neither
retries nor replans that step. Another exact action is denied while its in-process
effect outcome remains unresolved.
After the provider boundary begins, a non-success result is also treated as unknown
unless trusted provider code explicitly marks it `NO_EFFECT`. A generic
`expected_failure` is not evidence that a package install, process launch, or other
external mutation did nothing.

## Filesystem policy

Filesystem and code permissions require at least one absolute path. Trusted policy
declares canonical root directories. Requests containing NULs, relative paths,
`..` components, ambiguous separators, Windows device/reserved/ADS forms, UNC or
extended paths, different drives, or paths resolving through symlinks/junctions
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

## Application manager policy

`application.find`, `application.plan_install`, and `application.plan_update` only
read trusted-provider evidence and do not launch, install, update, or configure an
application. `application.launch` and `application.close` require
`application.launch` scoped to the exact stable inventory ID. Close is limited to a
process that the managed runtime previously launched.

`application.install` and `application.update` require `application.install` scoped
to the exact provider package ID. Both use the `software_installation` hard safety
class, so an otherwise matching `ALLOW` policy becomes `REQUIRE_APPROVAL`; remembered
grants are rejected. The approval request displays the trusted plan ID, package ID,
source, publisher, and version. Plans expire and are consumed before execution, so a
model cannot change a candidate after approval or replay a successful plan.

## Autonomous improvement policy

Phase 11 is not registered as a model-selectable tool and its proposal is not a
permission grant. Trusted composition may inspect a configured repository and write
only a generated isolated worktree. If planner access is added later, observation
must declare scoped `filesystem.read`; source changes must declare both
`filesystem.write` and `code.modify` scoped to the exact worktree, task, tool, and
duration; and Git must be a fixed catalogued command family under
`terminal.execute`. Model-provided paths, revisions, executable names, arguments,
policy decisions, and approval claims are never authority.

A successful `MergeDeploymentProposal` remains `AWAITING_TRUSTED_APPROVAL`. It does
not authorize a production write, merge, checkout, dependency installation, network
fetch/push, release, service restart, or deployment. A future trusted execution
service must define those actions as separately brokered tools, render the trusted
proposal record to an authenticated human, bind approval to the proposal fingerprint
and expiry, and revalidate the base revision, tree/diff, dependency assessment,
gates, and evaluation immediately before execution. Remembered or model-originated
approval must not cover high-impact self-modification.

Trusted tool code for any future self-modification action must declare the
`self_modification` hard safety class. Even a matching `ALLOW` policy is elevated to
`REQUIRE_APPROVAL`, and the broker's existing hard-safety rule prevents a remembered
grant. This classification does not itself expose or authorize a Phase 11 tool.

Developers must not add a convenience method that writes the production checkout,
passes a filesystem/command object to the coding agent, treats a gate exit code as a
sandbox attestation, approves a proposal from inside the engine, or maps proposal
success directly to merge/deployment. New dependencies remain denied unless trusted
configuration pre-analyzes and binds the exact manifest transition; that exception is
not installation authority.
