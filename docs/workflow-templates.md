# Workflow Templates

`WorkflowTemplate` is reusable, typed procedure metadata. It is not a task
controller or execution engine. Its only production operation is:

```text
WorkflowTemplate + typed parameters
    -> PlanProposal
    -> PlanValidator
    -> OwnedPlan
    -> PlanningEngine
```

The `PlanningEngine` remains the sole durable execution authority. A template
cannot execute a tool, create a task result, approve a permission, preserve an
approval, or bypass workspace/profile policy.

## Contract

Templates declare bounded `WorkflowInput` parameters, `WorkflowStepTemplate`
nodes, optional `WorkflowBranch` selection, `WorkflowOutput` declarations,
capabilities, permission expectations, workspace/profile scope, verification
criteria, fallbacks, trigger compatibility, context requirements, and
provenance. Parameter substitution is typed and bounded. Branches select a
normal plan subset; they do not introduce another scheduler or control plane.

`WorkflowTemplateRegistry` is an active projection over the runtime-owned
`SQLiteWorkflowProcedureStore` (`workflow-procedures.sqlite3`). The store keeps
every immutable `WorkflowTemplateVersion`, its provenance and scope, and its
user lifecycle state. A material edit must use a higher semantic version; the
store never silently overwrites a prior version. Disable, retire, enable, and
policy-allowed deletion operate on the durable lifecycle record and do not
delete task or verification history.

Lookup remains scope-aware. The generated proposal still undergoes the
ordinary trusted tool manifest, argument-schema, dependency, permission, and
verification checks in `PlanValidator`.

Context requirements use the same retrieval-hint contract as Skills. They do
not escalate memory, secrets, capabilities, or permissions. Context remains
subject to the canonical `ContextManager` workspace, classification, privacy,
and token checks.

## Security and lifecycle

Template provenance is descriptive metadata, not trusted policy. External or
model-authored template text must be treated as a proposal and validated by
application code. Every future execution obtains fresh permission decisions;
learned templates never preserve approvals or trusted identity.

Template outputs are expected to be checked by normal step and goal
verification. A template is not considered successful because a tool returned
success, and `UNKNOWN_OUTCOME` cannot be converted into a reusable method.

## Invocation and dependency failure

Invocation always calls `WorkflowTemplate.propose()` or `instantiate()`, then
the canonical `PlanValidator`, then `PlanningEngine`/`TaskController`. A
disabled, retired, missing, or stale-capability template is unavailable to
normal lookup; the application must revalidate or replan rather than execute a
broken cached proposal. No template stores approval objects, trusted identity,
or resolved context. Context requirements are persisted only as bounded,
workspace/profile-scoped retrieval hints and are resolved afresh by
`ContextManager` at invocation time.
