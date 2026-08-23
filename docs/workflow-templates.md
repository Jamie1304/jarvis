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

`WorkflowTemplateRegistry` provides explicit registration and scope-aware
lookup. The generated proposal still undergoes the ordinary trusted tool
manifest, argument-schema, dependency, permission, and verification checks in
`PlanValidator`.

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
