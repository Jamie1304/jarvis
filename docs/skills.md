# Native reusable Skills

JARVIS keeps these concepts separate:

- **Tool** — what can execute.
- **Skill** — how to do something well.
- **WorkflowTemplate** — a reusable execution structure.
- **Integration** — an external capability.
- **Agent** — a specialist worker.

`SkillManifest` is reusable procedure metadata. It records an ID/version,
purpose, prerequisites, tools/capabilities, bounded procedure, output and
verification hints, fallback guidance, provenance, and workspace/profile scope.
`SkillRegistry` validates explicit dependencies and scope; registering a skill
does not register a tool, grant a capability, or create permission.

## Explicit context priming

`SkillContextRequirements` contains retrieval hints for memory categories,
Knowledge Library queries, workspace documents, project knowledge queries,
preferred examples, and required prior artifacts. These are requests for
relevant context only. They cannot request arbitrary secrets, widen a workspace,
change classification, or escalate authority.

The existing agent-runtime `ContextManager` is the single priming boundary. It
passes each declared query to an application-owned source, then requires every
returned item to match the active workspace, allowed classification, privacy
mode, and token budget. Cross-workspace data, disallowed classifications,
privacy-sensitive data, malformed items, and unbounded context fail closed.
Missing context is reported explicitly and is never fabricated by the skill or
model. Context retrieval does not alter `PermissionBroker`, policy, approval,
trusted identity, task state, or tool authority.

Memory, Knowledge Libraries, workspace documents, and artifacts retain their
existing authoritative owners. Skill context is a bounded projection into a
model request, not a new memory or knowledge store. A future workflow engine
may consume a `SkillManifest`, but it must preserve the same planning and
permission boundaries.
