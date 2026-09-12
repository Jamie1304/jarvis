# Agent Zero architecture study — reference only

**Status:** research only; no Agent Zero implementation authority

Agent Zero is a donor/reference project. It must never become a required JARVIS
runtime, server, Docker image, Web UI, plugin host, browser, host bridge, or
memory service.

## Pinned provenance

- Official repository: <https://github.com/agent0ai/agent-zero>
- Official study tag: `v1.12`
- Resolved immutable revision: `75b26e197ea80eeb1fc1c8d1f2a6a6572e9090cb`
- Tag reference: <https://github.com/agent0ai/agent-zero/tree/v1.12>
- License at the pinned revision: repository `LICENSE`; verify the exact file
  and any third-party notices before copying anything.
- Current upstream documentation is not itself the pinned source and may have
  changed after `v1.12`.

This document records patterns and source locations for review. It does not
authorize code copying. Any future PORT decision requires a file-level license
and provenance review against this exact revision.

## Plugin lifecycle

### Plugin manifests and discovery

- **Repo/revision/files:** `plugins/`, `usr/plugins/`, `plugins/AGENTS.md`,
  `skills/a0-create-plugin/SKILL.md`, `plugin.yaml` examples at
  `v1.12@75b26e197ea80eeb1fc1c8d1f2a6a6572e9090cb`.
- **Problem:** extensions need discoverable identity, version, settings,
  scope, and UI/API/tool entry points.
- **Donor approach:** a `plugin.yaml` manifest describes name, title,
  description, version, settings sections, and project/agent scoping; built-in
  and user plugin roots are discovered separately.
- **JARVIS target:** inert capability metadata only. A future user-created
  capability may have a strict manifest outside Trusted Core; the sealed
  `ToolRegistry` and application services remain authoritative.
- **Security changes:** generated/unreviewed code cannot load into the trusted
  process; manifests cannot grant permission, select credentials, or enable a
  privileged effect; unknown fields and executable generated artifacts fail
  closed.
- **Dependency risk:** manifest schema drift, path traversal, package
  dependencies, and import-time side effects.
- **License/provenance:** study schema and behavior only; no donor manifest or
  implementation copied. Recheck `LICENSE` and third-party notices before any
  reuse.
- **Disposition:** **INSPIRE**.

### Create and review plugin

- **Repo/revision/files:** `skills/a0-create-plugin/SKILL.md`,
  `skills/a0-review-plugin/SKILL.md`, `plugins/AGENTS.md`, pinned revision above.
- **Problem:** plugin creation needs conventions, validation, UI/API contracts,
  cleanup, and a review gate.
- **Donor approach:** guided skill asks local-vs-community scope, requires a
  manifest and layout, separates runtime and index manifests, and reviews
  lifecycle/frontend patterns.
- **JARVIS target:** a future proposal/evaluation workflow for user-created
  capabilities, not a built-in plugin marketplace.
- **Security changes:** proposal code stays isolated; Trusted Core paths,
  policy, audit, credentials, and production wiring are immutable to routine
  self-expansion; approval cannot be a model-authored statement.
- **Dependency risk:** a “review” skill is not independent authority and can
  be bypassed by already-running code without process isolation.
- **License/provenance:** no skill text or plugin scaffold is ported.
- **Disposition:** **INSPIRE**, with JARVIS security gates replacing donor
  workflow assumptions.

### Install, update, uninstall, and hot reload

- **Repo/revision/files:** plugin lifecycle helpers under `plugins/`,
  `helpers/plugins/`, plugin `hooks.py`/`execute.py` conventions documented in
  `skills/a0-create-plugin/SKILL.md`, pinned revision above.
- **Problem:** plugins need installation, dependency setup, update hooks,
  reversible uninstall, and refresh without rebuilding the whole application.
- **Donor approach:** user plugins live under `/a0/usr/plugins`; install,
  pre-update, and uninstall hooks may run; the Web UI reloads plugin resources
  and frontend surfaces; hot reload is a convenience around the live framework.
- **JARVIS target:** snapshot/prepare/apply/start/health-check/commit for
  reviewed capability artifacts. No arbitrary hot code reload inside the
  trusted process.
- **Security changes:** updates require exact artifact identity, isolation,
  migration/rollback evidence, health verification, and Safe Mode gates;
  uninstall cannot remove audit, policy, broker, or recovery controls.
- **Dependency risk:** hooks can install packages into the running Python
  environment, leave state behind, race active requests, or resurrect stale
  code after refresh.
- **License/provenance:** no lifecycle code copied.
- **Disposition:** **REIMPLEMENT** only as a process-isolated, snapshot-backed
  future capability lifecycle; **REJECT** unrestricted hot reload.

### Watcher and frontend refresh

- **Repo/revision/files:** `webui/`, plugin frontend/API conventions in
  `skills/a0-create-plugin/SKILL.md`, pinned revision above.
- **Problem:** newly installed or changed plugins must become visible without a
  full UI restart.
- **Donor approach:** filesystem/plugin refresh triggers frontend extension
  loading and refreshed plugin lists/components.
- **JARVIS target:** typed UI projection refresh events only. UI calls
  application services and cannot mutate plugin/runtime authority directly.
- **Security changes:** watcher output is untrusted data; debounce, bounded
  events, path validation, and generation/revision checks prevent stale or
  forged refreshes. Safe Mode keeps diagnostics/safe UI but disables generated
  activation.
- **Dependency risk:** TOCTOU/reparse paths, stale callbacks, frontend code
  injection, and watcher storms.
- **License/provenance:** no frontend code copied.
- **Disposition:** **INSPIRE**.

## Projects, workspaces, and profiles

### Projects and workspaces

- **Repo/revision/files:** project/workspace implementation under `usr/`,
  `plugins/`, `tools/`, and project documentation at the pinned revision above;
  official guide: <https://github.com/agent0ai/agent-zero/blob/main/docs/guides/projects.md>.
- **Problem:** files, instructions, secrets, memories, repositories, and model
  choices need isolation by project.
- **Donor approach:** project-scoped workspaces under Agent Zero-owned data,
  with project memory/configuration and Git repository workflows.
- **JARVIS target:** explicit application-data/workspace ownership and future
  user-created capability scopes; task truth remains in the canonical planning
  store and project knowledge remains derived data.
- **Security changes:** workspace paths are validated and contained; secrets
  are not placed in model context or ordinary memory; model/project metadata
  cannot select privileged paths or bypass the broker.
- **Dependency risk:** shared mounts, project switching races, cross-project
  memory leakage, and credential bleed.
- **License/provenance:** no workspace implementation copied.
- **Disposition:** **REIMPLEMENT** only through JARVIS-owned stores/contracts.

### Agent Profiles

- **Repo/revision/files:** `usr/agents/`, `agents/`, profile `agent.yaml`/
  prompt conventions, `docs/guides/agent-profiles.md`, pinned revision above.
- **Problem:** repeatable role, tone, workflow, and prompt instructions need
  selection per chat.
- **Donor approach:** profiles are filesystem-managed prompt/config bundles and
  are distinct from projects, skills, and model presets.
- **JARVIS target:** future untrusted prompt/profile data in conversation
  context; no profile becomes a policy or identity source.
- **Security changes:** profiles cannot fabricate owner identity, trusted
  approval, tool permissions, or system policy; strict schema and provenance
  are required.
- **Dependency risk:** prompt injection, stale instructions, profile shadowing,
  and accidental cross-project loading.
- **License/provenance:** no profile files copied.
- **Disposition:** **INSPIRE**.

## Memory

### Vector memory, consolidation, and inspection

- **Repo/revision/files:** memory tools/plugins under `memory/`, `plugins/`,
  `tools/`, Web UI memory dashboard, and `docs/guides/memory.md`, pinned
  revision above.
- **Problem:** useful facts and prior solutions need retrieval, curation, and
  separation from stale or harmful memories.
- **Donor approach:** memory directories/areas, similarity search thresholds,
  vector-backed recall where configured, periodic/conversation-driven
  consolidation, and dashboard inspection/edit/delete/export.
- **JARVIS target:** existing `SQLiteMemoryStore` and memory services with one
  authoritative memory owner; retrieval remains a bounded projection into
  context.
- **Security changes:** memory is untrusted data, not policy, approval, task
  completion, or identity. User/project scope, retention, secret exclusion,
  provenance, and correction/deletion audit are mandatory. Vector recall may
  not outrank current trusted instructions.
- **Dependency risk:** embedding provider/network dependencies, vector DB
  persistence, stale-memory poisoning, privacy leakage, and unbounded growth.
- **License/provenance:** no vector database, embeddings, or memory code added.
- **Disposition:** **REIMPLEMENT** only with the JARVIS authoritative-state map
  and deterministic memory policy.

### Memory inspection

- **Repo/revision/files:** Agent Zero memory dashboard/UI and memory guide,
  pinned revision above.
- **Problem:** users need to inspect why an agent keeps repeating a belief or
  instruction.
- **Donor approach:** search/filter by memory directory, area, threshold, and
  limit; view metadata/content; edit or delete entries; distinguish
  conversation memory from imported knowledge.
- **JARVIS target:** an application-owned diagnostic service with read-only
  default views and explicit mutation authorization for edits/deletes.
- **Security changes:** UI cannot bypass services; inspection must redact
  secrets and distinguish source/evidence from model summaries.
- **Dependency risk:** exposing sensitive memory, bulk deletion, UI mutation
  races, and treating retrieved content as authority.
- **License/provenance:** no dashboard code copied.
- **Disposition:** **INSPIRE**.

## Time Travel and snapshots

- **Repo/revision/files:** Time Travel workspace history implementation and UI
  under `webui/`, workspace/project code, and official README/docs at pinned
  `v1.12@75b26e197ea80eeb1fc1c8d1f2a6a6572e9090cb`; current overview:
  <https://github.com/agent0ai/agent-zero#time-travel>.
- **Problem:** agent edits need inspectable history, diff, revert, and recovery
  without treating the feature as a replacement for Git/backups.
- **Donor approach:** Agent Zero-owned `/a0/usr` workspace history using shadow
  Git snapshots, diff/preview/travel/revert operations, and retention.
- **JARVIS target:** existing `RecoveryStore`/`RecoveryCoordinator` with
  transaction IDs, manifests, LKG, retention, rollback evidence, health checks,
  and authoritative-state boundaries.
- **Security changes:** snapshots never grant authority; restore requires
  containment, schema/version checks, audit evidence, health verification, and
  Safe Mode fallback. Planning, permissions, audit, memory, and credentials
  retain separate authoritative stores.
- **Dependency risk:** shadow repository corruption, reparse/TOCTOU paths,
  partial restore, storage growth, and confusing workspace snapshots with
  durable task/database recovery.
- **License/provenance:** no Time Travel code or Git layout copied.
- **Disposition:** **REIMPLEMENT** the generic recovery contract; **REJECT** a
  donor-managed workspace authority.

## Isolation and host access

### Docker patterns

- **Repo/revision/files:** `Dockerfile`, `DockerfileLocal`, `scripts/`,
  `docs/setup/installation.md`, pinned revision above.
- **Problem:** broad desktop/browser/terminal capabilities need an execution
  boundary and persistent user data.
- **Donor approach:** run a complete Linux desktop/agent/server in Docker,
  persist `/a0/usr`, expose a Web UI, and optionally bridge to the host.
- **JARVIS target:** generic native Windows primitives and future explicitly
  isolated capability workers; no Agent Zero container or server.
- **Security changes:** JARVIS privileges remain brokered and application-owned;
  Docker is not assumed to be a sufficient approval boundary, and host access
  requires exact executable/path identity, sanitized environment, and policy.
- **Dependency risk:** Docker daemon/socket privilege, image supply chain,
  host mounts, network exposure, image drift, and operational complexity.
- **License/provenance:** no Dockerfile/image/base-layer copied.
- **Disposition:** **REJECT** as a required runtime; **INSPIRE** for evaluating
  future process isolation.

### Host bridge

- **Repo/revision/files:** host bridge/CLI connector plugin and docs under
  `plugins/`, `skills/`, `webui/`, pinned revision above.
- **Problem:** a containerized agent needs controlled access to host files,
  processes, browser, or desktop surfaces.
- **Donor approach:** an authenticated HTTP/WebSocket or CLI connector bridges
  host capabilities back to the Agent Zero instance.
- **JARVIS target:** native brokered computer/process/filesystem primitives or a
  future least-privilege typed IPC worker, never a donor bridge.
- **Security changes:** bridge authentication is not enough; each operation
  must carry task, path, action, scope, and policy context through JARVIS’s
  broker. Host content remains untrusted.
- **Dependency risk:** remote-code execution, confused deputy, endpoint
  exposure, stale sessions, path escape, and host/container identity mismatch.
- **License/provenance:** no connector code or protocol copied.
- **Disposition:** **REJECT** donor bridge; **INSPIRE** a future native IPC
  boundary.

### Browser privacy and local-model-only data policy

- **Repo/revision/files:** browser/plugin docs and settings under `plugins/`,
  `webui/`, `prompts/`, `docs/`, and model/provider configuration at pinned
  revision above.
- **Problem:** browser automation can expose private pages, screenshots,
  cookies, credentials, and user content; local-model operation needs a clear
  data boundary.
- **Donor approach:** browser runs in the container by default, supports a host
  browser connector, and lets users configure providers/models and credentials.
- **JARVIS target:** browser/vision only as future generic, explicitly opted-in
  capabilities; local-model-only is a policy/configuration constraint, not an
  Agent Zero dependency.
- **Security changes:** no browser content, screenshots, cookies, credentials,
  or external instructions become policy; sensitive data is excluded from
  ordinary events/audit/memory and only trusted application code can request a
  privileged browser effect.
- **Dependency risk:** browser supply chain, fingerprinting/privacy leakage,
  remote model exfiltration, extension permissions, and host-browser bridge
  compromise.
- **License/provenance:** no browser integration copied.
- **Disposition:** **REIMPLEMENT** generic privacy/policy contracts only;
  **REJECT** donor browser/bridge runtime.

## JARVIS boundary and follow-up tests

JARVIS may learn from the donor’s separation of projects, profiles, skills,
plugin metadata, memory inspection, and recoverable workspace history. It must
not inherit Agent Zero’s runtime shape: a required Dockerized Linux system,
server/Web UI, plugin host, host bridge, vector-memory service, or donor control
plane.

Any future JARVIS work derived from this study must add tests for:

- manifest schema/path/dependency validation and generated-code isolation;
- install/update/uninstall atomicity, rollback, watcher cancellation, and stale
  callback suppression;
- project/profile/memory scope isolation and secret exclusion;
- memory provenance, consolidation determinism, inspection authorization, and
  deletion/retention behavior;
- snapshot schema refusal, LKG restore, failed-start/crash-loop detection,
  health verification, and rollback evidence;
- host/process/browser boundaries, exact identity, sanitized environment,
  permission brokerage, and local-model-only enforcement.

No Agent Zero package, server, Docker image, UI, host bridge, plugin, vector
database, or memory service was added by this study.
