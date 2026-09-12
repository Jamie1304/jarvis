# JARVIS donor/reference provenance map

**Status:** research and provenance baseline only

This map is the single index for donor/reference projects. Donors are not JARVIS
runtime dependencies. No donor code was copied by this study. A concept may be
useful without its implementation, and a repository license does not
automatically license its dependencies, assets, models, prompts, or generated
content.

The native `DonorStudyService` accepts only the bounded provenance records in
this map’s contract. It does not discover by cloning, import source, execute a
donor, install a package, or add dependencies. Any native implementation is
handed to the existing proposal-and-test self-improvement pipeline.

## Rules

- **PORT** means source reuse is approved only after exact-file provenance,
  applicable copyright/notice preservation, dependency review, and the tests
  listed in the entry. There are currently **no PORT decisions**.
- **REIMPLEMENT** means build an independent JARVIS-native implementation of a
  verified behavior. It is not permission to copy source.
- **INSPIRE_ONLY** means retain the idea for design research; no implementation
  commitment.
- **REJECT** means the concept conflicts with JARVIS architecture, security, or
  ownership rules.
- Exact revisions below are immutable SHAs resolved from the official
  repositories on 2026-08-23, except Goose, which was independently rechecked
  against official upstream on 2026-08-30. Where a branch head is used, it is
  recorded as a SHA rather than treated as a floating dependency.
- License findings are source-repository findings at the pinned revision. They
  are not legal advice and do not cover third-party dependencies.

## Revision and license index

| Donor | Official repository | Revision used | License inspected | Runtime decision |
|---|---|---|---|---|
| Goose | [aaif-goose/goose](https://github.com/aaif-goose/goose) | `403fcc84c78e5676197219071f4740497fdd4af3` | Apache-2.0 `LICENSE` | Reference only; no runtime dependency |
| Agent Zero | [agent0ai/agent-zero](https://github.com/agent0ai/agent-zero) | `v1.12@75b26e197ea80eeb1fc1c8d1f2a6a6572e9090cb` | MIT `LICENSE` | Reference only; no runtime/server/Docker/UI/memory dependency |
| fullstack-agent | [jaredrhod/fullstack-agent](https://github.com/jaredrhod/fullstack-agent) | `main@e020fb7ed77356a5394b560df0a1db5a64e2ada6` | AGPL-3.0-or-later `LICENSE` | Reference only; no installer dependency |
| Backtalk | [jaredrhod/backtalk](https://github.com/jaredrhod/backtalk) | `main@839a1c997f819ce17dfcfe9d764bc0fd39af8a3b` | AGPL-3.0-or-later `LICENSE` | Reference only; no voice runtime dependency |
| ai-visualizer | [jaredrhod/ai-visualizer](https://github.com/jaredrhod/ai-visualizer) | `main@06e6c31163bc319508895a986cf457333e8134fe` | AGPL-3.0-or-later `LICENSE` | Reference only; no visualizer runtime dependency |
| ai-memory-vault | [jaredrhod/ai-memory-vault](https://github.com/jaredrhod/ai-memory-vault) | `main@d16ba5a6c705456c0f53692f3be0819c2cfe98b3` | CC BY-SA 4.0 `LICENSE` | Reference only; no vault/memory dependency |
| barehands | [jaredrhod/barehands](https://github.com/jaredrhod/barehands) | `main@65bdeebfa91dc1e3f777f37e7885295be80e9568` | CC BY-NC-SA 4.0 `LICENSE` | Reference only; no gesture runtime dependency |

## Goose

### Source and scope

The official upstream repository and immutable commit were rechecked through
GitHub's repository and commit metadata on 2026-08-30. `LICENSE` at
`403fcc84c78e5676197219071f4740497fdd4af3` identifies Apache-2.0 (GitHub
content SHA `c83043d4494071fbd93ef245a14e573c5a8280c4`). This is provenance
evidence only: Goose source, package, binary, ACP, MCP runtime, server, and
extension manager are not JARVIS dependencies, and there remains no approved
PORT decision.

Relevant files at the pinned SHA:

- `crates/goose/src/agents/agent.rs` — agent loop, tool dispatch, error and
  context handling.
- `crates/goose/src/agents/extension_manager.rs` and
  `crates/goose/src/agents/mcp_client/` — extension/MCP management.
- `crates/goose/src/providers/canonical/` — provider registry/catalog.
- `crates/goose/src/session/` — session state and persistence.
- `crates/goose/src/skills/` and `crates/goose/src/agents/platform_extensions/` —
  skills and built-in extension patterns.
- `LICENSE` and repository notices — Apache-2.0 provenance boundary.

### Concepts

| Concept | Problem / donor approach | JARVIS target and security change | Dependency risk | Decision |
|---|---|---|---|---|
| Agent loop and operation pipeline | Provider chat emits tool calls; the agent dispatches extensions, feeds results back, and continues. | Existing `PlanningEngine` and application services; durable budgets, audit, broker, idempotency, and `UNKNOWN_OUTCOME -> RECOVERING`. | Duplicate task/control plane and model-directed authority. | REIMPLEMENT |
| Unknown tools and tool errors | Invalid JSON/missing tools become model-visible errors so the loop can continue. | Typed registry/plan validation; unknown tools fail closed and cannot self-register. | Error feedback can become prompt injection or repeated unsafe attempts. | REIMPLEMENT |
| Context revision/compaction | Summarize/delete stale context and reduce verbose tool output. | Transient conversation projection only; authoritative stores remain unchanged. | Secret leakage and compaction rewriting evidence. | INSPIRE_ONLY |
| Retry/repetition/max turns | Bound continuation and prevent loops. | Existing exact step budget, retry and effect-outcome contracts. | Blind replay after uncertain external effects. | REIMPLEMENT |
| ProviderRegistry | Map provider/model metadata to implementations. | Narrow trusted local provider configuration; no broad integration catalog. | Credentials, endpoint, and capability expansion. | INSPIRE_ONLY |
| Sessions, MCP, extensions, skills, subagents, hooks, restrictions | Persistent sessions, external tools, extensibility, delegated work, lifecycle notifications, and modes. | Future typed interfaces only; one PlanningEngine, brokered tools, isolated generated code, events as facts. | Donor runtime becomes production authority or untrusted code enters trusted process. | REJECT donor runtime; INSPIRE_ONLY concepts |

**License/provenance:** Apache-2.0 permits reuse subject to its notice and
dependency obligations, but no Goose source is approved for PORT. Tests would
need agent-loop bounds, unknown-tool rejection, context secret exclusion,
broker enforcement, and one-plane topology.

## Agent Zero

### Source and scope

Pinned official release: `v1.12@75b26e197ea80eeb1fc1c8d1f2a6a6572e9090cb`.
Relevant files/features at that revision include:

- `plugins/`, `usr/plugins/`, plugin manifests, install/update/uninstall hooks,
  and plugin management UI/API.
- `usr/`, project/workspace configuration and persistent data ownership.
- `agents/`, `usr/agents/`, profile definitions and prompts.
- `memory/`, memory tools/UI, vector/consolidation paths where present.
- `webui/` and Time Travel workspace-history UI/API.
- `Dockerfile`, `DockerfileLocal`, `scripts/`, host/CLI bridge paths, and
  browser integration.
- `LICENSE` — MIT, copyright Agent Zero, s.r.o.; preserve notice for any
  future approved reuse. Third-party licenses remain separate.

### Concepts

| Concept | Problem / donor approach | JARVIS target and security change | Dependency risk | Decision |
|---|---|---|---|---|
| Plugin manifests/create-review/install/update/uninstall | Manifest-driven plugins, guided creation, lifecycle hooks, and UI management. | Future isolated capability proposal flow; no in-process plugin manager or automatic package installation. | Hooks can mutate the live environment, install dependencies, or leave state. | REIMPLEMENT native lifecycle later; REJECT donor runtime |
| Hot reload/watcher/frontend refresh | Refresh plugin/UI surfaces after filesystem changes. | Typed projection refresh with revision checks and stale-callback protection. | TOCTOU, path/reparse attacks, stale UI authority. | INSPIRE_ONLY |
| Projects/workspaces | Isolate files, instructions, memory, secrets, repositories, and model choices. | JARVIS-owned workspace/path policy and authoritative-state map. | Cross-project secret/memory leakage and confused deputy. | REIMPLEMENT |
| Agent Profiles | Reusable role, behavior, and prompt configuration. | Untrusted profile/context data only; never identity, policy, or approval. | Prompt injection and profile shadowing. | INSPIRE_ONLY |
| Vector memory/consolidation/inspection | Retrieve, curate, edit, delete, and consolidate long-term memories. | Existing single-owner memory store, typed provenance, bounded retrieval, explicit inspection service. | Embedding/vector service, stale-memory poisoning, privacy leakage. | REIMPLEMENT native; REJECT donor service |
| Time Travel/snapshots | Shadow Git history for workspace diff, travel, and revert. | Existing `RecoveryStore`/LKG/health-checked rollback, separate from planning/audit truth. | Snapshot authority confusion, partial restore, storage growth. | REIMPLEMENT native |
| Docker/isolation/host bridge/browser privacy | Full Linux desktop/browser in Docker with optional host connection. | Native generic primitives and future least-privilege IPC only. Local-model policy remains JARVIS-owned. | Docker socket/mount privilege, bridge RCE, browser credential/data leakage. | REJECT required runtime; INSPIRE_ONLY isolation ideas |

**License/provenance:** MIT was read from the pinned `LICENSE`, including the
copyright and notice requirement. No Agent Zero code, container, server, Web UI,
plugin, vector store, or bridge is approved for PORT. Tests for any native
reimplementation must cover isolation, secret boundaries, snapshot recovery,
and Safe Mode.

## fullstack-agent

- **Official revision/license:** `jaredrhod/fullstack-agent`,
  `main@e020fb7ed77356a5394b560df0a1db5a64e2ada6`; `LICENSE` and README state
  AGPL-3.0-or-later, copyright Jared Rhodenizer. This is a strong copyleft
  and must not be treated as compatible with copying into a differently
  licensed JARVIS core without legal review.
- **Exact relevant files:** `fullstack-agent.md` (conductor/setup/adoption/
  repair/wiring), `start.sh`, `start.bat`, `update.sh`, `update.bat`,
  `TROUBLESHOOTING.md`, `CLAUDE.md`, `LICENSE`.
- **Problem:** assemble separate memory, voice, face, and hands repositories;
  collect answers once, adopt existing installations, repair failures, and
  update all pieces.
- **Donor approach:** a Claude Code wizard clones sibling repositories, runs
  their setup, wires configuration paths, and leaves old user files in place.
- **JARVIS target:** recovery/composition contracts can learn from explicit
  prepare/adopt/repair/verify steps. JARVIS must keep one composition root and
  must not become a stack installer for donor projects.
- **Security changes:** no model-authored installer commands; no arbitrary
  clone/package execution in the trusted process; every mutation uses the
  recovery transaction, provenance, policy, and rollback gates.
- **Dependency risk:** transitive donor dependencies, shell installers,
  cross-repository drift, arbitrary path/config writes, and AGPL obligations.
- **Disposition:** **REIMPLEMENT** setup/adoption/repair concepts natively;
  **REJECT** the conductor and all donor wiring.
- **Tests:** adoption without overwrite, failed setup rollback, exact path
  containment, dependency/provenance checks, restart recovery, and proof that
  no donor runtime is imported.

## Backtalk

- **Official revision/license:** `jaredrhod/backtalk`,
  `main@839a1c997f819ce17dfcfe9d764bc0fd39af8a3b`; `LICENSE`/README state
  AGPL-3.0-or-later, copyright Jared Rhodenizer. The README also identifies
  local STT/TTS components and separate third-party licenses; those must be
  reviewed independently.
- **Exact relevant files:** `backtalk/`, `backtalk.md`, `backtalk.json.example`,
  `pyproject.toml`, `install.sh`, `run.sh`, `update.sh`, `update.bat`,
  `TROUBLESHOOTING.md`, `LICENSE`.
- **Problem:** low-latency PTT voice capture, streamed sentence TTS, barge-in,
  session continuation, spoken approval, mic-mode separation, and graceful
  audio degradation.
- **Donor approach:** local speech models, a live agent session, key-held
  capture, sentence-by-sentence speech, interrupt-to-listen, local fallback,
  state-file signaling, and configurable resume.
- **JARVIS target:** existing native voice/audio contracts, typed streaming
  response, persistent output stream, stale-response drain, session rebuild,
  PTT/wake/open-mic separation, and trusted spoken approval.
- **Security changes:** JARVIS never supports a global bypass permission mode;
  spoken approval is only a strict decision over the trusted operation object;
  mic mode cannot alter authority; voice failures degrade without bypassing
  policy.
- **Dependency risk:** Claude Agent SDK coupling, local model downloads,
  optional cloud TTS credentials, platform audio behavior, and AGPL code.
- **Disposition:** **REIMPLEMENT** voice streaming/barge-in/audio lifecycle/
  session-recovery concepts; **REJECT** Backtalk runtime and permission
  semantics.
- **Tests:** deterministic fake audio, preroll/tail/noise rejection, PTT repeat,
  streaming TTS, persistent stream, barge-in/stale drain/session rebuild,
  degradation, approval ambiguity/timeout, and no vendor dependency.

## ai-visualizer

- **Official revision/license:** `jaredrhod/ai-visualizer`,
  `main@06e6c31163bc319508895a986cf457333e8134fe`; `LICENSE`/README state
  AGPL-3.0-or-later, copyright Jared Rhodenizer. Browser/CDN dependencies
  (including three.js) require their own notices and version review.
- **Exact relevant files:** `core.js`, `server.py`, `index.html`, `faces/`,
  `ai-visualizer.json.example`, `ai-visualizer.md`, `run.sh`, `run.bat`,
  `update.sh`, `update.bat`, `LICENSE`.
- **Problem:** present agent state as a live face/theme/simulation driven by
  idle/listening/thinking/speaking signals.
- **Donor approach:** a browser scene collection reads a tiny signal bus and
  renders full-screen themes through a standard-library server.
- **JARVIS target:** `PresenceProjection`/theme/simulation concepts as a
  rebuildable UI projection from typed events. UI cannot bypass application
  services or infer authority from animation state.
- **Security changes:** signals are facts only, stale events are ignored by
  revision/correlation, external assets are untrusted, and no visual state can
  authorize a tool or approval.
- **Dependency risk:** browser/CDN supply chain, local server exposure, XSS,
  stale signal files, and AGPL obligations.
- **Disposition:** **INSPIRE_ONLY** for presentation; **REIMPLEMENT** only if
  JARVIS later builds its own native projection. **REJECT** donor runtime.
- **Tests:** projection event mapping, stale-event suppression, safe-mode
  rendering, no authority transition from UI, asset/path containment, and
  browser privacy checks.

## ai-memory-vault

- **Official revision/license:** `jaredrhod/ai-memory-vault`,
  `main@d16ba5a6c705456c0f53692f3be0819c2cfe98b3`; `LICENSE`/README state
  CC BY-SA 4.0, copyright Jared Rhodenizer. Share-alike obligations make
  direct code/template reuse a legal review item.
- **Exact relevant files:** `ai-memory-vault.md`, `templates/CLAUDE.md`,
  `templates/VAULT-INDEX.md`, `templates/DAILY-NOTE.md`,
  `templates/MEMORY.md`, `README.md`, `LICENSE`.
- **Problem:** keep durable context outside the model, prime each task with
  relevant notes, organize projects/profile/jobs, and avoid multiple drifting
  memory layers.
- **Donor approach:** Obsidian/Markdown vault, task-specific priming lists,
  templates, daily notes, learned procedures, and a pointer redirecting native
  agent memory to the vault.
- **JARVIS target:** existing authoritative memory store/services, explicit
  project/episode/knowledge ownership, provenance-aware context priming, and
  learned-method records that remain suggestions/evidence rather than policy.
- **Security changes:** model-generated notes are untrusted; memory cannot
  authorize, mutate policy, complete tasks, or impersonate identity. Secrets,
  approvals, credentials, and audit truth remain outside generic memory.
- **Dependency risk:** Obsidian/Markdown semantics, prompt/config injection,
  stale learned methods, CC BY-SA share-alike obligations, and accidental
  competing memory authority.
- **Disposition:** **INSPIRE_ONLY** for priming and learned-method ideas;
  **REIMPLEMENT** authoritative-store/context contracts natively; **REJECT**
  donor vault as JARVIS memory service.
- **Tests:** memory ownership map, scope isolation, priming determinism, source
  provenance, secret exclusion, stale-method rejection, correction/deletion,
  and restart persistence.

## barehands

- **Official revision/license:** `jaredrhod/barehands`,
  `main@65bdeebfa91dc1e3f777f37e7885295be80e9568`; `LICENSE`/README state CC
  BY-NC-SA 4.0, copyright Jared Rhodenizer. MediaPipe and three.js are
  separately credited Apache-2.0/MIT/CDN dependencies; they are not covered by
  the repository license.
- **Exact relevant files:** `server.py`, `stage.html`, `barehands.json`,
  `barehands.md`, `bin/board.sh`, `bin/board-state.sh`, `state/`, `media/`,
  `README.md`, `LICENSE`.
- **Problem:** webcam hand tracking drives presentation cards, state, and
  gestures for an AI-facing visual board.
- **Donor approach:** browser camera/MediaPipe tracking, a localhost Python
  server, state files, an action allowlist, and a media jail.
- **JARVIS target:** future self-built gesture capability example only, behind
  camera privacy, accessibility/UI automation, broker, and exact-action policy.
  Generic presentation ideas may inform `PresenceProjection`.
- **Security changes:** gesture input is untrusted and never direct authority;
  every mutation still goes through application services and permission policy;
  camera mode remains independent of approval mode; browser/media paths need
  containment and reparse/TOCTOU defenses.
- **Dependency risk:** webcam privacy, browser/CDN supply chain, localhost
  action endpoint exposure, gesture false positives, and CC BY-NC-SA
  noncommercial/share-alike restrictions.
- **Disposition:** **INSPIRE_ONLY** for presentation; **REJECT** donor gesture
  runtime and direct board-control protocol.
- **Tests:** deterministic gesture recognition, false-positive thresholds,
  camera privacy/degradation, stale callback handling, action allowlist,
  permission brokerage, and no direct UI mutation path.

## PORT register

There are currently no approved PORT entries. Consequently there are no JARVIS
destinations, source modifications, copyright notices, or donor-derived tests
that can be claimed as port obligations. If a future PORT is proposed, add a
row containing all of these fields before copying anything:

| Project | Immutable revision | Exact source file | License | Copyright/notices | JARVIS destination | Modifications | Tests |
|---|---|---|---|---|---|---|---|
| None | None | None | None | None | None | None | None |

## Runtime dependency verification

The checked-out JARVIS `pyproject.toml`, lockfiles, and `jarvis/` source contain
no donor package, import, executable, server, Docker, UI, or memory-service
dependency. The existing architecture and audit documents continue to treat
all seven projects as reference/source material only. This map does not change
that rule.
