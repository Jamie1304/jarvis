# JARVIS v1 current-state integration audit

**Audit date:** 2026-08-23
**Authoritative branch:** `agent/v1-integration`
**Authoritative SHA:** `770e3ec` (`Implement v1 Trusted Core security boundary with models and startup validation`)
**Remote:** `origin` → `https://github.com/Jamie1304/jarvis.git`
**Worktree:** `README.md` had a pre-existing local modification and was preserved. This audit is the only file changed by this run; no commit, push, merge, tag, release, or PR action was performed.

## Executive baseline

The current branch is the cumulative integration tip of the phase branches visible in the repository. The current implementation, rather than older phase-branch descriptions, is authoritative. JARVIS now has a canonical `ApplicationRuntime` composition root and canonical `PlanningEngine`/`PlanningTaskController` task path. The runtime is deliberately narrow: safe calculator, local-time, and unavailable-weather tools are registered; privileged computer, camera, application-management, voice, multi-agent, improvement, scheduling, and remote-approval capabilities are not enabled by default.

The permanent architecture rule is respected: donor projects are not imported as runtime dependencies, and service-specific integrations remain optional adapters behind generic core contracts. The repository contains no Goose, Agent Zero, fullstack-agent, Backtalk, ai-visualizer, ai-memory-vault, or barehands runtime dependency.

## Classification matrix

| Area | Evidence and current wiring | Classification |
|---|---|---|
| Core configuration, errors, logging, API health | `jarvis/core`, FastAPI health surface, typed settings | IMPLEMENTED_AND_WIRED |
| Local AI/conversation | Ollama selected only in `bootstrap.py`; conversation owned by runtime | IMPLEMENTED_AND_WIRED |
| Canonical runtime composition | `ApplicationRuntime.create`; one provider/event/state/planning/memory/audit/broker/registry graph | IMPLEMENTED_AND_WIRED |
| Task control and planning | `PlanningEngine` + SQLite planning store + `PlanningTaskController`; restart reconciliation and state projection | IMPLEMENTED_AND_WIRED |
| Legacy `AgentOrchestrator` | Still implemented and exercised by compatibility/deterministic workflow tests; not accepted by production UI/runtime | DEPRECATED |
| Tool contracts and registry | Versioned manifests, strict schemas, explicit registration, sealed registry; safe catalog only by default | IMPLEMENTED_AND_WIRED |
| Permission broker and policy | Tool → `PermissionBroker` → policy → approval/audit; canonical runtime uses deny-all approval verifier | IMPLEMENTED_AND_WIRED |
| Trusted Core startup security | `jarvis/security` validates policy, endpoint, feature combinations, paths and safe-mode failures | IMPLEMENTED_AND_WIRED |
| Event bus | Bounded typed bus shared by state/planning/broker | IMPLEMENTED_AND_WIRED |
| State machine | `ApplicationStateMachine` and SQLite store are runtime-created; planning projects into it | IMPLEMENTED_AND_WIRED |
| State/task/plan authority | Multiple historical status models remain; projection exists but migration is incomplete | PARTIAL |
| Persistence | Separate SQLite state, planning, memory, and audit stores; migrations and path validation exist | IMPLEMENTED_AND_WIRED |
| Cross-store transaction/recovery | Planning reconciliation exists; no transaction spanning all stores | PARTIAL |
| Long-term/episodic memory | SQLite memory store and services are runtime-created | IMPLEMENTED_AND_WIRED |
| Project knowledge | Generated JSON loads into `KnowledgeStore`; hashes support staleness checks | IMPLEMENTED_AND_WIRED |
| Knowledge revision authority | Generated context is not durable runtime authority; refresh is not startup invariant | PARTIAL |
| Windows computer control | Semantic tools/adapters and broker boundary exist; optional providers not in default catalog | IMPLEMENTED_NOT_WIRED |
| Desktop vision | Grounding/observation/verification contracts and tests exist; no concrete production provider composed | IMPLEMENTED_NOT_WIRED |
| Camera | Brokered one-shot capture, expiring store, OpenCV adapter and tests exist; no default hardware composition | IMPLEMENTED_NOT_WIRED |
| Application/package management | Inventory, immutable plans, provider/runtime seams and verification exist; no default installation path | IMPLEMENTED_NOT_WIRED |
| Capability discovery | Advisory gap detection/evaluation cannot register, install, authorize, or execute candidates | IMPLEMENTED_NOT_WIRED |
| Improvement engine | Proposal/test boundary and gates exist; no production sandbox/deployment path | IMPLEMENTED_NOT_WIRED |
| System testing | Controlled runner and deterministic catalog exist; CI invokes deterministic suite | IMPLEMENTED_AND_WIRED |
| Multi-agent orchestration | Bounded contracts/scheduler and tests exist; disabled and not runtime-composed | IMPLEMENTED_NOT_WIRED |
| Voice activation | State machine and canonical task adapter exist; real audio providers not composed | IMPLEMENTED_NOT_WIRED |
| Frontend/UI boundary | Desktop obtains services through bootstrap/runtime; UI is not policy/state owner | IMPLEMENTED_AND_WIRED |
| Dynamic integrations/plugins | No unknown-directory loader or donor-project runtime dependency | MISSING (intentionally) |
| Phase 19 | No branch, commit, module, or contract identified | UNKNOWN |

## Architecture findings

### Control engines

Two task engines remain. `PlanningEngine` is authoritative for production through `PlanningTaskController`. `AgentOrchestrator` is compatibility/deterministic-test code and is a migration liability. `jarvis/voice/activation.py` retains a deprecated orchestrator adapter, while the canonical voice adapter targets `TaskController`.

`ApplicationStateMachine` is the intended lifecycle authority, but planning and legacy autonomy still expose separate status enums. Projection reduces divergence without eliminating duplicate models.

### Persistence ownership and migrations

Runtime ownership is explicit: state, planning, memory, and audit each have a SQLite store, and the runtime closes each store. Planning restart reconciliation and state projection are wired. These are not one transaction boundary, so crashes can leave cross-database records requiring reconciliation. Memory and knowledge are context stores, not task-control authorities. Approval receipts are not persisted as reusable authority.

### Security boundaries

Model output is untrusted through strict schemas and trusted action descriptors. Host effects are behind registered tools and the broker. Policy is deny-by-default; the canonical runtime has no approval-context minting authenticator, so approval is denied. Audit intent precedes effects and unknown-effect recovery is represented. External discovery/knowledge remains data and cannot grant authority. UI receives application services, not broker/provider authority.

Remaining same-process risks are documented: Python providers/integrations are not OS-isolated, generated improvement code is not a security sandbox, and an authenticated local approval service is still required before privileged providers can be enabled.

### Production wiring

`desktop/API → ApplicationRuntime → JarvisAssistantService/TaskController → PlanningEngine → ToolRegistry → Tool.invoke → PermissionBroker → policy/approval/audit`

The default catalog is intentionally limited to safe tools. Optional service-specific adapters are library code, not silently enabled capabilities. This matches the minimal adaptive-core architecture.

### Dead or compatibility code

`AgentOrchestrator` and its in-memory autonomy store are compatibility-era code, not a second production route. Phase-specific adapters remain useful contracts/tests but must not be described as default capabilities. `jarvis/security` is now an active startup/integrity boundary; older audit text calling it only a marker is obsolete.

## Blockers and risks

1. Finish the `AgentOrchestrator` migration/quarantine plan and converge status ownership without breaking compatibility tests.
2. Decide whether cross-store recovery needs a coordinator or whether independent durability is the accepted v1 contract.
3. Provide authenticated local approval before enabling privileged production providers; remote approval remains forbidden.
4. Add lower-privilege process/RPC isolation and executable identity enforcement before trusting user-created integrations.
5. Validate real Windows UI, camera, microphone, application/package, and approval flows manually.
6. Keep generated knowledge revision-pinned and refreshed explicitly; it remains context, never policy.

## Exact validation

| Command | Result |
|---|---|
| `python scripts/quality.py` | BLOCKED: `C:\Python314\python.exe: No module named ruff` |
| `python scripts/run_system_tests.py --suite deterministic-workflows` | BLOCKED: `ModuleNotFoundError: No module named 'httpx'` |

The CI workflow installs `requirements-dev.lock` on Windows Python 3.12 before running both commands. No local pass is claimed because this environment lacks the locked dependencies.

## Unexecuted hardware/manual tests

No real hardware or interactive acceptance test was executed: Windows UI Automation, desktop control, physical camera capture, microphone/wake-word/VAD/STT/TTS, application launch/close/install/update, authenticated local approval UI, executable identity/signing checks, OS sandboxing, and deployment/release workflows remain unvalidated. Deterministic fakes and fixtures do not count as hardware validation.

## Next run

Install the locked development dependencies in the intended Python 3.12 environment and rerun both requested commands. Then make one focused decision about legacy-orchestrator migration and cross-store recovery. Do not enable new integrations as part of that decision; preserve the brokered minimal-core boundary and add only targeted regression tests/documentation.
