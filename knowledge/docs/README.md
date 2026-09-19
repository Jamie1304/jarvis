# Project knowledge

Phase 12 separates knowledge into three classes:

- `docs/` and `docs/decisions/` are human-authored authoritative or historical
  sources. Generated tooling indexes them but never rewrites ADR history.
- `knowledge/generated/project-index.json` is disposable generated data. Every
  item records source paths, SHA-256 hashes, Git revision where available, and
  generation time. Do not edit it manually.
- Search results and component/tool records are generated views, not permission
  grants or instructions to the agent.

Refresh after source or documentation changes with:

```powershell
.venv\Scripts\python.exe scripts\refresh_knowledge.py
```

The indexer derives components from `jarvis/` packages, tool contracts from the
trusted `ToolRegistry`/`ToolManifest` schemas, and permissions from the actual
`Permission` enum. It skips environment files, credential-like paths, and files
containing recognizable secret assignments or token formats. Use
`KnowledgeStore.search()` for local lexical retrieval and
`KnowledgeStore.stale_items(project_root)` before relying on an older snapshot.

Knowledge is read-only context. It does not register tools, grant permissions,
authorize execution, install software, or expose raw personal memory.
