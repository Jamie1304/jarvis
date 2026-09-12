"""Refresh the repository-generated project knowledge index."""

from __future__ import annotations

from pathlib import Path

from jarvis.knowledge.indexer import ProjectKnowledgeBuilder
from jarvis.tools.catalog import create_safe_tool_registry


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    output = project_root / "knowledge" / "generated" / "project-index.json"
    snapshot = ProjectKnowledgeBuilder(project_root).refresh(
        output, registry=create_safe_tool_registry()
    )
    print(
        f"Generated {output.relative_to(project_root)}: "
        f"{len(snapshot.items)} items, {len(snapshot.components)} components, "
        f"{len(snapshot.tools)} tools, revision={snapshot.revision or 'unknown'}"
    )


if __name__ == "__main__":
    main()
