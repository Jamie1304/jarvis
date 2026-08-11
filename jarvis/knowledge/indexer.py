"""Repository index generation from source files, docs, and trusted registries."""

from __future__ import annotations

import ast
import hashlib
import inspect
import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from jarvis.knowledge.models import (
    Authority,
    ComponentRecord,
    KnowledgeItem,
    KnowledgeSnapshot,
    Provenance,
    ToolPermissionRecord,
)
from jarvis.permissions.models import Permission
from jarvis.tools.registry import ToolRegistry

Clock = Callable[[], datetime]
_SECRET_PATH = re.compile(r"(^|[._-])(env|secret|credential|password|token)([._-]|$)", re.I)
_SECRET_VALUE = re.compile(
    r"(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret)"
    r"\s*[:=]\s*['\"](?!(?:secret|password|token)['\"])[^'\"]+['\"]",
    re.I,
)
_TOKEN_VALUE = re.compile(r"\b(?:gh[oprsu]|sk)-[A-Za-z0-9_-]{12,}\b")
_LAYER = {
    "ai": "provider",
    "applications": "controlled-capability",
    "autonomy": "orchestration",
    "camera": "controlled-capability",
    "computer": "controlled-capability",
    "conversation": "application-service",
    "core": "cross-cutting",
    "discovery": "advisory-capability",
    "frontend": "presentation",
    "improvement": "proposal-only-improvement",
    "memory": "reserved-domain",
    "permissions": "security-boundary",
    "security": "security-boundary",
    "speech": "provider",
    "tools": "capability-boundary",
    "vision": "controlled-capability",
}


class ProjectKnowledgeBuilder:
    """Build a deterministic generated index while preserving human-authored docs."""

    def __init__(self, project_root: Path, *, clock: Clock | None = None) -> None:
        self.project_root = project_root.resolve()
        self._clock = clock or (lambda: datetime.now(UTC))

    def build(self, *, registry: ToolRegistry | None = None) -> KnowledgeSnapshot:
        generated_at = self._clock().astimezone(UTC)
        revision = self._git_revision()
        components = self._components(generated_at, revision)
        tools = self._tools(registry or ToolRegistry(), generated_at, revision)
        items = list(self._documentation_items(generated_at, revision))
        items.extend(self._component_items(components, generated_at))
        items.extend(self._tool_items(tools, generated_at, revision))
        items.extend(self._permission_items(generated_at, revision))
        items.append(self._project_tree_item(generated_at, revision))
        items.sort(key=lambda item: (item.kind, item.item_id))
        return KnowledgeSnapshot(
            schema_version=1,
            generated_at=generated_at,
            revision=revision,
            items=tuple(items),
            components=tuple(components),
            tools=tuple(tools),
            permissions=tuple(permission.value for permission in Permission),
        )

    def refresh(
        self, output_path: Path, *, registry: ToolRegistry | None = None
    ) -> KnowledgeSnapshot:
        """Build and write one generated artifact under the caller-selected directory."""

        snapshot = self.build(registry=registry)
        output_path = output_path.resolve()
        if not output_path.is_relative_to(self.project_root / "knowledge" / "generated"):
            raise ValueError("Generated knowledge must be written under knowledge/generated")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(snapshot.to_json(), encoding="utf-8", newline="\n")
        return snapshot

    def _documentation_items(
        self, generated_at: datetime, revision: str | None
    ) -> tuple[KnowledgeItem, ...]:
        items: list[KnowledgeItem] = []
        documentation_paths = list((self.project_root / "docs").rglob("*.md"))
        documentation_paths.extend(
            path
            for path in (
                self.project_root / name
                for name in (
                    "README.md",
                    "CONTRIBUTING.md",
                    "CHANGELOG.md",
                )
            )
            if path.exists()
        )
        for path in sorted(documentation_paths):
            relative = self._relative(path)
            text = self._read_safe(path)
            if text is None:
                continue
            title = self._markdown_title(text) or path.stem.replace("-", " ").title()
            authority = (
                Authority.HISTORICAL
                if relative.startswith("docs/decisions/")
                else Authority.AUTHORITATIVE
            )
            kind = "decision" if authority is Authority.HISTORICAL else "documentation"
            provenance = self._provenance((relative,), generated_at, revision)
            items.append(
                KnowledgeItem(
                    item_id=relative.removesuffix(".md").replace("/", ":"),
                    kind=kind,
                    title=title,
                    summary=self._summary(text),
                    content=text,
                    authority=authority,
                    provenance=provenance,
                    metadata=(("path", relative),),
                )
            )
        return tuple(items)

    def _project_tree_item(self, generated_at: datetime, revision: str | None) -> KnowledgeItem:
        paths = self._repository_files()
        provenance = self._provenance(paths, generated_at, revision)
        tree = "\n".join(paths)
        return KnowledgeItem(
            item_id="project-tree",
            kind="project-tree",
            title="Project tree",
            summary="Generated list of safe repository source, documentation, and workflow files.",
            content=tree,
            authority=Authority.GENERATED,
            provenance=provenance,
        )

    def _components(
        self, generated_at: datetime, revision: str | None
    ) -> tuple[ComponentRecord, ...]:
        package_root = self.project_root / "jarvis"
        records: list[ComponentRecord] = []
        for init in sorted(package_root.glob("*/__init__.py")):
            name = init.parent.name
            files = tuple(self._relative(path) for path in sorted(init.parent.rglob("*.py")))
            safe_files = tuple(
                path for path in files if self._read_safe(self.project_root / path) is not None
            )
            if not safe_files:
                continue
            interfaces, dependencies = self._python_metadata(
                [self.project_root / path for path in safe_files]
            )
            init_text = self._read_safe(init) or ""
            purpose = ast.get_docstring(ast.parse(init_text)) or f"{name} project component"
            provenance = self._provenance(safe_files, generated_at, revision)
            records.append(
                ComponentRecord(
                    name=name,
                    purpose=purpose.splitlines()[0].strip(),
                    public_interfaces=interfaces,
                    dependencies=dependencies,
                    relevant_files=safe_files,
                    architectural_layer=_LAYER.get(name, "domain"),
                    provenance=provenance,
                )
            )
        return tuple(records)

    def _tools(
        self, registry: ToolRegistry, generated_at: datetime, revision: str | None
    ) -> tuple[ToolPermissionRecord, ...]:
        records: list[ToolPermissionRecord] = []
        for manifest in sorted(registry.manifests(), key=lambda item: item.tool_id):
            source_files = {"jarvis/tools/registry.py"}
            for schema in (manifest.input_schema, manifest.output_schema):
                module = inspect.getmodule(schema)
                if module is not None:
                    source = inspect.getsourcefile(module)
                    if source:
                        source_files.add(self._relative(Path(source)))
            provenance = self._provenance(tuple(sorted(source_files)), generated_at, revision)
            records.append(
                ToolPermissionRecord(
                    tool_id=manifest.tool_id,
                    name=manifest.name,
                    description=manifest.description,
                    version=str(manifest.version),
                    permissions=tuple(
                        sorted(permission.value for permission in manifest.declared_permissions)
                    ),
                    capabilities=tuple(sorted(manifest.capabilities)),
                    platforms=tuple(
                        sorted(platform.value for platform in manifest.supported_platforms)
                    ),
                    input_schema=f"{manifest.input_schema.__module__}.{manifest.input_schema.__qualname__}",
                    output_schema=f"{manifest.output_schema.__module__}.{manifest.output_schema.__qualname__}",
                    status=manifest.status.value,
                    provenance=provenance,
                )
            )
        return tuple(records)

    def _component_items(
        self, components: tuple[ComponentRecord, ...], generated_at: datetime
    ) -> tuple[KnowledgeItem, ...]:
        return tuple(
            KnowledgeItem(
                item_id=f"component:{component.name}",
                kind="component",
                title=component.name,
                summary=component.purpose,
                content=(
                    f"{component.purpose} Layer: {component.architectural_layer}. "
                    f"Interfaces: {', '.join(component.public_interfaces)}. "
                    f"Dependencies: {', '.join(component.dependencies)}."
                ),
                authority=Authority.GENERATED,
                provenance=component.provenance,
                metadata=(("layer", component.architectural_layer),),
            )
            for component in components
        )

    def _tool_items(
        self,
        tools: tuple[ToolPermissionRecord, ...],
        generated_at: datetime,
        revision: str | None,
    ) -> tuple[KnowledgeItem, ...]:
        del generated_at, revision
        return tuple(
            KnowledgeItem(
                item_id=f"tool:{tool.tool_id}",
                kind="tool",
                title=tool.name,
                summary=tool.description,
                content=(
                    f"Tool {tool.tool_id} capabilities: {', '.join(tool.capabilities)}. "
                    f"Permissions: {', '.join(tool.permissions) or 'none'}. "
                    f"Input: {tool.input_schema}; output: {tool.output_schema}."
                ),
                authority=Authority.GENERATED,
                provenance=tool.provenance,
                metadata=(("tool_id", tool.tool_id),),
            )
            for tool in tools
        )

    def _permission_items(
        self, generated_at: datetime, revision: str | None
    ) -> tuple[KnowledgeItem, ...]:
        relative = "jarvis/permissions/models.py"
        provenance = self._provenance((relative,), generated_at, revision)
        return tuple(
            KnowledgeItem(
                item_id=f"permission:{permission.value}",
                kind="permission",
                title=permission.value,
                summary=f"Granular broker permission {permission.value}",
                content=(
                    f"{permission.value} is declared by trusted tool manifests and evaluated "
                    "by PermissionBroker; model text cannot grant it."
                ),
                authority=Authority.GENERATED,
                provenance=provenance,
            )
            for permission in Permission
        )

    def _python_metadata(self, paths: list[Path]) -> tuple[tuple[str, ...], tuple[str, ...]]:
        interfaces: set[str] = set()
        dependencies: set[str] = set()
        for path in paths:
            text = self._read_safe(path)
            if text is None:
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                    if not node.name.startswith("_"):
                        interfaces.add(node.name)
                elif isinstance(node, ast.Import):
                    dependencies.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    dependencies.add(node.module.split(".")[0])
        return tuple(sorted(interfaces)), tuple(sorted(dependencies))

    def _repository_files(self) -> tuple[str, ...]:
        roots = (".github", "jarvis", "docs", "scripts", "tests")
        paths = {
            self._relative(path)
            for root in roots
            for path in (self.project_root / root).rglob("*")
            if path.is_file() and self._read_safe(path) is not None
        }
        paths.update(
            self._relative(path)
            for path in (
                self.project_root / "README.md",
                self.project_root / "CONTRIBUTING.md",
                self.project_root / "pyproject.toml",
            )
            if path.exists() and self._read_safe(path) is not None
        )
        return tuple(sorted(paths))

    def _provenance(
        self, relative_paths: tuple[str, ...], generated_at: datetime, revision: str | None
    ) -> Provenance:
        paths = tuple(sorted(set(relative_paths)))
        hashes = tuple(
            (path, hashlib.sha256((self.project_root / path).read_bytes()).hexdigest())
            for path in paths
        )
        return Provenance(paths, hashes, generated_at, revision)

    def _read_safe(self, path: Path) -> str | None:
        relative = self._relative(path)
        if self._sensitive_path(relative):
            return None
        try:
            data = path.read_bytes()
            text = data.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        if _SECRET_VALUE.search(text) or _TOKEN_VALUE.search(text):
            return None
        return text

    def _git_revision(self) -> str | None:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.project_root,
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        revision = result.stdout.strip().lower()
        return revision if re.fullmatch(r"[0-9a-f]{40}", revision) else None

    def _relative(self, path: Path) -> str:
        return path.resolve().relative_to(self.project_root).as_posix()

    @staticmethod
    def _sensitive_path(relative: str) -> bool:
        name = Path(relative).name
        return name == ".env" or name.startswith(".env.") or bool(_SECRET_PATH.search(name))

    @staticmethod
    def _markdown_title(text: str) -> str | None:
        for line in text.splitlines():
            if line.startswith("# "):
                return line[2:].strip()
        return None

    @staticmethod
    def _summary(text: str) -> str:
        lines = [
            line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")
        ]
        return " ".join(lines)[:400]
