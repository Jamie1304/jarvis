"""Default-deny supply-chain analysis bound to immutable manifest snapshots."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from jarvis.improvement.models import (
    DependencyAssessment,
    DependencyChange,
    DependencyRecord,
    IsolatedWorkspace,
)
from jarvis.improvement.workspace import GitWorktreeManager, WorkspaceSecurityError

_MANIFEST_PATHS = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "requirements.lock",
    "requirements-dev.lock",
    "poetry.lock",
    "uv.lock",
    "Pipfile",
    "Pipfile.lock",
    "environment.yml",
    "environment.yaml",
    "conda-lock.yml",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
)
_ABSENT_DIGEST = hashlib.sha256(b"<absent>").hexdigest()


@dataclass(frozen=True, slots=True)
class ManifestDigest:
    path: str
    digest: str


@dataclass(frozen=True, slots=True)
class DependencyBaseline:
    workspace_id: str
    base_revision: str
    manifests: tuple[ManifestDigest, ...]


@dataclass(frozen=True, slots=True)
class TrustedDependencyException:
    """Exact operator-reviewed manifest transition; never created by a coding model."""

    path: str
    base_digest: str
    candidate_digest: str
    previous: DependencyRecord | None
    proposed: DependencyRecord | None
    risk_analysis: str
    reversible: bool

    def __post_init__(self) -> None:
        normalized = PurePosixPath(self.path.replace("\\", "/"))
        if (
            normalized.is_absolute()
            or normalized.as_posix() != self.path.replace("\\", "/")
            or ".." in normalized.parts
            or not _is_dependency_manifest(normalized.name)
        ):
            raise ValueError("Dependency exception must name a recognized manifest")
        if not _sha256(self.base_digest) or not _sha256(self.candidate_digest):
            raise ValueError("Dependency exception must bind exact manifest digests")
        if not self.risk_analysis.strip():
            raise ValueError("Dependency exception requires explicit risk analysis")
        if self.previous is None and self.proposed is None:
            raise ValueError("Dependency exception must describe an exact package change")


class ManifestDependencyGuard:
    """Reject all manifest changes except exact trusted, pre-analyzed transitions."""

    def __init__(
        self,
        workspace_manager: GitWorktreeManager,
        exceptions: tuple[TrustedDependencyException, ...] = (),
    ) -> None:
        keys = tuple((item.path, item.base_digest, item.candidate_digest) for item in exceptions)
        if len(keys) != len(set(keys)):
            raise ValueError("Dependency exceptions must be unique")
        self._manager = workspace_manager
        self._exceptions = {
            (item.path, item.base_digest, item.candidate_digest): item for item in exceptions
        }

    async def capture(
        self, workspace: IsolatedWorkspace, cancellation: asyncio.Event
    ) -> DependencyBaseline:
        await self._manager.validate(workspace, cancellation)
        return DependencyBaseline(
            workspace.workspace_id,
            workspace.base_revision,
            self._snapshot(workspace.root),
        )

    async def assess(
        self,
        workspace: IsolatedWorkspace,
        baseline: DependencyBaseline,
        cancellation: asyncio.Event,
    ) -> DependencyAssessment:
        await self._manager.validate(workspace, cancellation)
        if (
            baseline.workspace_id != workspace.workspace_id
            or baseline.base_revision != workspace.base_revision
        ):
            raise WorkspaceSecurityError("Dependency baseline does not belong to this workspace")
        current = self._snapshot(workspace.root)
        before = {item.path: item.digest for item in baseline.manifests}
        after = {item.path: item.digest for item in current}
        manifest_paths = tuple(sorted(set(before) | set(after), key=str.casefold))
        changed_paths = tuple(
            path
            for path in manifest_paths
            if before.get(path, _ABSENT_DIGEST) != after.get(path, _ABSENT_DIGEST)
        )
        if not changed_paths:
            return DependencyAssessment(True, "dependency_manifests_unchanged", ())

        changes: list[DependencyChange] = []
        for path in changed_paths:
            before_digest = before.get(path, _ABSENT_DIGEST)
            after_digest = after.get(path, _ABSENT_DIGEST)
            exception = self._exceptions.get((path, before_digest, after_digest))
            if exception is None:
                return DependencyAssessment(False, "unapproved_dependency_manifest_change", ())
            record = exception.proposed if exception.proposed is not None else exception.previous
            assert record is not None
            changes.append(
                DependencyChange(
                    name=record.name,
                    previous=exception.previous,
                    proposed=exception.proposed,
                    risk_analysis=exception.risk_analysis,
                )
            )
        return DependencyAssessment(True, "exact_dependency_changes_preapproved", tuple(changes))

    @staticmethod
    def _snapshot(root: Path) -> tuple[ManifestDigest, ...]:
        output: list[ManifestDigest] = []
        relatives = set(_MANIFEST_PATHS)
        for discovered in root.rglob("*"):
            if discovered.is_file() and _is_dependency_manifest(discovered.name):
                relative = discovered.relative_to(root).as_posix()
                if not relative.startswith(".git/"):
                    relatives.add(relative)
        for relative in sorted(relatives, key=str.casefold):
            path = root / relative
            if path.is_symlink() or path.is_junction():
                raise WorkspaceSecurityError("Dependency manifest cannot be a link or junction")
            if path.exists() and not path.is_file():
                raise WorkspaceSecurityError("Dependency manifest must be a regular file")
            digest = (
                hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else _ABSENT_DIGEST
            )
            output.append(ManifestDigest(relative, digest))
        return tuple(output)


def _sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _is_dependency_manifest(filename: str) -> bool:
    folded = filename.casefold()
    return (
        folded in {item.casefold() for item in _MANIFEST_PATHS}
        or folded.startswith("requirements")
        and folded.endswith((".txt", ".in", ".lock"))
        or folded.startswith("constraints")
        and folded.endswith((".txt", ".in"))
    )
