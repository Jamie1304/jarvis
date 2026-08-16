"""Owned Git workspaces and the only trusted file-mutation port for Phase 11."""

from __future__ import annotations

import asyncio
import hashlib
import os
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

from jarvis.improvement.models import (
    ChangeOperation,
    ChangeSpecification,
    IsolatedWorkspace,
    ModificationResult,
    ProposedChangeSet,
    ProposedFileChange,
)
from jarvis.security import (
    MutationAuthority,
    MutationContext,
    MutationPolicy,
    MutationStage,
)

_MAX_GIT_OUTPUT = 16_384
_PROTECTED_PATHS = frozenset(
    {
        ".coveragerc",
        ".git",
        ".github/workflows",
        ".ruff.toml",
        "coverage",
        "mypy",
        "mypy.ini",
        "noxfile.py",
        "pyproject.toml",
        "pytest",
        "pytest.ini",
        "ruff",
        "ruff.toml",
        "scripts/quality.py",
        "tests",
        "tox.ini",
    }
)
_PROTECTED_FILENAMES = frozenset(
    {
        ".coveragerc",
        ".ruff.toml",
        "conftest.py",
        "coverage.py",
        "mypy.ini",
        "mypy.py",
        "noxfile.py",
        "pyproject.toml",
        "pytest.ini",
        "pytest.py",
        "ruff.toml",
        "ruff.py",
        "setup.cfg",
        "sitecustomize.py",
        "tox.ini",
        "usercustomize.py",
    }
)
_WINDOWS_RESERVED = frozenset(
    {
        "aux",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)


class WorkspaceSecurityError(RuntimeError):
    """Fail-closed workspace ownership, containment, or integrity violation."""


class WorkspaceOperationError(RuntimeError):
    """Trusted Git operation failed without exposing its raw output."""


class WorkspaceDisposition(StrEnum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    RETAINED_FOR_PROPOSAL = "retained_for_proposal"


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    root: Path
    git_directory: Path
    head_revision: str
    clean: bool


class GitWorktreeClient(ABC):
    """Trusted internal Git adapter; callers never provide arbitrary argv."""

    @abstractmethod
    async def inspect(self, repository: Path, cancellation: asyncio.Event) -> RepositorySnapshot:
        """Return canonical repository identity and immutable HEAD."""

    @abstractmethod
    async def add_detached_worktree(
        self,
        production_root: Path,
        target: Path,
        base_revision: str,
        cancellation: asyncio.Event,
    ) -> None:
        """Create one detached worktree using a fixed Git operation."""


class SubprocessGitWorktreeClient(GitWorktreeClient):  # pragma: no cover
    """No-shell Git implementation for trusted application composition."""

    def __init__(self, git_executable: Path, timeout_seconds: float = 30.0) -> None:
        executable = git_executable.resolve(strict=True)
        if not executable.is_file() or timeout_seconds <= 0:
            raise ValueError("Git executable and timeout must be valid")
        self._git = executable
        self._timeout = timeout_seconds

    async def inspect(self, repository: Path, cancellation: asyncio.Event) -> RepositorySnapshot:
        root = Path(
            await self._run(repository, ("rev-parse", "--show-toplevel"), cancellation)
        ).resolve(strict=True)
        git_directory = Path(
            await self._run(repository, ("rev-parse", "--absolute-git-dir"), cancellation)
        ).resolve(strict=True)
        revision = await self._run(repository, ("rev-parse", "HEAD"), cancellation)
        status = await self._run(
            repository,
            ("status", "--porcelain=v1", "--untracked-files=all"),
            cancellation,
            permit_empty=True,
        )
        return RepositorySnapshot(root, git_directory, revision, not status)

    async def add_detached_worktree(
        self,
        production_root: Path,
        target: Path,
        base_revision: str,
        cancellation: asyncio.Event,
    ) -> None:
        await self._run(
            production_root,
            (
                "worktree",
                "add",
                "--detach",
                os.fspath(target),
                base_revision,
            ),
            cancellation,
            permit_empty=True,
        )

    async def _run(
        self,
        repository: Path,
        arguments: tuple[str, ...],
        cancellation: asyncio.Event,
        *,
        permit_empty: bool = False,
    ) -> str:
        trusted_path = [os.fspath(self._git.parent)]
        system_root = os.environ.get("SYSTEMROOT")
        if system_root:
            trusted_path.append(os.fspath(Path(system_root) / "System32"))
        environment = {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "PATH": os.pathsep.join(trusted_path),
            "SYSTEMROOT": system_root or "",
        }
        process = await asyncio.create_subprocess_exec(
            os.fspath(self._git),
            "--no-pager",
            "-C",
            os.fspath(repository),
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "diff.external=",
            "-c",
            "core.pager=cat",
            *arguments,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        communication = asyncio.create_task(process.communicate())
        cancellation_wait = asyncio.create_task(cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {communication, cancellation_wait},
                timeout=self._timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if communication in done:
                stdout, _stderr = await communication
                if process.returncode:
                    raise WorkspaceOperationError("Trusted Git operation failed")
                output = stdout.decode("utf-8", errors="replace")[:_MAX_GIT_OUTPUT].strip()
                if not output and not permit_empty:
                    raise WorkspaceOperationError("Trusted Git operation returned no evidence")
                return output
            if process.returncode is None:
                process.kill()
            await communication
            if cancellation_wait in done:
                raise asyncio.CancelledError
            raise WorkspaceOperationError("Trusted Git operation timed out")
        finally:
            if not cancellation_wait.done():
                cancellation_wait.cancel()
            await asyncio.gather(cancellation_wait, return_exceptions=True)


class GitWorktreeManager:
    """Mint and track workspaces without accepting model-provided paths or revisions."""

    def __init__(
        self,
        production_root: Path,
        workspace_parent: Path,
        client: GitWorktreeClient,
        *,
        clock: Callable[[], datetime] | None = None,
        uuid_factory: Callable[[], UUID] | None = None,
    ) -> None:
        self._production_root = _canonical_existing_directory(production_root)
        self._workspace_parent = _canonical_existing_directory(workspace_parent)
        if _paths_overlap(self._production_root, self._workspace_parent):
            raise WorkspaceSecurityError(
                "Workspace parent and production checkout must be disjoint"
            )
        _reject_reparse_ancestors(self._workspace_parent, self._workspace_parent)
        self._client = client
        self._clock = clock or (lambda: datetime.now(UTC))
        self._uuid_factory = uuid_factory or uuid4
        self._owned: dict[str, IsolatedWorkspace] = {}
        self._dispositions: dict[str, WorkspaceDisposition] = {}

    async def create(self, candidate_id: str, cancellation: asyncio.Event) -> IsolatedWorkspace:
        if not candidate_id or any(character.isspace() for character in candidate_id):
            raise WorkspaceSecurityError("Candidate identity is malformed")
        before = await self._client.inspect(self._production_root, cancellation)
        self._validate_production_snapshot(before)
        if not before.clean:
            raise WorkspaceSecurityError("Production checkout must be clean and known-good")

        run_id = self._uuid_factory()
        workspace_id = str(run_id)
        target = self._workspace_parent / run_id.hex
        if target.exists() or target.is_symlink():
            raise WorkspaceSecurityError("Generated workspace target already exists")
        await self._client.add_detached_worktree(
            self._production_root,
            target,
            before.head_revision,
            cancellation,
        )
        created = await self._client.inspect(target, cancellation)
        canonical_target = target.resolve(strict=True)
        if (
            _normal(created.root) != _normal(canonical_target)
            or created.head_revision != before.head_revision
            or not created.clean
            or not _is_direct_child(canonical_target, self._workspace_parent)
            or not _path_is_within(created.git_directory, before.git_directory)
        ):
            raise WorkspaceSecurityError("Created worktree failed identity verification")
        _reject_reparse_ancestors(canonical_target, self._workspace_parent)
        await self._assert_snapshot_unchanged(before, cancellation)
        handle = IsolatedWorkspace(
            workspace_id=workspace_id,
            root=canonical_target,
            branch=f"detached/improvement-{run_id.hex}",
            base_revision=before.head_revision,
            created_at=self._clock(),
        )
        self._owned[workspace_id] = handle
        self._dispositions[workspace_id] = WorkspaceDisposition.ACTIVE
        return handle

    async def validate(
        self, workspace: IsolatedWorkspace, cancellation: asyncio.Event
    ) -> IsolatedWorkspace:
        owned = self._owned.get(workspace.workspace_id)
        if owned is None or owned != workspace:
            raise WorkspaceSecurityError("Workspace handle is forged or no longer owned")
        if self._dispositions[workspace.workspace_id] is not WorkspaceDisposition.ACTIVE:
            raise WorkspaceSecurityError("Workspace is not active")
        resolved = workspace.root.resolve(strict=True)
        if _normal(resolved) != _normal(workspace.root) or not _is_direct_child(
            resolved, self._workspace_parent
        ):
            raise WorkspaceSecurityError("Workspace root changed or escaped its owned parent")
        _reject_reparse_ancestors(resolved, self._workspace_parent)
        snapshot = await self._client.inspect(resolved, cancellation)
        if snapshot.head_revision != workspace.base_revision or _normal(snapshot.root) != _normal(
            resolved
        ):
            raise WorkspaceSecurityError("Workspace Git identity changed")
        await self.assert_production_unchanged(workspace, cancellation)
        return owned

    async def assert_production_unchanged(
        self, workspace: IsolatedWorkspace, cancellation: asyncio.Event
    ) -> None:
        owned = self._owned.get(workspace.workspace_id)
        if owned is None or owned != workspace:
            raise WorkspaceSecurityError("Unknown workspace cannot attest production integrity")
        snapshot = await self._client.inspect(self._production_root, cancellation)
        self._validate_production_snapshot(snapshot)
        if snapshot.head_revision != workspace.base_revision or not snapshot.clean:
            self.quarantine(workspace)
            raise WorkspaceSecurityError("Production checkout changed during improvement run")

    async def assert_pristine(
        self, workspace: IsolatedWorkspace, cancellation: asyncio.Event
    ) -> None:
        await self.validate(workspace, cancellation)
        snapshot = await self._client.inspect(workspace.root, cancellation)
        if not snapshot.clean:
            self.quarantine(workspace)
            raise WorkspaceSecurityError("Baseline collection modified the pristine workspace")

    def quarantine(self, workspace: IsolatedWorkspace) -> None:
        self._set_disposition(workspace, WorkspaceDisposition.QUARANTINED)

    def retain_for_proposal(self, workspace: IsolatedWorkspace) -> None:
        self._set_disposition(workspace, WorkspaceDisposition.RETAINED_FOR_PROPOSAL)

    def disposition(self, workspace: IsolatedWorkspace) -> WorkspaceDisposition:
        owned = self._owned.get(workspace.workspace_id)
        if owned is None or owned != workspace:
            raise WorkspaceSecurityError("Workspace handle is not owned")
        return self._dispositions[workspace.workspace_id]

    def _set_disposition(
        self, workspace: IsolatedWorkspace, disposition: WorkspaceDisposition
    ) -> None:
        owned = self._owned.get(workspace.workspace_id)
        if owned is None or owned != workspace:
            raise WorkspaceSecurityError("Workspace handle is not owned")
        if self._dispositions[workspace.workspace_id] is not WorkspaceDisposition.ACTIVE:
            raise WorkspaceSecurityError("Workspace disposition is terminal")
        self._dispositions[workspace.workspace_id] = disposition

    def _validate_production_snapshot(self, snapshot: RepositorySnapshot) -> None:
        if _normal(snapshot.root) != _normal(self._production_root):
            raise WorkspaceSecurityError("Git client returned a different production root")
        if not _full_revision(snapshot.head_revision):
            raise WorkspaceSecurityError("Production HEAD is not a full immutable revision")
        if _paths_overlap(snapshot.git_directory, self._workspace_parent):
            raise WorkspaceSecurityError("Workspace parent overlaps shared Git metadata")

    async def _assert_snapshot_unchanged(
        self, expected: RepositorySnapshot, cancellation: asyncio.Event
    ) -> None:
        current = await self._client.inspect(self._production_root, cancellation)
        self._validate_production_snapshot(current)
        if current.head_revision != expected.head_revision or current.clean != expected.clean:
            raise WorkspaceSecurityError("Production changed while creating the worktree")


class TrustedWorkspaceChangeApplier:
    """Apply typed text changes after canonical, ownership, and base-digest checks."""

    def __init__(self, manager: GitWorktreeManager) -> None:
        self._manager = manager
        self._mutation_policy = MutationPolicy()
        self._proposal_context = MutationContext(
            MutationAuthority.ROUTINE_IMPROVEMENT,
            MutationStage.ISOLATED_PROPOSAL,
        )

    async def apply(
        self,
        workspace: IsolatedWorkspace,
        specification: ChangeSpecification,
        change_set: ProposedChangeSet,
        cancellation: asyncio.Event,
    ) -> ModificationResult:
        await self._manager.validate(workspace, cancellation)
        if change_set.specification_id != specification.specification_id:
            raise WorkspaceSecurityError("Change set does not match the approved specification")
        checked = tuple(
            self._check_change(workspace, specification, change) for change in change_set.changes
        )
        for change, destination in checked:
            if cancellation.is_set():
                self._manager.quarantine(workspace)
                raise asyncio.CancelledError
            self._apply_change(change, destination, workspace.root)
        await self._manager.assert_production_unchanged(workspace, cancellation)
        digest = hashlib.sha256()
        for change, _destination in checked:
            digest.update(change.path.encode("utf-8"))
            digest.update(change.operation.value.encode("ascii"))
            digest.update((change.expected_base_digest or "").encode("ascii"))
            digest.update((change.content or "").encode("utf-8"))
        return ModificationResult(
            workspace_id=workspace.workspace_id,
            changed_paths=tuple(change.path for change, _destination in checked),
            diff_digest=digest.hexdigest(),
            tree_digest=_tree_digest(workspace.root),
        )

    async def verify_unchanged(
        self,
        workspace: IsolatedWorkspace,
        modification: ModificationResult,
        cancellation: asyncio.Event,
    ) -> None:
        await self._manager.validate(workspace, cancellation)
        if modification.workspace_id != workspace.workspace_id:
            raise WorkspaceSecurityError("Modification evidence belongs to another workspace")
        if _tree_digest(workspace.root) != modification.tree_digest:
            self._manager.quarantine(workspace)
            raise WorkspaceSecurityError("Workspace changed after the trusted apply phase")

    def _check_change(
        self,
        workspace: IsolatedWorkspace,
        specification: ChangeSpecification,
        change: ProposedFileChange,
    ) -> tuple[ProposedFileChange, Path]:
        normalized = _validate_relative_change_path(change.path)
        destination = workspace.root.joinpath(*PurePosixPath(normalized).parts)
        _assert_destination_contained(destination, workspace.root)
        canonical_relative = _canonical_relative_destination(destination, workspace.root)
        if canonical_relative.casefold() != normalized.casefold():
            raise WorkspaceSecurityError("Change path has an ambiguous filesystem alias")
        if _is_protected(canonical_relative):
            raise WorkspaceSecurityError("Trusted control paths cannot be modified")
        mutation = self._mutation_policy.evaluate(canonical_relative, self._proposal_context)
        if not mutation.allowed:
            raise WorkspaceSecurityError(
                f"Trusted mutation policy denied the change ({mutation.reason.value})"
            )
        if not any(
            _path_matches_boundary(canonical_relative, boundary)
            for boundary in specification.likely_affected_paths
        ):
            raise WorkspaceSecurityError("Change is outside the specification boundaries")
        exists = destination.exists()
        if exists and _is_reparse(destination):
            raise WorkspaceSecurityError("Changed files cannot be links or junctions")
        if change.operation is ChangeOperation.CREATE and exists:
            raise WorkspaceSecurityError("Create operation cannot replace an existing path")
        if change.operation in {ChangeOperation.MODIFY, ChangeOperation.DELETE}:
            if not exists or not destination.is_file():
                raise WorkspaceSecurityError("Existing-file operation requires a regular file")
            current_digest = hashlib.sha256(destination.read_bytes()).hexdigest()
            if current_digest != change.expected_base_digest:
                raise WorkspaceSecurityError("File changed after the coding proposal was created")
            if (
                change.operation is ChangeOperation.MODIFY
                and hashlib.sha256((change.content or "").encode("utf-8")).hexdigest()
                == current_digest
            ):
                raise WorkspaceSecurityError("No-op file modifications cannot be proposed")
        return change, destination

    @staticmethod
    def _apply_change(change: ProposedFileChange, destination: Path, workspace_root: Path) -> None:
        if change.operation is ChangeOperation.DELETE:
            destination.unlink()
            return
        assert change.content is not None
        destination.parent.mkdir(parents=True, exist_ok=True)
        _assert_destination_contained(destination, workspace_root)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=destination.parent,
            prefix=".jarvis-improvement-",
            delete=False,
        ) as temporary:
            temporary.write(change.content)
            temporary_path = Path(temporary.name)
        try:
            os.replace(temporary_path, destination)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()


def _canonical_existing_directory(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise WorkspaceSecurityError("Configured workspace directory does not exist") from error
    if not resolved.is_dir() or _is_reparse(resolved):
        raise WorkspaceSecurityError("Configured workspace path must be a real directory")
    return resolved


def _normal(path: Path) -> str:
    return os.path.normcase(os.fspath(path.resolve(strict=False)))


def _paths_overlap(first: Path, second: Path) -> bool:
    first_value = _normal(first)
    second_value = _normal(second)
    try:
        common = os.path.commonpath((first_value, second_value))
    except ValueError:
        return False
    return common in {first_value, second_value}


def _path_is_within(path: Path, root: Path) -> bool:
    path_value = _normal(path)
    root_value = _normal(root)
    try:
        return os.path.commonpath((path_value, root_value)) == root_value
    except ValueError:
        return False


def _is_direct_child(path: Path, parent: Path) -> bool:
    return _normal(path.parent) == _normal(parent)


def _is_reparse(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _reject_reparse_ancestors(path: Path, root: Path) -> None:
    current = path
    root_normal = _normal(root)
    while True:
        if current.exists() and _is_reparse(current):
            raise WorkspaceSecurityError("Symlink or junction in workspace path")
        if _normal(current) == root_normal:
            return
        if current.parent == current:
            raise WorkspaceSecurityError("Workspace path escaped its configured parent")
        current = current.parent


def _full_revision(value: str) -> bool:
    return len(value) in {40, 64} and all(character in "0123456789abcdef" for character in value)


def _validate_relative_change_path(value: str) -> str:
    if not value or "\x00" in value or "\n" in value or "\r" in value or ":" in value:
        raise WorkspaceSecurityError("Change path is malformed")
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or normalized != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise WorkspaceSecurityError("Change path must be unambiguous and relative")
    for part in path.parts:
        stem = part.split(".", 1)[0].casefold()
        if part.endswith((" ", ".")) or stem in _WINDOWS_RESERVED:
            raise WorkspaceSecurityError("Change path is unsafe on Windows")
    return path.as_posix()


def _is_protected(path: str) -> bool:
    folded = path.casefold()
    return PurePosixPath(folded).name in _PROTECTED_FILENAMES or any(
        folded == item or folded.startswith(f"{item}/") for item in _PROTECTED_PATHS
    )


def _path_matches_boundary(path: str, boundary: str) -> bool:
    normalized_boundary = PurePosixPath(boundary.replace("\\", "/")).as_posix().casefold()
    folded = path.casefold()
    return folded == normalized_boundary or folded.startswith(f"{normalized_boundary}/")


def _assert_destination_contained(destination: Path, workspace_root: Path) -> None:
    _reject_reparse_ancestors(destination.parent, workspace_root)
    root = _normal(workspace_root)
    resolved = _normal(destination)
    try:
        if os.path.commonpath((root, resolved)) != root:
            raise WorkspaceSecurityError("Change destination escaped the workspace")
    except ValueError as error:
        raise WorkspaceSecurityError("Change destination changed volume") from error


def _canonical_relative_destination(destination: Path, workspace_root: Path) -> str:
    root = workspace_root.resolve(strict=True)
    unresolved_parts: list[str] = []
    existing = destination
    while not existing.exists():
        if existing == workspace_root or existing.parent == existing:
            raise WorkspaceSecurityError("Change destination has no owned existing ancestor")
        unresolved_parts.append(existing.name)
        existing = existing.parent
    canonical = existing.resolve(strict=True).joinpath(*reversed(unresolved_parts))
    try:
        return canonical.relative_to(root).as_posix()
    except ValueError as error:
        raise WorkspaceSecurityError(
            "Canonical change destination escaped the workspace"
        ) from error


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        relative = path.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if _is_reparse(path):
            raise WorkspaceSecurityError("Links and junctions are forbidden in candidate trees")
        if path.is_dir():
            continue
        if not path.is_file():
            raise WorkspaceSecurityError("Candidate tree contains a non-regular file")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()
