"""Generic safe presentation surfaces and actual UI-state verification.

Presentation is an application capability, not a product board and not an
execution authority.  Content is either an opaque artifact/package reference
or bounded declarative data.  No filesystem path, executable callback, HTML,
JavaScript, or Python source is accepted by these contracts.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID, uuid4

from jarvis.artifacts import ArtifactReference, ArtifactStore


class PresentationError(RuntimeError):
    """A presentation request or observed surface state is unsafe or invalid."""


class PresentationValidationError(PresentationError, ValueError):
    """Presentation content failed its strict declarative/reference contract."""


class PresentationKind(StrEnum):
    ARTIFACT = "artifact"
    IMAGE = "image"
    DOCUMENT = "document"
    CHART = "chart"
    PLAN = "plan"
    MODEL_COMPARISON = "model_comparison"
    CONTROL = "control"
    DECLARATIVE_VIEW = "declarative_view"


_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_STORAGE_REFERENCE = re.compile(r"^[0-9a-f]{32}-[0-9]+-[0-9a-f]{32}\.bin$")
_MAX_PRESENTATION_ENTRIES = 128
_FORBIDDEN_KEYS = frozenset(
    {
        "code",
        "eval",
        "exec",
        "file",
        "filename",
        "filepath",
        "html",
        "javascript",
        "markup",
        "path",
        "python",
        "script",
        "src",
    }
)


def _id(value: object, field: str) -> str:
    if type(value) is not str or not _SAFE_ID.fullmatch(value):
        raise PresentationValidationError(f"{field} is malformed")
    return value


def _text(value: object, field: str, limit: int = 512, *, allow_empty: bool = False) -> str:
    if (
        type(value) is not str
        or len(value) > limit
        or (not allow_empty and not value.strip())
        or "\x00" in value
        or "<script" in value.casefold()
        or "javascript:" in value.casefold()
    ):
        raise PresentationValidationError(f"{field} is malformed")
    return value


def _declarative(value: object, *, depth: int = 0, field: str = "data") -> object:
    """Validate JSON-like data without permitting executable or path-bearing data."""

    if depth > 6:
        raise PresentationValidationError(f"{field} is too deeply nested")
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        if value != value or value in {float("inf"), float("-inf")}:
            raise PresentationValidationError(f"{field} contains a non-finite number")
        return value
    if type(value) is str:
        return _text(value, field, 4_000, allow_empty=True)
    if isinstance(value, Mapping):
        if len(value) > 64:
            raise PresentationValidationError(f"{field} has too many properties")
        result: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str or not _SAFE_ID.fullmatch(key) or key in _FORBIDDEN_KEYS:
                raise PresentationValidationError(f"{field} contains an unsafe property name")
            result[key] = _declarative(item, depth=depth + 1, field=f"{field}.{key}")
        return MappingProxyType(result)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        if len(value) > 128:
            raise PresentationValidationError(f"{field} has too many items")
        return tuple(
            _declarative(item, depth=depth + 1, field=f"{field}[{index}]")
            for index, item in enumerate(value)
        )
    raise PresentationValidationError(f"{field} contains an unsupported value")


@dataclass(frozen=True, slots=True)
class PackageAssetReference:
    """Opaque reference to a validated package-owned asset; it contains no path."""

    package_id: str
    asset_id: str
    version: str
    content_hash: str

    def __post_init__(self) -> None:
        _id(self.package_id, "Package ID")
        _id(self.asset_id, "Asset ID")
        _text(self.version, "Asset version", 64)
        if type(self.content_hash) is not str or not _HASH.fullmatch(self.content_hash):
            raise PresentationValidationError("Asset content hash is malformed")


@dataclass(frozen=True, slots=True)
class PresentationContent:
    """One safe item that can be shown without arbitrary-path rendering."""

    kind: PresentationKind
    title: str
    artifact: ArtifactReference | None = None
    package_asset: PackageAssetReference | None = None
    data: Mapping[str, object] | None = None
    presentation_id: UUID | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, PresentationKind):
            raise PresentationValidationError("Presentation kind is malformed")
        _text(self.title, "Presentation title", 512, allow_empty=True)
        if self.artifact is not None and not isinstance(self.artifact, ArtifactReference):
            raise PresentationValidationError("Artifact reference is malformed")
        if self.package_asset is not None and not isinstance(
            self.package_asset, PackageAssetReference
        ):
            raise PresentationValidationError("Package asset reference is malformed")
        if self.artifact is not None and self.package_asset is not None:
            raise PresentationValidationError("Presentation content has multiple references")
        if self.data is not None:
            validated = _declarative(self.data, field="presentation.data")
            if not isinstance(validated, Mapping):
                raise PresentationValidationError("Presentation data must be an object")
            object.__setattr__(self, "data", validated)
        if self.presentation_id is not None and not isinstance(self.presentation_id, UUID):
            raise PresentationValidationError("Presentation ID is malformed")
        if (
            self.kind
            in {
                PresentationKind.ARTIFACT,
                PresentationKind.IMAGE,
                PresentationKind.DOCUMENT,
            }
            and self.artifact is None
            and self.package_asset is None
        ):
            raise PresentationValidationError("This presentation kind requires a safe reference")
        if (
            self.kind
            in {
                PresentationKind.CHART,
                PresentationKind.PLAN,
                PresentationKind.MODEL_COMPARISON,
                PresentationKind.CONTROL,
                PresentationKind.DECLARATIVE_VIEW,
            }
            and self.data is None
        ):
            raise PresentationValidationError("This presentation kind requires declarative data")

    @classmethod
    def from_artifact(
        cls, kind: PresentationKind, reference: ArtifactReference, *, title: str = ""
    ) -> PresentationContent:
        return cls(kind=kind, title=title, artifact=reference)

    @classmethod
    def from_package_asset(
        cls, kind: PresentationKind, reference: PackageAssetReference, *, title: str = ""
    ) -> PresentationContent:
        return cls(kind=kind, title=title, package_asset=reference)

    @classmethod
    def declarative(
        cls,
        kind: PresentationKind,
        data: Mapping[str, object],
        *,
        title: str = "",
    ) -> PresentationContent:
        return cls(kind=kind, title=title, data=data)


@dataclass(frozen=True, slots=True)
class PresentationEntry:
    presentation_id: UUID
    content: PresentationContent
    generation: int
    content_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.presentation_id, UUID) or not isinstance(
            self.content, PresentationContent
        ):
            raise PresentationValidationError("Presentation entry is malformed")
        if type(self.generation) is not int or self.generation < 1:
            raise PresentationValidationError("Presentation generation is malformed")
        if type(self.content_hash) is not str or not _HASH.fullmatch(self.content_hash):
            raise PresentationValidationError("Presentation content hash is malformed")


@dataclass(frozen=True, slots=True)
class UiStateReference:
    presentation_id: UUID
    kind: PresentationKind
    title: str
    generation: int
    content_hash: str
    artifact: ArtifactReference | None = None
    package_asset: PackageAssetReference | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.presentation_id, UUID) or not isinstance(
            self.kind, PresentationKind
        ):
            raise PresentationValidationError("UI state reference is malformed")
        _text(self.title, "UI state title", 512, allow_empty=True)
        if type(self.generation) is not int or self.generation < 1:
            raise PresentationValidationError("UI state generation is malformed")
        if type(self.content_hash) is not str or not _HASH.fullmatch(self.content_hash):
            raise PresentationValidationError("UI state content hash is malformed")
        if self.artifact is not None and not isinstance(self.artifact, ArtifactReference):
            raise PresentationValidationError("UI state artifact reference is malformed")
        if self.artifact is not None and not _ARTIFACT_STORAGE_REFERENCE.fullmatch(
            self.artifact.storage_reference
        ):
            raise PresentationValidationError("UI state artifact reference is unsafe")
        if self.package_asset is not None and not isinstance(
            self.package_asset, PackageAssetReference
        ):
            raise PresentationValidationError("UI state package asset reference is malformed")
        if self.artifact is not None and self.package_asset is not None:
            raise PresentationValidationError("UI state reference has multiple sources")


@dataclass(frozen=True, slots=True)
class UiStateSnapshot:
    surface_id: str
    revision: int
    captured_at: datetime
    references: tuple[UiStateReference, ...]
    state_fingerprint: str

    def __post_init__(self) -> None:
        _id(self.surface_id, "Presentation surface ID")
        if type(self.revision) is not int or self.revision < 0:
            raise PresentationValidationError("UI state revision is malformed")
        if self.captured_at.tzinfo is None:
            raise PresentationValidationError("UI state timestamp must be timezone-aware")
        if type(self.references) is not tuple or any(
            not isinstance(item, UiStateReference) for item in self.references
        ):
            raise PresentationValidationError("UI state references are malformed")
        if len({item.presentation_id for item in self.references}) != len(self.references):
            raise PresentationValidationError("UI state references are not unique")
        if type(self.state_fingerprint) is not str or not _HASH.fullmatch(self.state_fingerprint):
            raise PresentationValidationError("UI state fingerprint is malformed")


PresentationRenderer = Callable[[str, tuple[PresentationEntry, ...]], Awaitable[None]]
PresentationObserver = Callable[[str], Awaitable[tuple[PresentationEntry, ...] | UiStateSnapshot]]


class PresentationSurface:
    """Typed surface whose query reflects the currently observed presentation."""

    def __init__(
        self,
        surface_id: str,
        *,
        workspace_id: str | None = None,
        artifact_store: ArtifactStore | None = None,
        renderer: PresentationRenderer | None = None,
        observer: PresentationObserver | None = None,
    ) -> None:
        self._surface_id = _id(surface_id, "Presentation surface ID")
        self._workspace_id = workspace_id
        if workspace_id is not None:
            _id(workspace_id, "Presentation workspace ID")
        self._artifact_store = artifact_store
        self._renderer = renderer
        self._observer = observer
        self._entries: tuple[PresentationEntry, ...] = ()
        self._revision = 0

    async def present(
        self,
        content: PresentationContent | Sequence[PresentationContent],
        *,
        replace: bool = True,
    ) -> UiStateSnapshot:
        requested: tuple[PresentationContent, ...]
        if isinstance(content, PresentationContent):
            requested = (content,)
        elif isinstance(content, Sequence) and not isinstance(content, str | bytes | bytearray):
            requested = tuple(content)
        else:
            raise PresentationValidationError("Presentation content must be typed content")
        if not isinstance(replace, bool) or any(
            not isinstance(item, PresentationContent) for item in requested
        ):
            raise PresentationValidationError("Presentation content collection is malformed")
        entries = list(self._entries if not replace else ())
        if len(entries) + len(requested) > _MAX_PRESENTATION_ENTRIES:
            raise PresentationValidationError("Presentation surface has too many entries")
        next_generation = max((item.generation for item in entries), default=0) + 1
        for item in requested:
            self._validate_reference(item)
            presentation_id = item.presentation_id or uuid4()
            entries.append(
                PresentationEntry(
                    presentation_id,
                    item,
                    next_generation,
                    _content_hash(item),
                )
            )
        if len({item.presentation_id for item in entries}) != len(entries):
            raise PresentationValidationError("Presentation IDs must be unique")
        candidate = tuple(entries)
        if self._renderer is not None:
            await self._renderer(self._surface_id, candidate)
        self._entries = candidate
        self._revision += 1
        return _snapshot(self._surface_id, self._revision, candidate)

    async def query_state(self) -> UiStateSnapshot:
        """Return observed actual state, not merely the last requested state."""

        if self._observer is not None:
            observed = await self._observer(self._surface_id)
            if isinstance(observed, UiStateSnapshot):
                if observed.surface_id != self._surface_id:
                    raise PresentationError("Presentation observer returned another surface")
                return observed
            if not isinstance(observed, tuple) or any(
                not isinstance(item, PresentationEntry) for item in observed
            ):
                raise PresentationError("Presentation observer returned malformed state")
            for item in observed:
                self._validate_reference(item.content)
            return _snapshot(self._surface_id, self._revision, observed)
        return _snapshot(self._surface_id, self._revision, self._entries)

    def _validate_reference(self, content: PresentationContent) -> None:
        if content.artifact is None:
            return
        if (
            not isinstance(content.artifact.artifact_id, UUID)
            or type(content.artifact.version) is not int
            or content.artifact.version < 1
            or not _ARTIFACT_STORAGE_REFERENCE.fullmatch(content.artifact.storage_reference)
        ):
            raise PresentationValidationError("Artifact reference is malformed")
        if self._workspace_id is None or content.artifact.workspace_id != self._workspace_id:
            raise PresentationValidationError("Artifact reference is outside the surface workspace")
        if self._artifact_store is not None:
            try:
                version = self._artifact_store.get_version(
                    content.artifact,
                    workspace_id=self._workspace_id,
                )
            except (KeyError, PermissionError, ValueError) as error:
                raise PresentationValidationError("Artifact reference is not available") from error
            if version.classification.value == "credential_secret":
                raise PresentationValidationError("Credential secrets cannot be presented")


class PresentationVerificationStatus(StrEnum):
    VERIFIED = "verified"
    MISMATCH = "mismatch"


@dataclass(frozen=True, slots=True)
class PresentationVerificationResult:
    status: PresentationVerificationStatus
    expected_fingerprint: str
    actual_fingerprint: str
    missing: tuple[UUID, ...] = ()
    unexpected: tuple[UUID, ...] = ()


class VerificationEngine:
    """Compare intended presentation against a surface's actual queried state."""

    def compare(
        self,
        intended: UiStateSnapshot,
        actual: UiStateSnapshot,
    ) -> PresentationVerificationResult:
        if intended.surface_id != actual.surface_id:
            raise PresentationValidationError("Cannot compare different presentation surfaces")
        expected_ids = {item.presentation_id for item in intended.references}
        actual_ids = {item.presentation_id for item in actual.references}
        missing = tuple(sorted(expected_ids - actual_ids, key=str))
        unexpected = tuple(sorted(actual_ids - expected_ids, key=str))
        status = (
            PresentationVerificationStatus.VERIFIED
            if (
                intended.state_fingerprint == actual.state_fingerprint
                and not missing
                and not unexpected
            )
            else PresentationVerificationStatus.MISMATCH
        )
        return PresentationVerificationResult(
            status,
            intended.state_fingerprint,
            actual.state_fingerprint,
            missing,
            unexpected,
        )

    async def verify_surface(
        self, surface: PresentationSurface, intended: UiStateSnapshot
    ) -> PresentationVerificationResult:
        return self.compare(intended, await surface.query_state())


def _content_hash(content: PresentationContent) -> str:
    payload = {
        "kind": content.kind.value,
        "title": content.title,
        "artifact": _reference_json(content.artifact),
        "package_asset": _reference_json(content.package_asset),
        "data": content.data,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _reference_json(value: object) -> object:
    if isinstance(value, ArtifactReference):
        return {
            "artifact_id": str(value.artifact_id),
            "version": value.version,
            "workspace_id": value.workspace_id,
            "storage_reference": value.storage_reference,
        }
    if isinstance(value, PackageAssetReference):
        return {
            "package_id": value.package_id,
            "asset_id": value.asset_id,
            "version": value.version,
            "content_hash": value.content_hash,
        }
    return None


def _snapshot(
    surface_id: str,
    revision: int,
    entries: tuple[PresentationEntry, ...],
) -> UiStateSnapshot:
    references = tuple(
        UiStateReference(
            item.presentation_id,
            item.content.kind,
            item.content.title,
            item.generation,
            item.content_hash,
            item.content.artifact,
            item.content.package_asset,
        )
        for item in entries
    )
    fingerprint_payload = [
        {
            "id": str(item.presentation_id),
            "kind": item.kind.value,
            "title": item.title,
            "generation": item.generation,
            "hash": item.content_hash,
        }
        for item in references
    ]
    fingerprint = hashlib.sha256(
        json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return UiStateSnapshot(surface_id, revision, datetime.now(UTC), references, fingerprint)


__all__ = [
    "PackageAssetReference",
    "PresentationContent",
    "PresentationEntry",
    "PresentationError",
    "PresentationKind",
    "PresentationRenderer",
    "PresentationSurface",
    "PresentationValidationError",
    "PresentationVerificationResult",
    "PresentationVerificationStatus",
    "UiStateReference",
    "UiStateSnapshot",
    "VerificationEngine",
]
