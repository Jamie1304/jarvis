"""Bounded local-model lifecycle management with no post-install execution."""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast

from jarvis.ai.providers.registry import ModelMetadata
from jarvis.hardware import (
    FitStatus,
    HardwareProfile,
    ModelInventory,
    ModelMeasurement,
)


class ModelLifecycleError(RuntimeError):
    """A model lifecycle transition could not be completed safely."""


class ModelLifecycleState(StrEnum):
    DISCOVERED = "discovered"
    COMPATIBLE = "compatible"
    COMPATIBILITY_UNKNOWN = "compatibility_unknown"
    INCOMPATIBLE = "incompatible"
    DOWNLOADING = "downloading"
    DOWNLOADED = "downloaded"
    VERIFIED = "verified"
    INSTALLED = "installed"
    LOADED = "loaded"
    UNLOADED = "unloaded"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    REPAIRING = "repairing"
    FAILED = "failed"
    REMOVED = "removed"


_UNSET = object()


@dataclass(frozen=True, slots=True)
class ModelArtifact:
    """A content-addressed download description; it contains no executable hook."""

    source: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        _text(self.source, "Model artifact source", 2_048)
        if type(self.sha256) is not str or not re.fullmatch(r"[0-9a-fA-F]{64}", self.sha256):
            raise ModelLifecycleError("Model artifact hash must be a SHA-256 digest")
        if type(self.size_bytes) is not int or self.size_bytes <= 0:
            raise ModelLifecycleError("Model artifact size must be positive")


@dataclass(frozen=True, slots=True)
class LocalModelSpec:
    model_id: str
    metadata: ModelMetadata
    artifact: ModelArtifact

    def __post_init__(self) -> None:
        _identifier(self.model_id, "Model ID")
        if self.metadata.model_id != self.model_id:
            raise ModelLifecycleError("Model specification identity does not match metadata")
        if not isinstance(self.artifact, ModelArtifact):
            raise ModelLifecycleError("Model artifact is malformed")


@dataclass(frozen=True, slots=True)
class ModelHealth:
    model_id: str
    available: bool
    detail: str
    checked_at: datetime

    def __post_init__(self) -> None:
        _identifier(self.model_id, "Model ID")
        if type(self.available) is not bool or not self.detail.strip():
            raise ModelLifecycleError("Model health is malformed")
        if self.checked_at.tzinfo is None:
            raise ModelLifecycleError("Model health timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class LocalModelRecord:
    spec: LocalModelSpec
    state: ModelLifecycleState
    installed_path: Path | None = None
    last_error: str | None = None


class ModelCatalog(Protocol):
    async def discover(self) -> tuple[LocalModelSpec, ...]:
        """Return validated model specifications from a trusted catalog."""


class ModelDownloader(Protocol):
    async def download(self, source: str, destination: Path) -> None:
        """Write bytes to the exact destination; no scripts or hooks are supported."""


class LocalModelRuntime(Protocol):
    async def load(self, spec: LocalModelSpec, path: Path) -> object:
        """Load a validated model using a provider-owned typed runtime."""

    async def unload(self, model_id: str, handle: object) -> None:
        """Unload one previously returned runtime handle."""

    async def health(self, model_id: str, handle: object) -> ModelHealth:
        """Check one loaded model."""

    async def benchmark(self, model_id: str, handle: object) -> ModelMeasurement:
        """Run a bounded trusted benchmark and return measured facts."""


class LocalModelManager:
    """Own model files and typed lifecycle transitions inside one app root."""

    def __init__(
        self,
        root: Path,
        *,
        catalog: ModelCatalog | None = None,
        downloader: ModelDownloader | None = None,
        runtime: LocalModelRuntime | None = None,
        inventory: ModelInventory | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        candidate_root = root.expanduser()
        if candidate_root.is_symlink() or candidate_root.is_junction():
            raise ModelLifecycleError("Model root is not a trusted directory")
        self._root = candidate_root.resolve()
        try:
            self._root.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise ModelLifecycleError("Model root is not a trusted directory") from error
        self._validate_root()
        self._catalog = catalog
        self._downloader = downloader
        self._runtime = runtime
        self._inventory = inventory or ModelInventory()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._records: dict[str, LocalModelRecord] = {}
        self._handles: dict[str, object] = {}

    @property
    def inventory(self) -> ModelInventory:
        return self._inventory

    def inspect(self, model_id: str) -> LocalModelRecord:
        _identifier(model_id, "Model ID")
        try:
            return self._records[model_id]
        except KeyError as error:
            raise KeyError(f"Unknown local model: {model_id}") from error

    def register(self, spec: LocalModelSpec) -> LocalModelRecord:
        if not isinstance(spec, LocalModelSpec):
            raise ModelLifecycleError("Model specification is malformed")
        if (
            spec.model_id in self._records
            and self._records[spec.model_id].state is not ModelLifecycleState.REMOVED
        ):
            raise ModelLifecycleError("Model is already registered")
        if spec.model_id not in {item.model_id for item in self._inventory.models()}:
            self._inventory.register(spec.metadata)
        record = LocalModelRecord(spec, ModelLifecycleState.DISCOVERED)
        self._records[spec.model_id] = record
        return record

    async def discover(self) -> tuple[LocalModelRecord, ...]:
        if self._catalog is None:
            return tuple(self._records.values())
        specifications = await self._catalog.discover()
        if type(specifications) is not tuple:
            raise ModelLifecycleError("Model catalog returned malformed data")
        return tuple(self.register(spec) for spec in specifications)

    def check_compatibility(
        self, model_id: str, hardware: HardwareProfile, *, concurrency: int = 1
    ) -> FitStatus:
        record = self.inspect(model_id)
        if (
            not isinstance(hardware, HardwareProfile)
            or type(concurrency) is not int
            or concurrency <= 0
        ):
            raise ModelLifecycleError("Compatibility inputs are malformed")
        metadata = record.spec.metadata
        tags = hardware.reading.compatibility_tags
        if metadata.compatibility and not metadata.compatibility.issubset(tags):
            status = FitStatus.UNKNOWN if not tags else FitStatus.INCOMPATIBLE
        elif metadata.max_concurrency is not None and concurrency > metadata.max_concurrency:
            status = FitStatus.INCOMPATIBLE
        else:
            status = _resource_fit(metadata, hardware, concurrency)
        state = {
            FitStatus.COMPATIBLE: ModelLifecycleState.COMPATIBLE,
            FitStatus.UNKNOWN: ModelLifecycleState.COMPATIBILITY_UNKNOWN,
            FitStatus.INCOMPATIBLE: ModelLifecycleState.INCOMPATIBLE,
        }[status]
        self._replace(record, state)
        return status

    async def download(self, model_id: str) -> LocalModelRecord:
        record = self.inspect(model_id)
        if self._downloader is None:
            raise ModelLifecycleError("No typed model downloader is configured")
        final = self._artifact_path(model_id)
        if await asyncio.to_thread(self._verify_file, final, record.spec.artifact):
            return self._replace(record, ModelLifecycleState.VERIFIED, final)
        partial = final.with_suffix(".part")
        self._safe_unlink(partial)
        self._replace(record, ModelLifecycleState.DOWNLOADING, None)
        try:
            await self._downloader.download(record.spec.artifact.source, partial)
            self._replace(record, ModelLifecycleState.DOWNLOADED)
            if not await asyncio.to_thread(self._verify_file, partial, record.spec.artifact):
                raise ModelLifecycleError("Downloaded model failed integrity verification")
            os.replace(partial, final)
        except BaseException as error:
            self._safe_unlink(partial)
            self._replace(record, ModelLifecycleState.FAILED, None, type(error).__name__)
            raise
        return self._replace(record, ModelLifecycleState.VERIFIED, final)

    async def verify(self, model_id: str) -> bool:
        record = self.inspect(model_id)
        valid = await asyncio.to_thread(
            self._verify_file, self._artifact_path(model_id), record.spec.artifact
        )
        self._replace(record, ModelLifecycleState.VERIFIED if valid else ModelLifecycleState.FAILED)
        return valid

    async def install(self, model_id: str) -> LocalModelRecord:
        record = self.inspect(model_id)
        if not await self.verify(model_id):
            raise ModelLifecycleError("Only an integrity-verified model may be installed")
        model_dir = self._model_dir(model_id)
        model_dir.mkdir(parents=True, exist_ok=True)
        destination = model_dir / "model.bin"
        temporary = model_dir / "model.bin.part"
        self._safe_unlink(temporary)
        await asyncio.to_thread(shutil.copyfile, self._artifact_path(model_id), temporary)
        os.replace(temporary, destination)
        return self._replace(record, ModelLifecycleState.INSTALLED, destination)

    async def load(self, model_id: str) -> LocalModelRecord:
        record = self.inspect(model_id)
        if self._runtime is None:
            raise ModelLifecycleError("No typed model runtime is configured")
        if record.installed_path is None or record.state not in {
            ModelLifecycleState.INSTALLED,
            ModelLifecycleState.UNLOADED,
            ModelLifecycleState.HEALTHY,
        }:
            raise ModelLifecycleError("Model must be installed before loading")
        self._handles[model_id] = await self._runtime.load(record.spec, record.installed_path)
        return self._replace(record, ModelLifecycleState.LOADED)

    async def unload(self, model_id: str) -> LocalModelRecord:
        record = self.inspect(model_id)
        handle = self._handles.pop(model_id, None)
        if handle is not None:
            if self._runtime is None:
                raise ModelLifecycleError("Loaded model has no runtime owner")
            await self._runtime.unload(model_id, handle)
        return self._replace(record, ModelLifecycleState.UNLOADED)

    async def health(self, model_id: str) -> ModelHealth:
        record = self.inspect(model_id)
        handle = self._handles.get(model_id)
        if handle is None or self._runtime is None:
            return ModelHealth(model_id, False, "model runtime is not loaded", self._clock())
        health = await self._runtime.health(model_id, handle)
        if not isinstance(health, ModelHealth):
            raise ModelLifecycleError("Model runtime returned malformed health")
        self._replace(
            record,
            ModelLifecycleState.HEALTHY if health.available else ModelLifecycleState.DEGRADED,
        )
        return health

    async def benchmark(self, model_id: str) -> ModelMeasurement:
        handle = self._handles.get(model_id)
        if handle is None or self._runtime is None:
            raise ModelLifecycleError("A loaded model runtime is required for benchmarking")
        measurement = await self._runtime.benchmark(model_id, handle)
        if not isinstance(measurement, ModelMeasurement) or measurement.model_id != model_id:
            raise ModelLifecycleError("Model runtime returned malformed benchmark")
        self._inventory.record_measurement(measurement)
        return measurement

    async def repair(self, model_id: str) -> LocalModelRecord:
        record = self.inspect(model_id)
        if model_id in self._handles:
            raise ModelLifecycleError("Loaded models must be unloaded before repair")
        self._replace(record, ModelLifecycleState.REPAIRING)
        if not await self.verify(model_id):
            await self.download(model_id)
        return await self.install(model_id)

    async def remove(self, model_id: str) -> LocalModelRecord:
        record = self.inspect(model_id)
        if model_id in self._handles:
            raise ModelLifecycleError("Unload the model before removal")
        model_dir = self._model_dir(model_id)
        self._validate_child(model_dir)
        if model_dir.exists():
            await asyncio.to_thread(shutil.rmtree, model_dir)
        self._safe_unlink(self._artifact_path(model_id))
        return self._replace(record, ModelLifecycleState.REMOVED, None)

    async def aclose(self) -> None:
        for model_id in tuple(self._handles):
            await self.unload(model_id)

    def _replace(
        self,
        record: LocalModelRecord,
        state: ModelLifecycleState,
        installed_path: Path | None | object = _UNSET,
        error: str | None = None,
    ) -> LocalModelRecord:
        path = (
            record.installed_path if installed_path is _UNSET else cast(Path | None, installed_path)
        )
        updated = LocalModelRecord(record.spec, state, path, error)
        self._records[record.spec.model_id] = updated
        return updated

    def _model_dir(self, model_id: str) -> Path:
        return self._root / _safe_name(model_id)

    def _artifact_path(self, model_id: str) -> Path:
        return self._root / f"{_safe_name(model_id)}.download"

    def _validate_root(self) -> None:
        if self._root.is_symlink() or self._root.is_junction() or not self._root.is_dir():
            raise ModelLifecycleError("Model root is not a trusted directory")

    def _validate_child(self, path: Path) -> None:
        lexical = path.absolute()
        try:
            lexical_relative = lexical.relative_to(self._root)
        except ValueError as error:
            raise ModelLifecycleError("Model path is unsafe") from error
        if not lexical_relative.parts or any(
            part in {".", ".."} for part in lexical_relative.parts
        ):
            raise ModelLifecycleError("Model path is unsafe")
        current = self._root
        for part in lexical_relative.parts[:-1]:
            current /= part
            if current.is_symlink() or current.is_junction() or not current.is_dir():
                raise ModelLifecycleError("Model path is unsafe")
        resolved_root = self._root.resolve()
        resolved = path.resolve(strict=False)
        try:
            relative = resolved.relative_to(resolved_root)
        except ValueError as error:
            raise ModelLifecycleError("Model path is unsafe") from error
        if not relative.parts or path.is_symlink() or path.is_junction():
            raise ModelLifecycleError("Model path is unsafe")

    def _safe_unlink(self, path: Path) -> None:
        self._validate_child(path)
        if path.exists():
            if not path.is_file() or path.is_symlink() or path.is_junction():
                raise ModelLifecycleError("Model temporary path is unsafe")
            path.unlink()

    @staticmethod
    def _verify_file(path: Path, artifact: ModelArtifact) -> bool:
        if (
            not path.exists()
            or not path.is_file()
            or path.is_symlink()
            or path.is_junction()
            or path.stat().st_nlink > 1
        ):
            return False
        if path.stat().st_size != artifact.size_bytes:
            return False
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest().casefold() == artifact.sha256.casefold()


def _resource_fit(
    metadata: ModelMetadata, hardware: HardwareProfile, concurrency: int
) -> FitStatus:
    reading = hardware.reading
    unknown = False
    if metadata.storage_bytes is not None:
        if reading.disk_free_bytes is None:
            unknown = True
        elif metadata.storage_bytes > reading.disk_free_bytes:
            return FitStatus.INCOMPATIBLE
    if metadata.ram_bytes is not None:
        if reading.ram_bytes is None:
            unknown = True
        elif metadata.ram_bytes > reading.ram_bytes:
            return FitStatus.INCOMPATIBLE
    if metadata.vram_bytes is not None:
        available_vram = hardware.available_vram_bytes
        if available_vram is None:
            unknown = True
        elif metadata.vram_bytes > available_vram:
            return FitStatus.INCOMPATIBLE
    if reading.concurrency_limit is not None and concurrency > reading.concurrency_limit:
        return FitStatus.INCOMPATIBLE
    return FitStatus.UNKNOWN if unknown else FitStatus.COMPATIBLE


def _identifier(value: object, label: str) -> None:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
        raise ModelLifecycleError(f"{label} is invalid")


def _safe_name(value: str) -> str:
    return value.replace(":", "_").replace("/", "_").replace("\\", "_")


def _text(value: object, label: str, limit: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise ModelLifecycleError(f"{label} is invalid")
