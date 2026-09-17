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

from jarvis.ai.knowledge import (
    ModelKnowledgeService,
    ModelObservation,
    identity_for,
)
from jarvis.ai.providers.registry import ModelMetadata
from jarvis.hardware import (
    FitStatus,
    HardwareProfile,
    ModelInventory,
    ModelMeasurement,
)


class ModelLifecycleError(RuntimeError):
    """A model lifecycle transition could not be completed safely."""


class ModelRemovalUnknownOutcome(ModelLifecycleError):
    """A provider removal effect has no trusted terminal evidence."""


class ModelRemovalVerificationError(ModelLifecycleError):
    """Provider truth proves a requested removal did not close."""


class ModelLifecycleState(StrEnum):
    DISCOVERED = "discovered"
    AVAILABLE = "available"
    COMPATIBLE = "compatible"
    COMPATIBILITY_UNKNOWN = "compatibility_unknown"
    INCOMPATIBLE = "incompatible"
    DOWNLOADING = "downloading"
    DOWNLOADED = "downloaded"
    VERIFIED = "verified"
    INSTALLED = "installed"
    LOADING = "loading"
    LOADED = "loaded"
    WARM = "warm"
    IN_USE = "in_use"
    IDLE = "idle"
    UNLOADING = "unloading"
    UNLOADED = "unloaded"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    REPAIRING = "repairing"
    FAILED = "failed"
    REMOVED = "removed"


_UNSET = object()


@dataclass(frozen=True, slots=True)
class ModelArtifact:
    """A content-addressed download description; it contains no executable hook."""

    source: str
    sha256: str | None
    size_bytes: int | None
    provider_digest: str | None = None
    provider_managed: bool = False

    def __post_init__(self) -> None:
        _text(self.source, "Model artifact source", 2_048)
        if self.provider_managed:
            if self.sha256 is not None and (
                type(self.sha256) is not str or not re.fullmatch(r"[0-9a-fA-F]{64}", self.sha256)
            ):
                raise ModelLifecycleError(
                    "Provider model hash must be a SHA-256 digest when present"
                )
            if self.size_bytes is not None and (
                type(self.size_bytes) is not int or self.size_bytes < 0
            ):
                raise ModelLifecycleError("Provider model size is invalid")
            if self.provider_digest is not None:
                _text(self.provider_digest, "Provider model digest", 512)
            return
        if type(self.sha256) is not str or not re.fullmatch(r"[0-9a-fA-F]{64}", self.sha256):
            raise ModelLifecycleError("Model artifact hash must be a SHA-256 digest")
        if type(self.size_bytes) is not int or self.size_bytes <= 0:
            raise ModelLifecycleError("Model artifact size must be positive")
        if self.provider_digest is not None:
            _text(self.provider_digest, "Provider model digest", 512)


@dataclass(frozen=True, slots=True)
class LocalModelSpec:
    model_id: str
    metadata: ModelMetadata
    artifact: ModelArtifact | None = None
    provider_managed: bool = False
    installed: bool = False
    loaded: bool = False
    provider_digest: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.model_id, "Model ID")
        if self.metadata.model_id != self.model_id:
            raise ModelLifecycleError("Model specification identity does not match metadata")
        if self.provider_managed:
            if self.artifact is not None and not self.artifact.provider_managed:
                raise ModelLifecycleError("Provider-managed models require provider artifacts")
            if self.provider_digest is not None:
                _text(self.provider_digest, "Provider model digest", 512)
        elif not isinstance(self.artifact, ModelArtifact) or self.artifact.provider_managed:
            raise ModelLifecycleError("Model artifact is malformed")
        if type(self.installed) is not bool or type(self.loaded) is not bool:
            raise ModelLifecycleError("Model provider state is malformed")
        if self.loaded and not self.installed:
            raise ModelLifecycleError("A loaded model must be installed or provider-available")


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


class ProviderModelAdapter(Protocol):
    """Provider-owned lifecycle operations behind a generic control-plane seam."""

    async def ensure_provider(self) -> object:
        """Adopt or start the provider according to its trusted ownership policy."""

    async def discover(self) -> tuple[LocalModelSpec, ...]:
        """Return provider-reported model and volatile lifecycle observations."""

    async def acquire(self, spec: LocalModelSpec) -> None:
        """Acquire one model through a typed provider API."""

    async def verify(self, spec: LocalModelSpec) -> bool:
        """Verify provider identity; unknown provider integrity is never fabricated."""

    async def load(self, spec: LocalModelSpec) -> object:
        """Load or warm one provider-managed model."""

    async def unload(self, model_id: str, handle: object | None) -> None:
        """Unload one provider-managed model."""

    async def remove(self, spec: LocalModelSpec) -> None:
        """Remove one provider-managed model through its typed provider API."""

    async def health(self, model_id: str, handle: object | None) -> ModelHealth:
        """Report provider truth for one model."""

    async def benchmark(self, model_id: str, handle: object) -> ModelMeasurement:
        """Run a bounded trusted provider benchmark."""

    async def recover_provider(self) -> object:
        """Perform only ownership-authorized provider recovery."""

    async def aclose(self) -> None:
        """Release provider-adapter resources."""


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
        knowledge: ModelKnowledgeService | None = None,
        provider_id: str = "local-runtime",
        provider_adapter: ProviderModelAdapter | None = None,
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
        self._knowledge = knowledge
        self._provider_id = provider_id
        self._provider_adapter = provider_adapter
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
        initial_state = (
            ModelLifecycleState.WARM
            if spec.provider_managed and spec.loaded
            else ModelLifecycleState.AVAILABLE
            if spec.provider_managed and spec.installed
            else ModelLifecycleState.DISCOVERED
        )
        record = LocalModelRecord(spec, initial_state)
        self._records[spec.model_id] = record
        if self._knowledge is not None:
            observed_at = self._clock()
            self._knowledge.record_model_observation(
                ModelObservation(
                    identity_for(self._provider_id, spec.metadata),
                    spec.metadata,
                    observed_at,
                    "local_model_manager",
                    evidence_detail="Local model manager registration; not a machine measurement",
                )
            )
        return record

    async def discover(self) -> tuple[LocalModelRecord, ...]:
        if self._provider_adapter is not None:
            specifications = await self._provider_adapter.discover()
        elif self._catalog is None:
            return tuple(self._records.values())
        else:
            specifications = await self._catalog.discover()
        if type(specifications) is not tuple:
            raise ModelLifecycleError("Model catalog returned malformed data")
        if any(not isinstance(spec, LocalModelSpec) for spec in specifications):
            raise ModelLifecycleError("Model catalog returned malformed specifications")
        current = tuple(self._register_or_reconcile(spec) for spec in specifications)
        seen = {spec.model_id for spec in specifications}
        for model_id, record in tuple(self._records.items()):
            if (
                record.spec.provider_managed
                and model_id not in seen
                and record.state is not ModelLifecycleState.REMOVED
            ):
                self._replace(
                    record,
                    ModelLifecycleState.UNAVAILABLE,
                    error="provider did not report the installed model",
                )
        return current

    async def ensure_provider(self) -> object | None:
        """Adopt/start the configured provider through its typed adapter."""

        if self._provider_adapter is None:
            return None
        return await self._provider_adapter.ensure_provider()

    async def recover_provider(self) -> object | None:
        """Recover only a provider process whose adapter owns recovery authority."""

        if self._provider_adapter is None:
            return None
        return await self._provider_adapter.recover_provider()

    def records(self) -> tuple[LocalModelRecord, ...]:
        """Return deterministic lifecycle projections for the current process."""

        return tuple(self._records[key] for key in sorted(self._records))

    def has_runtime_handle(self, model_id: str) -> bool:
        _identifier(model_id, "Model ID")
        return model_id in self._handles

    def mark_in_use(self, model_id: str) -> LocalModelRecord:
        record = self.inspect(model_id)
        if model_id not in self._handles:
            raise ModelLifecycleError("Only a loaded model may be marked in use")
        return self._replace(record, ModelLifecycleState.IN_USE)

    def mark_idle(self, model_id: str) -> LocalModelRecord:
        record = self.inspect(model_id)
        if model_id not in self._handles:
            return record
        return self._replace(record, ModelLifecycleState.IDLE)

    async def unload_idle(
        self, *, exclude: tuple[str, ...] = (), preserve: tuple[str, ...] = ()
    ) -> tuple[str, ...]:
        """Unload only idle provider models, retaining explicitly preserved fallbacks."""

        excluded = set(exclude) | set(preserve)
        unloaded: list[str] = []
        for record in self.records():
            if (
                record.spec.model_id in excluded
                or (record.spec.model_id not in self._handles and not record.spec.provider_managed)
                or record.state is ModelLifecycleState.IN_USE
                or record.state is ModelLifecycleState.UNAVAILABLE
            ):
                continue
            if record.state not in {
                ModelLifecycleState.LOADED,
                ModelLifecycleState.WARM,
                ModelLifecycleState.HEALTHY,
                ModelLifecycleState.IDLE,
            }:
                continue
            await self.unload(record.spec.model_id)
            unloaded.append(record.spec.model_id)
        return tuple(unloaded)

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
        if self._provider_adapter is not None and record.spec.provider_managed:
            await self._provider_adapter.acquire(record.spec)
            await self.discover()
            return self.inspect(model_id)
        if self._downloader is None:
            raise ModelLifecycleError("No typed model downloader is configured")
        if record.spec.artifact is None:
            raise ModelLifecycleError("A file-managed model requires an artifact")
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
        if self._provider_adapter is not None and record.spec.provider_managed:
            valid = await self._provider_adapter.verify(record.spec)
            self._replace(
                record,
                ModelLifecycleState.AVAILABLE if valid else ModelLifecycleState.DEGRADED,
            )
            return valid
        if record.spec.artifact is None:
            raise ModelLifecycleError("A file-managed model requires an artifact")
        valid = await asyncio.to_thread(
            self._verify_file, self._artifact_path(model_id), record.spec.artifact
        )
        self._replace(record, ModelLifecycleState.VERIFIED if valid else ModelLifecycleState.FAILED)
        return valid

    async def install(self, model_id: str) -> LocalModelRecord:
        record = self.inspect(model_id)
        if self._provider_adapter is not None and record.spec.provider_managed:
            await self._provider_adapter.acquire(record.spec)
            await self.discover()
            return self.inspect(model_id)
        if not await self.verify(model_id):
            raise ModelLifecycleError("Only an integrity-verified model may be installed")
        if record.spec.artifact is None:
            raise ModelLifecycleError("A file-managed model requires an artifact")
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
        if self._provider_adapter is not None and record.spec.provider_managed:
            self._replace(record, ModelLifecycleState.LOADING)
            try:
                self._handles[model_id] = await self._provider_adapter.load(record.spec)
            except BaseException as error:
                self._replace(record, ModelLifecycleState.UNAVAILABLE, error=type(error).__name__)
                raise
            return self._replace(record, ModelLifecycleState.WARM)
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
        if self._provider_adapter is not None and record.spec.provider_managed:
            self._replace(record, ModelLifecycleState.UNLOADING)
            await self._provider_adapter.unload(model_id, handle)
        elif handle is not None:
            if self._runtime is None:
                raise ModelLifecycleError("Loaded model has no runtime owner")
            else:
                await self._runtime.unload(model_id, handle)
        return self._replace(
            record,
            ModelLifecycleState.AVAILABLE
            if self._provider_adapter is not None and record.spec.provider_managed
            else ModelLifecycleState.UNLOADED,
        )

    async def health(self, model_id: str) -> ModelHealth:
        record = self.inspect(model_id)
        handle = self._handles.get(model_id)
        if self._provider_adapter is not None and record.spec.provider_managed:
            health = await self._provider_adapter.health(model_id, handle)
            if not isinstance(health, ModelHealth):
                raise ModelLifecycleError("Provider adapter returned malformed health")
            self._replace(
                record,
                ModelLifecycleState.HEALTHY
                if health.available
                else ModelLifecycleState.UNAVAILABLE,
            )
            return health
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
        record = self.inspect(model_id)
        if self._provider_adapter is not None and record.spec.provider_managed:
            if handle is None:
                raise ModelLifecycleError("A loaded provider model is required for benchmarking")
            measurement = await self._provider_adapter.benchmark(model_id, handle)
            if not isinstance(measurement, ModelMeasurement) or measurement.model_id != model_id:
                raise ModelLifecycleError("Provider adapter returned malformed benchmark")
            self._inventory.record_measurement(measurement)
            if self._knowledge is not None:
                self._knowledge.record_measurement(
                    identity_for(self._provider_id, self._inventory.inspect(model_id)), measurement
                )
            return measurement
        if handle is None or self._runtime is None:
            raise ModelLifecycleError("A loaded model runtime is required for benchmarking")
        measurement = await self._runtime.benchmark(model_id, handle)
        if not isinstance(measurement, ModelMeasurement) or measurement.model_id != model_id:
            raise ModelLifecycleError("Model runtime returned malformed benchmark")
        self._inventory.record_measurement(measurement)
        if self._knowledge is not None:
            self._knowledge.record_measurement(
                identity_for(self._provider_id, self._inventory.inspect(model_id)), measurement
            )
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
        if self._provider_adapter is not None and record.spec.provider_managed:
            raise ModelLifecycleError("Provider-managed models are never auto-removed")
        if model_id in self._handles:
            raise ModelLifecycleError("Unload the model before removal")
        model_dir = self._model_dir(model_id)
        self._validate_child(model_dir)
        if model_dir.exists():
            await asyncio.to_thread(shutil.rmtree, model_dir)
        self._safe_unlink(self._artifact_path(model_id))
        return self._replace(record, ModelLifecycleState.REMOVED, None)

    async def remove_provider_model(
        self, model_id: str, *, expected_provider_digest: str | None = None
    ) -> LocalModelRecord:
        """Remove a provider-managed model after the caller's trusted TOCTOU check.

        This method deliberately does not decide whether removal is authorized;
        the portfolio coordinator and PermissionBroker own that boundary.  It
        only revalidates provider identity, unload state, and provider truth.
        """

        record = self.inspect(model_id)
        if not record.spec.provider_managed or self._provider_adapter is None:
            raise ModelLifecycleError("provider-managed removal requires a provider adapter")
        if model_id in self._handles or record.state is ModelLifecycleState.IN_USE:
            raise ModelLifecycleError("Unload the model before provider removal")
        if expected_provider_digest is not None and (
            record.spec.provider_digest != expected_provider_digest
        ):
            raise ModelLifecycleError("provider model identity changed before removal")
        remover = getattr(self._provider_adapter, "remove", None)
        if not callable(remover):
            raise ModelLifecycleError("provider does not expose a trusted removal operation")
        try:
            await remover(record.spec)
        except ModelRemovalUnknownOutcome:
            raise
        except Exception as error:
            raise ModelRemovalUnknownOutcome(
                "provider removal effect has no trusted terminal evidence"
            ) from error
        try:
            discovered = await self._provider_adapter.discover()
        except Exception as error:
            raise ModelRemovalUnknownOutcome(
                "provider inventory could not verify removal"
            ) from error
        if any(item.model_id == model_id for item in discovered):
            raise ModelRemovalVerificationError("provider still exposes the removed model")
        return self._replace(record, ModelLifecycleState.REMOVED, None)

    async def aclose(self) -> None:
        for model_id in tuple(self._handles):
            await self.unload(model_id)
        if self._provider_adapter is not None:
            await self._provider_adapter.aclose()

    def _register_or_reconcile(self, spec: LocalModelSpec) -> LocalModelRecord:
        existing = self._records.get(spec.model_id)
        if existing is None or existing.state is ModelLifecycleState.REMOVED:
            return self.register(spec)
        if spec.model_id not in {item.model_id for item in self._inventory.models()}:
            self._inventory.register(spec.metadata)
        if spec.provider_managed:
            if spec.loaded and spec.model_id not in self._handles:
                state = ModelLifecycleState.WARM
            elif spec.installed:
                state = (
                    existing.state
                    if existing.state in {ModelLifecycleState.IN_USE, ModelLifecycleState.IDLE}
                    else ModelLifecycleState.AVAILABLE
                )
            else:
                state = ModelLifecycleState.DISCOVERED
            updated = LocalModelRecord(
                spec,
                state,
                existing.installed_path,
                existing.last_error,
            )
            self._records[spec.model_id] = updated
            return updated
        updated = LocalModelRecord(
            spec, existing.state, existing.installed_path, existing.last_error
        )
        self._records[spec.model_id] = updated
        return updated

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
            artifact.provider_managed
            or artifact.sha256 is None
            or artifact.size_bytes is None
            or not path.exists()
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
