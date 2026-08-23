"""Deterministic local-model lifecycle tests; no network or model runtime is used."""

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from jarvis.ai.model_manager import (
    LocalModelManager,
    LocalModelSpec,
    ModelArtifact,
    ModelHealth,
    ModelLifecycleError,
    ModelLifecycleState,
)
from jarvis.ai.models import ModelRole
from jarvis.hardware import FitStatus, ModelMeasurement

from tests.test_hardware import _hardware, _model

PAYLOAD = b"trusted fixture model bytes"
HASH = hashlib.sha256(PAYLOAD).hexdigest()


def spec() -> LocalModelSpec:
    return LocalModelSpec(
        "fixture-model",
        _model("fixture-model", frozenset({ModelRole.GENERAL}), storage=len(PAYLOAD), ram=1),
        ModelArtifact("fixture://model", HASH, len(PAYLOAD)),
    )


class Catalog:
    async def discover(self) -> tuple[LocalModelSpec, ...]:
        return (spec(),)


class Downloader:
    def __init__(self, payload: bytes = PAYLOAD) -> None:
        self.payload = payload
        self.sources: list[str] = []

    async def download(self, source: str, destination: Path) -> None:
        self.sources.append(source)
        destination.write_bytes(self.payload)


class Runtime:
    def __init__(self) -> None:
        self.loaded: list[str] = []
        self.unloaded: list[str] = []

    async def load(self, item: LocalModelSpec, path: Path) -> object:
        assert path.read_bytes() == PAYLOAD
        self.loaded.append(item.model_id)
        return item.model_id

    async def unload(self, model_id: str, handle: object) -> None:
        assert handle == model_id
        self.unloaded.append(model_id)

    async def health(self, model_id: str, handle: object) -> ModelHealth:
        assert handle == model_id
        return ModelHealth(model_id, True, "fixture runtime healthy", datetime.now(UTC))

    async def benchmark(self, model_id: str, handle: object) -> ModelMeasurement:
        assert handle == model_id
        return ModelMeasurement(model_id, datetime.now(UTC), "fixture benchmark", throughput=12.5)


@pytest.mark.asyncio
async def test_local_model_lifecycle_is_typed_and_restart_safe(tmp_path: Path) -> None:
    downloader = Downloader()
    runtime = Runtime()
    manager = LocalModelManager(
        tmp_path / "models",
        catalog=Catalog(),
        downloader=downloader,
        runtime=runtime,
    )

    discovered = await manager.discover()
    assert discovered[0].state is ModelLifecycleState.DISCOVERED
    assert (
        manager.check_compatibility("fixture-model", _hardware(ram=8, disk=1024))
        is FitStatus.COMPATIBLE
    )
    verified = await manager.download("fixture-model")
    assert verified.state is ModelLifecycleState.VERIFIED
    installed = await manager.install("fixture-model")
    assert installed.state is ModelLifecycleState.INSTALLED
    loaded = await manager.load("fixture-model")
    assert loaded.state is ModelLifecycleState.LOADED
    assert (await manager.health("fixture-model")).available
    assert (await manager.benchmark("fixture-model")).throughput == 12.5
    await manager.unload("fixture-model")
    await manager.aclose()
    assert runtime.loaded == ["fixture-model"]
    assert runtime.unloaded == ["fixture-model"]

    restarted = LocalModelManager(tmp_path / "models")
    restarted.register(spec())
    assert await restarted.verify("fixture-model")
    assert (await restarted.remove("fixture-model")).state is ModelLifecycleState.REMOVED


@pytest.mark.asyncio
async def test_existing_verified_download_is_reused_without_redownload(tmp_path: Path) -> None:
    root = tmp_path / "models"
    root.mkdir()
    (root / "fixture-model.download").write_bytes(PAYLOAD)
    downloader = Downloader(b"wrong")
    manager = LocalModelManager(root, downloader=downloader)
    manager.register(spec())

    result = await manager.download("fixture-model")

    assert result.state is ModelLifecycleState.VERIFIED
    assert downloader.sources == []


@pytest.mark.asyncio
async def test_checksum_mismatch_fails_closed_and_repair_redownloads(tmp_path: Path) -> None:
    downloader = Downloader(b"tampered")
    manager = LocalModelManager(tmp_path / "models", downloader=downloader)
    manager.register(spec())

    with pytest.raises(ModelLifecycleError, match="integrity"):
        await manager.download("fixture-model")
    assert manager.inspect("fixture-model").state is ModelLifecycleState.FAILED

    downloader.payload = PAYLOAD
    repaired = await manager.repair("fixture-model")
    assert repaired.state is ModelLifecycleState.INSTALLED
    assert downloader.sources == ["fixture://model", "fixture://model"]


@pytest.mark.asyncio
async def test_model_manager_rejects_unsafe_root_and_runtime_transitions(tmp_path: Path) -> None:
    unsafe_file = tmp_path / "file"
    unsafe_file.write_text("x")
    with pytest.raises(ModelLifecycleError, match="root"):
        LocalModelManager(unsafe_file)
    manager = LocalModelManager(tmp_path / "models")
    manager.register(spec())
    assert manager.check_compatibility("fixture-model", _hardware(ram=None)) is FitStatus.UNKNOWN
    assert manager.inspect("fixture-model").state is ModelLifecycleState.COMPATIBILITY_UNKNOWN

    with pytest.raises(ModelLifecycleError, match="downloader"):
        await manager.download("fixture-model")


@pytest.mark.parametrize(
    ("sha256", "size_bytes"),
    (
        ("bad", 1),
        (HASH, 0),
    ),
)
def test_model_artifact_validation_rejects_bad_integrity_metadata(
    sha256: str, size_bytes: int
) -> None:
    with pytest.raises(ModelLifecycleError):
        ModelArtifact("fixture://model", sha256, size_bytes)


def test_model_contracts_reject_identity_health_and_registration_errors(tmp_path: Path) -> None:
    with pytest.raises(ModelLifecycleError, match="identity"):
        LocalModelSpec(
            "fixture-model", _model("other", frozenset({ModelRole.GENERAL})), spec().artifact
        )
    with pytest.raises(ModelLifecycleError, match="artifact"):
        LocalModelSpec("fixture-model", spec().metadata, cast(Any, object()))
    with pytest.raises(ModelLifecycleError, match="malformed"):
        ModelHealth("fixture-model", True, "", datetime.now(UTC))
    with pytest.raises(ModelLifecycleError, match="timestamp"):
        ModelHealth("fixture-model", True, "ok", datetime(2026, 1, 1))

    manager = LocalModelManager(tmp_path / "models")
    with pytest.raises(ModelLifecycleError, match="specification"):
        manager.register(cast(Any, object()))
    manager.register(spec())
    with pytest.raises(ModelLifecycleError, match="already"):
        manager.register(spec())
    with pytest.raises(ModelLifecycleError, match="Model ID"):
        manager.inspect("../escape")
    with pytest.raises(KeyError, match="Unknown"):
        manager.inspect("missing")


class BadCatalog:
    async def discover(self) -> tuple[LocalModelSpec, ...]:
        return cast(tuple[LocalModelSpec, ...], [spec()])


class BrokenDownloader:
    async def download(self, source: str, destination: Path) -> None:
        del source, destination
        raise RuntimeError("download failed")


class BadRuntime(Runtime):
    async def health(self, model_id: str, handle: object) -> ModelHealth:
        del model_id, handle
        return cast(ModelHealth, object())

    async def benchmark(self, model_id: str, handle: object) -> ModelMeasurement:
        del model_id, handle
        return cast(ModelMeasurement, object())


@pytest.mark.asyncio
async def test_model_catalog_download_health_benchmark_and_path_failures(tmp_path: Path) -> None:
    manager = LocalModelManager(tmp_path / "models", catalog=BadCatalog())
    with pytest.raises(ModelLifecycleError, match="catalog"):
        await manager.discover()

    broken = LocalModelManager(tmp_path / "broken", downloader=BrokenDownloader())
    broken.register(spec())
    with pytest.raises(RuntimeError, match="download failed"):
        await broken.download("fixture-model")
    assert broken.inspect("fixture-model").last_error == "RuntimeError"
    with pytest.raises(ModelLifecycleError, match="integrity"):
        await broken.install("fixture-model")

    no_runtime = LocalModelManager(tmp_path / "no-runtime")
    no_runtime.register(spec())
    assert (await no_runtime.health("fixture-model")).available is False
    with pytest.raises(ModelLifecycleError, match="benchmark"):
        await no_runtime.benchmark("fixture-model")
    with pytest.raises(ModelLifecycleError, match="runtime"):
        await no_runtime.load("fixture-model")
    with pytest.raises(ModelLifecycleError, match="path"):
        no_runtime._safe_unlink(tmp_path / "outside")

    bad_runtime = BadRuntime()
    manager = LocalModelManager(
        tmp_path / "bad-runtime", downloader=Downloader(), runtime=bad_runtime
    )
    manager.register(spec())
    await manager.download("fixture-model")
    await manager.install("fixture-model")
    await manager.load("fixture-model")
    with pytest.raises(ModelLifecycleError, match="health"):
        await manager.health("fixture-model")
    with pytest.raises(ModelLifecycleError, match="benchmark"):
        await manager.benchmark("fixture-model")


@pytest.mark.asyncio
async def test_model_compatibility_failures_and_loaded_mutation_guards(tmp_path: Path) -> None:
    metadata = _model(
        "guarded",
        frozenset({ModelRole.GENERAL}),
        storage=10,
        ram=10,
        vram=10,
        compatibility=frozenset(),
    )
    guarded = LocalModelSpec(
        "guarded", metadata, ModelArtifact("fixture://guarded", HASH, len(PAYLOAD))
    )
    manager = LocalModelManager(tmp_path / "models", downloader=Downloader(), runtime=Runtime())
    manager.register(guarded)
    assert (
        manager.check_compatibility("guarded", _hardware(tags=frozenset({"windows"})))
        is FitStatus.COMPATIBLE
    )
    assert (
        manager.check_compatibility("guarded", _hardware(tags=frozenset())) is FitStatus.COMPATIBLE
    )
    assert manager.check_compatibility("guarded", _hardware(disk=1)) is FitStatus.INCOMPATIBLE
    assert manager.check_compatibility("guarded", _hardware(ram=1)) is FitStatus.INCOMPATIBLE
    assert manager.check_compatibility("guarded", _hardware(vram=1)) is FitStatus.INCOMPATIBLE
    assert (
        manager.check_compatibility("guarded", _hardware(disk=None, ram=None, vram=None))
        is FitStatus.UNKNOWN
    )

    await manager.download("guarded")
    await manager.install("guarded")
    await manager.load("guarded")
    with pytest.raises(ModelLifecycleError, match="unloaded"):
        await manager.repair("guarded")
    with pytest.raises(ModelLifecycleError, match="removal"):
        await manager.remove("guarded")
