"""Deterministic tests for the generated-integration process boundary."""

from __future__ import annotations

import asyncio
import json
import math
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from jarvis import sandbox as sandbox_module
from jarvis.sandbox import (
    SandboxCancelled,
    SandboxConfigurationError,
    SandboxLimits,
    SandboxMessage,
    SandboxProcess,
    SandboxProcessError,
    SandboxProtocolError,
    SandboxTimeout,
)

WORKER = """
import json
import os
import subprocess
import sys
import time

for line in sys.stdin:
    message = json.loads(line)
    kind = message["kind"]
    if kind == "inspect":
        payload = {
            "cwd": os.getcwd(),
            "env_keys": sorted(os.environ),
            "sandbox_marker": os.environ.get("JARVIS_SANDBOX"),
        }
    elif kind == "spawn":
        try:
            child = subprocess.Popen([
                sys.executable,
                "-c",
                "import pathlib,time; time.sleep(.3); "
                "pathlib.Path('child-alive').write_text('alive')",
            ])
            time.sleep(0.1)
            payload = {"spawned": child.poll() is None, "pid": child.pid}
        except OSError as error:
            payload = {"spawned": False, "error": type(error).__name__}
    elif kind == "hang":
        time.sleep(30)
        payload = {"done": True}
    elif kind == "crash":
        os._exit(17)
    elif kind == "spoof-request":
        print(json.dumps({
            "version": 1,
            "request_id": "00000000-0000-0000-0000-000000000000",
            "integration_id": message["integration_id"],
            "kind": "result",
            "response": True,
            "payload": {},
        }), flush=True)
        continue
    elif kind == "spoof-identity":
        print(json.dumps({
            "version": 1,
            "request_id": message["request_id"],
            "integration_id": "other.integration",
            "kind": "result",
            "response": True,
            "payload": {},
        }), flush=True)
        continue
    elif kind == "oversized-response":
        print("x" * 70000, flush=True)
        continue
    elif kind == "malformed-response":
        print("{", flush=True)
        break
    else:
        payload = {"echo": message["payload"]}
    print(json.dumps({
        "version": 1,
        "request_id": message["request_id"],
        "integration_id": message["integration_id"],
        "kind": "result",
        "response": True,
        "payload": payload,
    }), flush=True)
"""


def sandbox(tmp_path: Path, *, limits: SandboxLimits | None = None) -> SandboxProcess:
    return SandboxProcess(
        Path(sys.executable),
        ("-c", WORKER),
        integration_id="test.integration",
        parent_directory=tmp_path / "owned-sandboxes",
        limits=limits or SandboxLimits(timeout_seconds=1, max_message_bytes=65_536, max_restarts=2),
    )


@pytest.mark.asyncio
async def test_typed_json_ipc_and_dedicated_paths_reject_non_json() -> None:
    message = SandboxMessage(
        request_id=uuid4(),
        integration_id="test.integration",
        kind="inspect",
        payload={"value": [1, "safe", None]},
    )
    encoded = message.encode(max_bytes=1_024)
    assert b"pickle" not in encoded.lower()
    assert SandboxMessage.decode(encoded) == message
    with pytest.raises(SandboxProtocolError):
        SandboxMessage(message.request_id, "test.integration", "bad", {"value": object()})
    with pytest.raises(SandboxProtocolError):
        SandboxMessage.decode(encoded[:-1] + b"x")


@pytest.mark.asyncio
async def test_environment_source_boundary_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("JARVIS_TEST_SECRET", "must-not-cross")
    source = tmp_path / "source" / "secret.txt"
    source.parent.mkdir()
    source.write_text("source-secret", encoding="utf-8")
    process = sandbox(tmp_path)
    await process.start()
    paths = process.paths
    result = await process.request("inspect", {})
    assert result["cwd"] == str(paths.work)
    assert result["cwd"] != str(source.parent)
    assert result["sandbox_marker"] == "1"
    env_keys = result["env_keys"]
    assert isinstance(env_keys, list)
    assert "JARVIS_TEST_SECRET" not in env_keys
    assert "PYTHONPATH" not in env_keys
    assert paths.work.is_dir() and paths.data.is_dir()
    root = paths.root
    await process.close()
    assert not root.exists()


@pytest.mark.asyncio
async def test_identity_spoof_oversized_response_and_crash_are_contained(tmp_path: Path) -> None:
    process = sandbox(tmp_path, limits=SandboxLimits(max_restarts=4))
    await process.start()
    with pytest.raises(SandboxProtocolError):
        await process.request("spoof-request", {})
    assert not process.is_running
    await process.restart()
    with pytest.raises(SandboxProtocolError):
        await process.request("spoof-identity", {})
    await process.restart()
    with pytest.raises(SandboxProtocolError):
        await process.request("oversized-response", {})
    await process.restart()
    with pytest.raises(SandboxProcessError):
        await process.request("crash", {})
    await process.close()


@pytest.mark.asyncio
async def test_timeout_cancellation_and_restart_bound(tmp_path: Path) -> None:
    process = sandbox(tmp_path, limits=SandboxLimits(timeout_seconds=0.1, max_restarts=1))
    await process.start()
    with pytest.raises(SandboxTimeout):
        await process.request("hang", {})
    await process.restart()
    cancellation = asyncio.Event()
    request = asyncio.create_task(process.request("hang", {}, cancellation=cancellation))
    await asyncio.sleep(0.02)
    cancellation.set()
    with pytest.raises(SandboxCancelled):
        await request
    with pytest.raises(SandboxProcessError):
        await process.restart()
    await process.close()


@pytest.mark.asyncio
async def test_oversized_request_and_process_spawn_limit(tmp_path: Path) -> None:
    process = sandbox(tmp_path)
    await process.start()
    with pytest.raises(SandboxProtocolError):
        await process.request("echo", {"value": "x" * 70_000})
    if sys.platform == "win32":
        result = await process.request("spawn", {})
        assert isinstance(result["spawned"], bool)
        child_marker = process.paths.work / "child-alive"
        await process.close()
        await asyncio.sleep(0.5)
        assert not child_marker.exists()
        return
    await process.close()


def test_limits_and_paths_fail_closed(tmp_path: Path) -> None:
    assert SandboxLimits().native_resource_controls is (sys.platform == "win32")
    with pytest.raises(SandboxConfigurationError):
        SandboxLimits(max_processes=0)
    with pytest.raises(SandboxConfigurationError):
        SandboxProcess(
            Path(sys.executable),
            (),
            integration_id="../escape",
            parent_directory=tmp_path,
        )
    with pytest.raises(SandboxConfigurationError):
        SandboxProcess(
            Path(sys.executable),
            ("-c", "print('x')", "\x00"),
            integration_id="safe",
            parent_directory=tmp_path,
        )


@pytest.mark.parametrize(
    "value",
    (
        math.nan,
        math.inf,
        [-1] * 4_097,
        {str(index): index for index in range(4_097)},
        {1: "bad"},
        object(),
    ),
)
def test_json_value_validation_is_strict(value: object) -> None:
    with pytest.raises(SandboxProtocolError):
        sandbox_module._json_value(value)
    nested: object = None
    for _ in range(34):
        nested = [nested]
    with pytest.raises(SandboxProtocolError):
        sandbox_module._json_value(nested)
    assert sandbox_module._json_value(1.5) == 1.5


def test_message_decode_rejects_each_security_metadata_shape() -> None:
    request_id = str(uuid4())
    body: dict[str, object] = {
        "version": 1,
        "request_id": request_id,
        "integration_id": "test.integration",
        "kind": "result",
        "response": True,
        "payload": {},
    }

    def frame(**updates: object) -> bytes:
        value = {**body, **updates}
        return json.dumps(value).encode() + b"\n"

    for raw in (
        b"{\n",
        frame(extra=True),
        frame(version=1.0),
        frame(version=2),
        frame(request_id=123),
        frame(request_id="not-a-uuid"),
        frame(integration_id=123),
        frame(response=1),
        frame(payload=[]),
    ):
        with pytest.raises(SandboxProtocolError):
            SandboxMessage.decode(raw)
    with pytest.raises(SandboxProtocolError):
        SandboxMessage.decode(b"{}")
    with pytest.raises(SandboxConfigurationError):
        SandboxMessage(uuid4(), "test.integration", "result", {}).encode(max_bytes=10)
    with pytest.raises(SandboxConfigurationError):
        SandboxMessage(uuid4(), "test.integration", "", {})
    with pytest.raises(SandboxProtocolError):
        SandboxMessage(
            uuid4(),
            "test.integration",
            "result",
            cast(Mapping[str, object], []),
        )
    with pytest.raises(SandboxProtocolError):
        SandboxMessage(uuid4(), "test.integration", "result", {}, response=cast(bool, 1))
    with pytest.raises(SandboxProtocolError):
        SandboxMessage(uuid4(), "test.integration", "result", {}, version=2)
    with pytest.raises(SandboxProtocolError):
        SandboxMessage("not-a-uuid", "test.integration", "result", {})  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_sandbox_lifecycle_guards_and_path_cleanup_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(SandboxConfigurationError):
        sandbox_module.SandboxPaths.create(Path("relative"), "safe")
    with pytest.raises(SandboxConfigurationError):
        sandbox_module.SandboxPaths.create(tmp_path / "missing" / "..", "safe")
    file_path = tmp_path / "file"
    file_path.write_text("not a directory", encoding="utf-8")
    with pytest.raises(SandboxConfigurationError):
        sandbox_module.SandboxPaths.create(file_path, "safe")

    paths = sandbox_module.SandboxPaths.create(tmp_path, "safe")
    fixed_id = uuid4()
    collision = tmp_path / f"jarvis-sandbox-safe-{fixed_id.hex}"
    collision.mkdir()
    with monkeypatch.context() as context:
        context.setattr(sandbox_module, "uuid4", lambda: fixed_id)
        with pytest.raises(SandboxConfigurationError):
            sandbox_module.SandboxPaths.create(tmp_path, "safe")
    collision.rmdir()
    with pytest.raises(SandboxConfigurationError):
        sandbox_module.SandboxPaths(paths.root, paths.root / "wrong", paths.data).validate()
    invalid_root = tmp_path / "not-sandbox"
    invalid_root.mkdir()
    (invalid_root / "work").mkdir()
    (invalid_root / "data").mkdir()
    with pytest.raises(sandbox_module.SandboxCleanupError):
        sandbox_module.SandboxPaths(
            invalid_root, invalid_root / "work", invalid_root / "data"
        ).cleanup()
    with monkeypatch.context() as context:
        sandbox_any: Any = sandbox_module
        context.setattr(sandbox_any.shutil, "rmtree", lambda path: (_ for _ in ()).throw(OSError()))
        with pytest.raises(sandbox_module.SandboxCleanupError):
            paths.cleanup()
    paths.cleanup()

    process = sandbox(tmp_path)
    with pytest.raises(SandboxProcessError):
        _ = process.paths
    with pytest.raises(SandboxProcessError):
        await process.request("inspect", {})
    await process.start()
    with pytest.raises(SandboxProcessError):
        await process.start()
    cancellation = asyncio.Event()
    cancellation.set()
    with pytest.raises(SandboxCancelled):
        await process.request("inspect", {}, cancellation=cancellation)
    await process.stop()
    await process.start()
    assert process.restart_count == 0
    await process.request("inspect", {}, cancellation=asyncio.Event())
    await process.close()
    await process.close()
    with pytest.raises(SandboxProcessError):
        await process.start()


@pytest.mark.asyncio
async def test_process_start_failure_and_malformed_response_are_contained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(SandboxConfigurationError):
        SandboxProcess(
            tmp_path / "missing.exe",
            (),
            integration_id="safe",
            parent_directory=tmp_path,
        )
    process = sandbox(tmp_path)
    with pytest.raises(SandboxProcessError):
        await process._read_response(SandboxMessage(uuid4(), "test.integration", "x", {}), None)

    async def fail_start(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("start failed")

    sandbox_any: Any = sandbox_module
    with monkeypatch.context() as context:
        context.setattr(sandbox_any.asyncio, "create_subprocess_exec", fail_start)
        with pytest.raises(SandboxProcessError):
            await process.start()

    process = sandbox(tmp_path)
    await process.start()
    with pytest.raises(SandboxProtocolError):
        await process.request("malformed-response", {})
    await process.close()
