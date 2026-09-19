"""D6B1 deterministic contract tests for the immutable sandbox worker."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import cast

import pytest
from jarvis.sandbox import SandboxLimits, SandboxProcess, WindowsContainmentMode
from jarvis.sandbox_worker import (
    BROKER_OPERATION,
    PAYLOAD_SCHEMA,
    WORKER_COMPATIBILITY,
    PayloadError,
    _complete_broker_result,
    _default_value,
    _dispatch,
    _failure,
    _load_payload,
    _result,
    main,
    validate_constrained_payload,
)


def _payload(*, health: str = "healthy", operation: str = "default_output") -> dict[str, object]:
    return {
        "schema": PAYLOAD_SCHEMA,
        "package_id": "generated.fictional",
        "label": "Fictional capability",
        "self_health": health,
        "dependencies": [],
        "actions": {
            "fictional-action": {
                "operation": operation,
                "output_schema": {
                    "type": "object",
                    "properties": {"result": {"type": "string"}},
                    "required": ["result"],
                },
            }
        },
    }


def _frame_payload(frame: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], frame["payload"])


async def _request(tmp_path: Path, payload: object, kind: str = "health") -> dict[str, object]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    worker = Path(__file__).resolve().parents[1] / "jarvis" / "sandbox_worker.py"
    process = SandboxProcess(
        Path(sys.base_prefix) / "python.exe",
        (str(worker), str(payload_path), "generated.fictional"),
        integration_id="generated.fictional",
        parent_directory=tmp_path / "owned",
        limits=SandboxLimits(
            timeout_seconds=2, windows_containment=WindowsContainmentMode.JOB_OBJECT_ONLY
        ),
    )
    await process.start()
    try:
        return await process.request(kind, {})
    finally:
        await process.close()


@pytest.mark.asyncio
async def test_worker_bootstraps_before_malformed_payload_load(tmp_path: Path) -> None:
    result = await _request(tmp_path, {"schema": "bad"})
    assert result["worker_status"] == "PROTOCOL_READY"
    assert result["package_load"] == "PAYLOAD_VERSION_UNSUPPORTED"
    assert result["status"] == "package_load_failed"


@pytest.mark.asyncio
async def test_worker_distinguishes_dependency_and_self_health(tmp_path: Path) -> None:
    missing = _payload()
    missing["dependencies"] = ["missing-native-dependency"]
    dependency = await _request(tmp_path / "dependency", missing)
    unhealthy = await _request(tmp_path / "health", _payload(health="unhealthy"))
    assert dependency["package_load"] == "DEPENDENCY_UNAVAILABLE"
    assert unhealthy["worker_status"] == "PROTOCOL_READY"
    assert unhealthy["package_load"] == "PAYLOAD_LOADED"
    assert unhealthy["self_health"] == "unhealthy"


@pytest.mark.asyncio
async def test_worker_runs_fictional_constrained_action_and_reports_action_failure(
    tmp_path: Path,
) -> None:
    successful = await _request(tmp_path / "success", _payload(), "fictional-action")
    failure = await _request(tmp_path / "failure", _payload(operation="fail"), "fictional-action")
    assert successful == {"result": "observed"}
    assert failure["status"] == "action_failed"
    assert failure["failure"] == "ACTION_FAILURE"


@pytest.mark.asyncio
async def test_worker_emits_allowlisted_broker_request_and_accepts_bounded_result(
    tmp_path: Path,
) -> None:
    payload = _payload(operation=BROKER_OPERATION)
    actions = cast(dict[str, dict[str, object]], payload["actions"])
    actions["fictional-action"]["fields"] = ["value"]
    process_root = tmp_path / "broker"
    process_root.mkdir(parents=True)
    payload_path = process_root / "payload.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    worker = Path(__file__).resolve().parents[1] / "jarvis" / "sandbox_worker.py"
    process = SandboxProcess(
        Path(sys.base_prefix) / "python.exe",
        (str(worker), str(payload_path), "generated.fictional"),
        integration_id="generated.fictional",
        parent_directory=process_root / "owned",
        limits=SandboxLimits(
            timeout_seconds=2, windows_containment=WindowsContainmentMode.JOB_OBJECT_ONLY
        ),
    )
    await process.start()
    try:
        request = await process.request("fictional-action", {"value": "hello"})
        assert request["status"] == "broker_request"
        assert request["operation"] == BROKER_OPERATION
        assert request["arguments"] == {"value": "hello"}
        result = await process.request(
            "broker_result", {"operation": BROKER_OPERATION, "result": "HELLO"}
        )
        assert result == {"result": "HELLO", "capability": "generated.fictional"}
        structured = await process.request(
            "broker_result", {"operation": BROKER_OPERATION, "result": {"result": "HELLO"}}
        )
        assert structured == {"result": "HELLO"}
    finally:
        await process.close()


def test_worker_preserves_structurally_valid_unknown_operation_for_parent() -> None:
    payload = _payload(operation="arbitrary.tool")
    validated = validate_constrained_payload(json.dumps(payload), "generated.fictional")
    actions = cast(dict[str, dict[str, object]], validated["actions"])
    assert actions["fictional-action"]["operation"] == "arbitrary.tool"


def test_worker_has_no_arbitrary_package_code_execution_path() -> None:
    source = (
        Path(__file__)
        .resolve()
        .parents[1]
        .joinpath("jarvis", "sandbox_worker.py")
        .read_text(encoding="utf-8")
    )
    assert WORKER_COMPATIBILITY == "jarvis-sandbox-worker-v1"
    for prohibited in ("exec(", "eval(", "importlib", "compile(", "__import__("):
        assert prohibited not in source


def test_worker_validates_each_payload_boundary(tmp_path: Path) -> None:
    valid = _payload(operation="concat_strings")
    action = cast(dict[str, object], cast(dict[str, object], valid["actions"])["fictional-action"])
    action["fields"] = ["left", "right"]
    cases: list[tuple[object, str]] = [
        ("not-json", "PAYLOAD_INVALID"),
        ({"schema": "bad"}, "PAYLOAD_VERSION_UNSUPPORTED"),
        ({**valid, "package_id": "other"}, "PACKAGE_MANIFEST_INVALID"),
        ({**valid, "label": 1}, "PAYLOAD_INVALID"),
        ({**valid, "self_health": "unknown"}, "PAYLOAD_INVALID"),
        ({**valid, "dependencies": [1]}, "PAYLOAD_INVALID"),
        ({**valid, "dependencies": ["native"]}, "DEPENDENCY_UNAVAILABLE"),
        ({**valid, "actions": []}, "PAYLOAD_INVALID"),
        ({**valid, "actions": {"a": "bad"}}, "PAYLOAD_INVALID"),
        (
            {**valid, "actions": {"a": {"operation": "", "output_schema": {}}}},
            "PAYLOAD_INVALID",
        ),
        ({**valid, "actions": {"a": {"operation": "x"}}}, "PAYLOAD_INVALID"),
        (
            {
                **valid,
                "actions": {
                    "a": {
                        "operation": "concat_strings",
                        "fields": [],
                        "output_schema": {},
                    }
                },
            },
            "PAYLOAD_INVALID",
        ),
        (
            {
                **valid,
                "actions": {
                    "a": {
                        "operation": "concat_strings",
                        "fields": ["ok", 1],
                        "output_schema": {},
                    }
                },
            },
            "PAYLOAD_INVALID",
        ),
        (
            {
                **valid,
                "actions": {
                    "a": {
                        "operation": "concat_strings",
                        "fields": ["ok"],
                        "delimiter": 1,
                        "output_schema": {},
                    }
                },
            },
            "PAYLOAD_INVALID",
        ),
    ]
    for value, reason in cases:
        content = value if isinstance(value, str) else json.dumps(value)
        with pytest.raises(PayloadError, match=reason):
            validate_constrained_payload(content, "generated.fictional")

    path = tmp_path / "payload.json"
    path.write_text(json.dumps(valid), encoding="utf-8")
    assert _load_payload(path, "generated.fictional")["package_id"] == "generated.fictional"
    with pytest.raises(PayloadError, match="PAYLOAD_INVALID"):
        _load_payload(tmp_path / "missing.json", "generated.fictional")


def test_worker_default_outputs_and_dispatch_boundaries() -> None:
    package_id = "generated.fictional"
    request = {"request_id": "r", "integration_id": package_id, "kind": "x"}
    assert _default_value({"type": "array"}, "result", package_id) == []
    assert _default_value({"type": "string"}, "capability", package_id) == package_id
    assert _default_value({"type": "string"}, "result", package_id) == "observed"
    assert _default_value({"type": "integer"}, "result", package_id) == 0
    assert _default_value({"type": "number"}, "result", package_id) == 0.0
    assert _default_value({"type": "boolean"}, "result", package_id) is False
    assert _default_value(
        {
            "type": "object",
            "properties": {"result": {"type": "string"}, "count": {"type": "integer"}},
            "required": ["result", "count", "missing"],
        },
        "result",
        package_id,
    ) == {"result": "observed", "count": 0}
    with pytest.raises(PayloadError, match="malformed"):
        _default_value({"type": "object", "properties": [], "required": []}, "result", package_id)
    with pytest.raises(PayloadError, match="unsupported"):
        _default_value({"type": "null"}, "result", package_id)

    payload = _payload()
    assert _frame_payload(_dispatch({**request, "kind": "health"}, payload))["status"] == "healthy"
    assert (
        _frame_payload(_dispatch({**request, "kind": "inspect"}, payload))["label"]
        == "Fictional capability"
    )
    assert _frame_payload(_dispatch({**request, "kind": "shadow"}, payload))["status"] == "shadow"
    assert _frame_payload(_dispatch({**request, "kind": "canary"}, payload))["status"] == "canary"
    assert (
        _frame_payload(_dispatch({**request, "kind": "missing"}, payload))["failure"]
        == "ACTION_UNDECLARED"
    )
    assert (
        _frame_payload(
            _dispatch({**request, "kind": "fictional-action"}, _payload(operation="fail"))
        )["failure"]
        == "ACTION_FAILURE"
    )
    assert (
        _frame_payload(
            _dispatch(
                {**request, "kind": "fictional-action", "payload": {"value": 3}},
                _payload(operation="arbitrary.tool"),
            )
        )["failure"]
        == "ACTION_INPUT_INVALID"
    )
    broker = _dispatch(
        {**request, "kind": "fictional-action", "payload": {"value": "ok"}},
        _payload(operation="arbitrary.tool"),
    )
    assert _frame_payload(broker)["status"] == "broker_request"

    concat = _payload(operation="concat_strings")
    concat_action = cast(
        dict[str, object], cast(dict[str, object], concat["actions"])["fictional-action"]
    )
    concat_action["fields"] = ["left", "right"]
    concat_action["delimiter"] = ":"
    assert (
        _frame_payload(
            _dispatch(
                {**request, "kind": "fictional-action", "payload": {"left": "a", "right": "b"}},
                concat,
            )
        )["result"]
        == "a:b"
    )
    for bad_payload in ({}, {"left": "a"}, {"left": "a", "right": 2}):
        assert (
            _frame_payload(
                _dispatch({**request, "kind": "fictional-action", "payload": bad_payload}, concat)
            )["failure"]
            == "ACTION_INPUT_INVALID"
        )
    concat_action["fields"] = "not-a-list"
    assert (
        _frame_payload(
            _dispatch({**request, "kind": "fictional-action", "payload": {"left": "a"}}, concat)
        )["failure"]
        == "ACTION_INPUT_INVALID"
    )

    assert (
        _frame_payload(_dispatch({**request, "kind": "fictional-action"}, payload))["result"]
        == "observed"
    )
    object_schema = _payload()
    object_action = cast(
        dict[str, object], cast(dict[str, object], object_schema["actions"])["fictional-action"]
    )
    object_action["output_schema"] = {"type": "array"}
    assert (
        _frame_payload(_dispatch({**request, "kind": "fictional-action"}, object_schema))["failure"]
        == "ACTION_FAILURE"
    )
    object_action["output_schema"] = "not-a-schema"
    assert (
        _frame_payload(_dispatch({**request, "kind": "fictional-action"}, object_schema))["failure"]
        == "ACTION_FAILURE"
    )


def test_worker_broker_frames_and_main_protocol_filtering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = {"request_id": "r", "integration_id": "i", "kind": "broker_result"}
    payload = {"package_id": "generated.fictional"}
    assert _frame_payload(_failure(request, "generated.fictional", "BAD"))["package_load"] == "BAD"
    assert _frame_payload(_result(request, {"ok": True})) == {"ok": True}
    for bad in ({}, {"operation": 1, "result": "ok"}, {"operation": "x", "result": 1}):
        assert (
            _frame_payload(_complete_broker_result({**request, "payload": bad}, payload))["failure"]
            == "BROKER_RESULT_INVALID"
        )
    assert _frame_payload(
        _complete_broker_result({**request, "payload": {"operation": "x", "result": "ok"}}, payload)
    ) == {"result": "ok", "capability": "generated.fictional"}
    assert _frame_payload(
        _complete_broker_result(
            {**request, "payload": {"operation": "x", "result": {"ok": True}}}, payload
        )
    ) == {"ok": True}
    assert _complete_broker_result(
        {**request, "payload": {"operation": "x", "result": "x" * 4097}}, payload
    )["payload"] == {"status": "action_failed", "failure": "BROKER_RESULT_INVALID"}

    path = tmp_path / "payload.json"
    path.write_text(json.dumps(_payload()), encoding="utf-8")
    stdin = io.StringIO(
        "not-json\n"
        + json.dumps({"request_id": "ignored"})
        + "\n"
        + json.dumps({"request_id": "r", "integration_id": "i", "kind": "health"})
        + "\n"
    )
    stdout = io.StringIO()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)
    assert main([str(path), "generated.fictional"]) == 0
    frames = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert len(frames) == 1
    assert frames[0]["payload"]["status"] == "healthy"
    bad_path = tmp_path / "bad-payload.json"
    bad_path.write_text("{bad", encoding="utf-8")
    invalid_request = {"request_id": "r", "integration_id": "i", "kind": "health"}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(invalid_request) + "\n"))
    stdout.seek(0)
    stdout.truncate(0)
    assert main([str(bad_path), "generated.fictional"]) == 0
    assert json.loads(stdout.getvalue())["payload"]["package_load"] == "PAYLOAD_INVALID"
    assert main([]) == 2
