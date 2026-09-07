"""Immutable, data-only sandbox worker for generated capability packages.

This module is JARVIS production code.  It deliberately parses constrained JSON
payloads rather than importing or evaluating package supplied code.  It runs in
the same AppContainer/one-process Job as the old entrypoint, but owns every
protocol byte written to stdout.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

WORKER_PROTOCOL_VERSION = 1
WORKER_COMPATIBILITY = "jarvis-sandbox-worker-v1"
PAYLOAD_SCHEMA = "jarvis.constrained-action-payload/v1"
BROKER_OPERATION = "broker_call"


class PayloadError(ValueError):
    """A package payload is not a supported constrained payload."""


def _default_value(schema: Mapping[str, object], key: str, package_id: str) -> object:
    kind = schema.get("type")
    if kind == "object":
        properties = schema.get("properties")
        required = schema.get("required")
        if not isinstance(properties, Mapping) or not isinstance(required, list):
            raise PayloadError("output schema is malformed")
        return {
            name: _default_value(value, name, package_id)
            for name in required
            if isinstance(name, str) and isinstance((value := properties.get(name)), Mapping)
        }
    if kind == "array":
        return []
    if kind == "string":
        return package_id if key == "capability" else "observed"
    if kind == "integer":
        return 0
    if kind == "number":
        return 0.0
    if kind == "boolean":
        return False
    raise PayloadError("unsupported output schema")


def validate_constrained_payload(content: str, expected_package_id: str) -> dict[str, object]:
    try:
        value: Any = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PayloadError("PAYLOAD_INVALID") from error
    if not isinstance(value, dict) or value.get("schema") != PAYLOAD_SCHEMA:
        raise PayloadError("PAYLOAD_VERSION_UNSUPPORTED")
    if value.get("package_id") != expected_package_id:
        raise PayloadError("PACKAGE_MANIFEST_INVALID")
    if type(value.get("label")) is not str or value.get("self_health") not in {
        "healthy",
        "unhealthy",
    }:
        raise PayloadError("PAYLOAD_INVALID")
    dependencies = value.get("dependencies", [])
    actions = value.get("actions")
    if not isinstance(dependencies, list) or any(type(item) is not str for item in dependencies):
        raise PayloadError("PAYLOAD_INVALID")
    if dependencies:
        raise PayloadError("DEPENDENCY_UNAVAILABLE")
    if not isinstance(actions, dict) or not actions:
        raise PayloadError("PAYLOAD_INVALID")
    for action_id, action in actions.items():
        if type(action_id) is not str or not isinstance(action, dict):
            raise PayloadError("PAYLOAD_INVALID")
        if type(action.get("operation")) is not str or not action["operation"].strip():
            raise PayloadError("PAYLOAD_INVALID")
        if not isinstance(action.get("output_schema"), dict):
            raise PayloadError("PAYLOAD_INVALID")
        if action["operation"] == "concat_strings":
            fields = action.get("fields")
            if (
                not isinstance(fields, list)
                or not fields
                or any(type(field) is not str for field in fields)
                or type(action.get("delimiter", "")) is not str
            ):
                raise PayloadError("PAYLOAD_INVALID")
    return value


def _load_payload(path: Path, expected_package_id: str) -> dict[str, object]:
    try:
        return validate_constrained_payload(path.read_text(encoding="utf-8"), expected_package_id)
    except OSError as error:
        raise PayloadError("PAYLOAD_INVALID") from error


def _result(request: Mapping[str, object], payload: Mapping[str, object]) -> dict[str, object]:
    return {
        "version": WORKER_PROTOCOL_VERSION,
        "request_id": request["request_id"],
        "integration_id": request["integration_id"],
        "kind": "result",
        "response": True,
        "payload": dict(payload),
    }


def _failure(request: Mapping[str, object], package_id: str, reason: str) -> dict[str, object]:
    return _result(
        request,
        {
            "status": "package_load_failed",
            "capability": package_id,
            "worker_status": "PROTOCOL_READY",
            "package_load": reason,
        },
    )


def _dispatch(request: Mapping[str, object], payload: Mapping[str, object]) -> dict[str, object]:
    package_id = str(payload["package_id"])
    kind = request.get("kind")
    if kind == "health":
        return _result(
            request,
            {
                "status": str(payload["self_health"]),
                "capability": package_id,
                "worker_status": "PROTOCOL_READY",
                "package_load": "PAYLOAD_LOADED",
                "self_health": str(payload["self_health"]),
            },
        )
    if kind == "inspect":
        return _result(
            request, {"status": "observed", "capability": package_id, "label": payload["label"]}
        )
    if kind in {"shadow", "canary"}:
        return _result(
            request, {"status": kind, "capability": package_id, "label": payload["label"]}
        )
    action = payload["actions"].get(kind) if isinstance(payload["actions"], dict) else None
    if not isinstance(action, dict):
        return _result(
            request,
            {"status": "action_failed", "capability": package_id, "failure": "ACTION_UNDECLARED"},
        )
    if action["operation"] == "fail":
        return _result(
            request,
            {"status": "action_failed", "capability": package_id, "failure": "ACTION_FAILURE"},
        )
    if action["operation"] not in {"default_output", "concat_strings", "fail"}:
        input_payload = request.get("payload")
        if not isinstance(input_payload, dict) or type(input_payload.get("value")) is not str:
            return _result(
                request,
                {
                    "status": "action_failed",
                    "capability": package_id,
                    "failure": "ACTION_INPUT_INVALID",
                },
            )
        return _result(
            request,
            {
                "status": "broker_request",
                "capability": package_id,
                "operation": action["operation"],
                "arguments": {"value": input_payload["value"]},
            },
        )
    if action["operation"] == "concat_strings":
        input_payload = request.get("payload")
        fields = action["fields"]
        if not isinstance(input_payload, dict) or not isinstance(fields, list):
            return _result(
                request,
                {
                    "status": "action_failed",
                    "capability": package_id,
                    "failure": "ACTION_INPUT_INVALID",
                },
            )
        try:
            value = str(action.get("delimiter", "")).join(
                input_payload[field]
                for field in fields
                if isinstance(field, str) and type(input_payload.get(field)) is str
            )
            if len(value.split(str(action.get("delimiter", "")))) != len(fields):
                raise ValueError
        except (KeyError, ValueError):
            return _result(
                request,
                {
                    "status": "action_failed",
                    "capability": package_id,
                    "failure": "ACTION_INPUT_INVALID",
                },
            )
        return _result(request, {"result": value})
    schema = action["output_schema"]
    if not isinstance(schema, Mapping):
        return _result(
            request,
            {"status": "action_failed", "capability": package_id, "failure": "ACTION_FAILURE"},
        )
    output = _default_value(schema, "result", package_id)
    if not isinstance(output, Mapping):
        return _result(
            request,
            {"status": "action_failed", "capability": package_id, "failure": "ACTION_FAILURE"},
        )
    return _result(request, output)


def _complete_broker_result(
    request: Mapping[str, object], payload: Mapping[str, object]
) -> dict[str, object]:
    result = request.get("payload")
    if not isinstance(result, dict) or type(result.get("operation")) is not str:
        return _result(
            request,
            {"status": "action_failed", "failure": "BROKER_RESULT_INVALID"},
        )
    value = result.get("result")
    if not isinstance(value, str | dict) or len(json.dumps(value, separators=(",", ":"))) > 4096:
        return _result(
            request,
            {"status": "action_failed", "failure": "BROKER_RESULT_INVALID"},
        )
    # A broker may return the exact action-output object.  Preserve that
    # schema instead of adding worker metadata that would invalidate a strict
    # generated output model.  The parent already binds this frame to the
    # package/action and serializes it through the bounded protocol.
    if isinstance(value, dict):
        return _result(request, value)
    return _result(request, {"result": value, "capability": payload["package_id"]})


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 2:
        return 2
    payload_path, package_id = Path(args[0]), args[1]
    try:
        payload = _load_payload(payload_path, package_id)
        load_error: str | None = None
    except PayloadError as error:
        payload = None
        load_error = str(error)
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if not isinstance(request, dict) or not all(
                key in request for key in ("request_id", "integration_id", "kind")
            ):
                continue
            outgoing = (
                _failure(request, package_id, load_error)
                if load_error is not None
                else _complete_broker_result(request, payload or {})
                if request.get("kind") == "broker_result"
                else _dispatch(request, payload or {})
            )
            sys.stdout.write(json.dumps(outgoing, separators=(",", ":")) + "\n")
            sys.stdout.flush()
        except (TypeError, ValueError, KeyError):
            continue
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
