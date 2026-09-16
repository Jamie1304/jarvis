"""Trusted typed guest operations with fixed guest programs and bounded data."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from jarvis.vm.models import EnvironmentKind, GuestCommand, NetworkPolicy
from jarvis.vm.router import ExecutionIntent

MAX_RESEARCH_INPUT_BYTES: Final = 4_096
MAX_BUILD_INPUT_BYTES: Final = 8_192


def _bounded_text(value: str, *, maximum_bytes: int, name: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError(f"{name} must be non-empty text without NUL")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{name} exceeds the bounded input size")
    if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
        raise ValueError(f"{name} contains unsupported control text")
    return value


class ResearchAnalysis(StrEnum):
    TEXT_STATISTICS = "text_statistics"


class BuildLanguage(StrEnum):
    PYTHON = "python"


class BuildProfile(StrEnum):
    PYTHON_SYNTAX = "python_syntax"


class VMResearchInput(BaseModel):
    """Planner-facing bounded research data; no command authority is exposed."""

    model_config = ConfigDict(extra="forbid", strict=True)

    text: str = Field(min_length=1, max_length=MAX_RESEARCH_INPUT_BYTES)
    requested_analysis: Literal["text_statistics"] = "text_statistics"

    @field_validator("text")
    @classmethod
    def _validate_text(cls, value: str) -> str:
        return _bounded_text(value, maximum_bytes=MAX_RESEARCH_INPUT_BYTES, name="text")


class VMBuildCheckInput(BaseModel):
    """Planner-facing bounded source data; source is never command/program authority."""

    model_config = ConfigDict(extra="forbid", strict=True)

    source: str = Field(min_length=1, max_length=MAX_BUILD_INPUT_BYTES)
    language: Literal["python"] = "python"
    profile: Literal["python_syntax"] = "python_syntax"

    @field_validator("source")
    @classmethod
    def _validate_source(cls, value: str) -> str:
        return _bounded_text(value, maximum_bytes=MAX_BUILD_INPUT_BYTES, name="source")


@dataclass(frozen=True, slots=True)
class GuestOperationSpec:
    """Trusted application-owned operation definition."""

    operation_id: str
    task_class: str
    intent: ExecutionIntent
    expected_environment: EnvironmentKind
    executable: str
    fixed_program: str
    network_policy: NetworkPolicy
    timeout_seconds: float
    semantic_result_type: str


@dataclass(frozen=True, slots=True)
class ResearchSemanticResult:
    operation_id: str
    semantic_result_type: str
    input_digest: str
    result_digest: str
    character_count: int
    line_count: int
    word_count: int
    normalized_digest: str
    semantic_status: str
    verification_passed: bool


@dataclass(frozen=True, slots=True)
class BuildCheckSemanticResult:
    operation_id: str
    semantic_result_type: str
    input_digest: str
    result_digest: str
    valid: bool
    error_type: str | None
    error_line: int | None
    error_offset: int | None
    semantic_status: str
    verification_passed: bool


type GuestOperationRequest = VMResearchInput | VMBuildCheckInput
type GuestOperationResult = ResearchSemanticResult | BuildCheckSemanticResult


# These programs are immutable application-owned templates. User/model data is
# supplied only as one base64 data argument and is never interpolated into code.
_RESEARCH_PROGRAM: Final = (
    "import base64,hashlib,json,sys\n"
    "data=base64.b64decode(sys.argv[1],validate=True)\n"
    "text=data.decode('utf-8')\n"
    "normalized=' '.join(text.split())\n"
    "result={'character_count':len(text),'line_count':text.count('\\n')+1,"
    "'word_count':len(text.split()),'input_sha256':hashlib.sha256(data).hexdigest(),"
    "'normalized_sha256':hashlib.sha256(normalized.encode('utf-8')).hexdigest()}\n"
    "print(json.dumps(result,sort_keys=True,separators=(',',':')))"
)

_BUILD_PROGRAM: Final = (
    "import base64,hashlib,json,sys\n"
    "data=base64.b64decode(sys.argv[1],validate=True)\n"
    "source=data.decode('utf-8')\n"
    "result={'source_sha256':hashlib.sha256(data).hexdigest()}\n"
    "try:\n"
    " compile(source,'<bounded-input>','exec')\n"
    "except SyntaxError as error:\n"
    " result.update({'valid':False,'error_type':'SyntaxError','error_line':"
    "error.lineno,'error_offset':error.offset})\n"
    " print(json.dumps(result,sort_keys=True,separators=(',',':')))\n"
    " raise SystemExit(1)\n"
    "else:\n"
    " result.update({'valid':True,'error_type':None,'error_line':None,'error_offset':None})\n"
    " print(json.dumps(result,sort_keys=True,separators=(',',':')))"
)


_RESEARCH_SPEC = GuestOperationSpec(
    operation_id="vm.research.text_statistics",
    task_class="research",
    intent=ExecutionIntent("research", network_required=True),
    expected_environment=EnvironmentKind.WORKBENCH_VM,
    executable="python3",
    fixed_program=_RESEARCH_PROGRAM,
    network_policy=NetworkPolicy.INTERNET_ONLY,
    timeout_seconds=60.0,
    semantic_result_type="text_statistics",
)

_BUILD_SPEC = GuestOperationSpec(
    operation_id="vm.coding.python_syntax",
    task_class="coding",
    intent=ExecutionIntent("coding", isolation_required=True),
    expected_environment=EnvironmentKind.DISPOSABLE_TEST_VM,
    executable="python3",
    fixed_program=_BUILD_PROGRAM,
    network_policy=NetworkPolicy.NO_NETWORK,
    timeout_seconds=60.0,
    semantic_result_type="python_syntax_build",
)


def operation_spec(request: GuestOperationRequest) -> GuestOperationSpec:
    if isinstance(request, VMResearchInput):
        return _RESEARCH_SPEC
    if isinstance(request, VMBuildCheckInput):
        return _BUILD_SPEC
    raise TypeError("unsupported trusted guest operation request")


def operation_input(request: GuestOperationRequest) -> str:
    if isinstance(request, VMResearchInput):
        return request.text
    if isinstance(request, VMBuildCheckInput):
        return request.source
    raise TypeError("unsupported trusted guest operation request")


def operation_input_digest(request: GuestOperationRequest) -> str:
    return hashlib.sha256(operation_input(request).encode("utf-8")).hexdigest()


def materialize_guest_command(request: GuestOperationRequest) -> GuestCommand:
    spec = operation_spec(request)
    encoded = base64.b64encode(operation_input(request).encode("utf-8")).decode("ascii")
    return GuestCommand(
        executable=spec.executable,
        args=("-c", spec.fixed_program, encoded),
        timeout_seconds=spec.timeout_seconds,
        network_policy=spec.network_policy,
    )


def expected_research_payload(request: VMResearchInput) -> dict[str, object]:
    data = request.text.encode("utf-8")
    normalized = " ".join(request.text.split())
    return {
        "character_count": len(request.text),
        "line_count": request.text.count("\n") + 1,
        "word_count": len(request.text.split()),
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "normalized_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
    }


def expected_build_payload(request: VMBuildCheckInput) -> dict[str, object]:
    data = request.source.encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    try:
        compile(request.source, "<bounded-input>", "exec")
    except SyntaxError as error:
        return {
            "source_sha256": digest,
            "valid": False,
            "error_type": "SyntaxError",
            "error_line": error.lineno,
            "error_offset": error.offset,
        }
    return {
        "source_sha256": digest,
        "valid": True,
        "error_type": None,
        "error_line": None,
        "error_offset": None,
    }


def result_digest(payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_operation(
    request: GuestOperationRequest,
    stdout: str,
    exit_code: int | None,
) -> GuestOperationResult:
    if isinstance(request, VMResearchInput):
        return _verify_research(request, stdout, exit_code)
    if isinstance(request, VMBuildCheckInput):
        return _verify_build(request, stdout, exit_code)
    raise TypeError("unsupported trusted guest operation request")


def _parse_result(stdout: str) -> dict[str, object] | None:
    try:
        value = json.loads(stdout.strip())
    except (TypeError, ValueError):
        return None
    return value if type(value) is dict else None


def _observed_digest(payload: dict[str, object] | None, stdout: str) -> str:
    if payload is not None:
        return result_digest(payload)
    return hashlib.sha256(stdout.encode("utf-8")).hexdigest()


def _int_value(payload: dict[str, object] | None, key: str, default: int = -1) -> int:
    value = None if payload is None else payload.get(key)
    if type(value) is not int:
        return default
    return value


def _str_value(payload: dict[str, object] | None, key: str) -> str:
    value = None if payload is None else payload.get(key)
    return value if type(value) is str else ""


def _verify_research(
    request: VMResearchInput,
    stdout: str,
    exit_code: int | None,
) -> ResearchSemanticResult:
    expected = expected_research_payload(request)
    observed = _parse_result(stdout)
    passed = exit_code == 0 and observed == expected
    return ResearchSemanticResult(
        operation_id=_RESEARCH_SPEC.operation_id,
        semantic_result_type=_RESEARCH_SPEC.semantic_result_type,
        input_digest=operation_input_digest(request),
        result_digest=result_digest(expected) if passed else _observed_digest(observed, stdout),
        character_count=_int_value(observed, "character_count"),
        line_count=_int_value(observed, "line_count"),
        word_count=_int_value(observed, "word_count"),
        normalized_digest=_str_value(observed, "normalized_sha256"),
        semantic_status="verified_success" if passed else "verification_failed",
        verification_passed=passed,
    )


def _verify_build(
    request: VMBuildCheckInput,
    stdout: str,
    exit_code: int | None,
) -> BuildCheckSemanticResult:
    expected = expected_build_payload(request)
    observed = _parse_result(stdout)
    expected_exit = 0 if expected["valid"] is True else 1
    passed = exit_code == expected_exit and observed == expected
    valid = observed.get("valid") if observed is not None else None
    return BuildCheckSemanticResult(
        operation_id=_BUILD_SPEC.operation_id,
        semantic_result_type=_BUILD_SPEC.semantic_result_type,
        input_digest=operation_input_digest(request),
        result_digest=result_digest(expected) if passed else _observed_digest(observed, stdout),
        valid=valid if type(valid) is bool else False,
        error_type=_str_value(observed, "error_type") or None,
        error_line=(
            _int_value(observed, "error_line", default=0) if observed is not None else None
        ),
        error_offset=(
            _int_value(observed, "error_offset", default=0) if observed is not None else None
        ),
        semantic_status=(
            "verified_valid"
            if passed and expected["valid"] is True
            else "verified_invalid"
            if passed
            else "verification_failed"
        ),
        verification_passed=passed,
    )


__all__ = [
    "BuildCheckSemanticResult",
    "BuildLanguage",
    "BuildProfile",
    "GuestOperationRequest",
    "GuestOperationResult",
    "GuestOperationSpec",
    "MAX_BUILD_INPUT_BYTES",
    "MAX_RESEARCH_INPUT_BYTES",
    "ResearchAnalysis",
    "ResearchSemanticResult",
    "VMBuildCheckInput",
    "VMResearchInput",
    "expected_build_payload",
    "expected_research_payload",
    "materialize_guest_command",
    "operation_input",
    "operation_input_digest",
    "operation_spec",
    "result_digest",
    "verify_operation",
]
