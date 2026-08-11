"""Safe local arithmetic capability with no code execution."""

import ast
import operator
import re
from collections.abc import Callable
from decimal import Decimal, DivisionByZero, InvalidOperation
from typing import cast

from pydantic import BaseModel, ConfigDict, Field

from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
    ToolEvidence,
    ToolExecutionContext,
    ToolManifest,
    ToolMetadata,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)


class CalculatorInput(BaseModel):
    """Strict input for a local arithmetic expression."""

    model_config = ConfigDict(extra="forbid", strict=True)

    expression: str = Field(min_length=1, max_length=256)


class CalculatorOutput(BaseModel):
    """Typed calculator result."""

    model_config = ConfigDict(extra="forbid", strict=True)

    result: str
    normalized_expression: str


class CalculatorTool(Tool[CalculatorInput, CalculatorOutput]):
    """Evaluate a deliberately small arithmetic grammar without eval or external access."""

    _manifest = ToolManifest(
        tool_id="calculator",
        name="Calculator",
        description="Safely evaluates local arithmetic and percentage expressions.",
        version=SemanticVersion(1, 0, 0),
        capability_tags=frozenset({"math", "calculation", "safe"}),
        input_schema=CalculatorInput,
        output_schema=CalculatorOutput,
        declared_permissions=frozenset(),
        supported_platforms=frozenset(
            {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
        ),
        timeout_seconds=1.0,
        implementation_id="jarvis.tools.calculator.CalculatorTool",
    )
    _percentage = re.compile(
        r"^\s*([0-9]+(?:[.,][0-9]+)?)\s*(?:%|percent|procent)\s+(?:of|van)\s+"
        r"([0-9]+(?:[.,][0-9]+)?)\s*$",
        flags=re.IGNORECASE,
    )
    _operators = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.USub: operator.neg,
        ast.UAdd: operator.pos,
    }

    @property
    def manifest(self) -> ToolManifest:
        return self._manifest

    @property
    def input_model(self) -> type[CalculatorInput]:
        return CalculatorInput

    async def execute(
        self, context: ToolExecutionContext, validated_input: CalculatorInput
    ) -> ToolResult:
        del context
        try:
            result, normalized = self._evaluate(validated_input.expression)
        except (SyntaxError, ValueError, InvalidOperation, DivisionByZero) as error:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "invalid_expression",
                "Calculator expression is invalid or cannot be evaluated",
                metadata=(ToolMetadata("diagnostic", str(error)),),
            )
        formatted = self._format(result)
        output = CalculatorOutput(result=formatted, normalized_expression=normalized)
        return ToolResult.success(
            output,
            evidence=(
                ToolEvidence("result", formatted),
                ToolEvidence("calculation_result", f"result={formatted}"),
            ),
            metadata=(ToolMetadata("engine", "safe_decimal_ast"),),
        )

    def _evaluate(self, expression: str) -> tuple[Decimal, str]:
        percentage = self._percentage.fullmatch(expression)
        if percentage:
            left = self._decimal(percentage.group(1))
            right = self._decimal(percentage.group(2))
            return left * right / Decimal("100"), f"{left} * {right} / 100"
        parsed = ast.parse(expression, mode="eval")
        return self._evaluate_node(parsed.body), expression.strip()

    def _evaluate_node(self, node: ast.AST) -> Decimal:
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, int | float)
            and not isinstance(node.value, bool)
        ):
            return self._decimal(str(node.value))
        if isinstance(node, ast.UnaryOp) and type(node.op) in self._operators:
            operation = cast(Callable[..., Decimal], self._operators[type(node.op)])
            return operation(self._evaluate_node(node.operand))
        if isinstance(node, ast.BinOp) and type(node.op) in self._operators:
            operation = cast(Callable[..., Decimal], self._operators[type(node.op)])
            return operation(self._evaluate_node(node.left), self._evaluate_node(node.right))
        raise ValueError("Only basic arithmetic is supported")

    @staticmethod
    def _decimal(value: str) -> Decimal:
        return Decimal(value.replace(",", "."))

    @staticmethod
    def _format(value: Decimal) -> str:
        normalized = value.normalize()
        formatted = format(normalized, "f")
        return formatted.rstrip("0").rstrip(".") if "." in formatted else formatted
