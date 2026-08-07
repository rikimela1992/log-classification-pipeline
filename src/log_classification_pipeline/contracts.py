"""Input and output contracts for batch classification."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """A validation failure tied to a source line when one is available."""

    reason: str
    line_number: int | None = None

    def __str__(self) -> str:
        if self.line_number is None:
            return self.reason
        return f"line {self.line_number}: {self.reason}"


class BatchValidationError(ValueError):
    """Raised after the entire input has been checked and found invalid."""

    def __init__(self, issues: list[ValidationIssue] | tuple[ValidationIssue, ...]):
        if not issues:
            raise ValueError("BatchValidationError requires at least one issue")
        self.issues = tuple(issues)
        details = "; ".join(str(issue) for issue in self.issues)
        super().__init__(f"batch validation failed: {details}")


class PredictionContractError(ValueError):
    """Raised when a predictor violates the one-input/one-output contract."""


def validate_input_record(record: Mapping[str, Any], line_number: int) -> list[ValidationIssue]:
    """Validate the stable v1 fields while allowing additional metadata."""

    issues: list[ValidationIssue] = []
    message = record.get("message")
    if not isinstance(message, str) or not message.strip():
        issues.append(
            ValidationIssue(
                line_number=line_number,
                reason="field 'message' must be a non-blank string",
            )
        )

    for field_name in ("host", "app", "severity"):
        if field_name in record and not isinstance(record[field_name], str):
            issues.append(
                ValidationIssue(
                    line_number=line_number,
                    reason=f"field '{field_name}' must be a string when present",
                )
            )

    return issues


def validate_prediction_record(record: object, output_index: int) -> Mapping[str, Any]:
    """Require each prediction to be serialisable as a JSON object."""

    if not isinstance(record, Mapping):
        raise PredictionContractError(
            f"prediction {output_index} must be a mapping, got {type(record).__name__}"
        )
    if any(not isinstance(key, str) for key in record):
        raise PredictionContractError(
            f"prediction {output_index} contains a non-string object key"
        )
    return record
