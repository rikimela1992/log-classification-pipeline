"""Strict, whole-file JSONL parsing for classifier inputs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import (
    BatchResourceLimitError,
    BatchValidationError,
    ValidationIssue,
    validate_input_record,
)


class _DuplicateKeyError(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    raise ValueError(f"non-finite number {value!r} is not valid JSON")


@dataclass(frozen=True, slots=True)
class ParsedBatch:
    """Validated records plus an identity derived from the exact source bytes."""

    records: tuple[dict[str, Any], ...]
    blank_lines: int
    source_sha256: str

    @property
    def batch_id(self) -> str:
        return f"sha256:{self.source_sha256}"


def _validate_limit(name: str, value: int | None) -> None:
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
    ):
        raise ValueError(f"{name} must be a positive integer or None")


def read_jsonl(
    path: str | Path,
    *,
    max_input_bytes: int | None = None,
    max_records: int | None = None,
) -> ParsedBatch:
    """Read and validate an entire JSONL file before returning any records."""

    _validate_limit("max_input_bytes", max_input_bytes)
    _validate_limit("max_records", max_records)

    source_path = Path(path)
    with source_path.open("rb") as stream:
        if max_input_bytes is None:
            payload = stream.read()
        else:
            payload = stream.read(max_input_bytes + 1)
    if max_input_bytes is not None and len(payload) > max_input_bytes:
        raise BatchResourceLimitError(
            "input byte count",
            max_input_bytes,
            observed_at_least=len(payload),
        )
    digest = hashlib.sha256(payload).hexdigest()

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        line_number = payload[: exc.start].count(b"\n") + 1
        raise BatchValidationError(
            [ValidationIssue(line_number=line_number, reason="input is not valid UTF-8")]
        ) from exc
    if text.startswith("\ufeff"):
        text = text[1:]

    records: list[dict[str, Any]] = []
    issues: list[ValidationIssue] = []
    blank_lines = 0

    raw_lines = text.split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines.pop()

    non_blank_lines = 0
    for line_number, raw_line in enumerate(raw_lines, start=1):
        if not raw_line.strip():
            blank_lines += 1
            continue

        non_blank_lines += 1
        if max_records is not None and non_blank_lines > max_records:
            raise BatchResourceLimitError(
                "record count",
                max_records,
                observed_at_least=non_blank_lines,
                line_number=line_number,
            )
        try:
            value = json.loads(
                raw_line,
                object_pairs_hook=_object_without_duplicate_keys,
                parse_constant=_reject_non_finite_number,
            )
        except (json.JSONDecodeError, _DuplicateKeyError, ValueError) as exc:
            issues.append(
                ValidationIssue(
                    line_number=line_number,
                    reason=f"invalid JSON: {exc}",
                )
            )
            continue

        if not isinstance(value, dict):
            issues.append(
                ValidationIssue(
                    line_number=line_number,
                    reason="top-level JSON value must be an object",
                )
            )
            continue

        record_issues = validate_input_record(value, line_number)
        if record_issues:
            issues.extend(record_issues)
            continue
        records.append(value)

    if not records and not issues:
        issues.append(ValidationIssue(reason="batch contains no records"))

    if issues:
        raise BatchValidationError(issues)

    return ParsedBatch(
        records=tuple(records),
        blank_lines=blank_lines,
        source_sha256=digest,
    )
