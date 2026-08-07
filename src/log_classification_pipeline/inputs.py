"""Bounded whole-file readers for supported user-facing log formats."""

from __future__ import annotations

import csv
import hashlib
import io
from pathlib import Path
from typing import Literal, cast

from .contracts import (
    BatchResourceLimitError,
    BatchValidationError,
    ValidationIssue,
    validate_input_record,
)
from .jsonl import ParsedBatch, read_jsonl

InputFormat = Literal["jsonl", "text", "csv"]

_SUFFIX_FORMATS: dict[str, InputFormat] = {
    ".csv": "csv",
    ".jsonl": "jsonl",
    ".log": "text",
    ".ndjson": "jsonl",
    ".txt": "text",
}
SUPPORTED_INPUT_SUFFIXES = tuple(sorted(_SUFFIX_FORMATS))


def resolve_input_format(
    filename: str | Path,
    input_format: str | None = None,
) -> InputFormat:
    """Resolve an explicit format or a supported, case-insensitive suffix."""

    if input_format is not None:
        if input_format not in {"jsonl", "text", "csv"}:
            raise ValueError("input_format must be one of: jsonl, text, csv")
        return cast(InputFormat, input_format)
    raw_name = str(filename).replace("\\", "/").rsplit("/", 1)[-1]
    suffix = Path(raw_name).suffix.casefold()
    try:
        return _SUFFIX_FORMATS[suffix]
    except KeyError as exc:
        supported = ", ".join(SUPPORTED_INPUT_SUFFIXES)
        raise ValueError(f"unsupported input file extension; expected one of: {supported}") from exc


def read_input_file(
    path: str | Path,
    *,
    input_format: str | None = None,
    max_input_bytes: int | None = None,
    max_records: int | None = None,
) -> ParsedBatch:
    """Read one supported file completely and preserve its exact byte digest."""

    source_path = Path(path)
    resolved_format = resolve_input_format(source_path, input_format)
    if resolved_format == "jsonl":
        return read_jsonl(
            source_path,
            max_input_bytes=max_input_bytes,
            max_records=max_records,
        )

    _validate_limit("max_input_bytes", max_input_bytes)
    _validate_limit("max_records", max_records)
    payload = _read_payload(source_path, max_input_bytes=max_input_bytes)
    digest = hashlib.sha256(payload).hexdigest()
    text = _decode_utf8(payload)
    if text.startswith("\ufeff"):
        text = text[1:]

    if resolved_format == "text":
        records, blank_lines = _read_text_records(text, max_records=max_records)
    else:
        records, blank_lines = _read_csv_records(text, max_records=max_records)
    return ParsedBatch(
        records=tuple(records),
        blank_lines=blank_lines,
        source_sha256=digest,
    )


def _read_payload(path: Path, *, max_input_bytes: int | None) -> bytes:
    with path.open("rb") as stream:
        payload = stream.read() if max_input_bytes is None else stream.read(max_input_bytes + 1)
    if max_input_bytes is not None and len(payload) > max_input_bytes:
        raise BatchResourceLimitError(
            "input byte count",
            max_input_bytes,
            observed_at_least=len(payload),
        )
    return payload


def _validate_limit(name: str, value: int | None) -> None:
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
    ):
        raise ValueError(f"{name} must be a positive integer or None")


def _decode_utf8(payload: bytes) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        line_number = payload[: exc.start].count(b"\n") + 1
        raise BatchValidationError(
            [ValidationIssue(line_number=line_number, reason="input is not valid UTF-8")]
        ) from exc


def _read_text_records(
    text: str,
    *,
    max_records: int | None,
) -> tuple[list[dict[str, str]], int]:
    raw_lines = text.split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines.pop()
    records: list[dict[str, str]] = []
    blank_lines = 0
    for line_number, raw_line in enumerate(raw_lines, start=1):
        message = raw_line[:-1] if raw_line.endswith("\r") else raw_line
        if not message.strip():
            blank_lines += 1
            continue
        _enforce_record_limit(len(records) + 1, max_records, line_number)
        records.append({"message": message})
    if not records:
        raise BatchValidationError([ValidationIssue(reason="batch contains no records")])
    return records, blank_lines


def _read_csv_records(
    text: str,
    *,
    max_records: int | None,
) -> tuple[list[dict[str, str]], int]:
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except StopIteration as exc:
        raise BatchValidationError([ValidationIssue(reason="CSV contains no header")]) from exc
    except csv.Error as exc:
        raise BatchValidationError(
            [ValidationIssue(line_number=reader.line_num or 1, reason=f"invalid CSV: {exc}")]
        ) from exc

    header_issues: list[ValidationIssue] = []
    if not header or any(not name.strip() for name in header):
        header_issues.append(
            ValidationIssue(line_number=1, reason="CSV header names must be non-blank")
        )
    if len(set(header)) != len(header):
        header_issues.append(
            ValidationIssue(line_number=1, reason="CSV header names must be unique")
        )
    if "message" not in header:
        header_issues.append(
            ValidationIssue(line_number=1, reason="CSV header must contain 'message'")
        )
    if header_issues:
        raise BatchValidationError(header_issues)

    records: list[dict[str, str]] = []
    issues: list[ValidationIssue] = []
    blank_lines = 0
    observed_records = 0
    try:
        for row in reader:
            line_number = reader.line_num
            if not row or all(not value.strip() for value in row):
                blank_lines += 1
                continue
            observed_records += 1
            _enforce_record_limit(observed_records, max_records, line_number)
            if len(row) != len(header):
                issues.append(
                    ValidationIssue(
                        line_number=line_number,
                        reason=(
                            "CSV row field count does not match header: "
                            f"expected {len(header)}, got {len(row)}"
                        ),
                    )
                )
                continue
            record = dict(zip(header, row, strict=True))
            record_issues = validate_input_record(record, line_number)
            if record_issues:
                issues.extend(record_issues)
                continue
            records.append(record)
    except csv.Error as exc:
        issues.append(
            ValidationIssue(
                line_number=reader.line_num or None,
                reason=f"invalid CSV: {exc}",
            )
        )
    if not records and not issues:
        issues.append(ValidationIssue(reason="batch contains no records"))
    if issues:
        raise BatchValidationError(issues)
    return records, blank_lines


def _enforce_record_limit(
    observed: int,
    limit: int | None,
    line_number: int,
) -> None:
    if limit is not None and observed > limit:
        raise BatchResourceLimitError(
            "record count",
            limit,
            observed_at_least=observed,
            line_number=line_number,
        )


__all__ = [
    "InputFormat",
    "SUPPORTED_INPUT_SUFFIXES",
    "read_input_file",
    "resolve_input_format",
]
