"""Small application services shared by the CLI and local UI."""

from __future__ import annotations

import json
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .batch import Predictor, process_batch


def _read_predictions(
    path: Path,
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            records.append(json.loads(line))
            if limit is not None and len(records) >= limit:
                break
    return records


def classify_message(message: str, predictor: Predictor) -> dict[str, Any]:
    """Classify one message without retaining it in the returned prediction."""

    if not isinstance(message, str) or not message.strip():
        raise ValueError("message must be a non-blank string")
    with tempfile.TemporaryDirectory(prefix="log-classify-") as directory:
        root = Path(directory)
        input_path = root / "input.jsonl"
        output_path = root / "output.jsonl"
        input_path.write_text(
            json.dumps({"message": message}, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        process_batch(input_path, output_path, predictor, max_records=1)
        return _read_predictions(output_path, limit=1)[0]


def classify_file_preview(
    input_path: str | Path,
    predictor: Predictor,
    *,
    preview_limit: int = 20,
    max_input_bytes: int = 1_000_000,
    max_records: int = 1_000,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Classify a file and return aggregate metadata plus a bounded preview."""

    if (
        isinstance(preview_limit, bool)
        or not isinstance(preview_limit, int)
        or preview_limit <= 0
    ):
        raise ValueError("preview_limit must be a positive integer")
    with tempfile.TemporaryDirectory(prefix="log-classify-") as directory:
        output_path = Path(directory) / "output.jsonl"
        summary = process_batch(
            input_path,
            output_path,
            predictor,
            max_input_bytes=max_input_bytes,
            max_records=max_records,
        )
        return asdict(summary), _read_predictions(
            output_path,
            limit=preview_limit,
        )
