"""Small application services shared by the CLI and local UI."""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .batch import Predictor, process_batch
from .contracts import BatchResourceLimitError
from .defaults import DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_RECORDS
from .workspace import MAX_RAW_PAYLOAD_BYTES, Workspace


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
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_records: int = DEFAULT_MAX_RECORDS,
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


def classify_file_into_workspace(
    input_path: str | Path,
    predictor: Predictor,
    workspace: Workspace,
    session_token: str,
    *,
    store_raw: bool = False,
    batch_size: int = 64,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_records: int = DEFAULT_MAX_RECORDS,
) -> tuple[dict[str, Any], str]:
    """Classify completely, then atomically persist a successful workspace job."""

    workspace.authorize_classification(session_token, retain_raw=store_raw)
    source = Path(input_path)
    if store_raw:
        # Refuse before classifying; store_completed_job re-checks the bytes read.
        source_bytes = source.stat().st_size
        if source_bytes > MAX_RAW_PAYLOAD_BYTES:
            raise BatchResourceLimitError(
                "retained raw source byte count",
                MAX_RAW_PAYLOAD_BYTES,
                observed_at_least=source_bytes,
            )
    with tempfile.TemporaryDirectory(prefix="log-classify-") as directory:
        output_path = Path(directory) / "output.jsonl"
        summary = process_batch(
            source,
            output_path,
            predictor,
            batch_size=batch_size,
            max_input_bytes=max_input_bytes,
            max_records=max_records,
        )
        results = _read_predictions(output_path)
        raw_payload: bytes | None = None
        if store_raw:
            with source.open("rb") as stream:
                raw_payload = stream.read(max_input_bytes + 1)
            if len(raw_payload) > max_input_bytes:
                raise BatchResourceLimitError(
                    "input byte count",
                    max_input_bytes,
                    observed_at_least=len(raw_payload),
                )
            observed_digest = hashlib.sha256(raw_payload).hexdigest()
            if observed_digest != summary.source_sha256:
                raise RuntimeError("input changed after classification; job was not stored")
        job_id = workspace.store_completed_job(
            session_token,
            summary.source_sha256,
            summary.input_records,
            results,
            raw_payload=raw_payload,
        )
    return asdict(summary), job_id
