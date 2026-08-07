"""Batch orchestration independent from any concrete ML runtime."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Any, Callable, Protocol

from .atomic import atomic_write_jsonl
from .contracts import PredictionContractError, validate_prediction_record
from .jsonl import read_jsonl


class Predictor(Protocol):
    """A predictor that emits one JSON object for every supplied input object."""

    def __call__(
        self,
        records: Sequence[Mapping[str, Any]],
    ) -> Sequence[Mapping[str, Any]]: ...


class BatchCancelledError(RuntimeError):
    """Cooperative cancellation was requested between predictor chunks."""


@dataclass(frozen=True, slots=True)
class BatchSummary:
    batch_id: str
    source_sha256: str
    input_records: int
    output_records: int
    blank_lines: int


def _same_path(first: Path, second: Path) -> bool:
    try:
        if first.exists() and second.exists() and os.path.samefile(first, second):
            return True
    except OSError:
        pass
    return first.resolve(strict=False) == second.resolve(strict=False)


def process_batch(
    input_path: str | Path,
    output_path: str | Path,
    predictor: Predictor,
    *,
    batch_size: int = 64,
    overwrite: bool = False,
    max_input_bytes: int | None = None,
    max_records: int | None = None,
    output_mode: int = 0o600,
    progress_callback: Callable[[int, int], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> BatchSummary:
    """Validate, predict, and atomically publish one complete batch."""

    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size <= 0:
        raise ValueError("batch_size must be a positive integer")

    source = Path(input_path)
    destination = Path(output_path)
    if _same_path(source, destination):
        raise ValueError("input and output paths must be different")
    if destination.is_symlink():
        raise FileExistsError(f"refusing symlink output path: {destination}")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"output already exists: {destination}")

    parsed = read_jsonl(
        source,
        max_input_bytes=max_input_bytes,
        max_records=max_records,
    )
    total_records = len(parsed.records)
    if progress_callback is not None:
        progress_callback(0, total_records)

    def predictions():
        output_index = 0
        for offset in range(0, len(parsed.records), batch_size):
            if should_cancel is not None and should_cancel():
                raise BatchCancelledError("batch cancellation requested")
            chunk = parsed.records[offset : offset + batch_size]
            predicted = predictor(chunk)
            try:
                iterator = iter(predicted)
            except TypeError as exc:
                raise PredictionContractError(
                    f"predictor returned a non-iterable result for records {offset + 1}-"
                    f"{offset + len(chunk)}"
                ) from exc
            predicted_chunk = list(islice(iterator, len(chunk) + 1))

            if len(predicted_chunk) != len(chunk):
                observed = str(len(predicted_chunk))
                if len(predicted_chunk) > len(chunk):
                    observed = f"at least {observed}"
                raise PredictionContractError(
                    "predictor output count mismatch for records "
                    f"{offset + 1}-{offset + len(chunk)}: expected {len(chunk)}, "
                    f"got {observed}"
                )

            if should_cancel is not None and should_cancel():
                raise BatchCancelledError("batch cancellation requested")

            for raw_prediction in predicted_chunk:
                output_index += 1
                yield validate_prediction_record(raw_prediction, output_index)
            if progress_callback is not None:
                progress_callback(output_index, total_records)

    output_count = atomic_write_jsonl(
        destination,
        predictions(),
        overwrite=overwrite,
        mode=output_mode,
    )

    return BatchSummary(
        batch_id=parsed.batch_id,
        source_sha256=parsed.source_sha256,
        input_records=len(parsed.records),
        output_records=output_count,
        blank_lines=parsed.blank_lines,
    )
