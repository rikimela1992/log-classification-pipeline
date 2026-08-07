"""Validate one synthetic JSONL example without invoking a predictor."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from log_classification_pipeline.contracts import BatchValidationError
from log_classification_pipeline.jsonl import read_jsonl


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="synthetic JSONL file to validate")
    arguments = parser.parse_args()

    try:
        batch = read_jsonl(arguments.input)
    except BatchValidationError as exc:
        print(
            f"synthetic example rejected with {len(exc.issues)} validation issue(s)",
            file=sys.stderr,
        )
        return 2

    print(
        f"synthetic example accepted: records={len(batch.records)} "
        f"blank_lines={batch.blank_lines} batch_id={batch.batch_id}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
