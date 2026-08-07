"""Command-line entry point for validation, classification, evaluation, and UI."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .adapters import RulesPredictor, ZeroShotConfig, ZeroShotPredictor
from .batch import process_batch
from .evaluation import evaluate_records
from .jsonl import read_jsonl


def _add_limits(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-input-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-records", type=int, default=1_000)


def _add_adapter(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--adapter",
        choices=("rules", "zero-shot"),
        default="rules",
        help="rules is a wiring baseline; zero-shot requires the ml extra",
    )
    parser.add_argument(
        "--model-source",
        help="local model directory",
    )
    parser.add_argument(
        "--model-id",
        help="declared model id for a local model directory",
    )
    parser.add_argument(
        "--model-revision",
        help="declared revision for a local model directory",
    )
    parser.add_argument(
        "--allow-download",
        action="store_true",
        help="explicitly permit a pinned Hub download",
    )
    parser.add_argument("--confidence-threshold", type=float, default=0.60)


def _build_predictor(args: argparse.Namespace):
    if args.adapter == "rules":
        return RulesPredictor(
            confidence_threshold=args.confidence_threshold,
        )
    defaults = ZeroShotConfig()
    if args.model_source:
        source_path = Path(args.model_source)
        if not source_path.is_dir():
            raise ValueError("model-source must be an existing local directory")
        if not args.model_id or not args.model_revision:
            raise ValueError(
                "local model-source requires --model-id and --model-revision"
            )
        if args.allow_download:
            raise ValueError("--allow-download cannot be used with a local model")
        source = source_path
        model_id = args.model_id
        revision = args.model_revision
        allow_download = False
    else:
        if args.model_id or args.model_revision:
            raise ValueError(
                "--model-id and --model-revision require --model-source"
            )
        source = defaults.model_source
        model_id = defaults.model_id
        revision = defaults.revision
        allow_download = args.allow_download
    return ZeroShotPredictor(
        ZeroShotConfig(
            model_source=source,
            model_id=model_id,
            revision=revision,
            allow_download=allow_download,
            confidence_threshold=args.confidence_threshold,
        )
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="log-classify")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate input JSONL")
    validate.add_argument("input", type=Path)
    _add_limits(validate)

    classify = subparsers.add_parser(
        "classify",
        help="classify JSONL into an atomically published output",
    )
    classify.add_argument("input", type=Path)
    classify.add_argument("output", type=Path)
    classify.add_argument("--overwrite", action="store_true")
    classify.add_argument("--batch-size", type=int, default=64)
    _add_limits(classify)
    _add_adapter(classify)

    evaluate = subparsers.add_parser(
        "evaluate",
        help="evaluate a labelled synthetic JSONL fixture",
    )
    evaluate.add_argument("input", type=Path)
    _add_limits(evaluate)
    _add_adapter(evaluate)

    ui = subparsers.add_parser("ui", help="launch the local Gradio interface")
    _add_adapter(ui)
    ui.add_argument("--port", type=int, default=7860)
    return parser


def _emit(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _run(args: argparse.Namespace) -> None:
    if args.command == "validate":
        parsed = read_jsonl(
            args.input,
            max_input_bytes=args.max_input_bytes,
            max_records=args.max_records,
        )
        _emit(
            {
                "batch_id": parsed.batch_id,
                "blank_lines": parsed.blank_lines,
                "input_records": len(parsed.records),
                "valid": True,
            }
        )
        return

    predictor = _build_predictor(args)
    if args.command == "classify":
        summary = process_batch(
            args.input,
            args.output,
            predictor,
            batch_size=args.batch_size,
            overwrite=args.overwrite,
            max_input_bytes=args.max_input_bytes,
            max_records=args.max_records,
        )
        _emit(asdict(summary))
        return
    if args.command == "evaluate":
        parsed = read_jsonl(
            args.input,
            max_input_bytes=args.max_input_bytes,
            max_records=args.max_records,
        )
        _emit(evaluate_records(parsed.records, predictor))
        return
    if args.command == "ui":
        from .ui import build_demo

        demo = build_demo(predictor)
        demo.queue(default_concurrency_limit=1).launch(
            server_name="127.0.0.1",
            server_port=args.port,
            share=False,
            inbrowser=False,
        )
        return
    raise AssertionError(f"unhandled command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and turn expected failures into a concise non-zero exit."""

    try:
        _run(_parser().parse_args(argv))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
