from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from log_classification_pipeline.batch import BatchCancelledError, process_batch
from log_classification_pipeline.contracts import (
    BatchResourceLimitError,
    BatchValidationError,
    PredictionContractError,
)


class RecordingPredictor:
    def __init__(self) -> None:
        self.calls: list[list[dict[str, object]]] = []

    def __call__(self, records):
        copied = [dict(record) for record in records]
        self.calls.append(copied)
        return [
            {
                "message": record["message"],
                "predicted_category": "synthetic-category-a",
            }
            for record in copied
        ]


class BatchTests(unittest.TestCase):
    def _input(self, directory: Path, lines: list[dict[str, object]]) -> Path:
        path = directory / "input.jsonl"
        path.write_text(
            "".join(json.dumps(line) + "\n" for line in lines),
            encoding="utf-8",
        )
        return path

    def test_chunks_input_and_publishes_one_output_per_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(
                directory,
                [{"message": f"event-{index}"} for index in range(5)],
            )
            destination = directory / "output.jsonl"
            predictor = RecordingPredictor()

            summary = process_batch(source, destination, predictor, batch_size=2)

            self.assertEqual([len(call) for call in predictor.calls], [2, 2, 1])
            self.assertEqual(summary.input_records, 5)
            self.assertEqual(summary.output_records, 5)
            self.assertTrue(summary.batch_id.startswith("sha256:"))
            self.assertEqual(len(destination.read_text(encoding="utf-8").splitlines()), 5)

    def test_progress_is_monotonic_and_cancellation_discards_staged_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(
                directory,
                [{"message": f"event-{index}"} for index in range(5)],
            )
            destination = directory / "output.jsonl"
            predictor = RecordingPredictor()
            progress: list[tuple[int, int]] = []

            with self.assertRaises(BatchCancelledError):
                process_batch(
                    source,
                    destination,
                    predictor,
                    batch_size=2,
                    progress_callback=lambda processed, total: progress.append(
                        (processed, total)
                    ),
                    should_cancel=lambda: bool(progress and progress[-1][0] >= 2),
                )

            self.assertEqual(progress, [(0, 5), (2, 5)])
            self.assertEqual(len(predictor.calls), 1)
            self.assertFalse(destination.exists())

    def test_invalid_input_is_rejected_before_predictor_is_called(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = directory / "input.jsonl"
            source.write_text('{"message":"valid"}\n{bad json}\n', encoding="utf-8")
            destination = directory / "output.jsonl"
            predictor = RecordingPredictor()

            with self.assertRaises(BatchValidationError):
                process_batch(source, destination, predictor)

            self.assertEqual(predictor.calls, [])
            self.assertFalse(destination.exists())

    def test_predictor_count_mismatch_leaves_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(directory, [{"message": "one"}, {"message": "two"}])
            destination = directory / "output.jsonl"

            with self.assertRaisesRegex(PredictionContractError, "count mismatch"):
                process_batch(source, destination, lambda records: [{"only": "one"}])

            self.assertFalse(destination.exists())

    def test_predictor_overproduction_is_consumed_only_to_first_excess(self) -> None:
        consumed: list[int] = []

        def overproducing_predictor(records):
            for index in range(100):
                consumed.append(index)
                if len(consumed) > len(records) + 1:
                    raise AssertionError("predictor output was consumed without a bound")
                yield {"result": index}

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(directory, [{"message": "one"}, {"message": "two"}])
            destination = directory / "output.jsonl"

            with self.assertRaisesRegex(PredictionContractError, "count mismatch"):
                process_batch(source, destination, overproducing_predictor)

            self.assertEqual(len(consumed), 3)
            self.assertFalse(destination.exists())

    def test_configured_input_limit_stops_before_predictor(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(directory, [{"message": "one"}, {"message": "two"}])
            destination = directory / "output.jsonl"
            predictor = RecordingPredictor()

            with self.assertRaises(BatchResourceLimitError):
                process_batch(source, destination, predictor, max_records=1)

            self.assertEqual(predictor.calls, [])
            self.assertFalse(destination.exists())

    def test_output_mode_is_configurable(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(directory, [{"message": "one"}])
            destination = directory / "output.jsonl"

            process_batch(
                source,
                destination,
                RecordingPredictor(),
                output_mode=0o640,
            )

            self.assertEqual(destination.stat().st_mode & 0o777, 0o640)

    def test_predictor_exception_leaves_no_output(self) -> None:
        def failing_predictor(records):
            raise RuntimeError("model unavailable")

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(directory, [{"message": "one"}])
            destination = directory / "output.jsonl"

            with self.assertRaisesRegex(RuntimeError, "model unavailable"):
                process_batch(source, destination, failing_predictor)

            self.assertFalse(destination.exists())

    def test_predictor_failure_in_later_chunk_leaves_no_output(self) -> None:
        call_count = 0

        def failing_later(records):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise RuntimeError("second chunk failed")
            return [{"result": "ok"} for _ in records]

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(
                directory,
                [{"message": "one"}, {"message": "two"}, {"message": "three"}],
            )
            destination = directory / "output.jsonl"

            with self.assertRaisesRegex(RuntimeError, "second chunk failed"):
                process_batch(source, destination, failing_later, batch_size=2)

            self.assertEqual(call_count, 2)
            self.assertFalse(destination.exists())

    def test_predictor_type_error_is_not_reclassified(self) -> None:
        def failing_predictor(records):
            raise TypeError("tensor shape bug")

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(directory, [{"message": "one"}])
            destination = directory / "output.jsonl"

            with self.assertRaisesRegex(TypeError, "tensor shape bug"):
                process_batch(source, destination, failing_predictor)

            self.assertFalse(destination.exists())

    def test_existing_output_stops_before_predictor(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(directory, [{"message": "one"}])
            destination = directory / "output.jsonl"
            destination.write_text("sentinel\n", encoding="utf-8")
            predictor = RecordingPredictor()

            with self.assertRaises(FileExistsError):
                process_batch(source, destination, predictor)

            self.assertEqual(predictor.calls, [])
            self.assertEqual(destination.read_text(encoding="utf-8"), "sentinel\n")

    def test_overwrite_failure_preserves_existing_output(self) -> None:
        def failing_predictor(records):
            raise RuntimeError("model failed")

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(directory, [{"message": "one"}])
            destination = directory / "output.jsonl"
            destination.write_bytes(b"sentinel\n")

            with self.assertRaisesRegex(RuntimeError, "model failed"):
                process_batch(source, destination, failing_predictor, overwrite=True)

            self.assertEqual(destination.read_bytes(), b"sentinel\n")

    def test_destination_created_during_prediction_wins_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(directory, [{"message": "one"}])
            destination = directory / "output.jsonl"

            def racing_predictor(records):
                destination.write_text("other-worker\n", encoding="utf-8")
                return [{"result": "ours"} for _ in records]

            with self.assertRaises(FileExistsError):
                process_batch(source, destination, racing_predictor)

            self.assertEqual(destination.read_text(encoding="utf-8"), "other-worker\n")

    def test_configuration_and_path_errors_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(directory, [{"message": "one"}])
            predictor = RecordingPredictor()

            for invalid_size in (0, -1, True, 1.5):
                with self.subTest(batch_size=invalid_size):
                    with self.assertRaises(ValueError):
                        process_batch(source, directory / "output.jsonl", predictor, batch_size=invalid_size)

            with self.assertRaises(ValueError):
                process_batch(source, source, predictor)

    def test_input_output_symlink_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            destination = self._input(directory, [{"message": "one"}])
            source_alias = directory / "input-link.jsonl"
            source_alias.symlink_to(destination)
            predictor = RecordingPredictor()

            with self.assertRaises(ValueError):
                process_batch(source_alias, destination, predictor, overwrite=True)

            self.assertEqual(predictor.calls, [])

    def test_input_output_hard_link_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            source = self._input(directory, [{"message": "one"}])
            destination = directory / "hard-link.jsonl"
            destination.hardlink_to(source)
            predictor = RecordingPredictor()

            with self.assertRaises(ValueError):
                process_batch(source, destination, predictor, overwrite=True)

            self.assertEqual(predictor.calls, [])

    def test_input_output_parent_symlink_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            real_parent = directory / "real"
            real_parent.mkdir()
            source = self._input(real_parent, [{"message": "one"}])
            alias_parent = directory / "alias"
            alias_parent.symlink_to(real_parent, target_is_directory=True)
            destination_alias = alias_parent / source.name
            predictor = RecordingPredictor()

            with self.assertRaises(ValueError):
                process_batch(source, destination_alias, predictor, overwrite=True)

            self.assertEqual(predictor.calls, [])


if __name__ == "__main__":
    unittest.main()
