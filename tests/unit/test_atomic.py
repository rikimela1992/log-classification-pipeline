from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from log_classification_pipeline.atomic import (
    PublicationCleanupError,
    PublicationDurabilityError,
    atomic_write_jsonl,
)
from log_classification_pipeline.contracts import PredictionContractError


class AtomicWriteTests(unittest.TestCase):
    def _temporary_files(self, directory: Path, destination: Path) -> list[Path]:
        return list(directory.glob(f".{destination.name}.*.tmp"))

    def test_success_publishes_complete_output_and_removes_temp(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            destination = directory / "output.jsonl"

            count = atomic_write_jsonl(destination, [{"id": 1}, {"id": 2}])

            self.assertEqual(count, 2)
            self.assertEqual(destination.read_text(encoding="utf-8").splitlines(), [
                '{"id":1}',
                '{"id":2}',
            ])
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self._temporary_files(directory, destination), [])

    def test_failure_keeps_existing_output_byte_identical(self) -> None:
        sentinel = b"known-good-output\n"

        def broken_records():
            yield {"id": 1}
            raise RuntimeError("predictor failed")

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            destination = directory / "output.jsonl"
            destination.write_bytes(sentinel)

            with self.assertRaisesRegex(RuntimeError, "predictor failed"):
                atomic_write_jsonl(destination, broken_records(), overwrite=True)

            self.assertEqual(destination.read_bytes(), sentinel)
            self.assertEqual(self._temporary_files(directory, destination), [])

    def test_existing_output_fails_closed_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            destination = Path(raw_directory) / "output.jsonl"
            destination.write_text("sentinel\n", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                atomic_write_jsonl(destination, [{"id": 1}])

            self.assertEqual(destination.read_text(encoding="utf-8"), "sentinel\n")

    def test_symlink_destination_is_rejected_even_with_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            target = directory / "target.jsonl"
            target.write_text("sentinel\n", encoding="utf-8")
            destination = directory / "output.jsonl"
            destination.symlink_to(target)

            with self.assertRaises(FileExistsError):
                atomic_write_jsonl(destination, [{"id": 1}], overwrite=True)

            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_non_finite_output_is_not_published(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            destination = directory / "output.jsonl"

            with self.assertRaises(ValueError):
                atomic_write_jsonl(destination, [{"confidence": float("nan")}])

            self.assertFalse(destination.exists())
            self.assertEqual(self._temporary_files(directory, destination), [])

    def test_non_serializable_output_raises_contract_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            destination = directory / "output.jsonl"

            with self.assertRaisesRegex(PredictionContractError, "not JSON serializable"):
                atomic_write_jsonl(destination, [{"value": object()}])

            self.assertFalse(destination.exists())
            self.assertEqual(self._temporary_files(directory, destination), [])

    def test_invalid_mode_is_rejected_before_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            destination = directory / "output.jsonl"

            for invalid_mode in (True, -1, 0o1000, 1.5):
                with self.subTest(mode=invalid_mode):
                    with self.assertRaises(ValueError):
                        atomic_write_jsonl(destination, [{"id": 1}], mode=invalid_mode)
                    self.assertFalse(destination.exists())

    def test_mode_failure_does_not_publish_or_leave_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            destination = directory / "output.jsonl"

            with mock.patch(
                "log_classification_pipeline.atomic.os.fchmod",
                side_effect=OSError("mode failed"),
            ):
                with self.assertRaisesRegex(OSError, "mode failed"):
                    atomic_write_jsonl(destination, [{"id": 1}])

            self.assertFalse(destination.exists())
            self.assertEqual(self._temporary_files(directory, destination), [])

    def test_link_failure_does_not_publish_or_leave_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            destination = directory / "output.jsonl"

            with mock.patch("log_classification_pipeline.atomic.os.link", side_effect=OSError("link failed")):
                with self.assertRaisesRegex(OSError, "link failed"):
                    atomic_write_jsonl(destination, [{"id": 1}])

            self.assertFalse(destination.exists())
            self.assertEqual(self._temporary_files(directory, destination), [])

    def test_temporary_link_cleanup_failure_reports_committed_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            destination = directory / "output.jsonl"
            original_unlink = Path.unlink

            def fail_temporary_unlink(path, *args, **kwargs):
                if path.name.startswith(f".{destination.name}."):
                    raise OSError("cleanup failed")
                return original_unlink(path, *args, **kwargs)

            with mock.patch.object(Path, "unlink", new=fail_temporary_unlink):
                with self.assertRaises(PublicationCleanupError) as raised:
                    atomic_write_jsonl(destination, [{"id": 1}])

            self.assertTrue(raised.exception.published)
            self.assertTrue(destination.exists())
            self.assertEqual(raised.exception.destination, destination)
            self.assertEqual(len(self._temporary_files(directory, destination)), 1)

    def test_replace_failure_keeps_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            destination = directory / "output.jsonl"
            destination.write_text("sentinel\n", encoding="utf-8")

            with mock.patch("log_classification_pipeline.atomic.os.replace", side_effect=OSError("disk error")):
                with self.assertRaisesRegex(OSError, "disk error"):
                    atomic_write_jsonl(destination, [{"id": 1}], overwrite=True)

            self.assertEqual(destination.read_text(encoding="utf-8"), "sentinel\n")
            self.assertEqual(self._temporary_files(directory, destination), [])

    def test_post_commit_sync_failure_has_unambiguous_exception(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            destination = directory / "output.jsonl"
            destination.write_text("old\n", encoding="utf-8")

            with mock.patch(
                "log_classification_pipeline.atomic._sync_directory",
                side_effect=OSError("sync failed"),
            ):
                with self.assertRaises(PublicationDurabilityError) as raised:
                    atomic_write_jsonl(destination, [{"id": 1}], overwrite=True)

            self.assertTrue(raised.exception.published)
            self.assertEqual(raised.exception.destination, destination)
            self.assertEqual(destination.read_text(encoding="utf-8"), '{"id":1}\n')


if __name__ == "__main__":
    unittest.main()
