from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from log_classification_pipeline.contracts import BatchValidationError
from log_classification_pipeline.jsonl import read_jsonl


class JsonlTests(unittest.TestCase):
    def _write(self, directory: Path, payload: bytes) -> Path:
        path = directory / "batch.jsonl"
        path.write_bytes(payload)
        return path

    def test_valid_records_preserve_order_and_exact_source_identity(self) -> None:
        payload = (
            b'{"message":"first","host":"synthetic-node-alpha","extra":1}\n'
            b'\n'
            b'{"message":"second","severity":"warning"}\n'
        )
        with tempfile.TemporaryDirectory() as raw_directory:
            parsed = read_jsonl(self._write(Path(raw_directory), payload))

        self.assertEqual([record["message"] for record in parsed.records], ["first", "second"])
        self.assertEqual(parsed.blank_lines, 1)
        self.assertEqual(parsed.source_sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(parsed.batch_id, f"sha256:{parsed.source_sha256}")

    def test_all_invalid_lines_are_reported(self) -> None:
        payload = (
            b'{"message":"valid"}\n'
            b'{not json}\n'
            b'["not", "an", "object"]\n'
            b'{"host":"missing-message"}\n'
            b'{"message":"duplicate","message":"again"}\n'
            b'{"message":"nan","value":NaN}\n'
        )
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self._write(Path(raw_directory), payload)
            with self.assertRaises(BatchValidationError) as raised:
                read_jsonl(path)

        self.assertEqual([issue.line_number for issue in raised.exception.issues], [2, 3, 4, 5, 6])

    def test_scalar_and_null_are_rejected(self) -> None:
        payload = b'null\n42\n"text"\n'
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self._write(Path(raw_directory), payload)
            with self.assertRaises(BatchValidationError) as raised:
                read_jsonl(path)

        self.assertEqual(len(raised.exception.issues), 3)
        self.assertTrue(
            all("top-level JSON value" in issue.reason for issue in raised.exception.issues)
        )

    def test_empty_batch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self._write(Path(raw_directory), b"\n  \n")
            with self.assertRaises(BatchValidationError) as raised:
                read_jsonl(path)

        self.assertEqual(raised.exception.issues[0].line_number, None)
        self.assertIn("no records", raised.exception.issues[0].reason)

    def test_invalid_utf8_reports_the_source_line(self) -> None:
        payload = b'{"message":"first"}\n{"message":"bad:\xff"}\n'
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self._write(Path(raw_directory), payload)
            with self.assertRaises(BatchValidationError) as raised:
                read_jsonl(path)

        self.assertEqual(raised.exception.issues[0].line_number, 2)
        self.assertIn("UTF-8", raised.exception.issues[0].reason)


if __name__ == "__main__":
    unittest.main()
