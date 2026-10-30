from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from log_classification_pipeline.contracts import (
    BatchResourceLimitError,
    BatchValidationError,
)
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

    def test_utf8_bom_is_accepted_without_changing_source_identity(self) -> None:
        payload = b'\xef\xbb\xbf{"message":"synthetic event"}\n'
        with tempfile.TemporaryDirectory() as raw_directory:
            parsed = read_jsonl(self._write(Path(raw_directory), payload))

        self.assertEqual(parsed.records[0]["message"], "synthetic event")
        self.assertEqual(parsed.source_sha256, hashlib.sha256(payload).hexdigest())

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

    def test_unicode_line_separators_inside_strings_are_not_jsonl_delimiters(self) -> None:
        for separator in ("\u0085", "\u2028", "\u2029"):
            with self.subTest(separator=ord(separator)):
                payload = (
                    json.dumps(
                        {"message": f"left{separator}right"},
                        ensure_ascii=False,
                    ).encode("utf-8")
                    + b"\n"
                )
                with tempfile.TemporaryDirectory() as raw_directory:
                    parsed = read_jsonl(self._write(Path(raw_directory), payload))
                self.assertEqual(parsed.records[0]["message"], f"left{separator}right")

    def test_input_limits_accept_boundary_and_reject_first_excess(self) -> None:
        payload = b'{"message":"one"}\n{"message":"two"}\n'
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self._write(Path(raw_directory), payload)

            parsed = read_jsonl(path, max_input_bytes=len(payload), max_records=2)
            self.assertEqual(len(parsed.records), 2)

            with self.assertRaises(BatchResourceLimitError) as byte_error:
                read_jsonl(path, max_input_bytes=len(payload) - 1)
            self.assertEqual(byte_error.exception.resource, "input byte count")

            with self.assertRaises(BatchResourceLimitError) as record_error:
                read_jsonl(path, max_records=1)
            self.assertEqual(record_error.exception.resource, "record count")
            self.assertEqual(record_error.exception.issues[0].line_number, 2)

    def test_invalid_input_limit_configuration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self._write(Path(raw_directory), b'{"message":"one"}\n')
            for invalid_limit in (0, -1, True, 1.5):
                with self.subTest(limit=invalid_limit):
                    with self.assertRaises(ValueError):
                        read_jsonl(path, max_input_bytes=invalid_limit)
                    with self.assertRaises(ValueError):
                        read_jsonl(path, max_records=invalid_limit)

    def test_excessive_nesting_is_a_located_validation_issue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.jsonl"
            path.write_bytes(
                b'{"message":"synthetic"}\n' + b"[" * 200_000 + b"\n",
            )
            with self.assertRaises(BatchValidationError) as caught:
                read_jsonl(path)
        self.assertEqual(caught.exception.issues[0].line_number, 2)
        self.assertIn("too deep", caught.exception.issues[0].reason)


if __name__ == "__main__":
    unittest.main()
