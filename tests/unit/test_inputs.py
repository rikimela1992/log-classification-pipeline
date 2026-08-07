from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from log_classification_pipeline.contracts import (
    BatchResourceLimitError,
    BatchValidationError,
)
from log_classification_pipeline.defaults import (
    DEFAULT_MAX_ADMITTED_BYTES,
    DEFAULT_MAX_INPUT_BYTES,
    DEFAULT_MAX_RECORDS,
)
from log_classification_pipeline.inputs import read_input_file, resolve_input_format


class InputFormatTests(unittest.TestCase):
    def write(self, root: Path, name: str, payload: bytes) -> Path:
        path = root / name
        path.write_bytes(payload)
        return path

    def test_text_and_log_lines_preserve_messages_and_exact_digest(self) -> None:
        payload = b"first event\r\n\r\n  second event  \nleft\xe2\x80\xa8right\n"
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self.write(Path(raw_directory), "synthetic.LOG", payload)
            parsed = read_input_file(path)

        self.assertEqual(
            [record["message"] for record in parsed.records],
            ["first event", "  second event  ", "left\u2028right"],
        )
        self.assertEqual(parsed.blank_lines, 1)
        self.assertEqual(parsed.source_sha256, hashlib.sha256(payload).hexdigest())

    def test_text_accepts_utf8_bom_without_changing_source_identity(self) -> None:
        payload = b"\xef\xbb\xbfsynthetic event\n"
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self.write(Path(raw_directory), "synthetic.txt", payload)
            parsed = read_input_file(path)

        self.assertEqual(parsed.records, ({"message": "synthetic event"},))
        self.assertEqual(parsed.source_sha256, hashlib.sha256(payload).hexdigest())

    def test_csv_requires_message_and_preserves_quoted_metadata(self) -> None:
        payload = (
            b"message,app,detail\r\n"
            b'"first, synthetic event",demo,"line one\nline two"\r\n'
            b"\r\n"
            b"second event,worker,ok\r\n"
        )
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self.write(Path(raw_directory), "synthetic.csv", payload)
            parsed = read_input_file(path)

        self.assertEqual(len(parsed.records), 2)
        self.assertEqual(parsed.records[0]["message"], "first, synthetic event")
        self.assertEqual(parsed.records[0]["detail"], "line one\nline two")
        self.assertEqual(parsed.records[1]["app"], "worker")
        self.assertEqual(parsed.blank_lines, 1)
        self.assertEqual(parsed.source_sha256, hashlib.sha256(payload).hexdigest())

    def test_csv_header_and_row_shape_fail_closed(self) -> None:
        cases = (
            (b"app,value\ndemo,one\n", "must contain 'message'"),
            (b"message,message\none,two\n", "must be unique"),
            (b"message,app\none\n", "field count does not match"),
            (b"message,\none,two\n", "must be non-blank"),
        )
        for payload, expected in cases:
            with self.subTest(expected=expected):
                with tempfile.TemporaryDirectory() as raw_directory:
                    path = self.write(Path(raw_directory), "synthetic.csv", payload)
                    with self.assertRaisesRegex(BatchValidationError, expected):
                        read_input_file(path)

    def test_csv_aggregates_invalid_messages(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self.write(
                Path(raw_directory),
                "synthetic.csv",
                b"message,app\n,one\n   ,two\n",
            )
            with self.assertRaises(BatchValidationError) as caught:
                read_input_file(path)

        self.assertEqual(len(caught.exception.issues), 2)
        self.assertEqual(
            [issue.line_number for issue in caught.exception.issues],
            [2, 3],
        )

    def test_non_json_formats_enforce_byte_record_and_utf8_limits(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            text_path = self.write(root, "synthetic.txt", b"one\ntwo\n")
            with self.assertRaises(BatchResourceLimitError):
                read_input_file(text_path, max_input_bytes=7)
            with self.assertRaises(BatchResourceLimitError):
                read_input_file(text_path, max_records=1)

            csv_path = self.write(root, "synthetic.csv", b"message\none\ntwo\n")
            with self.assertRaises(BatchResourceLimitError):
                read_input_file(csv_path, max_records=1)

            invalid = self.write(root, "invalid.log", b"first\n\xff\n")
            with self.assertRaises(BatchValidationError) as caught:
                read_input_file(invalid)
            self.assertEqual(caught.exception.issues[0].line_number, 2)

    def test_supported_suffixes_are_explicit_and_override_is_strict(self) -> None:
        self.assertEqual(resolve_input_format("synthetic.ndjson"), "jsonl")
        self.assertEqual(resolve_input_format(r"C:\upload\synthetic.TXT"), "text")
        self.assertEqual(resolve_input_format("synthetic.any", "csv"), "csv")
        with self.assertRaisesRegex(ValueError, "unsupported input file extension"):
            resolve_input_format("synthetic.exe")
        with self.assertRaisesRegex(ValueError, "input_format"):
            resolve_input_format("synthetic.txt", "xml")

    def test_application_defaults_are_explicit_and_memory_bounded(self) -> None:
        self.assertEqual(DEFAULT_MAX_INPUT_BYTES, 25 * 1024 * 1024)
        self.assertEqual(DEFAULT_MAX_RECORDS, 25_000)
        self.assertEqual(DEFAULT_MAX_ADMITTED_BYTES, 50 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
