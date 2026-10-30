from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from log_classification_pipeline.adapters.rules import RulesPredictor
from log_classification_pipeline.cli import main
from log_classification_pipeline.report import (
    group_findings,
    render_text_report,
    summarize_predictions,
)

RECORDS = [
    {"message": "Oct 30 12:00:01 host sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"},
    {"message": "Oct 30 12:00:02 host sshd[2]: Failed password for root from 203.0.113.6 port 2 ssh2"},
    {"message": "2026-10-30T12:00:03Z WARN disk /var usage 91%"},
    {"message": "2026-10-30T12:00:04Z ERROR service crashed"},
    {"message": "2026-10-30T12:00:05Z INFO service started"},
]


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.predictions = RulesPredictor()(RECORDS)

    def test_summary_counts_and_ranks_attention_worst_first(self) -> None:
        summary = summarize_predictions(self.predictions)
        self.assertEqual(summary["records"], 5)
        self.assertEqual(summary["severity"]["security_event"], 2)
        self.assertEqual(summary["attention_total"], 4)
        self.assertEqual(
            [item["record"] for item in summary["attention"]], [1, 2, 4, 3]
        )
        self.assertNotIn("message", repr(summary))

    def test_attention_limit_keeps_the_total(self) -> None:
        summary = summarize_predictions(self.predictions, attention_limit=1)
        self.assertEqual(len(summary["attention"]), 1)
        self.assertEqual(summary["attention_total"], 4)
        with self.assertRaises(ValueError):
            summarize_predictions(self.predictions, attention_limit=0)

    def test_repeated_events_collapse_into_one_pattern(self) -> None:
        findings = group_findings(RECORDS, self.predictions)
        self.assertEqual(findings[0]["count"], 2)
        self.assertEqual(findings[0]["first_record"], 1)
        self.assertEqual(len(findings), 3)
        self.assertEqual(len(group_findings(RECORDS, self.predictions, limit=1)), 1)

    def test_mismatched_inputs_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            group_findings(RECORDS[:1], self.predictions)

    def test_text_report_handles_a_clean_file(self) -> None:
        predictions = RulesPredictor()(RECORDS[-1:])
        text = render_text_report(summarize_predictions(predictions), [])
        self.assertIn("Nothing needs attention.", text)

    def test_cli_report_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.log"
            output = Path(directory) / "out.jsonl"
            source.write_text(
                "\n".join(item["message"] for item in RECORDS) + "\n", encoding="utf-8"
            )
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["classify", str(source), str(output)]), 0)
            text = io.StringIO()
            with contextlib.redirect_stdout(text):
                self.assertEqual(main(["report", str(source), str(output)]), 0)
            self.assertIn("2 x security_event", text.getvalue())
            emitted = io.StringIO()
            with contextlib.redirect_stdout(emitted):
                self.assertEqual(
                    main(["report", str(source), str(output), "--json", "--limit", "1"]),
                    0,
                )
            self.assertEqual(len(json.loads(emitted.getvalue())["findings"]), 1)
            output.write_text("{}\n", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["report", str(source), str(output)]), 2)


if __name__ == "__main__":
    unittest.main()
