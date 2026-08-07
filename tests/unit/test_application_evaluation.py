from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from log_classification_pipeline.adapters.rules import RulesPredictor
from log_classification_pipeline.application import classify_file_preview, classify_message
from log_classification_pipeline.contracts import PredictionContractError
from log_classification_pipeline.evaluation import evaluate_records
from log_classification_pipeline.taxonomy import SEVERITY_LABELS, SUBSYSTEM_LABELS, TAXONOMY_VERSION


def prediction(subsystem: str, severity: str, *, abstained: bool = False, model_id: str = "fixture"):
    return {
        "schema_version": TAXONOMY_VERSION,
        "subsystem": {"label": subsystem, "score": 0.9},
        "severity": {"label": severity, "score": 0.8},
        "abstained": abstained,
        "model": {"id": model_id, "revision": "1"},
    }


class ApplicationTests(unittest.TestCase):
    def test_classify_message_uses_full_pipeline_without_returning_input(self) -> None:
        result = classify_message("Authentication failed", RulesPredictor())
        self.assertEqual(result["subsystem"]["label"], "auth")
        self.assertEqual(result["severity"]["label"], "error")
        self.assertNotIn("message", result)

    def test_classify_message_rejects_blank_or_non_string_values(self) -> None:
        for value in ("", "   ", None, 1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    classify_message(value, RulesPredictor())

    def test_file_preview_is_bounded_but_summary_covers_complete_batch(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            path = Path(raw_directory) / "input.jsonl"
            path.write_text(
                "".join(
                    json.dumps({"message": f"service worker started {index}"}) + "\n"
                    for index in range(3)
                ),
                encoding="utf-8",
            )
            summary, preview = classify_file_preview(
                path,
                RulesPredictor(),
                preview_limit=2,
                max_records=3,
            )

        self.assertEqual(summary["input_records"], 3)
        self.assertEqual(summary["output_records"], 3)
        self.assertEqual(len(preview), 2)
        self.assertTrue(summary["batch_id"].startswith("sha256:"))

    def test_file_preview_configuration_and_resource_limits_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            path = Path(raw_directory) / "input.jsonl"
            path.write_text('{"message":"one"}\n{"message":"two"}\n', encoding="utf-8")
            for limit in (True, 0, -1, 1.5):
                with self.subTest(preview_limit=limit):
                    with self.assertRaises(ValueError):
                        classify_file_preview(path, RulesPredictor(), preview_limit=limit)
            with self.assertRaises(ValueError):
                classify_file_preview(path, RulesPredictor(), max_records=1)


class EvaluationTests(unittest.TestCase):
    def test_perfect_full_taxonomy_evaluation_reports_reproducible_metrics(self) -> None:
        records = []
        expected_predictions = []
        for index, subsystem in enumerate(SUBSYSTEM_LABELS):
            severity = SEVERITY_LABELS[index % len(SEVERITY_LABELS)]
            records.append(
                {
                    "message": f"synthetic event {index}",
                    "expected_subsystem": subsystem,
                    "expected_severity": severity,
                }
            )
            expected_predictions.append(prediction(subsystem, severity))

        def predictor(inputs):
            self.assertEqual(
                inputs,
                [{"message": record["message"]} for record in records],
            )
            return expected_predictions

        with mock.patch(
            "log_classification_pipeline.evaluation.time.perf_counter",
            side_effect=(10.0, 12.0),
        ):
            result = evaluate_records(records, predictor)

        self.assertEqual(result["records"], len(SUBSYSTEM_LABELS))
        self.assertEqual(result["subsystem_accuracy"], 1.0)
        self.assertEqual(result["subsystem_macro_f1"], 1.0)
        self.assertEqual(result["severity_accuracy"], 1.0)
        self.assertEqual(result["severity_macro_f1"], 1.0)
        self.assertEqual(result["coverage"], 1.0)
        self.assertEqual(result["elapsed_seconds"], 2.0)
        self.assertEqual(result["records_per_second"], 5.0)
        self.assertEqual(result["model_counts"], {"fixture": len(records)})

    def test_errors_abstention_and_multiple_models_are_aggregated(self) -> None:
        records = [
            {"message": "one", "expected_subsystem": "auth", "expected_severity": "error"},
            {"message": "two", "expected_subsystem": "network", "expected_severity": "warning"},
        ]
        predictions = [
            prediction("auth", "warning", model_id="a"),
            prediction("compute", "warning", abstained=True, model_id="b"),
        ]
        with mock.patch(
            "log_classification_pipeline.evaluation.time.perf_counter",
            side_effect=(1.0, 1.0),
        ):
            result = evaluate_records(records, lambda inputs: predictions)

        self.assertEqual(result["subsystem_accuracy"], 0.5)
        self.assertEqual(result["severity_accuracy"], 0.5)
        self.assertEqual(result["abstained"], 1)
        self.assertEqual(result["coverage"], 0.5)
        self.assertIsNone(result["records_per_second"])
        self.assertEqual(result["model_counts"], {"a": 1, "b": 1})

    def test_empty_input_and_predictor_cardinality_mismatch_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least one"):
            evaluate_records([], lambda inputs: [])

        record = {
            "message": "one",
            "expected_subsystem": "auth",
            "expected_severity": "error",
        }
        with self.assertRaisesRegex(ValueError, "wrong result count"):
            evaluate_records([record], lambda inputs: [])

    def test_expected_labels_and_predictions_are_validated(self) -> None:
        record = {
            "message": "one",
            "expected_subsystem": "auth",
            "expected_severity": "error",
        }

        for field in ("expected_subsystem", "expected_severity"):
            with self.subTest(field=field):
                invalid = dict(record)
                invalid[field] = "outside-taxonomy"
                with self.assertRaisesRegex(ValueError, f"invalid {field}"):
                    evaluate_records([invalid], lambda inputs: [])

        with self.assertRaises(PredictionContractError):
            evaluate_records([record], lambda inputs: [{"not": "classification"}])


if __name__ == "__main__":
    unittest.main()
