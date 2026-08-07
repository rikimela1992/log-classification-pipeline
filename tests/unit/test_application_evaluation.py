from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from log_classification_pipeline.adapters.rules import RulesPredictor
from log_classification_pipeline.application import (
    classify_file_into_workspace,
    classify_file_preview,
    classify_message,
)
from log_classification_pipeline.contracts import PredictionContractError
from log_classification_pipeline.contracts import BatchResourceLimitError
from log_classification_pipeline.evaluation import evaluate_records
from log_classification_pipeline.taxonomy import SEVERITY_LABELS, SUBSYSTEM_LABELS, TAXONOMY_VERSION
from log_classification_pipeline.workspace import AuthorizationError, Role, Workspace


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

    def test_workspace_classification_is_complete_and_privacy_minimal_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            input_path = root / "input.jsonl"
            input_path.write_text(
                '{"message":"Authentication failed"}\n',
                encoding="utf-8",
            )
            workspace = Workspace(root / "state" / "workspace.sqlite3")
            workspace.bootstrap(
                "sample-org",
                "owner",
                "correct-horse-battery-staple",
            )
            token, _ = workspace.login(
                "sample-org",
                "owner",
                "correct-horse-battery-staple",
            )

            summary, job_id = classify_file_into_workspace(
                input_path,
                RulesPredictor(),
                workspace,
                token,
            )
            job = workspace.get_job(token, job_id, include_raw=True)

        self.assertEqual(summary["input_records"], 1)
        self.assertEqual(job["status"], "succeeded")
        self.assertIsNone(job["raw_payload"])
        self.assertEqual(job["results"][0]["subsystem"]["label"], "auth")
        self.assertNotIn("message", job["results"][0])

    def test_failed_workspace_classification_leaves_no_job(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            input_path = root / "input.jsonl"
            input_path.write_text('{"message":"synthetic"}\n', encoding="utf-8")
            workspace = Workspace(root / "workspace.sqlite3")
            workspace.bootstrap(
                "sample-org",
                "owner",
                "correct-horse-battery-staple",
            )
            token, _ = workspace.login(
                "sample-org",
                "owner",
                "correct-horse-battery-staple",
            )

            with self.assertRaises(PredictionContractError):
                classify_file_into_workspace(
                    input_path,
                    lambda records: [],
                    workspace,
                    token,
                )

            self.assertEqual(workspace.list_jobs(token), [])

    def test_workspace_denies_viewer_before_reading_or_calling_predictor(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            input_path = root / "input.jsonl"
            input_path.write_text('{"message":"synthetic"}\n', encoding="utf-8")
            workspace = Workspace(root / "workspace.sqlite3")
            workspace.bootstrap(
                "sample-org",
                "owner",
                "correct-horse-battery-staple",
            )
            admin_token, _ = workspace.login(
                "sample-org",
                "owner",
                "correct-horse-battery-staple",
            )
            workspace.create_user(
                admin_token,
                "reviewer",
                "viewer-password-value",
                Role.VIEWER,
            )
            viewer_token, _ = workspace.login(
                "sample-org",
                "reviewer",
                "viewer-password-value",
            )
            workspace.create_user(
                admin_token,
                "analyst",
                "analyst-password-value",
                Role.ANALYST,
            )
            analyst_token, _ = workspace.login(
                "sample-org",
                "analyst",
                "analyst-password-value",
            )
            predictor_calls = []

            def predictor(records):
                predictor_calls.append(len(records))
                return [prediction("compute", "routine") for _ in records]

            with self.assertRaises(AuthorizationError):
                classify_file_into_workspace(
                    input_path,
                    predictor,
                    workspace,
                    viewer_token,
                )

            self.assertEqual(predictor_calls, [])
            self.assertEqual(workspace.list_jobs(viewer_token), [])

            with self.assertRaises(AuthorizationError):
                classify_file_into_workspace(
                    input_path,
                    predictor,
                    workspace,
                    analyst_token,
                    store_raw=True,
                )
            self.assertEqual(predictor_calls, [])

    def test_workspace_raw_reread_remains_bounded_if_source_grows(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            input_path = root / "input.jsonl"
            input_path.write_text('{"message":"synthetic"}\n', encoding="utf-8")
            workspace = Workspace(root / "workspace.sqlite3")
            workspace.bootstrap(
                "sample-org",
                "owner",
                "correct-horse-battery-staple",
            )
            token, _ = workspace.login(
                "sample-org",
                "owner",
                "correct-horse-battery-staple",
            )
            from log_classification_pipeline import application

            real_process_batch = application.process_batch

            def mutate_after_classification(*args, **kwargs):
                summary = real_process_batch(*args, **kwargs)
                input_path.write_bytes(b"x" * 101)
                return summary

            with (
                mock.patch(
                    "log_classification_pipeline.application.process_batch",
                    side_effect=mutate_after_classification,
                ),
                self.assertRaises(BatchResourceLimitError),
            ):
                classify_file_into_workspace(
                    input_path,
                    RulesPredictor(),
                    workspace,
                    token,
                    store_raw=True,
                    max_input_bytes=100,
                )

            self.assertEqual(workspace.list_jobs(token), [])


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
