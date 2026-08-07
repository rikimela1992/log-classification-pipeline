from __future__ import annotations

import unittest

from log_classification_pipeline.contracts import (
    BatchValidationError,
    PredictionContractError,
    ValidationIssue,
    validate_input_record,
    validate_prediction_record,
)


class ContractTests(unittest.TestCase):
    def test_validation_error_keeps_all_issues(self) -> None:
        issues = [
            ValidationIssue("first problem", line_number=2),
            ValidationIssue("second problem", line_number=4),
        ]

        error = BatchValidationError(issues)

        self.assertEqual(error.issues, tuple(issues))
        self.assertIn("line 2: first problem", str(error))
        self.assertIn("line 4: second problem", str(error))

    def test_message_is_required_and_optional_fields_are_typed(self) -> None:
        issues = validate_input_record(
            {"message": " ", "host": 12, "app": None, "severity": "error"},
            line_number=7,
        )

        self.assertEqual(len(issues), 3)
        self.assertTrue(all(issue.line_number == 7 for issue in issues))
        self.assertIn("message", issues[0].reason)
        self.assertIn("host", issues[1].reason)
        self.assertIn("app", issues[2].reason)

    def test_unknown_input_fields_are_allowed(self) -> None:
        issues = validate_input_record(
            {"message": "synthetic event", "custom": {"fixture_id": 42}},
            line_number=1,
        )

        self.assertEqual(issues, [])

    def test_prediction_must_be_mapping_with_string_keys(self) -> None:
        with self.assertRaises(PredictionContractError):
            validate_prediction_record(["not", "an", "object"], 1)
        with self.assertRaises(PredictionContractError):
            validate_prediction_record({1: "bad key"}, 1)


if __name__ == "__main__":
    unittest.main()
