from __future__ import annotations

import math
import unittest

from log_classification_pipeline.contracts import PredictionContractError
from log_classification_pipeline.prediction import validate_classification_prediction
from log_classification_pipeline.taxonomy import (
    SEVERITY_CANDIDATES,
    SEVERITY_LABELS,
    SUBSYSTEM_CANDIDATES,
    SUBSYSTEM_LABELS,
    TAXONOMY_VERSION,
)


def valid_prediction() -> dict[str, object]:
    return {
        "schema_version": TAXONOMY_VERSION,
        "subsystem": {"label": "auth", "score": 0.987654321},
        "severity": {"label": "warning", "score": 1},
        "abstained": False,
        "model": {"id": "  synthetic-model  ", "revision": "  rev-1  "},
        "message": "must not be retained",
    }


class TaxonomyTests(unittest.TestCase):
    def test_labels_are_unique_and_candidate_maps_are_complete(self) -> None:
        self.assertEqual(len(SUBSYSTEM_LABELS), len(set(SUBSYSTEM_LABELS)))
        self.assertEqual(len(SEVERITY_LABELS), len(set(SEVERITY_LABELS)))
        self.assertEqual(tuple(SUBSYSTEM_CANDIDATES), SUBSYSTEM_LABELS)
        self.assertEqual(tuple(SEVERITY_CANDIDATES), SEVERITY_LABELS)
        self.assertTrue(TAXONOMY_VERSION)

    def test_candidate_descriptions_are_non_blank_and_unique_per_head(self) -> None:
        for candidates in (SUBSYSTEM_CANDIDATES, SEVERITY_CANDIDATES):
            descriptions = tuple(candidates.values())
            self.assertTrue(all(value.strip() for value in descriptions))
            self.assertEqual(len(descriptions), len(set(descriptions)))


class PredictionContractTests(unittest.TestCase):
    def test_valid_prediction_is_normalized_and_privacy_minimal(self) -> None:
        normalized = validate_classification_prediction(valid_prediction(), 3)

        self.assertEqual(normalized["subsystem"], {"label": "auth", "score": 0.987654})
        self.assertEqual(normalized["severity"], {"label": "warning", "score": 1.0})
        self.assertEqual(normalized["model"], {"id": "synthetic-model", "revision": "rev-1"})
        self.assertNotIn("message", normalized)

    def test_top_level_shape_version_and_abstention_are_strict(self) -> None:
        invalid_values = (None, [], "prediction")
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(PredictionContractError):
                    validate_classification_prediction(value, 1)

        for field, value in (("schema_version", "2"), ("abstained", 1)):
            with self.subTest(field=field):
                record = valid_prediction()
                record[field] = value
                with self.assertRaises(PredictionContractError):
                    validate_classification_prediction(record, 1)

    def test_heads_reject_unknown_labels_and_invalid_scores(self) -> None:
        invalid_scores = (True, None, "0.5", -0.01, 1.01, math.nan, math.inf)
        for head in ("subsystem", "severity"):
            with self.subTest(head=head, case="unknown-label"):
                record = valid_prediction()
                record[head] = {"label": "unknown", "score": 0.5}
                with self.assertRaises(PredictionContractError):
                    validate_classification_prediction(record, 7)
            for score in invalid_scores:
                with self.subTest(head=head, score=score):
                    record = valid_prediction()
                    label = "auth" if head == "subsystem" else "warning"
                    record[head] = {"label": label, "score": score}
                    with self.assertRaises(PredictionContractError):
                        validate_classification_prediction(record, 7)

    def test_model_metadata_must_be_non_blank_strings(self) -> None:
        for model in (None, {}, {"id": " ", "revision": "r"}, {"id": "m", "revision": 1}):
            with self.subTest(model=model):
                record = valid_prediction()
                record["model"] = model
                with self.assertRaises(PredictionContractError):
                    validate_classification_prediction(record, 2)

    def test_profile_provenance_is_complete_and_digest_is_strict(self) -> None:
        record = valid_prediction()
        provenance = {
            "profile_id": "multilingual-bge-m3-v1",
            "profile_revision": "1",
            "config_sha256": "sha256:" + ("a" * 64),
        }
        record["model"].update(provenance)
        normalized = validate_classification_prediction(record, 1)
        self.assertEqual(
            normalized["model"]["profile_id"],
            "multilingual-bge-m3-v1",
        )

        for field in provenance:
            with self.subTest(missing=field):
                invalid = valid_prediction()
                invalid["model"].update(provenance)
                del invalid["model"][field]
                with self.assertRaises(PredictionContractError):
                    validate_classification_prediction(invalid, 1)

        invalid = valid_prediction()
        invalid["model"].update(provenance)
        invalid["model"]["config_sha256"] = "sha256:not-a-digest"
        with self.assertRaises(PredictionContractError):
            validate_classification_prediction(invalid, 1)

        signed = valid_prediction()
        signed["model"].update(provenance)
        signed["model"]["config_sha256"] = "sha256:+" + ("a" * 63)
        with self.assertRaises(PredictionContractError):
            validate_classification_prediction(signed, 1)

    def test_artifact_digest_requires_profile_and_is_strict(self) -> None:
        digest = "sha256:" + ("b" * 64)
        record = valid_prediction()
        record["model"].update(
            {
                "profile_id": "english-deberta-v1",
                "profile_revision": "1",
                "config_sha256": "sha256:" + ("a" * 64),
                "artifact_sha256": digest,
            }
        )
        normalized = validate_classification_prediction(record, 1)
        self.assertEqual(normalized["model"]["artifact_sha256"], digest)

        without_profile = valid_prediction()
        without_profile["model"]["artifact_sha256"] = digest
        with self.assertRaisesRegex(PredictionContractError, "requires a profile"):
            validate_classification_prediction(without_profile, 1)

        invalid = valid_prediction()
        invalid["model"].update(record["model"])
        invalid["model"]["artifact_sha256"] = "sha256:not-valid"
        with self.assertRaisesRegex(PredictionContractError, "artifact_sha256"):
            validate_classification_prediction(invalid, 1)

    def test_callers_can_supply_a_versioned_label_subset(self) -> None:
        record = valid_prediction()
        record["subsystem"] = {"label": "custom-subsystem", "score": 0.5}
        record["severity"] = {"label": "custom-severity", "score": 0.5}

        normalized = validate_classification_prediction(
            record,
            1,
            subsystem_labels=("custom-subsystem",),
            severity_labels=("custom-severity",),
        )

        self.assertEqual(normalized["subsystem"]["label"], "custom-subsystem")
        self.assertEqual(normalized["severity"]["label"], "custom-severity")


if __name__ == "__main__":
    unittest.main()
