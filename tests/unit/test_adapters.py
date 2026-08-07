from __future__ import annotations

import unittest

from log_classification_pipeline.adapters.rules import RulesPredictor
from log_classification_pipeline.adapters.zero_shot import ZeroShotConfig, ZeroShotPredictor
from log_classification_pipeline.contracts import PredictionContractError
from log_classification_pipeline.taxonomy import SEVERITY_CANDIDATES, SUBSYSTEM_CANDIDATES


class FakeZeroShotPipeline:
    def __init__(self, *, subsystem_score: float = 0.91, severity_score: float = 0.82):
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.subsystem_score = subsystem_score
        self.severity_score = severity_score

    def __call__(self, inputs, **kwargs):
        texts = list(inputs)
        self.calls.append((texts, kwargs))
        is_subsystem = kwargs["candidate_labels"] == list(SUBSYSTEM_CANDIDATES.values())
        label = (
            SUBSYSTEM_CANDIDATES["network"]
            if is_subsystem
            else SEVERITY_CANDIDATES["warning"]
        )
        score = self.subsystem_score if is_subsystem else self.severity_score
        results = [{"labels": [label], "scores": [score]} for _ in texts]
        return results[0] if len(results) == 1 else results


class RulesPredictorTests(unittest.TestCase):
    def test_all_subsystem_rules_are_reachable(self) -> None:
        messages = (
            "authentication completed",
            "firewall policy ready",
            "vpn tunnel connected",
            "wireless access point ready",
            "filesystem backup completed",
            "camera recorder ready",
            "media transcode completed",
            "model inference completed",
            "network route ready",
            "service worker started",
        )

        predictions = RulesPredictor()([{"message": message} for message in messages])

        self.assertEqual(
            [item["subsystem"]["label"] for item in predictions],
            ["auth", "firewall", "vpn", "wifi-ap", "storage", "nvr-cctv", "media", "ai-ml", "network", "compute"],
        )
        self.assertTrue(all(not item["abstained"] for item in predictions))

    def test_severity_precedence_is_security_error_warning_info_routine(self) -> None:
        messages = (
            "authentication denied after error",
            "service failed with warning",
            "network warning while connected",
            "service started",
            "routine service heartbeat",
        )
        predictions = RulesPredictor()([{"message": message} for message in messages])
        self.assertEqual(
            [item["severity"]["label"] for item in predictions],
            ["security_event", "error", "warning", "info", "routine"],
        )

    def test_unknown_subsystem_abstains_without_echoing_input(self) -> None:
        prediction = RulesPredictor()([{"message": "synthetic heartbeat"}])[0]
        self.assertTrue(prediction["abstained"])
        self.assertEqual(prediction["subsystem"], {"label": "compute", "score": 0.0})
        self.assertNotIn("message", prediction)

    def test_threshold_configuration_is_strict(self) -> None:
        for value in (True, "0.5", -0.1, 1.1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    RulesPredictor(confidence_threshold=value)
        self.assertEqual(RulesPredictor()([]), [])


class ZeroShotConfigTests(unittest.TestCase):
    def test_invalid_configuration_is_rejected(self) -> None:
        cases = (
            {"model_source": " "},
            {"model_id": " "},
            {"revision": " "},
            {"confidence_threshold": True},
            {"confidence_threshold": -0.1},
            {"confidence_threshold": 1.1},
            {"inference_batch_size": True},
            {"inference_batch_size": 0},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    ZeroShotConfig(**kwargs)


class ZeroShotPredictorTests(unittest.TestCase):
    def test_pipeline_is_lazy_reused_and_receives_bounded_options(self) -> None:
        fake = FakeZeroShotPipeline()
        factory_calls = []

        def factory(config):
            factory_calls.append(config)
            return fake

        config = ZeroShotConfig(
            model_source="local-model",
            model_id="logical-model",
            revision="sha256:fixture",
            confidence_threshold=0.8,
            inference_batch_size=3,
        )
        predictor = ZeroShotPredictor(config, pipeline_factory=factory)
        self.assertFalse(predictor.loaded)

        predictions = predictor([{"message": "one"}, {"message": "two"}])
        predictor([{"message": "three"}])

        self.assertTrue(predictor.loaded)
        self.assertEqual(factory_calls, [config])
        self.assertEqual(len(fake.calls), 4)
        self.assertEqual(predictions[0]["subsystem"], {"label": "network", "score": 0.91})
        self.assertEqual(predictions[0]["severity"], {"label": "warning", "score": 0.82})
        self.assertEqual(predictions[0]["model"], {"id": "logical-model", "revision": "sha256:fixture"})
        for _, kwargs in fake.calls:
            self.assertFalse(kwargs["multi_label"])
            self.assertTrue(kwargs["truncation"])
            self.assertEqual(kwargs["batch_size"], 3)

    def test_empty_batch_does_not_load_pipeline(self) -> None:
        def unexpected_factory(config):
            self.fail("pipeline factory must not be called")

        predictor = ZeroShotPredictor(pipeline_factory=unexpected_factory)
        self.assertEqual(predictor([]), [])
        self.assertFalse(predictor.loaded)

    def test_low_score_causes_abstention(self) -> None:
        fake = FakeZeroShotPipeline(subsystem_score=0.9, severity_score=0.59)
        predictor = ZeroShotPredictor(pipeline_factory=lambda config: fake)
        self.assertTrue(predictor([{"message": "synthetic"}])[0]["abstained"])

    def test_wrong_count_and_unknown_candidate_fail_closed(self) -> None:
        class WrongCountPipeline:
            def __call__(self, inputs, **kwargs):
                return []

        predictor = ZeroShotPredictor(pipeline_factory=lambda config: WrongCountPipeline())
        with self.assertRaisesRegex(RuntimeError, "wrong result count"):
            predictor([{"message": "one"}])

        class UnknownLabelPipeline:
            def __call__(self, inputs, **kwargs):
                return {"labels": ["not a candidate"], "scores": [0.9]}

        predictor = ZeroShotPredictor(pipeline_factory=lambda config: UnknownLabelPipeline())
        with self.assertRaisesRegex(RuntimeError, "unknown candidate"):
            predictor([{"message": "one"}])


    def test_non_numeric_pipeline_scores_fail_with_stable_error(self) -> None:
        class InvalidScorePipeline:
            def __call__(self, inputs, **kwargs):
                return {"labels": [kwargs["candidate_labels"][0]], "scores": [True]}

        predictor = ZeroShotPredictor(
            pipeline_factory=lambda config: InvalidScorePipeline()
        )
        with self.assertRaisesRegex(RuntimeError, "invalid score"):
            predictor([{"message": "one"}])
    def test_non_finite_pipeline_score_is_rejected_by_output_contract(self) -> None:
        fake = FakeZeroShotPipeline(subsystem_score=float("nan"))
        predictor = ZeroShotPredictor(pipeline_factory=lambda config: fake)
        with self.assertRaises(PredictionContractError):
            predictor([{"message": "one"}])


if __name__ == "__main__":
    unittest.main()
