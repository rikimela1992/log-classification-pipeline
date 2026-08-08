from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from log_classification_pipeline.adapters.rules import RulesPredictor
from log_classification_pipeline.adapters.zero_shot import (
    ZeroShotConfig,
    ZeroShotPredictor,
)
from log_classification_pipeline.contracts import PredictionContractError
from log_classification_pipeline.model_artifact import create_artifact_manifest
from log_classification_pipeline.model_catalog import (
    configured_model_catalog,
    registered_model_catalog,
)
from log_classification_pipeline.model_profiles import (
    MODEL_PROFILE_IDS,
    MULTILINGUAL_BALANCED_PROFILE_ID,
    MULTILINGUAL_FAST_PROFILE_ID,
    MULTILINGUAL_PROFILE_ID,
    get_model_profile,
)
from log_classification_pipeline.taxonomy import (
    SEVERITY_CANDIDATES,
    SUBSYSTEM_CANDIDATES,
)


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


class ModelCatalogTests(unittest.TestCase):
    def test_catalog_is_safe_ordered_public_metadata(self) -> None:
        catalog = registered_model_catalog(
            (
                "custom-synthetic",
                MULTILINGUAL_PROFILE_ID,
                "rules",
                MULTILINGUAL_FAST_PROFILE_ID,
            )
        )

        self.assertEqual(
            [item["id"] for item in catalog],
            [
                "rules",
                MULTILINGUAL_FAST_PROFILE_ID,
                MULTILINGUAL_PROFILE_ID,
                "custom-synthetic",
            ],
        )
        self.assertEqual(catalog[0]["quality_status"], "wiring-baseline")
        self.assertTrue(catalog[0]["artifact_bundled"])
        self.assertIsNone(catalog[0]["artifact_verified"])
        self.assertEqual(catalog[1]["languages"], ["en", "it", "fr", "es"])
        self.assertEqual(catalog[1]["execution_tier"], "cpu-fast")
        self.assertFalse(catalog[1]["artifact_bundled"])
        self.assertEqual(catalog[-1]["quality_status"], "unknown")
        self.assertIsNone(catalog[-1]["model_id"])

    def test_catalog_rejects_invalid_names_and_deduplicates(self) -> None:
        self.assertEqual(
            [item["id"] for item in registered_model_catalog(("rules", "rules"))],
            ["rules"],
        )
        for names in (("",), (" ",), (None,)):
            with self.subTest(names=names):
                with self.assertRaises(ValueError):
                    registered_model_catalog(names)

    def test_configured_catalog_reserves_trusted_model_names(self) -> None:
        class ArbitraryPredictor:
            def __call__(self, records):
                return list(records)

        class DifferentRules(RulesPredictor):
            model_id = "different-rules"
            revision = "99"

        class DifferentZeroShot(ZeroShotPredictor):
            pass

        with self.assertRaisesRegex(ValueError, "canonical rules identity"):
            configured_model_catalog({"rules": ArbitraryPredictor()})
        with self.assertRaisesRegex(ValueError, "canonical rules identity"):
            configured_model_catalog({"rules": DifferentRules()})
        with self.assertRaisesRegex(ValueError, "matching zero-shot predictor"):
            configured_model_catalog(
                {MULTILINGUAL_PROFILE_ID: RulesPredictor()}
            )
        with self.assertRaisesRegex(ValueError, "matching zero-shot predictor"):
            configured_model_catalog(
                {
                    MULTILINGUAL_PROFILE_ID: DifferentZeroShot(
                        ZeroShotConfig.from_profile(MULTILINGUAL_PROFILE_ID)
                    )
                }
            )
        self.assertEqual(
            configured_model_catalog({"rules": RulesPredictor()})[0]["adapter"],
            "rules",
        )


class ZeroShotConfigTests(unittest.TestCase):
    def test_invalid_configuration_is_rejected(self) -> None:
        cases = (
            {"model_source": " "},
            {"model_source": None},
            {"model_id": " "},
            {"model_id": 1},
            {"revision": " "},
            {"revision": 1},
            {"confidence_threshold": True},
            {"confidence_threshold": -0.1},
            {"confidence_threshold": 1.1},
            {"subsystem_threshold": True},
            {"subsystem_threshold": -0.1},
            {"severity_threshold": 1.1},
            {"inference_batch_size": True},
            {"inference_batch_size": 0},
            {"profile_id": MULTILINGUAL_PROFILE_ID},
            {"profile_id": "outside-registry"},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    ZeroShotConfig(**kwargs)

    def test_versioned_profile_resolves_model_and_stable_configuration(self) -> None:
        profile = get_model_profile(MULTILINGUAL_PROFILE_ID)
        config = ZeroShotConfig.from_profile(
            MULTILINGUAL_PROFILE_ID,
            model_source="/synthetic/local-model",
            subsystem_threshold=0.7,
            severity_threshold=0.5,
        )

        self.assertEqual(config.model_id, profile.model_id)
        self.assertEqual(config.model_source, "/synthetic/local-model")
        self.assertEqual(config.revision, profile.model_revision)
        self.assertEqual(config.resolved_subsystem_threshold, 0.7)
        self.assertEqual(config.resolved_severity_threshold, 0.5)
        self.assertRegex(config.configuration_digest, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(config.configuration_digest, config.configuration_digest)

    def test_multilingual_profiles_are_pinned_and_cover_target_languages(self) -> None:
        fast = get_model_profile(MULTILINGUAL_FAST_PROFILE_ID)
        balanced = get_model_profile(MULTILINGUAL_BALANCED_PROFILE_ID)
        config = ZeroShotConfig.from_profile(MULTILINGUAL_BALANCED_PROFILE_ID)

        self.assertEqual(
            balanced.model_id,
            "MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7",
        )
        self.assertEqual(
            fast.model_id,
            "MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli",
        )
        for profile in (fast, balanced):
            self.assertRegex(profile.model_revision, r"^[0-9a-f]{40}$")
            self.assertEqual(profile.languages, ("en", "it", "fr", "es"))
            self.assertEqual(profile.license_spdx, "MIT")
        self.assertEqual(config.model_id, balanced.model_id)
        self.assertEqual(config.revision, balanced.model_revision)
        self.assertIn(MULTILINGUAL_FAST_PROFILE_ID, MODEL_PROFILE_IDS)
        self.assertIn(MULTILINGUAL_BALANCED_PROFILE_ID, MODEL_PROFILE_IDS)
        self.assertLess(
            MODEL_PROFILE_IDS.index(MULTILINGUAL_FAST_PROFILE_ID),
            MODEL_PROFILE_IDS.index(MULTILINGUAL_BALANCED_PROFILE_ID),
        )
        self.assertLess(
            MODEL_PROFILE_IDS.index(MULTILINGUAL_BALANCED_PROFILE_ID),
            MODEL_PROFILE_IDS.index(MULTILINGUAL_PROFILE_ID),
        )


class ZeroShotPredictorTests(unittest.TestCase):
    def test_verified_artifact_digest_enters_config_and_prediction_provenance(self) -> None:
        fake = FakeZeroShotPipeline()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        model_root = Path(temporary.name) / "model"
        model_root.mkdir()
        (model_root / "config.json").write_text("{}\n", encoding="utf-8")
        manifest = create_artifact_manifest(model_root, "english-deberta-v1")
        manifest_path = Path(temporary.name) / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        digest = manifest["tree_sha256"]
        config = ZeroShotConfig(
            model_source=model_root,
            artifact_manifest=manifest_path,
            artifact_sha256=digest,
        )
        baseline_digest = ZeroShotConfig().configuration_digest

        prediction = ZeroShotPredictor(
            config,
            pipeline_factory=lambda _: fake,
        )([{"message": "synthetic"}])[0]

        self.assertEqual(prediction["model"]["artifact_sha256"], digest)
        self.assertNotEqual(config.configuration_digest, baseline_digest)

    def test_pipeline_is_lazy_reused_and_receives_bounded_options(self) -> None:
        fake = FakeZeroShotPipeline()
        factory_calls = []

        def factory(config):
            factory_calls.append(config)
            return fake

        config = ZeroShotConfig(
            model_source="local-model",
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
        model = predictions[0]["model"]
        profile = get_model_profile("english-deberta-v1")
        self.assertEqual(model["id"], profile.model_id)
        self.assertEqual(model["revision"], profile.model_revision)
        self.assertEqual(model["profile_id"], "english-deberta-v1")
        self.assertEqual(model["profile_revision"], "1")
        self.assertRegex(model["config_sha256"], r"^sha256:[0-9a-f]{64}$")
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

    def test_head_specific_thresholds_are_applied(self) -> None:
        fake = FakeZeroShotPipeline(subsystem_score=0.65, severity_score=0.55)
        predictor = ZeroShotPredictor(
            ZeroShotConfig(
                subsystem_threshold=0.6,
                severity_threshold=0.5,
            ),
            pipeline_factory=lambda config: fake,
        )
        self.assertFalse(predictor([{"message": "synthetic"}])[0]["abstained"])

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
