from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import ModuleType
from unittest import mock

from log_classification_pipeline.adapters.zero_shot import (
    ZeroShotConfig,
    ZeroShotPredictor,
    load_zero_shot_pipeline,
)
from log_classification_pipeline.cli import _build_predictor, _parser, main
from log_classification_pipeline.model_artifact import (
    MAX_MODEL_BYTES,
    MAX_MODEL_FILES,
    ArtifactManifestError,
    create_artifact_manifest,
    materialize_verified_artifact,
    verify_artifact_manifest,
)
from log_classification_pipeline.model_catalog import configured_model_catalog
from log_classification_pipeline.model_profiles import (
    ENGLISH_PROFILE_ID,
    get_model_profile,
)


class ModelArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "model"
        self.root.mkdir()
        (self.root / "config.json").write_text(
            '{"model_type":"synthetic"}\n',
            encoding="utf-8",
        )
        (self.root / "tokenizer").mkdir()
        (self.root / "tokenizer" / "vocab.json").write_text(
            '{"token":1}\n',
            encoding="utf-8",
        )
        self.manifest_path = Path(self.temporary.name) / "manifest.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_manifest(self, manifest: object) -> None:
        self.manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def test_manifest_is_deterministic_and_verifies_every_file(self) -> None:
        first = create_artifact_manifest(self.root, ENGLISH_PROFILE_ID)
        second = create_artifact_manifest(self.root, ENGLISH_PROFILE_ID)
        self._write_manifest(first)

        verification = verify_artifact_manifest(
            self.root,
            self.manifest_path,
            ENGLISH_PROFILE_ID,
        )

        self.assertEqual(first, second)
        self.assertEqual(verification.tree_sha256, first["tree_sha256"])
        self.assertEqual(verification.file_count, 2)
        self.assertEqual(
            verification.total_bytes,
            sum(item["size"] for item in first["files"]),
        )
        self.assertEqual(
            [item["path"] for item in first["files"]],
            ["config.json", "tokenizer/vocab.json"],
        )
        profile = get_model_profile(ENGLISH_PROFILE_ID)
        self.assertEqual(first["model_id"], profile.model_id)
        self.assertEqual(first["model_revision"], profile.model_revision)

    def test_operational_cache_directories_are_excluded(self) -> None:
        cache = self.root / ".cache"
        cache.mkdir()
        (cache / "download-state").write_text("ignored", encoding="utf-8")

        manifest = create_artifact_manifest(self.root, ENGLISH_PROFILE_ID)

        self.assertNotIn(
            ".cache/download-state",
            [item["path"] for item in manifest["files"]],
        )

    def test_tamper_missing_and_extra_files_fail_closed(self) -> None:
        manifest = create_artifact_manifest(self.root, ENGLISH_PROFILE_ID)
        self._write_manifest(manifest)

        (self.root / "config.json").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ArtifactManifestError, "do not match"):
            verify_artifact_manifest(
                self.root,
                self.manifest_path,
                ENGLISH_PROFILE_ID,
            )

        (self.root / "config.json").write_text(
            '{"model_type":"synthetic"}\n',
            encoding="utf-8",
        )
        (self.root / "extra.bin").write_bytes(b"extra")
        with self.assertRaisesRegex(ArtifactManifestError, "do not match"):
            verify_artifact_manifest(
                self.root,
                self.manifest_path,
                ENGLISH_PROFILE_ID,
            )

        (self.root / "extra.bin").unlink()
        (self.root / "config.json").unlink()
        with self.assertRaisesRegex(ArtifactManifestError, "do not match"):
            verify_artifact_manifest(
                self.root,
                self.manifest_path,
                ENGLISH_PROFILE_ID,
            )

    def test_symbolic_links_and_limits_are_rejected(self) -> None:
        (self.root / "linked.json").symlink_to(self.root / "config.json")
        with self.assertRaisesRegex(ArtifactManifestError, "regular files"):
            create_artifact_manifest(self.root, ENGLISH_PROFILE_ID)
        (self.root / "linked.json").unlink()

        with self.assertRaisesRegex(ArtifactManifestError, "file limit"):
            create_artifact_manifest(
                self.root,
                ENGLISH_PROFILE_ID,
                max_files=1,
            )
        with self.assertRaisesRegex(ArtifactManifestError, "byte limit"):
            create_artifact_manifest(
                self.root,
                ENGLISH_PROFILE_ID,
                max_total_bytes=1,
            )
        for limits in (
            {"max_files": MAX_MODEL_FILES + 1},
            {"max_total_bytes": MAX_MODEL_BYTES + 1},
        ):
            with self.subTest(limits=limits):
                with self.assertRaisesRegex(ValueError, "must not exceed"):
                    create_artifact_manifest(
                        self.root,
                        ENGLISH_PROFILE_ID,
                        **limits,
                    )

        (self.root / "unsafe\\name").write_text("unsafe", encoding="utf-8")
        with self.assertRaisesRegex(ArtifactManifestError, "invalid path"):
            create_artifact_manifest(self.root, ENGLISH_PROFILE_ID)
        (self.root / "unsafe\\name").unlink()

        linked_root = Path(self.temporary.name) / "linked-model"
        linked_root.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ArtifactManifestError, "symbolic link"):
            create_artifact_manifest(linked_root, ENGLISH_PROFILE_ID)

    def test_hard_links_are_rejected(self) -> None:
        external = Path(self.temporary.name) / "external-weights.bin"
        external.write_bytes(b"synthetic-weights")
        linked = self.root / "weights.bin"
        linked.hardlink_to(external)

        with self.assertRaisesRegex(ArtifactManifestError, "one hard link"):
            create_artifact_manifest(self.root, ENGLISH_PROFILE_ID)

    def test_growth_races_are_detected_and_actual_reads_are_bounded(self) -> None:
        race_root = Path(self.temporary.name) / "race-model"
        race_root.mkdir()
        weights = race_root / "weights.bin"
        weights.write_bytes(b"x")
        real_open = os.open
        opened = False

        def mutate_before_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal opened
            if path == "weights.bin" and dir_fd is not None and not opened:
                opened = True
                weights.write_bytes(b"y" * 2_000_000)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch(
            "log_classification_pipeline.model_artifact.os.open",
            side_effect=mutate_before_open,
        ):
            with self.assertRaisesRegex(ArtifactManifestError, "changed during scan"):
                create_artifact_manifest(
                    race_root,
                    ENGLISH_PROFILE_ID,
                    max_total_bytes=1,
                )

        weights.write_bytes(b"x")
        real_read = os.read
        grew_during_read = False

        def grow_during_read(descriptor, amount):
            nonlocal grew_during_read
            chunk = real_read(descriptor, amount)
            if chunk and not grew_during_read:
                grew_during_read = True
                with weights.open("ab") as stream:
                    stream.write(b"z" * 2_000_000)
            return chunk

        with mock.patch(
            "log_classification_pipeline.model_artifact.os.read",
            side_effect=grow_during_read,
        ):
            with self.assertRaisesRegex(ArtifactManifestError, "byte limit"):
                create_artifact_manifest(
                    race_root,
                    ENGLISH_PROFILE_ID,
                    max_total_bytes=1,
                )

    def test_manifest_json_shape_identity_paths_and_duplicates_are_strict(self) -> None:
        manifest = create_artifact_manifest(self.root, ENGLISH_PROFILE_ID)

        wrong_identity = dict(manifest)
        wrong_identity["model_revision"] = "different"
        self._write_manifest(wrong_identity)
        with self.assertRaisesRegex(ArtifactManifestError, "identity"):
            verify_artifact_manifest(
                self.root,
                self.manifest_path,
                ENGLISH_PROFILE_ID,
            )

        unsafe_path = json.loads(json.dumps(manifest))
        unsafe_path["files"][0]["path"] = "../config.json"
        self._write_manifest(unsafe_path)
        with self.assertRaisesRegex(ArtifactManifestError, "unsafe path"):
            verify_artifact_manifest(
                self.root,
                self.manifest_path,
                ENGLISH_PROFILE_ID,
            )

        self.manifest_path.write_text(
            '{"schema_version":1,"schema_version":1}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ArtifactManifestError, "duplicate key"):
            verify_artifact_manifest(
                self.root,
                self.manifest_path,
                ENGLISH_PROFILE_ID,
            )

    def test_cli_create_verify_and_local_predictor_require_manifest(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(
                [
                    "model-manifest",
                    "create",
                    str(self.root),
                    "--model-profile",
                    ENGLISH_PROFILE_ID,
                ]
            )
        self.assertEqual(status, 0)
        manifest = json.loads(output.getvalue())
        self._write_manifest(manifest)

        output = io.StringIO()
        with redirect_stdout(output):
            status = main(
                [
                    "model-manifest",
                    "verify",
                    str(self.root),
                    str(self.manifest_path),
                    "--model-profile",
                    ENGLISH_PROFILE_ID,
                ]
            )
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "verified")

        profile = get_model_profile(ENGLISH_PROFILE_ID)
        arguments = [
            "classify",
            "input.jsonl",
            "output.jsonl",
            "--adapter",
            "zero-shot",
            "--model-source",
            str(self.root),
            "--model-id",
            profile.model_id,
            "--model-revision",
            profile.model_revision,
        ]
        with self.assertRaisesRegex(ValueError, "requires --model-manifest"):
            _build_predictor(_parser().parse_args(arguments))

        predictor = _build_predictor(
            _parser().parse_args(
                [*arguments, "--model-manifest", str(self.manifest_path)]
            )
        )
        self.assertEqual(
            predictor.config.artifact_sha256,
            manifest["tree_sha256"],
        )
        self.assertFalse(predictor.loaded)

    def test_loader_reverifies_before_importing_transformers(self) -> None:
        manifest = create_artifact_manifest(self.root, ENGLISH_PROFILE_ID)
        self._write_manifest(manifest)
        config = ZeroShotConfig.from_profile(
            ENGLISH_PROFILE_ID,
            model_source=self.root,
            artifact_manifest=self.manifest_path,
            artifact_sha256=manifest["tree_sha256"],
        )
        (self.root / "config.json").write_text("tampered\n", encoding="utf-8")

        with self.assertRaises(ArtifactManifestError):
            load_zero_shot_pipeline(config)

        with self.assertRaisesRegex(ArtifactManifestError, "not accessible"):
            ZeroShotConfig.from_profile(
                ENGLISH_PROFILE_ID,
                model_source=Path(self.temporary.name) / "missing-model",
                artifact_manifest=self.manifest_path,
                artifact_sha256=manifest["tree_sha256"],
            )

    def test_private_snapshot_is_verified_and_loader_uses_it(self) -> None:
        manifest = create_artifact_manifest(self.root, ENGLISH_PROFILE_ID)
        self._write_manifest(manifest)
        with materialize_verified_artifact(
            self.root,
            self.manifest_path,
            ENGLISH_PROFILE_ID,
        ) as (snapshot, verification):
            staged_snapshot = snapshot
            self.assertNotEqual(snapshot, self.root)
            self.assertEqual(
                (snapshot / "config.json").read_bytes(),
                (self.root / "config.json").read_bytes(),
            )
            self.assertEqual(verification.tree_sha256, manifest["tree_sha256"])
            self.assertEqual((snapshot / "config.json").stat().st_nlink, 1)
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o700)
        self.assertFalse(staged_snapshot.exists())

        config = ZeroShotConfig.from_profile(
            ENGLISH_PROFILE_ID,
            model_source=self.root,
            artifact_manifest=self.manifest_path,
            artifact_sha256=manifest["tree_sha256"],
        )
        loaded_sources: list[Path] = []

        class FakeTokenizer:
            @classmethod
            def from_pretrained(cls, source, **_kwargs):
                loaded_sources.append(Path(source))
                return {"kind": "tokenizer"}

        class FakeModel:
            @classmethod
            def from_pretrained(cls, source, **_kwargs):
                loaded_sources.append(Path(source))
                return {"kind": "model"}

        fake_transformers = ModuleType("transformers")
        fake_transformers.AutoTokenizer = FakeTokenizer
        fake_transformers.AutoModelForSequenceClassification = FakeModel
        fake_transformers.pipeline = lambda **kwargs: kwargs
        with mock.patch.dict("sys.modules", {"transformers": fake_transformers}):
            pipeline = load_zero_shot_pipeline(config)

        self.assertEqual(len(loaded_sources), 2)
        self.assertTrue(all(source != self.root for source in loaded_sources))
        self.assertTrue(all(not source.exists() for source in loaded_sources))
        self.assertEqual(pipeline["task"], "zero-shot-classification")

    def test_configured_catalog_discloses_verified_artifact_digest(self) -> None:
        manifest = create_artifact_manifest(self.root, ENGLISH_PROFILE_ID)
        self._write_manifest(manifest)
        predictor = ZeroShotPredictor(
            ZeroShotConfig.from_profile(
                ENGLISH_PROFILE_ID,
                model_source=self.root,
                artifact_manifest=self.manifest_path,
                artifact_sha256=manifest["tree_sha256"],
            )
        )

        catalog = configured_model_catalog({ENGLISH_PROFILE_ID: predictor})

        self.assertTrue(catalog[0]["artifact_verified"])
        self.assertEqual(catalog[0]["artifact_sha256"], manifest["tree_sha256"])

    def test_config_rejects_unverified_local_path_and_partial_binding(self) -> None:
        digest = "sha256:" + ("a" * 64)
        for kwargs in (
            {"model_source": self.root},
            {"artifact_manifest": self.manifest_path},
            {"artifact_sha256": digest},
            {"artifact_manifest": self.manifest_path, "artifact_sha256": 1},
            {"artifact_manifest": self.manifest_path, "artifact_sha256": "bad"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    ZeroShotConfig(**kwargs)

    def test_manifest_symlink_is_rejected(self) -> None:
        actual = Path(self.temporary.name) / "actual-manifest.json"
        actual.write_text("{}", encoding="utf-8")
        self.manifest_path.symlink_to(actual)

        with self.assertRaisesRegex(ArtifactManifestError, "regular file"):
            verify_artifact_manifest(
                self.root,
                self.manifest_path,
                ENGLISH_PROFILE_ID,
            )


if __name__ == "__main__":
    unittest.main()
