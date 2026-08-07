"""Lazy, offline-first zero-shot adapter backed by an NLI encoder."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from numbers import Real
from pathlib import Path
from typing import Any, Protocol

from ..model_artifact import (
    materialize_verified_artifact,
    verify_artifact_manifest,
)
from ..model_profiles import (
    ENGLISH_PROFILE_ID,
    get_model_profile,
    profile_configuration_digest,
)
from ..prediction import validate_classification_prediction
from ..taxonomy import TAXONOMY_VERSION

_DEFAULT_PROFILE = get_model_profile(ENGLISH_PROFILE_ID)
DEFAULT_MODEL_ID = _DEFAULT_PROFILE.model_id
DEFAULT_MODEL_REVISION = _DEFAULT_PROFILE.model_revision


class ZeroShotPipeline(Protocol):
    def __call__(self, inputs, **kwargs): ...


@dataclass(frozen=True, slots=True)
class ZeroShotConfig:
    model_source: str | Path = DEFAULT_MODEL_ID
    model_id: str = DEFAULT_MODEL_ID
    revision: str = DEFAULT_MODEL_REVISION
    allow_download: bool = False
    device: int | str = -1
    confidence_threshold: float = 0.60
    subsystem_threshold: float | None = None
    severity_threshold: float | None = None
    inference_batch_size: int = 8
    profile_id: str = ENGLISH_PROFILE_ID
    artifact_manifest: str | Path | None = None
    artifact_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.model_source, (str, Path)) or not str(
            self.model_source
        ).strip():
            raise ValueError("model_source must not be blank")
        if not isinstance(self.revision, str) or not self.revision.strip():
            raise ValueError("revision must not be blank")
        if not isinstance(self.model_id, str) or not self.model_id.strip():
            raise ValueError("model_id must not be blank")
        if isinstance(self.confidence_threshold, bool) or not isinstance(
            self.confidence_threshold, (int, float)
        ):
            raise ValueError("confidence_threshold must be numeric")
        if not 0 <= self.confidence_threshold <= 1:
            raise ValueError("confidence_threshold must be in [0, 1]")
        for name, value in (
            ("subsystem_threshold", self.subsystem_threshold),
            ("severity_threshold", self.severity_threshold),
        ):
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not 0 <= value <= 1
            ):
                raise ValueError(f"{name} must be numeric in [0, 1]")
        if (
            isinstance(self.inference_batch_size, bool)
            or not isinstance(self.inference_batch_size, int)
            or self.inference_batch_size <= 0
        ):
            raise ValueError("inference_batch_size must be a positive integer")
        profile = get_model_profile(self.profile_id)
        if (
            self.model_id != profile.model_id
            or self.revision != profile.model_revision
        ):
            raise ValueError(
                "model_id and revision must match the selected model profile"
            )
        if (self.artifact_manifest is None) != (self.artifact_sha256 is None):
            raise ValueError(
                "artifact_manifest and artifact_sha256 must be provided together"
            )
        if self.artifact_manifest is not None and (
            not isinstance(self.artifact_manifest, (str, Path))
            or not str(self.artifact_manifest).strip()
        ):
            raise ValueError("artifact_manifest must not be blank")
        if self.artifact_sha256 is not None:
            if not isinstance(self.artifact_sha256, str):
                raise ValueError("artifact_sha256 must be a SHA-256 digest")
            hexadecimal = self.artifact_sha256.removeprefix("sha256:")
            if (
                len(self.artifact_sha256) != 71
                or not self.artifact_sha256.startswith("sha256:")
                or any(
                    character not in "0123456789abcdef"
                    for character in hexadecimal
                )
            ):
                raise ValueError("artifact_sha256 must be a SHA-256 digest")
            verification = verify_artifact_manifest(
                Path(self.model_source),
                self.artifact_manifest,
                self.profile_id,
            )
            if verification.tree_sha256 != self.artifact_sha256:
                raise ValueError(
                    "artifact_sha256 does not match the verified artifact manifest"
                )
        if isinstance(self.model_source, Path) and self.artifact_manifest is None:
            raise ValueError(
                "a local Path model_source requires a verified artifact manifest"
            )

    @property
    def resolved_subsystem_threshold(self) -> float:
        value = self.subsystem_threshold
        return float(self.confidence_threshold if value is None else value)

    @property
    def resolved_severity_threshold(self) -> float:
        value = self.severity_threshold
        return float(self.confidence_threshold if value is None else value)

    @classmethod
    def from_profile(cls, profile_id: str, **kwargs) -> ZeroShotConfig:
        profile = get_model_profile(profile_id)
        model_source = kwargs.pop("model_source", profile.model_id)
        return cls(
            model_source=model_source,
            model_id=profile.model_id,
            revision=profile.model_revision,
            profile_id=profile.profile_id,
            **kwargs,
        )

    @property
    def configuration_digest(self) -> str:
        return profile_configuration_digest(
            get_model_profile(self.profile_id),
            model_id=self.model_id,
            model_revision=self.revision,
            subsystem_threshold=self.resolved_subsystem_threshold,
            severity_threshold=self.resolved_severity_threshold,
            inference_batch_size=self.inference_batch_size,
            artifact_sha256=self.artifact_sha256,
        )


def load_zero_shot_pipeline(config: ZeroShotConfig) -> ZeroShotPipeline:
    """Load only local files unless the caller explicitly permits a download."""

    source_path = Path(config.model_source)
    local_source = isinstance(config.model_source, Path) or source_path.is_dir()
    if local_source:
        if config.artifact_manifest is None or config.artifact_sha256 is None:
            raise RuntimeError(
                "local model loading requires a verified artifact manifest"
            )
        source_context = materialize_verified_artifact(
            source_path,
            config.artifact_manifest,
            config.profile_id,
        )
    else:
        source_context = nullcontext((source_path, None))

    with source_context as (load_root, verification):
        if (
            verification is not None
            and verification.tree_sha256 != config.artifact_sha256
        ):
            raise RuntimeError("local model artifact digest changed before loading")
        try:
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
                pipeline,
            )
        except ImportError as exc:
            raise RuntimeError(
                "zero-shot support is optional; install "
                "'log-classification-pipeline[ml]'"
            ) from exc

        common = {
            "revision": config.revision,
            "local_files_only": not config.allow_download,
            "trust_remote_code": False,
        }
        source = str(load_root if local_source else config.model_source)
        tokenizer = AutoTokenizer.from_pretrained(source, **common)
        model = AutoModelForSequenceClassification.from_pretrained(
            source,
            use_safetensors=True,
            **common,
        )
        return pipeline(
            task="zero-shot-classification",
            model=model,
            tokenizer=tokenizer,
            device=config.device,
        )


def _as_result_list(raw: object, expected: int, task: str) -> list[Mapping[str, Any]]:
    if expected == 1 and isinstance(raw, Mapping):
        values = [raw]
    elif isinstance(raw, list):
        values = raw
    else:
        raise RuntimeError(f"{task} pipeline returned an unsupported result type")
    if len(values) != expected or any(not isinstance(value, Mapping) for value in values):
        raise RuntimeError(f"{task} pipeline returned the wrong result count")
    return values


def _top_prediction(
    result: Mapping[str, Any],
    candidates: Mapping[str, str],
    task: str,
) -> tuple[str, float]:
    labels = result.get("labels")
    scores = result.get("scores")
    if (
        not isinstance(labels, list)
        or not isinstance(scores, list)
        or not labels
        or len(labels) != len(scores)
    ):
        raise RuntimeError(f"{task} pipeline result is missing labels or scores")
    reverse = {description: label for label, description in candidates.items()}
    label = reverse.get(labels[0])
    if label is None:
        raise RuntimeError(f"{task} pipeline returned an unknown candidate label")
    score = scores[0]
    if isinstance(score, bool) or not isinstance(score, Real):
        raise RuntimeError(f"{task} pipeline returned an invalid score")
    return label, float(score)


class ZeroShotPredictor:
    """Run subsystem and severity classification through one lazy NLI model."""

    def __init__(
        self,
        config: ZeroShotConfig | None = None,
        *,
        pipeline_factory: Callable[[ZeroShotConfig], ZeroShotPipeline] = load_zero_shot_pipeline,
    ):
        self.config = config or ZeroShotConfig()
        self._pipeline_factory = pipeline_factory
        self._pipeline: ZeroShotPipeline | None = None

    @property
    def loaded(self) -> bool:
        return self._pipeline is not None

    def _get_pipeline(self) -> ZeroShotPipeline:
        if self._pipeline is None:
            self._pipeline = self._pipeline_factory(self.config)
        return self._pipeline

    def _classify(
        self,
        texts: list[str],
        candidates: Mapping[str, str],
        hypothesis_template: str,
        task: str,
    ) -> list[tuple[str, float]]:
        classifier = self._get_pipeline()
        raw = classifier(
            texts,
            candidate_labels=list(candidates.values()),
            hypothesis_template=hypothesis_template,
            multi_label=False,
            batch_size=self.config.inference_batch_size,
            truncation=get_model_profile(self.config.profile_id).truncation,
        )
        results = _as_result_list(raw, len(texts), task)
        return [_top_prediction(result, candidates, task) for result in results]

    def __call__(
        self,
        records: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        if not records:
            return []
        profile = get_model_profile(self.config.profile_id)
        texts = [str(record["message"]) for record in records]
        subsystems = self._classify(
            texts,
            dict(profile.subsystem_candidates),
            profile.subsystem_hypothesis,
            "subsystem",
        )
        severities = self._classify(
            texts,
            dict(profile.severity_candidates),
            profile.severity_hypothesis,
            "severity",
        )

        predictions = []
        for output_index, (subsystem, severity) in enumerate(
            zip(subsystems, severities, strict=True),
            start=1,
        ):
            subsystem_label, subsystem_score = subsystem
            severity_label, severity_score = severity
            raw_prediction = {
                "schema_version": TAXONOMY_VERSION,
                "subsystem": {
                    "label": subsystem_label,
                    "score": subsystem_score,
                },
                "severity": {
                    "label": severity_label,
                    "score": severity_score,
                },
                "abstained": (
                    subsystem_score < self.config.resolved_subsystem_threshold
                    or severity_score < self.config.resolved_severity_threshold
                ),
                "model": {
                    "id": self.config.model_id,
                    "revision": self.config.revision,
                    "profile_id": profile.profile_id,
                    "profile_revision": profile.profile_revision,
                    "config_sha256": self.config.configuration_digest,
                    **(
                        {"artifact_sha256": self.config.artifact_sha256}
                        if self.config.artifact_sha256 is not None
                        else {}
                    ),
                },
            }
            predictions.append(
                validate_classification_prediction(raw_prediction, output_index)
            )
        return predictions
