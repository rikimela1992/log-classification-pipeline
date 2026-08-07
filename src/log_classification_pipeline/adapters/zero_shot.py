"""Lazy, offline-first zero-shot adapter backed by an NLI encoder."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from numbers import Real
from pathlib import Path
from typing import Any, Protocol

from ..prediction import validate_classification_prediction
from ..taxonomy import (
    SEVERITY_CANDIDATES,
    SUBSYSTEM_CANDIDATES,
    TAXONOMY_VERSION,
)

DEFAULT_MODEL_ID = "MoritzLaurer/deberta-v3-base-zeroshot-v2.0-c"
DEFAULT_MODEL_REVISION = "bddf8c5411c34ac3565e16e04384fd68b2618dda"


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
    inference_batch_size: int = 8

    def __post_init__(self) -> None:
        if not str(self.model_source).strip():
            raise ValueError("model_source must not be blank")
        if not self.revision.strip():
            raise ValueError("revision must not be blank")
        if not self.model_id.strip():
            raise ValueError("model_id must not be blank")
        if isinstance(self.confidence_threshold, bool) or not isinstance(
            self.confidence_threshold, (int, float)
        ):
            raise ValueError("confidence_threshold must be numeric")
        if not 0 <= self.confidence_threshold <= 1:
            raise ValueError("confidence_threshold must be in [0, 1]")
        if (
            isinstance(self.inference_batch_size, bool)
            or not isinstance(self.inference_batch_size, int)
            or self.inference_batch_size <= 0
        ):
            raise ValueError("inference_batch_size must be a positive integer")


def load_zero_shot_pipeline(config: ZeroShotConfig) -> ZeroShotPipeline:
    """Load only local files unless the caller explicitly permits a download."""

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
    source = str(config.model_source)
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
            truncation=True,
        )
        results = _as_result_list(raw, len(texts), task)
        return [_top_prediction(result, candidates, task) for result in results]

    def __call__(
        self,
        records: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        if not records:
            return []
        texts = [str(record["message"]) for record in records]
        subsystems = self._classify(
            texts,
            SUBSYSTEM_CANDIDATES,
            "This technical log event concerns {}.",
            "subsystem",
        )
        severities = self._classify(
            texts,
            SEVERITY_CANDIDATES,
            "The severity of this technical log event is {}.",
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
                "abstained": min(subsystem_score, severity_score)
                < self.config.confidence_threshold,
                "model": {
                    "id": self.config.model_id,
                    "revision": self.config.revision,
                },
            }
            predictions.append(
                validate_classification_prediction(raw_prediction, output_index)
            )
        return predictions
