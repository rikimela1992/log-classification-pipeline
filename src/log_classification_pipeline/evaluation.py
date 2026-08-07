"""Dependency-free evaluation helpers for synthetic labelled fixtures."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from .batch import Predictor
from .taxonomy import SEVERITY_LABELS, SUBSYSTEM_LABELS
from .prediction import validate_classification_prediction


_SUPPORTED_FIXTURE_LANGUAGES = ("en", "it", "fr", "es")


def _macro_f1(
    expected: list[str],
    predicted: list[str],
    labels: Sequence[str],
) -> float:
    scores = []
    pairs = tuple(zip(expected, predicted, strict=True))
    for label in labels:
        true_positive = sum(e == label and p == label for e, p in pairs)
        false_positive = sum(e != label and p == label for e, p in pairs)
        false_negative = sum(e == label and p != label for e, p in pairs)
        denominator = (2 * true_positive) + false_positive + false_negative
        scores.append((2 * true_positive / denominator) if denominator else 0.0)
    return sum(scores) / len(scores)


def _accuracy(expected: list[str], predicted: list[str]) -> float:
    return sum(
        expected_value == predicted_value
        for expected_value, predicted_value in zip(
            expected,
            predicted,
            strict=True,
        )
    ) / len(expected)


def _selective_accuracy(
    expected: list[str],
    predicted: list[str],
    accepted: list[bool],
) -> float | None:
    selected = [
        (expected_value, predicted_value)
        for expected_value, predicted_value, is_accepted in zip(
            expected,
            predicted,
            accepted,
            strict=True,
        )
        if is_accepted
    ]
    if not selected:
        return None
    return sum(
        expected_value == predicted_value
        for expected_value, predicted_value in selected
    ) / len(selected)


def _group_metrics(
    indices: list[int],
    expected_subsystem: list[str],
    expected_severity: list[str],
    predicted_subsystem: list[str],
    predicted_severity: list[str],
    accepted: list[bool],
) -> dict[str, Any]:
    group_expected_subsystem = [expected_subsystem[index] for index in indices]
    group_expected_severity = [expected_severity[index] for index in indices]
    group_predicted_subsystem = [predicted_subsystem[index] for index in indices]
    group_predicted_severity = [predicted_severity[index] for index in indices]
    group_accepted = [accepted[index] for index in indices]
    scored_subsystem = [
        predicted if is_accepted else "__abstain__"
        for predicted, is_accepted in zip(
            group_predicted_subsystem,
            group_accepted,
            strict=True,
        )
    ]
    scored_severity = [
        predicted if is_accepted else "__abstain__"
        for predicted, is_accepted in zip(
            group_predicted_severity,
            group_accepted,
            strict=True,
        )
    ]
    joint_successes = sum(
        is_accepted
        and expected_subsystem_value == predicted_subsystem_value
        and expected_severity_value == predicted_severity_value
        for (
            expected_subsystem_value,
            predicted_subsystem_value,
            expected_severity_value,
            predicted_severity_value,
            is_accepted,
        ) in zip(
            group_expected_subsystem,
            group_predicted_subsystem,
            group_expected_severity,
            group_predicted_severity,
            group_accepted,
            strict=True,
        )
    )
    return {
        "records": len(indices),
        "coverage": round(sum(group_accepted) / len(indices), 6),
        "subsystem_accuracy": round(
            _accuracy(group_expected_subsystem, scored_subsystem),
            6,
        ),
        "severity_accuracy": round(
            _accuracy(group_expected_severity, scored_severity),
            6,
        ),
        "joint_accuracy": round(joint_successes / len(indices), 6),
        "selective_subsystem_accuracy": (
            round(value, 6)
            if (
                value := _selective_accuracy(
                    group_expected_subsystem,
                    group_predicted_subsystem,
                    group_accepted,
                )
            )
            is not None
            else None
        ),
        "selective_severity_accuracy": (
            round(value, 6)
            if (
                value := _selective_accuracy(
                    group_expected_severity,
                    group_predicted_severity,
                    group_accepted,
                )
            )
            is not None
            else None
        ),
    }


def evaluate_records(
    records: Sequence[Mapping[str, Any]],
    predictor: Predictor,
) -> dict[str, Any]:
    """Evaluate predictions; fixtures must include expected labels."""

    if not records:
        raise ValueError("evaluation requires at least one record")
    inputs = []
    expected_subsystem: list[str] = []
    expected_severity: list[str] = []
    languages: list[str | None] = []
    fixture_versions: set[str] = set()
    scenario_ids: set[str] = set()
    metadata_values: dict[str, list[str | None]] = {
        "fixture_version": [],
        "scenario_id": [],
        "split": [],
    }
    for index, record in enumerate(records, start=1):
        message = record.get("message")
        if not isinstance(message, str) or not message.strip():
            raise ValueError(
                f"evaluation record {index} message must be a non-blank string"
            )
        subsystem = record.get("expected_subsystem")
        if not isinstance(subsystem, str) or subsystem not in SUBSYSTEM_LABELS:
            raise ValueError(
                f"evaluation record {index} has invalid expected_subsystem"
            )
        severity = record.get("expected_severity")
        if not isinstance(severity, str) or severity not in SEVERITY_LABELS:
            raise ValueError(
                f"evaluation record {index} has invalid expected_severity"
            )
        inputs.append({"message": message})
        expected_subsystem.append(subsystem)
        expected_severity.append(severity)
        language = record.get("language")
        if language is not None and (
            not isinstance(language, str)
            or language not in _SUPPORTED_FIXTURE_LANGUAGES
        ):
            raise ValueError(f"evaluation record {index} has invalid language")
        languages.append(language)
        for field in ("fixture_version", "scenario_id", "split"):
            value = record.get(field)
            metadata_values[field].append(value)
            if value is not None and (
                not isinstance(value, str) or not value.strip()
            ):
                raise ValueError(
                    f"evaluation record {index} has invalid {field}"
                )
        fixture_version = record.get("fixture_version")
        if isinstance(fixture_version, str):
            fixture_versions.add(fixture_version)
        scenario_id = record.get("scenario_id")
        if isinstance(scenario_id, str):
            if scenario_id in scenario_ids:
                raise ValueError(
                    f"evaluation record {index} has duplicate scenario_id"
                )
            scenario_ids.add(scenario_id)
        split = record.get("split")
        if split is not None and split not in {"development", "test"}:
            raise ValueError(f"evaluation record {index} has invalid split")

    if len(fixture_versions) > 1:
        raise ValueError("evaluation records mix fixture versions")
    for field, values in metadata_values.items():
        if any(value is None for value in values) and any(
            value is not None for value in values
        ):
            raise ValueError(
                f"evaluation {field} must be present on every record"
            )
    if len(
        {value for value in metadata_values["split"] if value is not None}
    ) > 1:
        raise ValueError("evaluation records mix splits")
    if any(language is None for language in languages) and any(
        language is not None for language in languages
    ):
        raise ValueError("evaluation language must be present on every record")

    started = time.perf_counter()
    predictions = list(predictor(inputs))
    elapsed = time.perf_counter() - started
    if len(predictions) != len(records):
        raise ValueError("predictor returned the wrong result count")
    predictions = [
        validate_classification_prediction(item, index)
        for index, item in enumerate(predictions, start=1)
    ]
    model_provenance = {
        (
            str(item["model"]["id"]),
            str(item["model"]["revision"]),
            item["model"].get("profile_id"),
            item["model"].get("profile_revision"),
            item["model"].get("config_sha256"),
            item["model"].get("artifact_sha256"),
        )
        for item in predictions
    }
    if len(model_provenance) != 1:
        raise ValueError("evaluation predictions mix model provenance")

    predicted_subsystem = [
        str(item["subsystem"]["label"]) for item in predictions
    ]
    predicted_severity = [
        str(item["severity"]["label"]) for item in predictions
    ]
    abstained = sum(bool(item["abstained"]) for item in predictions)
    accepted = [not bool(item["abstained"]) for item in predictions]
    scored_subsystem = [
        label if is_accepted else "__abstain__"
        for label, is_accepted in zip(
            predicted_subsystem,
            accepted,
            strict=True,
        )
    ]
    scored_severity = [
        label if is_accepted else "__abstain__"
        for label, is_accepted in zip(
            predicted_severity,
            accepted,
            strict=True,
        )
    ]
    overall = _group_metrics(
        list(range(len(records))),
        expected_subsystem,
        expected_severity,
        predicted_subsystem,
        predicted_severity,
        accepted,
    )
    result = {
        "records": len(records),
        "subsystem_accuracy": round(
            _accuracy(expected_subsystem, scored_subsystem),
            6,
        ),
        "subsystem_macro_f1": round(
            _macro_f1(
                expected_subsystem,
                scored_subsystem,
                SUBSYSTEM_LABELS,
            ),
            6,
        ),
        "severity_accuracy": round(
            _accuracy(expected_severity, scored_severity),
            6,
        ),
        "severity_macro_f1": round(
            _macro_f1(
                expected_severity,
                scored_severity,
                SEVERITY_LABELS,
            ),
            6,
        ),
        "abstained": abstained,
        "coverage": round(1 - (abstained / len(records)), 6),
        "joint_accuracy": overall["joint_accuracy"],
        "selective_subsystem_accuracy": overall[
            "selective_subsystem_accuracy"
        ],
        "selective_severity_accuracy": overall[
            "selective_severity_accuracy"
        ],
        "elapsed_seconds": round(elapsed, 6),
        "records_per_second": (
            round(len(records) / elapsed, 3) if elapsed else None
        ),
        "model_counts": dict(
            Counter(str(item["model"]["id"]) for item in predictions)
        ),
        "model": dict(predictions[0]["model"]),
    }
    fixture_version = metadata_values["fixture_version"][0]
    split = metadata_values["split"][0]
    if fixture_version is not None:
        result["fixture_version"] = fixture_version
    if split is not None:
        result["split"] = split
    observed_languages = sorted({value for value in languages if value is not None})
    if observed_languages:
        language_metrics = {
            language: _group_metrics(
                [index for index, value in enumerate(languages) if value == language],
                expected_subsystem,
                expected_severity,
                predicted_subsystem,
                predicted_severity,
                accepted,
            )
            for language in observed_languages
        }
        result["language_metrics"] = language_metrics
        result["worst_language"] = {
            metric: min(
                language_metrics,
                key=lambda language: language_metrics[language][metric],
            )
            for metric in (
                "coverage",
                "joint_accuracy",
                "severity_accuracy",
                "subsystem_accuracy",
            )
        }
        result["max_language_gap"] = {
            metric: round(
                max(values) - min(values),
                6,
            )
            for metric in (
                "coverage",
                "joint_accuracy",
                "severity_accuracy",
                "subsystem_accuracy",
            )
            if (
                values := [
                    language_metrics[language][metric]
                    for language in observed_languages
                ]
            )
        }
    return result
