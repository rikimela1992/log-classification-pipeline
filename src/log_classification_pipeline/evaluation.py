"""Dependency-free evaluation helpers for synthetic labelled fixtures."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from .batch import Predictor
from .taxonomy import SEVERITY_LABELS, SUBSYSTEM_LABELS
from .prediction import validate_classification_prediction


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

    started = time.perf_counter()
    predictions = list(predictor(inputs))
    elapsed = time.perf_counter() - started
    if len(predictions) != len(records):
        raise ValueError("predictor returned the wrong result count")
    predictions = [
        validate_classification_prediction(item, index)
        for index, item in enumerate(predictions, start=1)
    ]

    predicted_subsystem = [
        str(item["subsystem"]["label"]) for item in predictions
    ]
    predicted_severity = [
        str(item["severity"]["label"]) for item in predictions
    ]
    abstained = sum(bool(item["abstained"]) for item in predictions)
    return {
        "records": len(records),
        "subsystem_accuracy": round(
            sum(
                expected == predicted
                for expected, predicted in zip(
                    expected_subsystem,
                    predicted_subsystem,
                    strict=True,
                )
            )
            / len(records),
            6,
        ),
        "subsystem_macro_f1": round(
            _macro_f1(
                expected_subsystem,
                predicted_subsystem,
                SUBSYSTEM_LABELS,
            ),
            6,
        ),
        "severity_accuracy": round(
            sum(
                expected == predicted
                for expected, predicted in zip(
                    expected_severity,
                    predicted_severity,
                    strict=True,
                )
            )
            / len(records),
            6,
        ),
        "severity_macro_f1": round(
            _macro_f1(
                expected_severity,
                predicted_severity,
                SEVERITY_LABELS,
            ),
            6,
        ),
        "abstained": abstained,
        "coverage": round(1 - (abstained / len(records)), 6),
        "elapsed_seconds": round(elapsed, 6),
        "records_per_second": (
            round(len(records) / elapsed, 3) if elapsed else None
        ),
        "model_counts": dict(
            Counter(str(item["model"]["id"]) for item in predictions)
        ),
    }
