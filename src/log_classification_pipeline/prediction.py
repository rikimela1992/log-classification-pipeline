"""Strict classification output contract shared by model adapters."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

from .contracts import PredictionContractError
from .taxonomy import SEVERITY_LABELS, SUBSYSTEM_LABELS, TAXONOMY_VERSION


def _validate_head(
    value: object,
    *,
    name: str,
    labels: Sequence[str],
    output_index: int,
) -> dict[str, str | float]:
    if not isinstance(value, Mapping):
        raise PredictionContractError(
            f"prediction {output_index} field {name!r} must be a mapping"
        )

    label = value.get("label")
    score = value.get("score")
    if label not in labels:
        raise PredictionContractError(
            f"prediction {output_index} field {name!r} has unknown label {label!r}"
        )
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or score < 0
        or score > 1
    ):
        raise PredictionContractError(
            f"prediction {output_index} field {name!r} score must be finite in [0, 1]"
        )
    return {"label": str(label), "score": round(float(score), 6)}


def validate_classification_prediction(
    record: object,
    output_index: int,
    *,
    subsystem_labels: Sequence[str] = SUBSYSTEM_LABELS,
    severity_labels: Sequence[str] = SEVERITY_LABELS,
) -> dict[str, Any]:
    """Validate and normalize one privacy-minimal classification prediction."""

    if not isinstance(record, Mapping):
        raise PredictionContractError(
            f"prediction {output_index} must be a mapping"
        )
    if record.get("schema_version") != TAXONOMY_VERSION:
        raise PredictionContractError(
            f"prediction {output_index} has unsupported schema_version"
        )
    abstained = record.get("abstained")
    if not isinstance(abstained, bool):
        raise PredictionContractError(
            f"prediction {output_index} field 'abstained' must be boolean"
        )

    model = record.get("model")
    if not isinstance(model, Mapping):
        raise PredictionContractError(
            f"prediction {output_index} field 'model' must be a mapping"
        )
    model_id = model.get("id")
    revision = model.get("revision")
    if not isinstance(model_id, str) or not model_id.strip():
        raise PredictionContractError(
            f"prediction {output_index} model id must be a non-blank string"
        )
    if not isinstance(revision, str) or not revision.strip():
        raise PredictionContractError(
            f"prediction {output_index} model revision must be a non-blank string"
        )

    optional_model_fields = {}
    present_provenance = {
        name: model.get(name)
        for name in ("profile_id", "profile_revision", "config_sha256")
        if name in model
    }
    if present_provenance:
        if set(present_provenance) != {
            "profile_id",
            "profile_revision",
            "config_sha256",
        }:
            raise PredictionContractError(
                f"prediction {output_index} model profile provenance is incomplete"
            )
        for name, value in present_provenance.items():
            if not isinstance(value, str) or not value.strip():
                raise PredictionContractError(
                    f"prediction {output_index} model {name} must be a non-blank string"
                )
            optional_model_fields[name] = value.strip()
        digest = optional_model_fields["config_sha256"]
        hexadecimal = digest.removeprefix("sha256:")
        if (
            len(digest) != 71
            or not digest.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in hexadecimal)
        ):
            raise PredictionContractError(
                f"prediction {output_index} model config_sha256 is invalid"
            )

    return {
        "schema_version": TAXONOMY_VERSION,
        "subsystem": _validate_head(
            record.get("subsystem"),
            name="subsystem",
            labels=subsystem_labels,
            output_index=output_index,
        ),
        "severity": _validate_head(
            record.get("severity"),
            name="severity",
            labels=severity_labels,
            output_index=output_index,
        ),
        "abstained": abstained,
        "model": {
            "id": model_id.strip(),
            "revision": revision.strip(),
            **optional_model_fields,
        },
    }
