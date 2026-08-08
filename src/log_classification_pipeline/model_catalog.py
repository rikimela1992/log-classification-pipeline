"""Public, lazy model metadata for CLI, API, and interface discovery."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .adapters.rules import RulesPredictor
from .adapters.zero_shot import ZeroShotPredictor
from .batch import Predictor
from .model_profiles import MODEL_PROFILE_IDS, MODEL_PROFILES

RULES_MODEL_NAME = "rules"


def _rules_metadata() -> dict[str, Any]:
    return {
        "adapter": "rules",
        "artifact_bundled": True,
        "artifact_verified": None,
        "artifact_sha256": None,
        "execution_tier": "cpu-fast",
        "experimental": True,
        "id": RULES_MODEL_NAME,
        "languages": ["en"],
        "license_spdx": "MIT",
        "model_id": RulesPredictor.model_id,
        "model_revision": RulesPredictor.revision,
        "profile_revision": None,
        "quality_status": "wiring-baseline",
    }


def _profile_metadata(profile_id: str) -> dict[str, Any]:
    profile = MODEL_PROFILES[profile_id]
    return {
        "adapter": "zero-shot",
        "artifact_bundled": False,
        "artifact_verified": False,
        "artifact_sha256": None,
        "execution_tier": profile.execution_tier,
        "experimental": True,
        "id": profile.profile_id,
        "languages": list(profile.languages),
        "license_spdx": profile.license_spdx,
        "model_id": profile.model_id,
        "model_revision": profile.model_revision,
        "profile_revision": profile.profile_revision,
        "quality_status": "unqualified",
    }


def _custom_metadata(model_name: str) -> dict[str, Any]:
    return {
        "adapter": "custom",
        "artifact_bundled": None,
        "artifact_verified": None,
        "artifact_sha256": None,
        "execution_tier": "unknown",
        "experimental": True,
        "id": model_name,
        "languages": [],
        "license_spdx": None,
        "model_id": None,
        "model_revision": None,
        "profile_revision": None,
        "quality_status": "unknown",
    }


def registered_model_catalog(model_names: Iterable[str]) -> list[dict[str, Any]]:
    """Resolve deterministic metadata for explicit registered model names."""

    unique_names = tuple(dict.fromkeys(model_names))
    if any(not isinstance(name, str) or not name.strip() for name in unique_names):
        raise ValueError("model names must be non-blank strings")
    available = set(unique_names)
    ordered_names = []
    if RULES_MODEL_NAME in available:
        ordered_names.append(RULES_MODEL_NAME)
    ordered_names.extend(
        profile_id for profile_id in MODEL_PROFILE_IDS if profile_id in available
    )
    ordered_names.extend(
        sorted(available.difference(ordered_names))
    )

    catalog = []
    for model_name in ordered_names:
        if model_name == RULES_MODEL_NAME:
            catalog.append(_rules_metadata())
        elif model_name in MODEL_PROFILES:
            catalog.append(_profile_metadata(model_name))
        else:
            catalog.append(_custom_metadata(model_name))
    return catalog


def configured_model_catalog(
    predictors: Mapping[str, Predictor],
) -> list[dict[str, Any]]:
    """Validate reserved identities and describe configured predictors lazily."""

    for model_name, predictor in predictors.items():
        if model_name == RULES_MODEL_NAME and (
            type(predictor) is not RulesPredictor
        ):
            raise ValueError(
                "the reserved rules name requires the canonical rules identity"
            )
        if model_name in MODEL_PROFILES and (
            type(predictor) is not ZeroShotPredictor
            or predictor.config.profile_id != model_name
        ):
            raise ValueError(
                "registered profile names require their matching zero-shot predictor"
            )
    catalog = registered_model_catalog(predictors)
    by_name = {item["id"]: item for item in catalog}
    for model_name, predictor in predictors.items():
        if type(predictor) is ZeroShotPredictor and predictor.config.artifact_sha256:
            by_name[model_name]["artifact_verified"] = True
            by_name[model_name]["artifact_sha256"] = (
                predictor.config.artifact_sha256
            )
    return catalog
