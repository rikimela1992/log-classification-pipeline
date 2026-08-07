"""Versioned zero-shot model and prompt profiles."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .taxonomy import SEVERITY_CANDIDATES, SUBSYSTEM_CANDIDATES


ENGLISH_PROFILE_ID = "english-deberta-v1"
MULTILINGUAL_PROFILE_ID = "multilingual-bge-m3-v1"
MULTILINGUAL_FAST_PROFILE_ID = "multilingual-minilm-v1"
MULTILINGUAL_BALANCED_PROFILE_ID = "multilingual-mdeberta-v1"


@dataclass(frozen=True, slots=True)
class ModelProfile:
    profile_id: str
    profile_revision: str
    model_id: str
    model_revision: str
    languages: tuple[str, ...]
    license_spdx: str
    execution_tier: str
    subsystem_candidates: tuple[tuple[str, str], ...]
    severity_candidates: tuple[tuple[str, str], ...]
    subsystem_hypothesis: str
    severity_hypothesis: str
    hypothesis_language: str = "en"
    truncation: bool = True

    def canonical_configuration(self) -> dict[str, Any]:
        return {
            "hypothesis_language": self.hypothesis_language,
            "languages": list(self.languages),
            "license_spdx": self.license_spdx,
            "model_id": self.model_id,
            "model_revision": self.model_revision,
            "profile_id": self.profile_id,
            "profile_revision": self.profile_revision,
            "severity_candidates": dict(self.severity_candidates),
            "severity_hypothesis": self.severity_hypothesis,
            "subsystem_candidates": dict(self.subsystem_candidates),
            "subsystem_hypothesis": self.subsystem_hypothesis,
            "truncation": self.truncation,
        }


_COMMON_PROFILE = {
    "profile_revision": "1",
    "license_spdx": "MIT",
    "subsystem_candidates": tuple(SUBSYSTEM_CANDIDATES.items()),
    "severity_candidates": tuple(SEVERITY_CANDIDATES.items()),
    "subsystem_hypothesis": "This technical log event concerns {}.",
    "severity_hypothesis": "The severity of this technical log event is {}.",
}

_PROFILES = {
    ENGLISH_PROFILE_ID: ModelProfile(
        profile_id=ENGLISH_PROFILE_ID,
        model_id="MoritzLaurer/deberta-v3-base-zeroshot-v2.0-c",
        model_revision="bddf8c5411c34ac3565e16e04384fd68b2618dda",
        languages=("en",),
        execution_tier="cpu-standard",
        **_COMMON_PROFILE,
    ),
    MULTILINGUAL_FAST_PROFILE_ID: ModelProfile(
        profile_id=MULTILINGUAL_FAST_PROFILE_ID,
        model_id="MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli",
        model_revision="0a71e92a985b6e1ad1828cf67ce9c459639c1dca",
        languages=("en", "it", "fr", "es"),
        execution_tier="cpu-fast",
        **_COMMON_PROFILE,
    ),
    MULTILINGUAL_BALANCED_PROFILE_ID: ModelProfile(
        profile_id=MULTILINGUAL_BALANCED_PROFILE_ID,
        model_id="MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7",
        model_revision="b5113eb38ab63efdd7f280f8c144ea8b13f978ce",
        languages=("en", "it", "fr", "es"),
        execution_tier="cpu-asynchronous",
        **_COMMON_PROFILE,
    ),
    MULTILINGUAL_PROFILE_ID: ModelProfile(
        profile_id=MULTILINGUAL_PROFILE_ID,
        model_id="MoritzLaurer/bge-m3-zeroshot-v2.0-c",
        model_revision="705510dfe0f35d223a4bf6f5d2695ec5fd162341",
        languages=("en", "it", "fr", "es"),
        execution_tier="gpu-preferred",
        **_COMMON_PROFILE,
    ),
}

MODEL_PROFILES = MappingProxyType(_PROFILES)
MODEL_PROFILE_IDS = tuple(MODEL_PROFILES)


def get_model_profile(profile_id: str) -> ModelProfile:
    if not isinstance(profile_id, str):
        raise ValueError("model profile id must be a string")
    try:
        return MODEL_PROFILES[profile_id]
    except KeyError as exc:
        raise ValueError(f"unknown model profile: {profile_id!r}") from exc


def profile_configuration_digest(
    profile: ModelProfile,
    *,
    model_id: str,
    model_revision: str,
    subsystem_threshold: float,
    severity_threshold: float,
    inference_batch_size: int,
) -> str:
    configuration = {
        **profile.canonical_configuration(),
        "inference_batch_size": inference_batch_size,
        "resolved_model_id": model_id,
        "resolved_model_revision": model_revision,
        "severity_threshold": severity_threshold,
        "subsystem_threshold": subsystem_threshold,
    }
    encoded = json.dumps(
        configuration,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
