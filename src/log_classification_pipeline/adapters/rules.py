"""Deterministic synthetic baseline; this is not a machine-learning model."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..prediction import validate_classification_prediction
from ..taxonomy import TAXONOMY_VERSION

_SUBSYSTEM_RULES = (
    ("auth", ("login", "credential", "authentication", "permission")),
    ("firewall", ("firewall", "packet", "policy", "blocked traffic")),
    ("vpn", ("vpn", "tunnel", "wireguard")),
    ("wifi-ap", ("wifi", "wireless", "access point")),
    ("storage", ("disk", "filesystem", "volume", "backup")),
    ("nvr-cctv", ("camera", "surveillance", "recorder")),
    ("media", ("stream", "transcode", "playback", "codec")),
    ("ai-ml", ("model", "inference", "training", "tensor")),
    ("network", ("network", "route", "dns", "connection")),
    ("compute", ("process", "service", "runtime", "worker")),
)

_SECURITY_TERMS = ("denied", "unauthorized", "brute force", "intrusion")
_ERROR_TERMS = ("failed", "failure", "error", "crash", "unavailable")
_WARNING_TERMS = ("warning", "degraded", "retry", "slow")
_INFO_TERMS = ("started", "completed", "connected", "ready")


def _first_match(message: str, rules: tuple[tuple[str, tuple[str, ...]], ...]):
    for label, terms in rules:
        if any(term in message for term in terms):
            return label
    return None


class RulesPredictor:
    """Classify intentionally simple synthetic messages for wiring demos."""

    model_id = "synthetic-rules-baseline"
    revision = "1"

    def __init__(self, *, confidence_threshold: float = 0.60):
        if isinstance(confidence_threshold, bool) or not isinstance(
            confidence_threshold, (int, float)
        ):
            raise ValueError("confidence_threshold must be numeric")
        if not 0 <= confidence_threshold <= 1:
            raise ValueError("confidence_threshold must be in [0, 1]")
        self.confidence_threshold = confidence_threshold

    def __call__(
        self,
        records: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        predictions = []
        for output_index, record in enumerate(records, start=1):
            message = str(record.get("message", "")).lower()
            subsystem = _first_match(message, _SUBSYSTEM_RULES)

            if any(term in message for term in _SECURITY_TERMS):
                severity = "security_event"
            elif any(term in message for term in _ERROR_TERMS):
                severity = "error"
            elif any(term in message for term in _WARNING_TERMS):
                severity = "warning"
            elif any(term in message for term in _INFO_TERMS):
                severity = "info"
            else:
                severity = "routine"

            subsystem_score = 0.99 if subsystem is not None else 0.0
            severity_score = 0.95 if severity != "routine" else 0.75
            raw_prediction = {
                "schema_version": TAXONOMY_VERSION,
                "subsystem": {
                    "label": subsystem or "compute",
                    "score": subsystem_score,
                },
                "severity": {
                    "label": severity,
                    "score": severity_score,
                },
                "abstained": min(subsystem_score, severity_score)
                < self.confidence_threshold,
                "model": {
                    "id": self.model_id,
                    "revision": self.revision,
                },
            }
            predictions.append(
                validate_classification_prediction(raw_prediction, output_index)
            )
        return predictions
