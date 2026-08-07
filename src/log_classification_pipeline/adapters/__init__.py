"""Optional and deterministic predictor adapters."""

from .rules import RulesPredictor
from .zero_shot import (
    DEFAULT_MODEL_ID,
    DEFAULT_MODEL_REVISION,
    ZeroShotConfig,
    ZeroShotPredictor,
)

__all__ = [
    "DEFAULT_MODEL_ID",
    "DEFAULT_MODEL_REVISION",
    "RulesPredictor",
    "ZeroShotConfig",
    "ZeroShotPredictor",
]
