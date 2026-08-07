"""Fail-closed batch-processing foundations for log classification."""

from .batch import BatchSummary, Predictor, process_batch
from .contracts import (
    BatchResourceLimitError,
    BatchValidationError,
    PredictionContractError,
    ValidationIssue,
)
from .atomic import PublicationCleanupError, PublicationDurabilityError

__all__ = [
    "BatchSummary",
    "BatchResourceLimitError",
    "BatchValidationError",
    "PredictionContractError",
    "Predictor",
    "PublicationCleanupError",
    "PublicationDurabilityError",
    "ValidationIssue",
    "process_batch",
]
