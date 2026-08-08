"""Fail-closed batch-processing foundations for log classification."""

from .atomic import PublicationCleanupError, PublicationDurabilityError
from .batch import BatchSummary, Predictor, process_batch
from .contracts import (
    BatchResourceLimitError,
    BatchValidationError,
    PredictionContractError,
    ValidationIssue,
)

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
