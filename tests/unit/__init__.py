"""Unit tests for the dependency-free platform foundation."""

from log_classification_pipeline import workspace

# The production scrypt cost takes a noticeable fraction of a second per password.
workspace._SCRYPT_N = 2**10
