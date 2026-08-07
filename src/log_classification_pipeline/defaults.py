"""Conservative local application defaults shared by CLI and web adapters."""

DEFAULT_MAX_INPUT_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_RECORDS = 25_000
DEFAULT_MAX_ADMITTED_BYTES = 50 * 1024 * 1024

__all__ = [
    "DEFAULT_MAX_ADMITTED_BYTES",
    "DEFAULT_MAX_INPUT_BYTES",
    "DEFAULT_MAX_RECORDS",
]
