"""Atomic publication helpers for JSONL classifier output."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .contracts import validate_prediction_record


class PublicationCommittedError(RuntimeError):
    """Base error for failures after the destination has become visible."""

    def __init__(self, destination: Path, message: str):
        self.destination = destination
        self.published = True
        super().__init__(f"{message}: {destination}")


class PublicationDurabilityError(PublicationCommittedError):
    """The output is visible, but crash durability could not be confirmed."""


class PublicationCleanupError(PublicationCommittedError):
    """The output is published, but the temporary hard link could not be removed."""


def _sync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    directory_fd = os.open(path, flags)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def atomic_write_jsonl(
    path: str | Path,
    records: Iterable[Mapping[str, Any]],
    *,
    overwrite: bool = False,
    mode: int = 0o640,
) -> int:
    """Write complete JSONL output and publish it atomically.

    The temporary file lives in the destination directory. Before publication,
    failures remove it and preserve any existing output. After publication,
    durability or cleanup failures raise a ``PublicationCommittedError`` subtype
    whose ``published`` attribute is true; rollback is no longer possible.
    """

    destination = Path(path)
    parent = destination.parent
    if not parent.is_dir():
        raise FileNotFoundError(f"output directory does not exist: {parent}")
    if destination.is_symlink():
        raise FileExistsError(f"refusing symlink output path: {destination}")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"output already exists: {destination}")

    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=parent,
        text=True,
    )
    temporary_path = Path(temporary_name)
    count = 0
    published = False

    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as stream:
            for output_index, raw_record in enumerate(records, start=1):
                record = validate_prediction_record(raw_record, output_index)
                encoded = json.dumps(
                    dict(record),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                stream.write(encoded)
                stream.write("\n")
                count += 1
            stream.flush()
            os.fsync(stream.fileno())

        os.chmod(temporary_path, mode)
        if overwrite:
            os.replace(temporary_path, destination)
        else:
            os.link(temporary_path, destination)
        published = True

        cleanup_error: OSError | None = None
        if not overwrite:
            try:
                temporary_path.unlink()
            except OSError as exc:
                cleanup_error = exc

        try:
            _sync_directory(parent)
        except OSError as exc:
            raise PublicationDurabilityError(
                destination,
                "output was published but directory durability could not be confirmed",
            ) from exc

        if cleanup_error is not None:
            raise PublicationCleanupError(
                destination,
                "output was published but its temporary hard link could not be removed",
            ) from cleanup_error
        return count
    except BaseException:
        if not published:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
