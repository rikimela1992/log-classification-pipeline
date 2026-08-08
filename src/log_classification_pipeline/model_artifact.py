"""Deterministic, fail-closed manifests for local model artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from .model_profiles import get_model_profile

MANIFEST_SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 1_048_576
MAX_MODEL_FILES = 2_048
MAX_MODEL_BYTES = 20 * 1024**3
_IGNORED_ROOT_DIRECTORIES = frozenset({".cache", ".git"})
_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "profile_id",
        "profile_revision",
        "model_id",
        "model_revision",
        "files",
        "tree_sha256",
    }
)
_FILE_KEYS = frozenset({"path", "size", "sha256"})


class ArtifactManifestError(ValueError):
    """A local model artifact or its manifest failed strict validation."""


@dataclass(frozen=True, slots=True)
class ArtifactVerification:
    profile_id: str
    tree_sha256: str
    file_count: int
    total_bytes: int


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 71:
        return False
    if not value.startswith("sha256:"):
        return False
    return all(character in "0123456789abcdef" for character in value[7:])


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _relative_name(root: Path, directory: str, filename: str) -> str:
    relative_directory = os.path.relpath(directory, root)
    if relative_directory == ".":
        return filename
    return PurePosixPath(relative_directory, filename).as_posix()


def _validate_artifact_path(path: object) -> str:
    if (
        not isinstance(path, str)
        or not path
        or "\\" in path
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in path
        )
    ):
        raise ArtifactManifestError("artifact manifest contains an invalid path")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or parsed.as_posix() != path or any(
        part in {"", ".", ".."} for part in parsed.parts
    ):
        raise ArtifactManifestError("artifact manifest contains an unsafe path")
    return path


def _validate_scan_limits(max_files: int, max_total_bytes: int) -> None:
    for name, value in (
        ("max_files", max_files),
        ("max_total_bytes", max_total_bytes),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if max_files > MAX_MODEL_FILES:
        raise ValueError(f"max_files must not exceed {MAX_MODEL_FILES}")
    if max_total_bytes > MAX_MODEL_BYTES:
        raise ValueError(f"max_total_bytes must not exceed {MAX_MODEL_BYTES}")


def _hash_file(
    directory_fd: int,
    filename: str,
    relative_path: str,
    expected: os.stat_result,
    *,
    max_bytes: int,
    copy_path: Path | None = None,
) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow == 0:
        raise ArtifactManifestError(
            "artifact verification requires no-follow file support"
        )
    try:
        file_fd = os.open(filename, flags | no_follow, dir_fd=directory_fd)
    except OSError as exc:
        raise ArtifactManifestError(
            f"cannot open model artifact file {relative_path!r} safely"
        ) from exc
    try:
        before = os.fstat(file_fd)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_nlink",
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or expected.st_nlink != 1
            or before.st_nlink != 1
            or any(
                getattr(expected, name) != getattr(before, name)
                for name in stable_fields
            )
        ):
            raise ArtifactManifestError(
                f"model artifact file changed during scan: {relative_path!r}"
            )
        copy_fd: int | None = None
        if copy_path is not None:
            destination_flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | no_follow
                | getattr(os, "O_CLOEXEC", 0)
            )
            copy_fd = os.open(copy_path, destination_flags, 0o600)
        digest = hashlib.sha256()
        actual_size = 0
        try:
            while True:
                chunk = os.read(
                    file_fd,
                    min(1024 * 1024, max_bytes - actual_size + 1),
                )
                if not chunk:
                    break
                actual_size += len(chunk)
                if actual_size > max_bytes:
                    raise ArtifactManifestError(
                        "model artifact exceeds the byte limit"
                    )
                digest.update(chunk)
                if copy_fd is not None:
                    view = memoryview(chunk)
                    while view:
                        written = os.write(copy_fd, view)
                        if written <= 0:
                            raise OSError("model snapshot write made no progress")
                        view = view[written:]
            after = os.fstat(file_fd)
            if (
                actual_size != before.st_size
                or after.st_nlink != 1
                or any(
                    getattr(before, name) != getattr(after, name)
                    for name in stable_fields
                )
            ):
                raise ArtifactManifestError(
                    f"model artifact file changed during scan: {relative_path!r}"
                )
            return "sha256:" + digest.hexdigest(), actual_size
        finally:
            if copy_fd is not None:
                os.close(copy_fd)
    finally:
        os.close(file_fd)


def _scan_model_files(
    model_root: Path,
    *,
    max_files: int,
    max_total_bytes: int,
    copy_root: Path | None = None,
) -> tuple[list[dict[str, Any]], int]:
    _validate_scan_limits(max_files, max_total_bytes)
    try:
        root_status = model_root.lstat()
    except OSError as exc:
        raise ArtifactManifestError("model directory is not accessible") from exc
    if stat.S_ISLNK(root_status.st_mode) or not stat.S_ISDIR(root_status.st_mode):
        raise ArtifactManifestError(
            "model directory must be a real directory, not a symbolic link"
        )

    files: list[dict[str, Any]] = []
    total_bytes = 0
    try:
        walker = os.fwalk(model_root, topdown=True, follow_symlinks=False)
        for directory, directory_names, file_names, directory_fd in walker:
            relative_directory = os.path.relpath(directory, model_root)
            if relative_directory == ".":
                directory_names[:] = [
                    name
                    for name in directory_names
                    if name not in _IGNORED_ROOT_DIRECTORIES
                ]
            directory_names.sort()
            file_names.sort()
            if copy_root is not None:
                destination_directory = (
                    copy_root
                    if relative_directory == "."
                    else copy_root / PurePosixPath(relative_directory)
                )
                destination_directory.mkdir(
                    mode=0o700,
                    parents=True,
                    exist_ok=True,
                )
                destination_directory.chmod(0o700)

            for name in directory_names:
                relative_path = _validate_artifact_path(
                    _relative_name(model_root, directory, name)
                )
                entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(entry.st_mode) or not stat.S_ISDIR(entry.st_mode):
                    raise ArtifactManifestError(
                        "model artifact directories must be real directories: "
                        f"{relative_path!r}"
                    )

            for name in file_names:
                relative_path = _validate_artifact_path(
                    _relative_name(model_root, directory, name)
                )
                entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(entry.st_mode) or not stat.S_ISREG(entry.st_mode):
                    raise ArtifactManifestError(
                        "model artifact entries must be regular files: "
                        f"{relative_path!r}"
                    )
                if entry.st_nlink != 1:
                    raise ArtifactManifestError(
                        "model artifact files must have exactly one hard link: "
                        f"{relative_path!r}"
                    )
                if len(files) >= max_files:
                    raise ArtifactManifestError(
                        "model artifact exceeds the file limit"
                    )
                copy_path = (
                    copy_root / PurePosixPath(relative_path)
                    if copy_root is not None
                    else None
                )
                file_digest, actual_size = _hash_file(
                    directory_fd,
                    name,
                    relative_path,
                    entry,
                    max_bytes=max_total_bytes - total_bytes,
                    copy_path=copy_path,
                )
                total_bytes += actual_size
                files.append(
                    {
                        "path": relative_path,
                        "size": actual_size,
                        "sha256": file_digest,
                    }
                )
    except ArtifactManifestError:
        raise
    except OSError as exc:
        raise ArtifactManifestError("model artifact scan failed") from exc

    files.sort(key=lambda item: item["path"])
    if not files:
        raise ArtifactManifestError("model directory contains no artifact files")
    return files, total_bytes


def _manifest_payload(profile_id: str, files: list[dict[str, Any]]) -> dict[str, Any]:
    profile = get_model_profile(profile_id)
    identity = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "profile_id": profile.profile_id,
        "profile_revision": profile.profile_revision,
        "model_id": profile.model_id,
        "model_revision": profile.model_revision,
        "files": files,
    }
    return {**identity, "tree_sha256": _canonical_digest(identity)}


def create_artifact_manifest(
    model_root: str | Path,
    profile_id: str,
    *,
    max_files: int = MAX_MODEL_FILES,
    max_total_bytes: int = MAX_MODEL_BYTES,
) -> dict[str, Any]:
    """Hash a local model tree and return its canonical manifest mapping."""

    get_model_profile(profile_id)
    files, _ = _scan_model_files(
        Path(model_root),
        max_files=max_files,
        max_total_bytes=max_total_bytes,
    )
    return _manifest_payload(profile_id, files)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ArtifactManifestError(f"manifest contains duplicate key {key!r}")
        value[key] = item
    return value


def _read_manifest(manifest_path: Path) -> object:
    try:
        status = manifest_path.lstat()
    except OSError as exc:
        raise ArtifactManifestError("artifact manifest is not accessible") from exc
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise ArtifactManifestError("artifact manifest must be a regular file")
    if status.st_size > MAX_MANIFEST_BYTES:
        raise ArtifactManifestError("artifact manifest exceeds the byte limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow == 0:
        raise ArtifactManifestError(
            "artifact verification requires no-follow file support"
        )
    try:
        descriptor = os.open(manifest_path, flags | no_follow)
    except OSError as exc:
        raise ArtifactManifestError("cannot open artifact manifest safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != status.st_dev
            or opened.st_ino != status.st_ino
        ):
            raise ArtifactManifestError("artifact manifest changed while opening")
        payload = bytearray()
        while len(payload) <= MAX_MANIFEST_BYTES:
            chunk = os.read(
                descriptor,
                min(65_536, MAX_MANIFEST_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_MANIFEST_BYTES:
            raise ArtifactManifestError("artifact manifest exceeds the byte limit")
        after = os.fstat(descriptor)
        if (
            opened.st_size != after.st_size
            or opened.st_mtime_ns != after.st_mtime_ns
            or opened.st_ctime_ns != after.st_ctime_ns
        ):
            raise ArtifactManifestError("artifact manifest changed while reading")
    finally:
        os.close(descriptor)
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ArtifactManifestError(
                    f"manifest contains invalid numeric constant {value!r}"
                )
            ),
        )
    except ArtifactManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactManifestError("artifact manifest is not valid UTF-8 JSON") from exc


def _validate_manifest_shape(value: object, expected_profile_id: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _MANIFEST_KEYS:
        raise ArtifactManifestError("artifact manifest has an unsupported shape")
    if (
        isinstance(value["schema_version"], bool)
        or value["schema_version"] != MANIFEST_SCHEMA_VERSION
    ):
        raise ArtifactManifestError(
            "artifact manifest has an unsupported schema version"
        )

    profile = get_model_profile(expected_profile_id)
    expected_identity = {
        "profile_id": profile.profile_id,
        "profile_revision": profile.profile_revision,
        "model_id": profile.model_id,
        "model_revision": profile.model_revision,
    }
    if any(value[name] != expected for name, expected in expected_identity.items()):
        raise ArtifactManifestError(
            "artifact manifest identity does not match the selected model profile"
        )
    if not _is_sha256(value["tree_sha256"]):
        raise ArtifactManifestError("artifact manifest tree_sha256 is invalid")

    files = value["files"]
    if not isinstance(files, list) or not files or len(files) > MAX_MODEL_FILES:
        raise ArtifactManifestError("artifact manifest files list is invalid")
    previous_path: str | None = None
    total_bytes = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != _FILE_KEYS:
            raise ArtifactManifestError("artifact manifest file entry is invalid")
        path = _validate_artifact_path(item["path"])
        if previous_path is not None and path <= previous_path:
            raise ArtifactManifestError(
                "artifact manifest file paths must be unique and sorted"
            )
        previous_path = path
        size = item["size"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ArtifactManifestError("artifact manifest file size is invalid")
        total_bytes += size
        if total_bytes > MAX_MODEL_BYTES:
            raise ArtifactManifestError("artifact manifest exceeds the byte limit")
        if not _is_sha256(item["sha256"]):
            raise ArtifactManifestError("artifact manifest file sha256 is invalid")

    unsigned = {name: value[name] for name in value if name != "tree_sha256"}
    if _canonical_digest(unsigned) != value["tree_sha256"]:
        raise ArtifactManifestError("artifact manifest tree_sha256 does not match")
    return value


def verify_artifact_manifest(
    model_root: str | Path,
    manifest_path: str | Path,
    expected_profile_id: str,
    *,
    max_files: int = MAX_MODEL_FILES,
    max_total_bytes: int = MAX_MODEL_BYTES,
) -> ArtifactVerification:
    """Verify identity and every relevant byte in a local model directory."""

    manifest = _validate_manifest_shape(
        _read_manifest(Path(manifest_path)),
        expected_profile_id,
    )
    actual_files, total_bytes = _scan_model_files(
        Path(model_root),
        max_files=max_files,
        max_total_bytes=max_total_bytes,
    )
    if actual_files != manifest["files"]:
        raise ArtifactManifestError("model artifact files do not match the manifest")
    actual = _manifest_payload(expected_profile_id, actual_files)
    if actual["tree_sha256"] != manifest["tree_sha256"]:
        raise ArtifactManifestError("model artifact digest does not match the manifest")
    return ArtifactVerification(
        profile_id=expected_profile_id,
        tree_sha256=manifest["tree_sha256"],
        file_count=len(actual_files),
        total_bytes=total_bytes,
    )


@contextmanager
def materialize_verified_artifact(
    model_root: str | Path,
    manifest_path: str | Path,
    expected_profile_id: str,
    *,
    max_files: int = MAX_MODEL_FILES,
    max_total_bytes: int = MAX_MODEL_BYTES,
) -> Iterator[tuple[Path, ArtifactVerification]]:
    """Yield a private verified copy suitable for framework loading."""

    manifest = _validate_manifest_shape(
        _read_manifest(Path(manifest_path)),
        expected_profile_id,
    )
    with tempfile.TemporaryDirectory(
        prefix="log-classification-model-"
    ) as temporary_directory:
        snapshot_root = Path(temporary_directory)
        snapshot_root.chmod(0o700)
        source_files, _ = _scan_model_files(
            Path(model_root),
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            copy_root=snapshot_root,
        )
        if source_files != manifest["files"]:
            raise ArtifactManifestError(
                "model artifact files do not match the manifest"
            )
        snapshot_files, total_bytes = _scan_model_files(
            snapshot_root,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
        )
        if snapshot_files != manifest["files"]:
            raise ArtifactManifestError(
                "private model snapshot does not match the manifest"
            )
        snapshot = _manifest_payload(expected_profile_id, snapshot_files)
        if snapshot["tree_sha256"] != manifest["tree_sha256"]:
            raise ArtifactManifestError(
                "private model snapshot digest does not match the manifest"
            )
        verification = ArtifactVerification(
            profile_id=expected_profile_id,
            tree_sha256=manifest["tree_sha256"],
            file_count=len(snapshot_files),
            total_bytes=total_bytes,
        )
        yield snapshot_root, verification
