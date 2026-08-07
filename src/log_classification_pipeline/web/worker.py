"""Bounded single-worker execution for the local web workspace."""

from __future__ import annotations

import hashlib
import json
import os
import queue
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

try:
    import fcntl
except ImportError:  # pragma: no cover - the documented web target is POSIX.
    fcntl = None  # type: ignore[assignment]

from ..batch import BatchCancelledError, Predictor, process_batch
from ..contracts import (
    BatchResourceLimitError,
    BatchValidationError,
    PredictionContractError,
)
from ..workspace import NotFoundError, Workspace


class QueueCapacityError(RuntimeError):
    """The configured number of admitted jobs is already reached."""


class WorkerUnavailableError(RuntimeError):
    """The local single-worker lock or thread is unavailable."""


@dataclass(frozen=True, slots=True)
class _QueuedWork:
    capability: str
    job_id: str
    model_name: str
    payload: bytearray
    source_sha256: str


class LocalClassificationQueue:
    """Keep bounded raw bytes in memory and publish only complete job results."""

    def __init__(
        self,
        workspace: Workspace,
        predictors: Mapping[str, Predictor],
        *,
        max_admitted_jobs: int = 8,
        batch_size: int = 16,
        max_input_bytes: int = 1_000_000,
        max_records: int = 1_000,
    ) -> None:
        for name, value in (
            ("max_admitted_jobs", max_admitted_jobs),
            ("batch_size", batch_size),
            ("max_input_bytes", max_input_bytes),
            ("max_records", max_records),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self.workspace = workspace
        self.predictors = dict(predictors)
        self.batch_size = batch_size
        self.max_input_bytes = max_input_bytes
        self.max_records = max_records
        self._items: queue.Queue[_QueuedWork | None] = queue.Queue()
        self._slots = threading.BoundedSemaphore(max_admitted_jobs)
        self._admission_lock = threading.Lock()
        self._admitted = 0
        self._payload_lock = threading.Lock()
        self._queued_payloads: dict[str, bytearray] = {}
        self._start_lock = threading.RLock()
        self._process_lock_guard = threading.Lock()
        self._stop = threading.Event()
        self._idle = threading.Event()
        self._idle.set()
        self._thread: threading.Thread | None = None
        self._lock_descriptor: int | None = None
        self._closed = False
        self.worker_id = f"web-{uuid4()}"

    @property
    def lock_path(self) -> Path:
        return self.workspace.database_path.with_name(
            self.workspace.database_path.name + ".worker.lock"
        )

    def start(self) -> None:
        with self._start_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            if self._closed:
                raise WorkerUnavailableError("classification worker is closed")
            if fcntl is None:
                raise WorkerUnavailableError("classification worker requires POSIX locking")
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(self.lock_path, flags, 0o600)
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (OSError, BlockingIOError) as exc:
                if "descriptor" in locals():
                    os.close(descriptor)
                raise WorkerUnavailableError(
                    "another classification worker owns this workspace"
                ) from exc
            with self._process_lock_guard:
                self._lock_descriptor = descriptor
            try:
                self.workspace.recover_incomplete_jobs()
                self._thread = threading.Thread(
                    target=self._run,
                    name="log-classification-worker",
                    daemon=True,
                )
                self._thread.start()
            except Exception:
                self._release_process_lock()
                raise

    def submit(
        self,
        token: str,
        model_name: str,
        payload: bytes,
        source_sha256: str,
        input_records: int,
    ) -> str:
        if model_name not in self.predictors:
            raise ValueError("unknown configured model")
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if len(payload) > self.max_input_bytes:
            raise BatchResourceLimitError(
                "input byte count",
                self.max_input_bytes,
                observed_at_least=len(payload),
            )
        if not hashlib.sha256(payload).hexdigest() == source_sha256:
            raise ValueError("payload digest changed before queue admission")
        with self._start_lock:
            self.start()
            if self._closed:
                raise WorkerUnavailableError("classification worker is closed")
            if not self._slots.acquire(blocking=False):
                raise QueueCapacityError("classification queue is full")
            with self._admission_lock:
                self._admitted += 1
                self._idle.clear()
            try:
                job_id, capability = self.workspace.enqueue_classification_job(
                    token,
                    source_sha256,
                    input_records,
                    model_name,
                )
                queued_payload = bytearray(payload)
                with self._payload_lock:
                    self._queued_payloads[job_id] = queued_payload
                self._items.put_nowait(
                    _QueuedWork(
                        capability=capability,
                        job_id=job_id,
                        model_name=model_name,
                        payload=queued_payload,
                        source_sha256=source_sha256,
                    )
                )
            except Exception:
                if "queued_payload" in locals():
                    with self._payload_lock:
                        self._queued_payloads.pop(job_id, None)
                    self._zero_payload(queued_payload)
                self._slots.release()
                self._release_admission()
                raise
        return job_id

    def _run(self) -> None:
        try:
            while True:
                item = self._items.get()
                try:
                    if item is None:
                        return
                    try:
                        self._execute(item)
                    except Exception:
                        try:
                            self.workspace.fail_classification_job(
                                item.capability,
                                "internal_error",
                            )
                        except Exception:
                            pass
                finally:
                    if item is not None:
                        with self._payload_lock:
                            self._queued_payloads.pop(item.job_id, None)
                        self._zero_payload(item.payload)
                    self._items.task_done()
                    if item is not None:
                        self._slots.release()
                        self._release_admission()
        finally:
            self._release_process_lock()

    def _release_admission(self) -> None:
        with self._admission_lock:
            self._admitted -= 1
            if self._admitted == 0:
                self._idle.set()

    def wait_until_idle(self, timeout: float = 5.0) -> bool:
        return self._idle.wait(timeout)

    @staticmethod
    def _zero_payload(payload: bytearray) -> None:
        payload[:] = b"\0" * len(payload)

    def discard_queued_payload(self, job_id: str) -> bool:
        """Best-effort zero the in-memory bytes for a job cancelled while queued."""

        with self._payload_lock:
            payload = self._queued_payloads.pop(job_id, None)
        if payload is None:
            return False
        self._zero_payload(payload)
        return True

    @staticmethod
    def _write_private(path: Path, payload: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())

    @staticmethod
    def _read_results(path: Path) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise PredictionContractError("stored prediction must be an object")
                results.append(value)
        return results

    def _execute(self, item: _QueuedWork) -> None:
        try:
            self.workspace.claim_classification_job(item.capability, self.worker_id)
        except NotFoundError:
            return
        with self._payload_lock:
            self._queued_payloads.pop(item.job_id, None)

        try:
            with tempfile.TemporaryDirectory(prefix="log-classify-worker-") as directory:
                root = Path(directory)
                input_path = root / "input.jsonl"
                output_path = root / "output.jsonl"
                self._write_private(input_path, item.payload)

                def cancelled() -> bool:
                    return self._stop.is_set() or self.workspace.classification_cancel_requested(
                        item.capability
                    )

                def progress(processed: int, _total: int) -> None:
                    if not self.workspace.update_classification_progress(
                        item.capability,
                        processed,
                    ):
                        raise BatchCancelledError("job no longer accepts progress")

                summary = process_batch(
                    input_path,
                    output_path,
                    self.predictors[item.model_name],
                    batch_size=self.batch_size,
                    max_input_bytes=self.max_input_bytes,
                    max_records=self.max_records,
                    progress_callback=progress,
                    should_cancel=cancelled,
                )
                results = self._read_results(output_path)
                if cancelled():
                    raise BatchCancelledError("job cancelled before result commit")
                self.workspace.complete_classification_job(
                    item.capability,
                    summary.source_sha256,
                    results,
                )
        except BatchCancelledError:
            self.workspace.fail_classification_job(
                item.capability,
                "interrupted" if self._stop.is_set() else "cancelled",
            )
        except (BatchResourceLimitError, BatchValidationError):
            self._fail_item(item, "input_invalidated")
        except PredictionContractError:
            self._fail_item(item, "prediction_failed")
        except Exception:
            self._fail_item(item, "internal_error")

    def _fail_item(self, item: _QueuedWork, default_code: str) -> None:
        if self._stop.is_set():
            failure_code = "interrupted"
        elif self.workspace.classification_cancel_requested(item.capability):
            failure_code = "cancelled"
        else:
            failure_code = default_code
        self.workspace.fail_classification_job(item.capability, failure_code)

    def close(self, *, timeout: float = 5.0) -> None:
        with self._start_lock:
            if self._closed:
                return
            self._closed = True
            self._stop.set()
            while True:
                try:
                    item = self._items.get_nowait()
                except queue.Empty:
                    break
                try:
                    if item is not None:
                        self.workspace.fail_classification_job(
                            item.capability,
                            "interrupted",
                        )
                        with self._payload_lock:
                            self._queued_payloads.pop(item.job_id, None)
                        self._zero_payload(item.payload)
                        self._slots.release()
                        self._release_admission()
                finally:
                    self._items.task_done()
            self._items.put_nowait(None)
            thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
        if thread is None or not thread.is_alive():
            self._release_process_lock()

    def _release_process_lock(self) -> None:
        with self._process_lock_guard:
            descriptor = self._lock_descriptor
            self._lock_descriptor = None
        if descriptor is None:
            return
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
