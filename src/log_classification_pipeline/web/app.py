"""FastAPI adapter for the local authenticated workspace."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import tempfile
from collections.abc import Mapping
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from fastapi import FastAPI, File, Form, HTTPException, Request, Security, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..batch import Predictor
from ..contracts import (
    BatchResourceLimitError,
    BatchValidationError,
    PredictionContractError,
)
from ..defaults import (
    DEFAULT_MAX_ADMITTED_BYTES,
    DEFAULT_MAX_INPUT_BYTES,
    DEFAULT_MAX_RECORDS,
)
from ..inputs import InputFormat, read_input_file, resolve_input_format
from ..jsonl import ParsedBatch
from ..model_catalog import RULES_MODEL_NAME, configured_model_catalog
from ..model_profiles import MODEL_PROFILES
from ..workspace import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
    RetentionPolicy,
    Role,
    Workspace,
    WorkspaceError,
)
from .i18n import SUPPORTED_LOCALES, load_catalogs, negotiate_locale, translator
from .rate_limit import LoginRateLimiter
from .worker import (
    LocalClassificationQueue,
    QueueCapacityError,
    WorkerUnavailableError,
)

_SESSION_COOKIE = "lcp_session"
_LOGIN_CSRF_COOKIE = "lcp_login_csrf"
_LOCALE_COOKIE = "lcp_locale"
_CSRF_HEADER = b"x-csrf-token"
_SESSION_SECONDS = 8 * 60 * 60


@dataclass(frozen=True, slots=True)
class WebSettings:
    database_path: Path
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")
    cookie_secure: bool = False
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES
    max_records: int = DEFAULT_MAX_RECORDS
    max_request_bytes: int = DEFAULT_MAX_INPUT_BYTES + 262_144
    max_admitted_jobs: int = 8
    max_admitted_bytes: int = DEFAULT_MAX_ADMITTED_BYTES
    worker_batch_size: int = 16
    login_account_limit: int = 5
    login_source_limit: int = 20
    login_window_seconds: int = 60

    def __post_init__(self) -> None:
        if not self.allowed_hosts or any(not item for item in self.allowed_hosts):
            raise ValueError("allowed_hosts must contain at least one non-blank host")
        for name, value in (
            ("max_input_bytes", self.max_input_bytes),
            ("max_records", self.max_records),
            ("max_request_bytes", self.max_request_bytes),
            ("max_admitted_jobs", self.max_admitted_jobs),
            ("max_admitted_bytes", self.max_admitted_bytes),
            ("worker_batch_size", self.worker_batch_size),
            ("login_account_limit", self.login_account_limit),
            ("login_source_limit", self.login_source_limit),
            ("login_window_seconds", self.login_window_seconds),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_request_bytes <= self.max_input_bytes:
            raise ValueError("max_request_bytes must exceed max_input_bytes")
        if self.max_admitted_bytes < self.max_input_bytes:
            raise ValueError(
                "max_admitted_bytes must be greater than or equal to max_input_bytes"
            )
        if self.login_source_limit < self.login_account_limit:
            raise ValueError(
                "login_source_limit must be greater than or equal to "
                "login_account_limit"
            )


class SessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization: str = Field(min_length=3, max_length=64)
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class ClassificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records: list[dict[str, Any]] = Field(min_length=1)
    model: str = Field(default="rules", min_length=1, max_length=128)


class UserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=1024)
    role: Role


class UserUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role | None = None
    disabled: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=1024)


class RetentionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw_days: int = Field(ge=1, le=3650)
    result_days: int = Field(ge=1, le=3650)
    audit_days: int = Field(ge=1, le=3650)


class _RequestTooLarge(Exception):
    pass


def _headers(scope: Scope) -> dict[bytes, bytes]:
    return {key.lower(): value for key, value in scope.get("headers", [])}


def _cookie_value(scope: Scope, name: str) -> str | None:
    raw_cookie = _headers(scope).get(b"cookie")
    if not raw_cookie:
        return None
    parsed = SimpleCookie()
    try:
        parsed.load(raw_cookie.decode("latin-1"))
    except Exception:
        return None
    morsel = parsed.get(name)
    return morsel.value if morsel is not None else None


def _bearer_value(scope: Scope) -> str | None:
    raw_authorization = _headers(scope).get(b"authorization")
    if raw_authorization is None:
        return None
    try:
        scheme, token = raw_authorization.decode("ascii").split(" ", 1)
    except (UnicodeDecodeError, ValueError):
        return None
    if scheme.casefold() != "bearer" or not token or " " in token:
        return None
    return token


def _problem_response(
    status_code: int,
    code: str,
    detail: str,
    *,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        media_type="application/problem+json",
        headers=headers,
        content={
            "type": f"urn:log-classify:error:{code}",
            "title": detail,
            "status": status_code,
            "code": code,
            "detail": detail,
            "request_id": str(uuid4()),
        },
    )


def _security_headers(*, hsts: bool) -> dict[str, str]:
    headers = {
        "Cache-Control": "no-store",
        "Content-Security-Policy": (
            "default-src 'self'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'none'; object-src 'none'"
        ),
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }
    if hsts:
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return headers


class RequestSizeLimitMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = _headers(scope)
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                if int(raw_length) > self.max_bytes:
                    await _problem_response(
                        413,
                        "request_too_large",
                        "Request body exceeds the configured limit.",
                    )(scope, receive, send)
                    return
            except ValueError:
                await _problem_response(
                    400,
                    "invalid_content_length",
                    "Content-Length is invalid.",
                )(scope, receive, send)
                return

        observed = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal observed
            message = await receive()
            if message["type"] == "http.request":
                observed += len(message.get("body", b""))
                if observed > self.max_bytes:
                    raise _RequestTooLarge
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _RequestTooLarge:
            if response_started:
                raise
            await _problem_response(
                413,
                "request_too_large",
                "Request body exceeds the configured limit.",
            )(scope, receive, send)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool):
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def secure_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    (name.lower().encode("ascii"), value.encode("ascii"))
                    for name, value in _security_headers(hsts=self.hsts).items()
                )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, secure_send)


class AuthenticationPreflightMiddleware:
    """Authorize sensitive routes before FastAPI parses a request body."""

    def __init__(self, app: ASGIApp, *, workspace: Workspace):
        self.app = app
        self.workspace = workspace

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = scope.get("method", "GET").upper()
        path = scope.get("path", "")
        headers = _headers(scope)

        if path.startswith("/app/") and method not in {"GET", "HEAD", "OPTIONS"}:
            host = headers.get(b"host", b"").decode("latin-1")
            origin = headers.get(b"origin", b"").decode("latin-1")
            expected_origin = f"{scope.get('scheme', 'http')}://{host}"
            if not origin or origin != expected_origin:
                await _problem_response(403, "origin_denied", "Request origin is not allowed.")(
                    scope, receive, send
                )
                return
            if path == "/app/login" or (
                path == "/app/locale"
                and _cookie_value(scope, _SESSION_COOKIE) is None
            ):
                cookie_csrf = _cookie_value(scope, _LOGIN_CSRF_COOKIE)
                submitted = headers.get(_CSRF_HEADER, b"").decode(
                    "ascii",
                    errors="ignore",
                )
                if (
                    cookie_csrf is None
                    or not submitted
                    or not secrets.compare_digest(cookie_csrf, submitted)
                ):
                    await _problem_response(
                        403,
                        "csrf_denied",
                        "Login request protection failed.",
                    )(scope, receive, send)
                    return
            else:
                token = _cookie_value(scope, _SESSION_COOKIE)
                submitted = headers.get(_CSRF_HEADER, b"").decode("ascii", errors="ignore")
                try:
                    if token is None:
                        raise AuthenticationError("invalid session")
                    await run_in_threadpool(
                        self.workspace.verify_csrf,
                        token,
                        submitted,
                    )
                    if path == "/app/classify":
                        await run_in_threadpool(
                            self.workspace.authorize_classification,
                            token,
                        )
                    elif path.startswith("/app/admin/"):
                        await run_in_threadpool(
                            self.workspace.authorize_admin,
                            token,
                        )
                except AuthenticationError:
                    await _problem_response(
                        401,
                        "not_authenticated",
                        "Authentication is required.",
                    )(scope, receive, send)
                    return
                except AuthorizationError:
                    await _problem_response(403, "forbidden", "Operation is not permitted.")(
                        scope, receive, send
                    )
                    return
                except (OSError, RuntimeError, sqlite3.Error, WorkspaceError):
                    await _problem_response(
                        503,
                        "workspace_unavailable",
                        "Workspace is temporarily unavailable.",
                        headers={"Retry-After": "1"},
                    )(scope, receive, send)
                    return

        public_api_paths = {
            "/api/v1/docs",
            "/api/v1/openapi.json",
            "/api/v1/sessions",
        }
        if path.startswith("/api/v1/") and path not in public_api_paths:
            cookie_token = _cookie_value(scope, _SESSION_COOKIE)
            bearer_token = _bearer_value(scope)
            if cookie_token is not None and bearer_token is not None:
                await _problem_response(
                    400,
                    "ambiguous_authentication",
                    "Cookie and bearer authentication cannot be combined.",
                )(scope, receive, send)
                return
            if bearer_token is None:
                await _problem_response(
                    401,
                    "not_authenticated",
                    "Bearer authentication is required.",
                    headers={"WWW-Authenticate": "Bearer"},
                )(scope, receive, send)
                return
            try:
                await run_in_threadpool(self.workspace.principal, bearer_token)
                if method not in {"GET", "HEAD", "OPTIONS"}:
                    if path.startswith("/api/v1/classifications"):
                        await run_in_threadpool(
                            self.workspace.authorize_classification,
                            bearer_token,
                        )
                    elif path.startswith("/api/v1/admin/"):
                        await run_in_threadpool(
                            self.workspace.authorize_admin,
                            bearer_token,
                        )
            except AuthenticationError:
                await _problem_response(
                    401,
                    "not_authenticated",
                    "Bearer token is invalid or expired.",
                    headers={"WWW-Authenticate": "Bearer"},
                )(scope, receive, send)
                return
            except AuthorizationError:
                await _problem_response(403, "forbidden", "Operation is not permitted.")(
                    scope, receive, send
                )
                return
            except (OSError, RuntimeError, sqlite3.Error, WorkspaceError):
                await _problem_response(
                    503,
                    "workspace_unavailable",
                    "Workspace is temporarily unavailable.",
                    headers={"Retry-After": "1"},
                )(scope, receive, send)
                return

        await self.app(scope, receive, send)


def _write_records(path: Path, records: list[dict[str, Any]]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                )
            )
            stream.write("\n")


async def _save_upload(upload: UploadFile, path: Path, *, max_bytes: int) -> int:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    observed = 0
    try:
        with os.fdopen(descriptor, "wb") as stream:
            while True:
                chunk = await upload.read(min(65_536, max_bytes + 1 - observed))
                if not chunk:
                    break
                observed += len(chunk)
                if observed > max_bytes:
                    raise BatchResourceLimitError(
                        "input byte count",
                        max_bytes,
                        observed_at_least=observed,
                    )
                stream.write(chunk)
    finally:
        await upload.close()
    return observed


def _read_validated_payload(
    path: Path,
    *,
    input_format: str,
    max_input_bytes: int,
    max_records: int,
) -> tuple[bytes, ParsedBatch]:
    parsed = read_input_file(
        path,
        input_format=input_format,
        max_input_bytes=max_input_bytes,
        max_records=max_records,
    )
    with path.open("rb") as stream:
        payload = stream.read(max_input_bytes + 1)
    if len(payload) > max_input_bytes:
        raise BatchResourceLimitError(
            "input byte count",
            max_input_bytes,
            observed_at_least=len(payload),
        )
    if not secrets.compare_digest(
        hashlib.sha256(payload).hexdigest(),
        parsed.source_sha256,
    ):
        raise RuntimeError("staged input changed after validation")
    return payload, parsed


def create_app(
    settings: WebSettings,
    predictors: Mapping[str, Predictor],
) -> FastAPI:
    """Build the local web app without opening a socket."""

    if not predictors:
        raise ValueError("at least one predictor must be configured")
    if any(not isinstance(name, str) or not name.strip() for name in predictors):
        raise ValueError("predictor names must be non-blank strings")
    model_registry = dict(predictors)
    workspace = Workspace(settings.database_path)
    workspace.initialize(create=False)
    workspace.verify()
    model_catalog = configured_model_catalog(model_registry)
    job_queue = LocalClassificationQueue(
        workspace,
        model_registry,
        max_admitted_jobs=settings.max_admitted_jobs,
        max_admitted_bytes=settings.max_admitted_bytes,
        batch_size=settings.worker_batch_size,
        max_input_bytes=settings.max_input_bytes,
        max_records=settings.max_records,
    )
    login_rate_limiter = LoginRateLimiter(
        account_limit=settings.login_account_limit,
        source_limit=settings.login_source_limit,
        window_seconds=settings.login_window_seconds,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await run_in_threadpool(job_queue.start)
        try:
            yield
        finally:
            await run_in_threadpool(job_queue.close)

    app = FastAPI(
        title="Log Classification Pipeline",
        version="0.1.0-alpha.1",
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
        lifespan=lifespan,
    )
    app.state.workspace = workspace
    app.state.predictors = model_registry
    app.state.model_catalog = model_catalog
    app.state.job_queue = job_queue
    app.state.login_rate_limiter = login_rate_limiter
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(AuthenticationPreflightMiddleware, workspace=workspace)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(settings.allowed_hosts),
        www_redirect=False,
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.cookie_secure)

    package_root = Path(__file__).parent
    templates = Jinja2Templates(directory=package_root / "templates")
    catalogs = load_catalogs()
    app.mount(
        "/static",
        StaticFiles(directory=package_root / "static"),
        name="static",
    )
    bearer = HTTPBearer(auto_error=False)

    def request_locale(request: Request) -> str:
        return negotiate_locale(
            request.cookies.get(_LOCALE_COOKIE),
            request.headers.get("Accept-Language"),
        )

    def render_template(
        request: Request,
        name: str,
        context: dict[str, Any],
        *,
        status_code: int = 200,
    ):
        locale = request_locale(request)
        translate = translator(catalogs, locale)
        response = templates.TemplateResponse(
            request=request,
            name=name,
            context={
                **context,
                "locale": locale,
                "locales": SUPPORTED_LOCALES,
                "locale_target": "app" if context.get("principal") else "login",
                "t": translate,
            },
            status_code=status_code,
        )
        response.headers["Content-Language"] = locale
        response.headers["Vary"] = "Accept-Language, Cookie"
        return response

    def api_token(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Security(bearer),
    ) -> str:
        if request.cookies.get(_SESSION_COOKIE) is not None:
            raise HTTPException(status_code=400, detail="ambiguous authentication")
        if credentials is None or credentials.scheme.casefold() != "bearer":
            raise HTTPException(
                status_code=401,
                detail="bearer authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        workspace.principal(credentials.credentials)
        return credentials.credentials

    def login_source(request: Request) -> str:
        return request.client.host if request.client is not None else "unknown"

    def login_retry_after(
        request: Request,
        organization: str,
        username: str,
    ) -> int | None:
        return login_rate_limiter.retry_after(
            login_source(request),
            organization,
            username,
        )

    def record_login_failure(
        request: Request,
        organization: str,
        username: str,
    ) -> int | None:
        return login_rate_limiter.record_failure(
            login_source(request),
            organization,
            username,
        )

    def record_login_success(
        request: Request,
        organization: str,
        username: str,
    ) -> None:
        login_rate_limiter.record_success(
            login_source(request),
            organization,
            username,
        )

    def enqueue_sync(
        path: Path,
        model_name: str,
        token: str,
        input_format: str = "jsonl",
    ) -> str:
        if model_name not in model_registry:
            raise ValueError("unknown configured model")
        payload, parsed = _read_validated_payload(
            path,
            input_format=input_format,
            max_input_bytes=settings.max_input_bytes,
            max_records=settings.max_records,
        )
        return job_queue.submit(
            token,
            model_name,
            payload,
            parsed.source_sha256,
            len(parsed.records),
            input_format,
        )

    def accepted_job(job_id: str) -> JSONResponse:
        job_url = f"/api/v1/jobs/{job_id}"
        status_url = f"/api/v1/jobs/{job_id}/status"
        return JSONResponse(
            status_code=202,
            headers={"Location": job_url, "Retry-After": "1"},
            content={
                "job_id": job_id,
                "job_url": job_url,
                "status": "queued",
                "status_url": status_url,
            },
        )

    def result_export(stored_job: dict[str, Any]) -> StreamingResponse:
        results = stored_job.get("results")
        if results is None:
            raise ConflictError("results are unavailable")

        def body():
            for result in results:
                yield json.dumps(
                    result,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                ) + "\n"

        filename = f'classification-{stored_job["id"]}.jsonl'
        return StreamingResponse(
            body(),
            media_type="application/x-ndjson",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    @app.exception_handler(AuthenticationError)
    async def authentication_error(_request: Request, _exc: AuthenticationError):
        return _problem_response(
            401,
            "not_authenticated",
            "Authentication is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(AuthorizationError)
    async def authorization_error(_request: Request, _exc: AuthorizationError):
        return _problem_response(403, "forbidden", "Operation is not permitted.")

    @app.exception_handler(NotFoundError)
    async def not_found_error(_request: Request, _exc: NotFoundError):
        return _problem_response(404, "not_found", "Resource was not found.")

    @app.exception_handler(ConflictError)
    async def conflict_error(_request: Request, _exc: ConflictError):
        return _problem_response(409, "conflict", "Resource already exists.")

    @app.exception_handler(BatchResourceLimitError)
    async def resource_error(_request: Request, _exc: BatchResourceLimitError):
        return _problem_response(413, "input_too_large", "Input exceeds configured limits.")

    @app.exception_handler(BatchValidationError)
    async def validation_error(_request: Request, exc: BatchValidationError):
        return _problem_response(
            422,
            "batch_validation",
            f"Input failed validation with {len(exc.issues)} issue(s).",
        )

    @app.exception_handler(PredictionContractError)
    async def prediction_error(_request: Request, _exc: PredictionContractError):
        return _problem_response(503, "prediction_failed", "Prediction failed closed.")

    @app.exception_handler(QueueCapacityError)
    async def queue_capacity_error(_request: Request, _exc: QueueCapacityError):
        return _problem_response(
            503,
            "queue_full",
            "The local classification queue is full; retry later.",
            headers={"Retry-After": "1"},
        )

    @app.exception_handler(WorkerUnavailableError)
    async def worker_unavailable_error(
        _request: Request,
        _exc: WorkerUnavailableError,
    ):
        return _problem_response(
            503,
            "worker_unavailable",
            "The local classification worker is unavailable.",
            headers={"Retry-After": "1"},
        )

    @app.exception_handler(sqlite3.Error)
    async def database_error(_request: Request, _exc: sqlite3.Error):
        return _problem_response(
            503,
            "workspace_unavailable",
            "Workspace is temporarily unavailable.",
            headers={"Retry-After": "1"},
        )

    @app.exception_handler(ValueError)
    async def value_error(_request: Request, _exc: ValueError):
        return _problem_response(422, "invalid_request", "Request is invalid.")

    @app.exception_handler(RequestValidationError)
    async def request_validation_error(_request: Request, _exc: RequestValidationError):
        return _problem_response(422, "invalid_request", "Request is invalid.")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException):
        detail = "Request could not be completed."
        if exc.status_code == 401:
            detail = "Authentication is required."
        elif exc.status_code == 403:
            detail = "Operation is not permitted."
        elif exc.status_code == 404:
            detail = "Resource was not found."
        return _problem_response(
            exc.status_code,
            "http_error",
            detail,
            headers=dict(exc.headers or {}),
        )

    @app.exception_handler(WorkspaceError)
    async def workspace_error(_request: Request, _exc: WorkspaceError):
        return _problem_response(
            503,
            "workspace_unavailable",
            "Workspace is temporarily unavailable.",
        )

    @app.exception_handler(RuntimeError)
    async def runtime_error(_request: Request, _exc: RuntimeError):
        return _problem_response(
            503,
            "model_unavailable",
            "The configured model is unavailable.",
        )

    @app.exception_handler(Exception)
    async def unexpected_error(_request: Request, _exc: Exception):
        return _problem_response(
            500,
            "internal_error",
            "The request failed closed.",
            headers=_security_headers(hsts=settings.cookie_secure),
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        workspace.verify()
        return {"status": "ok", "maturity": "alpha"}

    @app.post(
        "/api/v1/sessions",
        status_code=201,
        responses={429: {"description": "Login attempts are temporarily limited"}},
    )
    def create_session(
        request: Request,
        payload: SessionRequest,
    ) -> dict[str, Any]:
        if request.cookies.get(_SESSION_COOKIE) is not None:
            raise HTTPException(status_code=400, detail="ambiguous authentication")
        retry_after = login_retry_after(
            request,
            payload.organization,
            payload.username,
        )
        if retry_after is not None:
            return _problem_response(
                429,
                "login_rate_limited",
                "Too many failed login attempts; retry later.",
                headers={"Retry-After": str(retry_after)},
            )
        try:
            token, principal = workspace.login(
                payload.organization,
                payload.username,
                payload.password,
            )
        except AuthenticationError:
            retry_after = record_login_failure(
                request,
                payload.organization,
                payload.username,
            )
            if retry_after is not None:
                return _problem_response(
                    429,
                    "login_rate_limited",
                    "Too many failed login attempts; retry later.",
                    headers={"Retry-After": str(retry_after)},
                )
            raise
        record_login_success(request, payload.organization, payload.username)
        return {
            "access_token": token,
            "expires_in": _SESSION_SECONDS,
            "principal": {
                "organization_id": principal.organization_id,
                "role": principal.role.value,
                "username": principal.username,
            },
            "token_type": "bearer",
        }

    @app.delete("/api/v1/session", status_code=204)
    def delete_session(token: str = Security(api_token)) -> None:
        workspace.logout(token)

    @app.get("/api/v1/me")
    def me(token: str = Security(api_token)) -> dict[str, str]:
        principal = workspace.principal(token)
        return {
            "organization_id": principal.organization_id,
            "role": principal.role.value,
            "username": principal.username,
        }

    @app.get("/api/v1/models")
    def models(token: str = Security(api_token)) -> dict[str, Any]:
        workspace.principal(token)
        return {
            "default_model": model_catalog[0]["id"],
            "items": model_catalog,
        }

    @app.get("/api/v1/jobs")
    def jobs(
        limit: int = 50,
        offset: int = 0,
        token: str = Security(api_token),
    ) -> dict[str, Any]:
        if isinstance(limit, bool) or not 1 <= limit <= 200:
            raise ValueError("invalid limit")
        page = workspace.list_jobs(token, limit=limit + 1, offset=offset)
        items = page[:limit]
        next_offset = offset + len(items) if len(page) > limit else None
        return {"items": items, "next_offset": next_offset}

    @app.get("/api/v1/jobs/{job_id}")
    def job(job_id: str, token: str = Security(api_token)) -> dict[str, Any]:
        return workspace.get_job(token, job_id)

    @app.get("/api/v1/jobs/{job_id}/export")
    def export_job(job_id: str, token: str = Security(api_token)):
        return result_export(workspace.get_job(token, job_id))

    @app.get("/api/v1/jobs/{job_id}/status")
    def job_status(job_id: str, token: str = Security(api_token)) -> dict[str, Any]:
        return workspace.get_job_status(token, job_id)

    def cancel_sync(token: str, job_id: str) -> dict[str, Any]:
        status = workspace.request_job_cancellation(token, job_id)
        if status["status"] == "cancelled":
            job_queue.discard_queued_payload(job_id)
        return status

    @app.post("/api/v1/jobs/{job_id}/cancel")
    def cancel_job(job_id: str, token: str = Security(api_token)) -> dict[str, Any]:
        return cancel_sync(token, job_id)

    @app.post("/api/v1/classifications", status_code=202)
    async def classify_records(
        payload: ClassificationRequest,
        token: str = Security(api_token),
    ) -> JSONResponse:
        with tempfile.TemporaryDirectory(prefix="log-classify-web-") as directory:
            input_path = Path(directory) / "input.jsonl"
            _write_records(input_path, payload.records)
            job_id = await run_in_threadpool(
                enqueue_sync,
                input_path,
                payload.model,
                token,
                "jsonl",
            )
        return accepted_job(job_id)

    @app.post("/api/v1/classifications/file", status_code=202)
    async def classify_file(
        upload: Annotated[UploadFile, File()],
        model: Annotated[str, Form()] = "rules",
        token: str = Security(api_token),
    ) -> JSONResponse:
        input_format: InputFormat = resolve_input_format(upload.filename or "")
        with tempfile.TemporaryDirectory(prefix="log-classify-web-") as directory:
            input_path = Path(directory) / "input.data"
            await _save_upload(upload, input_path, max_bytes=settings.max_input_bytes)
            job_id = await run_in_threadpool(
                enqueue_sync,
                input_path,
                model,
                token,
                input_format,
            )
        return accepted_job(job_id)

    @app.get("/api/v1/admin/users")
    def users(token: str = Security(api_token)) -> dict[str, Any]:
        workspace.authorize_admin(token)
        return {"items": workspace.list_users(token)}

    @app.post("/api/v1/admin/users", status_code=201)
    def create_user(
        payload: UserRequest,
        token: str = Security(api_token),
    ) -> dict[str, str]:
        user_id = workspace.create_user(
            token,
            payload.username,
            payload.password,
            payload.role,
        )
        return {"id": user_id, "role": payload.role.value, "username": payload.username}

    @app.patch("/api/v1/admin/users/{user_id}")
    def update_user(
        user_id: str,
        payload: UserUpdateRequest,
        token: str = Security(api_token),
    ) -> dict[str, Any]:
        return workspace.update_user(
            token,
            user_id,
            role=payload.role,
            disabled=payload.disabled,
            password=payload.password,
        )

    @app.get("/api/v1/admin/retention")
    def retention(token: str = Security(api_token)) -> dict[str, int]:
        workspace.authorize_admin(token)
        return asdict(workspace.get_retention_policy(token))

    @app.put("/api/v1/admin/retention")
    def update_retention(
        payload: RetentionRequest,
        token: str = Security(api_token),
    ) -> dict[str, Any]:
        policy = RetentionPolicy(**payload.model_dump())
        workspace.set_retention_policy(token, policy)
        return {"policy": asdict(policy), "status": "updated"}

    @app.post("/api/v1/admin/retention/purge")
    def purge(token: str = Security(api_token)) -> dict[str, int]:
        return asdict(workspace.purge_expired(token))

    @app.get("/api/v1/admin/audit")
    def audit(
        limit: int = 100,
        token: str = Security(api_token),
    ) -> dict[str, Any]:
        return {"items": workspace.list_audit_events(token, limit=limit)}

    def login_page(
        request: Request,
        error_key: str | None = None,
        *,
        status_code: int = 200,
    ):
        csrf = secrets.token_urlsafe(32)
        locale = request_locale(request)
        translate = translator(catalogs, locale)
        response = render_template(
            request,
            "login.html",
            {"csrf": csrf, "error": translate(error_key) if error_key else None},
            status_code=status_code,
        )
        response.set_cookie(
            _LOGIN_CSRF_COOKIE,
            csrf,
            httponly=True,
            max_age=600,
            path="/",
            samesite="strict",
            secure=settings.cookie_secure,
        )
        return response

    def cookie_token(request: Request) -> str:
        token = request.cookies.get(_SESSION_COOKIE)
        if token is None:
            raise AuthenticationError("invalid session")
        workspace.principal(token)
        return token

    def dashboard_context(
        token: str,
        *,
        error: str | None = None,
        job_offset: int = 0,
    ) -> dict[str, Any]:
        principal = workspace.principal(token)
        job_limit = 25
        job_page = workspace.list_jobs(
            token,
            limit=job_limit + 1,
            offset=job_offset,
        )
        jobs = job_page[:job_limit]
        model_options = []
        for item in model_catalog:
            model_name = item["id"]
            known = model_name == RULES_MODEL_NAME or model_name in MODEL_PROFILES
            model_options.append(
                {
                    **item,
                    "description_key": (
                        f"model.{model_name}.description" if known else None
                    ),
                    "label_key": f"model.{model_name}.label" if known else None,
                }
            )
        context: dict[str, Any] = {
            "audit": [],
            "csrf": workspace.csrf_token(token),
            "error": error,
            "job_next_offset": (
                job_offset + len(jobs) if len(job_page) > job_limit else None
            ),
            "job_previous_offset": max(0, job_offset - job_limit),
            "job_offset": job_offset,
            "jobs": jobs,
            "models": model_options,
            "max_input_mib": round(settings.max_input_bytes / (1024 * 1024), 1),
            "max_records": settings.max_records,
            "policy": None,
            "principal": principal,
            "users": [],
        }
        if principal.role is Role.ADMIN:
            context["users"] = workspace.list_users(token)
            context["policy"] = workspace.get_retention_policy(token)
            context["audit"] = workspace.list_audit_events(token, limit=20)
        return context

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/app", status_code=303)

    @app.get("/app/login", include_in_schema=False)
    def login_form(request: Request):
        return login_page(request)

    @app.post("/app/login", include_in_schema=False)
    def login_submit(
        request: Request,
        organization: Annotated[str, Form()],
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        csrf: Annotated[str, Form()],
    ):
        cookie_csrf = request.cookies.get(_LOGIN_CSRF_COOKIE)
        if (
            cookie_csrf is None
            or not secrets.compare_digest(cookie_csrf, csrf)
        ):
            return login_page(request, "login.expired", status_code=403)
        retry_after = login_retry_after(request, organization, username)
        if retry_after is not None:
            response = login_page(
                request,
                "login.rate_limited",
                status_code=429,
            )
            response.headers["Retry-After"] = str(retry_after)
            return response
        try:
            token, _principal = workspace.login(organization, username, password)
        except (AuthenticationError, ValueError):
            retry_after = record_login_failure(request, organization, username)
            if retry_after is not None:
                if request.headers.get("X-CSRF-Token"):
                    return _problem_response(
                        429,
                        "login_rate_limited",
                        "Too many failed login attempts; retry later.",
                        headers={"Retry-After": str(retry_after)},
                    )
                response = login_page(
                    request,
                    "login.rate_limited",
                    status_code=429,
                )
                response.headers["Retry-After"] = str(retry_after)
                return response
            if request.headers.get("X-CSRF-Token"):
                return _problem_response(
                    401,
                    "invalid_credentials",
                    "Invalid credentials.",
                )
            return login_page(request, "login.invalid", status_code=401)
        record_login_success(request, organization, username)
        response = RedirectResponse("/app", status_code=303)
        response.set_cookie(
            _SESSION_COOKIE,
            token,
            httponly=True,
            max_age=_SESSION_SECONDS,
            path="/",
            samesite="strict",
            secure=settings.cookie_secure,
        )
        response.delete_cookie(_LOGIN_CSRF_COOKIE, path="/")
        return response

    @app.get("/app", include_in_schema=False)
    def dashboard(request: Request, offset: int = 0):
        try:
            token = cookie_token(request)
        except AuthenticationError:
            return RedirectResponse("/app/login", status_code=303)
        return render_template(
            request,
            "dashboard.html",
            dashboard_context(token, job_offset=offset),
        )

    @app.post("/app/locale", include_in_schema=False)
    def select_locale(
        request: Request,
        locale: Annotated[str, Form()],
        target: Annotated[str, Form()] = "login",
    ):
        if locale not in SUPPORTED_LOCALES:
            raise ValueError("unsupported locale")
        destination = "/app" if target == "app" else "/app/login"
        response = RedirectResponse(destination, status_code=303)
        response.set_cookie(
            _LOCALE_COOKIE,
            locale,
            httponly=True,
            max_age=365 * 24 * 60 * 60,
            path="/app",
            samesite="strict",
            secure=settings.cookie_secure,
        )
        return response

    @app.post("/app/logout", include_in_schema=False)
    def logout(request: Request):
        token = cookie_token(request)
        workspace.logout(token)
        response = RedirectResponse("/app/login", status_code=303)
        response.delete_cookie(_SESSION_COOKIE, path="/")
        return response

    @app.post("/app/classify", include_in_schema=False)
    async def classify_ui(
        request: Request,
        upload: Annotated[UploadFile, File()],
        model: Annotated[str, Form()] = "rules",
    ):
        token = await run_in_threadpool(cookie_token, request)
        input_format: InputFormat = resolve_input_format(upload.filename or "")
        with tempfile.TemporaryDirectory(prefix="log-classify-web-") as directory:
            input_path = Path(directory) / "input.data"
            await _save_upload(upload, input_path, max_bytes=settings.max_input_bytes)
            job_id = await run_in_threadpool(
                enqueue_sync,
                input_path,
                model,
                token,
                input_format,
            )
        return RedirectResponse(f"/app/jobs/{job_id}", status_code=303)

    @app.get("/app/jobs/{job_id}", include_in_schema=False)
    def job_page(request: Request, job_id: str):
        try:
            token = cookie_token(request)
        except AuthenticationError:
            return RedirectResponse("/app/login", status_code=303)
        stored_job = workspace.get_job(token, job_id)
        status = workspace.get_job_status(token, job_id)
        return render_template(
            request,
            "job.html",
            {
                "csrf": workspace.csrf_token(token),
                "job": stored_job,
                "status": status,
                "principal": workspace.principal(token),
            },
        )

    @app.get("/app/jobs/{job_id}/status", include_in_schema=False)
    def job_status_ui(request: Request, job_id: str) -> dict[str, Any]:
        token = cookie_token(request)
        return workspace.get_job_status(token, job_id)

    @app.post("/app/jobs/{job_id}/cancel", include_in_schema=False)
    def cancel_job_ui(request: Request, job_id: str):
        token = cookie_token(request)
        cancel_sync(token, job_id)
        return RedirectResponse(f"/app/jobs/{job_id}", status_code=303)

    @app.get("/app/jobs/{job_id}/export", include_in_schema=False)
    def export_job_ui(request: Request, job_id: str):
        token = cookie_token(request)
        return result_export(workspace.get_job(token, job_id))

    @app.post("/app/admin/users", include_in_schema=False)
    def create_user_ui(
        request: Request,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        role: Annotated[Role, Form()],
    ):
        token = cookie_token(request)
        workspace.create_user(token, username, password, role)
        return RedirectResponse("/app", status_code=303)

    @app.post("/app/admin/users/{user_id}", include_in_schema=False)
    def update_user_ui(
        request: Request,
        user_id: str,
        role: Annotated[Role, Form()],
        disabled: Annotated[bool, Form()] = False,
        password: Annotated[str, Form()] = "",
    ):
        token = cookie_token(request)
        workspace.update_user(
            token,
            user_id,
            role=role,
            disabled=disabled,
            password=password or None,
        )
        return RedirectResponse("/app", status_code=303)

    @app.post("/app/admin/retention", include_in_schema=False)
    def retention_ui(
        request: Request,
        raw_days: Annotated[int, Form()],
        result_days: Annotated[int, Form()],
        audit_days: Annotated[int, Form()],
    ):
        token = cookie_token(request)
        workspace.set_retention_policy(
            token,
            RetentionPolicy(
                raw_days=raw_days,
                result_days=result_days,
                audit_days=audit_days,
            ),
        )
        return RedirectResponse("/app", status_code=303)

    @app.post("/app/admin/purge", include_in_schema=False)
    def purge_ui(request: Request):
        token = cookie_token(request)
        workspace.purge_expired(token)
        return RedirectResponse("/app", status_code=303)

    return app
