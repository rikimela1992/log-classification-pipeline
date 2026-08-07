"""Local multi-user workspace with explicit RBAC and retention boundaries.

This module is intentionally dependency-free and local-first.  It provides the
application domain needed by a future HTTP UI without opening a network socket
or claiming production-ready identity management.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from stat import S_ISREG
from typing import Any, Iterator
from urllib.parse import quote
from uuid import uuid4

from .prediction import validate_classification_prediction


class WorkspaceError(RuntimeError):
    """Base class for expected workspace failures."""


class AuthenticationError(WorkspaceError):
    """Credentials or a session token could not be authenticated."""


class AuthorizationError(WorkspaceError):
    """An authenticated user is not allowed to perform an operation."""


class ConflictError(WorkspaceError):
    """A unique workspace resource already exists."""


class NotFoundError(WorkspaceError):
    """A resource is absent or is outside the caller's organization."""


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class JobStatus(StrEnum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: str
    organization_id: str
    username: str
    role: Role


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    raw_days: int = 30
    result_days: int = 90
    audit_days: int = 180

    def __post_init__(self) -> None:
        for name, value in (
            ("raw_days", self.raw_days),
            ("result_days", self.result_days),
            ("audit_days", self.audit_days),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
                or value > 3650
            ):
                raise ValueError(f"{name} must be an integer between 1 and 3650")


@dataclass(frozen=True, slots=True)
class PurgeSummary:
    raw_payloads_removed: int
    jobs_removed: int
    audit_events_removed: int
    sessions_removed: int


_IDENTIFIER_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}\Z")
_PASSWORD_MIN_LENGTH = 12
_PASSWORD_MAX_LENGTH = 1024
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SESSION_BYTES = 32
_DEFAULT_SESSION_HOURS = 8
_MAX_SESSION_HOURS = 24
_MAX_RAW_PAYLOAD_BYTES = 1_000_000
_SCHEMA_VERSION = "1"
_EXPECTED_TABLES = {
    "audit_events",
    "jobs",
    "organizations",
    "retention_policies",
    "sessions",
    "users",
    "workspace_metadata",
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _normalize_identifier(value: str, *, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    normalized = value.strip().casefold()
    if not _IDENTIFIER_PATTERN.fullmatch(normalized):
        raise ValueError(
            f"{name} must be 3-64 characters using lowercase letters, digits, '.', '_', or '-'"
        )
    return normalized


def _validate_password(password: str) -> None:
    if not isinstance(password, str):
        raise ValueError("password must be a string")
    if len(password) < _PASSWORD_MIN_LENGTH:
        raise ValueError(
            f"password must contain at least {_PASSWORD_MIN_LENGTH} characters"
        )
    if len(password) > _PASSWORD_MAX_LENGTH:
        raise ValueError(
            f"password must contain at most {_PASSWORD_MAX_LENGTH} characters"
        )


def _password_hash(password: str) -> str:
    _validate_password(password)
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
    )
    return "$".join(
        (
            "scrypt",
            str(_SCRYPT_N),
            str(_SCRYPT_R),
            str(_SCRYPT_P),
            salt.hex(),
            derived.hex(),
        )
    )


def _password_matches(password: str, encoded: str) -> bool:
    try:
        algorithm, raw_n, raw_r, raw_p, raw_salt, raw_derived = encoded.split("$")
        if algorithm != "scrypt":
            return False
        expected = bytes.fromhex(raw_derived)
        observed = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(raw_salt),
            n=int(raw_n),
            r=int(raw_r),
            p=int(raw_p),
            dklen=len(expected),
        )
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(observed, expected)


def _dummy_password_hash() -> str:
    salt = b"local-auth-dummy"
    derived = hashlib.scrypt(
        b"dummy-password-value",
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
    )
    return "$".join(
        (
            "scrypt",
            str(_SCRYPT_N),
            str(_SCRYPT_R),
            str(_SCRYPT_P),
            salt.hex(),
            derived.hex(),
        )
    )


_DUMMY_PASSWORD_HASH = _dummy_password_hash()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _validate_input_records(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("input_records must be a positive integer")


def _validate_source(source_sha256: str, raw_payload: bytes | None) -> None:
    if (
        not isinstance(source_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", source_sha256)
    ):
        raise ValueError("source_sha256 must be 64 lowercase hexadecimal characters")
    if raw_payload is not None and not isinstance(raw_payload, bytes):
        raise TypeError("raw_payload must be bytes or None")
    if raw_payload is not None and len(raw_payload) > _MAX_RAW_PAYLOAD_BYTES:
        raise ValueError(f"raw_payload must not exceed {_MAX_RAW_PAYLOAD_BYTES} bytes")
    if raw_payload is not None and not hmac.compare_digest(
        hashlib.sha256(raw_payload).hexdigest(), source_sha256
    ):
        raise ValueError("raw_payload does not match source_sha256")


class Workspace:
    """SQLite-backed local workspace with tenant-scoped operations."""

    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)

    def _validate_database_file(self) -> None:
        if self.database_path.is_symlink():
            raise OSError("refusing a symlink workspace database")
        parent_mode = self.database_path.parent.stat().st_mode
        if parent_mode & 0o022:
            raise OSError("workspace database directory must not be group/world writable")
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.database_path, flags)
        except OSError as exc:
            if self.database_path.is_symlink():
                raise OSError("refusing a symlink workspace database") from exc
            raise
        try:
            metadata = os.fstat(descriptor)
            if not S_ISREG(metadata.st_mode):
                raise OSError("workspace database path must be a regular file")
            if metadata.st_mode & 0o077:
                raise OSError("workspace database must have mode 0o600 or stricter")
        finally:
            os.close(descriptor)

    @contextmanager
    def _connect(
        self,
        *,
        require_schema: bool = True,
    ) -> Iterator[sqlite3.Connection]:
        self._validate_database_file()
        database_uri = f"file:{quote(str(self.database_path.absolute()))}?mode=rw"
        connection = sqlite3.connect(
            database_uri,
            timeout=5,
            isolation_level="IMMEDIATE",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        try:
            if require_schema:
                tables = {
                    row["name"]
                    for row in connection.execute(
                        """SELECT name FROM sqlite_master
                           WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"""
                    ).fetchall()
                }
                if tables != _EXPECTED_TABLES:
                    raise WorkspaceError("workspace schema is missing or unexpected")
                schema_row = connection.execute(
                    "SELECT value FROM workspace_metadata WHERE key = 'schema_version'"
                ).fetchone()
                if schema_row is None or schema_row["value"] != _SCHEMA_VERSION:
                    observed = None if schema_row is None else schema_row["value"]
                    raise WorkspaceError(
                        f"unsupported workspace schema version {observed!r}"
                    )
            connection.execute("PRAGMA busy_timeout = 5000")
            if require_schema:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("PRAGMA secure_delete = ON")
                connection.execute("PRAGMA journal_mode = DELETE")
                connection.execute("PRAGMA synchronous = FULL")
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        """Create the schema and restrict an existing database file to its owner."""

        if self.database_path.is_symlink():
            raise OSError("refusing a symlink workspace database")
        self.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_mode = self.database_path.parent.stat().st_mode
        if parent_mode & 0o022:
            raise OSError("workspace database directory must not be group/world writable")
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            database_fd = os.open(
                self.database_path,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            database_created = True
        except FileExistsError:
            try:
                database_fd = os.open(self.database_path, flags)
            except OSError as exc:
                if self.database_path.is_symlink():
                    raise OSError("refusing a symlink workspace database") from exc
                raise
            database_created = False
        except OSError as exc:
            if self.database_path.is_symlink():
                raise OSError("refusing a symlink workspace database") from exc
            raise
        try:
            metadata = os.fstat(database_fd)
            if not S_ISREG(metadata.st_mode):
                raise OSError("workspace database path must be a regular file")
            if database_created:
                os.fchmod(database_fd, 0o600)
            elif metadata.st_mode & 0o077:
                raise OSError("workspace database must have mode 0o600 or stricter")
        finally:
            os.close(database_fd)
        with self._connect(require_schema=False) as connection:
            existing_tables = {
                row["name"]
                for row in connection.execute(
                    """SELECT name FROM sqlite_master
                       WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"""
                ).fetchall()
            }
            if existing_tables:
                if "workspace_metadata" not in existing_tables:
                    raise WorkspaceError(
                        "refusing a non-empty database without workspace metadata"
                    )
                schema_row = connection.execute(
                    "SELECT value FROM workspace_metadata WHERE key = 'schema_version'"
                ).fetchone()
                if schema_row is None or schema_row["value"] != _SCHEMA_VERSION:
                    observed = None if schema_row is None else schema_row["value"]
                    raise WorkspaceError(
                        f"unsupported workspace schema version {observed!r}"
                    )
                if existing_tables != _EXPECTED_TABLES:
                    raise WorkspaceError("workspace schema is incomplete or unexpected")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                BEGIN IMMEDIATE;

                CREATE TABLE IF NOT EXISTS workspace_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS organizations (
                    id TEXT PRIMARY KEY,
                    slug TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
                    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
                    created_at TEXT NOT NULL,
                    UNIQUE (organization_id, username)
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS retention_policies (
                    organization_id TEXT PRIMARY KEY REFERENCES organizations(id),
                    raw_days INTEGER NOT NULL CHECK (raw_days BETWEEN 1 AND 3650),
                    result_days INTEGER NOT NULL CHECK (result_days BETWEEN 1 AND 3650),
                    audit_days INTEGER NOT NULL CHECK (audit_days BETWEEN 1 AND 3650),
                    updated_at TEXT NOT NULL,
                    updated_by TEXT NOT NULL REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    created_by TEXT NOT NULL REFERENCES users(id),
                    status TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed')),
                    source_sha256 TEXT NOT NULL,
                    input_records INTEGER NOT NULL CHECK (input_records > 0),
                    output_records INTEGER CHECK (output_records >= 0),
                    raw_payload BLOB,
                    raw_expires_at TEXT NOT NULL,
                    results_json TEXT,
                    results_expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );

                CREATE INDEX IF NOT EXISTS jobs_organization_created
                    ON jobs (organization_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    actor_user_id TEXT REFERENCES users(id),
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT,
                    occurred_at TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS audit_organization_time
                    ON audit_events (organization_id, occurred_at DESC);

                INSERT OR IGNORE INTO workspace_metadata (key, value)
                    VALUES ('schema_version', '1');

                COMMIT;
                """
            )

    def verify(self) -> None:
        """Fail closed unless this is a recognized, accessible workspace."""

        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()

    def bootstrap(
        self,
        organization: str,
        username: str,
        password: str,
        *,
        now: datetime | None = None,
    ) -> tuple[str, str]:
        """Create the first organization and administrator in an empty workspace."""

        self.initialize()
        organization_slug = _normalize_identifier(organization, name="organization")
        normalized_username = _normalize_identifier(username, name="username")
        encoded_password = _password_hash(password)
        instant = now or _utc_now()
        organization_id = str(uuid4())
        user_id = str(uuid4())
        policy = RetentionPolicy()
        try:
            with self._connect() as connection:
                if connection.execute("SELECT 1 FROM organizations LIMIT 1").fetchone():
                    raise ConflictError("workspace has already been bootstrapped")
                connection.execute(
                    "INSERT INTO organizations (id, slug, created_at) VALUES (?, ?, ?)",
                    (organization_id, organization_slug, _timestamp(instant)),
                )
                connection.execute(
                    """INSERT INTO users
                       (id, organization_id, username, password_hash, role, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        user_id,
                        organization_id,
                        normalized_username,
                        encoded_password,
                        Role.ADMIN.value,
                        _timestamp(instant),
                    ),
                )
                connection.execute(
                    """INSERT INTO retention_policies
                       (organization_id, raw_days, result_days, audit_days, updated_at, updated_by)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        organization_id,
                        policy.raw_days,
                        policy.result_days,
                        policy.audit_days,
                        _timestamp(instant),
                        user_id,
                    ),
                )
                self._audit(
                    connection,
                    organization_id,
                    user_id,
                    "workspace.bootstrap",
                    "organization",
                    organization_id,
                    instant,
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("workspace bootstrap conflicts with existing data") from exc
        return organization_id, user_id

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        organization_id: str,
        actor_user_id: str | None,
        action: str,
        target_type: str,
        target_id: str | None,
        now: datetime,
        details: dict[str, Any] | None = None,
    ) -> None:
        connection.execute(
            """INSERT INTO audit_events
               (organization_id, actor_user_id, action, target_type, target_id,
                occurred_at, details_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                organization_id,
                actor_user_id,
                action,
                target_type,
                target_id,
                _timestamp(now),
                json.dumps(details or {}, sort_keys=True, separators=(",", ":")),
            ),
        )

    def login(
        self,
        organization: str,
        username: str,
        password: str,
        *,
        session_hours: int = _DEFAULT_SESSION_HOURS,
        now: datetime | None = None,
    ) -> tuple[str, Principal]:
        """Authenticate credentials and return a new opaque session token."""

        organization_slug = _normalize_identifier(organization, name="organization")
        normalized_username = _normalize_identifier(username, name="username")
        if (
            isinstance(session_hours, bool)
            or not isinstance(session_hours, int)
            or not 1 <= session_hours <= _MAX_SESSION_HOURS
        ):
            raise ValueError(
                f"session_hours must be an integer between 1 and {_MAX_SESSION_HOURS}"
            )
        instant = now or _utc_now()
        authentication_failed = False
        token: str | None = None
        principal: Principal | None = None
        with self._connect() as connection:
            row = connection.execute(
                """SELECT users.id, users.organization_id, users.username,
                          users.password_hash, users.role, users.disabled
                   FROM users
                   JOIN organizations ON organizations.id = users.organization_id
                   WHERE organizations.slug = ? AND users.username = ?""",
                (organization_slug, normalized_username),
            ).fetchone()
            password_input_valid = (
                isinstance(password, str)
                and 1 <= len(password) <= _PASSWORD_MAX_LENGTH
            )
            password_is_valid = _password_matches(
                password if password_input_valid else "invalid-password-input",
                row["password_hash"] if row is not None else _DUMMY_PASSWORD_HASH,
            )
            if (
                row is None
                or row["disabled"]
                or not password_input_valid
                or not password_is_valid
            ):
                organization_row = connection.execute(
                    "SELECT id FROM organizations WHERE slug = ?",
                    (organization_slug,),
                ).fetchone()
                if organization_row is not None:
                    self._audit(
                        connection,
                        organization_row["id"],
                        None,
                        "auth.login_failed",
                        "session",
                        None,
                        instant,
                    )
                authentication_failed = True
            else:
                token = secrets.token_urlsafe(_SESSION_BYTES)
                connection.execute(
                    """INSERT INTO sessions
                       (token_hash, user_id, created_at, expires_at)
                       VALUES (?, ?, ?, ?)""",
                    (
                        _token_hash(token),
                        row["id"],
                        _timestamp(instant),
                        _timestamp(instant + timedelta(hours=session_hours)),
                    ),
                )
                self._audit(
                    connection,
                    row["organization_id"],
                    row["id"],
                    "auth.login",
                    "session",
                    None,
                    instant,
                )
                principal = Principal(
                    user_id=row["id"],
                    organization_id=row["organization_id"],
                    username=row["username"],
                    role=Role(row["role"]),
                )
        if authentication_failed:
            raise AuthenticationError("invalid credentials")
        assert token is not None and principal is not None
        return token, principal

    def principal(self, token: str, *, now: datetime | None = None) -> Principal:
        """Resolve an active session without exposing its persisted hash."""

        if not isinstance(token, str) or not token:
            raise AuthenticationError("invalid session")
        instant = now or _utc_now()
        try:
            digest = _token_hash(token)
        except UnicodeEncodeError as exc:
            raise AuthenticationError("invalid session") from exc
        with self._connect() as connection:
            row = connection.execute(
                """SELECT sessions.expires_at, users.id, users.organization_id,
                          users.username, users.role, users.disabled
                   FROM sessions
                   JOIN users ON users.id = sessions.user_id
                   WHERE sessions.token_hash = ?""",
                (digest,),
            ).fetchone()
            if row is None or row["disabled"] or row["expires_at"] <= _timestamp(instant):
                if row is not None:
                    connection.execute(
                        "DELETE FROM sessions WHERE token_hash = ?", (digest,)
                    )
                raise AuthenticationError("invalid or expired session")
            return Principal(
                user_id=row["id"],
                organization_id=row["organization_id"],
                username=row["username"],
                role=Role(row["role"]),
            )

    def logout(self, token: str, *, now: datetime | None = None) -> None:
        principal = self.principal(token, now=now)
        instant = now or _utc_now()
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),)
            )
            self._audit(
                connection,
                principal.organization_id,
                principal.user_id,
                "auth.logout",
                "session",
                None,
                instant,
            )

    @staticmethod
    def _require(principal: Principal, *roles: Role) -> None:
        if principal.role not in roles:
            raise AuthorizationError("operation is not permitted for this role")

    def authorize_classification(
        self,
        token: str,
        *,
        retain_raw: bool = False,
        now: datetime | None = None,
    ) -> Principal:
        """Fail-fast before reading input or invoking a model."""

        principal = self.principal(token, now=now)
        self._require(principal, Role.ADMIN, Role.ANALYST)
        if retain_raw:
            self._require(principal, Role.ADMIN)
        return principal

    def authorize_admin(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> Principal:
        principal = self.principal(token, now=now)
        self._require(principal, Role.ADMIN)
        return principal

    def csrf_token(self, token: str, *, now: datetime | None = None) -> str:
        """Derive a session-bound CSRF value without exposing the session token."""

        self.principal(token, now=now)
        return self._csrf_digest(token)

    @staticmethod
    def _csrf_digest(token: str) -> str:
        try:
            token_bytes = token.encode("ascii")
        except UnicodeEncodeError as exc:
            raise AuthenticationError("invalid session") from exc
        return hmac.new(
            token_bytes,
            b"log-classification-pipeline:csrf:v1",
            hashlib.sha256,
        ).hexdigest()

    def verify_csrf(
        self,
        token: str,
        submitted: str,
        *,
        now: datetime | None = None,
    ) -> Principal:
        if not isinstance(submitted, str) or not submitted:
            raise AuthorizationError("invalid CSRF token")
        principal = self.principal(token, now=now)
        expected = self._csrf_digest(token)
        if not hmac.compare_digest(expected, submitted):
            raise AuthorizationError("invalid CSRF token")
        return principal

    def create_user(
        self,
        token: str,
        username: str,
        password: str,
        role: Role | str,
        *,
        now: datetime | None = None,
    ) -> str:
        principal = self.principal(token, now=now)
        self._require(principal, Role.ADMIN)
        normalized_username = _normalize_identifier(username, name="username")
        encoded_password = _password_hash(password)
        try:
            parsed_role = Role(role)
        except ValueError as exc:
            raise ValueError("role must be admin, analyst, or viewer") from exc
        instant = now or _utc_now()
        user_id = str(uuid4())
        try:
            with self._connect() as connection:
                connection.execute(
                    """INSERT INTO users
                       (id, organization_id, username, password_hash, role, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        user_id,
                        principal.organization_id,
                        normalized_username,
                        encoded_password,
                        parsed_role.value,
                        _timestamp(instant),
                    ),
                )
                self._audit(
                    connection,
                    principal.organization_id,
                    principal.user_id,
                    "user.create",
                    "user",
                    user_id,
                    instant,
                    {"role": parsed_role.value},
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("username already exists in this organization") from exc
        return user_id

    def list_users(
        self,
        token: str,
        *,
        limit: int = 100,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        principal = self.authorize_admin(token, now=now)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("limit must be an integer between 1 and 200")
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, username, role, disabled, created_at
                   FROM users WHERE organization_id = ?
                   ORDER BY username ASC, id ASC LIMIT ?""",
                (principal.organization_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_retention_policy(
        self, token: str, *, now: datetime | None = None
    ) -> RetentionPolicy:
        principal = self.principal(token, now=now)
        with self._connect() as connection:
            row = connection.execute(
                """SELECT raw_days, result_days, audit_days
                   FROM retention_policies WHERE organization_id = ?""",
                (principal.organization_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("retention policy not found")
        return RetentionPolicy(
            raw_days=row["raw_days"],
            result_days=row["result_days"],
            audit_days=row["audit_days"],
        )

    def set_retention_policy(
        self,
        token: str,
        policy: RetentionPolicy,
        *,
        now: datetime | None = None,
    ) -> None:
        principal = self.principal(token, now=now)
        self._require(principal, Role.ADMIN)
        if not isinstance(policy, RetentionPolicy):
            raise TypeError("policy must be a RetentionPolicy")
        instant = now or _utc_now()
        with self._connect() as connection:
            connection.execute(
                """UPDATE retention_policies
                   SET raw_days = ?, result_days = ?, audit_days = ?,
                       updated_at = ?, updated_by = ?
                   WHERE organization_id = ?""",
                (
                    policy.raw_days,
                    policy.result_days,
                    policy.audit_days,
                    _timestamp(instant),
                    principal.user_id,
                    principal.organization_id,
                ),
            )
            self._audit(
                connection,
                principal.organization_id,
                principal.user_id,
                "retention.update",
                "retention_policy",
                principal.organization_id,
                instant,
                {
                    "raw_days": policy.raw_days,
                    "result_days": policy.result_days,
                    "audit_days": policy.audit_days,
                },
            )

    def create_job(
        self,
        token: str,
        source_sha256: str,
        input_records: int,
        *,
        raw_payload: bytes | None = None,
        now: datetime | None = None,
    ) -> str:
        principal = self.principal(token, now=now)
        self._require(principal, Role.ADMIN, Role.ANALYST)
        if raw_payload is not None:
            self._require(principal, Role.ADMIN)
        _validate_input_records(input_records)
        _validate_source(source_sha256, raw_payload)
        policy = self.get_retention_policy(token, now=now)
        instant = now or _utc_now()
        job_id = str(uuid4())
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO jobs
                   (id, organization_id, created_by, status, source_sha256, input_records,
                    raw_payload, raw_expires_at, results_expires_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    job_id,
                    principal.organization_id,
                    principal.user_id,
                    JobStatus.PENDING.value,
                    source_sha256,
                    input_records,
                    raw_payload,
                    _timestamp(instant + timedelta(days=policy.raw_days)),
                    _timestamp(instant + timedelta(days=policy.result_days)),
                    _timestamp(instant),
                ),
            )
            self._audit(
                connection,
                principal.organization_id,
                principal.user_id,
                "job.create",
                "job",
                job_id,
                instant,
                {"input_records": input_records, "raw_stored": raw_payload is not None},
            )
        return job_id

    def complete_job(
        self,
        token: str,
        job_id: str,
        results: list[dict[str, Any]],
        *,
        now: datetime | None = None,
    ) -> None:
        principal = self.principal(token, now=now)
        self._require(principal, Role.ADMIN, Role.ANALYST)
        if not isinstance(results, list):
            raise TypeError("results must be a list of classification objects")
        normalized_results = [
            validate_classification_prediction(item, index)
            for index, item in enumerate(results, start=1)
        ]
        try:
            encoded_results = json.dumps(
                normalized_results,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("results must be JSON serializable") from exc
        instant = now or _utc_now()
        with self._connect() as connection:
            job_row = connection.execute(
                """SELECT input_records FROM jobs
                   WHERE id = ? AND organization_id = ? AND status = ?""",
                (job_id, principal.organization_id, JobStatus.PENDING.value),
            ).fetchone()
            if job_row is None:
                raise NotFoundError("pending job not found")
            if len(normalized_results) != job_row["input_records"]:
                raise ValueError(
                    "result count must exactly match the persisted input record count"
                )
            cursor = connection.execute(
                """UPDATE jobs SET status = ?, results_json = ?, output_records = ?,
                                  completed_at = ?
                   WHERE id = ? AND organization_id = ? AND status = ?""",
                (
                    JobStatus.SUCCEEDED.value,
                    encoded_results,
                    len(normalized_results),
                    _timestamp(instant),
                    job_id,
                    principal.organization_id,
                    JobStatus.PENDING.value,
                ),
            )
            if cursor.rowcount != 1:
                raise NotFoundError("pending job not found")
            self._audit(
                connection,
                principal.organization_id,
                principal.user_id,
                "job.complete",
                "job",
                job_id,
                instant,
                {"result_count": len(normalized_results)},
            )

    def store_completed_job(
        self,
        token: str,
        source_sha256: str,
        input_records: int,
        results: list[dict[str, Any]],
        *,
        raw_payload: bytes | None = None,
        now: datetime | None = None,
    ) -> str:
        """Atomically store one already completed, fully validated classification."""

        principal = self.principal(token, now=now)
        self._require(principal, Role.ADMIN, Role.ANALYST)
        if raw_payload is not None:
            self._require(principal, Role.ADMIN)
        _validate_input_records(input_records)
        _validate_source(source_sha256, raw_payload)
        if not isinstance(results, list):
            raise TypeError("results must be a list of classification objects")
        normalized_results = [
            validate_classification_prediction(item, index)
            for index, item in enumerate(results, start=1)
        ]
        if len(normalized_results) != input_records:
            raise ValueError("result count must exactly match input_records")
        try:
            encoded_results = json.dumps(
                normalized_results,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("results must be JSON serializable") from exc
        policy = self.get_retention_policy(token, now=now)
        instant = now or _utc_now()
        job_id = str(uuid4())
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO jobs
                   (id, organization_id, created_by, status, source_sha256,
                    input_records, output_records,
                    raw_payload, raw_expires_at, results_json, results_expires_at,
                    created_at, completed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    job_id,
                    principal.organization_id,
                    principal.user_id,
                    JobStatus.SUCCEEDED.value,
                    source_sha256,
                    input_records,
                    len(normalized_results),
                    raw_payload,
                    _timestamp(instant + timedelta(days=policy.raw_days)),
                    encoded_results,
                    _timestamp(instant + timedelta(days=policy.result_days)),
                    _timestamp(instant),
                    _timestamp(instant),
                ),
            )
            self._audit(
                connection,
                principal.organization_id,
                principal.user_id,
                "job.store_completed",
                "job",
                job_id,
                instant,
                {
                    "raw_stored": raw_payload is not None,
                    "input_records": input_records,
                    "result_count": len(normalized_results),
                },
            )
        return job_id

    def get_job(
        self,
        token: str,
        job_id: str,
        *,
        include_raw: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        principal = self.principal(token, now=now)
        if include_raw:
            self._require(principal, Role.ADMIN)
        instant = now or _utc_now()
        instant_timestamp = _timestamp(instant)
        with self._connect() as connection:
            row = connection.execute(
                """SELECT id, status, source_sha256, input_records, output_records,
                          raw_payload, raw_expires_at,
                          results_json, results_expires_at, created_at, completed_at
                   FROM jobs
                   WHERE id = ? AND organization_id = ? AND results_expires_at > ?""",
                (job_id, principal.organization_id, instant_timestamp),
            ).fetchone()
            if row is None:
                raise NotFoundError("job not found")
            results_included = row["results_json"] is not None
            raw_included = (
                include_raw
                and row["raw_payload"] is not None
                and row["raw_expires_at"] > instant_timestamp
            )
            self._audit(
                connection,
                principal.organization_id,
                principal.user_id,
                "job.export" if results_included or raw_included else "job.view",
                "job",
                job_id,
                instant,
                {
                    "raw_included": raw_included,
                    "results_included": results_included,
                },
            )
        result: dict[str, Any] = {
            "id": row["id"],
            "status": row["status"],
            "source_sha256": row["source_sha256"],
            "input_records": row["input_records"],
            "output_records": row["output_records"],
            "results": (
                json.loads(row["results_json"]) if results_included else None
            ),
            "created_at": row["created_at"],
            "completed_at": row["completed_at"],
        }
        if include_raw:
            result["raw_payload"] = (
                row["raw_payload"] if raw_included else None
            )
        return result

    def list_jobs(
        self,
        token: str,
        *,
        limit: int = 50,
        offset: int = 0,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        principal = self.principal(token, now=now)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 201:
            raise ValueError("limit must be an integer between 1 and 201")
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or not 0 <= offset <= 100_000
        ):
            raise ValueError("offset must be an integer between 0 and 100000")
        with self._connect() as connection:
            instant_timestamp = _timestamp(now or _utc_now())
            rows = connection.execute(
                """SELECT id, status, source_sha256, input_records, output_records,
                          created_at, completed_at,
                          (results_json IS NOT NULL) AS has_results
                   FROM jobs WHERE organization_id = ? AND results_expires_at > ?
                   ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?""",
                (principal.organization_id, instant_timestamp, limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_audit_events(
        self,
        token: str,
        *,
        limit: int = 100,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        principal = self.principal(token, now=now)
        self._require(principal, Role.ADMIN)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be an integer between 1 and 500")
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, actor_user_id, action, target_type, target_id,
                          occurred_at, details_json
                   FROM audit_events WHERE organization_id = ?
                   ORDER BY id DESC LIMIT ?""",
                (principal.organization_id, limit),
            ).fetchall()
        return [
            {
                **{key: row[key] for key in row.keys() if key != "details_json"},
                "details": json.loads(row["details_json"]),
            }
            for row in rows
        ]

    def purge_expired(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> PurgeSummary:
        """Remove expired payloads/results and old audit events for one tenant."""

        principal = self.principal(token, now=now)
        self._require(principal, Role.ADMIN)
        policy = self.get_retention_policy(token, now=now)
        instant = now or _utc_now()
        threshold = instant - timedelta(days=policy.audit_days)
        with self._connect() as connection:
            raw_cursor = connection.execute(
                """UPDATE jobs SET raw_payload = NULL
                   WHERE organization_id = ? AND raw_payload IS NOT NULL
                     AND raw_expires_at <= ?""",
                (principal.organization_id, _timestamp(instant)),
            )
            job_cursor = connection.execute(
                """DELETE FROM jobs
                   WHERE organization_id = ? AND results_expires_at <= ?""",
                (principal.organization_id, _timestamp(instant)),
            )
            audit_cursor = connection.execute(
                """DELETE FROM audit_events
                   WHERE organization_id = ? AND occurred_at <= ?""",
                (principal.organization_id, _timestamp(threshold)),
            )
            session_cursor = connection.execute(
                """DELETE FROM sessions
                   WHERE expires_at <= ? AND user_id IN (
                       SELECT id FROM users WHERE organization_id = ?
                   )""",
                (_timestamp(instant), principal.organization_id),
            )
            summary = PurgeSummary(
                raw_payloads_removed=raw_cursor.rowcount,
                jobs_removed=job_cursor.rowcount,
                audit_events_removed=audit_cursor.rowcount,
                sessions_removed=session_cursor.rowcount,
            )
            self._audit(
                connection,
                principal.organization_id,
                principal.user_id,
                "retention.purge",
                "organization",
                principal.organization_id,
                instant,
                {
                    "raw_payloads_removed": summary.raw_payloads_removed,
                    "jobs_removed": summary.jobs_removed,
                    "audit_events_removed": summary.audit_events_removed,
                    "sessions_removed": summary.sessions_removed,
                },
            )
        return summary
