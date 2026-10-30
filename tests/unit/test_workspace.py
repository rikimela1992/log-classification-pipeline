from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from log_classification_pipeline.contracts import PredictionContractError
from log_classification_pipeline.workspace import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    JobStatus,
    NotFoundError,
    RetentionPolicy,
    Role,
    Workspace,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
PASSWORD = "correct-horse-battery-staple"


def prediction() -> dict[str, object]:
    return {
        "schema_version": "1",
        "subsystem": {"label": "auth", "score": 0.9},
        "severity": {"label": "security_event", "score": 0.8},
        "abstained": False,
        "model": {"id": "synthetic-test", "revision": "test-only"},
    }


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class WorkspaceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "workspace.sqlite3"
        self.workspace = Workspace(self.database_path)
        self.organization_id, self.admin_id = self.workspace.bootstrap(
            "sample-org",
            "owner",
            PASSWORD,
            now=NOW,
        )
        self.admin_token, self.admin = self.workspace.login(
            "sample-org",
            "owner",
            PASSWORD,
            now=NOW,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def create_user_and_login(self, username: str, role: Role) -> str:
        self.workspace.create_user(
            self.admin_token,
            username,
            PASSWORD,
            role,
            now=NOW,
        )
        token, _ = self.workspace.login(
            "sample-org",
            username,
            PASSWORD,
            now=NOW,
        )
        return token

    def admin_token_at(self, now: datetime) -> str:
        token, _ = self.workspace.login(
            "sample-org",
            "owner",
            PASSWORD,
            now=now,
        )
        return token

    def test_bootstrap_creates_private_database_and_default_policy(self) -> None:
        self.assertEqual(
            stat.S_IMODE(self.database_path.stat().st_mode),
            0o600,
        )
        self.assertEqual(
            self.workspace.get_retention_policy(self.admin_token, now=NOW),
            RetentionPolicy(raw_days=30, result_days=90, audit_days=180),
        )
        with closing(sqlite3.connect(self.database_path)) as connection:
            self.assertEqual(connection.execute("PRAGMA secure_delete").fetchone()[0], 1)
        with self.assertRaises(ConflictError):
            self.workspace.bootstrap("another-org", "admin", PASSWORD, now=NOW)

    def test_login_failure_is_generic_and_does_not_store_password_or_username(self) -> None:
        for username, password in (
            ("owner", "definitely-the-wrong-password"),
            ("unknown-user", PASSWORD),
        ):
            with self.subTest(username=username):
                with self.assertRaisesRegex(AuthenticationError, "invalid credentials"):
                    self.workspace.login(
                        "sample-org",
                        username,
                        password,
                        now=NOW,
                    )

        database_bytes = self.database_path.read_bytes()
        self.assertNotIn(b"definitely-the-wrong-password", database_bytes)
        self.assertNotIn(b"unknown-user", database_bytes)
        events = self.workspace.list_audit_events(self.admin_token, now=NOW)
        self.assertEqual(
            sum(event["action"] == "auth.login_failed" for event in events),
            2,
        )

    def test_session_expiry_logout_and_non_ascii_token_fail_closed(self) -> None:
        self.assertEqual(self.workspace.principal(self.admin_token, now=NOW), self.admin)
        with self.assertRaises(AuthenticationError):
            self.workspace.principal(self.admin_token, now=NOW + timedelta(hours=8))
        with self.assertRaises(AuthenticationError):
            self.workspace.principal("not-ascii-\N{SNOWMAN}", now=NOW)

        token, _ = self.workspace.login("sample-org", "owner", PASSWORD, now=NOW)
        self.workspace.logout(token, now=NOW)
        with self.assertRaises(AuthenticationError):
            self.workspace.principal(token, now=NOW)

    def test_csrf_is_bound_to_one_live_session(self) -> None:
        second_token, _ = self.workspace.login(
            "sample-org",
            "owner",
            PASSWORD,
            now=NOW,
        )
        first_csrf = self.workspace.csrf_token(self.admin_token, now=NOW)

        self.assertEqual(
            self.workspace.verify_csrf(self.admin_token, first_csrf, now=NOW),
            self.admin,
        )
        with self.assertRaises(AuthorizationError):
            self.workspace.verify_csrf(second_token, first_csrf, now=NOW)

        self.workspace.logout(self.admin_token, now=NOW)
        with self.assertRaises(AuthenticationError):
            self.workspace.verify_csrf(self.admin_token, first_csrf, now=NOW)

    def test_bootstrap_rejects_bad_input_without_creating_a_workspace(self) -> None:
        database = Path(self.temporary_directory.name) / "fresh.sqlite3"
        with self.assertRaises(ValueError):
            Workspace(database).bootstrap("sample-org", "owner", "short")
        self.assertFalse(database.exists())

    def test_update_user_revokes_sessions_and_enforces_role_changes(self) -> None:
        analyst_token = self.create_user_and_login("analyst", Role.ANALYST)
        analyst_id = next(
            item["id"]
            for item in self.workspace.list_users(self.admin_token, now=NOW)
            if item["username"] == "analyst"
        )
        with self.assertRaises(AuthorizationError):
            self.workspace.update_user(analyst_token, analyst_id, disabled=True, now=NOW)

        updated = self.workspace.update_user(
            self.admin_token, analyst_id, role=Role.VIEWER, disabled=True, now=NOW
        )
        self.assertEqual((updated["role"], updated["disabled"]), ("viewer", 1))
        with self.assertRaises(AuthenticationError):
            self.workspace.principal(analyst_token, now=NOW)
        with self.assertRaises(AuthenticationError):
            self.workspace.login("sample-org", "analyst", PASSWORD, now=NOW)

        self.workspace.update_user(
            self.admin_token,
            analyst_id,
            disabled=False,
            password="replacement-password",
            now=NOW,
        )
        with self.assertRaises(AuthenticationError):
            self.workspace.login("sample-org", "analyst", PASSWORD, now=NOW)
        self.workspace.login("sample-org", "analyst", "replacement-password", now=NOW)
        events = self.workspace.list_audit_events(self.admin_token, now=NOW)
        self.assertNotIn("replacement-password", repr(events))
        self.assertIn("user.update", {event["action"] for event in events})

    def test_update_user_preserves_last_active_administrator(self) -> None:
        owner_id = self.workspace.principal(self.admin_token, now=NOW).user_id
        for change in ({"disabled": True}, {"role": Role.VIEWER}):
            with self.subTest(change=change):
                with self.assertRaises(ConflictError):
                    self.workspace.update_user(
                        self.admin_token, owner_id, now=NOW, **change
                    )
        self.workspace.principal(self.admin_token, now=NOW)

    def test_update_user_requires_a_change_and_an_organization_member(self) -> None:
        owner_id = self.workspace.principal(self.admin_token, now=NOW).user_id
        with self.assertRaises(ValueError):
            self.workspace.update_user(self.admin_token, owner_id, now=NOW)
        with self.assertRaises(NotFoundError):
            self.workspace.update_user(
                self.admin_token, "missing", disabled=True, now=NOW
            )

    def test_user_listing_is_admin_only_and_bounded(self) -> None:
        analyst_token = self.create_user_and_login("analyst", Role.ANALYST)
        users = self.workspace.list_users(self.admin_token, now=NOW)

        self.assertEqual([item["username"] for item in users], ["analyst", "owner"])
        self.assertNotIn("password_hash", repr(users))
        with self.assertRaises(AuthorizationError):
            self.workspace.list_users(analyst_token, now=NOW)
        for invalid_limit in (True, 0, 201):
            with self.subTest(limit=invalid_limit):
                with self.assertRaises(ValueError):
                    self.workspace.list_users(
                        self.admin_token,
                        limit=invalid_limit,
                        now=NOW,
                    )

    def test_role_matrix_blocks_viewer_and_limits_raw_access(self) -> None:
        analyst_token = self.create_user_and_login("analyst", Role.ANALYST)
        viewer_token = self.create_user_and_login("viewer", Role.VIEWER)

        source_digest = "a" * 64
        job_id = self.workspace.create_job(
            analyst_token,
            source_digest,
            1,
            now=NOW,
        )
        self.workspace.complete_job(analyst_token, job_id, [prediction()], now=NOW)

        self.assertEqual(
            self.workspace.get_job(viewer_token, job_id, now=NOW)["results"],
            [prediction()],
        )
        with self.assertRaises(AuthorizationError):
            self.workspace.get_job(viewer_token, job_id, include_raw=True, now=NOW)
        with self.assertRaises(AuthorizationError):
            self.workspace.create_job(viewer_token, source_digest, 1, now=NOW)
        with self.assertRaises(AuthorizationError):
            self.workspace.create_job(
                analyst_token,
                digest(b"synthetic raw"),
                1,
                raw_payload=b"synthetic raw",
                now=NOW,
            )
        with self.assertRaises(AuthorizationError):
            self.workspace.store_completed_job(
                analyst_token,
                digest(b"synthetic raw"),
                1,
                [prediction()],
                raw_payload=b"synthetic raw",
                now=NOW,
            )
        with self.assertRaises(AuthorizationError):
            self.workspace.set_retention_policy(
                analyst_token,
                RetentionPolicy(raw_days=7, result_days=30, audit_days=180),
                now=NOW,
            )
        with self.assertRaises(AuthorizationError):
            self.workspace.list_audit_events(analyst_token, now=NOW)

    def test_job_results_are_validated_and_completion_is_atomic(self) -> None:
        job_id = self.workspace.create_job(self.admin_token, "b" * 64, 1, now=NOW)
        invalid = prediction()
        invalid["subsystem"] = {"label": "invented", "score": 1.0}
        with self.assertRaises(PredictionContractError):
            self.workspace.complete_job(self.admin_token, job_id, [invalid], now=NOW)

        job = self.workspace.get_job(self.admin_token, job_id, now=NOW)
        self.assertEqual(job["status"], JobStatus.PENDING.value)
        self.assertIsNone(job["results"])

        self.workspace.complete_job(self.admin_token, job_id, [prediction()], now=NOW)
        with self.assertRaises(NotFoundError):
            self.workspace.complete_job(self.admin_token, job_id, [prediction()], now=NOW)

        two_record_job = self.workspace.create_job(
            self.admin_token,
            "c" * 64,
            2,
            now=NOW,
        )
        with self.assertRaisesRegex(ValueError, "exactly match"):
            self.workspace.complete_job(
                self.admin_token,
                two_record_job,
                [prediction()],
                now=NOW,
            )

    def test_worker_capability_progress_and_completion_are_atomic(self) -> None:
        analyst_token = self.create_user_and_login("worker-analyst", Role.ANALYST)
        job_id, capability = self.workspace.enqueue_classification_job(
            analyst_token,
            "e" * 64,
            2,
            "rules",
            now=NOW,
        )
        self.assertNotIn(capability.encode("ascii"), self.database_path.read_bytes())
        queued = self.workspace.get_job_status(analyst_token, job_id, now=NOW)
        self.assertEqual(queued["status"], "queued")
        self.assertEqual(queued["processed_records"], 0)

        claimed = self.workspace.claim_classification_job(
            capability,
            "worker-test",
            now=NOW,
        )
        self.assertEqual(claimed["id"], job_id)
        self.assertTrue(
            self.workspace.update_classification_progress(
                capability,
                1,
                now=NOW,
            )
        )
        for invalid in (0, 3):
            with self.subTest(processed=invalid):
                with self.assertRaises(ValueError):
                    self.workspace.update_classification_progress(
                        capability,
                        invalid,
                        now=NOW,
                    )

        completed_id = self.workspace.complete_classification_job(
            capability,
            "e" * 64,
            [prediction(), prediction()],
            now=NOW,
        )
        self.assertEqual(completed_id, job_id)
        completed = self.workspace.get_job(analyst_token, job_id, now=NOW)
        self.assertEqual(completed["status"], "succeeded")
        self.assertEqual(completed["processed_records"], 2)
        self.assertEqual(len(completed["results"]), 2)
        self.assertFalse(self.workspace.fail_classification_job(capability, "internal_error"))

    def test_cancellation_is_creator_scoped_and_wins_before_publication(self) -> None:
        creator_token = self.create_user_and_login("job-creator", Role.ANALYST)
        other_token = self.create_user_and_login("other-analyst", Role.ANALYST)
        job_id, capability = self.workspace.enqueue_classification_job(
            creator_token,
            "f" * 64,
            1,
            "rules",
            now=NOW,
        )
        self.workspace.claim_classification_job(capability, "worker-test", now=NOW)
        with self.assertRaises(AuthorizationError):
            self.workspace.request_job_cancellation(other_token, job_id, now=NOW)

        cancelling = self.workspace.request_job_cancellation(
            creator_token,
            job_id,
            now=NOW,
        )
        self.assertEqual(cancelling["status"], "cancelling")
        self.assertTrue(self.workspace.classification_cancel_requested(capability))
        with self.assertRaises(ConflictError):
            self.workspace.complete_classification_job(
                capability,
                "f" * 64,
                [prediction()],
                now=NOW,
            )
        self.assertTrue(
            self.workspace.fail_classification_job(capability, "cancelled", now=NOW)
        )
        cancelled = self.workspace.get_job(creator_token, job_id, now=NOW)
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertIsNone(cancelled["results"])

        queued_id, queued_capability = self.workspace.enqueue_classification_job(
            creator_token,
            "1" * 64,
            1,
            "rules",
            now=NOW,
        )
        queued_cancelled = self.workspace.request_job_cancellation(
            creator_token,
            queued_id,
            now=NOW,
        )
        self.assertEqual(queued_cancelled["status"], "cancelled")
        with self.assertRaises(NotFoundError):
            self.workspace.claim_classification_job(
                queued_capability,
                "worker-test",
                now=NOW,
            )

    def test_status_polling_is_read_only_and_recovery_is_fail_closed(self) -> None:
        job_id, capability = self.workspace.enqueue_classification_job(
            self.admin_token,
            "2" * 64,
            1,
            "rules",
            now=NOW,
        )
        audit_before = self.workspace.list_audit_events(self.admin_token, now=NOW)
        for _ in range(5):
            self.assertEqual(
                self.workspace.get_job_status(self.admin_token, job_id, now=NOW)[
                    "status"
                ],
                "queued",
            )
        self.assertEqual(
            self.workspace.list_audit_events(self.admin_token, now=NOW),
            audit_before,
        )

        future = NOW + timedelta(days=100)
        future_token = self.admin_token_at(future)
        self.assertEqual(
            self.workspace.purge_expired(future_token, now=future).jobs_removed,
            0,
        )
        self.workspace.claim_classification_job(capability, "worker-test", now=future)
        self.assertEqual(self.workspace.recover_incomplete_jobs(now=future), 1)
        recovered = self.workspace.get_job_status(future_token, job_id, now=future)
        self.assertEqual(recovered["status"], "failed")
        self.assertEqual(recovered["failure_code"], "interrupted")

    def test_raw_payload_and_digest_are_bounded(self) -> None:
        for invalid_digest in ("A" * 64, "0" * 63, "../not-a-digest"):
            with self.subTest(digest=invalid_digest):
                with self.assertRaises(ValueError):
                    self.workspace.create_job(
                        self.admin_token,
                        invalid_digest,
                        1,
                        now=NOW,
                    )
        excessive_payload = b"x" * 1_000_001
        with self.assertRaises(ValueError):
            self.workspace.create_job(
                self.admin_token,
                digest(excessive_payload),
                1,
                raw_payload=excessive_payload,
                now=NOW,
            )
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.workspace.create_job(
                self.admin_token,
                "d" * 64,
                1,
                raw_payload=b"different synthetic bytes",
                now=NOW,
            )

    def test_atomic_completed_store_enforces_digest_and_cardinality(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.workspace.store_completed_job(
                self.admin_token,
                "a" * 64,
                1,
                [prediction()],
                raw_payload=b"synthetic source",
                now=NOW,
            )
        with self.assertRaisesRegex(ValueError, "exactly match"):
            self.workspace.store_completed_job(
                self.admin_token,
                "b" * 64,
                2,
                [prediction()],
                now=NOW,
            )
        self.assertEqual(self.workspace.list_jobs(self.admin_token, now=NOW), [])

    def test_job_listing_supports_bounded_offset_pagination(self) -> None:
        job_ids = {
            self.workspace.store_completed_job(
                self.admin_token,
                f"{index:064x}",
                1,
                [prediction()],
                now=NOW,
            )
            for index in range(1, 4)
        }

        first_page = self.workspace.list_jobs(
            self.admin_token,
            limit=2,
            offset=0,
            now=NOW,
        )
        second_page = self.workspace.list_jobs(
            self.admin_token,
            limit=2,
            offset=2,
            now=NOW,
        )
        first_ids = {item["id"] for item in first_page}
        second_ids = {item["id"] for item in second_page}
        self.assertEqual(len(first_page), 2)
        self.assertEqual(len(second_page), 1)
        self.assertFalse(first_ids & second_ids)
        self.assertEqual(first_ids | second_ids, job_ids)

        for invalid_offset in (True, -1, 100_001):
            with self.subTest(offset=invalid_offset):
                with self.assertRaises(ValueError):
                    self.workspace.list_jobs(
                        self.admin_token,
                        offset=invalid_offset,
                        now=NOW,
                    )

    def test_retention_hides_at_boundary_then_purges_idempotently(self) -> None:
        self.workspace.set_retention_policy(
            self.admin_token,
            RetentionPolicy(raw_days=7, result_days=30, audit_days=180),
            now=NOW,
        )
        raw_payload = b"synthetic payload"
        job_id = self.workspace.create_job(
            self.admin_token,
            digest(raw_payload),
            1,
            raw_payload=raw_payload,
            now=NOW,
        )
        self.workspace.complete_job(self.admin_token, job_id, [prediction()], now=NOW)

        before_time = NOW + timedelta(days=7) - timedelta(microseconds=1)
        before = self.workspace.get_job(
            self.admin_token_at(before_time),
            job_id,
            include_raw=True,
            now=before_time,
        )
        self.assertEqual(before["raw_payload"], b"synthetic payload")
        raw_boundary = NOW + timedelta(days=7)
        at_raw_boundary = self.workspace.get_job(
            self.admin_token_at(raw_boundary),
            job_id,
            include_raw=True,
            now=raw_boundary,
        )
        self.assertIsNone(at_raw_boundary["raw_payload"])
        self.assertEqual(at_raw_boundary["results"], [prediction()])

        result_boundary = NOW + timedelta(days=30)
        result_boundary_token = self.admin_token_at(result_boundary)
        with self.assertRaises(NotFoundError):
            self.workspace.get_job(
                result_boundary_token,
                job_id,
                include_raw=True,
                now=result_boundary,
            )
        self.assertEqual(
            self.workspace.list_jobs(
                result_boundary_token,
                now=result_boundary,
            ),
            [],
        )

        purged = self.workspace.purge_expired(
            result_boundary_token,
            now=result_boundary,
        )
        self.assertEqual(purged.raw_payloads_removed, 1)
        self.assertEqual(purged.jobs_removed, 1)
        self.assertGreaterEqual(purged.sessions_removed, 1)
        second = self.workspace.purge_expired(
            result_boundary_token,
            now=result_boundary,
        )
        self.assertEqual(second.raw_payloads_removed, 0)
        self.assertEqual(second.jobs_removed, 0)

    def test_retention_change_is_not_retroactive(self) -> None:
        raw_payload = b"synthetic payload"
        job_id = self.workspace.create_job(
            self.admin_token,
            digest(raw_payload),
            1,
            raw_payload=raw_payload,
            now=NOW,
        )
        policy_time = NOW + timedelta(days=1)
        self.workspace.set_retention_policy(
            self.admin_token_at(policy_time),
            RetentionPolicy(raw_days=7, result_days=7, audit_days=180),
            now=policy_time,
        )
        inspection_time = NOW + timedelta(days=8)
        job = self.workspace.get_job(
            self.admin_token_at(inspection_time),
            job_id,
            include_raw=True,
            now=inspection_time,
        )
        self.assertEqual(job["raw_payload"], b"synthetic payload")

    def test_audit_is_privacy_minimal_and_records_sensitive_actions(self) -> None:
        raw_payload = b"private synthetic message"
        job_id = self.workspace.create_job(
            self.admin_token,
            digest(raw_payload),
            1,
            raw_payload=raw_payload,
            now=NOW,
        )
        self.workspace.complete_job(self.admin_token, job_id, [prediction()], now=NOW)
        self.workspace.get_job(self.admin_token, job_id, include_raw=True, now=NOW)

        events = self.workspace.list_audit_events(self.admin_token, now=NOW)
        actions = {event["action"] for event in events}
        self.assertTrue(
            {"workspace.bootstrap", "auth.login", "job.create", "job.complete", "job.export"}
            <= actions
        )
        encoded_events = repr(events)
        self.assertNotIn("private synthetic message", encoded_events)
        self.assertNotIn(self.admin_token, encoded_events)
        self.assertNotIn(PASSWORD, encoded_events)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_initialize_rejects_database_symlink(self) -> None:
        target = Path(self.temporary_directory.name) / "other.sqlite3"
        target.touch()
        alias = Path(self.temporary_directory.name) / "alias.sqlite3"
        alias.symlink_to(target)
        with self.assertRaisesRegex(OSError, "symlink"):
            Workspace(alias).initialize()

        workspace_alias = Path(self.temporary_directory.name) / "workspace-alias.sqlite3"
        workspace_alias.symlink_to(self.database_path)
        with self.assertRaisesRegex(OSError, "symlink"):
            Workspace(workspace_alias).login("sample-org", "owner", PASSWORD, now=NOW)

    @unittest.skipUnless(hasattr(os, "link"), "hard links are unavailable")
    def test_every_database_open_rejects_hard_link_aliases(self) -> None:
        alias = Path(self.temporary_directory.name) / "workspace-alias.sqlite3"
        os.link(self.database_path, alias)

        with self.assertRaisesRegex(OSError, "exactly one hard link"):
            Workspace(alias).initialize(create=False)
        with self.assertRaisesRegex(OSError, "exactly one hard link"):
            self.workspace.principal(self.admin_token, now=NOW)

    def test_login_typo_does_not_create_a_database(self) -> None:
        typo = Path(self.temporary_directory.name) / "typo.sqlite3"
        with self.assertRaises(FileNotFoundError):
            Workspace(typo).login("sample-org", "owner", PASSWORD, now=NOW)
        self.assertFalse(typo.exists())

    def test_initialize_rejects_unknown_future_schema(self) -> None:
        future_database = Path(self.temporary_directory.name) / "future.sqlite3"
        with closing(sqlite3.connect(future_database)) as connection:
            with connection:
                connection.execute(
                    "CREATE TABLE workspace_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO workspace_metadata VALUES ('schema_version', '999')"
                )
        future_database.chmod(0o600)
        bytes_before = future_database.read_bytes()
        with closing(sqlite3.connect(future_database)) as connection:
            before = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            ).fetchall()
        with self.assertRaisesRegex(RuntimeError, "unsupported workspace schema"):
            Workspace(future_database).initialize()
        with closing(sqlite3.connect(future_database)) as connection:
            after = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            ).fetchall()
        self.assertEqual(after, before)
        self.assertEqual(future_database.read_bytes(), bytes_before)

    def test_initialize_migrates_v1_and_fails_old_pending_jobs(self) -> None:
        legacy_database = Path(self.temporary_directory.name) / "legacy.sqlite3"
        with (
            closing(sqlite3.connect(self.database_path)) as source,
            closing(sqlite3.connect(legacy_database)) as destination,
        ):
            source.backup(destination)
        with closing(sqlite3.connect(legacy_database)) as connection:
            with connection:
                connection.execute("DROP TABLE jobs")
                connection.executescript(
                    """
                    CREATE TABLE jobs (
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
                    CREATE INDEX jobs_organization_created
                        ON jobs (organization_id, created_at DESC);
                    UPDATE workspace_metadata SET value = '1'
                        WHERE key = 'schema_version';
                    """
                )
                connection.execute(
                    """INSERT INTO jobs
                       (id, organization_id, created_by, status, source_sha256,
                        input_records, raw_expires_at, results_expires_at, created_at)
                       VALUES (?, ?, ?, 'pending', ?, 1, ?, ?, ?)""",
                    (
                        "legacy-pending",
                        self.organization_id,
                        self.admin_id,
                        "3" * 64,
                        (NOW + timedelta(days=30)).isoformat(timespec="microseconds"),
                        (NOW + timedelta(days=90)).isoformat(timespec="microseconds"),
                        NOW.isoformat(timespec="microseconds"),
                    ),
                )
        legacy_database.chmod(0o600)

        migrated = Workspace(legacy_database)
        migrated.initialize()
        migrated.verify()
        token, _ = migrated.login("sample-org", "owner", PASSWORD, now=NOW)
        job = migrated.get_job(token, "legacy-pending", now=NOW)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["failure_code"], "interrupted")
        with closing(sqlite3.connect(legacy_database)) as connection:
            version = connection.execute(
                "SELECT value FROM workspace_metadata WHERE key = 'schema_version'"
            ).fetchone()[0]
        self.assertEqual(version, "2")

    def test_initialize_rejects_unrelated_non_empty_database(self) -> None:
        unrelated = Path(self.temporary_directory.name) / "unrelated.sqlite3"
        with closing(sqlite3.connect(unrelated)) as connection:
            with connection:
                connection.execute("CREATE TABLE unrelated (value TEXT)")
        unrelated.chmod(0o600)
        bytes_before = unrelated.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "non-empty database"):
            Workspace(unrelated).initialize()
        with closing(sqlite3.connect(unrelated)) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            ).fetchall()
        self.assertEqual(tables, [("unrelated",)])
        self.assertEqual(unrelated.read_bytes(), bytes_before)


class RetentionPolicyValidationTests(unittest.TestCase):
    def test_policy_rejects_bool_zero_and_excessive_values(self) -> None:
        for value in (True, 0, -1, 3651, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    RetentionPolicy(raw_days=value)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
