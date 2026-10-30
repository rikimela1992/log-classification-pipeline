from __future__ import annotations

import asyncio
import hashlib
import io
import json
import re
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

try:
    import fastapi  # noqa: F401
except ModuleNotFoundError as exc:
    if exc.name != "fastapi":
        raise
    TestClient = None  # type: ignore[assignment,misc]
    WEB_AVAILABLE = False
else:
    from fastapi.testclient import TestClient

    from log_classification_pipeline.web import WebSettings, create_app
    from log_classification_pipeline.web.app import RequestSizeLimitMiddleware
    from log_classification_pipeline.web.i18n import (
        load_catalogs,
        negotiate_locale,
        translator,
    )
    from log_classification_pipeline.web.rate_limit import LoginRateLimiter
    from log_classification_pipeline.web.worker import (
        LocalClassificationQueue,
        WorkerUnavailableError,
    )

    WEB_AVAILABLE = True

from log_classification_pipeline.adapters import RulesPredictor
from log_classification_pipeline.adapters.zero_shot import ZeroShotPredictor
from log_classification_pipeline.cli import main
from log_classification_pipeline.model_profiles import MULTILINGUAL_PROFILE_ID
from log_classification_pipeline.workspace import AuthenticationError, Role, Workspace

PASSWORD = "correct-horse-battery-staple"


class MarkupPredictor:
    def __call__(self, records):
        predictions = RulesPredictor()(records)
        for prediction in predictions:
            prediction["model"]["id"] = "<script>alert('synthetic')</script>"
        return predictions


class ExplodingPredictor:
    def __call__(self, _records):
        raise TypeError("synthetic internal detail that must not escape")


class BlockingPredictor:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def __call__(self, records):
        self.calls += 1
        self.started.set()
        if not self.release.wait(5.0):
            raise RuntimeError("synthetic blocking predictor timed out")
        return RulesPredictor()(records)


@unittest.skipUnless(WEB_AVAILABLE, "web extra is not installed")
class WebApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self.temporary_directory.name)
        self.database = root / "workspace.sqlite3"
        self.workspace = Workspace(self.database)
        self.workspace.bootstrap("sample-org", "owner", PASSWORD)
        admin_token, _ = self.workspace.login("sample-org", "owner", PASSWORD)
        self.workspace.create_user(
            admin_token,
            "analyst",
            "analyst-password-value",
            Role.ANALYST,
        )
        self.workspace.create_user(
            admin_token,
            "reviewer",
            "viewer-password-value",
            Role.VIEWER,
        )
        self.workspace.logout(admin_token)
        self.predictor = RulesPredictor()
        self.rules_call_patch = mock.patch.object(
            RulesPredictor,
            "__call__",
            autospec=True,
            side_effect=RulesPredictor.__call__,
        )
        self.rules_call_mock = self.rules_call_patch.start()
        self.app = create_app(
            WebSettings(
                self.database,
                allowed_hosts=("testserver",),
                max_input_bytes=1_000,
                max_records=10,
                max_request_bytes=4_096,
            ),
            {"rules": self.predictor},
        )
        self.client = TestClient(
            self.app,
            base_url="http://testserver",
            raise_server_exceptions=False,
        )
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.rules_call_patch.stop()
        self.temporary_directory.cleanup()

    def wait_for_job(self, job_id: str, token: str) -> dict[str, object]:
        self.assertTrue(self.app.state.job_queue.wait_until_idle(5.0))
        response = self.client.get(
            f"/api/v1/jobs/{job_id}/status",
            headers=self.bearer(token),
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def api_login(self, username: str, password: str) -> str:
        response = self.client.post(
            "/api/v1/sessions",
            json={
                "organization": "sample-org",
                "username": username,
                "password": password,
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["access_token"]

    @staticmethod
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def ui_login(self, username: str = "owner", password: str = PASSWORD) -> None:
        login_page = self.client.get("/app/login")
        self.assertEqual(login_page.status_code, 200)
        csrf_cookie = self.client.cookies.get("lcp_login_csrf")
        self.assertIsNotNone(csrf_cookie)
        match = re.search(r'name="csrf" value="([^"]+)"', login_page.text)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), csrf_cookie)
        response = self.client.post(
            "/app/login",
            data={
                "organization": "sample-org",
                "username": username,
                "password": password,
                "csrf": csrf_cookie,
            },
            headers={
                "Origin": "http://testserver",
                "X-CSRF-Token": csrf_cookie,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303, response.text)
        self.assertIsNotNone(self.client.cookies.get("lcp_session"))

    def csrf_header(self) -> dict[str, str]:
        dashboard = self.client.get("/app")
        self.assertEqual(dashboard.status_code, 200, dashboard.text)
        match = re.search(r'<meta name="csrf-token" content="([^"]+)"', dashboard.text)
        self.assertIsNotNone(match)
        return {
            "Origin": "http://testserver",
            "X-CSRF-Token": match.group(1),
        }

    def test_security_headers_trusted_host_and_no_cors(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"maturity": "alpha", "status": "ok"})
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertNotIn("strict-transport-security", response.headers)
        self.assertNotIn("access-control-allow-origin", response.headers)

        hostile = self.client.get("/health", headers={"Host": "hostile.invalid"})
        self.assertEqual(hostile.status_code, 400)
        self.assertIn("x-content-type-options", hostile.headers)

    def test_web_startup_does_not_create_a_missing_workspace(self) -> None:
        missing_parent = Path(self.temporary_directory.name) / "missing-parent"
        missing_database = missing_parent / "workspace.sqlite3"
        with self.assertRaises(FileNotFoundError):
            create_app(
                WebSettings(missing_database, allowed_hosts=("testserver",)),
                {"rules": RulesPredictor()},
            )
        self.assertFalse(missing_parent.exists())

        with self.assertRaisesRegex(ValueError, "matching zero-shot predictor"):
            create_app(
                WebSettings(self.database, allowed_hosts=("testserver",)),
                {MULTILINGUAL_PROFILE_ID: RulesPredictor()},
            )
        with self.assertRaisesRegex(ValueError, "canonical rules identity"):
            create_app(
                WebSettings(self.database, allowed_hosts=("testserver",)),
                {"rules": ExplodingPredictor()},
            )

    def test_catalogs_negotiate_language_and_fallback_without_api_drift(self) -> None:
        catalogs = load_catalogs()
        self.assertEqual(set(catalogs), {"en", "it", "fr", "es"})
        self.assertEqual(negotiate_locale(None, "fr-CA,fr;q=0.9,en;q=0.8"), "fr")
        self.assertEqual(negotiate_locale("it", "es"), "it")
        self.assertEqual(negotiate_locale(None, "de,*;q=0.5"), "en")
        self.assertEqual(
            negotiate_locale(None, "x" * 1025),
            "en",
        )
        self.assertIn("40", translator(catalogs, "es")("jobs.shown", count=40))

        page = self.client.get(
            "/app/login",
            headers={"Accept-Language": "it-IT,it;q=0.9"},
        )
        self.assertEqual(page.headers["content-language"], "it")
        self.assertIn("Accept-Language", page.headers["vary"])
        self.assertIn("Cookie", page.headers["vary"])
        self.assertIn('<html lang="it">', page.text)
        self.assertIn("Accedi", page.text)
        self.assertIn("Troppi tentativi di accesso", page.text)

        api = self.client.post(
            "/api/v1/sessions",
            headers={"Accept-Language": "it"},
            json={"organization": "x", "username": "x", "password": "x"},
        )
        self.assertEqual(api.status_code, 422)
        self.assertEqual(api.headers["content-type"], "application/problem+json")
        self.assertEqual(api.json()["code"], "invalid_request")

    def test_locale_cookie_change_is_csrf_protected_and_bounded(self) -> None:
        self.client.get("/app/login")
        csrf = self.client.cookies.get("lcp_login_csrf")
        self.assertIsNotNone(csrf)

        denied = self.client.post(
            "/app/locale",
            data={"locale": "fr", "target": "login"},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        self.assertEqual(denied.status_code, 403)

        changed = self.client.post(
            "/app/locale",
            data={"locale": "fr", "target": "outside"},
            headers={
                "Origin": "http://testserver",
                "X-CSRF-Token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(changed.status_code, 303)
        self.assertEqual(changed.headers["location"], "/app/login")
        locale_cookie = next(
            value
            for value in changed.headers.get_list("set-cookie")
            if "lcp_locale=" in value
        )
        self.assertIn("HttpOnly", locale_cookie)
        self.assertIn("SameSite=strict", locale_cookie)

        selected = self.client.get(
            "/app/login",
            headers={"Accept-Language": "es"},
        )
        self.assertEqual(selected.headers["content-language"], "fr")
        self.assertIn('<html lang="fr">', selected.text)

    def test_api_bearer_authentication_and_ambiguous_cookie_are_rejected(self) -> None:
        missing = self.client.get("/api/v1/jobs")
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(missing.headers["www-authenticate"], "Bearer")

        token = self.api_login("owner", PASSWORD)
        me = self.client.get("/api/v1/me", headers=self.bearer(token))
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["role"], "admin")

        self.client.cookies.set("lcp_session", "synthetic-cookie-value")
        ambiguous = self.client.get("/api/v1/me", headers=self.bearer(token))
        self.assertEqual(ambiguous.status_code, 400)
        self.assertEqual(ambiguous.json()["code"], "ambiguous_authentication")

    def test_api_logout_revokes_the_server_side_session(self) -> None:
        token = self.api_login("owner", PASSWORD)
        logged_out = self.client.delete(
            "/api/v1/session",
            headers=self.bearer(token),
        )
        self.assertEqual(logged_out.status_code, 204, logged_out.text)

        denied = self.client.get("/api/v1/me", headers=self.bearer(token))
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(denied.json()["code"], "not_authenticated")

    def test_api_and_ui_login_failures_are_bounded_without_echoing_identity(self) -> None:
        limiter = self.app.state.login_rate_limiter
        limiter._account_limit = 2
        limiter._source_limit = 10
        with mock.patch.object(
            self.app.state.workspace,
            "login",
            side_effect=AuthenticationError("synthetic failure"),
        ) as login:
            first = self.client.post(
                "/api/v1/sessions",
                json={
                    "organization": "sample-org",
                    "username": "owner",
                    "password": "synthetic-wrong-password",
                },
            )
            self.assertEqual(first.status_code, 401, first.text)

            limited = self.client.post(
                "/api/v1/sessions",
                json={
                    "organization": "sample-org",
                    "username": "owner",
                    "password": "synthetic-wrong-password",
                },
            )
            self.assertEqual(limited.status_code, 429, limited.text)
            self.assertEqual(limited.json()["code"], "login_rate_limited")
            self.assertGreaterEqual(int(limited.headers["retry-after"]), 1)
            self.assertNotIn("owner", limited.text)
            self.assertNotIn("synthetic-wrong-password", limited.text)

            still_limited = self.client.post(
                "/api/v1/sessions",
                json={
                    "organization": "sample-org",
                    "username": "owner",
                    "password": PASSWORD,
                },
            )
            self.assertEqual(still_limited.status_code, 429)
            self.assertEqual(login.call_count, 2)

            self.client.get(
                "/app/login",
                headers={"Accept-Language": "it"},
            )
            csrf = self.client.cookies.get("lcp_login_csrf")
            self.assertIsNotNone(csrf)
            for expected_status in (401, 429):
                response = self.client.post(
                    "/app/login",
                    data={
                        "organization": "sample-org",
                        "username": "analyst",
                        "password": "synthetic-wrong-password",
                        "csrf": csrf,
                    },
                    headers={
                        "Origin": "http://testserver",
                        "X-CSRF-Token": csrf,
                    },
                    follow_redirects=False,
                )
                self.assertEqual(response.status_code, expected_status, response.text)
            self.assertEqual(response.json()["code"], "login_rate_limited")
            self.assertEqual(login.call_count, 4)

    def test_model_catalog_is_authenticated_lazy_and_safe_ordered(self) -> None:
        unauthenticated = self.client.get("/api/v1/models")
        self.assertEqual(unauthenticated.status_code, 401)

        viewer_token = self.api_login("reviewer", "viewer-password-value")
        response = self.client.get(
            "/api/v1/models",
            headers=self.bearer(viewer_token),
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["default_model"], "rules")
        self.assertEqual(response.json()["items"][0]["id"], "rules")
        self.assertEqual(response.json()["items"][0]["languages"], ["en"])
        self.assertEqual(self.rules_call_mock.call_count, 0)

        self.ui_login()
        page = self.client.get("/app", headers={"Accept-Language": "it"})
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn(
            '<option value="rules">Baseline a regole — scelta sicura</option>',
            page.text,
        )
        self.assertIn("non carica artefatti", page.text)

    def test_viewer_is_denied_before_predictor_and_analyst_can_classify(self) -> None:
        viewer_token = self.api_login("reviewer", "viewer-password-value")
        denied = self.client.post(
            "/api/v1/classifications",
            headers=self.bearer(viewer_token),
            json={"records": [{"message": "Authentication failed"}]},
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.rules_call_mock.call_count, 0)

        analyst_token = self.api_login("analyst", "analyst-password-value")
        created = self.client.post(
            "/api/v1/classifications",
            headers=self.bearer(analyst_token),
            json={"records": [{"message": "Authentication failed"}]},
        )
        self.assertEqual(created.status_code, 202, created.text)
        job_id = created.json()["job_id"]
        self.assertEqual(created.headers["location"], created.json()["job_url"])
        self.assertEqual(self.wait_for_job(job_id, analyst_token)["status"], "succeeded")
        self.assertEqual(self.rules_call_mock.call_count, 1)

        stored = self.client.get(
            f"/api/v1/jobs/{job_id}",
            headers=self.bearer(analyst_token),
        )
        self.assertEqual(stored.status_code, 200)
        self.assertEqual(stored.json()["input_records"], 1)
        self.assertEqual(stored.json()["output_records"], 1)
        self.assertNotIn("message", json.dumps(stored.json()["results"]))

        exported = self.client.get(
            f"/api/v1/jobs/{job_id}/export",
            headers=self.bearer(analyst_token),
        )
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.headers["content-type"], "application/x-ndjson")
        exported_record = json.loads(exported.text)
        self.assertNotIn("message", exported_record)
        self.assertNotIn("Authentication failed", exported.text)

        admin_denied = self.client.get(
            "/api/v1/admin/users",
            headers=self.bearer(analyst_token),
        )
        self.assertEqual(admin_denied.status_code, 403)

    def test_async_job_returns_before_prediction_and_cancels_fail_closed(self) -> None:
        self.app.state.job_queue.close()
        predictor = BlockingPredictor()
        asynchronous_app = create_app(
            WebSettings(
                self.database,
                allowed_hosts=("testserver",),
                max_input_bytes=1_000,
                max_records=10,
                max_request_bytes=4_096,
                max_admitted_jobs=2,
                worker_batch_size=1,
            ),
            {"slow": predictor},
        )
        with TestClient(
            asynchronous_app,
            base_url="http://testserver",
            raise_server_exceptions=False,
        ) as client:
            session = client.post(
                "/api/v1/sessions",
                json={
                    "organization": "sample-org",
                    "username": "analyst",
                    "password": "analyst-password-value",
                },
            )
            token = session.json()["access_token"]
            created = client.post(
                "/api/v1/classifications",
                headers=self.bearer(token),
                json={"model": "slow", "records": [{"message": "Synthetic wait"}]},
            )
            self.assertEqual(created.status_code, 202, created.text)
            self.assertTrue(predictor.started.wait(1.0))
            job_id = created.json()["job_id"]
            running = client.get(
                created.json()["status_url"],
                headers=self.bearer(token),
            )
            self.assertEqual(running.json()["status"], "running")
            self.assertEqual(running.json()["processed_records"], 0)

            logged_out = client.delete(
                "/api/v1/session",
                headers=self.bearer(token),
            )
            self.assertEqual(logged_out.status_code, 204)
            admin_session = client.post(
                "/api/v1/sessions",
                json={
                    "organization": "sample-org",
                    "username": "owner",
                    "password": PASSWORD,
                },
            )
            admin_token = admin_session.json()["access_token"]

            cancelling = client.post(
                f"/api/v1/jobs/{job_id}/cancel",
                headers=self.bearer(admin_token),
            )
            self.assertEqual(cancelling.status_code, 200, cancelling.text)
            self.assertEqual(cancelling.json()["status"], "cancelling")
            predictor.release.set()
            self.assertTrue(asynchronous_app.state.job_queue.wait_until_idle(5.0))

            terminal = client.get(
                created.json()["status_url"],
                headers=self.bearer(admin_token),
            )
            self.assertEqual(terminal.json()["status"], "cancelled")
            self.assertEqual(terminal.json()["failure_code"], "cancelled")
            exported = client.get(
                f"/api/v1/jobs/{job_id}/export",
                headers=self.bearer(admin_token),
            )
            self.assertEqual(exported.status_code, 409)
            self.assertNotIn(b"Synthetic wait", self.database.read_bytes())

    def test_bounded_queue_rejects_excess_without_orphan_job(self) -> None:
        self.app.state.job_queue.close()
        predictor = BlockingPredictor()
        bounded_app = create_app(
            WebSettings(
                self.database,
                allowed_hosts=("testserver",),
                max_input_bytes=1_000,
                max_records=10,
                max_request_bytes=4_096,
                max_admitted_jobs=1,
                worker_batch_size=1,
            ),
            {"slow": predictor},
        )
        with TestClient(
            bounded_app,
            base_url="http://testserver",
            raise_server_exceptions=False,
        ) as client:
            session = client.post(
                "/api/v1/sessions",
                json={
                    "organization": "sample-org",
                    "username": "analyst",
                    "password": "analyst-password-value",
                },
            )
            token = session.json()["access_token"]
            first = client.post(
                "/api/v1/classifications",
                headers=self.bearer(token),
                json={"model": "slow", "records": [{"message": "First synthetic"}]},
            )
            self.assertEqual(first.status_code, 202, first.text)
            self.assertTrue(predictor.started.wait(1.0))
            rejected = client.post(
                "/api/v1/classifications",
                headers=self.bearer(token),
                json={"model": "slow", "records": [{"message": "Second synthetic"}]},
            )
            self.assertEqual(rejected.status_code, 503, rejected.text)
            self.assertEqual(rejected.json()["code"], "queue_full")
            jobs = client.get("/api/v1/jobs", headers=self.bearer(token))
            self.assertEqual(len(jobs.json()["items"]), 1)

            competing_app = create_app(
                WebSettings(
                    self.database,
                    allowed_hosts=("testserver",),
                    max_input_bytes=1_000,
                    max_records=10,
                    max_request_bytes=4_096,
                ),
                {"slow": RulesPredictor()},
            )
            competing_client = TestClient(
                competing_app,
                base_url="http://testserver",
                raise_server_exceptions=False,
            )
            try:
                competing = competing_client.post(
                    "/api/v1/classifications",
                    headers=self.bearer(token),
                    json={
                        "model": "slow",
                        "records": [{"message": "Third synthetic"}],
                    },
                )
                self.assertEqual(competing.status_code, 503, competing.text)
                self.assertEqual(competing.json()["code"], "worker_unavailable")
            finally:
                competing_app.state.job_queue.close()
                competing_client.close()

            predictor.release.set()
            self.assertTrue(bounded_app.state.job_queue.wait_until_idle(5.0))

    def test_worker_releases_process_lock_after_late_thread_exit(self) -> None:
        self.app.state.job_queue.close()
        predictor = BlockingPredictor()
        worker = LocalClassificationQueue(
            self.workspace,
            {"slow": predictor},
            max_admitted_jobs=1,
            batch_size=1,
        )
        token, _ = self.workspace.login(
            "sample-org",
            "analyst",
            "analyst-password-value",
        )
        payload = b'{"message":"Synthetic delayed shutdown"}\n'
        worker.submit(
            token,
            "slow",
            payload,
            hashlib.sha256(payload).hexdigest(),
            1,
        )
        self.assertTrue(predictor.started.wait(1.0))

        worker.close(timeout=0.01)
        self.assertIsNotNone(worker._thread)
        self.assertTrue(worker._thread.is_alive())
        predictor.release.set()
        worker._thread.join(5.0)
        self.assertFalse(worker._thread.is_alive())
        self.assertIsNone(worker._lock_descriptor)

        replacement = LocalClassificationQueue(
            self.workspace,
            {"rules": RulesPredictor()},
        )
        replacement.start()
        replacement.close()

    def test_submit_and_close_are_serialized_without_stranded_job(self) -> None:
        self.app.state.job_queue.close()
        predictor = BlockingPredictor()
        worker = LocalClassificationQueue(
            self.workspace,
            {"slow": predictor},
            max_admitted_jobs=1,
            batch_size=1,
        )
        token, _ = self.workspace.login(
            "sample-org",
            "analyst",
            "analyst-password-value",
        )
        payload = b'{"message":"Synthetic submit close race"}\n'
        entered_enqueue = threading.Event()
        allow_enqueue = threading.Event()
        submit_result: list[str] = []
        errors: list[BaseException] = []
        original_enqueue = self.workspace.enqueue_classification_job

        def delayed_enqueue(*args, **kwargs):
            entered_enqueue.set()
            if not allow_enqueue.wait(2.0):
                raise RuntimeError("test did not release enqueue")
            return original_enqueue(*args, **kwargs)

        def submit() -> None:
            try:
                submit_result.append(
                    worker.submit(
                        token,
                        "slow",
                        payload,
                        hashlib.sha256(payload).hexdigest(),
                        1,
                    )
                )
            except BaseException as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        close_started = threading.Event()

        def close() -> None:
            close_started.set()
            worker.close()

        with mock.patch.object(
            self.workspace,
            "enqueue_classification_job",
            side_effect=delayed_enqueue,
        ):
            submit_thread = threading.Thread(target=submit)
            submit_thread.start()
            self.assertTrue(entered_enqueue.wait(1.0))
            close_thread = threading.Thread(target=close)
            close_thread.start()
            self.assertTrue(close_started.wait(1.0))
            self.assertTrue(close_thread.is_alive())
            allow_enqueue.set()
            submit_thread.join(5.0)

        predictor.release.set()
        close_thread.join(5.0)
        self.assertFalse(submit_thread.is_alive())
        self.assertFalse(close_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(submit_result), 1)
        terminal = self.workspace.get_job_status(token, submit_result[0])
        self.assertEqual(terminal["status"], "failed")
        self.assertEqual(terminal["failure_code"], "interrupted")
        self.assertTrue(worker.wait_until_idle(1.0))

        with self.assertRaises(WorkerUnavailableError):
            worker.submit(
                token,
                "slow",
                payload,
                hashlib.sha256(payload).hexdigest(),
                1,
            )

    def test_file_upload_is_bounded_and_ignores_hostile_filename(self) -> None:
        token = self.api_login("analyst", "analyst-password-value")
        accepted = self.client.post(
            "/api/v1/classifications/file",
            headers=self.bearer(token),
            data={"model": "rules"},
            files={
                "upload": (
                    "../../synthetic.jsonl",
                    b'{"message":"Backup completed"}\n',
                    "application/octet-stream",
                )
            },
        )
        self.assertEqual(accepted.status_code, 202, accepted.text)
        self.assertEqual(
            self.wait_for_job(accepted.json()["job_id"], token)["status"],
            "succeeded",
        )

        oversized = self.client.post(
            "/api/v1/classifications/file",
            headers=self.bearer(token),
            files={"upload": ("input.jsonl", b"x" * 1_001, "application/x-ndjson")},
        )
        self.assertEqual(oversized.status_code, 413, oversized.text)

    def test_file_upload_accepts_text_log_and_csv_but_rejects_unknown_suffix(self) -> None:
        token = self.api_login("analyst", "analyst-password-value")
        fixtures = (
            ("synthetic.txt", b"Backup completed\nAuthentication failed\n"),
            ("synthetic.log", b"Service started\r\n"),
            (
                "synthetic.csv",
                b'message,component\r\n"Backup completed",worker\r\n',
            ),
        )
        for filename, payload in fixtures:
            with self.subTest(filename=filename):
                accepted = self.client.post(
                    "/api/v1/classifications/file",
                    headers=self.bearer(token),
                    data={"model": "rules"},
                    files={"upload": (filename, payload, "application/octet-stream")},
                )
                self.assertEqual(accepted.status_code, 202, accepted.text)
                self.assertEqual(
                    self.wait_for_job(accepted.json()["job_id"], token)["status"],
                    "succeeded",
                )

        before = self.client.get("/api/v1/jobs", headers=self.bearer(token)).json()
        rejected = self.client.post(
            "/api/v1/classifications/file",
            headers=self.bearer(token),
            files={"upload": ("synthetic.exe", b"synthetic event\n")},
        )
        self.assertEqual(rejected.status_code, 422, rejected.text)
        after = self.client.get("/api/v1/jobs", headers=self.bearer(token)).json()
        self.assertEqual(len(after["items"]), len(before["items"]))

    def test_aggregate_queue_byte_limit_rejects_without_orphan_job(self) -> None:
        self.app.state.job_queue.close()
        predictor = BlockingPredictor()
        bounded_app = create_app(
            WebSettings(
                self.database,
                allowed_hosts=("testserver",),
                max_input_bytes=1_000,
                max_records=10,
                max_request_bytes=4_096,
                max_admitted_jobs=8,
                max_admitted_bytes=1_000,
                worker_batch_size=1,
            ),
            {"slow": predictor},
        )
        with TestClient(
            bounded_app,
            base_url="http://testserver",
            raise_server_exceptions=False,
        ) as client:
            session = client.post(
                "/api/v1/sessions",
                json={
                    "organization": "sample-org",
                    "username": "analyst",
                    "password": "analyst-password-value",
                },
            )
            token = session.json()["access_token"]
            first_payload = (b"a" * 600) + b"\n"
            first = client.post(
                "/api/v1/classifications/file",
                headers=self.bearer(token),
                data={"model": "slow"},
                files={"upload": ("first.txt", first_payload)},
            )
            self.assertEqual(first.status_code, 202, first.text)
            self.assertTrue(predictor.started.wait(1.0))

            second = client.post(
                "/api/v1/classifications/file",
                headers=self.bearer(token),
                data={"model": "slow"},
                files={"upload": ("second.log", (b"b" * 600) + b"\n")},
            )
            self.assertEqual(second.status_code, 503, second.text)
            self.assertEqual(second.json()["code"], "queue_full")
            jobs = client.get("/api/v1/jobs", headers=self.bearer(token))
            self.assertEqual(len(jobs.json()["items"]), 1)
            predictor.release.set()
            self.assertTrue(bounded_app.state.job_queue.wait_until_idle(5.0))

    def test_unknown_model_is_sanitized_and_openapi_excludes_ui_routes(self) -> None:
        token = self.api_login("analyst", "analyst-password-value")
        rejected = self.client.post(
            "/api/v1/classifications",
            headers=self.bearer(token),
            json={
                "model": "not-configured",
                "records": [{"message": "Synthetic event"}],
            },
        )
        self.assertEqual(rejected.status_code, 422)
        self.assertEqual(rejected.json()["detail"], "Request is invalid.")
        self.assertNotIn("not-configured", rejected.text)

        schema = self.client.get("/api/v1/openapi.json")
        self.assertEqual(schema.status_code, 200, schema.text)
        paths = schema.json()["paths"]
        self.assertIn("/api/v1/classifications", paths)
        self.assertIn(
            "202",
            paths["/api/v1/classifications"]["post"]["responses"],
        )
        self.assertIn("/api/v1/jobs/{job_id}/status", paths)
        self.assertIn("/api/v1/jobs/{job_id}/cancel", paths)
        self.assertIn("/api/v1/models", paths)
        self.assertTrue(all(not path.startswith("/app") for path in paths))

    def test_database_failure_during_authentication_returns_sanitized_503(self) -> None:
        token = self.api_login("analyst", "analyst-password-value")
        self.database.write_bytes(b"synthetic non-sqlite bytes")

        response = self.client.get("/api/v1/jobs", headers=self.bearer(token))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["code"], "workspace_unavailable")
        self.assertEqual(response.headers["retry-after"], "1")
        self.assertNotIn(str(self.database), response.text)
        self.assertNotIn("Traceback", response.text)

    def test_job_pagination_and_unavailable_export_are_explicit(self) -> None:
        token = self.api_login("owner", PASSWORD)
        for index in range(1, 4):
            self.workspace.store_completed_job(
                token,
                f"{index:064x}",
                1,
                [RulesPredictor()([{"message": "Backup completed"}])[0]],
            )

        first = self.client.get(
            "/api/v1/jobs?limit=2",
            headers=self.bearer(token),
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(len(first.json()["items"]), 2)
        self.assertEqual(first.json()["next_offset"], 2)
        second = self.client.get(
            "/api/v1/jobs?limit=2&offset=2",
            headers=self.bearer(token),
        )
        self.assertEqual(len(second.json()["items"]), 1)
        self.assertIsNone(second.json()["next_offset"])

        pending_id = self.workspace.create_job(token, "f" * 64, 1)
        unavailable = self.client.get(
            f"/api/v1/jobs/{pending_id}/export",
            headers=self.bearer(token),
        )
        self.assertEqual(unavailable.status_code, 409)
        self.assertEqual(unavailable.json()["code"], "conflict")

    def test_ui_cookie_login_origin_csrf_and_classification_flow(self) -> None:
        page = self.client.get("/app/login")
        set_cookie = page.headers.get_list("set-cookie")
        login_cookie = next(item for item in set_cookie if "lcp_login_csrf=" in item)
        self.assertIn("HttpOnly", login_cookie)
        self.assertIn("SameSite=strict", login_cookie)
        self.assertNotIn("Secure", login_cookie)

        csrf = self.client.cookies.get("lcp_login_csrf")
        denied_origin = self.client.post(
            "/app/login",
            data={
                "organization": "sample-org",
                "username": "owner",
                "password": PASSWORD,
                "csrf": csrf,
            },
        )
        self.assertEqual(denied_origin.status_code, 403)

        self.ui_login()
        dashboard = self.client.get("/app")
        self.assertIn("Classification workspace", dashboard.text)
        self.assertIn(".txt", dashboard.text)
        self.assertIn(".log", dashboard.text)
        self.assertIn(".csv", dashboard.text)
        self.assertIn("10 records", dashboard.text)
        self.assertNotIn(self.client.cookies.get("lcp_session"), dashboard.text)
        self.assertNotIn("retain raw", dashboard.text.casefold())

        missing_csrf = self.client.post(
            "/app/classify",
            headers={"Origin": "http://testserver"},
            files={"upload": ("input.jsonl", b'{"message":"Backup completed"}\n')},
        )
        self.assertEqual(missing_csrf.status_code, 403)
        calls_before = self.rules_call_mock.call_count

        created = self.client.post(
            "/app/classify",
            headers=self.csrf_header(),
            data={"model": "rules"},
            files={"upload": ("input.jsonl", b'{"message":"Backup completed"}\n')},
            follow_redirects=False,
        )
        self.assertEqual(created.status_code, 303, created.text)
        self.assertTrue(self.app.state.job_queue.wait_until_idle(5.0))
        self.assertEqual(self.rules_call_mock.call_count, calls_before + 1)
        detail = self.client.get(created.headers["location"])
        self.assertEqual(detail.status_code, 200)
        self.assertIn("Classification job", detail.text)
        self.assertNotIn("Backup completed", detail.text)

        logout = self.client.post(
            "/app/logout",
            headers=self.csrf_header(),
            follow_redirects=False,
        )
        self.assertEqual(logout.status_code, 303)
        self.assertIsNone(self.client.cookies.get("lcp_session"))
        redirected = self.client.get("/app", follow_redirects=False)
        self.assertEqual(redirected.status_code, 303)
        self.assertEqual(redirected.headers["location"], "/app/login")

    def test_ui_viewer_is_denied_before_upload_parsing_and_prediction(self) -> None:
        admin_token, _ = self.workspace.login("sample-org", "owner", PASSWORD)
        queued_id = self.workspace.create_job(admin_token, "4" * 64, 1)
        self.workspace.logout(admin_token)
        self.ui_login("reviewer", "viewer-password-value")
        calls_before = self.rules_call_mock.call_count
        denied = self.client.post(
            "/app/classify",
            headers=self.csrf_header(),
            files={"upload": ("input.jsonl", b"not even json")},
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.rules_call_mock.call_count, calls_before)

        cancel_denied = self.client.post(
            f"/app/jobs/{queued_id}/cancel",
            headers=self.csrf_header(),
            follow_redirects=False,
        )
        self.assertEqual(cancel_denied.status_code, 403)
        viewer_token = self.client.cookies.get("lcp_session")
        self.assertEqual(
            self.workspace.get_job_status(viewer_token, queued_id)["status"],
            "queued",
        )

    def test_template_autoescape_blocks_model_markup(self) -> None:
        self.app.state.job_queue.close()
        markup_app = create_app(
            WebSettings(
                self.database,
                allowed_hosts=("testserver",),
                max_input_bytes=1_000,
                max_records=10,
                max_request_bytes=4_096,
            ),
            {"markup": MarkupPredictor()},
        )
        with TestClient(
            markup_app,
            base_url="http://testserver",
            raise_server_exceptions=False,
        ) as client:
            session = client.post(
                "/api/v1/sessions",
                json={
                    "organization": "sample-org",
                    "username": "analyst",
                    "password": "analyst-password-value",
                },
            )
            token = session.json()["access_token"]
            created = client.post(
                "/api/v1/classifications",
                headers=self.bearer(token),
                json={
                    "model": "markup",
                    "records": [{"message": "Backup completed"}],
                },
            )
            self.assertEqual(created.status_code, 202, created.text)
            self.assertTrue(markup_app.state.job_queue.wait_until_idle(5.0))
            client.cookies.set("lcp_session", token)
            detail = client.get(f'/app/jobs/{created.json()["job_id"]}')
            self.assertEqual(detail.status_code, 200, detail.text)
            self.assertNotIn("<script>alert", detail.text)
            self.assertIn("&lt;script&gt;alert", detail.text)

    def test_unexpected_predictor_error_becomes_sanitized_failed_job(self) -> None:
        self.app.state.job_queue.close()
        failing_app = create_app(
            WebSettings(
                self.database,
                allowed_hosts=("testserver",),
                max_input_bytes=1_000,
                max_records=10,
                max_request_bytes=4_096,
            ),
            {"failing": ExplodingPredictor()},
        )
        with TestClient(
            failing_app,
            base_url="http://testserver",
            raise_server_exceptions=False,
        ) as client:
            session = client.post(
                "/api/v1/sessions",
                json={
                    "organization": "sample-org",
                    "username": "analyst",
                    "password": "analyst-password-value",
                },
            )
            token = session.json()["access_token"]
            response = client.post(
                "/api/v1/classifications",
                headers=self.bearer(token),
                json={
                    "model": "failing",
                    "records": [{"message": "Synthetic event"}],
                },
            )
            self.assertEqual(response.status_code, 202, response.text)
            self.assertTrue(failing_app.state.job_queue.wait_until_idle(5.0))
            status = client.get(
                response.json()["status_url"],
                headers=self.bearer(token),
            )
            self.assertEqual(status.status_code, 200, status.text)
            self.assertEqual(status.json()["status"], "failed")
            self.assertEqual(status.json()["failure_code"], "internal_error")
            self.assertNotIn("synthetic internal detail", status.text)
            self.assertNotIn("Traceback", status.text)

    def test_admin_can_disable_a_user_through_api_and_ui(self) -> None:
        token = self.api_login("owner", PASSWORD)
        created = self.client.post(
            "/api/v1/admin/users",
            headers=self.bearer(token),
            json={
                "username": "observer",
                "password": "observer-password-value",
                "role": "viewer",
            },
        )
        user_id = created.json()["id"]
        observer = self.api_login("observer", "observer-password-value")

        denied = self.client.patch(
            f"/api/v1/admin/users/{user_id}",
            headers=self.bearer(observer),
            json={"disabled": True},
        )
        self.assertEqual(denied.status_code, 403)
        updated = self.client.patch(
            f"/api/v1/admin/users/{user_id}",
            headers=self.bearer(token),
            json={"disabled": True},
        )
        self.assertEqual(updated.status_code, 200, updated.text)
        self.assertEqual(updated.json()["disabled"], 1)
        revoked = self.client.get("/api/v1/me", headers=self.bearer(observer))
        self.assertEqual(revoked.status_code, 401)

        self.ui_login()
        dashboard = self.client.get("/app")
        self.assertIn(f'action="/app/admin/users/{user_id}"', dashboard.text)
        restored = self.client.post(
            f"/app/admin/users/{user_id}",
            data={"role": "analyst"},
            headers={
                "Origin": "http://testserver",
                "X-CSRF-Token": re.search(
                    r'name="csrf-token" content="([^"]+)"', dashboard.text
                ).group(1),
            },
            follow_redirects=False,
        )
        self.assertEqual(restored.status_code, 303, restored.text)
        users = self.workspace_users()
        self.assertEqual(users["observer"]["role"], "analyst")
        self.assertEqual(users["observer"]["disabled"], 0)

    def workspace_users(self) -> dict[str, dict[str, object]]:
        token, _principal = Workspace(self.database).login(
            "sample-org", "owner", PASSWORD
        )
        items = Workspace(self.database).list_users(token)
        return {item["username"]: item for item in items}

    def test_ui_respects_its_content_security_policy(self) -> None:
        page = self.client.get("/app/login")
        self.assertNotRegex(page.text, r"<[^>]+\son[a-z]+=")
        self.assertIn("data-auto-submit", page.text)
        self.assertEqual(self.client.get("/api/v1/docs").status_code, 404)
        self.assertEqual(self.client.get("/api/v1/openapi.json").status_code, 200)

    def test_admin_user_retention_and_request_limit(self) -> None:
        token = self.api_login("owner", PASSWORD)
        created = self.client.post(
            "/api/v1/admin/users",
            headers=self.bearer(token),
            json={
                "username": "observer",
                "password": "observer-password-value",
                "role": "viewer",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        users = self.client.get("/api/v1/admin/users", headers=self.bearer(token))
        self.assertEqual(users.status_code, 200)
        self.assertIn("observer", {item["username"] for item in users.json()["items"]})

        policy = self.client.put(
            "/api/v1/admin/retention",
            headers=self.bearer(token),
            json={"raw_days": 7, "result_days": 30, "audit_days": 180},
        )
        self.assertEqual(policy.status_code, 200)
        self.assertEqual(policy.json()["policy"]["raw_days"], 7)

        too_large = self.client.post(
            "/api/v1/sessions",
            content=b"x" * 4_097,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(too_large.status_code, 413)
        self.assertNotIn("Traceback", too_large.text)


    def test_streamed_request_limit_cannot_be_bypassed_without_content_length(self) -> None:
        sent = []
        incoming = iter(
            (
                {"type": "http.request", "body": b"a" * 4, "more_body": True},
                {"type": "http.request", "body": b"b" * 5, "more_body": False},
            )
        )

        async def receive():
            return next(incoming)

        async def send(message):
            sent.append(message)

        async def consume_body(_scope, wrapped_receive, wrapped_send):
            while True:
                message = await wrapped_receive()
                if not message.get("more_body", False):
                    break
            await wrapped_send(
                {"type": "http.response.start", "status": 204, "headers": []}
            )
            await wrapped_send({"type": "http.response.body", "body": b""})

        middleware = RequestSizeLimitMiddleware(consume_body, max_bytes=8)
        asyncio.run(
            middleware(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/synthetic",
                    "headers": [],
                },
                receive,
                send,
            )
        )
        start = next(message for message in sent if message["type"] == "http.response.start")
        self.assertEqual(start["status"], 413)

    def test_secure_cookie_profile_enables_secure_and_hsts(self) -> None:
        self.app.state.job_queue.close()
        secure_app = create_app(
            WebSettings(
                self.database,
                allowed_hosts=("testserver",),
                cookie_secure=True,
            ),
            {"rules": RulesPredictor()},
        )
        with TestClient(
            secure_app,
            base_url="https://testserver",
            raise_server_exceptions=False,
        ) as client:
            response = client.get("/app/login")
            self.assertEqual(response.status_code, 200)
            self.assertIn("strict-transport-security", response.headers)
            login_cookie = next(
                item
                for item in response.headers.get_list("set-cookie")
                if "lcp_login_csrf=" in item
            )
            self.assertIn("Secure", login_cookie)

    def test_cli_web_binds_loopback_and_rejects_irrelevant_model_options(self) -> None:
        with mock.patch("uvicorn.run") as run:
            status = main(["web", str(self.database), "--port", "8091"])
        self.assertEqual(status, 0)
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs["host"], "127.0.0.1")
        self.assertEqual(run.call_args.kwargs["port"], 8091)
        self.assertFalse(run.call_args.kwargs["access_log"])
        self.assertFalse(run.call_args.kwargs["proxy_headers"])

        with (
            mock.patch("uvicorn.run") as rejected_run,
            redirect_stderr(io.StringIO()) as error_output,
        ):
            status = main(
                [
                    "web",
                    str(self.database),
                    "--model-source",
                    str(self.database.parent),
                ]
            )
        self.assertEqual(status, 2)
        rejected_run.assert_not_called()
        self.assertIn("model options require --adapter zero-shot", error_output.getvalue())

        with (
            mock.patch("uvicorn.run") as mismatch_run,
            redirect_stderr(io.StringIO()) as mismatch_error,
        ):
            status = main(
                [
                    "web",
                    str(self.database),
                    "--adapter",
                    "zero-shot",
                    "--model-source",
                    str(self.database.parent),
                    "--model-id",
                    "example/mismatch",
                    "--model-revision",
                    "mismatch",
                ]
            )
        self.assertEqual(status, 2)
        mismatch_run.assert_not_called()
        self.assertIn("must match --model-profile", mismatch_error.getvalue())

        with mock.patch("uvicorn.run") as profile_run:
            status = main(
                [
                    "web",
                    str(self.database),
                    "--enable-model-profile",
                    MULTILINGUAL_PROFILE_ID,
                ]
            )
        self.assertEqual(status, 0)
        configured_app = profile_run.call_args.args[0]
        self.assertEqual(
            set(configured_app.state.predictors),
            {"rules", MULTILINGUAL_PROFILE_ID},
        )
        self.assertEqual(
            [item["id"] for item in configured_app.state.model_catalog],
            ["rules", MULTILINGUAL_PROFILE_ID],
        )
        configured = configured_app.state.predictors[MULTILINGUAL_PROFILE_ID]
        self.assertIsInstance(configured, ZeroShotPredictor)
        self.assertFalse(configured.loaded)


@unittest.skipUnless(WEB_AVAILABLE, "web extra is not installed")
class LoginRateLimiterTests(unittest.TestCase):
    def test_account_source_expiry_success_and_privacy(self) -> None:
        now = [100.0]
        limiter = LoginRateLimiter(
            account_limit=2,
            source_limit=3,
            window_seconds=10,
            clock=lambda: now[0],
        )

        self.assertIsNone(limiter.retry_after("client-a", "sample-org", "owner"))
        self.assertIsNone(
            limiter.record_failure("client-a", "sample-org", "owner")
        )
        self.assertEqual(
            limiter.record_failure("client-a", "sample-org", "owner"),
            10,
        )
        self.assertEqual(limiter.retry_after("client-a", "sample-org", "owner"), 10)
        self.assertIsNone(
            limiter.retry_after("client-b", "sample-org", "different-user")
        )

        limiter.record_success("client-a", "sample-org", "owner")
        self.assertIsNone(limiter.retry_after("client-a", "sample-org", "owner"))
        self.assertEqual(
            limiter.record_failure("client-a", "sample-org", "different-user"),
            10,
        )

        internal_state = repr(vars(limiter))
        self.assertNotIn("sample-org", internal_state)
        self.assertNotIn("owner", internal_state)
        self.assertNotIn("client-a", internal_state)

        now[0] = 111.0
        self.assertIsNone(
            limiter.retry_after("client-a", "sample-org", "different-user")
        )

    def test_configuration_rejects_invalid_limits(self) -> None:
        with self.assertRaisesRegex(ValueError, "source_limit"):
            LoginRateLimiter(
                account_limit=3,
                source_limit=2,
                window_seconds=10,
            )
        with self.assertRaisesRegex(ValueError, "positive integer"):
            LoginRateLimiter(
                account_limit=True,
                source_limit=2,
                window_seconds=10,
            )
        with self.assertRaisesRegex(ValueError, "login_source_limit"):
            WebSettings(
                Path("synthetic-workspace.sqlite3"),
                login_account_limit=3,
                login_source_limit=2,
            )

    def test_bucket_capacity_fails_closed_without_unbounded_keys(self) -> None:
        limiter = LoginRateLimiter(
            account_limit=5,
            source_limit=5,
            window_seconds=10,
            max_account_buckets=2,
            max_source_buckets=1,
            clock=lambda: 100.0,
        )
        self.assertIsNone(
            limiter.record_failure("client-a", "sample-org", "first-user")
        )
        self.assertEqual(
            limiter.record_failure("client-b", "sample-org", "second-user"),
            10,
        )
        self.assertEqual(len(limiter._accounts), 2)
        self.assertEqual(len(limiter._sources), 1)


if __name__ == "__main__":
    unittest.main()
